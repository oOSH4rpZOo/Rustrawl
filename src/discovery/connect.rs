//! The sweep and expand stages over TCP connect — the no-root fallback. Slower
//! and noisier than
//! SYN (full handshakes or refused connections, no RST-only liveness), but the
//! same permutation, rate bucket, mute safety, evidence files and cursor
//! semantics as the SYN engine. Semantics (see `classify_connect`): refused
//! and reset count as live (a RST is a live stack); timeout is mute; the
//! unreachables are mute too but tracked apart — they speak about our
//! routing, not about the target.

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::config;
use crate::targets::Targets;
use crate::util::{fmt_count, format_duration};

use super::db::{Answer, Db, Stage};
use super::perm::HostPerm;
use super::rate::TokenBucket;
use super::state::{self, Cursor, EngineState, LiveLog, StageFiles};
use super::{on_sigint, ABORT};

const WORKERS: usize = 128;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);
struct Probe {
    host_idx: u64,
    ip: Ipv4Addr,
    port: u16,
}

enum Res {
    /// The connect succeeded (open port) or was refused/reset (RST-equivalent).
    Live {
        host_idx: u64,
        ip: Ipv4Addr,
        port: u16,
        why: &'static str,
    },
    /// Timeout — no answer; the host's verdict is `no_response` once every
    /// port came back mute.
    Dead { host_idx: u64, ip: Ipv4Addr },
    /// ENETUNREACH/EHOSTUNREACH/ENETDOWN: the probe never reached a network —
    /// that says more about OUR routing than about the target. Counts as a
    /// mute answer for the host verdict (a miss is not a verdict) but is
    /// tracked separately and reported: a scope of unreachables is a local
    /// posture problem to surface, not a dark range to grind through.
    Unroutable { host_idx: u64, ip: Ipv4Addr },
    /// Dispatcher checkpoint: cursor position and a snapshot of the sent counter.
    Checkpoint(Cursor, u64),
}

/// What a connect outcome says about the target.
enum Verdict {
    /// The remote stack answered (connected, RST refused, RST reset) → live.
    Live(&'static str),
    /// No answer within the timeout.
    Mute,
    /// No network path — our side, not the target's.
    Unroutable,
}

/// Pure errno → verdict mapping, so the semantics carry their own tests.
fn classify_connect(e: &io::Error) -> Verdict {
    match e.raw_os_error() {
        Some(libc::ECONNREFUSED) => Verdict::Live("refused"),
        Some(libc::ECONNRESET) => Verdict::Live("reset"),
        Some(libc::ENETUNREACH | libc::EHOSTUNREACH | libc::ENETDOWN) => Verdict::Unroutable,
        // timeouts and anything unclassified: no answer is no answer
        _ => Verdict::Mute,
    }
}

struct Shared {
    bucket: Mutex<TokenBucket>,
    paused: AtomicBool,
    sent: AtomicU64,
    /// Probes whose result the main loop has processed — the dispatcher
    /// checkpoints a block only once everything before it is done, so
    /// `--resume` replays at most the in-flight window instead of skipping
    /// unsent probes.
    completed: AtomicU64,
}

/// Per-host result accounting: results received vs live results, so a host
/// that finishes all its ports fully mute increments the mute counter once.
struct HostAccount {
    received: u32,
    live: u32,
}

pub fn run(
    scope: &config::Scope,
    scan: &Targets,
    run_dir: &Path,
    ports: Vec<u16>,
    resume: bool,
    ctx: &mut super::StageCtx,
) -> Result<i32> {
    unsafe { libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t) };

    let stage = ctx.stage;
    let files: StageFiles = ctx.files;
    let skip = Arc::clone(&ctx.skip);
    let db: &mut Db = ctx.db;
    let clamp = ctx.clamp;
    let label = ctx.label.clone();

    let ports_n = ports.len() as u64;
    let block = scope.discovery.block;
    let host_total = scan.total();
    let total_probes = host_total.saturating_mul(ports_n);

    // Resume: replay the live hosts, keep the seed, and replay the interrupted
    // block from its start — already-probed hosts get duplicate probes
    // (deduplicated downstream) instead of skipped ones. Hosts settled since
    // (DB verdicts) sit in the skip set: they still advance the cursor.
    let (mut state, mut live_hosts) = if resume {
        let mut st = state::read_state(run_dir, &files)?;
        st.cursor = Cursor {
            block_list_pos: st.cursor.block_list_pos,
            inner: 0,
            port: 0,
        };
        let live = LiveLog::replay(run_dir, &files, &scan.as_bitmap())?;
        (st, live)
    } else {
        let seed: [u8; 32] = rand::random();
        (
            EngineState {
                schema: state::STATE_SCHEMA,
                seed_hex: hex(&seed),
                host_total,
                ports_n,
                block,
                scan_hash: state::fingerprint(scan.ranges(), &ports),
                group: ctx.group,
                groups_total: ctx.groups_total,
                cursor: Cursor::default(),
                sent: 0,
                since_reply: 0,
                mute_budget: 1024,
                last_live_idx: None,
                done: false,
            },
            BTreeSet::new(),
        )
    };
    // The mute budget survives interrupts (see state.rs) — a resumed run does
    // not get a fresh 1024-host mute allowance.
    let resume_mute = state.since_reply;
    let resume_last_live = state
        .last_live_idx
        .and_then(|idx| scan.nth(idx).map(|ip| (idx, ip)));
    let mut seed = [0u8; 32];
    unhex(&state.seed_hex, &mut seed);
    let perm = HostPerm::new(seed, host_total, block);

    let mut live_log = LiveLog::open(run_dir, &files)?;
    let mut log = state::open_run_log(run_dir)?;
    state::log_line(
        &mut log,
        &format!(
            "{label} start (connect mode, {WORKERS} workers) | {} hosts × {} ports = {} probes | {} pps ±{}% | run {}",
            fmt_count(host_total),
            ports_n,
            fmt_count(total_probes),
            fmt_count(u64::from(scope.discovery.rate_pps)),
            scope.discovery.jitter_pct,
            run_dir.file_name().unwrap_or_default().to_string_lossy(),
        ),
    );
    state::write_state(run_dir, &files, &state)?;

    // Live progress footer (inert without a terminal); workers poll the same
    // pause flag the `p` key toggles.
    let screen = crate::tui::Screen::start(&label, total_probes, crate::tui::Footer::Discovery);
    let status = Arc::clone(screen.status());

    let shared = Arc::new(Shared {
        bucket: Mutex::new(TokenBucket::new(
            u64::from(scope.discovery.rate_pps),
            scope.discovery.jitter_pct,
        )),
        paused: AtomicBool::new(false),
        // Cumulative across resumes: checkpoints stamp state.sent with this
        // counter, so it must start from the persisted count, not zero.
        sent: AtomicU64::new(state.sent),
        completed: AtomicU64::new(0),
    });

    let started = Instant::now();
    // Channels live in this frame (not the scope body) so spawned threads can own their halves.
    let (ptx, prx) = mpsc::sync_channel::<Probe>(4096);
    let (rtx, rrx) = mpsc::channel::<Res>();
    let cursor0 = state.cursor;
    let prx = Arc::new(Mutex::new(prx));

    let outcome = thread::scope(|s| {
        // Dispatcher: walks the permutation, hands probes to the workers.
        // The checkpointed cursor only ever advances past a block once every
        // probe of that block has been processed by the main loop — an
        // interrupt then replays the small in-flight window instead of
        // skipping it.
        let rtx_d = rtx.clone();
        let ports_d = ports.clone();
        let shared_d = Arc::clone(&shared);
        let skip_d = Arc::clone(&skip);
        s.spawn(move || {
            let mut dispatched = 0u64;
            let mut acked = cursor0;
            'outer: for (bli, &bid) in perm
                .block_order()
                .iter()
                .enumerate()
                .skip(cursor0.block_list_pos as usize)
            {
                let hosts = perm.shuffle_block(bid);
                let inner_from = if bli as u64 == cursor0.block_list_pos {
                    cursor0.inner as usize
                } else {
                    0
                };
                for (hi, &local) in hosts.iter().enumerate().skip(inner_from) {
                    let host_idx = u64::from(bid) * u64::from(block) + u64::from(local);
                    let ip = match scan.nth(host_idx) {
                        Some(ip) => ip,
                        None => continue,
                    };
                    // Fresh verdict in the DB: probed nowhere, but the block
                    // accounting stays identical, so a resume remains
                    // deterministic even if the skip set grew.
                    if skip_d.contains(u32::from(ip)) {
                        continue;
                    }
                    let port_from =
                        if bli as u64 == cursor0.block_list_pos && hi as u32 == cursor0.inner {
                            cursor0.port as usize
                        } else {
                            0
                        };
                    for &port in ports_d.iter().skip(port_from) {
                        if ABORT.load(Ordering::Relaxed) {
                            break 'outer;
                        }
                        if ptx.send(Probe { host_idx, ip, port }).is_err() {
                            break 'outer;
                        }
                        dispatched += 1;
                    }
                }
                // Block boundary: wait until the main loop processed every
                // probe of the block, then checkpoint.
                while dispatched > shared_d.completed.load(Ordering::Relaxed)
                    && !ABORT.load(Ordering::Relaxed)
                {
                    thread::sleep(Duration::from_millis(1));
                }
                if ABORT.load(Ordering::Relaxed) {
                    break 'outer;
                }
                acked = Cursor {
                    block_list_pos: bli as u64 + 1,
                    inner: 0,
                    port: 0,
                };
                let _ = rtx_d.send(Res::Checkpoint(
                    acked,
                    shared_d.sent.load(Ordering::Relaxed),
                ));
            }
            let _ = rtx_d.send(Res::Checkpoint(
                acked,
                shared_d.sent.load(Ordering::Relaxed),
            ));
        });

        // The probe queue: mpsc::Receiver isn't clonable, workers share it.
        for _ in 0..WORKERS {
            let prx = Arc::clone(&prx);
            let rtx = rtx.clone();
            let shared = Arc::clone(&shared);
            s.spawn(move || loop {
                let p = {
                    let rx = prx.lock().unwrap_or_else(|e| e.into_inner());
                    match rx.recv() {
                        Ok(p) => p,
                        Err(_) => return,
                    }
                };
                while (shared.paused.load(Ordering::Relaxed) || crate::tui::paused())
                    && !ABORT.load(Ordering::Relaxed)
                {
                    thread::sleep(Duration::from_millis(100));
                }
                if ABORT.load(Ordering::Relaxed) {
                    return;
                }
                let got_token = {
                    let mut bucket = shared.bucket.lock().unwrap_or_else(|e| e.into_inner());
                    bucket.wait_take(&ABORT)
                };
                if !got_token {
                    return;
                }
                let res = match TcpStream::connect_timeout(
                    &SocketAddr::from((p.ip, p.port)),
                    CONNECT_TIMEOUT,
                ) {
                    Ok(_) => Res::Live {
                        host_idx: p.host_idx,
                        ip: p.ip,
                        port: p.port,
                        why: "connected",
                    },
                    Err(e) => match classify_connect(&e) {
                        Verdict::Live(why) => Res::Live {
                            host_idx: p.host_idx,
                            ip: p.ip,
                            port: p.port,
                            why,
                        },
                        Verdict::Unroutable => Res::Unroutable {
                            host_idx: p.host_idx,
                            ip: p.ip,
                        },
                        Verdict::Mute => Res::Dead {
                            host_idx: p.host_idx,
                            ip: p.ip,
                        },
                    },
                };
                shared.sent.fetch_add(1, Ordering::Relaxed);
                let _ = rtx.send(res);
            });
        }
        drop(prx); // main thread's Arc — workers hold their own
        drop(rtx); // otherwise the main loop below waits on its own sender forever

        // Main thread: results, mute accounting, checkpoints, cooldown/abort.
        // Housekeeping runs on a wall-clock schedule: with 128 workers a mute
        // stretch produces results every few milliseconds, so gating it on the
        // channel going quiet would starve it exactly when it matters.
        let mut consecutive_mute = resume_mute;
        let mut mute_reacted = false;
        // Kill-switch budget: the scope's knob fresh, the persisted (possibly
        // doubled) value on resume; 0 disables the switch. Cooldown from the
        // scope too — the fixed 60 s taxed legitimately sparse space.
        let mut mute_budget = if resume {
            state.mute_budget
        } else {
            u64::from(scope.discovery.mute_abort_after)
        };
        let cooldown = Duration::from_secs(scope.discovery.mute_cooldown_secs);
        let mut last_live = resume_last_live;
        let mut live_events = 0u64;
        let mut unroutable = 0u64;
        let mut unroutable_next = 1u64;
        let mut suspicious = false;
        let mut last_cursor = state.cursor;
        let mut accounts: HashMap<u64, HostAccount> = HashMap::new();
        let mut next_check = Instant::now();
        let mut progress_at = Instant::now();
        let mut dark_next = 4096u64;

        loop {
            let now = Instant::now();
            if now >= next_check {
                next_check = now + Duration::from_millis(200);
                // Footer refresh + keyboard pause: workers check the same
                // flag every probe, so pausing here propagates within 100 ms.
                status.set_done(shared.sent.load(Ordering::Relaxed));
                status.set_up(live_hosts.len() as u64);
                status.set_mute(consecutive_mute);
                status.set_unroutable(unroutable);
                if now.duration_since(progress_at) >= Duration::from_secs(5) {
                    progress_at = now;
                    status.set_extra(format!("port hits {}", fmt_count(live_events)));
                    state::log_line(
                        &mut log,
                        &format!(
                            "{label} | {} / {} probes | live hosts {} ({}) | mute {} | cursor blk {}",
                            fmt_count(shared.sent.load(Ordering::Relaxed)),
                            fmt_count(total_probes),
                            fmt_count(live_hosts.len() as u64),
                            fmt_count(live_events),
                            fmt_count(consecutive_mute),
                            last_cursor.block_list_pos,
                        ),
                    );
                }
                if let Err(e) = db.flush_if_needed() {
                    state::log_line(&mut log, &format!("db flush failed: {e}"));
                }
                if unroutable >= unroutable_next {
                    state::log_line(
                        &mut log,
                        &format!(
                            "{unroutable} unreachable probe(s) (no route to host) - our routing, not the target; counted as misses (a miss is not a verdict)"
                        ),
                    );
                    unroutable_next = if unroutable_next == 1 {
                        4096
                    } else {
                        unroutable_next + 4096
                    };
                }
                if mute_budget > 0
                    && consecutive_mute >= mute_budget
                    && last_live.is_some()
                    && !mute_reacted
                {
                    mute_reacted = true;
                    // Re-probe ports: the ranking's most-answered ports this
                    // stream covers — with `full` or an arbitrary explicit
                    // list, ports[..5] would be ports 1-5, where nothing
                    // answers, and a healthy network would "confirm" the
                    // filtering verdict.
                    let reprobe_ports: Vec<u16> = {
                        let v: Vec<u16> = crate::ports::top_n(5)
                            .into_iter()
                            .filter(|p| ports.contains(p))
                            .collect();
                        if v.is_empty() {
                            ports.iter().take(5).copied().collect()
                        } else {
                            v
                        }
                    };
                    // Cooldown with the workers paused, then re-probe the last
                    // live host. Any reply during the wait resumes immediately
                    // — same semantics as the SYN engine.
                    let (_, ip) = last_live.expect("checked just above");
                    state::log_line(
                        &mut log,
                        &format!(
                            "{} consecutive mute hosts after live ones - {} s cooldown, then re-probe {ip} (budget {mute_budget}, 0 = off)",
                            fmt_count(consecutive_mute),
                            cooldown.as_secs(),
                        ),
                    );
                    state.sent = shared.sent.load(Ordering::Relaxed);
                    state.since_reply = consecutive_mute;
                    state.mute_budget = mute_budget;
                    state.last_live_idx = last_live.map(|(idx, _)| idx);
                    state.mute_budget = mute_budget;
                    if let Err(e) = state::write_state(run_dir, &files, &state) {
                        state::log_line(&mut log, &format!("state write failed: {e}"));
                    }
                    if let Err(e) = db.flush() {
                        state::log_line(&mut log, &format!("db flush failed: {e}"));
                    }
                    shared.paused.store(true, Ordering::Relaxed);
                    let deadline = Instant::now() + cooldown;
                    let mut resumed = false;
                    while Instant::now() < deadline && !ABORT.load(Ordering::Relaxed) {
                        // `s` on the keyboard: cut the cooldown short, the
                        // re-probe below decides.
                        if crate::tui::take_skip() {
                            state::log_line(
                                &mut log,
                                "cooldown skipped from the keyboard - re-probing now",
                            );
                            break;
                        }
                        thread::sleep(Duration::from_millis(100));
                        // Keep consuming while paused: in-flight results must
                        // reach their hosts' accounts and the dispatcher.
                        loop {
                            match rrx.try_recv() {
                                Ok(Res::Checkpoint(cursor, sent)) => {
                                    last_cursor = cursor;
                                    state.cursor = cursor;
                                    state.sent = sent;
                                    state.since_reply = consecutive_mute;
                                    state.last_live_idx = last_live.map(|(idx, _)| idx);
                                    state.mute_budget = mute_budget;
                                    if let Err(e) = state::write_state(run_dir, &files, &state) {
                                        state::log_line(
                                            &mut log,
                                            &format!("state write failed: {e}"),
                                        );
                                    }
                                }
                                Ok(res) => {
                                    let live = handle_result(
                                        res,
                                        &mut live_log,
                                        &mut live_hosts,
                                        &mut accounts,
                                        &mut consecutive_mute,
                                        &mut mute_reacted,
                                        &mut last_live,
                                        &mut live_events,
                                        &mut unroutable,
                                        db,
                                        stage,
                                        ports_n,
                                    );
                                    shared.completed.fetch_add(1, Ordering::Relaxed);
                                    if live {
                                        resumed = true;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        if resumed {
                            break;
                        }
                    }
                    if ABORT.load(Ordering::Relaxed) {
                        // ^C wins over the filtering verdict — exit 0, resumable.
                        break;
                    }
                    if resumed {
                        mute_budget = (mute_budget.saturating_mul(2)).min(super::MUTE_BUDGET_MAX);
                        state::log_line(
                            &mut log,
                            &format!(
                                "replies came back during cooldown - network alive, resuming (mute budget now {mute_budget})"
                            ),
                        );
                    } else {
                        if !reprobe_last_live(ip, &reprobe_ports, &mut log) {
                            suspicious = true;
                            ABORT.store(true, Ordering::Relaxed);
                            break;
                        }
                        // Proven-false alarm: the stretch was merely empty —
                        // double the budget (capped) so sparse space stops
                        // taxing the run; a real filter still trips later.
                        mute_budget = (mute_budget.saturating_mul(2)).min(super::MUTE_BUDGET_MAX);
                    }
                    // Resume the stream and re-arm the mute detector.
                    shared.paused.store(false, Ordering::Relaxed);
                    consecutive_mute = 0;
                    mute_reacted = false;
                } else if last_live.is_none() && consecutive_mute >= dark_next {
                    state::log_line(
                        &mut log,
                        &format!(
                            "{} consecutive mute hosts, no live host seen yet - dark range, continuing",
                            fmt_count(consecutive_mute),
                        ),
                    );
                    dark_next += 4096;
                }
            }
            match rrx.recv_timeout(Duration::from_millis(200)) {
                Ok(Res::Checkpoint(cursor, sent)) => {
                    last_cursor = cursor;
                    state.cursor = cursor;
                    state.sent = sent;
                    state.since_reply = consecutive_mute;
                    state.mute_budget = mute_budget;
                    state.last_live_idx = last_live.map(|(idx, _)| idx);
                    state.mute_budget = mute_budget;
                    if let Err(e) = state::write_state(run_dir, &files, &state) {
                        state::log_line(&mut log, &format!("state write failed: {e}"));
                    }
                }
                Ok(res) => {
                    handle_result(
                        res,
                        &mut live_log,
                        &mut live_hosts,
                        &mut accounts,
                        &mut consecutive_mute,
                        &mut mute_reacted,
                        &mut last_live,
                        &mut live_events,
                        &mut unroutable,
                        db,
                        stage,
                        ports_n,
                    );
                    shared.completed.fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
        let cursor = last_cursor;
        let sent = shared.sent.load(Ordering::Relaxed);
        let interrupted = ABORT.load(Ordering::Relaxed);
        (
            cursor,
            sent,
            suspicious,
            interrupted,
            live_events,
            unroutable,
            consecutive_mute,
            last_live.map(|(idx, _)| idx),
        )
    });

    let (
        cursor,
        sent,
        suspicious,
        interrupted,
        live_events,
        unroutable,
        final_mute,
        final_live_idx,
    ) = outcome;
    let code = if suspicious { 2 } else { 0 };
    // Verdicts before state: a failed flush must not leave done=true behind —
    // surface the error, the operator reruns with --resume.
    db.flush()?;
    state.cursor = cursor;
    state.sent = sent;
    state.done = code == 0 && !interrupted;
    state.since_reply = final_mute;
    state.last_live_idx = final_live_idx;
    state::write_state(run_dir, &files, &state)?;
    let ips = super::finalize_ip_list(db, scan, clamp, stage, &live_hosts, &mut log)?;
    state::write_ip_list(run_dir, &files, ips.into_iter())?;
    if interrupted && !suspicious {
        state::log_line(&mut log, "interrupted - state saved, rerun with --resume");
    }
    state::log_line(
        &mut log,
        &format!(
            "{label} end (connect mode) | {} probes sent in {} | live hosts {} ({} port events) | unreachable {unroutable} | evidence: {}",
            fmt_count(sent),
            format_duration(started.elapsed()),
            fmt_count(live_hosts.len() as u64),
            fmt_count(live_events),
            run_dir.display(),
        ),
    );
    Ok(code)
}

/// Records one engine result: evidence log, DB rows (probe answer, then the
/// host verdict once every port answered). Returns true for a live event.
///
/// Unlike the SYN engine, a late result is NOT compensated when its host's
/// account already settled: there is no pending map here, only the received
/// counter, and a late `Res::Live` cannot be told apart from a duplicate —
/// probe replay after a resume can legitimately re-deliver. The evidence is
/// still correct (the event reaches live.jsonl and live_hosts, so the ip
/// lists are right), and the DB self-heals on the next run: the host re-enters
/// the retry window and gets re-probed.
#[allow(clippy::too_many_arguments)]
fn handle_result(
    res: Res,
    live_log: &mut LiveLog,
    live_hosts: &mut BTreeSet<u64>,
    accounts: &mut HashMap<u64, HostAccount>,
    consecutive_mute: &mut u64,
    mute_reacted: &mut bool,
    last_live: &mut Option<(u64, Ipv4Addr)>,
    live_events: &mut u64,
    unroutable: &mut u64,
    db: &mut Db,
    stage: Stage,
    ports_n: u64,
) -> bool {
    match res {
        Res::Live {
            host_idx,
            ip,
            port,
            why,
        } => {
            if live_log.record(host_idx, ip, port, why).is_ok() {
                *live_events += 1;
            }
            let answer = if why == "connected" {
                Answer::Open
            } else {
                Answer::Closed
            };
            db.record_result(ip, port, stage, answer);
            live_hosts.insert(host_idx);
            *last_live = Some((host_idx, ip));
            *consecutive_mute = 0;
            *mute_reacted = false;
            if let Some(up) = account_result(accounts, host_idx, true, consecutive_mute, ports_n) {
                db.record_host(ip, stage, up, ports_n as u32);
            }
            true
        }
        Res::Unroutable { host_idx, ip } => {
            *unroutable += 1;
            // A miss is not a verdict: the host settles no_response like any
            // mute answer and re-enters the retry window later.
            if account_result(accounts, host_idx, false, consecutive_mute, ports_n).is_some() {
                db.record_host(ip, stage, false, ports_n as u32);
            }
            false
        }
        Res::Dead { host_idx, ip } => {
            if account_result(accounts, host_idx, false, consecutive_mute, ports_n).is_some() {
                db.record_host(ip, stage, false, ports_n as u32);
            }
            false
        }
        Res::Checkpoint(..) => false,
    }
}

/// Accumulates one probe's outcome; once every port of the host answered,
/// removes the account and returns Some(host is up).
fn account_result(
    accounts: &mut HashMap<u64, HostAccount>,
    host_idx: u64,
    live: bool,
    consecutive_mute: &mut u64,
    ports_n: u64,
) -> Option<bool> {
    let acc = accounts.entry(host_idx).or_insert(HostAccount {
        received: 0,
        live: 0,
    });
    acc.received += 1;
    if live {
        acc.live += 1;
    }
    if acc.received >= ports_n as u32 {
        let up = acc.live > 0;
        if !up {
            *consecutive_mute += 1;
        }
        accounts.remove(&host_idx);
        Some(up)
    } else {
        None
    }
}

/// Direct liveness re-probe of the last live host: up to 5 ports (the
/// ranking's most-answered this stream covers), 3 rounds. A refusal or a
/// reset counts as answered — same definition of live as the engine itself.
/// Returns false when the target looks filtered (abort, code 2).
fn reprobe_last_live(ip: Ipv4Addr, ports: &[u16], log: &mut std::fs::File) -> bool {
    for _round in 0..3 {
        // ^C wins over the filtering verdict — stay resumable.
        if ABORT.load(Ordering::Relaxed) {
            return true;
        }
        for &port in ports.iter().take(5) {
            if ABORT.load(Ordering::Relaxed) {
                return true;
            }
            let answered = match TcpStream::connect_timeout(
                &SocketAddr::from((ip, port)),
                Duration::from_secs(2),
            ) {
                Ok(_) => true,
                // Same triage as the scan: a refusal or a reset is a live
                // stack; unroutable is our routing, silence stays silence.
                Err(e) => matches!(classify_connect(&e), Verdict::Live(_)),
            };
            if answered {
                state::log_line(
                    log,
                    "liveness re-probe answered - the mute stretch was local, resuming",
                );
                return true;
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
    if ABORT.load(Ordering::Relaxed) {
        return true;
    }
    state::log_line(
        log,
        "sustained silence after a live start - filtering suspected (check our posture before blaming the target); state saved, rerun with --resume",
    );
    false
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str, out: &mut [u8; 32]) {
    let b = s.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = b
            .get(i * 2)
            .and_then(|c| (*c as char).to_digit(16))
            .unwrap_or(0) as u8;
        let lo = b
            .get(i * 2 + 1)
            .and_then(|c| (*c as char).to_digit(16))
            .unwrap_or(0) as u8;
        *slot = (hi << 4) | lo;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_semantics() {
        let v = |errno: i32| classify_connect(&io::Error::from_raw_os_error(errno));
        // answered stacks: RST-flavored refusals are live, however they surface
        assert!(matches!(v(libc::ECONNREFUSED), Verdict::Live("refused")));
        assert!(matches!(v(libc::ECONNRESET), Verdict::Live("reset")));
        // silent target
        assert!(matches!(v(libc::ETIMEDOUT), Verdict::Mute));
        assert!(
            matches!(v(libc::EIO), Verdict::Mute),
            "unknown errno stays mute"
        );
        // no network path: our side — tracked, never a target verdict
        for errno in [libc::ENETUNREACH, libc::EHOSTUNREACH, libc::ENETDOWN] {
            assert!(matches!(v(errno), Verdict::Unroutable), "errno {errno}");
        }
    }
}
