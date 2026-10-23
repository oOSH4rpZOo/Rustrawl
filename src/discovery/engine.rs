//! SYN engine for one sweep group (or the /24 expansion): walk the seeded
//! permutation at the configured rate, send stateless SYNs, decode replies by
//! their echoed cookie, and persist evidence as it arrives. Crash-safe: the
//! permutation cursor is written at every block boundary (and on abort), so
//! `--resume` continues the stream.
//!
//! Mute-host safety (lessons 14/17): a run that has already seen live hosts
//! and then goes fully mute for `MUTE_THRESHOLD` consecutive hosts re-probes
//! the last live host right away — a cooldown is only waited out if that
//! probe stays silent — and aborts (resumably) only if both volleys fail. A
//! dark range with no live host ever seen is logged, never fatal — aborting
//! a legitimate scan is the lesson-14 mistake.

use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use roaring::RoaringBitmap;

use crate::config;
use crate::targets::Targets;
use crate::util::fmt_count;

use super::db::{Answer, Db, Stage};
use super::encoder;
use super::packet::Reply;
use super::perm::HostPerm;
use super::rate::TokenBucket;
use super::receiver::Receiver;
use super::sender::Sender;
use super::state::{self, Cursor, EngineState, LiveLog, StageFiles};
use super::{on_sigint, ABORT};

/// A host's probes are settled (mute or answered) this long after its first send.
const SETTLE_AFTER: Duration = Duration::from_secs(3);
/// Keep draining after the last probe before declaring the run over.
const END_GRACE: Duration = Duration::from_secs(5);
const END_MAX: Duration = Duration::from_secs(20);

struct Pending {
    first_sent: Instant,
    replies: u32,
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
    crate::util::raise_nofile();

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
    let iface = scope.discovery.interface.as_deref();

    // Resume: replay the live hosts, keep the seed, and replay the interrupted
    // block from its start — already-probed hosts get duplicate probes
    // (deduplicated downstream) instead of skipped ones. Hosts settled since
    // (DB verdicts) sit in the skip set: they still advance the cursor.
    let (state, live_hosts) = if resume {
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
                mute_budget: 1024, // placeholder — the engine stamps the live budget on every write
                last_live_idx: None,
                done: false,
            },
            BTreeSet::new(),
        )
    };
    // The mute budget survives interrupts: a run that was already deep into a
    // mute stretch does not get a fresh 1024-host allowance after --resume.
    // last_live_idx's IP is re-derived from the (fingerprint-guarded) targets.
    let resume_mute = state.since_reply;
    let resume_last_live = state
        .last_live_idx
        .and_then(|idx| scan.nth(idx).map(|ip| (idx, ip)));
    // The kill-switch budget: the scope's knob on a fresh run, the persisted
    // (possibly doubled) value on a resume. 0 disables the switch entirely.
    let mute_budget = if resume {
        state.mute_budget
    } else {
        u64::from(scope.discovery.mute_abort_after)
    };
    let cooldown = Duration::from_secs(scope.discovery.mute_cooldown_secs);
    let mut seed = [0u8; 32];
    unhex(&state.seed_hex, &mut seed);
    // The reply cookie is salted per run+stage: a retransmitted SYN-ACK from
    // the previous stage decodes to a pseudo-random index instead of colliding
    // with this stage's flat indexes. seed_hex is persisted, so --resume
    // reconstructs the same key.
    let cookie_key = u32::from_le_bytes([seed[0], seed[1], seed[2], seed[3]]);
    let perm = HostPerm::new(seed, host_total, block);

    let sender = Sender::open(iface).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            anyhow::anyhow!(
                "raw sockets unavailable ({e}) - run as root/CAP_NET_RAW, or use --mode connect"
            )
        } else {
            anyhow::anyhow!("raw send socket: {e}")
        }
    })?;
    let receiver = Receiver::open(8 * 1024 * 1024, iface)?;
    eprintln!(
        "  receiver up - rcvbuf {} KiB, BPF reply filter attached",
        receiver.actual_rcvbuf() / 1024
    );

    let live_log = LiveLog::open(run_dir, &files)?;
    let mut log = state::open_run_log(run_dir)?;
    state::log_line(
        &mut log,
        &format!(
            "{label} start | {} hosts × {} ports = {} probes | {} pps ±{}% | block {} | run {}",
            fmt_count(host_total),
            ports_n,
            fmt_count(total_probes),
            fmt_count(u64::from(scope.discovery.rate_pps)),
            scope.discovery.jitter_pct,
            block,
            run_dir.file_name().unwrap_or_default().to_string_lossy(),
        ),
    );
    state::write_state(run_dir, &files, &state)?;
    let resume_sent = state.sent;

    // Live progress footer (inert without a terminal): done = probes sent,
    // up/mute/unroutable as the engine learns them. `p` pauses the send loop,
    // `s` cuts a mute cooldown short, `q` trips the same ABORT as SIGINT.
    let screen = crate::tui::Screen::start(&label, total_probes, crate::tui::Footer::Discovery);
    let status = Arc::clone(screen.status());
    // The Screen itself is never read — it is kept on this frame for its
    // Drop (clear the block, restore the terminal when the engine ends).
    let _screen = screen;

    let mut eng = Engine {
        scan,
        run_dir: run_dir.to_path_buf(),
        log,
        stage,
        files,
        label,
        db,
        skip,
        clamp,
        cookie_key,
        ports,
        ports_n,
        block,
        total_probes,
        perm,
        sender,
        receiver,
        live_log,
        bucket: TokenBucket::new(
            u64::from(scope.discovery.rate_pps),
            scope.discovery.jitter_pct,
        ),
        status,
        state,
        live_hosts,
        pending: HashMap::new(),
        consecutive_mute: resume_mute,
        mute_reacted: false,
        mute_budget,
        cooldown,
        last_live: resume_last_live,
        last_reply: Instant::now(),
        sport_roll: 0u32,
        overflows: 0,
        undecoded: 0,
        live_events: 0,
        settle_in: 0,
        progress_at: Instant::now(),
        progress_sent: resume_sent,
        started: Instant::now(),
        interrupted: false,
    };

    let code = eng.stream();
    eng.finalize(code)?;
    Ok(code)
}

struct Engine<'a> {
    scan: &'a Targets,
    run_dir: std::path::PathBuf,
    log: std::fs::File,
    stage: Stage,
    files: StageFiles,
    /// Human label for logs and the footer: `sweep 2/3` or `expand`.
    label: String,
    db: &'a mut Db,
    skip: Arc<RoaringBitmap>,
    /// Perimeter set the finalize ip list is clamped to (DB history can hold
    /// up hosts outside the current scope after a contract change).
    clamp: &'a Targets,
    /// Run+stage salt XORed into the sequence cookie (see run()).
    cookie_key: u32,
    ports: Vec<u16>,
    ports_n: u64,
    block: u32,
    total_probes: u64,
    perm: HostPerm,
    sender: Sender,
    receiver: Receiver,
    live_log: LiveLog,
    bucket: TokenBucket,
    /// Live footer shared with the renderer thread (inert without a TTY).
    status: Arc<crate::tui::Status>,
    state: EngineState,
    live_hosts: BTreeSet<u64>,
    pending: HashMap<u64, Pending>,
    consecutive_mute: u64,
    mute_reacted: bool,
    /// Live consecutive-mute budget: starts at the scope's mute_abort_after,
    /// doubles on every re-probe that proves the stretch was merely empty,
    /// 0 = kill-switch disabled (scope).
    mute_budget: u64,
    cooldown: Duration,
    /// Re-probe target of the mute path; persisted as `last_live_idx` in the
    /// state writes so a resume can rebuild it (IP via `scan.nth`).
    last_live: Option<(u64, Ipv4Addr)>,
    last_reply: Instant,
    sport_roll: u32,
    overflows: u64,
    undecoded: u64,
    live_events: u64,
    settle_in: u32,
    progress_at: Instant,
    progress_sent: u64,
    started: Instant,
    interrupted: bool,
}

impl<'a> Engine<'a> {
    /// The send/drain loop. Returns the exit code: 0 finished (or ^C, resumable),
    /// 2 aborted on suspected filtering.
    fn stream(&mut self) -> i32 {
        let mut cursor = self.state.cursor;
        let mut suspicious = false;
        // Locals so the send loop holds no borrow of `self` while servicing replies.
        let block_order: Vec<u32> = self.perm.block_order().to_vec();
        let ports = self.ports.clone();

        'outer: for (bli, &bid) in block_order
            .iter()
            .enumerate()
            .skip(cursor.block_list_pos as usize)
        {
            let hosts = self.perm.shuffle_block(bid);
            let inner_from = if bli as u64 == cursor.block_list_pos {
                cursor.inner as usize
            } else {
                0
            };
            for (hi, &local) in hosts.iter().enumerate().skip(inner_from) {
                let host_idx = u64::from(bid) * u64::from(self.block) + u64::from(local);
                let ip = self.scan.nth(host_idx).expect("host index within targets");
                // Fresh verdict in the DB (skip_done / retry window): the host
                // is probed nowhere, but the cursor still advances past it, so
                // a resume stays deterministic even if the skip set grew.
                if self.skip.contains(u32::from(ip)) {
                    continue;
                }
                let src = match self.sender.source_ip_for(ip) {
                    Ok(s) => s,
                    Err(e) => {
                        state::log_line(
                            &mut self.log,
                            &format!("no route to {ip}: {e} - host skipped"),
                        );
                        continue;
                    }
                };
                let port_from = if bli as u64 == cursor.block_list_pos && hi as u32 == cursor.inner
                {
                    cursor.port as usize
                } else {
                    0
                };
                self.pending.entry(host_idx).or_insert(Pending {
                    first_sent: Instant::now(),
                    replies: 0,
                });

                for (pi, &port) in ports.iter().enumerate().skip(port_from) {
                    if ABORT.load(Ordering::Relaxed) {
                        self.interrupted = true;
                        break 'outer;
                    }
                    // `p` on the keyboard: hold the stream here until `p`
                    // again or `q` (^C path). The receiver keeps servicing
                    // during the hold — a long pause must not fill the
                    // kernel receive queue and turn waiting replies into
                    // false no_response verdicts. Cooldown stays off inside
                    // the hold; the post-pause service re-checks the budget.
                    while crate::tui::paused() && !ABORT.load(Ordering::Relaxed) {
                        if !self.service(false) {
                            suspicious = true;
                            self.interrupted = true;
                            break 'outer;
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    if !self.service(true) {
                        suspicious = true;
                        self.interrupted = true;
                        break 'outer;
                    }
                    let ms = self.bucket.ms_until_token();
                    if ms > 0 {
                        self.receiver.wait(ms);
                    }
                    if !self.bucket.wait_take(&ABORT) {
                        self.interrupted = true;
                        break 'outer;
                    }
                    self.sport_roll = self.sport_roll.wrapping_add(1);
                    let sport = 20_000 + (self.sport_roll % 2048) as u16;
                    let seq =
                        encoder::encode(host_idx * self.ports_n + pi as u64) ^ self.cookie_key;
                    match self.sender.send_syn(src, ip, sport, port, seq) {
                        Ok(()) => {
                            self.state.sent += 1;
                            // Only a probe handed to the kernel advances the
                            // cursor — a transient ENOBUFS must be retried by
                            // the resume replay, never skipped.
                            cursor = Cursor {
                                block_list_pos: bli as u64,
                                inner: hi as u32,
                                port: pi as u32 + 1,
                            };
                        }
                        Err(e) => self.send_err(&e),
                    }
                }
            }
            cursor = Cursor {
                block_list_pos: bli as u64 + 1,
                inner: 0,
                port: 0,
            };
            self.state.cursor = cursor;
            self.state.since_reply = self.consecutive_mute;
            self.state.mute_budget = self.mute_budget;
            self.state.last_live_idx = self.last_live.map(|(idx, _)| idx);
            self.state.mute_budget = self.mute_budget;
            if let Err(e) = state::write_state(self.run_dir.as_path(), &self.files, &self.state) {
                state::log_line(&mut self.log, &format!("state write failed: {e}"));
            }
        }

        if self.interrupted && !suspicious {
            // ^C: drain briefly, keep the exact cursor, leave resumable.
            // allow_cooldown=false: the mute path must not fire mid-drain.
            let until = Instant::now() + Duration::from_secs(2);
            while Instant::now() < until {
                self.receiver.wait(50);
                self.service(false);
            }
            state::log_line(
                &mut self.log,
                "interrupted - state saved, rerun with --resume",
            );
        } else if !suspicious {
            // normal end: collect the stragglers, then settle everyone.
            let hard_end = Instant::now() + END_MAX;
            while Instant::now() < hard_end
                && self.last_reply.elapsed() < END_GRACE
                && !ABORT.load(Ordering::Relaxed)
            {
                self.receiver.wait(50);
                self.service(false);
            }
            if ABORT.load(Ordering::Relaxed) {
                // ^C landed during the end-of-stream drain: the stragglers
                // are still pending, not mute. Mass-settling them would
                // write false no_response rows AND mark the run done —
                // leave resumable like any other interruption instead.
                self.interrupted = true;
                state::log_line(
                    &mut self.log,
                    "interrupted during the end-of-stream drain - state saved, rerun with --resume",
                );
            } else {
                let ids: Vec<u64> = self.pending.keys().copied().collect();
                for id in ids {
                    if let Some(p) = self.pending.remove(&id) {
                        self.settle_host(id, p.replies == 0);
                    }
                }
            }
        }
        self.state.cursor = cursor;
        self.state.since_reply = self.consecutive_mute;
        self.state.mute_budget = self.mute_budget;
        self.state.last_live_idx = self.last_live.map(|(idx, _)| idx);
        if suspicious {
            2
        } else {
            0
        }
    }

    /// Drain replies, settle old pendings, print progress. Returns false when
    /// the mute-abort path decided the network is blocking us. `allow_cooldown`
    /// is false in the drain paths: a mute threshold crossed while flushing a
    /// ^C or the end of the stream must not trigger a 60 s cooldown there.
    fn service(&mut self, allow_cooldown: bool) -> bool {
        if self.receiver.took_overflow() {
            self.overflows += 1;
            state::log_line(
                &mut self.log,
                "kernel receive queue overflowed - replies were lost, treat misses with suspicion",
            );
        }
        let mut batch = Vec::new();
        self.receiver.drain(|r| batch.push(r));
        for r in batch {
            self.handle_reply(r);
        }
        self.settle_in = self.settle_in.wrapping_add(1);
        if self.settle_in.is_multiple_of(256) {
            self.settle();
        }
        if let Err(e) = self.db.flush_if_needed() {
            state::log_line(&mut self.log, &format!("db flush failed: {e}"));
        }
        self.progress();
        if allow_cooldown
            && !self.mute_reacted
            && !ABORT.load(Ordering::Relaxed)
            && self.mute_budget > 0
            && self.consecutive_mute >= self.mute_budget
            && self.last_live.is_some()
        {
            self.mute_reacted = true;
            return self.cooldown_reprobe();
        }
        true
    }

    fn handle_reply(&mut self, r: Reply) {
        // A bare RST (no ACK) carries no cookie — it cannot be matched
        // statelessly, so it counts as noise, never as a live verdict. A
        // real SYN-ACK can legitimately echo any 32-bit ack (exactly one
        // probe index produces ack == 0), so no early-out here.
        if !(r.is_synack() || r.is_rst()) {
            self.undecoded += 1;
            return;
        }
        // A reply to one of our probes echoes our dedicated source-port band
        // (20000..22048); the BPF filter is flags-only, this catches the rest.
        if !(20_000..22_048).contains(&r.dport) {
            self.undecoded += 1;
            return;
        }
        let idx = encoder::decode((r.ack.wrapping_sub(1)) ^ self.cookie_key);
        if idx >= self.total_probes || self.scan.nth(idx / self.ports_n) != Some(r.src) {
            self.undecoded += 1;
            return;
        }
        let host_idx = idx / self.ports_n;
        let port = self.ports[(idx % self.ports_n) as usize];
        let (why, answer) = if r.is_synack() {
            ("synack", Answer::Open)
        } else {
            ("rst", Answer::Closed)
        };
        if self.live_log.record(host_idx, r.src, port, why).is_ok() {
            self.live_events += 1;
        }
        self.db.record_result(r.src, port, self.stage, answer);
        self.live_hosts.insert(host_idx);
        // Late reply after the host already settled (mute most likely): the
        // mute verdict is in the DB buffer — compensate with the up truth.
        // The upsert keeps the fresher of the two, so ordering is safe.
        if !self.pending.contains_key(&host_idx) {
            self.db
                .record_host(r.src, self.stage, true, self.ports_n as u32);
        }
        if let Some(p) = self.pending.get_mut(&host_idx) {
            p.replies += 1;
        }
        self.last_live = Some((host_idx, r.src));
        self.last_reply = Instant::now();
        self.consecutive_mute = 0;
        self.mute_reacted = false;
    }

    fn settle(&mut self) {
        let now = Instant::now();
        let old: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| now.duration_since(p.first_sent) > SETTLE_AFTER)
            .map(|(id, _)| *id)
            .collect();
        for id in old {
            if let Some(p) = self.pending.remove(&id) {
                self.settle_host(id, p.replies == 0);
            }
        }
    }

    /// Records one host's verdict: mute accounting plus the DB row (`up` or
    /// `no_response`), the row the next run's skip set is built from.
    fn settle_host(&mut self, host_idx: u64, muted: bool) {
        let ip = self.scan.nth(host_idx);
        if muted {
            self.consecutive_mute += 1;
            if let Some(ip) = ip {
                self.db
                    .record_host(ip, self.stage, false, self.ports_n as u32);
            }
            if self.last_live.is_none() && self.consecutive_mute.is_multiple_of(4096) {
                state::log_line(
                    &mut self.log,
                    &format!(
                        "{} consecutive mute hosts, no live host seen yet - dark range, continuing (lesson 14: never abort a legitimate sweep)",
                        fmt_count(self.consecutive_mute)
                    ),
                );
            }
        } else {
            if let Some(ip) = ip {
                self.db
                    .record_host(ip, self.stage, true, self.ports_n as u32);
            }
            self.consecutive_mute = 0;
            self.mute_reacted = false;
        }
    }

    /// Lesson 14/17 path: stop sending, re-probe the last host that answered,
    /// and only ride out a cooldown if that probe stays silent. Resume on any
    /// reply; abort only when both volleys fail — our probes are being
    /// filtered, pushing on is pointless.
    fn cooldown_reprobe(&mut self) -> bool {
        let Some((host_idx, ip)) = self.last_live else {
            return true;
        };
        state::log_line(
            &mut self.log,
            &format!(
                "{} consecutive mute hosts after live ones - liveness re-probe {ip} first, {} s cooldown only if it stays silent (lessons 14/17)",
                fmt_count(self.consecutive_mute),
                self.cooldown.as_secs()
            ),
        );
        self.state.since_reply = self.consecutive_mute;
        self.state.mute_budget = self.mute_budget;
        self.state.last_live_idx = self.last_live.map(|(idx, _)| idx);
        if let Err(e) = state::write_state(self.run_dir.as_path(), &self.files, &self.state) {
            state::log_line(&mut self.log, &format!("state write failed: {e}"));
        }
        // The wait exists to ride out a transient block — probing first
        // proves in seconds whether there is one. An answer means nothing
        // was blocking us, and on a legitimately dark range that is almost
        // every fire: waiting would have bought nothing.
        if self.reprobe_volley(host_idx, ip) {
            return true;
        }
        if ABORT.load(Ordering::Relaxed) {
            return true;
        }
        // Silent through the volley: now ride out the configured cooldown —
        // the wait for a transient block the first volley may have missed —
        // and try once more. `s` cuts the wait short.
        state::log_line(
            &mut self.log,
            &format!(
                "re-probe silent - {} s cooldown, then one more volley",
                self.cooldown.as_secs()
            ),
        );
        let deadline = Instant::now() + self.cooldown;
        while Instant::now() < deadline && !ABORT.load(Ordering::Relaxed) {
            // `s` on the keyboard: the operator confirms the network is fine —
            // cut the cooldown short and go straight to the second volley.
            if crate::tui::take_skip() {
                state::log_line(
                    &mut self.log,
                    "cooldown skipped from the keyboard - re-probing now",
                );
                break;
            }
            self.receiver.wait(100);
            let mut batch = Vec::new();
            self.receiver.drain(|r| batch.push(r));
            for r in batch {
                self.handle_reply(r);
            }
            if self.consecutive_mute == 0 {
                self.mute_budget = self.raise_mute_budget();
                state::log_line(
                    &mut self.log,
                    &format!(
                        "replies came back during cooldown - network alive, resuming (mute budget now {})",
                        self.mute_budget
                    ),
                );
                return true;
            }
        }
        if ABORT.load(Ordering::Relaxed) {
            return true;
        }
        if self.reprobe_volley(host_idx, ip) {
            return true;
        }
        if ABORT.load(Ordering::Relaxed) {
            return true;
        }
        state::log_line(
            &mut self.log,
            "sustained silence after a live start - filtering suspected (lesson 15: check our posture before blaming the target); state saved, rerun with --resume",
        );
        false
    }

    /// One liveness volley against the last live host: its best-answered
    /// ports, three rounds. Logs and raises the mute budget on the first
    /// reply, so both call sites resume the same way.
    fn reprobe_volley(&mut self, host_idx: u64, ip: Ipv4Addr) -> bool {
        let src = match self.sender.source_ip_for(ip) {
            Ok(s) => s,
            Err(_) => ip,
        };
        self.pending.insert(
            host_idx,
            Pending {
                first_sent: Instant::now(),
                replies: 0,
            },
        );
        // Re-probe positions in the stream layout: the ranking's
        // most-answered ports that this stream actually covers. With `full`
        // or an arbitrary explicit list, ports[..5] would be ports 1-5 —
        // nothing answers there and a healthy network would "confirm" the
        // filtering verdict.
        let picks: Vec<usize> = {
            let mut v: Vec<usize> = crate::ports::top_n(5)
                .into_iter()
                .filter_map(|p| self.ports.iter().position(|&q| q == p))
                .collect();
            if v.is_empty() {
                v = (0..(self.ports_n as usize).min(5)).collect();
            }
            v
        };
        for _round in 0..3 {
            // ^C wins over the filtering verdict — stay resumable.
            if ABORT.load(Ordering::Relaxed) {
                return false;
            }
            for &pi in &picks {
                self.sport_roll = self.sport_roll.wrapping_add(1);
                let sport = 20_000 + (self.sport_roll % 2048) as u16;
                let seq = encoder::encode(host_idx * self.ports_n + pi as u64) ^ self.cookie_key;
                let _ = self.sender.send_syn(src, ip, sport, self.ports[pi], seq);
            }
            let until = Instant::now() + Duration::from_secs(2);
            while Instant::now() < until && !ABORT.load(Ordering::Relaxed) {
                self.receiver.wait(50);
                let mut batch = Vec::new();
                self.receiver.drain(|r| batch.push(r));
                for r in batch {
                    self.handle_reply(r);
                }
                if self.pending.get(&host_idx).is_some_and(|p| p.replies > 0) {
                    self.mute_budget = self.raise_mute_budget();
                    state::log_line(
                        &mut self.log,
                        &format!(
                            "liveness re-probe answered - the mute stretch was local, resuming (mute budget now {})",
                            self.mute_budget
                        ),
                    );
                    return true;
                }
            }
        }
        false
    }

    /// A proven-false alarm (the re-probe answered): the stretch was merely
    /// empty — double the consecutive-mute budget for the rest of the stage,
    /// capped, so a sparse /8 stops taxing the run while a real filter still
    /// trips the switch.
    fn raise_mute_budget(&mut self) -> u64 {
        self.mute_budget
            .saturating_mul(2)
            .min(crate::discovery::MUTE_BUDGET_MAX)
    }

    fn send_err(&mut self, e: &std::io::Error) {
        match e.raw_os_error() {
            Some(libc::ENOBUFS) | Some(libc::EAGAIN) => {
                // kernel backpressure: brief pause, the token bucket re-paces anyway
                std::thread::sleep(Duration::from_millis(1));
            }
            Some(libc::EHOSTUNREACH) | Some(libc::ENETUNREACH) | Some(libc::EINVAL) => {
                // unroutable target — counted by silence, not fatal
            }
            _ => {
                state::log_line(&mut self.log, &format!("send error: {e}"));
            }
        }
    }

    fn progress(&mut self) {
        // Footer: every service() call — the atomics are free next to the
        // syscall budget; the file log below stays throttled to 5 s.
        let st = Arc::clone(&self.status);
        st.set_done(self.state.sent);
        st.set_up(self.live_hosts.len() as u64);
        st.set_mute(self.consecutive_mute);
        let now = Instant::now();
        let dt = now.duration_since(self.progress_at);
        if dt < Duration::from_secs(5) {
            return;
        }
        let pps = (self.state.sent - self.progress_sent) as f64 / dt.as_secs_f64();
        self.progress_at = now;
        self.progress_sent = self.state.sent;
        st.set_extra(format!("port hits {}", fmt_count(self.live_events)));
        let label = self.label.clone();
        state::log_line(
            &mut self.log,
            &format!(
                "{label} | {} / {} probes | {:.0} pps | live hosts {} ({} port events) | mute {} | undecoded {} | ovf {}",
                fmt_count(self.state.sent),
                fmt_count(self.total_probes),
                pps,
                fmt_count(self.live_hosts.len() as u64),
                fmt_count(self.live_events),
                fmt_count(self.consecutive_mute),
                fmt_count(self.undecoded),
                fmt_count(self.overflows),
            ),
        );
    }

    fn finalize(&mut self, code: i32) -> Result<()> {
        // Verdicts before state: a failed flush must not leave done=true
        // behind — surface the error, the operator reruns with --resume.
        self.db.flush()?;
        self.state.done = code == 0 && !self.interrupted;
        self.state.since_reply = self.consecutive_mute;
        self.state.mute_budget = self.mute_budget;
        self.state.last_live_idx = self.last_live.map(|(idx, _)| idx);
        state::write_state(self.run_dir.as_path(), &self.files, &self.state)?;
        let ips = super::finalize_ip_list(
            self.db,
            self.scan,
            self.clamp,
            self.stage,
            &self.live_hosts,
            &mut self.log,
        )?;
        state::write_ip_list(self.run_dir.as_path(), &self.files, ips.into_iter())?;
        let label = self.label.clone();
        let sent = fmt_count(self.state.sent);
        let live = fmt_count(self.live_hosts.len() as u64);
        let events = fmt_count(self.live_events);
        let mute = fmt_count(self.consecutive_mute);
        let undecoded = fmt_count(self.undecoded);
        let ovf = fmt_count(self.overflows);
        state::log_line(
            &mut self.log,
            &format!(
                "{label} end | {sent} probes sent in {} | live hosts {live} ({events} port events) | mute {mute} | undecoded {undecoded} | ovf {ovf} | evidence: {}",
                crate::util::format_duration(self.started.elapsed()),
                self.run_dir.display(),
            ),
        );
        Ok(())
    }
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
    fn hex_roundtrip() {
        let seed: [u8; 32] = core::array::from_fn(|i| (i * 7 + 3) as u8);
        let mut back = [0u8; 32];
        unhex(&hex(&seed), &mut back);
        assert_eq!(seed, back);
    }

    /// The salted wire path exactly as the engine uses it: seq = encode(idx) ^
    /// run-salt, the stack answers ack = seq+1, decode((ack-1) ^ salt) must
    /// return the probe index for every salt — including the salt that makes
    /// the seq wrap past u32 (the XOR must not break the bijection).
    #[test]
    fn salted_cookie_roundtrip() {
        for key in [0u32, 1, 0xFFFF_FFFF, 0x9E37_79B1, 0xDEAD_BEEF, 0x8000_0000] {
            for idx in [0u64, 1, 42, 1023, u32::MAX as u64 - 2] {
                let seq = encoder::encode(idx) ^ key;
                let ack = seq.wrapping_add(1); // what a SYN-ACK echoes
                assert_eq!(
                    encoder::decode(ack.wrapping_sub(1) ^ key),
                    idx,
                    "salt {key:#010x} corrupted index {idx}"
                );
            }
        }
        // dense sweep under one run-style salt: no aliasing anywhere
        let key = 0x1BAD_B002;
        for idx in (0..200_000u64).step_by(7) {
            let ack = (encoder::encode(idx) ^ key).wrapping_add(1);
            assert_eq!(encoder::decode(ack.wrapping_sub(1) ^ key), idx);
        }
    }

    /// Root-only end-to-end: raw SYN against the loopback stack, an open port
    /// and a closed one, replies decoded through the real BPF-filtered socket.
    /// Run with: sudo cargo test syn_loopback -- --ignored --nocapture
    #[test]
    #[ignore]
    fn syn_loopback() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let open_port = listener.local_addr().unwrap().port();
        let closed_port = open_port ^ 1;

        let mut sender = Sender::open(None).unwrap();
        let mut receiver = Receiver::open(1024 * 1024, None).unwrap();
        let ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let src = sender.source_ip_for(ip).unwrap();
        assert_eq!(src, ip);

        let hits = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        for (pi, &port) in [open_port, closed_port].iter().enumerate() {
            sender
                .send_syn(src, ip, 20123, port, encoder::encode(pi as u64))
                .unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && hits.lock().unwrap().len() < 2 {
            receiver.wait(50);
            let hits = hits.clone();
            receiver.drain(move |r| {
                if r.ack != 0 && (r.is_synack() || r.is_rst()) {
                    let idx = encoder::decode(r.ack.wrapping_sub(1));
                    hits.lock()
                        .unwrap()
                        .push((idx, r.src, r.is_synack(), r.is_rst()));
                }
            });
        }
        let got = hits.lock().unwrap();
        assert_eq!(got.len(), 2, "expected SYN-ACK + RST, got {got:?}");
        assert!(got.iter().any(|&(idx, _, sa, _)| idx == 0 && sa));
        assert!(got.iter().any(|&(idx, _, _, rst)| idx == 1 && rst));
    }
}
