//! Discovery engine orchestration: the perimeter is partitioned into sweep
//! groups (one per `sweep_profiles` entry, in YAML order — first match wins),
//! each group is swept with its own uniform port list, and a single /24
//! expansion pass runs over every live finding. Raw-socket SYN with a
//! TCP-connect fallback, chained by `run_all` over one perimeter.

pub mod bpf;
pub mod classify;
pub mod connect;
pub mod db;
pub mod encoder;
pub mod engine;
pub mod packet;
pub mod perm;
pub mod rate;
pub mod receiver;
pub mod sender;
pub mod state;

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use roaring::RoaringBitmap;

use crate::cli::Mode;
use crate::config;
use crate::targets::{IpRange, Targets};
use crate::util::fmt_count;

use db::Db;

/// Shared shutdown flag — SIGINT (or `q` in the live view) flips it, both
/// engines wind down gracefully.
pub(crate) static ABORT: AtomicBool = AtomicBool::new(false);

pub(crate) extern "C" fn on_sigint(_: libc::c_int) {
    ABORT.store(true, Ordering::Relaxed);
}

/// One partition piece: a contiguous slice of the perimeter swept with a
/// uniform port profile. First matching profile wins; what none covers falls
/// to the default group (`discovery.ports`), always last.
pub struct SweepGroup {
    pub targets: Targets,
    pub ports: config::PortSpec,
    /// Profile range for logs — `192.168.0.0/16`, or `default` for the rest.
    pub label: String,
}

/// Partitions the perimeter into sweep groups. Profiles claim their whole
/// declared range (even the part outside the perimeter) in YAML order, so two
/// overlapping profiles partition cleanly; the remainder forms the default
/// group. No profiles → one group over the whole perimeter.
pub fn sweep_groups(scope: &config::Scope, scan: &Targets) -> Result<Vec<SweepGroup>> {
    let mut claimed: Vec<IpRange> = Vec::new();
    let mut groups = Vec::new();
    for p in &scope.discovery.sweep_profiles {
        let range =
            IpRange::parse(&p.range).with_context(|| format!("sweep profile range {}", p.range))?;
        let piece = Targets::from_ranges(vec![range])
            .subtract(&claimed)
            .intersect(scan);
        if !piece.is_empty() {
            groups.push(SweepGroup {
                targets: piece,
                ports: p.ports.clone(),
                label: p.range.clone(),
            });
        }
        claimed.push(range);
    }
    let rest = scan.subtract(&claimed);
    if !rest.is_empty() {
        groups.push(SweepGroup {
            targets: rest,
            ports: scope.discovery.ports.clone(),
            label: "default".to_string(),
        });
    }
    Ok(groups)
}

/// Everything an engine needs beyond the permutation itself: which stage it
/// runs (and its human label — `sweep 2/3` or `expand`), where its evidence
/// lives, the shared DB, the skip set (hosts with a fresh verdict — probed
/// nowhere, but still advancing the cursor), and the perimeter set the
/// stage's ip list is clamped to at finalize.
pub struct StageCtx<'a> {
    pub stage: db::Stage,
    pub files: state::StageFiles,
    pub label: String,
    /// 1-based sweep-group index stamped into the state (0 for expand).
    pub group: u32,
    pub groups_total: u32,
    pub db: &'a mut Db,
    pub skip: Arc<RoaringBitmap>,
    pub clamp: &'a Targets,
}

/// Runs the sweep groups then the /24 expansion over `scan` (includes −
/// excludes − passive zones) and returns the process exit code: 0 done (or
/// ^C, resumable), 2 aborted on suspected filtering, anything else via Err.
///
/// Chain semantics: a nonzero stage code stops the chain (the run stays
/// resumable); a skipped stage falls through to the next one.
pub fn run_all(
    scope: &config::Scope,
    scan: &Targets,
    out_root: &Path,
    mode: Mode,
    resume: bool,
    force: bool,
) -> Result<i32> {
    let _lock = state::lock_perimeter(out_root)?;
    if force {
        eprintln!("note: --force rescans everything - the database memory is ignored for this run");
    }
    for z in &scope.sensitive_zones {
        if z.policy == crate::config::Policy::Light {
            eprintln!(
                "warning: sensitive zone {} (light) is probed at the full profile in this version",
                z.range
            );
        }
    }

    // Everything fatal about the configuration is settled before any run
    // directory exists — a failed start leaves no litter behind.
    let block = scope.discovery.block;
    let iface = scope.discovery.interface.as_deref();
    let groups = sweep_groups(scope, scan)?;
    let mut resolved: Vec<(Vec<u16>, u64)> = Vec::with_capacity(groups.len());
    for g in &groups {
        let (ports, n) = resolve_ports(&g.ports, &format!("sweep profile {} ports", g.label))?;
        let probes = g.targets.total().saturating_mul(n);
        if probes > encoder::MAX_PROBES {
            bail!(
                "{} probes in sweep group {} exceed the 32-bit sequence encoder - split the scope",
                fmt_count(probes),
                g.label
            );
        }
        resolved.push((ports, n));
    }

    let syn_available = match mode {
        Mode::Syn => match sender::Sender::open(iface) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => bail!(
                "raw sockets unavailable ({e}) - run as root/CAP_NET_RAW, or use --mode connect"
            ),
            Err(e) => return Err(anyhow::anyhow!("raw send socket: {e}")),
        },
        Mode::Connect => false,
        Mode::Auto => match sender::Sender::open(iface) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "warning: raw sockets unavailable ({e}) - falling back to TCP connect (slower, noisier)"
                );
                false
            }
            Err(e) => return Err(anyhow::anyhow!("raw send socket: {e}")),
        },
    };
    if !syn_available {
        if iface.is_some() {
            eprintln!(
                "warning: discovery.interface is honored in raw mode only - connect mode probes from the routing table"
            );
        }
        if scope.discovery.icmp {
            eprintln!(
                "note: discovery.icmp is set but the ICMP echo pass needs raw sockets - skipped in connect mode"
            );
        }
    }
    if syn_available {
        // Fail fast on a wrong pin: the first perimeter address of EVERY
        // sweep group must be routable before anything is created — a group
        // checked only at run time would be skipped host-by-host ("no
        // route"), complete empty and mark the run done with no evidence.
        let mut probe = sender::Sender::open(iface)?;
        for g in &groups {
            let Some(first) = g.targets.iter().next() else {
                continue;
            };
            if let Err(e) = probe.source_ip_for(first) {
                match iface {
                    Some(name) => bail!(
                        "discovery.interface \"{name}\" has no route to {first} (sweep group {}, {e}) - pin the interface that faces the perimeter, or clear discovery.interface",
                        g.label
                    ),
                    None => bail!(
                        "no route to the perimeter (sweep group {}, first target {first}: {e})",
                        g.label
                    ),
                }
            }
        }
    }

    let mut db = Db::open(out_root)?;
    let retry_after = scope.rescan.no_response_delay()?;
    let recheck_up = scope.rescan.recheck_up_delay()?;
    // --force overrides the registry, and so does skip_done: false — the
    // engines then see the full target set, whatever the DB remembers.
    let use_memory = !force && scope.rescan.skip_done;

    // Fresh verdicts from previous runs: the sweep skip set, over the whole
    // perimeter (each group intersects it with its own targets).
    let skip_a = if use_memory {
        db.skip_set(db::Stage::Sweep, retry_after, recheck_up)?
    } else {
        RoaringBitmap::new()
    };
    let remaining_a = scan.subtract_bitmap(&skip_a);

    // Which pass resumes where: the run directory, and whether the sweep
    // (and at which group) or the expansion is the incomplete part.
    enum Resume {
        Fresh,
        Sweep { group: u32 },
        Expand,
    }
    let (run_dir, how) = if resume {
        let dir = state::find_resumable(out_root)?.with_context(|| {
            format!(
                "no resumable run under {} - start without --resume",
                out_root.display()
            )
        })?;
        // A sweep state may be absent (every group skipped): that run's sweep
        // is complete by definition.
        let a_state = dir
            .join(state::SWEEP_FILES.state)
            .is_file()
            .then(|| state::read_state(&dir, &state::SWEEP_FILES))
            .transpose()?;
        match a_state {
            Some(mut a) if !a.done => {
                // Pre-sweep-profile states recorded a single implicit group
                // as 0/0 — normalize to 1/1 so the partition check sees the
                // shape this build would have written.
                if a.groups_total == 0 && a.group == 0 {
                    a.groups_total = 1;
                    a.group = 1;
                }
                if a.groups_total != groups.len() as u32 {
                    bail!(
                        "the sweep profile partition changed since this run started ({} groups then, {} now) - resuming would remap every recorded index; start without --resume",
                        a.groups_total,
                        groups.len()
                    );
                }
                if a.group == 0 || a.group > a.groups_total {
                    bail!(
                        "corrupt sweep state: group {} of {} - start without --resume",
                        a.group,
                        a.groups_total
                    );
                }
                (dir, Resume::Sweep { group: a.group })
            }
            _ => {
                let b_state = dir
                    .join(state::EXPAND_FILES.state)
                    .is_file()
                    .then(|| state::read_state(&dir, &state::EXPAND_FILES))
                    .transpose()?;
                match b_state {
                    Some(b) if !b.done => (dir, Resume::Expand),
                    _ => bail!(
                        "newest run is already complete - start without --resume for a fresh pass"
                    ),
                }
            }
        }
    } else {
        // Nothing at all to do? Don't create a run directory.
        let up_a = db.up_hosts(&[db::Stage::Sweep])?;
        let nothing = remaining_a.is_empty()
            && (up_a.is_empty() || {
                let b_full = crate::targets::expand_neighborhoods(&up_a, scan);
                b_full
                    .subtract_bitmap(&if use_memory {
                        db.skip_set(db::Stage::Expand, retry_after, recheck_up)?
                    } else {
                        RoaringBitmap::new()
                    })
                    .is_empty()
            });
        if nothing {
            eprintln!("nothing to do - every host has a recent verdict (--force to rescan)");
            return Ok(0);
        }
        (
            state::create_run(out_root, &state::new_run_id())?,
            Resume::Fresh,
        )
    };
    let (resume_sweep_group, resume_expand) = match how {
        Resume::Fresh => (0, false),
        Resume::Sweep { group } => (group, false),
        Resume::Expand => (0, true),
    };
    let run_id = run_dir
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    db.set_run_id(&run_id);

    // ---- sweep groups (the wide pass, one engine run each) ----
    let groups_total = groups.len() as u32;
    for (gi, g) in groups.iter().enumerate() {
        let group_no = gi as u32 + 1;
        if resume_expand || (resume_sweep_group > 0 && group_no < resume_sweep_group) {
            continue; // completed in an earlier pass of this run
        }
        let (ports_g, ports_n_g) = &resolved[gi];
        let label = if groups_total == 1 {
            "sweep".to_string()
        } else {
            format!("sweep {group_no}/{groups_total} ({})", g.label)
        };
        let group_skip = &skip_a & g.targets.as_bitmap();
        let this_group_is_resume = resume_sweep_group == group_no;
        if !this_group_is_resume && group_skip == g.targets.as_bitmap() {
            eprintln!("{label}: every host has a recent verdict - skipped (--force to rescan)");
            continue;
        }
        if !group_skip.is_empty() {
            eprintln!(
                "{label}: skipping {} host(s) with a recent verdict",
                fmt_count(group_skip.len())
            );
        }
        if this_group_is_resume {
            // Refuse resumes that would silently reinterpret the recorded
            // stream: the group's target set, port list or block changed.
            let st = state::read_state(&run_dir, &state::SWEEP_FILES)?;
            let fp = state::fingerprint(g.targets.ranges(), ports_g);
            if st.host_total != g.targets.total()
                || st.ports_n != *ports_n_g
                || st.block != block
                || st.scan_hash != fp
            {
                bail!(
                    "scope or sweep profile changed since this run started - resuming would remap every recorded index; start without --resume"
                );
            }
        }
        let mut ctx = StageCtx {
            stage: db::Stage::Sweep,
            files: state::SWEEP_FILES,
            label,
            group: group_no,
            groups_total,
            db: &mut db,
            skip: Arc::new(group_skip),
            clamp: scan,
        };
        let code = if syn_available {
            engine::run(
                scope,
                &g.targets,
                &run_dir,
                ports_g.clone(),
                this_group_is_resume,
                &mut ctx,
            )?
        } else {
            connect::run(
                scope,
                &g.targets,
                &run_dir,
                ports_g.clone(),
                this_group_is_resume,
                &mut ctx,
            )?
        };
        // ip.txt from the registry: every sweep finding so far, this run's
        // groups and the DB history alike — a group's engine finalize only
        // knows its own stream.
        rewrite_sweep_list(&mut db, &run_dir, scan)?;
        if code != 0 || ABORT.load(Ordering::Relaxed) {
            // ^C or filtering: stop the chain — the run stays resumable. The
            // ABORT check matters because a graceful wind-down still returns
            // exit code 0, and a dead ^C must not chain into the next group.
            return Ok(code);
        }
    }

    // ---- expand (/24 liveness expansion of the sweep findings) ----
    let up_a = db.up_hosts(&[db::Stage::Sweep])?;
    let code_b = if up_a.is_empty() {
        eprintln!("expand: no live host from the sweep - nothing to expand");
        mark_done(&run_dir, &state::EXPAND_FILES);
        write_up_list(&mut db, &run_dir, scan)?;
        0
    } else {
        let b_full = crate::targets::expand_neighborhoods(&up_a, scan);
        let (ports_b, ports_n_b) =
            resolve_ports(&scope.discovery.expand_ports, "discovery.expand_ports")?;
        // The /24 union can dwarf the sweep (each live host pulls up to 253
        // new targets): the 32-bit sequence encoder needs its own headroom.
        if b_full.total().saturating_mul(ports_n_b) > encoder::MAX_PROBES {
            bail!(
                "{} expand probes exceed the 32-bit sequence encoder - split the scope or shrink discovery.expand_ports",
                fmt_count(b_full.total().saturating_mul(ports_n_b))
            );
        }
        if resume_expand {
            // The expand stream is indexed over the expansion of the up set
            // as it was when expand started — a changed DB or profile would
            // remap it.
            let st = state::read_state(&run_dir, &state::EXPAND_FILES)?;
            let fp = state::fingerprint(b_full.ranges(), &ports_b);
            if st.host_total != b_full.total()
                || st.ports_n != ports_n_b
                || st.block != block
                || st.scan_hash != fp
            {
                bail!(
                    "scope, database or expand profile changed since this run started - resuming would remap every recorded index; start without --resume"
                );
            }
        }
        let skip_b = if use_memory {
            db.skip_set(db::Stage::Expand, retry_after, recheck_up)?
        } else {
            RoaringBitmap::new()
        };
        let remaining_b = b_full.subtract_bitmap(&skip_b);
        if !resume_expand && remaining_b.is_empty() {
            eprintln!(
                "expand: every neighborhood host has a recent verdict - skipped (--force to rescan)"
            );
            mark_done(&run_dir, &state::EXPAND_FILES);
            write_up_list(&mut db, &run_dir, scan)?;
            0
        } else {
            if !skip_b.is_empty() {
                eprintln!(
                    "expand: skipping {} host(s) with a recent verdict",
                    fmt_count(skip_b.len())
                );
            }
            let mut ctx = StageCtx {
                stage: db::Stage::Expand,
                files: state::EXPAND_FILES,
                label: "expand".to_string(),
                group: 0,
                groups_total: 0,
                db: &mut db,
                skip: Arc::new(skip_b),
                clamp: scan,
            };
            if syn_available {
                engine::run(scope, &b_full, &run_dir, ports_b, resume_expand, &mut ctx)?
            } else {
                connect::run(scope, &b_full, &run_dir, ports_b, resume_expand, &mut ctx)?
            }
        }
    };

    if let Err(e) = db.flush() {
        eprintln!("warning: final db flush failed: {e}");
    }
    Ok(code_b)
}

/// ip.txt rewritten from the registry: every host up in the sweep, clamped to
/// the current perimeter. Called after each sweep group so the list reflects
/// all groups so far, not just the last engine pass.
fn rewrite_sweep_list(db: &mut Db, run_dir: &Path, scan: &Targets) -> Result<()> {
    let remembered = db.up_hosts(&[db::Stage::Sweep])?;
    let up = &remembered & scan.as_bitmap();
    let mut ips: Vec<u32> = up.iter().collect();
    ips.sort_unstable();
    state::write_ip_list(
        run_dir,
        &state::SWEEP_FILES,
        ips.into_iter().map(std::net::Ipv4Addr::from),
    )
}

/// The stage's ip list, shared by both engines' finalize: plain findings for
/// the sweep; for expand the scan input — every host up in sweep or expand,
/// from this run and the DB history (a host up in a previous expand pass but
/// skipped as fresh this run has no live event here — it must still be
/// listed), clamped to the current perimeter (the DB may remember up hosts a
/// contract change has since excluded).
pub(crate) fn finalize_ip_list(
    db: &mut Db,
    scan: &Targets,
    clamp: &Targets,
    stage: db::Stage,
    live_hosts: &std::collections::BTreeSet<u64>,
    log: &mut std::fs::File,
) -> Result<Vec<std::net::Ipv4Addr>> {
    if stage != db::Stage::Expand {
        return Ok(live_hosts.iter().filter_map(|idx| scan.nth(*idx)).collect());
    }
    let mut bm = db.up_hosts(&[db::Stage::Sweep, db::Stage::Expand])?;
    for idx in live_hosts {
        if let Some(ip) = scan.nth(*idx) {
            bm.insert(u32::from(ip));
        }
    }
    let before = bm.len();
    bm &= clamp.as_bitmap();
    if bm.len() < before {
        state::log_line(
            log,
            &format!(
                "{} up host(s) outside the current perimeter dropped from the ip list",
                fmt_count(before - bm.len())
            ),
        );
    }
    let mut ips: Vec<u32> = bm.iter().collect();
    ips.sort_unstable();
    Ok(ips.into_iter().map(std::net::Ipv4Addr::from).collect())
}

/// Materializes a port profile into the explicit list the engines iterate.
/// "full" (count-only in `PortSpec::resolve`, so dry runs never build it)
/// expands here to 1..=65535 — 128 KiB, bounded by `encoder::MAX_PROBES`
/// checks downstream.
fn resolve_ports(spec: &config::PortSpec, what: &str) -> Result<(Vec<u16>, u64)> {
    match spec.resolve().with_context(|| what.to_string())? {
        (Some(list), n) => Ok((list, n)),
        (None, n) => Ok(((1..=u16::MAX).collect(), n)),
    }
}

/// Marks a leftover pass complete (its whole target set is covered by fresh
/// DB verdicts) so --resume never replays a no-op forever. The pass may have
/// never started — the state file then does not exist, and a minimal
/// done-marker is written so the run is never mistaken for unfinished work.
/// Ceiling for the adaptive mute budget: after enough proven-empty stretches
/// the kill-switch has effectively learned the network's sparsity — beyond
/// this it would never fire again even on a real filter.
pub(crate) const MUTE_BUDGET_MAX: u64 = 65_536;

fn mark_done(run_dir: &Path, files: &state::StageFiles) {
    let mut st = match state::read_state(run_dir, files) {
        Ok(st) => st,
        Err(_) => state::EngineState {
            schema: state::STATE_SCHEMA,
            seed_hex: "skipped".into(),
            host_total: 0,
            ports_n: 0,
            block: 0,
            scan_hash: 0,
            group: 0,
            groups_total: 0,
            cursor: state::Cursor::default(),
            sent: 0,
            mute_budget: 1024,
            since_reply: 0,
            last_live_idx: None,
            done: true,
        },
    };
    if !st.done {
        st.done = true;
    }
    if let Err(e) = state::write_state(run_dir, files, &st) {
        eprintln!("warning: could not mark {} done: {e}", files.state);
    }
}

/// ip_b.txt: every host up in sweep or expand, clamped to the current
/// perimeter — the scan input. Hosts remembered up but since excluded from
/// the scope (contract change) are dropped here, not silently shipped to
/// nmap.
fn write_up_list(db: &mut Db, run_dir: &Path, clamp: &Targets) -> Result<()> {
    let remembered = db.up_hosts(&[db::Stage::Sweep, db::Stage::Expand])?;
    let up = &remembered & clamp.as_bitmap();
    if up.len() < remembered.len() {
        eprintln!(
            "note: {} up host(s) outside the current perimeter dropped from the scan list",
            fmt_count(remembered.len() - up.len())
        );
    }
    let mut ips: Vec<u32> = up.iter().collect();
    ips.sort_unstable();
    state::write_ip_list(
        run_dir,
        &state::EXPAND_FILES,
        ips.into_iter().map(std::net::Ipv4Addr::from),
    )
}
