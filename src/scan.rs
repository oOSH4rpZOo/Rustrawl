//! The nmap scan: operator-driven fingerprinting over the registry's up list.
//!
//! nmap runs against every host the registry remembers up in discovery (not
//! only hosts with a known-open port — a silent host is exactly what a
//! pentester wants explained), always clamped to the current perimeter. The
//! operator tunes the pass at launch time: free-form nmap arguments
//! (`--nmap-args` or `scan.nmap_args`, spliced verbatim into rustrawl's
//! fixed frame — the port list rides in them: `-p-`, `-p 21,22`,
//! `--exclude-ports`; no `-p` means nmap's own default, the top 1000 TCP
//! ports), thread count.
//!
//! The queue is chunked (CHUNK_HOSTS hosts per nmap process), ordered
//! rich-hosts-first (known open-port counts), and crash-safe: every finished
//! chunk is recorded in `scan_state.json` (atomic rename), so --resume
//! continues the queue without re-scanning done chunks. Every open port nmap
//! finds lands in the registry as a scan results row, and in the `services`
//! table (service name + version from the banner).
//!
//! Run directories are named `scan_<date>_<time>` so `runs/` shows scans
//! apart from discovery passes (`discovery_<date>_<time>`; each command's
//! resume only ever picks its own kind).
//!
//! Test seam: `RUSTRAWL_NMAP_BIN` overrides the binary path (production
//! installs just need nmap; the override exists so the queue machinery can
//! be exercised without it).

use std::collections::VecDeque;
use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;

use anyhow::{bail, Context, Result};
use roaring::RoaringBitmap;
use serde::{Deserialize, Serialize};

use crate::cli::ScanArgs;
use crate::config;
use crate::targets::Targets;
use crate::util::fmt_count;

use crate::discovery::db::{Answer, Db, Stage};
use crate::discovery::{on_sigint, state, ABORT};
use crate::tui::{ChunkViz, Footer, Screen, TAIL_LINES};

/// Hosts per nmap invocation — the resume granularity, balanced against
/// nmap's per-process startup cost.
const CHUNK_HOSTS: usize = 32;

/// One open port as parsed from a .gnmap line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPort {
    pub port: u16,
    pub service: String,
    pub version: String,
}

/// A host line of a .gnmap file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnmapHost {
    pub ip: Ipv4Addr,
    pub ports: Vec<OpenPort>,
}

// --------------------------------------------------------------- scan state

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ScanState {
    /// Legacy field, always written `[]`: the port list moved into the
    /// nmap args. Kept so pre-rework `scan_state.json` files keep parsing
    /// (resume, evidence, fixtures); a loaded state with non-empty ports
    /// is a pre-rework queue — adoption re-pins it.
    ports: Vec<u16>,
    /// Pinned: a queue started with -sC -sV resumed with --nmap-args "-sV"
    /// would silently lighten the remaining chunks.
    nmap_args: String,
    /// FNV over the profile table + the queued host list (same role as the
    /// engines' scan_hash): a changed registry, scope or CLI must not remap
    /// the queue. Single-default plans reuse the pre-profiles recipe, so
    /// old state files stay resumable.
    queue_hash: u64,
    /// One entry per group that queued ≥1 host, dispatch order. `label` is
    /// the profile's range as declared, or "default" for the remainder.
    /// Always non-empty after `read_scan_state` (old files normalize) and
    /// on fresh construction.
    #[serde(default)]
    profiles: Vec<StateProfile>,
    /// The `--only-profile` labels this queue was built with — re-applied
    /// on resume (the state, not the CLI, is authoritative for the filter).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    only: Vec<String>,
    pub(crate) chunks: Vec<Chunk>,
    done: bool,
}

/// One scan group as pinned in the state: resolved values, compared on
/// resume (a scope edit that changes a label or its args forks the plan).
/// `ports` is legacy — always `[]` on fresh writes; non-empty only on a
/// pre-rework queue, until adoption re-pins it.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub(crate) struct StateProfile {
    pub(crate) label: String,
    pub(crate) ports: Vec<u16>,
    pub(crate) nmap_args: String,
}

impl ScanState {
    /// Index of the first chunk whose host list holds `ip` (dotted quad) —
    /// the registry has no ip→chunk column, the state file is the map.
    pub(crate) fn chunk_of(&self, ip: &str) -> Option<usize> {
        self.chunks
            .iter()
            .position(|c| c.hosts.iter().any(|h| h == ip))
    }

    /// nmap args chunk `idx` runs with. Invariant: `profiles` is
    /// non-empty (normalized on read, ≥1 on construction); an index past
    /// the end (hand-edited state) falls back to the first profile rather
    /// than panicking mid-scan.
    fn chunk_profile(&self, idx: usize) -> &str {
        let p = self
            .profiles
            .first()
            .zip(self.profiles.get(self.chunks[idx].profile))
            .map(|(_, p)| p)
            .or_else(|| self.profiles.first());
        match p {
            Some(p) => &p.nmap_args,
            // Unreachable outside a hand-edited state (normalize guarantees
            // one entry); the legacy field keeps the answer honest anyway.
            None => &self.nmap_args,
        }
    }

    /// The group label a chunk runs under — the live chunk view shows it,
    /// so the operator sees the printer chunk really is running top10.
    fn chunk_label(&self, idx: usize) -> &str {
        self.profiles
            .get(self.chunks[idx].profile)
            .map(|p| p.label.as_str())
            .unwrap_or("default")
    }

    /// Old state files have no `profiles`: synthesize the single default
    /// from the pinned ports/args so `chunk.profile = 0` resolves. The
    /// legacy ports ride along so adoption can still see them.
    fn normalize_profiles(&mut self) {
        if self.profiles.is_empty() {
            self.profiles.push(StateProfile {
                label: "default".into(),
                ports: self.ports.clone(),
                nmap_args: self.nmap_args.clone(),
            });
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Chunk {
    /// Dotted-quad strings: the state file is evidence, read by humans.
    pub(crate) hosts: Vec<String>,
    done: bool,
    /// nmap invocations this chunk has seen — kills from the keyboard count,
    /// so a chunk that keeps getting killed shows in the stats.
    #[serde(default)]
    attempts: u32,
    /// Killed from the keyboard and left unscanned: reported at the end,
    /// requeued by the next `scan --resume`.
    #[serde(default)]
    skipped: bool,
    /// Index into `ScanState::profiles` — which group's ports/args this
    /// chunk runs with. Chunks never straddle a group.
    #[serde(default)]
    profile: usize,
}

/// FNV-1a over the nmap arguments and the queued hosts, in order. The
/// port list is gone from the recipe (it rides in the args); pre-rework
/// states are adopted rather than hash-matched, so no port fold remains.
fn queue_hash(nmap_args: &str, hosts: &[u32]) -> u64 {
    const BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x100_0000_01b3;
    let mut h = BASIS;
    let mut fold = |bytes: &[u8]| {
        for &b in bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(PRIME);
        }
    };
    fold(nmap_args.as_bytes());
    fold(b"|");
    for host in hosts {
        fold(&host.to_le_bytes());
    }
    h
}

/// FNV-1a over the group table then the queued hosts, in chunk order: per
/// profile fold `G`, label, `|`, args, `|`; then `H` and the hosts in
/// order. The flat host list plus the group table pins the whole plan —
/// chunks are cut per group at CHUNK_HOSTS, so the chunk→profile mapping
/// is derived, never hashed separately.
fn queue_hash_grouped(profiles: &[StateProfile], hosts: &[u32]) -> u64 {
    const BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x100_0000_01b3;
    let mut h = BASIS;
    let mut fold = |bytes: &[u8]| {
        for &b in bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(PRIME);
        }
    };
    for p in profiles {
        fold(b"G");
        fold(p.label.as_bytes());
        fold(b"|");
        fold(p.nmap_args.as_bytes());
        fold(b"|");
    }
    fold(b"H");
    for host in hosts {
        fold(&host.to_le_bytes());
    }
    h
}

/// The queue hash for a plan. A single-default plan (no profile applies —
/// the historical shape) uses the flat recipe verbatim; "default" can only
/// name the remainder group (a profile's label is its range string, and
/// `IpRange::parse("default")` fails), so the shape is unambiguous.
fn queue_hash_plan(profiles: &[StateProfile], hosts: &[u32]) -> u64 {
    if profiles.len() == 1 && profiles[0].label == "default" {
        queue_hash(&profiles[0].nmap_args, hosts)
    } else {
        queue_hash_grouped(profiles, hosts)
    }
}

// --------------------------------------------------------------- nmap frame

fn nmap_bin() -> Result<String> {
    if let Ok(b) = std::env::var("RUSTRAWL_NMAP_BIN") {
        return Ok(b);
    }
    Ok("nmap".into())
}

/// The nmap argv for one chunk — a pure function so tests can pin the flags
/// without spawning anything. The frame is rustrawl's: -Pn (the registry
/// says these hosts are up — skip discovery), -n (never resolve names
/// against the client's DNS), --open, -oA evidence base, then the
/// root-dependent scan type (-sS under root, else -sT), then the periodic
/// stats heartbeat (ticks the captured output even on quiet chunks — the
/// live chunk view reads it), then the operator's arguments verbatim, then
/// the hosts. The output files and the target list stay rustrawl's; the
/// port list is the operator's (`-p-`, `-p 21,22`, `--exclude-ports` ride
/// in the args verbatim) — no `-p` means nmap's own default, the top 1000
/// TCP ports.
fn nmap_argv(bin: &str, nmap_args: &str, gnmap_base: &Path, hosts: &[String]) -> Vec<String> {
    let mut argv = vec![
        bin.to_string(),
        "-Pn".into(),
        "-n".into(),
        "--open".into(),
        "-oA".into(),
        gnmap_base.display().to_string(),
    ];
    argv.push(if is_root() { "-sS" } else { "-sT" }.to_string());
    argv.push("--stats-every".into());
    argv.push("30s".into());
    argv.extend(nmap_args.split_whitespace().map(str::to_string));
    argv.extend(hosts.iter().cloned());
    argv
}

fn is_root() -> bool {
    // SAFETY: geteuid takes no arguments and never fails.
    unsafe { libc::geteuid() == 0 }
}

// --------------------------------------------------------- scan profiles

/// One partition piece of the perimeter, scanned as a unit: a profile
/// range's hosts (or the default remainder) with a uniform nmap args line
/// — the port list rides inside them. Mirrors `discovery::SweepGroup`.
pub(crate) struct ScanGroup {
    pub(crate) targets: Targets,
    pub(crate) nmap_args: String,
    /// The profile's range as declared, or "default" for the remainder —
    /// also the `--only-profile` label.
    pub(crate) label: String,
    /// The claimed range (the default group claims everything — its label
    /// is what `--only-profile` matches, the range is a fallback).
    pub(crate) range: crate::targets::IpRange,
    /// Where the args come from, for the dry run and the run log:
    /// `--profile`, `scan.profiles[i]`, or `baseline (--nmap-args)` /
    /// `baseline (scan.nmap_args)`.
    pub(crate) provenance: String,
}

/// Partitions the perimeter into scan groups: CLI `--profile` entries
/// first, then the scope's `scan.profiles`; first match wins; empty pieces
/// are claimed but skipped; the remainder is the default group (baseline
/// args), always last. Declaration order is dispatch order — the groups
/// you want covered before a ^C go first in the YAML. No profiles → one
/// group over the whole perimeter, byte-identical to the pre-profiles
/// queue.
pub(crate) fn scan_groups(
    scope: &config::Scope,
    cli_profiles: &[config::ScanProfile],
    scan: &Targets,
    baseline_args: &str,
    baseline_provenance: &str,
) -> Result<Vec<ScanGroup>> {
    let mut claimed: Vec<crate::targets::IpRange> = Vec::new();
    let mut groups = Vec::new();
    let entries = cli_profiles
        .iter()
        .map(|p| (p, "--profile".to_string()))
        .chain(
            scope
                .scan
                .profiles
                .iter()
                .enumerate()
                .map(|(i, p)| (p, format!("scan.profiles[{i}]"))),
        );
    for (p, prov) in entries {
        let range = crate::targets::IpRange::parse(&p.range)
            .with_context(|| format!("scan profile range {}", p.range))?;
        let piece = Targets::from_ranges(vec![range])
            .subtract(&claimed)
            .intersect(scan);
        if !piece.is_empty() {
            groups.push(ScanGroup {
                targets: piece,
                nmap_args: p
                    .nmap_args
                    .clone()
                    .unwrap_or_else(|| baseline_args.to_string()),
                label: p.range.clone(),
                range,
                provenance: prov,
            });
        }
        claimed.push(range);
    }
    let rest = scan.subtract(&claimed);
    if !rest.is_empty() {
        groups.push(ScanGroup {
            targets: rest,
            nmap_args: baseline_args.to_string(),
            label: "default".to_string(),
            range: crate::targets::IpRange {
                start: 0,
                end: u32::MAX,
            },
            provenance: baseline_provenance.to_string(),
        });
    }
    Ok(groups)
}

/// Per-group view of a built plan — the dry run's and the run log's lines.
pub(crate) struct GroupPlan {
    pub(crate) label: String,
    pub(crate) hosts: u64,
    pub(crate) chunks: usize,
    pub(crate) provenance: String,
    pub(crate) nmap_args: String,
}

/// The queue a run will drive: pinned profiles, chunks (never straddling a
/// group), and the flat host list in chunk order. Pure — a fresh start and
/// the resume drift check build the identical plan.
struct ScanPlan {
    /// Groups that queued ≥1 host, dispatch order (the state's `profiles`).
    profiles: Vec<StateProfile>,
    /// Profile index per input group (`None` = queued nothing) — resume
    /// re-pinning maps a pending chunk's first host through this.
    group_profile: Vec<Option<usize>>,
    chunks: Vec<Chunk>,
    /// Queued hosts in chunk order (the queue-hash fold order).
    hosts: Vec<u32>,
    /// Per group, in input order (selected or not): the dry-run lines.
    groups: Vec<GroupPlan>,
}

/// Does `want` (a `--only-profile` entry) select group `g`? The literal
/// `default` names the remainder group; otherwise the entry matches a
/// group's label as declared, or parses to the same range (`10.10.4.17`
/// matches a `/32` entry).
fn only_matches(g: &ScanGroup, want: &str) -> bool {
    if want == g.label {
        return true;
    }
    g.label != "default"
        && crate::targets::IpRange::parse(want)
            .map(|r| r == g.range)
            .unwrap_or(false)
}

/// Resolves nothing — the args ride as declared — sorts hosts rich-first
/// WITHIN the group, and cuts per-group chunks pinning their profile
/// index.
fn build_plan(
    ups: &[u32],
    groups: &[ScanGroup],
    open_counts: &std::collections::HashMap<u32, u32>,
    only: &[String],
) -> Result<ScanPlan> {
    // The selection is validated against every declared group (zero-up-host
    // groups included) before anything is filtered — a typo must stop the
    // run, not silently scan everything.
    for want in only {
        if !groups.iter().any(|g| only_matches(g, want)) {
            let labels = groups
                .iter()
                .map(|g| g.label.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            bail!("unknown profile label \"{want}\" - declared: {labels}");
        }
    }
    let ups_bm: RoaringBitmap = ups.iter().copied().collect();
    let mut plan = ScanPlan {
        profiles: Vec::new(),
        group_profile: Vec::with_capacity(groups.len()),
        chunks: Vec::new(),
        hosts: Vec::new(),
        groups: Vec::with_capacity(groups.len()),
    };
    for g in groups {
        let selected = only.is_empty() || only.iter().any(|w| only_matches(g, w));
        // Membership only: no port resolution left — the args ride as
        // declared.
        let mine: Vec<u32> = if selected {
            let mine = &ups_bm & g.targets.as_bitmap();
            let mut mine: Vec<u32> = mine.iter().collect();
            // Rich hosts first within the group (the pre-profiles queue's
            // ordering, applied per group), IP-ascending tie-break for a
            // deterministic order the queue hash pins across resumes.
            mine.sort_by(|a, b| {
                let ca = open_counts.get(a).copied().unwrap_or(0);
                let cb = open_counts.get(b).copied().unwrap_or(0);
                cb.cmp(&ca).then(a.cmp(b))
            });
            mine
        } else {
            Vec::new()
        };
        if mine.is_empty() {
            plan.group_profile.push(None);
            if selected {
                plan.groups.push(GroupPlan {
                    label: g.label.clone(),
                    hosts: 0,
                    chunks: 0,
                    provenance: g.provenance.clone(),
                    nmap_args: g.nmap_args.clone(),
                });
            }
            continue;
        }
        let profile_idx = plan.profiles.len();
        plan.profiles.push(StateProfile {
            label: g.label.clone(),
            ports: Vec::new(),
            nmap_args: g.nmap_args.clone(),
        });
        plan.group_profile.push(Some(profile_idx));
        let chunk_count = mine.len().div_ceil(CHUNK_HOSTS);
        for chunk_hosts in mine.chunks(CHUNK_HOSTS).map(<[u32]>::to_vec) {
            plan.hosts.extend_from_slice(&chunk_hosts);
            plan.chunks.push(Chunk {
                hosts: chunk_hosts
                    .iter()
                    .map(|ip| Ipv4Addr::from(*ip).to_string())
                    .collect(),
                done: false,
                attempts: 0,
                skipped: false,
                profile: profile_idx,
            });
        }
        plan.groups.push(GroupPlan {
            label: g.label.clone(),
            hosts: mine.len() as u64,
            chunks: chunk_count,
            provenance: g.provenance.clone(),
            nmap_args: g.nmap_args.clone(),
        });
    }
    Ok(plan)
}

// ------------------------------------------------------------ gnmap parser

/// Parses one .gnmap file. Lines look like (fields separated by TABs):
/// `Host: 10.0.0.5 () <TAB> Status: Up`
/// `Host: 10.0.0.5 () <TAB> Ports: 22/open/tcp//ssh//OpenSSH 8.4p1, 80/open/tcp//http//nginx`
/// Service and version are separated from the triple by `//`; the version
/// itself may contain slashes, so only the first two `//` are split.
pub fn parse_gnmap(text: &str) -> Vec<GnmapHost> {
    let mut out: Vec<GnmapHost> = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("Host: ") else {
            continue;
        };
        let Some((ip_s, tail)) = rest.split_once(' ') else {
            continue;
        };
        let Ok(ip) = ip_s.parse::<Ipv4Addr>() else {
            continue;
        };
        let Some(fields) = tail.split('\t').find(|f| f.starts_with("Ports: ")) else {
            continue;
        };
        let ports_field = &fields["Ports: ".len()..];
        let mut ports = Vec::new();
        for piece in ports_field.split(", ") {
            let mut it = piece.splitn(3, "//");
            let head = it.next().unwrap_or("");
            let service = it.next().unwrap_or("").to_string();
            let version = it.next().unwrap_or("").to_string();
            let mut h = head.split('/');
            let (Some(port_s), Some(state_s)) = (h.next(), h.next()) else {
                continue;
            };
            let Ok(port) = port_s.parse::<u16>() else {
                continue;
            };
            if state_s != "open" {
                continue;
            }
            ports.push(OpenPort {
                port,
                service,
                version,
            });
        }
        out.push(GnmapHost { ip, ports });
    }
    out
}

// ------------------------------------------------------------------- run

/// The chunk's exact command line, one line, next to its captures — every
/// recorded run can show what actually ran. Tokens carry no spaces (the
/// operator args were whitespace-split), so the join is lossless. Written
/// per spawn: a requeued chunk restamps its command, like its captures.
fn write_chunk_argv(scans_dir: &Path, idx: usize, argv: &[String]) -> Result<()> {
    let path = scans_dir.join(format!("chunk-{idx:04}.argv"));
    std::fs::write(&path, format!("{}\n", argv.join(" ")))
        .with_context(|| format!("writing {}", path.display()))
}

/// Spawns one nmap process for chunk `idx`. Children inherit our working
/// directory, so every path we hand them (and later re-read) resolves the
/// same way.
fn spawn_chunk(
    bin: &str,
    nmap_args: &str,
    chunk: &Chunk,
    idx: usize,
    scans_dir: &Path,
    log: &mut File,
) -> Result<Child> {
    let base = scans_dir.join(format!("chunk-{idx:04}"));
    let argv = nmap_argv(bin, nmap_args, &base, &chunk.hosts);
    write_chunk_argv(scans_dir, idx, &argv)?;
    let (prog, rest) = argv.split_first().expect("argv holds the binary");
    let attempt = if chunk.attempts > 0 {
        format!(" (attempt {})", chunk.attempts + 1)
    } else {
        String::new()
    };
    state::log_line(
        log,
        &format!(
            "chunk {idx:04}{attempt}: nmap over {} host(s)",
            chunk.hosts.len()
        ),
    );
    // stdout+stderr stream into one capture file next to the evidence: the
    // live chunk view tails it, and the operator can `tail -f` it from
    // another terminal to watch nmap work. Truncated per spawn — a requeued
    // chunk restarts its capture, like its evidence files.
    let out_path = scans_dir.join(format!("chunk-{idx:04}.out"));
    let out_file =
        File::create(&out_path).with_context(|| format!("capturing {}", out_path.display()))?;
    Command::new(prog)
        .args(rest)
        .stdout(Stdio::from(
            out_file
                .try_clone()
                .context("sharing the chunk capture file")?,
        ))
        .stderr(Stdio::from(out_file))
        .spawn()
        .with_context(|| {
            format!("spawning {prog} - is nmap installed? (RUSTRAWL_NMAP_BIN overrides)")
        })
}

/// Parses chunk `idx`'s .gnmap, records every open port as a scan results row
/// plus a services row (banner inventory), and marks the chunk done in the
/// queue state.
fn ingest_chunk(
    db: &mut Db,
    scans_dir: &Path,
    idx: usize,
    st: &mut ScanState,
    log: &mut File,
) -> Result<()> {
    ingest_gnmap(db, scans_dir, idx, log)?;
    st.chunks[idx].done = true;
    Ok(())
}

// ----------------------------------------------------------- manual rescan

/// Wall-clock cap on one dashboard-triggered rescan. A single host is
/// minutes of work even with scripts and version detection; past this the
/// nmap process is killed and the operator gets the capture path.
const MANUAL_SCAN_CAP: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// The same brake for a multi-host batch. A killed run ingests nothing,
/// so an undersized cap would throw away whole legitimate batches — a
/// /24 with `-sC -sV -p-` legitimately outlives the single-host cap; the
/// stop button stays the escape hatch.
const MANUAL_SCAN_CAP_MULTI: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// Backstop on a batch rescan's host count. Bigger jobs belong to the
/// `scan` queue with its per-range profiles, not to one dashboard POST.
pub(crate) const MANUAL_SCAN_MAX_HOSTS: usize = 1024;

/// The run id of the newest manual rescan, set the moment its run directory
/// exists and left set after it finishes — the dashboard's live-output
/// endpoint reads this to find `scans/chunk-0000.out`, and keeping it after
/// completion means a page that navigated away still recovers the tail until
/// the next scan overwrites it. Last writer wins: the SCANNING gate makes
/// dashboard rescans exclusive, and the console's `hosts -r` writes it too.
pub(crate) static CURRENT_MANUAL_RUN: std::sync::Mutex<Option<String>> =
    std::sync::Mutex::new(None);

/// The manual frame's verbosity: `-v` makes nmap report each host as it
/// completes instead of holding the whole report for the end, which is what
/// the rescan tab's live output actually shows. Skipped when the operator's
/// args already ask for verbosity. Queue runs keep their own frame — their
/// console output is the TUI's business.
fn manual_frame_args(nmap_args: &str) -> String {
    let verbose = nmap_args
        .split_whitespace()
        .any(|a| a == "-v" || a == "-vv" || a == "-vvv" || a == "--verbose");
    if verbose {
        nmap_args.to_string()
    } else {
        format!("{nmap_args} -v")
    }
}

/// What one manual rescan produced.
pub(crate) struct ManualScan {
    pub run_id: String,
    /// (port, service, version) of every open port nmap reported.
    pub open: Vec<(u16, String, String)>,
}

/// One operator-triggered rescan (the dashboard's POST /api/scan and the
/// console's `hosts -r`): nmap once over the given hosts — usually one,
/// a batch for the dashboard's range and result-set rescans — the
/// operator's arguments spliced into rustrawl's frame, the evidence in
/// its own `manual_<date>_<time>` run directory and the rows ingested
/// through the same core as a queue chunk. One nmap process either way:
/// nmap parallelizes internally, so a batch never fans out into chunks.
/// The frame adds `-v` (see `manual_frame_args`) so the captured
/// `chunk-0000.out` reports each host live; the run id lands in
/// `CURRENT_MANUAL_RUN` for the dashboard's output tail.
/// Synchronous — the caller's thread waits — and serialized by the
/// perimeter lock, so a rescan never overlaps a real run.
pub(crate) fn manual_scan(out: &Path, ips: &[Ipv4Addr], nmap_args: &str) -> Result<ManualScan> {
    debug_assert!(!ips.is_empty(), "a rescan needs at least one host");
    if ips.len() > MANUAL_SCAN_MAX_HOSTS {
        bail!(
            "{} host(s) is past the {}-host rescan ceiling - bigger jobs belong to `rustrawl scan` with its profiles",
            ips.len(),
            MANUAL_SCAN_MAX_HOSTS
        );
    }
    let _lock = state::lock_perimeter(out)?;
    let run_id = state::stamped_id("manual");
    let run_dir = state::create_run(out, &run_id)?;
    // The real id (same-second collisions suffix -2) goes up for the
    // dashboard's live tail before any nmap byte moves.
    *CURRENT_MANUAL_RUN.lock().expect("manual run id mutex") = Some(run_id.clone());
    let scans_dir = run_dir.join("scans");
    std::fs::create_dir_all(&scans_dir)
        .with_context(|| format!("creating {}", scans_dir.display()))?;
    let log_path = run_dir.join("run.log");
    let mut log =
        File::create(&log_path).with_context(|| format!("opening {}", log_path.display()))?;
    state::log_line(
        &mut log,
        &format!(
            "manual rescan of {} host(s): nmap args {nmap_args:?}",
            ips.len()
        ),
    );

    // The evidence map first: a crash mid-scan leaves a state file that
    // says the chunk is not done, and locate_host_chunk can already see
    // the run (its chunk carries the host).
    let hosts: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
    let u32s: Vec<u32> = ips.iter().map(|ip| u32::from(*ip)).collect();
    let mut st = ScanState {
        ports: Vec::new(),
        nmap_args: nmap_args.to_string(),
        queue_hash: queue_hash(nmap_args, &u32s),
        profiles: vec![StateProfile {
            label: "manual".into(),
            ports: Vec::new(),
            nmap_args: nmap_args.to_string(),
        }],
        only: Vec::new(),
        chunks: vec![Chunk {
            hosts,
            done: false,
            attempts: 0,
            skipped: false,
            profile: 0,
        }],
        done: false,
    };
    write_scan_state(&run_dir, &st)?;

    let mut child = spawn_chunk(
        &nmap_bin()?,
        &manual_frame_args(nmap_args),
        &st.chunks[0],
        0,
        &scans_dir,
        &mut log,
    )?;
    let started = std::time::Instant::now();
    let cap = if ips.len() > 1 {
        MANUAL_SCAN_CAP_MULTI
    } else {
        MANUAL_SCAN_CAP
    };
    let status = loop {
        match child.try_wait()? {
            Some(s) => break s,
            None => {
                if ABORT.load(Ordering::Relaxed) {
                    let _ = child.kill();
                    let _ = child.wait();
                    bail!(
                        "manual rescan of {} host(s): interrupted - capture in {scans_dir:?}",
                        ips.len()
                    );
                }
                if started.elapsed() > cap {
                    let _ = child.kill();
                    let _ = child.wait();
                    bail!(
                        "manual rescan of {} host(s): nmap passed {}s - killed; capture in {}",
                        ips.len(),
                        cap.as_secs(),
                        scans_dir.join("chunk-0000.out").display()
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
    };
    if !status.success() {
        bail!(
            "manual rescan of {} host(s): nmap exited {status} - capture in {}",
            ips.len(),
            scans_dir.join("chunk-0000.out").display()
        );
    }

    let mut db = Db::open(out)?;
    db.set_run_id(&run_id);
    let parsed = ingest_gnmap(&mut db, &scans_dir, 0, &mut log)?;
    st.chunks[0].done = true;
    st.done = true;
    write_scan_state(&run_dir, &st)?;
    Ok(ManualScan {
        run_id,
        open: parsed
            .into_iter()
            .flat_map(|h| {
                h.ports
                    .into_iter()
                    .map(move |p| (p.port, p.service, p.version))
            })
            .collect(),
    })
}

/// The ingest core shared by queue chunks and the dashboard's manual
/// rescan: one .gnmap file → results + services rows, the classifier
/// re-run over every host it touched, the flush that makes it durable.
/// Returns the parsed hosts so the caller can report what came back.
fn ingest_gnmap(
    db: &mut Db,
    scans_dir: &Path,
    idx: usize,
    log: &mut File,
) -> Result<Vec<GnmapHost>> {
    let gnmap = scans_dir.join(format!("chunk-{idx:04}.gnmap"));
    let bytes = std::fs::read(&gnmap).with_context(|| format!("reading {}", gnmap.display()))?;
    // nmap banners can carry non-UTF-8 bytes from exotic services; lossy
    // keeps the chunk ingestible (a mangled banner beats a wedged queue).
    let text = String::from_utf8_lossy(&bytes);
    let hosts = parse_gnmap(&text);
    let mut open_ports = 0usize;
    for host in &hosts {
        for p in &host.ports {
            db.record_result(host.ip, p.port, Stage::Scan, Answer::Open);
            db.record_service(host.ip, p.port, &p.service, &p.version);
            open_ports += 1;
        }
    }
    // The rows hit the database BEFORE the chunk is marked done — a "done"
    // chunk that loses its rows to a crash would never be re-scanned. The
    // checkpoint pulls the WAL into the main file, so even a power cut keeps
    // what scan_state.json is about to call done.
    db.flush()?;
    db.checkpoint()?;
    // Asset types ride the same granularity: every host the chunk touched
    // gets re-run through the classifier (manual overrides never move), one
    // flush for the whole chunk.
    for host in &hosts {
        crate::discovery::classify::reclassify_host(db, host.ip);
    }
    db.flush()?;
    state::log_line(
        log,
        &format!(
            "chunk {idx:04}: {} open port(s) recorded to the registry",
            fmt_count(open_ports as u64)
        ),
    );
    Ok(hosts)
}

pub fn run(args: &ScanArgs) -> Result<()> {
    unsafe { libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t) };
    crate::util::raise_nofile();

    let scope = config::load(&args.scope).context("loading scope")?;
    let threads = args.threads.unwrap_or(scope.scan.threads);
    if !(1..=64).contains(&threads) {
        bail!("--threads: {threads} - 1..=64 nmap processes in parallel");
    }
    let nmap_args = match &args.nmap_args {
        Some(a) => {
            config::check_nmap_args(a).context("--nmap-args")?;
            a.clone()
        }
        None => scope.scan.resolved_args(),
    };
    let cli_profiles: Vec<config::ScanProfile> = args
        .profile
        .iter()
        .map(|s| config::ScanProfile::parse_cli(s))
        .collect::<Result<Vec<_>>>()?;
    // The selection is recorded in the state and re-applied on resume —
    // restating it on the CLI would be ambiguous (same? different?).
    if args.resume && !args.only_profile.is_empty() {
        bail!(
            "--only-profile shapes a fresh queue; the interrupted queue re-applies its own \
             recorded selection - resume without it, or start without --resume"
        );
    }
    // Incremental window: CLI overrides the YAML; None = full queue.
    let (refresh_after, refresh_after_s) = match &args.refresh_after {
        Some(s) => {
            let d = crate::util::parse_duration(s).context("--refresh-after")?;
            if d.is_zero() {
                bail!("--refresh-after: zero window");
            }
            (Some(d), Some(s.clone()))
        }
        None => (
            scope.scan.refresh_delay()?,
            scope.scan.refresh_after.clone(),
        ),
    };

    let all_targets =
        Targets::build(&scope.includes, &scope.excludes).context("resolving targets")?;
    for z in &scope.sensitive_zones {
        if z.policy == config::Policy::Light
            && all_targets.intersects(
                crate::targets::IpRange::parse(&z.range)
                    .with_context(|| format!("sensitive zone {}", z.range))?,
            )
        {
            eprintln!(
                "warning: sensitive zone {} (light) is scanned like the rest in this version - exclude it from the scope if it must stay untouched",
                z.range
            );
        }
    }
    let passives = crate::passive_ranges(&scope, &all_targets)?;
    let scan_set = all_targets.subtract(&passives);
    if scan_set.is_empty() {
        bail!("no scannable targets - the whole perimeter is in passive zones");
    }

    // The registry is an input, never a product: open what exists, create
    // nothing. The perimeter lock is taken below, once the dry run has
    // returned — a dry run must not even hold the lock.
    let mut db = Db::open_existing(&args.out)?;

    // The queue: hosts up in discovery (all of them, or — incremental mode —
    // the never-scanned / stale ones), clamped to the current perimeter. No
    // queued hosts → the scan has nothing to explain.
    let remembered = db.scan_queue(refresh_after)?;
    let ups_bitmap = &remembered & scan_set.as_bitmap();
    if ups_bitmap.is_empty() {
        bail!(
            "no up hosts in the registry for this perimeter - run `rustrawl run` (discovery) first"
        );
    }
    let mut ups: Vec<u32> = ups_bitmap.iter().collect();
    ups.sort_unstable();
    let dropped = remembered.len() - ups_bitmap.len();
    if dropped > 0 {
        eprintln!(
            "note: {} up host(s) outside the current perimeter dropped from the scan queue",
            fmt_count(dropped)
        );
    }

    // The resume lookup comes before the plan build: the recorded
    // --only-profile selection lives in the state, and the dry run reuses
    // the directory instead of searching twice.
    let resume_dir = if args.resume {
        Some(find_resumable(&args.out)?.with_context(|| {
            format!(
                "nothing to resume under {} - every scan queue is complete, or none exists; start without --resume",
                args.out.display()
            )
        })?)
    } else {
        None
    };
    let recorded_only = match &resume_dir {
        Some(dir) => read_scan_state(dir)?.only,
        None => Vec::new(),
    };
    let only: &[String] = if args.resume {
        &recorded_only
    } else {
        &args.only_profile
    };

    // Per-range partition (CLI profiles, then the scope's; first match
    // wins; the remainder is the default group) and the queue plan: hosts
    // sorted rich-first WITHIN each group, chunks cut per group. Rich
    // hosts first: the operator sees the interesting boxes early, and a ^C
    // keeps the most valuable work already done — the tie-break by IP
    // keeps the order deterministic (the queue hash pins it).
    let open_counts = db.open_counts(&[Stage::Sweep, Stage::Expand])?;
    let baseline_provenance = if args.nmap_args.is_some() {
        "baseline (--nmap-args)"
    } else {
        "baseline (scan.nmap_args)"
    };
    let groups = scan_groups(
        &scope,
        &cli_profiles,
        &scan_set,
        &nmap_args,
        baseline_provenance,
    )?;
    let plan = build_plan(&ups, &groups, &open_counts, only)?;
    if plan.hosts.is_empty() {
        if !only.is_empty() {
            bail!(
                "no up host in the selected profile(s) ({}) - `scan --dry-run` prints the declared groups",
                only.join(", ")
            );
        }
        bail!(
            "no up hosts in the registry for this perimeter - run `rustrawl run` (discovery) first"
        );
    }

    if args.dry_run {
        // Plan only: never creates a run directory. With --resume, reports
        // what is left in the interrupted queue instead — the state is the
        // truth (the re-derived plan above only feeds the drift check).
        let st_resume = match (&resume_dir, args.resume) {
            (Some(dir), true) => Some(read_scan_state(dir)?),
            _ => None,
        };
        println!("Scan - dry run, zero nmap processes");
        let (hosts_n, chunk_n, done_n, skipped_n) = match &st_resume {
            Some(st) => (
                st.chunks.iter().map(|c| c.hosts.len() as u64).sum(),
                st.chunks.len(),
                st.chunks.iter().filter(|c| c.done).count(),
                st.chunks.iter().filter(|c| c.skipped && !c.done).count(),
            ),
            None => (plan.hosts.len() as u64, plan.chunks.len(), 0, 0),
        };
        println!(
            "  Queue             : {} up host(s) from the registry, clamped to the perimeter",
            fmt_count(hosts_n)
        );
        if let Some(w) = &refresh_after_s {
            println!("  Incremental       : only hosts never scanned or last scanned over {w} ago");
        }
        // One default group (the no-profiles shape, or `--only-profile
        // default`) needs no table; anything else — several groups, or a
        // single PROFILED group — prints the per-group lines.
        let multi = match &st_resume {
            Some(st) => st.profiles.len() > 1 || st.profiles[0].label != "default",
            None => {
                plan.groups.len() > 1 || plan.profiles.first().is_some_and(|p| p.label != "default")
            }
        };
        if multi {
            println!(
                "  Profiles          : {} group(s) · ≤ {CHUNK_HOSTS} hosts per chunk · threads {threads}",
                match &st_resume {
                    Some(st) => st.profiles.len(),
                    None => plan.groups.len(),
                }
            );
            match &st_resume {
                Some(st) => {
                    let mut per = vec![(0u64, 0u64); st.profiles.len()];
                    for c in &st.chunks {
                        let i = c.profile.min(per.len().saturating_sub(1));
                        if c.done {
                            per[i].0 += 1;
                        } else {
                            per[i].1 += 1;
                        }
                    }
                    for (i, p) in st.profiles.iter().enumerate() {
                        println!(
                            "    {:<16} {:>3} done · {:>3} pending chunk(s) · args \"{}\"",
                            p.label, per[i].0, per[i].1, p.nmap_args,
                        );
                    }
                    if !st.only.is_empty() {
                        println!(
                            "  Only              : {} (recorded with the queue)",
                            st.only.join(", ")
                        );
                    }
                }
                None => {
                    for g in &plan.groups {
                        println!(
                            "    {:<16} {} host(s) · {} chunk(s) ({}) · args \"{}\"",
                            g.label, g.hosts, g.chunks, g.provenance, g.nmap_args,
                        );
                    }
                    if !only.is_empty() {
                        println!("  Only              : {}", only.join(", "));
                    }
                }
            }
        }
        println!(
            "  Chunks            : {} × ≤ {CHUNK_HOSTS} hosts, {done_n} done{}, threads {threads}",
            chunk_n,
            if skipped_n > 0 {
                format!(", {skipped_n} skipped (keyboard)")
            } else {
                String::new()
            },
        );
        let scan_kind = if is_root() {
            "-sS (root)"
        } else {
            "-sT (no root - connect scan)"
        };
        let pinned_args = match &st_resume {
            Some(st) => st.nmap_args.clone(),
            None => nmap_args.clone(),
        };
        println!("  Nmap args         : {pinned_args}");
        println!("  Scan type         : {scan_kind}");
        if args.resume {
            println!("  Resuming          : the interrupted queue's remaining chunks");
        } else {
            println!("  Run dir           : not created in dry run");
        }
        println!(
            "  Registry          : every open port lands as a scan results row + a services row"
        );
        return Ok(());
    }

    // From here on the scan writes: perimeter lock, then the run directory —
    // fresh per invocation (scan_<date>_<time>), or the interrupted queue.
    let _lock = state::lock_perimeter(&args.out)?;
    let (run_dir, mut st) = if args.resume {
        let dir = resume_dir.expect("resume checked above");
        let mut loaded = read_scan_state(&dir)?;
        if adopt_legacy_ports(&mut loaded) {
            eprintln!(
                "warning: pre-rework queue adopted - its pinned port list is gone (ports now \
                 ride in the nmap args); the queue re-pins to args-only and the drift check \
                 runs from there"
            );
        }
        // Chunks killed from the keyboard last session come back: --resume
        // is the retry path the end-of-run note points at.
        let requeued = loaded
            .chunks
            .iter_mut()
            .filter(|c| c.skipped && !c.done)
            .map(|c| {
                c.skipped = false;
                true
            })
            .count();
        if requeued > 0 {
            eprintln!("note: {requeued} chunk(s) skipped from the keyboard last session are back in the queue");
        }
        let qh = queue_hash_plan(&plan.profiles, &plan.hosts);
        if loaded.profiles != plan.profiles || loaded.queue_hash != qh {
            // A drift with no CLI override means the scope or the registry
            // moved underneath the queue: refuse. An explicit --nmap-args /
            // --profile is the operator changing the plan mid-queue —
            // allowed, loudly, with the state re-pinned.
            if args.nmap_args.is_none() && args.profile.is_empty() {
                bail!(
                    "scan plan (profiles, nmap args or up-host set) changed since this \
                     queue started - resuming would mix evidence; pass --nmap-args/--profile \
                     to change the plan explicitly, or start without --resume"
                );
            }
            let old_labels = loaded
                .profiles
                .iter()
                .map(|p| p.label.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let new_labels = plan
                .profiles
                .iter()
                .map(|p| p.label.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            eprintln!(
                "warning: scan plan changed on resume - {} chunk(s) already done keep the old evidence; groups were [{}], now [{}] - pending chunks re-pin to the new plan (a chunk's first host decides)",
                loaded.chunks.iter().filter(|c| c.done).count(),
                old_labels,
                new_labels,
            );
            loaded.ports = Vec::new();
            loaded.nmap_args = nmap_args.clone();
            loaded.profiles = plan.profiles.clone();
            loaded.queue_hash = qh;
            // Re-map PENDING chunks to the new plan: the chunk's first host
            // picks the group (chunks were cut within old-plan groups; a
            // scope change can straddle one — first host wins, already
            // warned). Done chunks keep their recorded profile and their old
            // evidence; a host no group covers keeps the first profile.
            let group_bm: Vec<RoaringBitmap> =
                groups.iter().map(|g| g.targets.as_bitmap()).collect();
            for chunk in loaded.chunks.iter_mut().filter(|c| !c.done) {
                let gidx = chunk
                    .hosts
                    .first()
                    .and_then(|h| h.parse::<Ipv4Addr>().ok())
                    .map(u32::from)
                    .and_then(|v| group_bm.iter().position(|bm| bm.contains(v)));
                chunk.profile = gidx.and_then(|gi| plan.group_profile[gi]).unwrap_or(0);
            }
        }
        (dir, loaded)
    } else {
        let dir = state::create_run(&args.out, &state::new_scan_id())?;
        (
            dir,
            ScanState {
                ports: Vec::new(),
                nmap_args: nmap_args.clone(),
                queue_hash: queue_hash_plan(&plan.profiles, &plan.hosts),
                profiles: plan.profiles,
                only: args.only_profile.clone(),
                chunks: plan.chunks,
                done: false,
            },
        )
    };
    let scans_dir = run_dir.join("scans");
    std::fs::create_dir_all(&scans_dir)
        .with_context(|| format!("creating {}", scans_dir.display()))?;
    let run_id = run_dir
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    db.set_run_id(&run_id);
    let mut log = state::open_run_log(&run_dir)?;

    let hosts_n: u64 = st.chunks.iter().map(|c| c.hosts.len() as u64).sum();
    let done_chunks = st.chunks.iter().filter(|c| c.done).count();
    state::log_line(
        &mut log,
        &format!(
            "scan start (nmap args: {nmap_args}) | {} hosts | {} chunk(s), {} pending | threads {threads} | run {run_id}",
            fmt_count(hosts_n),
            st.chunks.len(),
            st.chunks.len() - done_chunks,
        ),
    );
    // The run log is the operator's evidence of who got what: one line per
    // group (label, hosts, chunks, args) when a profile table drives
    // the queue.
    if st.profiles.len() > 1 {
        let mut per = vec![(0u64, 0u64); st.profiles.len()];
        for c in &st.chunks {
            let i = c.profile.min(per.len().saturating_sub(1));
            per[i].0 += c.hosts.len() as u64;
            per[i].1 += 1;
        }
        for (i, p) in st.profiles.iter().enumerate() {
            state::log_line(
                &mut log,
                &format!(
                    "group {}: {} host(s), {} chunk(s), args \"{}\"",
                    p.label,
                    fmt_count(per[i].0),
                    per[i].1,
                    p.nmap_args,
                ),
            );
        }
    }
    write_scan_state(&run_dir, &st)?;

    // The interactive screen: one bar over the pending chunks. Event lines
    // (chunk spawns, ingest counts) keep printing above it.
    let pending_total = st.chunks.len() - done_chunks;
    let screen = Screen::start("scan", pending_total as u64, Footer::Scan);
    let status = screen.status().clone();
    let mut open_found: u64 = 0;
    status.set_extra(String::new());

    // Drive the queue: up to `threads` nmap processes, each one chunk;
    // finished chunks are parsed, recorded and checkpointed before the next
    // spawn. ^C / q kill the children, save the state, stay resumable.
    // Keyboard: p pauses the dispatch (running nmaps finish), k kills the
    // oldest running chunk and requeues it, x kills it and leaves it
    // unscanned (reported at the end; `scan --resume` brings it back).
    let bin = nmap_bin()?;
    let mut queue: VecDeque<usize> = (0..st.chunks.len())
        .filter(|&i| !st.chunks[i].done && !st.chunks[i].skipped)
        .collect();
    let mut inflight: Vec<(usize, Child)> = Vec::new();

    /// Spawns up to `threads` chunks from the queue, honoring the pause key.
    #[allow(clippy::too_many_arguments)] // one flat spawn step, all of it needed
    fn fill(
        queue: &mut VecDeque<usize>,
        inflight: &mut Vec<(usize, Child)>,
        status: &crate::tui::Status,
        threads: u32,
        bin: &str,
        st: &ScanState,
        scans_dir: &Path,
        log: &mut File,
    ) {
        status.wait_while_paused();
        while inflight.len() < threads as usize {
            let Some(idx) = queue.pop_front() else { break };
            let chunk_args = st.chunk_profile(idx);
            match spawn_chunk(bin, chunk_args, &st.chunks[idx], idx, scans_dir, log) {
                Ok(child) => inflight.push((idx, child)),
                Err(e) => {
                    // The chunk stays pending (it was popped, never marked
                    // done) and the caller drains the children that DID
                    // start — no orphans still writing evidence after
                    // rustrawl exits.
                    state::log_line(log, &format!("chunk {idx:04}: spawn failed: {e}"));
                    break;
                }
            }
        }
        status.set_mute(inflight.len() as u64);
    }

    fill(
        &mut queue,
        &mut inflight,
        &status,
        threads,
        &bin,
        &st,
        &scans_dir,
        &mut log,
    );

    while !inflight.is_empty() || !queue.is_empty() {
        if ABORT.load(Ordering::Relaxed) {
            for (_, child) in inflight.iter_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
            state::log_line(
                &mut log,
                "interrupted - in-flight chunks killed, queue saved; rerun `rustrawl scan --resume`",
            );
            write_scan_state(&run_dir, &st)?;
            drop(screen);
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        // Live chunk views: the captures are re-read every tick so the
        // operator sees nmap working between chunk completions (`n` cycles
        // the views). Inert without a TTY — no reads at all.
        if screen.is_live() {
            let viz: Vec<ChunkViz> = inflight
                .iter()
                .map(|(idx, _)| {
                    chunk_viz(
                        *idx,
                        st.chunk_label(*idx),
                        st.chunks[*idx].hosts.len(),
                        &scans_dir,
                    )
                })
                .collect();
            crate::tui::set_chunks(viz);
        }

        // Kills act on the oldest running chunks (first in inflight order);
        // each keypress is a counted request, so rapid presses all land.
        let redo = crate::tui::take_kill_redo().min(inflight.len() as u32);
        for _ in 0..redo {
            let idx = inflight[0].0;
            let _ = inflight[0].1.kill();
            let _ = inflight[0].1.wait();
            inflight.remove(0);
            st.chunks[idx].attempts += 1;
            queue.push_back(idx);
            state::log_line(
                &mut log,
                &format!("chunk {idx:04}: killed from the keyboard - requeued"),
            );
        }
        let skip = crate::tui::take_kill_skip().min(inflight.len() as u32);
        for _ in 0..skip {
            let idx = inflight[0].0;
            let _ = inflight[0].1.kill();
            let _ = inflight[0].1.wait();
            inflight.remove(0);
            st.chunks[idx].attempts += 1;
            st.chunks[idx].skipped = true;
            state::log_line(
                &mut log,
                &format!(
                    "chunk {idx:04}: killed from the keyboard - left unscanned (`scan --resume` requeues it)"
                ),
            );
        }
        status.set_skipped(st.chunks.iter().filter(|c| c.skipped).count() as u64);
        // Freed slots refill immediately: a kill that emptied the in-flight
        // set must hand the queue its slot back, not end the run.
        fill(
            &mut queue,
            &mut inflight,
            &status,
            threads,
            &bin,
            &st,
            &scans_dir,
            &mut log,
        );
        if inflight.is_empty() && !queue.is_empty() {
            // fill() could not spawn anything (repeated spawn failure) —
            // stopping beats spinning; the coverage check reports the rest.
            state::log_line(
                &mut log,
                "no chunk could be spawned - stopping; rerun `rustrawl scan --resume`",
            );
            break;
        }

        let mut finished: Vec<usize> = Vec::new();
        let mut dead: Vec<usize> = Vec::new();
        for (idx, child) in inflight.iter_mut() {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => finished.push(*idx),
                Ok(Some(status)) => {
                    state::log_line(
                        &mut log,
                        &format!(
                            "chunk {idx:04}: nmap exited with {status} - chunk left pending for --resume"
                        ),
                    );
                    // Terminal for the slot: no ingest (no/partial evidence),
                    // no re-queue this session. The chunk keeps done:false,
                    // so `scan --resume` will retry it.
                    dead.push(*idx);
                }
                Ok(None) => {}
                Err(e) => {
                    state::log_line(
                        &mut log,
                        &format!("chunk {idx:04}: wait failed: {e} - chunk left pending"),
                    );
                    dead.push(*idx);
                }
            }
        }
        if finished.is_empty() && dead.is_empty() {
            continue;
        }
        inflight.retain(|(idx, _)| !finished.contains(idx) && !dead.contains(idx));
        for idx in finished {
            if let Err(e) =
                ingest_chunk_counted(&mut db, &scans_dir, idx, &mut st, &mut log, &mut open_found)
            {
                state::log_line(&mut log, &format!("chunk {idx:04}: ingest failed: {e}"));
            }
            status.set_up(open_found);
            status.set_extra(format!(
                "last chunk {idx:04}: {} host(s)",
                st.chunks[idx].hosts.len()
            ));
            if let Err(e) = write_scan_state(&run_dir, &st) {
                state::log_line(&mut log, &format!("scan_state write failed: {e}"));
            }
        }
        status.set_done(done_chunks_this_session(&st, pending_total as u64));
        fill(
            &mut queue,
            &mut inflight,
            &status,
            threads,
            &bin,
            &st,
            &scans_dir,
            &mut log,
        );
    }

    if let Err(e) = db.flush() {
        state::log_line(&mut log, &format!("final db flush failed: {e}"));
    }
    // Coverage check: a chunk left pending this session (nmap failure, spawn
    // or wait error, unreadable evidence) or skipped from the keyboard must
    // not be finalized — done would lie and the db views would flag
    // never-scanned hosts as silent.
    let pending: Vec<usize> = st
        .chunks
        .iter()
        .enumerate()
        .filter(|(_, c)| !c.done && !c.skipped)
        .map(|(i, _)| i)
        .collect();
    let skipped: Vec<usize> = st
        .chunks
        .iter()
        .enumerate()
        .filter(|(_, c)| c.skipped)
        .map(|(i, _)| i)
        .collect();
    drop(screen);
    if !pending.is_empty() || !skipped.is_empty() {
        st.done = false;
        write_scan_state(&run_dir, &st)?;
        let list = pending
            .iter()
            .map(|i| format!("{i:04}"))
            .collect::<Vec<_>>()
            .join(", ");
        let mut note = String::new();
        if !pending.is_empty() {
            note.push_str(&format!("{} chunk(s) pending ({list})", pending.len()));
        }
        if !skipped.is_empty() {
            if !note.is_empty() {
                note.push_str(", ");
            }
            let killed = skipped
                .iter()
                .map(|i| format!("{i:04}"))
                .collect::<Vec<_>>()
                .join(", ");
            note.push_str(&format!(
                "{} chunk(s) skipped from the keyboard ({killed})",
                skipped.len()
            ));
        }
        state::log_line(
            &mut log,
            &format!(
                "scan incomplete: {note} - nothing marked done; rerun `rustrawl scan --resume` (skipped chunks are requeued)"
            ),
        );
        return Ok(());
    }
    st.done = true;
    write_scan_state(&run_dir, &st)?;

    let retried: u64 = st.chunks.iter().map(|c| u64::from(c.attempts)).sum();
    let mut summary = format!(
        "scan end | {} chunk(s) | {} open port(s) recorded",
        st.chunks.len(),
        fmt_count(open_found)
    );
    if retried > 0 {
        summary.push_str(&format!(" | {retried} chunk kill(s) from the keyboard"));
    }
    summary.push_str(&format!(
        " | evidence: {} | `rustrawl db` console (hosts, services levels) to review",
        run_dir.display()
    ));
    state::log_line(&mut log, &summary);
    Ok(())
}

/// Progress bookkeeping helpers for the screen (done = chunks finished this
/// session, so the bar moves 0→100 % over what is actually left).
fn done_chunks_this_session(st: &ScanState, pending_total: u64) -> u64 {
    pending_total.saturating_sub(st.chunks.iter().filter(|c| !c.done).count() as u64)
}

/// The live view of one inflight chunk, read from its capture. nmap writes
/// as hosts complete, so the counts and tail move between chunk
/// completions — mid-chunk this is the only progress signal there is, and
/// `--stats-every` keeps it ticking on quiet chunks. Any read failure (the
/// chunk has not written its capture yet) degrades to an empty view: the
/// view must never take the scan down. Truncation keeps a pathological
/// banner line from wrapping the operator's terminal.
fn chunk_viz(idx: usize, label: &str, hosts_total: usize, scans_dir: &Path) -> ChunkViz {
    const TAIL_CHARS: usize = 160;
    let text = std::fs::read(scans_dir.join(format!("chunk-{idx:04}.out")))
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let tail: Vec<String> = text
        .lines()
        .rev()
        .take(TAIL_LINES)
        .map(|l| l.chars().take(TAIL_CHARS).collect())
        .collect();
    ChunkViz {
        idx,
        profile: label.to_string(),
        hosts_done: text.matches("Nmap scan report for").count(),
        hosts_total,
        tail: tail.into_iter().rev().collect(),
    }
}

/// [`ingest_chunk`] plus the screen counter (open ports found so far).
fn ingest_chunk_counted(
    db: &mut Db,
    scans_dir: &Path,
    idx: usize,
    st: &mut ScanState,
    log: &mut File,
    open_found: &mut u64,
) -> Result<()> {
    let before = *open_found;
    ingest_chunk(db, scans_dir, idx, st, log)?;
    // The chunk's open count: re-read what ingest just counted. Cheap — the
    // .gnmap is in page cache — and it keeps ingest_chunk testable in
    // isolation.
    let gnmap = scans_dir.join(format!("chunk-{idx:04}.gnmap"));
    if let Ok(bytes) = std::fs::read(&gnmap) {
        let text = String::from_utf8_lossy(&bytes);
        *open_found = before
            + parse_gnmap(&text)
                .iter()
                .map(|h| h.ports.len() as u64)
                .sum::<u64>();
    }
    Ok(())
}

/// Newest run directory with an unfinished scan queue (scan_state.json).
/// Complete queues are skipped, so an --resume over an all-done history
/// falls through to the "nothing to resume" path instead of blocking on a
/// finished newest run while an older interrupted one waits. A directory
/// still holding the pre-redesign `fp_state.json` is refused explicitly —
/// its queue shape cannot be interpreted by this build.
fn find_resumable(root: &Path) -> Result<Option<PathBuf>> {
    let runs = state::runs_dir(root);
    if !runs.is_dir() {
        return Ok(None);
    }
    let mut legacy = false;
    let mut candidates: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(&runs)
        .with_context(|| format!("listing {}", runs.display()))?
        .flatten()
    {
        let p = entry.path();
        if p.join("scan_state.json").is_file() {
            candidates.push(p);
        } else if p.join("fp_state.json").is_file() {
            legacy = true;
        }
    }
    if candidates.is_empty() {
        if legacy {
            bail!(
                "found a pre-redesign scan queue (fp_state.json) under {} - \
                 this build cannot resume it; delete the run directory or start fresh without --resume",
                runs.display()
            );
        }
        return Ok(None);
    }
    candidates.sort();
    while let Some(dir) = candidates.pop() {
        let st = read_scan_state(&dir)?;
        if st.done || st.chunks.iter().all(|c| c.done) {
            continue; // finished run — look for an older interrupted one
        }
        return Ok(Some(dir));
    }
    Ok(None)
}

/// Adopts a pre-rework queue: `ports` moved into the nmap args, so a
/// loaded state still carrying non-empty legacy port lists is re-pinned
/// in place (fields zeroed, hash recomputed over its own chunks' hosts)
/// and the regular drift check decides the rest. Returns true when
/// adoption changed something.
fn adopt_legacy_ports(st: &mut ScanState) -> bool {
    let legacy = !st.ports.is_empty() || st.profiles.iter().any(|p| !p.ports.is_empty());
    if !legacy {
        return false;
    }
    st.ports = Vec::new();
    for p in st.profiles.iter_mut() {
        p.ports = Vec::new();
    }
    let hosts: Vec<u32> = st
        .chunks
        .iter()
        .flat_map(|c| c.hosts.iter())
        .filter_map(|h| h.parse::<Ipv4Addr>().ok())
        .map(u32::from)
        .collect();
    st.queue_hash = queue_hash_plan(&st.profiles, &hosts);
    true
}

pub(crate) fn read_scan_state(run_dir: &Path) -> Result<ScanState> {
    let path = run_dir.join("scan_state.json");
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let mut st: ScanState =
        serde_json::from_str(&text).with_context(|| format!("format of {}", path.display()))?;
    // Pre-profiles state files normalize to a single default profile, so
    // chunk.profile = 0 resolves and old queues stay resumable.
    st.normalize_profiles();
    Ok(st)
}

fn write_scan_state(run_dir: &Path, st: &ScanState) -> Result<()> {
    let path = run_dir.join("scan_state.json");
    let tmp = run_dir.join("scan_state.json.tmp");
    let text = serde_json::to_string_pretty(st).context("serializing scan state")?;
    let mut f = File::create(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
    f.write_all(text.as_bytes())
        .with_context(|| format!("writing {}", tmp.display()))?;
    f.sync_all()
        .with_context(|| format!("syncing {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("renaming {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gnmap_parsing() {
        let text = concat!(
            "# Nmap 7.94 scan initiated Mon Oct  7 10:00:00 2026 as: nmap -Pn -oA chunk-0\n",
            "Host: 10.0.0.5 ()\tStatus: Up\n",
            "Host: 10.0.0.5 ()\tPorts: 22/open/tcp//ssh//OpenSSH 8.4p1 Debian 5 (protocol 2.0)/, 80/open/tcp//http//nginx 1.22.1, 443/filtered/tcp//https//\tIgnored State: 997\n",
            "Host: 10.0.0.6 ()\tPorts: 3389/open/tcp//ms-wbt-server//Microsoft Terminal Services\tIgnored State: 999\n",
            "Host: 10.0.0.7 ()\tStatus: Down\n",
        );
        let hosts = parse_gnmap(text);
        assert_eq!(hosts.len(), 2, "down host and Status-only lines ignored");
        assert_eq!(hosts[0].ip, "10.0.0.5".parse::<Ipv4Addr>().unwrap());
        assert_eq!(hosts[0].ports.len(), 2, "filtered port skipped");
        assert_eq!(hosts[0].ports[0].port, 22);
        assert_eq!(hosts[0].ports[0].service, "ssh");
        // version keeps embedded slashes and even the trailing one
        assert_eq!(
            hosts[0].ports[0].version,
            "OpenSSH 8.4p1 Debian 5 (protocol 2.0)/"
        );
        assert_eq!(hosts[0].ports[1].port, 80);
        assert_eq!(hosts[0].ports[1].service, "http");
        assert_eq!(hosts[1].ports[0].port, 3389);
        assert_eq!(hosts[1].ports[0].version, "Microsoft Terminal Services");
    }

    #[test]
    fn gnmap_no_ports_line() {
        // a host line without Ports: is simply not a scan finding yet
        assert!(parse_gnmap("Host: 10.0.0.9 ()\tStatus: Up\n").is_empty());
    }

    #[test]
    fn manual_frame_appends_v() {
        assert_eq!(manual_frame_args("-sC -sV"), "-sC -sV -v");
        // the operator's own verbosity is respected, never doubled
        assert_eq!(manual_frame_args("-sV -v"), "-sV -v");
        assert_eq!(manual_frame_args("-vv -sC"), "-vv -sC");
        assert_eq!(manual_frame_args("--verbose -p-"), "--verbose -p-");
    }

    #[test]
    fn chunk_argv_file_holds_the_command() {
        let dir = std::env::temp_dir().join(format!("rustrawl-argv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let argv = nmap_argv(
            "nmap",
            "-sC -p 22",
            Path::new("scans/chunk-0003"),
            &["10.0.0.5".into()],
        );
        write_chunk_argv(&dir, 3, &argv).unwrap();
        let text = std::fs::read_to_string(dir.join("chunk-0003.argv")).unwrap();
        // one line, the whole command - the scan type depends on the uid,
        // so the frame and the targets are pinned, not -sS/-sT
        assert_eq!(text, format!("{}\n", argv.join(" ")));
        assert!(
            text.starts_with("nmap -Pn -n --open -oA scans/chunk-0003 ")
                && text.ends_with("--stats-every 30s -sC -p 22 10.0.0.5\n"),
            "{text:?}"
        );
    }

    #[test]
    fn argv_shape() {
        let argv = nmap_argv(
            "nmap",
            "-sC -sV -p 22,80",
            Path::new("scans/chunk-0000"),
            &["10.0.0.5".into(), "10.0.0.6".into()],
        );
        let joined = argv.join(" ");
        // fixed prefix, the root-dependent scan type, then the heartbeat
        assert!(joined.starts_with("nmap -Pn -n --open -oA scans/chunk-0000 "));
        let hb = joined
            .find("--stats-every 30s")
            .expect("heartbeat in the frame");
        assert!(
            hb < joined.find(" -sC -sV ").expect("operator args"),
            "the heartbeat sits between the scan type and the operator's args"
        );
        assert!(
            joined.contains("-p 22,80"),
            "the operator's -p rides verbatim"
        );
        assert!(joined.ends_with("10.0.0.5 10.0.0.6"));
        // multi-token args keep their order
        let light = nmap_argv(
            "nmap",
            "-sV --version-light -T4",
            Path::new("x"),
            &["h".into()],
        );
        let j = light.join(" ");
        assert!(j.contains(" -sV --version-light -T4 "));
        assert!(!j.contains("-sC"), "no hidden default scripts");
        assert!(
            !j.contains(" -p "),
            "rustrawl injects no port list of its own"
        );
    }

    #[test]
    fn chunk_viz_counts_reports_and_tails_the_capture() {
        let dir = std::env::temp_dir().join(format!(
            "rustrawl-viz-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // no capture yet (chunk starting up): an empty view, never an error
        let v = chunk_viz(7, "10.30.0.0/24", 32, &dir);
        assert_eq!(v.idx, 7);
        assert_eq!(v.profile, "10.30.0.0/24");
        assert_eq!(v.hosts_done, 0);
        assert_eq!(v.hosts_total, 32);
        assert!(v.tail.is_empty());
        // reports count, the tail keeps the newest lines in reading order
        let mut text = String::new();
        for i in 0..12 {
            text.push_str(&format!(
                "Nmap scan report for 10.0.0.{i}\n22/tcp open ssh\n\n"
            ));
        }
        text.push_str("Stats: 0:01:00 elapsed; 12 hosts completed\n");
        std::fs::write(dir.join("chunk-0003.out"), &text).unwrap();
        let v = chunk_viz(3, "default", 32, &dir);
        assert_eq!(v.hosts_done, 12);
        assert_eq!(v.tail.len(), TAIL_LINES);
        assert!(
            v.tail.last().unwrap().starts_with("Stats:"),
            "newest line last: {:?}",
            v.tail.last()
        );
        assert_eq!(
            v.tail[0], "Nmap scan report for 10.0.0.9",
            "oldest kept line first"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn queue_hash_changes_with_inputs() {
        let hosts = [0x0A00_0005u32];
        assert_eq!(queue_hash("-sC -sV", &hosts), queue_hash("-sC -sV", &hosts));
        assert_ne!(
            queue_hash("-sC -sV", &hosts),
            queue_hash("-sV", &hosts),
            "a changed nmap_args must fork the queue"
        );
        assert_ne!(
            queue_hash("-sC -sV", &hosts),
            queue_hash("-sC -sV", &[0x0A00_0006])
        );
    }

    // ---- per-range profiles ----

    fn scope_with(profiles: Vec<config::ScanProfile>) -> config::Scope {
        config::Scope {
            name: "t".into(),
            includes: vec!["10.0.0.0/8".to_string()],
            excludes: vec![],
            sensitive_zones: vec![],
            discovery: Default::default(),
            scan: config::ScanCfg {
                profiles,
                ..Default::default()
            },
            rescan: Default::default(),
        }
    }

    fn targets_10() -> Targets {
        Targets::build(&["10.0.0.0/8".to_string()], &[]).unwrap()
    }

    fn yprofile(range: &str, args: Option<&str>) -> config::ScanProfile {
        config::ScanProfile {
            range: range.into(),
            nmap_args: args.map(str::to_string),
        }
    }

    #[test]
    fn scan_groups_first_match_wins_with_default_remainder() {
        let scope = scope_with(vec![yprofile("10.30.0.0/24", Some("-p 80,9100"))]);
        let cli = vec![
            config::ScanProfile::parse_cli("10.30.0.0/25=-p 22").unwrap(),
            config::ScanProfile::parse_cli("10.40.0.0/16=-p 443").unwrap(),
        ];
        let groups = scan_groups(
            &scope,
            &cli,
            &targets_10(),
            "-sC -sV",
            "baseline (scan.nmap_args)",
        )
        .unwrap();
        // CLI first, in CLI order: 10.30.0.0/25 claims, then 10.40/16; the
        // YAML /24 keeps its upper half; the rest of 10/8 is the default
        // group, always last. Declaration order is dispatch order.
        let labels: Vec<&str> = groups.iter().map(|g| g.label.as_str()).collect();
        assert_eq!(
            labels,
            ["10.30.0.0/25", "10.40.0.0/16", "10.30.0.0/24", "default"],
            "{labels:?}"
        );
        assert_eq!(groups[0].provenance, "--profile");
        assert_eq!(groups[1].provenance, "--profile");
        assert_eq!(groups[2].provenance, "scan.profiles[0]");
        assert_eq!(groups[3].provenance, "baseline (scan.nmap_args)");
        // the args line per group — the port list rides inside it
        assert_eq!(groups[0].nmap_args, "-p 22");
        assert_eq!(groups[1].nmap_args, "-p 443");
        assert_eq!(groups[2].nmap_args, "-p 80,9100");
        // the default group inherits the baseline args
        assert_eq!(groups[3].nmap_args, "-sC -sV");
    }

    #[test]
    fn scan_groups_inherits_baseline_args_when_profile_omits_them() {
        let scope = scope_with(vec![yprofile("10.30.0.0/24", None)]);
        let groups = scan_groups(
            &scope,
            &[],
            &targets_10(),
            "-sV",
            "baseline (scan.nmap_args)",
        )
        .unwrap();
        assert_eq!(groups.len(), 2, "profile group + default");
        assert_eq!(
            groups[0].nmap_args, "-sV",
            "a profile without args inherits the baseline"
        );
        assert_eq!(groups[1].nmap_args, "-sV");
    }

    #[test]
    fn scan_groups_range_outside_perimeter_claims_but_yields_no_group() {
        let scope = scope_with(vec![yprofile("192.168.0.0/16", Some("-p 80"))]);
        let groups = scan_groups(&scope, &[], &targets_10(), "-sV", "baseline").unwrap();
        assert_eq!(groups.len(), 1, "only the default group");
        assert_eq!(groups[0].label, "default");
    }

    #[test]
    fn build_plan_cuts_chunks_within_groups_and_pins_profiles() {
        let mut ups: Vec<u32> = (0u32..40)
            .map(|i| u32::from("10.30.0.1".parse::<Ipv4Addr>().unwrap()) + i)
            .collect();
        ups.extend((0u32..3).map(|i| u32::from("10.40.0.1".parse::<Ipv4Addr>().unwrap()) + i));
        ups.sort_unstable();
        let mk = |range: &str| ScanGroup {
            targets: Targets::build(&[range.to_string()], &[]).unwrap(),
            nmap_args: "-sV".into(),
            label: range.into(),
            range: crate::targets::IpRange::parse(range).unwrap(),
            provenance: "test".into(),
        };
        let groups = vec![mk("10.30.0.0/24"), mk("10.40.0.0/24")];
        let plan = build_plan(&ups, &groups, &Default::default(), &[]).unwrap();
        // 40 hosts → 2 chunks in group A, 3 hosts → 1 chunk in group B
        assert_eq!(plan.profiles.len(), 2);
        assert_eq!(
            plan.profiles
                .iter()
                .map(|p| p.label.as_str())
                .collect::<Vec<_>>(),
            ["10.30.0.0/24", "10.40.0.0/24"]
        );
        assert_eq!(plan.chunks.len(), 3);
        assert!(
            plan.chunks.iter().take(2).all(|c| c.profile == 0),
            "group A chunks pinned to profile 0"
        );
        assert_eq!(plan.chunks[2].profile, 1);
        assert!(
            plan.chunks[2].hosts.iter().all(|h| h.starts_with("10.40.")),
            "chunks never straddle a group"
        );
        // the flat host list is the chunks concatenated (the hash fold order)
        let flat: Vec<String> = plan
            .chunks
            .iter()
            .flat_map(|c| c.hosts.iter().cloned())
            .collect();
        let rebuilt: Vec<String> = plan
            .hosts
            .iter()
            .map(|ip| Ipv4Addr::from(*ip).to_string())
            .collect();
        assert_eq!(flat, rebuilt);
        // 32-host cap per chunk
        assert_eq!(plan.chunks[0].hosts.len(), 32);
        assert_eq!(plan.chunks[1].hosts.len(), 8);
    }

    #[test]
    fn build_plan_rich_first_within_group() {
        let ups: Vec<u32> = (1u32..=5)
            .map(|i| u32::from("10.30.0.1".parse::<Ipv4Addr>().unwrap()) + i - 1)
            .collect();
        let group = ScanGroup {
            targets: Targets::build(&["10.30.0.0/29".to_string()], &[]).unwrap(),
            nmap_args: String::new(),
            label: "g".into(),
            range: crate::targets::IpRange::parse("10.30.0.0/29").unwrap(),
            provenance: "test".into(),
        };
        // 10.30.0.3 is the rich host — first in the queue, rest ascending
        let mut counts = std::collections::HashMap::new();
        counts.insert(u32::from("10.30.0.3".parse::<Ipv4Addr>().unwrap()), 5u32);
        let plan = build_plan(&ups, &[group], &counts, &[]).unwrap();
        assert_eq!(
            plan.hosts[0],
            u32::from("10.30.0.3".parse::<Ipv4Addr>().unwrap())
        );
        assert_eq!(
            &plan.hosts[1..],
            &[1u32, 2, 4, 5].map(|i| u32::from("10.30.0.1".parse::<Ipv4Addr>().unwrap()) + i - 1)
        );
    }

    #[test]
    fn build_plan_only_profile_filters_and_rejects_unknown_labels() {
        let ups: Vec<u32> = (1u32..=4)
            .map(|i| u32::from("10.30.0.1".parse::<Ipv4Addr>().unwrap()) + i - 1)
            .chain((1u32..=2).map(|i| u32::from("10.40.0.1".parse::<Ipv4Addr>().unwrap()) + i - 1))
            .collect();
        let mk = |range: &str| ScanGroup {
            targets: Targets::build(&[range.to_string()], &[]).unwrap(),
            nmap_args: String::new(),
            label: range.into(),
            range: crate::targets::IpRange::parse(range).unwrap(),
            provenance: "test".into(),
        };
        let groups = vec![mk("10.30.0.0/24"), mk("10.40.0.0/24"), mk("10.50.0.5/32")];
        // the /32 is selected by its bare-ip form: same range, no host up
        let plan = build_plan(
            &ups,
            &groups,
            &Default::default(),
            &["10.50.0.5".to_string()],
        )
        .unwrap();
        assert!(plan.hosts.is_empty(), "the /32 has no up host");
        assert_eq!(plan.groups.len(), 1, "only the selected group prints");
        assert_eq!(plan.groups[0].label, "10.50.0.5/32");
        assert_eq!(plan.groups[0].hosts, 0);

        // a label that selects exactly one group
        let plan = build_plan(
            &ups,
            &groups,
            &Default::default(),
            &["10.40.0.0/24".to_string()],
        )
        .unwrap();
        assert_eq!(plan.hosts.len(), 2);
        assert!(plan.chunks.iter().all(|c| c.profile == 0));
        assert_eq!(plan.profiles[0].label, "10.40.0.0/24");

        // `default` selects the remainder... there is none here: every host
        // is covered — `default` matches nothing but stays a legal label
        // only when a default group exists; with none, the label errors.
        let err = build_plan(&ups, &groups, &Default::default(), &["nope".to_string()])
            .err()
            .expect("an unknown label bails");
        assert!(
            err.to_string()
                .contains("unknown profile label \"nope\" - declared:"),
            "{err}"
        );
    }

    #[test]
    fn build_plan_only_default_selects_the_remainder() {
        let ups: Vec<u32> = (1u32..=2)
            .map(|i| u32::from("10.30.0.1".parse::<Ipv4Addr>().unwrap()) + i - 1)
            .chain((1u32..=2).map(|i| u32::from("10.60.0.1".parse::<Ipv4Addr>().unwrap()) + i - 1))
            .collect();
        let profiled = ScanGroup {
            targets: Targets::build(&["10.30.0.0/24".to_string()], &[]).unwrap(),
            nmap_args: String::new(),
            label: "10.30.0.0/24".into(),
            range: crate::targets::IpRange::parse("10.30.0.0/24").unwrap(),
            provenance: "test".into(),
        };
        let default = ScanGroup {
            // Production's default group is the perimeter MINUS every
            // profile's range — it never overlaps the profiled group.
            targets: Targets::build(&["10.60.0.0/24".to_string()], &[]).unwrap(),
            nmap_args: String::new(),
            label: "default".into(),
            range: crate::targets::IpRange {
                start: 0,
                end: u32::MAX,
            },
            provenance: "baseline".into(),
        };
        let plan = build_plan(
            &ups,
            &[profiled, default],
            &Default::default(),
            &["default".to_string()],
        )
        .unwrap();
        assert_eq!(plan.hosts.len(), 2);
        assert!(
            plan.hosts
                .iter()
                .all(|ip| Ipv4Addr::from(*ip).to_string().starts_with("10.60.")),
            "only the default group's hosts queued"
        );
    }

    #[test]
    fn queue_hash_plan_single_default_uses_the_flat_recipe() {
        // The shape pin: a no-profiles plan hashes with the flat recipe,
        // grouped plans with the grouped one.
        let hosts: Vec<u32> = [0x0A00_0005u32, 0x0A00_0006].to_vec();
        let legacy = [StateProfile {
            label: "default".into(),
            ports: Vec::new(),
            nmap_args: "-sC -sV".into(),
        }];
        assert_eq!(
            queue_hash_plan(&legacy, &hosts),
            queue_hash("-sC -sV", &hosts)
        );
    }

    #[test]
    fn queue_hash_plan_forks_on_label_args_and_host_changes() {
        let hosts: Vec<u32> = [0x0A00_0005u32].to_vec();
        let a = [StateProfile {
            label: "10.30.0.0/24".into(),
            ports: Vec::new(),
            nmap_args: "-sC -sV".into(),
        }];
        let same = a.clone();
        assert_eq!(queue_hash_plan(&a, &hosts), queue_hash_plan(&same, &hosts));
        let new_label = [StateProfile {
            label: "10.30.0.0/25".into(),
            ..a[0].clone()
        }];
        assert_ne!(
            queue_hash_plan(&a, &hosts),
            queue_hash_plan(&new_label, &hosts),
            "a label change forks the queue"
        );
        let new_args = [StateProfile {
            nmap_args: "-sV -p 22,80".into(),
            ..a[0].clone()
        }];
        assert_ne!(
            queue_hash_plan(&a, &hosts),
            queue_hash_plan(&new_args, &hosts),
            "an args change — the port list rides in it — forks the queue"
        );
        assert_ne!(
            queue_hash_plan(&a, &hosts),
            queue_hash_plan(&a, &[0x0A00_0006]),
            "a host change forks the queue"
        );
        // multi-group plans never take the flat recipe
        let two = [
            a[0].clone(),
            StateProfile {
                label: "default".into(),
                ports: Vec::new(),
                nmap_args: String::new(),
            },
        ];
        assert_ne!(
            queue_hash_plan(&two, &hosts),
            queue_hash("", &hosts),
            "a grouped plan must not collide with the flat recipe"
        );
    }

    #[test]
    fn legacy_state_without_profiles_normalizes() {
        // The exact pre-profiles state shape (pinned by the web integration
        // fixture): no `profiles`, no `only`, no `profile` on the chunk.
        // The pinned port list rides along until adoption re-pins it.
        let text = r#"{"ports":[80],"nmap_args":"","queue_hash":0,"chunks":[{"hosts":["127.0.0.2","127.0.0.3"],"done":true,"attempts":0,"skipped":false}],"done":true}"#;
        let dir = std::env::temp_dir().join(format!(
            "rustrawl-legacy-state-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("scan_state.json"), text).unwrap();
        let st = read_scan_state(&dir).unwrap();
        assert_eq!(st.profiles.len(), 1, "one synthetic default profile");
        assert_eq!(st.profiles[0].label, "default");
        assert_eq!(
            st.profiles[0].ports,
            vec![80],
            "legacy ports preserved so adoption can see them"
        );
        assert_eq!(st.chunk_profile(0), "");
        assert_eq!(st.chunk_label(0), "default");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn adoption_repins_legacy_port_lists_and_recomputes_the_hash() {
        let mut st = ScanState {
            ports: vec![80, 443],
            nmap_args: "-sC -sV".into(),
            queue_hash: 0,
            profiles: vec![StateProfile {
                label: "10.30.0.0/24".into(),
                ports: vec![80],
                nmap_args: "-sC -sV".into(),
            }],
            only: Vec::new(),
            chunks: vec![Chunk {
                hosts: vec!["10.30.0.7".into()],
                done: false,
                attempts: 0,
                skipped: false,
                profile: 0,
            }],
            done: false,
        };
        assert!(adopt_legacy_ports(&mut st), "a legacy queue is adopted");
        assert!(st.ports.is_empty());
        assert!(st.profiles[0].ports.is_empty());
        // the recomputed hash is the args-only recipe over the chunk's
        // hosts; a labeled profile pins the grouped shape — the same
        // recipe the resume drift check recomputes on the next run
        let hosts = vec![u32::from("10.30.0.7".parse::<Ipv4Addr>().unwrap())];
        assert_eq!(st.queue_hash, queue_hash_grouped(&st.profiles, &hosts));
        // already-adopted state: untouched
        let before = st.queue_hash;
        assert!(!adopt_legacy_ports(&mut st));
        assert_eq!(st.queue_hash, before);
    }

    #[test]
    fn adoption_of_a_pre_profiles_state_uses_the_flat_recipe() {
        let mut st = ScanState {
            ports: vec![80, 443],
            nmap_args: "-sC -sV".into(),
            queue_hash: 0,
            profiles: Vec::new(),
            only: Vec::new(),
            chunks: vec![Chunk {
                hosts: vec!["10.30.0.7".into()],
                done: false,
                attempts: 0,
                skipped: false,
                profile: 0,
            }],
            done: false,
        };
        st.normalize_profiles();
        assert!(adopt_legacy_ports(&mut st));
        let hosts = vec![u32::from("10.30.0.7".parse::<Ipv4Addr>().unwrap())];
        assert_eq!(st.queue_hash, queue_hash("-sC -sV", &hosts));
    }
}
