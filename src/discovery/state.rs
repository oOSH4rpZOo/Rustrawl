//! Run identity, crash-safe state, perimeter lock, and the evidence files.
//!
//! One run directory holds the whole sweep→expand chain: `state.json` /
//! `state_b.json` (seed + cursor, atomic rename), `live.jsonl` /
//! `live_b.jsonl` (append-only events) and `ip.txt` / `ip_b.txt`
//! (regenerated at the end of every stage — `ip_b.txt` is the nmap scan
//! input). The inter-run registry itself is the DB (`scandb.sqlite`, see
//! `db.rs`).

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};

/// Per-stage evidence filenames inside one run directory. The sweep keeps
/// its historical names; later stages get a suffix.
#[derive(Debug, Clone, Copy)]
pub struct StageFiles {
    pub state: &'static str,
    pub live: &'static str,
    pub ip: &'static str,
}

pub const SWEEP_FILES: StageFiles = StageFiles {
    state: "state.json",
    live: "live.jsonl",
    ip: "ip.txt",
};

pub const EXPAND_FILES: StageFiles = StageFiles {
    state: "state_b.json",
    live: "live_b.jsonl",
    ip: "ip_b.txt",
};

/// Where the permutation stream stopped. Block granularity, plus the exact
/// position inside the block being written on abort (SIGINT, mute abort).
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct Cursor {
    pub block_list_pos: u64,
    pub inner: u32,
    pub port: u32,
}

fn d_mute_budget() -> u64 {
    1024
}

/// Layout version of the state files. A state written by another version is
/// refused with an explicit message — a silent reinterpretation (fields that
/// moved meaning) would corrupt the resume cursor.
pub const STATE_SCHEMA: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct EngineState {
    /// Set by every writer; read_state refuses 0 (pre-schema file) and any
    /// version newer than this build.
    #[serde(default)]
    pub schema: u32,
    pub seed_hex: String,
    /// Fingerprints of the target set and the profile: a --resume against a
    /// changed scope would silently remap every flat index to different
    /// hosts, so the caller refuses on mismatch. `scan_hash` is a content
    /// hash of the merged ranges and the port list — a scope edit that keeps
    /// the host count must still be caught.
    pub host_total: u64,
    pub ports_n: u64,
    pub block: u32,
    #[serde(default)]
    pub scan_hash: u64,
    pub cursor: Cursor,
    pub sent: u64,
    /// Mute accounting across resumes: consecutively settled-mute hosts at
    /// the last state write. Without it, every `--resume` would hand the
    /// mute protection a fresh 1024-host budget — a filtering verdict could
    /// then hide behind a chain of interrupts.
    #[serde(default)]
    pub since_reply: u64,
    /// Current consecutive-mute kill-switch budget (starts at the scope's
    /// mute_abort_after, doubles on every re-probe that proves the stretch
    /// was merely empty, capped at 65,536; 0 disables the switch).
    /// Persisted so a resume keeps the adapted budget instead of handing
    /// the protection a fresh default.
    #[serde(default = "d_mute_budget")]
    pub mute_budget: u64,
    /// Host index of the last live event; the IP is re-derived from the
    /// target set on resume (the fingerprint guard guarantees the same
    /// mapping). `Option` because a run may never have seen a live host.
    #[serde(default)]
    pub last_live_idx: Option<u64>,
    /// Sweep-group bookkeeping. Per-range port profiles partition the
    /// perimeter into groups swept sequentially; this records where a
    /// partial run stopped. `0`/`0` on older state files (serde default):
    /// resume maps them onto a single legacy group, so old runs stay
    /// resumable unchanged.
    #[serde(default)]
    pub group: u32,
    #[serde(default)]
    pub groups_total: u32,
    pub done: bool,
}

/// FNV-1a over the merged ranges and the port list, in order. Ranges are
/// canonical (sorted, merged) from `Targets::new`, so the hash is stable
/// across processes; even the expand stage's ~65k ranges cost microseconds.
pub fn fingerprint(ranges: &[crate::targets::IpRange], ports: &[u16]) -> u64 {
    const BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x100_0000_01b3;
    let mut h = BASIS;
    let mut fold = |bytes: &[u8]| {
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(PRIME);
        }
    };
    for r in ranges {
        fold(&r.start.to_le_bytes());
        fold(&r.end.to_le_bytes());
    }
    // separator so [range 1-2] + [port 3] never collides with [range 1] + ...
    fold(b"|");
    for p in ports {
        fold(&p.to_le_bytes());
    }
    h
}

/// `<prefix>_<YYYY-MM-DD>_<HHMMSS>` in local time — sortable, fs-safe and
/// readable at a glance in `runs/`. Two runs started within the same second
/// stay distinct through `create_run`'s `-2`/`-3` suffix.
pub fn stamped_id(prefix: &str) -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: localtime_r with a valid timestamp and out-struct (the _r
    // variant touches no global state).
    unsafe { libc::localtime_r(&secs, &mut tm) };
    format!(
        "{prefix}_{}-{:02}-{:02}_{:02}{:02}{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

/// `discovery_<date>_<time>` — the `run` (discovery) run-directory name.
pub fn new_run_id() -> String {
    stamped_id("discovery")
}

/// `scan_<date>_<time>` — the `scan` (nmap fingerprinting) run-directory name.
pub fn new_scan_id() -> String {
    stamped_id("scan")
}

/// `names_<date>_<time>` — the `names` (hostname collection) run-directory
/// name.
pub fn new_names_id() -> String {
    stamped_id("names")
}

pub fn runs_dir(root: &Path) -> PathBuf {
    root.join("runs")
}

pub fn create_run(root: &Path, run_id: &str) -> Result<PathBuf> {
    let runs = runs_dir(root);
    std::fs::create_dir_all(&runs).with_context(|| format!("creating {}", runs.display()))?;
    // Exclusive create — two runs started in the same second must never merge
    // their evidence into one directory.
    let mut dir = runs.join(run_id);
    let mut n = 1u32;
    loop {
        match std::fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                n += 1;
                dir = runs.join(format!("{run_id}-{n}"));
            }
            Err(e) => {
                return Err(e).with_context(|| format!("creating run dir {}", dir.display()));
            }
        }
    }
}

/// Newest run with an unfinished stage — the resume target. Either stage's
/// state file qualifies: a run interrupted during the expansion may never
/// have written `state.json` (the sweep skipped over fresh-verdict hosts),
/// and it is still the newest resumable run.
pub fn find_resumable(root: &Path) -> Result<Option<PathBuf>> {
    let runs = runs_dir(root);
    if !runs.is_dir() {
        return Ok(None);
    }
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(&runs)
        .with_context(|| format!("listing {}", runs.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.join(SWEEP_FILES.state).is_file() || p.join(EXPAND_FILES.state).is_file())
        .collect();
    candidates.sort();
    Ok(candidates.pop())
}

pub fn read_state(run_dir: &Path, files: &StageFiles) -> Result<EngineState> {
    let path = run_dir.join(files.state);
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let st: EngineState =
        serde_json::from_str(&text).with_context(|| format!("format of {}", path.display()))?;
    if st.schema == 0 {
        bail!(
            "{}: state has no schema marker - written by an older rustrawl; \
             this build cannot resume it safely, start a fresh run",
            path.display()
        );
    }
    if st.schema > STATE_SCHEMA {
        bail!(
            "{}: state schema {} but this build expects {STATE_SCHEMA} - \
             written by a newer rustrawl; upgrade before resuming",
            path.display(),
            st.schema
        );
    }
    Ok(st)
}

/// Atomic write (tmp + fsync + rename) — a crash or power cut never leaves a
/// torn state file behind.
pub fn write_state(run_dir: &Path, files: &StageFiles, state: &EngineState) -> Result<()> {
    let path = run_dir.join(files.state);
    let tmp = run_dir.join(format!("{}.tmp", files.state));
    let text = serde_json::to_string_pretty(state).context("serializing state")?;
    let mut f = File::create(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
    f.write_all(text.as_bytes())
        .with_context(|| format!("writing {}", tmp.display()))?;
    f.sync_all()
        .with_context(|| format!("syncing {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("renaming {}", path.display()))?;
    Ok(())
}

/// Exclusive lock on `<root>/run.lock` — one scan per perimeter (lesson 8).
/// Held for the lifetime of the returned file.
pub fn lock_perimeter(root: &Path) -> Result<File> {
    std::fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
    let file = File::create(root.join("run.lock")).context("opening run.lock")?;
    file.try_lock_exclusive().map_err(|_| {
        anyhow::anyhow!(
            "another rustrawl holds {} - one scan per perimeter (lesson 8)",
            root.join("run.lock").display()
        )
    })?;
    Ok(file)
}

/// Append-only evidence for discovered live ports; every event is flushed so a
/// crash keeps what it saw.
pub struct LiveLog {
    file: File,
}

impl LiveLog {
    pub fn open(run_dir: &Path, files: &StageFiles) -> Result<Self> {
        let path = run_dir.join(files.live);
        // read(true) is required by the torn-tail check below: without it the
        // handle is O_WRONLY, the read fails with EBADF, and a torn last line
        // would silently swallow the next recorded event on replay.
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .with_context(|| format!("opening {} in {}", files.live, run_dir.display()))?;
        // A crash mid-write leaves a torn last line; terminate it so the next
        // recorded event starts on a fresh line and replay never drops it.
        if file.metadata().map(|m| m.len()).unwrap_or(0) > 0 {
            let mut last = [0u8; 1];
            if file.seek(SeekFrom::End(-1)).is_ok()
                && file.read_exact(&mut last).is_ok()
                && last[0] != b'\n'
            {
                let _ = file.write_all(b"\n");
            }
        }
        Ok(Self { file })
    }

    pub fn record(&mut self, host_idx: u64, ip: Ipv4Addr, port: u16, why: &str) -> Result<()> {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        writeln!(
            self.file,
            r#"{{"t":{secs},"idx":{host_idx},"ip":"{ip}","port":{port},"why":"{why}"}}"#
        )?;
        self.file.flush()?;
        Ok(())
    }

    /// Replays a previous run's events (resume): unique live host indexes.
    /// `allow` is the resuming group's target bitmap: the log line carries
    /// the ip, so a group resume drops other groups' events instead of
    /// mapping foreign indexes onto this group's host list. Lines without
    /// an ip predate sweep groups (one implicit group = the whole list,
    /// indexes align) and are kept.
    pub fn replay(
        run_dir: &Path,
        files: &StageFiles,
        allow: &roaring::RoaringBitmap,
    ) -> Result<std::collections::BTreeSet<u64>> {
        let path = run_dir.join(files.live);
        let mut out = std::collections::BTreeSet::new();
        if !path.is_file() {
            return Ok(out);
        }
        for line in BufReader::new(File::open(&path)?).lines() {
            let line = line?;
            #[derive(Deserialize)]
            struct Ev {
                idx: u64,
                ip: Option<String>,
            }
            let Ok(ev) = serde_json::from_str::<Ev>(&line) else {
                continue;
            };
            let keep = ev
                .ip
                .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                .map(|ip| allow.contains(u32::from(ip)))
                .unwrap_or(true);
            if keep {
                out.insert(ev.idx);
            }
        }
        Ok(out)
    }
}

/// One IP per line — the next stage's input list.
pub fn write_ip_list(
    run_dir: &Path,
    files: &StageFiles,
    ips: impl Iterator<Item = Ipv4Addr>,
) -> Result<()> {
    let path = run_dir.join(files.ip);
    let mut f = File::create(&path).with_context(|| format!("writing {}", path.display()))?;
    for ip in ips {
        writeln!(f, "{ip}")?;
    }
    Ok(())
}

/// Appends a line to the run log and returns an appender used by the engine.
pub fn open_run_log(run_dir: &Path) -> Result<File> {
    open_run_log_as(run_dir, "run.log")
}

/// Same, under a caller-chosen file name — the `names` collector writes
/// `names.log` (its run dir holds no engine state, the log is the evidence).
pub fn open_run_log_as(run_dir: &Path, file: &str) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(run_dir.join(file))
        .with_context(|| format!("opening {file} in {}", run_dir.display()))
}

pub fn log_line(log: &mut File, line: &str) {
    let _ = writeln!(log, "{line}");
    // The evidence copy always lands; the terminal copy goes above the
    // status bar when a screen is up, plain stderr otherwise.
    crate::tui::event(line);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::targets::Targets;

    fn sample(seed: &str) -> EngineState {
        EngineState {
            schema: STATE_SCHEMA,
            seed_hex: seed.to_string(),
            host_total: 256,
            ports_n: 2,
            block: 16,
            scan_hash: 42,
            group: 0,
            groups_total: 1,
            cursor: Cursor::default(),
            sent: 10,
            since_reply: 3,
            mute_budget: 1024,
            last_live_idx: Some(7),
            done: false,
        }
    }

    #[test]
    fn schema_guard_refuses_older_and_newer_states() {
        let dir = std::env::temp_dir().join(format!("rustrawl-state-it-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // schema 0 (pre-marker file): refuse, say why, never resume
        let mut old = sample("aa");
        old.schema = 0;
        write_state(&dir, &SWEEP_FILES, &old).unwrap();
        let err = format!("{}", read_state(&dir, &SWEEP_FILES).unwrap_err());
        assert!(err.contains("older rustrawl"), "{err}");

        // a future build: refuse with the upgrade hint
        let mut new = sample("bb");
        new.schema = STATE_SCHEMA + 1;
        write_state(&dir, &SWEEP_FILES, &new).unwrap();
        let err = format!("{}", read_state(&dir, &SWEEP_FILES).unwrap_err());
        assert!(err.contains("newer rustrawl"), "{err}");

        // current schema roundtrips, including the resume fields defaults
        // carry (an older build's file lacks them entirely — serde default).
        let cur = sample("cc");
        write_state(&dir, &SWEEP_FILES, &cur).unwrap();
        let back = read_state(&dir, &SWEEP_FILES).unwrap();
        assert_eq!(back.schema, STATE_SCHEMA);
        assert_eq!((back.since_reply, back.last_live_idx), (3, Some(7)));
        // a file without the newer fields still loads via serde defaults
        // (mute_budget 1024) — but its schema stays 0, so read_state refuses
        // it: the intended contract for pre-schema states.
        let legacy = r#"{"seed_hex":"dd","host_total":256,"ports_n":2,"block":16,
            "cursor":{"block_list_pos":0,"inner":0,"port":0},"sent":0,"done":false}"#;
        std::fs::write(dir.join(SWEEP_FILES.state), legacy).unwrap();
        let err = format!("{}", read_state(&dir, &SWEEP_FILES).unwrap_err());
        assert!(err.contains("older rustrawl"), "{err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn torn_live_log_repairs_and_replays() {
        let dir = std::env::temp_dir().join(format!("rustrawl-torn-it-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // a crash mid-line: the last record is cut in half
        let torn = concat!(
            r#"{"t":100,"idx":1,"ip":"10.0.0.1","port":22,"why":"refused"}"#,
            "\n",
            r#"{"t":101,"idx":2,"ip":"10.0.0.2","port":80,"why":"re"#,
        );
        std::fs::write(dir.join(SWEEP_FILES.live), torn).unwrap();

        // open repairs the tail; the next event lands on a fresh line
        let mut log = LiveLog::open(&dir, &SWEEP_FILES).unwrap();
        log.record(3, Ipv4Addr::new(10, 0, 0, 3), 443, "reset")
            .unwrap();
        drop(log);

        let allow = roaring::RoaringBitmap::from_iter([
            u32::from(Ipv4Addr::new(10, 0, 0, 1)),
            u32::from(Ipv4Addr::new(10, 0, 0, 3)),
        ]);
        let replayed = LiveLog::replay(&dir, &SWEEP_FILES, &allow).unwrap();
        assert_eq!(
            replayed.iter().copied().collect::<Vec<u64>>(),
            vec![1, 3],
            "the torn line must be dropped, the valid prefix and the new event kept"
        );

        // a clean (newline-terminated) file must not be modified by open()
        std::fs::write(
            dir.join(SWEEP_FILES.live),
            concat!(
                r#"{"t":1,"idx":9,"ip":"10.0.0.9","port":22,"why":"x"}"#,
                "\n"
            ),
        )
        .unwrap();
        let len_before = std::fs::metadata(dir.join(SWEEP_FILES.live)).unwrap().len();
        LiveLog::open(&dir, &SWEEP_FILES).unwrap();
        assert_eq!(
            std::fs::metadata(dir.join(SWEEP_FILES.live)).unwrap().len(),
            len_before,
            "a clean log must not grow on open"
        );
        assert_eq!(
            LiveLog::replay(&dir, &EXPAND_FILES, &roaring::RoaringBitmap::new())
                .unwrap()
                .len(),
            0,
            "missing file → empty"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fingerprint_detects_equal_size_changes() {
        let a = Targets::build(&["10.0.0.0/24".into(), "10.0.1.0/24".into()], &[]).unwrap();
        let b = Targets::build(&["10.0.0.0/24".into(), "10.0.2.0/24".into()], &[]).unwrap();
        let ports = [22u16, 80];
        assert_eq!(
            fingerprint(a.ranges(), &ports),
            fingerprint(a.ranges(), &ports)
        );
        assert_ne!(
            fingerprint(a.ranges(), &ports),
            fingerprint(b.ranges(), &ports),
            "same host count, different ranges must not pass the resume guard"
        );
        assert_ne!(
            fingerprint(a.ranges(), &ports),
            fingerprint(a.ranges(), &[80u16, 22]),
            "same ports reordered is a different stream layout"
        );
    }
}
