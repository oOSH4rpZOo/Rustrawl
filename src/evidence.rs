//! Raw nmap evidence for one host: which scan run queued it, in which
//! chunk, and the host's verbatim section of the chunk's captured .nmap.
//!
//! The registry stores hosts, probes and services — not which chunk a host
//! was queued into — so the map is `scan_state.json` itself: its chunk host
//! lists are written once at queue build time and never reordered. Scan run
//! directory names are chronological (the same assumption `find_resumable`
//! makes), so "newest first" is directory sort reversed.

use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::scan::read_scan_state;

/// Where a host's nmap evidence lives: the newest scan run that queued it
/// and the chunk index inside that run.
pub struct Hit {
    pub run_dir: PathBuf,
    pub run_id: String,
    pub chunk: usize,
}

/// One run's evidence for the host, for the web sheet's stack: the run and
/// chunk it was queued in, whether the capture carries a report, the
/// command that chunk ran (empty when the .argv capture is missing - runs
/// from before the capture existed, or a pruned one), and the text (the
/// verbatim capture, or the explanation sentence).
pub struct Block {
    pub run_id: String,
    pub chunk: usize,
    pub has_report: bool,
    pub cmd: String,
    pub text: String,
}

/// How many run blocks the web sheet stacks, newest first. Rescans pile
/// up; the sheet keeps the freshest twenty and the registry stays the
/// full record.
pub const SHEET_STACK: usize = 20;

const REPORT_MARK: &str = "Nmap scan report for ";

/// The IP a report line is about: `Nmap scan report for <ip>` bare, or
/// `Nmap scan report for name (<ip>)` when reverse resolution was on.
/// The comparison is token-exact — 10.0.0.55 must not match 10.0.0.5.
fn report_ip(line: &str) -> Option<&str> {
    let rest = line.strip_prefix(REPORT_MARK)?;
    let ip = match rest.rsplit_once(" (") {
        // "name (10.0.0.5)" — the paren form; drop the trailing ")".
        Some((_, tail)) => tail.strip_suffix(')')?,
        None => rest,
    };
    let ip = ip.trim();
    ip.parse::<Ipv4Addr>().is_ok().then_some(ip)
}

/// The host's verbatim section of a captured .nmap: from its report line to
/// the next report line (or end of text), trailing blank lines trimmed.
/// `None` when no report line in `text` is about `ip`.
pub fn extract_host_block(text: &str, ip: Ipv4Addr) -> Option<String> {
    let dotted = ip.to_string();
    let mut started = false;
    let mut block: Vec<&str> = Vec::new();
    for line in text.lines() {
        if !started {
            if report_ip(line) == Some(dotted.as_str()) {
                started = true;
                block.push(line); // the report line opens the block
            }
            continue;
        }
        if line.starts_with(REPORT_MARK) {
            break;
        }
        block.push(line);
    }
    if !started {
        return None;
    }
    while matches!(block.last(), Some(l) if l.trim().is_empty()) {
        block.pop();
    }
    Some(format!("{}\n", block.join("\n")))
}

/// Sort key for run directory names: the `YYYY-MM-DD_HHMMSS` stamp when
/// the name carries one (every current prefix does), so `manual_…` and
/// `scan_…` runs interleave chronologically instead of sorting apart by
/// prefix; legacy unstamped ids sort oldest. `create_run`'s `-2` collision
/// suffix rides along and lands after its base, as intended.
fn run_stamp_key(name: &str) -> String {
    let legacy = name.starts_with("run-") || name.starts_with("fp-run-");
    match name.find(|c: char| c.is_ascii_digit()) {
        Some(i) if !legacy => name[i..].to_string(),
        _ => format!("0{name}"),
    }
}

/// Find every scan run that queued `ip`, newest first. Manual rescans
/// (`manual_…` run dirs) count as scan runs — they are the freshest
/// evidence by construction. A perimeter with no runs/ yields an empty
/// vec (the caller picks the wording); a run whose state cannot be read is
/// skipped, not fatal for the others (the operator may have pruned it
/// half-way).
pub fn locate_host_chunks(runs_dir: &Path, ip: Ipv4Addr) -> Result<Vec<Hit>> {
    let dotted = ip.to_string();
    let mut runs: Vec<PathBuf> = match std::fs::read_dir(runs_dir) {
        // A perimeter that never ran anything has no runs/ — that is the
        // "no scan run yet" fallback, not an error.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        other => other
            .with_context(|| format!("reading {}", runs_dir.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("scan_") || n.starts_with("manual_"))
            })
            .collect(),
    };
    runs.sort_by_key(|p| run_stamp_key(p.file_name().and_then(|n| n.to_str()).unwrap_or_default()));
    let mut hits = Vec::new();
    for run_dir in runs.iter().rev() {
        let run_id = run_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let state = match read_scan_state(run_dir) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if let Some(chunk) = state.chunk_of(&dotted) {
            hits.push(Hit {
                run_dir: run_dir.clone(),
                run_id,
                chunk,
            });
        }
    }
    Ok(hits)
}

/// Whether the perimeter holds any scan (or manual) run at all — the
/// "never queued" vs "nothing ran yet" wording split.
pub fn has_scan_runs(runs_dir: &Path) -> bool {
    std::fs::read_dir(runs_dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok()).any(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                n.starts_with("scan_") || n.starts_with("manual_")
            })
        })
        .unwrap_or(false)
}

/// The chunk's captured command line (`chunk-XXXX.argv`, written per
/// spawn): joined to one line, lossy. A run that captured the command one
/// token per line (the test nmap stand-in does) reads the same - the join
/// rebuilds the command either way. A missing file is an empty string: the
/// renderers hide the line rather than invent one.
pub(crate) fn chunk_cmd(run_dir: &Path, chunk: usize) -> String {
    let path = run_dir.join("scans").join(format!("chunk-{chunk:04}.argv"));
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => return String::new(),
    };
    String::from_utf8_lossy(&bytes)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The command line of one chunk of a named run, from the perimeter root -
/// the dashboard's live-output route reads the running rescan's command
/// this way.
pub(crate) fn run_chunk_cmd(out: &Path, run: &str, chunk: usize) -> String {
    chunk_cmd(&crate::discovery::state::runs_dir(out).join(run), chunk)
}

/// Every run's evidence for the host, newest first, capped at
/// [`SHEET_STACK`] — the web sheet's stack. Each queued pass yields a
/// block even when its capture is missing or holds no report: the stack
/// tells the truth about every pass instead of hiding the empty ones.
pub fn collect_host_evidence(out: &Path, ip: Ipv4Addr, cap: usize) -> Result<Vec<Block>> {
    let runs_dir = crate::discovery::state::runs_dir(out);
    let hits = locate_host_chunks(&runs_dir, ip)?;
    let mut blocks = Vec::new();
    for hit in hits.into_iter().take(cap) {
        let capture = hit
            .run_dir
            .join("scans")
            .join(format!("chunk-{:04}.nmap", hit.chunk));
        let (has_report, text) = match std::fs::read(&capture) {
            // lossy: a capture with a stray non-UTF-8 byte still renders
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes).into_owned();
                match extract_host_block(&text, ip) {
                    Some(block) => (true, block),
                    None => (
                        false,
                        format!(
                            "chunk-{:04}.nmap holds no report for {ip} (killed mid-chunk, or the host was down that pass)",
                            hit.chunk
                        ),
                    ),
                }
            }
            Err(_) => (
                false,
                format!("evidence file missing or unreadable: {}", capture.display()),
            ),
        };
        blocks.push(Block {
            run_id: hit.run_id,
            chunk: hit.chunk,
            has_report,
            cmd: chunk_cmd(&hit.run_dir, hit.chunk),
            text,
        });
    }
    Ok(blocks)
}

/// The `hosts -S` stack: the N newest evidence blocks (the operator picks
/// N, one is the default), each labeled with its run and chunk. The
/// fallback wording matches the single-block view when nothing exists at
/// all.
pub fn render_host_evidence_last(
    w: &mut dyn Write,
    out: &Path,
    ip: Ipv4Addr,
    n: usize,
) -> Result<()> {
    let runs_dir = crate::discovery::state::runs_dir(out);
    let blocks = collect_host_evidence(out, ip, n)?;
    if blocks.is_empty() {
        writeln!(w, "--- nmap evidence ---")?;
        if has_scan_runs(&runs_dir) {
            writeln!(
                w,
                "  {ip} was never queued in a scan run (discovery-only host)"
            )?;
        } else {
            writeln!(w, "  no scan run on this perimeter yet")?;
        }
        return Ok(());
    }
    for b in &blocks {
        writeln!(
            w,
            "--- nmap evidence \u{b7} run {} \u{b7} chunk-{:04} ---",
            b.run_id, b.chunk
        )?;
        if !b.cmd.is_empty() {
            writeln!(w, "  $ {}", b.cmd)?;
        }
        write!(w, "{}", b.text)?;
        if !b.text.ends_with('\n') {
            writeln!(w)?;
        }
    }
    if blocks.len() < n {
        writeln!(w, "  ({} scan pass(es) recorded for {ip})", blocks.len())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One scan run: `scan_state.json` with the given chunk host lists and a
    /// captured .nmap per chunk. Returns the run directory.
    fn scan_run(runs: &Path, name: &str, chunks: &[&[&str]], nmaps: &[&str]) -> PathBuf {
        let dir = runs.join(name).join("scans");
        std::fs::create_dir_all(&dir).unwrap();
        let state = format!(
            "{{\"ports\":[80],\"nmap_args\":\"\",\"queue_hash\":0,\"chunks\":[{}],\"done\":true}}",
            chunks
                .iter()
                .map(|hosts| format!(
                    "{{\"hosts\":[{}],\"done\":true,\"attempts\":0,\"skipped\":false}}",
                    hosts
                        .iter()
                        .map(|h| format!("\"{h}\""))
                        .collect::<Vec<_>>()
                        .join(",")
                ))
                .collect::<Vec<_>>()
                .join(",")
        );
        std::fs::write(runs.join(name).join("scan_state.json"), state).unwrap();
        for (i, text) in nmaps.iter().enumerate() {
            std::fs::write(dir.join(format!("chunk-{i:04}.nmap")), text).unwrap();
        }
        runs.join(name)
    }

    const REPORT_A: &str = "\
Starting Nmap 7.99 ( https://nmap.org )
Nmap scan report for 127.0.0.5
Host is up (0.00042s latency).
PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx 1.22.1
Nmap scan report for 127.0.0.6
Host is down.
";

    #[test]
    fn locate_prefers_the_newest_run() {
        let root = std::env::temp_dir().join(format!("rustrawl-ev-1-{}", std::process::id()));
        let runs = root.join("runs");
        std::fs::create_dir_all(&runs).unwrap();
        scan_run(&runs, "scan_2026-10-01_090000", &[&["127.0.0.5"]], &["old"]);
        scan_run(&runs, "scan_2026-10-02_090000", &[&["127.0.0.5"]], &["new"]);
        // Discovery runs are noise for this lookup — never matched.
        scan_run(&runs, "discovery_2026-10-03_090000", &[&["127.0.0.5"]], &[]);
        let ip: Ipv4Addr = "127.0.0.5".parse().unwrap();

        let hits = locate_host_chunks(&runs, ip).unwrap();
        assert_eq!(hits.len(), 2, "both scan runs queued it, newest first");
        assert_eq!(hits[0].run_id, "scan_2026-10-02_090000");
        assert_eq!(hits[0].chunk, 0);
        assert_eq!(hits[1].run_id, "scan_2026-10-01_090000");

        // A host only an older run queued still resolves, through the newer
        // runs' states.
        scan_run(&runs, "scan_2026-10-04_090000", &[&["127.0.0.9"]], &[]);
        let hits = locate_host_chunks(&runs, ip).unwrap();
        assert_eq!(hits[0].run_id, "scan_2026-10-02_090000");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn manual_and_scan_runs_interleave_by_stamp() {
        // Lexically "manual_…" < "scan_…", so a name sort would bury a
        // rescan under an older queue run; the stamp inside the name is
        // what orders the lookup.
        let root = std::env::temp_dir().join(format!("rustrawl-ev-5-{}", std::process::id()));
        let runs = root.join("runs");
        std::fs::create_dir_all(&runs).unwrap();
        scan_run(
            &runs,
            "scan_2026-10-09_120000",
            &[&["127.0.0.5"]],
            &["queue"],
        );
        scan_run(
            &runs,
            "manual_2026-10-10_083000",
            &[&["127.0.0.5"]],
            &["rescan"],
        );
        let ip: Ipv4Addr = "127.0.0.5".parse().unwrap();

        let hits = locate_host_chunks(&runs, ip).unwrap();
        assert_eq!(hits[0].run_id, "manual_2026-10-10_083000");
        assert_eq!(hits[1].run_id, "scan_2026-10-09_120000");

        // A newer queue run takes the crown back.
        scan_run(
            &runs,
            "scan_2026-10-11_090000",
            &[&["127.0.0.5"]],
            &["fresh"],
        );
        let hits = locate_host_chunks(&runs, ip).unwrap();
        assert_eq!(hits[0].run_id, "scan_2026-10-11_090000");
        assert_eq!(hits.len(), 3, "every older pass stays in the list");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_corrupt_state_does_not_kill_the_lookup() {
        let root = std::env::temp_dir().join(format!("rustrawl-ev-2-{}", std::process::id()));
        let runs = root.join("runs");
        std::fs::create_dir_all(&runs).unwrap();
        scan_run(&runs, "scan_2026-10-01_090000", &[&["127.0.0.5"]], &["old"]);
        std::fs::write(runs.join("scan_2026-10-02_090000.json"), "not a run dir").ok();
        std::fs::create_dir_all(runs.join("scan_2026-10-02_090000")).unwrap();
        std::fs::write(
            runs.join("scan_2026-10-02_090000").join("scan_state.json"),
            "{ broken",
        )
        .unwrap();
        let ip: Ipv4Addr = "127.0.0.5".parse().unwrap();
        let hits = locate_host_chunks(&runs, ip).unwrap();
        assert_eq!(hits[0].run_id, "scan_2026-10-01_090000");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn host_block_spans_exactly_one_report() {
        let ip: Ipv4Addr = "127.0.0.5".parse().unwrap();
        let block = extract_host_block(REPORT_A, ip).expect("a block");
        assert!(block.starts_with("Nmap scan report for 127.0.0.5\n"));
        assert!(block.contains("nginx 1.22.1"));
        assert!(
            !block.contains("127.0.0.6"),
            "stops at the next report: {block:?}"
        );
        assert!(
            !block.contains("Starting Nmap"),
            "starts at the report line"
        );

        // The parenthesized name form still resolves to the bare IP.
        let text = "Nmap scan report for foo.example (127.0.0.5)\nHost is up.\n";
        let block = extract_host_block(text, ip).expect("a block");
        assert!(block.contains("Host is up."), "{block:?}");

        // Token-exact: 10.0.0.55 is not 10.0.0.5.
        let ip5: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let text = "Nmap scan report for 10.0.0.55\nHost is up.\n";
        assert!(extract_host_block(text, ip5).is_none());

        // Absent IP → None.
        let ip9: Ipv4Addr = "127.0.0.9".parse().unwrap();
        assert!(extract_host_block(REPORT_A, ip9).is_none());
    }

    #[test]
    fn trailing_blank_lines_are_trimmed() {
        let ip: Ipv4Addr = "127.0.0.5".parse().unwrap();
        // Everything after the last report line belongs to that host's block
        // (verbatim, to the end of the capture); trailing blanks go.
        let text = "Nmap scan report for 127.0.0.5\nHost is up.\n\n\n\n";
        let block = extract_host_block(text, ip).expect("a block");
        assert_eq!(block, "Nmap scan report for 127.0.0.5\nHost is up.\n");
    }

    #[test]
    fn render_last_covers_every_fallback_sentence() {
        let root = std::env::temp_dir().join(format!("rustrawl-ev-3-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let runs = crate::discovery::state::runs_dir(&root);
        let ip: Ipv4Addr = "127.0.0.5".parse().unwrap();
        let ip9: Ipv4Addr = "127.0.0.9".parse().unwrap();

        // 1. no scan run at all.
        let mut buf = Vec::new();
        render_host_evidence_last(&mut buf, &root, ip, 1).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("no scan run on this perimeter yet"), "{out}");

        // 2. a scan run exists, but the host was never queued.
        scan_run(&runs, "scan_2026-10-01_090000", &[&["127.0.0.6"]], &[]);
        let mut buf = Vec::new();
        render_host_evidence_last(&mut buf, &root, ip9, 1).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("never queued in a scan run (discovery-only host)"),
            "{out}"
        );

        // 3. queued (its own run), but the capture file is missing.
        scan_run(&runs, "scan_2026-10-02_090000", &[&["127.0.0.5"]], &[]);
        let mut buf = Vec::new();
        render_host_evidence_last(&mut buf, &root, ip, 1).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("evidence file missing or unreadable"), "{out}");
        assert!(out.contains("chunk-0000"), "{out}");

        // 4. capture present but holds no report for the host.
        scan_run(
            &runs,
            "scan_2026-10-03_090000",
            &[&["127.0.0.5"]],
            &["nothing here"],
        );
        let mut buf = Vec::new();
        render_host_evidence_last(&mut buf, &root, ip, 1).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("holds no report for 127.0.0.5"), "{out}");

        // And the happy path: the verbatim block under its run label.
        let text = "Nmap scan report for 127.0.0.5\nHost is up (0.001s latency).\nPORT   STATE SERVICE\n80/tcp open  http\n";
        scan_run(&runs, "scan_2026-10-04_090000", &[&["127.0.0.5"]], &[text]);
        let mut buf = Vec::new();
        render_host_evidence_last(&mut buf, &root, ip, 3).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("run scan_2026-10-04_090000 · chunk-0000"),
            "{out}"
        );
        assert!(out.contains("PORT   STATE SERVICE"), "verbatim: {out}");
        assert!(
            out.contains("run scan_2026-10-02_090000"),
            "three runs queued it, three blocks come back: {out}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn the_stack_collects_every_run_newest_first() {
        let root = std::env::temp_dir().join(format!("rustrawl-ev-6-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let runs = crate::discovery::state::runs_dir(&root);
        let ip: Ipv4Addr = "127.0.0.5".parse().unwrap();

        // Nothing anywhere → empty vec, note decides the wording.
        assert!(collect_host_evidence(&root, ip, SHEET_STACK)
            .unwrap()
            .is_empty());
        assert!(!has_scan_runs(&runs));

        // A discovery-only run is not a scan run for this purpose.
        scan_run(&runs, "discovery_2026-10-01_090000", &[&["127.0.0.5"]], &[]);
        assert!(!has_scan_runs(&runs));
        assert!(collect_host_evidence(&root, ip, SHEET_STACK)
            .unwrap()
            .is_empty());

        // Three scan runs, oldest first; the middle one's capture is empty
        // (no report) and the newest one carries a real block. The oldest
        // carries a real report too — a stack keeps verbatim blocks from
        // every run, not just the newest.
        scan_run(
            &runs,
            "scan_2026-10-01_090000",
            &[&["127.0.0.5"]],
            &["Nmap scan report for 127.0.0.5\n22/tcp open ssh (old block)\n"],
        );
        scan_run(
            &runs,
            "scan_2026-10-02_090000",
            &[&["127.0.0.5"]],
            &["nothing here"],
        );
        let text = "Nmap scan report for 127.0.0.5\nHost is up.\nPORT   STATE SERVICE\n80/tcp open  http\n";
        scan_run(
            &runs,
            "manual_2026-10-03_083000",
            &[&["127.0.0.5"]],
            &[text],
        );
        assert!(has_scan_runs(&runs));

        let stack = collect_host_evidence(&root, ip, SHEET_STACK).unwrap();
        assert_eq!(stack.len(), 3);
        assert_eq!(stack[0].run_id, "manual_2026-10-03_083000");
        assert!(stack[0].has_report);
        assert!(stack[0].text.contains("PORT   STATE SERVICE"));
        assert_eq!(stack[1].run_id, "scan_2026-10-02_090000");
        assert!(
            !stack[1].has_report,
            "no-report capture becomes a note block"
        );
        assert!(stack[1].text.contains("holds no report for 127.0.0.5"));
        assert_eq!(stack[2].run_id, "scan_2026-10-01_090000");
        assert!(stack[2].text.contains("old block"));

        // A host only an older run queued still lands in the stack.
        let stack9 =
            collect_host_evidence(&root, "127.0.0.9".parse().unwrap(), SHEET_STACK).unwrap();
        assert!(stack9.is_empty(), "127.0.0.9 was never queued");

        // The cap keeps the freshest blocks and drops the oldest.
        let capped = collect_host_evidence(&root, ip, 2).unwrap();
        assert_eq!(capped.len(), 2);
        assert_eq!(capped[0].run_id, "manual_2026-10-03_083000");
        assert_eq!(capped[1].run_id, "scan_2026-10-02_090000");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_capture_with_stray_bytes_still_renders() {
        let root = std::env::temp_dir().join(format!("rustrawl-ev-4-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let runs = crate::discovery::state::runs_dir(&root);
        let ip: Ipv4Addr = "127.0.0.5".parse().unwrap();
        // A banner carrying a non-UTF-8 byte must not downgrade the whole
        // capture to "unreadable" — lossy read, report still extracted.
        let mut raw =
            b"Nmap scan report for 127.0.0.5\nPORT   STATE SERVICE\n22/tcp open  ssh \xff banner\n"
                .to_vec();
        raw.extend([0xc3, 0x28]); // a truncated sequence, still not valid UTF-8
        let dir = runs.join("scan_2026-10-05_090000").join("scans");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            runs.join("scan_2026-10-05_090000").join("scan_state.json"),
            r#"{"ports":[22],"nmap_args":"","queue_hash":0,"chunks":[{"hosts":["127.0.0.5"],"done":true,"attempts":0,"skipped":false}],"done":true}"#,
        )
        .unwrap();
        std::fs::write(dir.join("chunk-0000.nmap"), &raw).unwrap();

        let mut buf = Vec::new();
        render_host_evidence_last(&mut buf, &root, ip, 1).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("Nmap scan report for 127.0.0.5"), "{out}");
        assert!(out.contains("22/tcp open"), "verbatim: {out}");
        assert!(
            !out.contains("unreadable"),
            "lossy read must not report the capture unreadable: {out}"
        );
        std::fs::remove_dir_all(&root).ok();
    }
}
