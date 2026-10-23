//! End-to-end scan without nmap and without any network beyond 127/8: a
//! connect-mode discovery pass seeds the registry on the loopback /26
//! (every address refuses instantly, and a refusal is a live stack), then
//! `scan` drives a deterministic fake nmap. Asserts the full contract
//! through the db views: the queue over the registry, chunk ingestion as
//! service rows, the discovery/scan cross-checks, the CSV and Metasploit
//! exports, and the complete-queue resume refusal.

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::Command;

/// Deterministic nmap stand-in: the host list is every argv entry that looks
/// like an IPv4 address (scan interleaves flags around them). Findings by
/// last octet: %5==0 → 39145+80 open, %7==0 (and not %5) → 443 open,
/// otherwise Status: Up only. Also emits real-looking stdout (one
/// "Nmap scan report for" line per host — what the live chunk view counts)
/// and a .nmap evidence file (what `db`/console host sheets quote), plus
/// the full argv one-per-line in a .argv file (what the per-profile tests
/// pin the `-p` list against).
/// FAKE_NMAP_FAIL=1 fails chunk-0000.
const FAKE_NMAP: &str = r#"#!/usr/bin/env bash
set -u
base=""
hosts=()
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  if [[ "${args[$i]}" == "-oA" ]]; then
    base="${args[$((i + 1))]}"
  fi
done
if [[ -n "$base" ]]; then
  printf '%s\n' "${args[@]}" > "$base.argv"
fi
for a in "${args[@]}"; do
  if [[ "$a" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    hosts+=("$a")
  fi
done
if [[ -n "${FAKE_NMAP_FAIL:-}" && "$base" == *chunk-0000* ]]; then
  echo "fake nmap: chunk-0000 fails on request" >&2
  exit 1
fi
: > "$base.gnmap"
: > "$base.nmap"
for h in "${hosts[@]}"; do
  last=$(( ${h##*.} ))
  printf 'Nmap scan report for %s\nHost is up (0.001s latency).\n' "$h"
  printf 'Nmap scan report for %s\nHost is up (0.001s latency).\n' "$h" >> "$base.nmap"
  if (( last % 5 == 0 )); then
    printf 'Host: %s ()\tStatus: Up\n' "$h" >> "$base.gnmap"
    printf 'Host: %s ()\tPorts: 39145/open/tcp//hidden-svc//OpenSSH 9.2p1 Debian 2, 80/open/tcp//http//nginx 1.22.1\tIgnored State: closed (2)\n' "$h" >> "$base.gnmap"
  elif (( last % 7 == 0 )); then
    printf 'Host: %s ()\tStatus: Up\n' "$h" >> "$base.gnmap"
    printf 'Host: %s ()\tPorts: 443/open/tcp//https//Apache 2.4.57\tIgnored State: closed (3)\n' "$h" >> "$base.gnmap"
  else
    printf 'Host: %s ()\tStatus: Up\n' "$h" >> "$base.gnmap"
  fi
done
# A service-only host: never discovered, never queued - the gnmap evidence
# still ingests, and the MSF export's up-fold must keep it. Every chunk
# emits the same row; the services PK makes the double ingest idempotent.
printf 'Host: 127.0.0.99 ()\tPorts: 9999/open/tcp//lone-svc//service without discovery\tStatus: Up\n' >> "$base.gnmap"
printf 'Nmap scan report for 127.0.0.99\nHost is up (0.001s latency).\n' >> "$base.nmap"
"#;

const SCOPE: &str = "\
name: scan-it
includes:
  - 127.0.0.0/26
discovery:
  rate_pps: 5000
  ports: [39145]
  expand_ports: [39145, 39146]
  icmp: false
scan:
  nmap_args: \"-sV --version-light -p 39145,80,443\"
  threads: 2
";

fn temp_root(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "rustrawl-scan-it-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.subsec_nanos())
            .unwrap_or(0)
    ));
    fs::create_dir_all(&d).unwrap();
    d
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rustrawl"))
}

fn write_fake_nmap(root: &std::path::Path) -> PathBuf {
    let fake_nmap = root.join("fake-nmap");
    fs::write(&fake_nmap, FAKE_NMAP).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&fake_nmap, fs::Permissions::from_mode(0o755)).unwrap();
    }
    fake_nmap
}

fn run_discovery(root: &std::path::Path, scope_path: &std::path::Path) -> PathBuf {
    let perim = root.join("perim");
    let out = bin()
        .args([
            "run",
            scope_path.to_str().unwrap(),
            "--out",
            perim.to_str().unwrap(),
            "--mode",
            "connect",
        ])
        .output()
        .expect("run launches");
    assert!(
        out.status.success(),
        "run failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    perim
}

/// A batch console session: `db --out perim` with the script piped in —
/// the same entry point an operator's `printf ... | rustrawl db` takes.
/// Returns stdout; a nonzero exit fails the test (errors travel inline on
/// purpose, the session must survive them).
fn console(perim: &std::path::Path, script: &str) -> String {
    let mut child = bin()
        .arg("db")
        .arg("--out")
        .arg(perim.to_str().unwrap())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("db console launches");
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(script.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("console drains");
    assert!(
        out.status.success(),
        "console session failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The two-profile scope: a printer /29 on its own port list, one crown
/// jewel /32 on another, and the baseline args for the rest — the port
/// list rides in each args line.
const PROFILES_SCOPE: &str = "\
name: scan-profiles
includes:
  - 127.0.0.0/26
discovery:
  rate_pps: 5000
  ports: [39145]
  expand_ports: [39145, 39146]
  icmp: false
scan:
  nmap_args: \"-sV --version-light -p 39145,80,443\"
  threads: 2
  profiles:
    - range: 127.0.0.32/29
      nmap_args: \"-sV -p 80,9100\"
    - range: 127.0.0.50/32
      nmap_args: \"-sV -p 21-100\"
";

/// Latest scan_* run directory under the perimeter (discovery runs sort
/// before scan runs, and later runs sort after earlier ones).
fn last_scan_dir(perim: &std::path::Path) -> PathBuf {
    let mut dirs: Vec<_> = fs::read_dir(perim.join("runs"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .starts_with("scan_")
        })
        .collect();
    dirs.sort();
    dirs.last().expect("a scan run exists").clone()
}

/// The value that followed `-p` in a chunk's captured argv (one arg per
/// line, as the fake nmap dumps them).
fn argv_ports(run_dir: &std::path::Path, chunk: &str) -> String {
    let text = fs::read_to_string(run_dir.join("scans").join(format!("{chunk}.argv"))).unwrap();
    let mut it = text.lines();
    while let Some(l) = it.next() {
        if l == "-p" {
            return it.next().expect("the -p value follows").to_string();
        }
    }
    panic!("no -p in the captured argv: {text}");
}

#[test]
fn scan_end_to_end_over_fake_nmap() {
    let root = temp_root("e2e");
    let scope_path = root.join("scope.yaml");
    fs::write(&scope_path, SCOPE).unwrap();
    let fake_nmap = write_fake_nmap(&root);
    let perim = run_discovery(&root, &scope_path);

    // ---- the scan, fully configured from the scope's `scan:` section ----
    let out = bin()
        .args([
            "scan",
            scope_path.to_str().unwrap(),
            "--out",
            perim.to_str().unwrap(),
        ])
        .env("RUSTRAWL_NMAP_BIN", &fake_nmap)
        .output()
        .expect("scan launches");
    assert!(
        out.status.success(),
        "scan failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // run dirs speak the new vocabulary
    let runs: Vec<String> = fs::read_dir(perim.join("runs"))
        .unwrap()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .collect();
    assert!(runs.iter().any(|n| n.starts_with("discovery_")), "{runs:?}");
    assert!(runs.iter().any(|n| n.starts_with("scan_")), "{runs:?}");

    // every chunk's nmap stdout/stderr landed in a capture file — the live
    // chunk view's source (and `tail -f` material for the operator)
    let scan_dir = {
        let mut dirs: Vec<_> = fs::read_dir(perim.join("runs"))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .starts_with("scan_")
            })
            .collect();
        dirs.sort();
        dirs.last().expect("a scan run exists").join("scans")
    };
    let capture = fs::read_to_string(scan_dir.join("chunk-0000.out")).expect("capture file exists");
    assert!(
        !capture.is_empty(),
        "the fake nmap's stdout must land in the capture"
    );
    assert!(
        capture.contains("Nmap scan report for"),
        "report lines land in the capture: {capture:?}"
    );

    // 64 queued hosts (0..63): 13 with last octet %5==0 (39145+80 open),
    // 8 more with %7==0 (443 open) → 34 queue rows, 43 silent hosts. The
    // fake nmap also reports 127.0.0.99, never discovered nor queued: the
    // evidence still ingests, so the registry holds 35 service rows and the
    // db views through the console: the host list, one identity card, the
    // services table and its filters, the /24 buckets, the exports.
    let hosts = console(&perim, "hosts\nquit\n");
    assert_eq!(
        hosts.lines().filter(|l| l.starts_with("127.")).count(),
        64,
        "64 up hosts expected: {hosts}"
    );

    let detail = console(&perim, "hosts -i 127.0.0.5\nquit\n");
    assert!(detail.contains("discovery\tsweep"), "{detail}");
    assert!(detail.contains("service 39145"), "{detail}");
    assert!(detail.contains("OpenSSH 9.2p1"), "{detail}");

    let services = console(&perim, "services\nquit\n");
    assert_eq!(
        services.lines().filter(|l| l.starts_with("127.")).count(),
        35,
        "35 open service rows expected (34 queued + the lone host): {services}"
    );
    assert!(services.contains("OpenSSH 9.2p1"), "{services}");
    assert!(
        console(&perim, "services 39145\nquit\n")
            .contains("# 13 service row(s) on port 39145, sorted by host"),
        "the port spec filters the level view"
    );
    assert_eq!(
        console(&perim, "services https\nquit\n")
            .lines()
            .filter(|l| l.starts_with("127."))
            .count(),
        8
    );

    // the /24 bucket carries what the old anomalies view reported:
    // 64 up, 43 silent, 35 open.
    let ranges = console(&perim, "ranges\nquit\n");
    assert!(ranges.contains("127.0.0.0/24\t64\t43\t35\t"), "{ranges}");

    // exports: CSV of the service rows, ONE nmap XML document of the
    // whole registry
    let csv = console(&perim, "services -e csv\nquit\n");
    let mut csv_lines = csv.lines();
    assert_eq!(
        csv_lines.next(),
        Some("ip,port,proto,service,version,last_seen,run"),
        "{csv}"
    );
    assert_eq!(
        csv_lines
            .filter(|l| l.starts_with("127.") && l.contains(",tcp,"))
            .count(),
        35,
        "35 CSV data rows expected: {csv}"
    );
    assert!(csv.contains("OpenSSH 9.2p1"), "{csv}");

    let xml = console(&perim, "db export\nquit\n");
    assert!(xml.contains("<nmaprun scanner=\"nmap\""), "{xml}");
    // 64 discovery-up hosts + the service-only 127.0.0.99 the up-fold must
    // keep (deleting the fold's up.insert drops exactly this one host).
    // nmap parsers key on the state elements, so that is what gets pinned.
    assert_eq!(xml.matches("<host>").count(), 65, "{xml}");
    assert!(xml.contains("<address addr=\"127.0.0.99\""), "{xml}");
    assert!(xml.contains("<address addr=\"127.0.0.5\""), "{xml}");
    assert_eq!(xml.matches("<state state=\"open\"/>").count(), 35, "{xml}");
    assert!(
        xml.contains("<port protocol=\"tcp\" portid=\"39145\">"),
        "{xml}"
    );
    assert!(xml.contains("OpenSSH 9.2p1"), "{xml}");
    assert!(xml.contains("</nmaprun>"), "{xml}");

    // a complete queue refuses --resume (a no-op "completion" would lie)
    let out = bin()
        .args([
            "scan",
            scope_path.to_str().unwrap(),
            "--out",
            perim.to_str().unwrap(),
            "--resume",
        ])
        .env("RUSTRAWL_NMAP_BIN", &fake_nmap)
        .output()
        .expect("scan --resume launches");
    assert!(
        !out.status.success(),
        "resume of a complete queue must fail, got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("every scan queue is complete"),
        "the refusal must say why: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    fs::remove_dir_all(&root).ok();
}

/// The db console in batch mode: stdin piped, prompt suppressed, the same
/// renderers as the one-shot subcommands, and the raw nmap evidence section
/// on a host sheet (the fake nmap writes real .nmap files).
#[test]
fn db_console_batch_over_piped_stdin() {
    let root = temp_root("console");
    let scope_path = root.join("scope.yaml");
    fs::write(&scope_path, SCOPE).unwrap();
    let fake_nmap = write_fake_nmap(&root);
    let perim = run_discovery(&root, &scope_path);
    let out = bin()
        .args([
            "scan",
            scope_path.to_str().unwrap(),
            "--out",
            perim.to_str().unwrap(),
        ])
        .env("RUSTRAWL_NMAP_BIN", &fake_nmap)
        .output()
        .expect("scan launches");
    assert!(
        out.status.success(),
        "scan failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // A piped session: an unknown verb at the top (must NOT kill the
    // session), the host list, one identity card, one evidence stack, the
    // ranges table, a bad positional, a filtered service view and a
    // redirect outside the perimeter, then quit. Errors land inline; the
    // exit stays 0.
    let csv_out = root.join("svc-export.csv");
    let script = format!(
        "frobnicate\nhosts\nhosts -i 127.0.0.5\nhosts -S 127.0.0.5\nranges\n\
         ranges bogus\nservices 39145\nservices -e csv > {}\nquit\n",
        csv_out.display()
    );
    let mut child = bin()
        .arg("db")
        .arg("--out")
        .arg(perim.to_str().unwrap())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("db console launches");
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(script.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("console drains");
    assert!(
        out.status.success(),
        "batch console failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);

    // the batch-mode notice went to stderr, not stdout
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("commands read from stdin"), "{err}");
    assert!(
        !text.contains("rustrawl("),
        "no prompt in batch mode: {text}"
    );

    // the unknown verb printed at the top and the session lived on
    assert!(text.contains("unknown command \"frobnicate\""), "{text}");

    // overview rows only — the identity card's bare `127.0.0.5` header line
    // must not count
    assert_eq!(
        text.lines()
            .filter(|l| l.starts_with("127.") && l.contains("last up"))
            .count(),
        64,
        "64 up hosts through the console: {text}"
    );
    // the identity card: registry detail lines
    assert!(text.contains("discovery\tsweep"), "{text}");
    assert!(text.contains("service 39145"), "{text}");
    // the evidence stack: the raw nmap block from the fake nmap's .nmap file
    assert!(text.contains("nmap evidence"), "{text}");
    assert!(text.contains("Nmap scan report for 127.0.0.5"), "{text}");
    assert!(text.contains("OpenSSH 9.2p1"), "{text}");
    // the ranges triage view: one /24 bucket, 64 up, 43 silent, 35 open,
    // the top services with their counts (hidden-svc/http tie broken by name)
    assert!(
        text.contains("127.0.0.0/24\t64\t43\t35\thidden-svc x13, http x13, https x8, lone-svc x1"),
        "{text}"
    );
    assert!(
        text.contains("# 1 bucket(s) at /24 - sorted by up hosts"),
        "{text}"
    );
    // the filtered level view's footer pins the query
    assert!(
        text.contains("# 13 service row(s) on port 39145, sorted by host"),
        "{text}"
    );
    // a bad positional errors but the session lives
    assert!(text.contains("error:"), "{text}");

    // the redirect wrote the filtered export outside the perimeter
    assert!(text.contains("# wrote"), "{text}");
    let dumped = fs::read_to_string(&csv_out).unwrap();
    assert!(
        dumped.starts_with("ip,port,proto,service,version,last_seen,run\n"),
        "{dumped}"
    );

    fs::remove_dir_all(&root).ok();
}

/// A failed nmap process is terminal for its chunk: scan ends incomplete
/// (exit 0, nothing marked done — partial coverage must not look complete),
/// and `scan --resume` then finishes the queue.
#[test]
fn scan_failed_chunk_stays_resumable() {
    let root = temp_root("fail");
    let scope_path = root.join("scope.yaml");
    fs::write(&scope_path, SCOPE).unwrap();
    let fake_nmap = write_fake_nmap(&root);
    let perim = run_discovery(&root, &scope_path);

    let scan = |fail: bool| {
        let mut c = bin();
        c.args([
            "scan",
            scope_path.to_str().unwrap(),
            "--out",
            perim.to_str().unwrap(),
        ])
        .env("RUSTRAWL_NMAP_BIN", &fake_nmap);
        if fail {
            c.env("FAKE_NMAP_FAIL", "1");
        }
        c.output().expect("scan launches")
    };

    // chunk-0000 dies: scan ends 0 (clean incomplete), nothing marked done
    let out = scan(true);
    assert!(
        out.status.success(),
        "clean incomplete is exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("incomplete"),
        "must report pending chunks: {combined}"
    );

    let partial = console(&perim, "services\nquit\n");
    let partial_rows = partial.lines().filter(|l| l.starts_with("127.")).count();
    assert!(partial_rows < 35, "partial coverage expected: {partial}");

    // resume without FAKE_NMAP_FAIL completes the queue
    let out = scan(false);
    assert!(
        out.status.success(),
        "resume failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let services = console(&perim, "services\nquit\n");
    assert_eq!(
        services.lines().filter(|l| l.starts_with("127.")).count(),
        35,
        "the whole queue must be covered after the resume: {services}"
    );

    fs::remove_dir_all(&root).ok();
}

/// Per-range scan profiles end to end: the dry run prints the group plan,
/// each chunk's nmap argv carries its group's `-p`, the state file pins the
/// profiles, a killed chunk resumes with the plan intact, and
/// `--resume --only-profile` is refused. Loopback only.
#[test]
fn scan_profiles_split_the_queue_and_resume() {
    let root = temp_root("profiles");
    let scope_path = root.join("scope.yaml");
    fs::write(&scope_path, PROFILES_SCOPE).unwrap();
    let fake_nmap = write_fake_nmap(&root);
    let perim = run_discovery(&root, &scope_path);
    let scan = |extra: &[&str], fail: bool| {
        let mut c = bin();
        c.arg("scan")
            .arg(scope_path.to_str().unwrap())
            .arg("--out")
            .arg(perim.to_str().unwrap())
            .args(extra)
            .env("RUSTRAWL_NMAP_BIN", &fake_nmap);
        if fail {
            c.env("FAKE_NMAP_FAIL", "1");
        }
        c.output().expect("scan launches")
    };
    let text = |o: &std::process::Output| {
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    };

    // ---- the dry run: three groups, dispatch order, no nmap ----
    let out = scan(&["--dry-run"], false);
    assert!(out.status.success(), "{}", text(&out));
    let dry = text(&out);
    assert!(dry.contains("Profiles          : 3 group(s)"), "{dry}");
    // printer /29: 8 hosts, 1 chunk, its own args line
    assert!(
        dry.contains("127.0.0.32/29")
            && dry.contains("8 host(s) · 1 chunk(s) (scan.profiles[0]) · args \"-sV -p 80,9100\""),
        "{dry}"
    );
    // server /32: 1 host, its own args line
    assert!(
        dry.contains("1 host(s) · 1 chunk(s) (scan.profiles[1]) · args \"-sV -p 21-100\""),
        "{dry}"
    );
    // the remainder: 64 up hosts - 9 profiled = 55, baseline args, last
    assert!(
        dry.contains(
            "55 host(s) · 2 chunk(s) (baseline (scan.nmap_args)) \
             · args \"-sV --version-light -p 39145,80,443\""
        ),
        "{dry}"
    );
    assert!(dry.contains("Chunks            : 4 × ≤ 32 hosts"), "{dry}");

    // ---- --only-profile shapes a fresh queue (dry run shows it) ----
    let out = scan(&["--dry-run", "--only-profile", "127.0.0.32/29"], false);
    assert!(out.status.success(), "{}", text(&out));
    let dry = text(&out);
    assert!(dry.contains("Profiles          : 1 group(s)"), "{dry}");
    assert!(dry.contains("8 host(s)"), "{dry}");
    assert!(
        !dry.contains("127.0.0.50/32"),
        "unselected groups stay out: {dry}"
    );
    assert!(!dry.contains("55 host(s)"), "{dry}");
    assert!(dry.contains("Only              : 127.0.0.32/29"), "{dry}");

    // an unknown label must stop the run, not silently scan everything
    let out = scan(&["--dry-run", "--only-profile", "nope"], false);
    assert!(!out.status.success(), "unknown label must refuse");
    assert!(
        text(&out).contains("unknown profile label \"nope\" - declared:"),
        "{}",
        text(&out)
    );

    // ---- the real run: chunk-0000 fails, the rest complete ----
    let out = scan(&[], true);
    assert!(
        out.status.success(),
        "clean incomplete is exit 0: {}",
        text(&out)
    );
    assert!(text(&out).contains("incomplete"), "{}", text(&out));

    // per-chunk argv: each group's -p (inside its args) went to its own
    // chunks — the port list rides verbatim, rustrawl adds none
    let run_dir = last_scan_dir(&perim);
    assert_eq!(
        argv_ports(&run_dir, "chunk-0000"),
        "80,9100",
        "printer ports"
    );
    assert_eq!(
        argv_ports(&run_dir, "chunk-0001"),
        "21-100",
        "the server's range rides as typed"
    );
    assert_eq!(
        argv_ports(&run_dir, "chunk-0002"),
        "39145,80,443",
        "baseline ports"
    );
    assert_eq!(argv_ports(&run_dir, "chunk-0003"), "39145,80,443");

    // state round-trip: profiles pinned (args only — the legacy ports
    // field stays but is always written empty), chunks never straddle
    let st: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(run_dir.join("scan_state.json")).unwrap())
            .unwrap();
    let profiles = st["profiles"].as_array().unwrap();
    let labels: Vec<&str> = profiles
        .iter()
        .map(|p| p["label"].as_str().unwrap())
        .collect();
    assert_eq!(labels, ["127.0.0.32/29", "127.0.0.50/32", "default"]);
    for p in profiles {
        assert!(
            p["ports"].as_array().unwrap().is_empty(),
            "the legacy ports field stays empty: {p}"
        );
    }
    assert_eq!(
        profiles[0]["nmap_args"], "-sV -p 80,9100",
        "the printer's own args"
    );
    assert_eq!(profiles[1]["nmap_args"], "-sV -p 21-100");
    assert_eq!(
        profiles[2]["nmap_args"], "-sV --version-light -p 39145,80,443",
        "baseline args"
    );
    let chunks = st["chunks"].as_array().unwrap();
    assert_eq!(chunks.len(), 4);
    let counts: Vec<usize> = chunks
        .iter()
        .map(|c| c["hosts"].as_array().unwrap().len())
        .collect();
    assert_eq!(counts, [8, 1, 32, 23]);
    let profile_of: Vec<u64> = chunks
        .iter()
        .map(|c| c["profile"].as_u64().unwrap())
        .collect();
    assert_eq!(profile_of, [0, 1, 2, 2]);
    assert_eq!(
        chunks[1]["hosts"][0], "127.0.0.50",
        "the /32 queues one host"
    );

    // ---- `--resume --only-profile` refuses: the interrupted queue re-applies
    // its own recorded selection ----
    let out = scan(&["--resume", "--only-profile", "default"], false);
    assert!(!out.status.success(), "only-profile must refuse on resume");
    assert!(
        text(&out).contains("--only-profile shapes a fresh queue"),
        "{}",
        text(&out)
    );

    // ---- resume without flags completes the queue, profiles intact ----
    let out = scan(&["--resume"], false);
    assert!(out.status.success(), "{}", text(&out));
    let st: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(run_dir.join("scan_state.json")).unwrap())
            .unwrap();
    assert_eq!(
        st["profiles"].as_array().unwrap().len(),
        3,
        "the profiles survive the resume"
    );
    assert!(st["chunks"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["done"] == true));
    let services = console(&perim, "services\nquit\n");
    assert_eq!(
        services.lines().filter(|l| l.starts_with("127.")).count(),
        35,
        "full coverage after the resume: {services}"
    );

    fs::remove_dir_all(&root).ok();
}

/// `--only-profile <server /32>`: a fresh queue holding exactly one host —
/// the bare-IP form selects the /32 profile by range equality.
#[test]
fn scan_only_profile_queues_just_that_group() {
    let root = temp_root("only");
    let scope_path = root.join("scope.yaml");
    fs::write(&scope_path, PROFILES_SCOPE).unwrap();
    let fake_nmap = write_fake_nmap(&root);
    let perim = run_discovery(&root, &scope_path);

    let out = bin()
        .args([
            "scan",
            scope_path.to_str().unwrap(),
            "--out",
            perim.to_str().unwrap(),
            "--only-profile",
            "127.0.0.50",
        ])
        .env("RUSTRAWL_NMAP_BIN", &fake_nmap)
        .output()
        .expect("scan launches");
    assert!(
        out.status.success(),
        "scan failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let run_dir = last_scan_dir(&perim);
    let st: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(run_dir.join("scan_state.json")).unwrap())
            .unwrap();
    let profiles = st["profiles"].as_array().unwrap();
    assert_eq!(profiles.len(), 1, "{st}");
    assert_eq!(
        profiles[0]["label"], "127.0.0.50/32",
        "bare IP matches the /32"
    );
    assert!(
        profiles[0]["ports"].as_array().unwrap().is_empty(),
        "no port list outside the args: {st}"
    );
    let chunks = st["chunks"].as_array().unwrap();
    assert_eq!(chunks.len(), 1);
    assert_eq!(
        chunks[0]["hosts"].as_array().unwrap(),
        &["127.0.0.50"],
        "only the /32's host is queued"
    );
    assert_eq!(chunks[0]["profile"].as_u64(), Some(0));
    assert_eq!(chunks[0]["done"], true);
    assert_eq!(
        argv_ports(&run_dir, "chunk-0000"),
        "21-100",
        "the server chunk runs its own port list"
    );

    // the registry: the server's rows (last octet 50 → 39145 + 80) plus the
    // fake nmap's lone service-only host; every other up host stays silent
    let services = console(&perim, "services\nquit\n");
    assert_eq!(
        services.lines().filter(|l| l.starts_with("127.")).count(),
        3,
        "only the targeted host scanned: {services}"
    );
    // the /24 row keeps the untouched hosts visible as silent
    let ranges = console(&perim, "ranges\nquit\n");
    assert!(
        ranges.contains("127.0.0.0/24\t64\t63\t3\t"),
        "unselected hosts are untouched, not dropped: {ranges}"
    );

    fs::remove_dir_all(&root).ok();
}
