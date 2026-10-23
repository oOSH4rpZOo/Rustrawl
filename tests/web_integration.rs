//! The `db --web` dashboard over a real socket: a seeded loopback perimeter
//! (connect-mode discovery over 127.0.0.0/29 — every refusal is a live
//! stack), a fabricated scan run holding a captured .nmap, then the actual
//! binary serving HTTP on an ephemeral port. GETs go through TcpStream, so
//! the server, the routing and the JSON all run for real. Loopback only.

use std::fs;
use std::io::{BufRead, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const SCOPE: &str = "\
name: web-it
includes:
  - 127.0.0.0/29
discovery:
  rate_pps: 5000
  ports: [39145]
  expand_ports: [39145, 39146]
  icmp: false
";

fn temp_root(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "rustrawl-web-it-{tag}-{}-{}",
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

/// A scan run that never ran nmap: hand-written state file (the serde shape
/// scan.rs writes) + a captured chunk-0000.nmap with a report for .2 only —
/// .3 then exercises the "holds no report" fallback path through HTTP. The
/// .argv sibling carries the command line the evidence stack displays.
fn fabricate_scan_run(perim: &std::path::Path) {
    let run = perim.join("runs").join("scan_2026-10-09_120000");
    fs::create_dir_all(run.join("scans")).unwrap();
    fs::write(
        run.join("scan_state.json"),
        r#"{"ports":[80],"nmap_args":"","queue_hash":0,"chunks":[{"hosts":["127.0.0.2","127.0.0.3"],"done":true,"attempts":0,"skipped":false}],"done":true}"#,
    )
    .unwrap();
    fs::write(
        run.join("scans").join("chunk-0000.nmap"),
        "Nmap scan report for 127.0.0.2\nHost is up (0.001s latency).\nPORT     STATE SERVICE VERSION\n39145/tcp open  unknown  bait-svc 1.0\n",
    )
    .unwrap();
    fs::write(
        run.join("scans").join("chunk-0000.argv"),
        "nmap -Pn -n --open -oA runs/scan_2026-10-09_120000/scans/chunk-0000 -sT --stats-every 30s -p 39145 127.0.0.2 127.0.0.3\n",
    )
    .unwrap();
}

/// The nmap stand-in the dashboard spawns for POST /api/scan: same argv
/// contract as the real one (-oA base, hosts pinned last), one open port
/// 39147 per host argument, real .gnmap/.nmap captures on disk. Its echo
/// rides spawn_chunk's stdout tee into chunk-0000.out — the bytes the
/// live-output route tails — and FAKE_NMAP_SLEEP stretches the run so the
/// test can watch the tail grow mid-flight.
const FAKE_RESCAN_NMAP: &str = r#"#!/usr/bin/env bash
set -u
echo "fake nmap on $*"
if [[ -n "${FAKE_NMAP_SLEEP:-}" ]]; then sleep "$FAKE_NMAP_SLEEP"; fi
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
: > "$base.gnmap"
: > "$base.nmap"
for h in "${hosts[@]}"; do
  printf 'Host: %s ()\tStatus: Up\n' "$h" >> "$base.gnmap"
  printf 'Host: %s ()\tPorts: 39147/open/tcp//rescan-svc//found by the rescan\tIgnored State: closed (1)\n' "$h" >> "$base.gnmap"
  printf 'Nmap scan report for %s\nHost is up (0.001s latency).\nPORT     STATE SERVICE VERSION\n39147/tcp open  rescan-svc  found by the rescan\n' "$h" >> "$base.nmap"
done
"#;

/// One HTTP GET over a fresh TcpStream; returns (status, body).
fn get(port: u16, path: &str) -> (u16, String) {
    try_get(port, path).unwrap_or_else(|| panic!("GET {path}: no parseable response"))
}

/// The raw header block of a GET — pins for headers beyond content-type
/// (the export downloads' Content-Disposition).
fn get_head(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("server accepts");
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).expect("response drains");
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no header/body split in GET {path}"));
    String::from_utf8_lossy(&buf[..split]).into_owned()
}

/// Binary-body POST (the screenshot upload): (status, content-type, body).
fn post_bytes(
    port: u16,
    path: &str,
    ctype: &str,
    body: &[u8],
    guard: bool,
) -> (u16, String, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("server accepts");
    let guard_hdr = if guard { "X-Rustrawl: 1\r\n" } else { "" };
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: {ctype}\r\n{guard_hdr}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    use std::io::Write as _;
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).expect("response drains");
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no header/body split in POST {path}"));
    let head_text = String::from_utf8_lossy(&buf[..split]).into_owned();
    let status: u16 = head_text
        .split_whitespace()
        .nth(1)
        .and_then(|x| x.parse().ok())
        .unwrap_or_else(|| panic!("no status line in POST {path}: {head_text:?}"));
    let rtype = head_text
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-type:"))
        .map(|l| l.split_once(':').unwrap().1.trim().to_string())
        .unwrap_or_default();
    (status, rtype, buf[split + 4..].to_vec())
}

/// The same GET with raw bytes back: (status, content-type, body).
fn get_bytes(port: u16, path: &str) -> (u16, String, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("server accepts");
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).expect("response drains");
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| {
            panic!(
                "no header/body split in GET {path}: {:?}",
                String::from_utf8_lossy(&buf)
            )
        });
    let head_text = String::from_utf8_lossy(&buf[..split]).into_owned();
    let status: u16 = head_text
        .split_whitespace()
        .nth(1)
        .and_then(|x| x.parse().ok())
        .unwrap_or_else(|| panic!("no status line in GET {path}: {head_text:?}"));
    let rtype = head_text
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-type:"))
        .map(|l| l.split_once(':').unwrap().1.trim().to_string())
        .unwrap_or_default();
    (status, rtype, buf[split + 4..].to_vec())
}

/// The same GET, silent on failure — the readiness probe's building block
/// (a server between bind and its first accept can close a connection
/// without answering; that is a "not ready", not a bug).
fn try_get(port: u16, path: &str) -> Option<(u16, String)> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status: u16 = text.split_whitespace().nth(1)?.parse().ok()?;
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Some((status, body))
}

/// Kills the dashboard on drop, panic paths included — a test that fails
/// halfway must not leave a server bound to its ephemeral port behind.
struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The `db --web` dashboard on an ephemeral port, the fake nmap wired in
/// through RUSTRAWL_NMAP_BIN, extra env layered on top: returns the
/// kill-on-drop child, the resolved port and the stderr reader. The reader
/// must outlive the test: dropping it closes the stderr pipe and the
/// server's next log line dies on EPIPE, taking the connection thread —
/// and whatever response it owed — with it. The banner is read exactly
/// one line (reading to EOF would block: the server runs until killed),
/// then the accept loop is probed: the banner prints before the loop is
/// scheduled, so an immediate connection can land in the backlog and die
/// unread.
fn spawn_dashboard(
    perim: &std::path::Path,
    tag: &str,
    extra_env: &[(&str, &str)],
) -> (
    KillOnDrop,
    u16,
    std::io::BufReader<std::process::ChildStderr>,
) {
    let root = perim.parent().expect("perimeter has a parent");
    let fake_nmap = root.join(format!("fake-rescan-nmap-{tag}"));
    fs::write(&fake_nmap, FAKE_RESCAN_NMAP).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&fake_nmap, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut cmd = bin();
    cmd.args([
        "db",
        "--out",
        perim.to_str().unwrap(),
        "--web",
        "--port",
        "0",
    ])
    .env("RUSTRAWL_NMAP_BIN", &fake_nmap)
    .stdout(Stdio::null())
    .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("dashboard launches");
    let stderr = child.stderr.take().expect("stderr piped");
    let mut reader = std::io::BufReader::new(stderr);
    let mut banner = String::new();
    reader.read_line(&mut banner).expect("banner line");
    let port: u16 = banner
        .trim_start_matches("# dashboard: http://")
        .trim_end_matches(
            "/ - writes: triage, types, bookmark, pwned, tags, notes, screenshots, manual rescans (one host, a list or a range); exports: /api/export/*; ^C stops the server\n",
        )
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("no dashboard banner with a port in: {banner:?}"));
    assert!(port > 0, "ephemeral port must be resolved: {banner:?}");
    let mut ready = false;
    for _ in 0..100 {
        if try_get(port, "/api/status").map(|(s, _)| s) == Some(200) {
            ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(ready, "dashboard never answered /api/status");
    (KillOnDrop(child), port, reader)
}

/// One HTTP POST with a JSON body; `guard` adds the X-Rustrawl: 1 header
/// the write route demands. Returns (status, body).
fn post(port: u16, path: &str, body: &str, guard: bool) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("server accepts");
    let guard_hdr = if guard { "X-Rustrawl: 1\r\n" } else { "" };
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n{guard_hdr}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).expect("response drains");
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no status line in POST {path} [{body}]: {text:?}"));
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

#[test]
fn web_dashboard_serves_the_registry_over_http() {
    let root = temp_root("dash");
    let scope_path = root.join("scope.yaml");
    fs::write(&scope_path, SCOPE).unwrap();
    let perim = root.join("perim");

    // discovery seeds the registry (8 addresses, all "live" refusals)
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
    fabricate_scan_run(&perim);

    // the dashboard on an ephemeral port (see spawn_dashboard for the
    // banner and backlog handling). The rescan route inherits the same
    // nmap stand-in the scan tests use, so POST /api/scan exercises the
    // whole path without a real nmap. The stderr reader rides along
    // unused: it must outlive the server, or its next log line EPIPEs.
    let (child, port, _stderr_reader) = spawn_dashboard(&perim, "dash", &[]);

    // the page
    let (status, body) = get(port, "/");
    assert_eq!(status, 200);
    assert!(body.contains("rustrawl"), "the embedded page: {body:?}");
    assert!(
        body.contains("nmap evidence"),
        "host-page material ships in the JS"
    );
    // the ranges tab ships in the nav and the router's tab list
    assert!(body.contains("id=\"tab-ranges\""), "{body:?}");
    assert!(
        body.contains("renderRanges") && body.contains("\"ranges\""),
        "the ranges view ships in the JS: {body:?}"
    );
    // the fielded search ships in the JS: the query parser (port ranges,
    // quoted values) and the per-view matchers over the new column set
    for key in [
        "tokenize",
        "portRanges",
        "svcMatcher",
        "hostMatcher",
        // matcher-specific: the `banner` alias exists only inside svcMatcher
        "case \"banner\"",
        // the per-host history table keeps its date/run columns (the main
        // services table dropped them for the aligned column set)
        "last seen",
        // the ranges home: the wide range rows and the clickable state
        // pastilles, and the triage/type tokens the matcher still speaks
        "rangerow",
        // the hosts list hides the no-port hosts behind the checkbox, and
        // says what it hid when the page goes empty
        "hidewh",
        "hidden by the checkbox",
        // the checkbox must not inherit the search input's wide-box look
        ".bar > input",
        "label.hidewh input",
        "pastille",
        "state:todo",
        "type:dc",
        // the pwned dot and the tag editor (the bookmark UI left the page:
        // the flag lives on in the API and the CLI only)
        "postFlag",
        "pwnedDot",
        "tagEditor",
        // the filter tokens the matchers still honor
        "pwned:yes",
        "tag:dc",
        // the sheet's markdown note: the editor section, the paste-upload
        // route and the textContent-only renderer
        "noteSection",
        "renderMarkdown",
        "note-image",
        "setRangeText",
        // the page's POST helpers carry the write-guard header, and the
        // sheet's kind badge swaps to the /api/type editor
        "X-Rustrawl",
        "postType",
        "typeEditor",
        // the rescan section: its defaults fetch, its POST helpers (run
        // and the stop brake) and the buttons all ship in the page JS
        "scan-defaults",
        "postScanBatch",
        "postScanStop",
        "run nmap",
        "stopbtn",
        // the sheet's evidence stack: the renderer, the native collapsible
        // blocks and the friendly fetch-failure line
        "evidenceBlock",
        "details",
        "evblock",
        "dashboard unreachable (server stopped?)",
    ] {
        assert!(body.contains(key), "query search contract: {key} missing");
    }
    // the bookmark UI left the page for good, and so did the ranges
    // expander its rows replaced
    assert!(
        !body.contains("bookmarkNode") && !body.contains("bkmark") && !body.contains("chev"),
        "the bookmark UI and the ranges expander must stay gone"
    );
    // the white identity ships the project logo (banner emblem + favicon)
    assert!(body.contains("logo.png"), "{body:?}");
    // the banner is the fixed vertical aside, and the status view is gone
    assert!(body.contains("aside id=\"side\""), "{body:?}");
    assert!(
        !body.contains("renderStatus") && !body.contains("tab-status"),
        "the status view must stay gone"
    );
    // a stale #/status deep link re-homes on ranges, and the compromise
    // mark keeps one color in every state
    assert!(body.contains("#/status"), "{body:?}");
    assert!(body.contains("--pwned"), "{body:?}");
    assert!(
        !body.contains("filled red once it is"),
        "the pwned wording must stay black"
    );
    // the filter survives round trips: each bar carries its view's route
    // (typing mirrors into the URL), the ranges bar writes its bucket size
    // into the hash, the range row's click-through derives its octets from
    // the row's prefix, and the sheet's two tables sort on their own state
    // without crashing on each other's columns
    for key in [
        "filterBar(\"bar-services\", \"/services\", \"search\", renderServices)",
        "filterBar(\"bar-hosts\", \"/hosts\", \"search\", renderHosts)",
        "() => rangePrefix === 24 ? \"\" : \"p\" + rangePrefix",
        "Math.min(4, Math.ceil(p / 8))",
        "sortState",
        "if (!col) st.key = null;",
    ] {
        assert!(
            body.contains(key),
            "filter and sort contract: {key} missing"
        );
    }
    // the bulk machinery and the new surfaces: the batch POST helper, the
    // the page contract: the bulk-rescan machinery, the hash router's
    // prefix segment, the filter bar's export dropdown (what is
    // displayed is what leaves), the plain rescan queue buttons, the
    // range->up-ips read and the rescan tab itself — the sidebar link is
    // its only way in
    for key in [
        "postScanBatch",
        "^p(8|16|24|32)(?:\\/(.*))?$",
        "/api/export/scan.xml",
        "/api/export/services.csv",
        "/api/export/hosts.txt",
        "postExport(",
        "exportSelect(",
        "sortedRows(",
        "queueRescanBtn(",
        "postUpIps",
        "renderRescan",
        "#/rescan",
        "tab-rescan",
        "outbox",
        "rescan-add",
        // the queue persists in the browser and merges every entry point
        // into one list that only the chips' × and the clear button empty
        "rustrawl-rescan-queue",
        "loadRescanQueue(",
        "saveRescanQueue(",
        "queueHosts(",
        // the queue buttons stay on their page and flash what they queued
        "flashQueued(",
        // each evidence block and the live output show the captured command
        "evcmd",
        "rescan-cmd",
        "setRescanCmd(",
    ] {
        assert!(body.contains(key), "bulk-rescan contract: {key} missing");
    }
    // the shapes the redesign retired: the per-view rescan boxes (confirm
    // dialog, inline batch runner), the sidebar exports block, the
    // one-host postScan, and any programmatic jump to the tab — the
    // sidebar link is the only way in
    for gone in [
        "confirm(",
        "runBatch(",
        "rescanControls",
        "openRangeRescan",
        "postScan(",
        "class=\"exports\"",
        "watch it",
        "location.hash = \"#/rescan\"",
    ] {
        assert!(!body.contains(gone), "retired shape must stay gone: {gone}");
    }

    // hosts: every loopback /29 address discovery reported
    let (status, body) = get(port, "/api/hosts");
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let hosts = v["hosts"].as_array().expect("hosts array");
    assert_eq!(v["count"].as_u64().unwrap(), hosts.len() as u64);
    assert!(hosts.iter().any(|h| h["ip"] == "127.0.0.2"), "{body}");
    assert!(
        hosts.iter().all(|h| h["open_ports"].is_u64()),
        "open port counts are numbers: {body}"
    );

    // host sheet with the fabricated evidence, newest-first stack
    let (status, body) = get(port, "/api/host/127.0.0.2");
    assert_eq!(status, 200);
    assert!(
        body.contains("\"run\":\"scan_2026-10-09_120000\"") && body.contains("\"chunk\":0"),
        "the evidence stack names its run: {body}"
    );
    assert!(
        body.contains("Nmap scan report for 127.0.0.2"),
        "the verbatim nmap block: {body}"
    );
    assert!(body.contains("bait-svc 1.0"), "{body}");
    // the captured command line rides the evidence block (chunk-0000.argv)
    assert!(
        body.contains("\"cmd\":\"nmap -Pn -n --open -oA "),
        "the evidence block carries the nmap command: {body}"
    );
    // the page reads stages/ports/services/evidence — pin those keys (a key
    // drift here renders every host sheet as "nothing in the registry")
    for key in [
        "\"stages\":",
        "\"ports\":",
        "\"services\":",
        "\"evidence\":",
        "\"evidence_note\":",
    ] {
        assert!(body.contains(key), "page contract: {key} missing: {body}");
    }

    // queued but no report in the capture → the explicit fallback
    let (status, body) = get(port, "/api/host/127.0.0.3");
    assert_eq!(status, 200);
    assert!(body.contains("holds no report for 127.0.0.3"), "{body}");

    // services: empty registry services table, still valid JSON
    let (status, body) = get(port, "/api/services");
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["count"], 0, "{body}");

    // ranges: the /29's hosts bucket into one /24 — no services table rows
    // (the fabricated scan run carries none), so open is 0
    let (status, body) = get(port, "/api/ranges");
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["prefix"], 24);
    let ranges = v["ranges"].as_array().expect("ranges array");
    assert_eq!(v["count"].as_u64().unwrap(), ranges.len() as u64);
    assert_eq!(ranges.len(), 1, "{body}");
    assert_eq!(ranges[0]["range"], "127.0.0.0/24");
    assert_eq!(ranges[0]["up"], 8);
    assert_eq!(
        ranges[0]["silent"], 8,
        "no open port anywhere in this fixture"
    );
    assert_eq!(ranges[0]["open"], 0);
    assert_eq!(ranges[0]["services"], "");

    // the same registry re-bucketed: /16 keeps the tally, /8 keeps it too,
    // and an out-of-range prefix is a 404 like any junk segment
    let (status, body) = get(port, "/api/ranges/16");
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["prefix"], 16, "{body}");
    let ranges = v["ranges"].as_array().expect("ranges array");
    assert_eq!(ranges.len(), 1, "{body}");
    assert_eq!(ranges[0]["range"], "127.0.0.0/16");
    assert_eq!(ranges[0]["up"], 8);
    let (status, _) = get(port, "/api/ranges/8");
    assert_eq!(status, 200);
    let (status, _) = get(port, "/api/ranges/33");
    assert_eq!(status, 404);

    // status: counts + the runs table text
    let (status, body) = get(port, "/api/status");
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["perimeter"], "perim");
    assert!(
        v["runs_text"]
            .as_str()
            .unwrap()
            .contains("scan_2026-10-09_120000"),
        "{body}"
    );

    // routing refuses what it must
    assert_eq!(get(port, "/nope").0, 404);
    assert_eq!(get(port, "/api/host/not-an-ip").0, 404);
    assert_eq!(get(port, "/api/host/../../etc/passwd").0, 404);

    // the write path: a triage mark set over HTTP, read back over the GETs
    let (status, body) = post(
        port,
        "/api/triage",
        r#"{"ip":"127.0.0.2","status":"todo","note":"start here"}"#,
        true,
    );
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"ok\":true"), "{body}");
    let (status, body) = get(port, "/api/host/127.0.0.2");
    assert_eq!(status, 200);
    assert!(
        body.contains("\"state\":{") && body.contains("\"status\":\"todo\""),
        "the sheet carries the host state: {body}"
    );
    // the same write without the guard header: 403, and it changes nothing
    let (status, _) = post(
        port,
        "/api/triage",
        r#"{"ip":"127.0.0.2","status":"vuln"}"#,
        false,
    );
    assert_eq!(status, 403);
    let (_, body) = get(port, "/api/host/127.0.0.2");
    assert!(
        body.contains("\"status\":\"todo\"") && !body.contains("\"status\":\"vuln\""),
        "the guard refusal wrote nothing: {body}"
    );
    // marks live on the host only: a port field refuses outright, whatever
    // word rides with it (the retired host words refuse too)
    let (status, body) = post(
        port,
        "/api/triage",
        r#"{"ip":"127.0.0.2","port":39145,"status":"vuln","note":"bait"}"#,
        true,
    );
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("host only"), "{body}");
    let (status, body) = post(
        port,
        "/api/triage",
        r#"{"ip":"127.0.0.2","status":"flagged"}"#,
        true,
    );
    assert_eq!(status, 400, "{body}");
    // clearing answers deleted:true and the row is gone
    let (status, body) = post(
        port,
        "/api/triage",
        r#"{"ip":"127.0.0.2","status":"none","note":""}"#,
        true,
    );
    assert_eq!(status, 200);
    assert!(body.contains("\"deleted\":true"), "{body}");
    let (_, body) = get(port, "/api/host/127.0.0.2");
    assert!(!body.contains("\"state\":{"), "cleared: {body}");

    // the retired value ranking answers 405 — the route is gone, its write
    // slot carried by the bookmark/pwned/tag routes (covered in
    // post_flags_and_tags_write_and_unmark below)
    let (status, _) = post(
        port,
        "/api/value",
        r#"{"ip":"127.0.0.2","rank":"crown"}"#,
        true,
    );
    assert_eq!(status, 405, "the value route is retired");

    // the second write route: the asset type — forced, read on the sheet
    // as a manual row, then withdrawn (the classifier may guess again)
    let (status, body) = post(
        port,
        "/api/type",
        r#"{"ip":"127.0.0.2","kind":"bastion","basis":"jump host"}"#,
        true,
    );
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"kind\":\"bastion\""), "{body}");
    let (_, body) = get(port, "/api/host/127.0.0.2");
    assert!(
        body.contains("\"kind\":\"bastion\"") && body.contains("\"source\":\"manual\""),
        "{body}"
    );
    let (status, body) = post(port, "/api/type", r#"{"ip":"127.0.0.2"}"#, true);
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"cleared\":true"), "{body}");
    let (_, body) = get(port, "/api/host/127.0.0.2");
    assert!(body.contains("\"type\":null"), "withdrawn: {body}");
    // and the 403 guard covers this route too
    let (status, _) = post(
        port,
        "/api/type",
        r#"{"ip":"127.0.0.2","kind":"bastion"}"#,
        false,
    );
    assert_eq!(status, 403);
    // a body over the cap is refused unread — 413 before any parsing (the
    // JSON writes cap at 256 KiB; screenshots get their own 5 MiB route)
    let big = format!(
        "{{\"ip\":\"127.0.0.2\",\"note\":\"{}\"}}",
        "x".repeat(300_000)
    );
    let (status, _) = post(port, "/api/triage", &big, true);
    assert_eq!(status, 413);

    // the screenshot upload: the guard holds, the magic bytes decide, the
    // digest names the file, the bytes come back byte-for-byte, and the
    // saved note can reference the url
    let mut shot = vec![0x89u8, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    shot.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let (status, _, _) = post_bytes(port, "/api/note-image/127.0.0.2", "image/png", &shot, false);
    assert_eq!(status, 403, "the upload needs the guard");
    let (status, _, raw) = post_bytes(port, "/api/note-image/127.0.0.2", "image/png", &shot, true);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&raw));
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let url = v["url"].as_str().unwrap().to_string();
    assert!(
        url.starts_with("/notes/127.0.0.2/") && url.ends_with(".png"),
        "{url}"
    );
    let (status, ctype, raw) = get_bytes(port, &url);
    assert_eq!(status, 200);
    assert_eq!(ctype, "image/png");
    assert_eq!(raw, shot, "the screenshot comes back byte-for-byte");
    // junk magic refuses, and the fs name is pinned to the digest shape
    let (status, _, raw) = post_bytes(
        port,
        "/api/note-image/127.0.0.2",
        "image/png",
        b"GIF89a",
        true,
    );
    assert_eq!(status, 400, "{}", String::from_utf8_lossy(&raw));
    assert!(!url.contains(".."));
    // the note references the shot; the saved markdown rides back
    let (status, body) = post(
        port,
        "/api/triage",
        &format!("{{\"ip\":\"127.0.0.2\",\"note\":\"# finding\\n![shot]({url})\"}}"),
        true,
    );
    assert_eq!(status, 200, "{body}");
    let (_, body) = get(port, "/api/host/127.0.0.2");
    assert!(body.contains(&format!("![shot]({url})")), "{body}");

    // a malformed request line is a 400, not a hang or a 405
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("server accepts");
    write!(s, "GARBAGE\r\n\r\n").unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).expect("400 drains");
    assert!(
        String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 400 "),
        "{:?}",
        String::from_utf8_lossy(&buf)
    );

    // a bare-LF request (no CRLF) still terminates its headers and is served
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("server accepts");
    write!(s, "GET /api/status HTTP/1.1\nHost: x\n\n").unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).expect("LF request drains");
    assert!(
        String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 200 "),
        "{:?}",
        String::from_utf8_lossy(&buf)
    );

    // the third write route: the manual rescan. Defaults first — the
    // fabricated queue run pins them (its empty args fall back to the CLI
    // default), and a manual run must never feed them.
    let (status, body) = get(port, "/api/scan-defaults");
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["args"], "-sC -sV", "{body}");

    // the guard covers this route too: no X-Rustrawl, no nmap
    let (status, _) = post(
        port,
        "/api/scan",
        r#"{"ip":"127.0.0.2","args":"-sV -p 39147"}"#,
        false,
    );
    assert_eq!(status, 403);

    // the registry, not the request, picks targets: an IP that never came
    // up is a 400 before anything spawns
    let (status, body) = post(
        port,
        "/api/scan",
        r#"{"ip":"127.0.0.99","args":"-sV -p 39147"}"#,
        true,
    );
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("not an up host"), "{body}");

    // the brake: the guard covers it, and with nothing running it says so
    let (status, _) = post(port, "/api/scan/stop", r#"{}"#, false);
    assert_eq!(status, 403);
    let (status, body) = post(port, "/api/scan/stop", r#"{}"#, true);
    assert_eq!(status, 409, "{body}");
    assert!(body.contains("no scan is running"), "{body}");

    // the happy path: one synchronous nmap over .2, rows ingested, the
    // answer carries the manual run id and the open services (the port
    // list rides in the args)
    let (status, body) = post(
        port,
        "/api/scan",
        r#"{"ip":"127.0.0.2","args":"-sV -p 39147"}"#,
        true,
    );
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["ip"], "127.0.0.2");
    assert_eq!(v["open"], 1);
    assert!(
        v["run"].as_str().unwrap().starts_with("manual_"),
        "the run id names the manual run: {body}"
    );
    assert_eq!(v["services"][0]["port"], 39147);
    assert_eq!(v["services"][0]["service"], "rescan-svc");

    // the sheet now carries the fresh rows: the services table row and the
    // evidence stack led by the manual run (it beats the older fabricated
    // scan_ run — a rescan is the freshest evidence)
    let (status, body) = get(port, "/api/host/127.0.0.2");
    assert_eq!(status, 200);
    assert!(body.contains("rescan-svc"), "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let ev = v["evidence"].as_array().expect("evidence stack");
    assert!(
        ev[0]["run"].as_str().unwrap().starts_with("manual_"),
        "the rescan's own capture is the newest evidence: {body}"
    );
    assert!(
        ev[0]["text"]
            .as_str()
            .unwrap()
            .contains("found by the rescan"),
        "{body}"
    );
    assert!(body.contains("found by the rescan"), "{body}");
    // the services table sees the row too
    let (status, body) = get(port, "/api/services");
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["count"], 1, "{body}");
    assert_eq!(v["services"][0]["name"], "rescan-svc");
    // and the defaults still come from the queue run, not the manual one
    let (status, body) = get(port, "/api/scan-defaults");
    assert_eq!(status, 200);
    assert!(body.contains("\"args\":\"-sC -sV\""), "{body}");

    // ── batch rescans ────────────────────────────────────────────────
    // an ips list: one nmap process, sorted/deduped, up-filtered, and the
    // answer drops the single-host keys (no ip, no per-host services dump)
    let manual_runs = || -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = fs::read_dir(perim.join("runs"))
            .expect("runs dir")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("manual_"))
                    .unwrap_or(false)
            })
            .collect();
        v.sort();
        v
    };
    let runs_before = manual_runs().len();
    let (status, body) = post(
        port,
        "/api/scan",
        r#"{"ips":["127.0.0.3","127.0.0.2"],"args":"-sV -p 39147"}"#,
        true,
    );
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["count"], 2, "{body}");
    assert_eq!(v["skipped"], 0, "{body}");
    assert_eq!(v["open"], 2, "{body}");
    assert!(v["run"].as_str().unwrap().starts_with("manual_"), "{body}");
    assert!(
        v.get("ip").is_none() && v.get("services").is_none(),
        "the batch answer carries no single-host keys: {body}"
    );
    // ONE spawn: the newest manual run's argv names both hosts (sorted)
    // and carries exactly one output base
    let runs = manual_runs();
    assert_eq!(runs.len(), runs_before + 1, "{runs:?}");
    let argv = fs::read_to_string(runs.last().unwrap().join("scans").join("chunk-0000.argv"))
        .expect("argv dump");
    let argv_lines: Vec<&str> = argv.lines().collect();
    assert_eq!(
        argv_lines.iter().filter(|l| **l == "-oA").count(),
        1,
        "one nmap process: {argv:?}"
    );
    assert_eq!(
        argv_lines.last(),
        Some(&"127.0.0.3"),
        "hosts pinned last, sorted: {argv:?}"
    );
    assert!(argv_lines.contains(&"127.0.0.2"), "{argv:?}");

    // a not-up member is dropped and counted, not fatal
    let (status, body) = post(
        port,
        "/api/scan",
        r#"{"ips":["127.0.0.4","127.0.0.99"]}"#,
        true,
    );
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["count"], 1, "{body}");
    assert_eq!(v["skipped"], 1, "{body}");

    // a range: everything up inside it, skipped stays 0 (nothing outside
    // the range was ever requested)
    let (status, body) = post(port, "/api/scan", r#"{"range":"127.0.0.0/29"}"#, true);
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["count"], 8, "{body}");
    assert_eq!(v["skipped"], 0, "{body}");
    let runs = manual_runs();
    let argv = fs::read_to_string(runs.last().unwrap().join("scans").join("chunk-0000.argv"))
        .expect("argv dump");
    let n_hosts = argv
        .lines()
        .filter(|l| l.parse::<std::net::Ipv4Addr>().is_ok())
        .count();
    assert_eq!(n_hosts, 8, "{argv:?}");

    // the refusal matrix — all before anything spawns
    let runs_before = manual_runs().len();
    let (status, body) = post(port, "/api/scan", r#"{"range":"junk"}"#, true);
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("bad range"), "{body}");
    let (status, body) = post(
        port,
        "/api/scan",
        r#"{"ip":"127.0.0.2","range":"127.0.0.0/29"}"#,
        true,
    );
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("exactly one of ip, range, ips"), "{body}");
    let (status, body) = post(port, "/api/scan", r#"{"range":"127.9.0.0/24"}"#, true);
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("no up host"), "{body}");
    // guard-less: 403 and no run directory created
    let (status, _) = post(port, "/api/scan", r#"{"range":"127.0.0.0/29"}"#, false);
    assert_eq!(status, 403);
    assert_eq!(
        manual_runs().len(),
        runs_before,
        "a refused scan must not create a run"
    );

    // ── exports ──────────────────────────────────────────────────────
    // reads, so no guard header; each names its download filename
    let (status, ctype, body) = get_bytes(port, "/api/export/services.csv");
    assert_eq!(status, 200);
    assert_eq!(ctype, "text/csv", "{ctype}");
    let text = String::from_utf8_lossy(&body).into_owned();
    assert!(
        text.starts_with("ip,port,proto,service,version,last_seen,run\n"),
        "{text:?}"
    );
    assert!(text.contains("rescan-svc"), "{text:?}");
    let head = get_head(port, "/api/export/services.csv");
    assert!(
        head.contains("Content-Disposition: attachment; filename=\"rustrawl-services.csv\""),
        "{head}"
    );

    let (status, ctype, body) = get_bytes(port, "/api/export/scan.xml");
    assert_eq!(status, 200);
    assert_eq!(ctype, "application/xml", "{ctype}");
    let text = String::from_utf8_lossy(&body).into_owned();
    assert!(text.contains("<nmaprun"), "{text:?}");
    assert!(text.contains("127.0.0.2"), "{text:?}");

    let (status, ctype, body) = get_bytes(port, "/api/export/hosts.txt");
    assert_eq!(status, 200);
    assert_eq!(ctype, "text/plain; charset=utf-8", "{ctype}");
    let text = String::from_utf8_lossy(&body).into_owned();
    let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 8, "{text:?}");
    let head = get_head(port, "/api/export/hosts.txt");
    assert!(head.contains("filename=\"rustrawl-hosts.txt\""), "{head}");

    let (status, ctype, _) = get_bytes(port, "/api/export/services.txt");
    assert_eq!(status, 200);
    assert!(ctype.starts_with("text/plain"), "{ctype}");
    let (status, ctype, _) = get_bytes(port, "/api/export/services.xml");
    assert_eq!(status, 200);
    assert_eq!(ctype, "application/xml", "{ctype}");

    let (status, _) = get(port, "/api/export/nope");
    assert_eq!(status, 404);
    // the filtered-export POST is a guard-free read: an empty body is a
    // 400 naming the shape, on the wire, with no X-Rustrawl at all
    let (status, body) = post(port, "/api/export/hosts.txt", r#"{}"#, false);
    assert_eq!(status, 400);
    assert!(body.contains("give rows or ips"), "{body}");

    drop(child);
    fs::remove_dir_all(&root).ok();
}

/// The fixed page the capture listeners serve: a title to extract and a
/// signature fragment ("welcome to nginx") to fingerprint.
fn cap_page() -> Vec<u8> {
    let body = b"<html><head><title>Big Router</title></head><body>\
                 <h1>Welcome to nginx!</h1>\
                 <p>bait page for the capture pass</p></body></html>";
    let mut resp = format!(
        "HTTP/1.1 200 OK\r\nServer: bait-httpd/1.0\r\nContent-Type: text/html\r\n\
         Connection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    resp.extend_from_slice(body);
    resp
}

/// One loopback HTTP listener answering every connection with the same
/// fixed page. The accept loop runs detached — the test process ends
/// before the port could bother anyone. The ports (39147/39148) sit
/// outside the 39145/39146 set the other tests' discovery sweeps, so a
/// parallel test's sweep never sees these listeners as open.
fn serve_cap_page(port: u16) {
    let listener = std::net::TcpListener::bind(("127.0.0.2", port))
        .unwrap_or_else(|e| panic!("capture listener {port}: {e}"));
    std::thread::spawn(move || {
        let page = cap_page();
        while let Ok((mut s, _)) = listener.accept() {
            let page = page.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf); // request head; the answer is fixed
                let _ = s.write_all(&page);
            });
        }
    });
}

/// The chromium stand-in: appends its full argv to $FAKE_CHROME_ARGV (two
/// spawns expected, appended in completion order) and writes the same 16
/// fixed bytes at the --screenshot path — identical bytes on purpose, so
/// the two live targets collide into one digest and exercise the dedup.
const FAKE_CHROME: &str = r#"#!/usr/bin/env bash
set -u
out=""
for a in "$@"; do
  case "$a" in
    --screenshot=*) out="${a#--screenshot=}" ;;
  esac
done
if [[ -n "${FAKE_CHROME_ARGV:-}" ]]; then printf '%s\n' "$@" >> "$FAKE_CHROME_ARGV"; fi
if [[ -n "$out" ]]; then
  printf '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52' > "$out"
fi
"#;

/// The bytes the fake chromium writes; the valid PNG magic is all the
/// capture pass checks before digesting and storing.
const FAKE_PNG: &[u8] = &[
    0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, b'I', b'H', b'D', b'R',
];

/// The nmap stand-in for the manual rescan that SEEDS the registry: the
/// dashboard's own fake only ever reports one hardcoded port, so this one
/// reads its port list from the environment — $FAKE_CAP_PORTS as http and
/// $FAKE_CAP_TLS_PORT as https on every host argument. Same argv contract
/// and file shapes as the real one (-oA base, hosts pinned last, real
/// .gnmap/.nmap on disk).
const FAKE_CAP_NMAP: &str = r#"#!/usr/bin/env bash
set -u
echo "fake capture nmap on $*"
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
: > "$base.gnmap"
: > "$base.nmap"
for h in "${hosts[@]}"; do
  printf 'Host: %s ()\tStatus: Up\n' "$h" >> "$base.gnmap"
  ports=""
  {
    printf 'Nmap scan report for %s\nHost is up (0.001s latency).\nPORT     STATE SERVICE VERSION\n' "$h"
    for p in ${FAKE_CAP_PORTS:-}; do
      printf '%s/tcp open  http    bait-web 1.0\n' "$p"
      ports+="$p/open/tcp//http//bait-web 1.0, "
    done
    if [[ -n "${FAKE_CAP_TLS_PORT:-}" ]]; then
      printf '%s/tcp open  https   bait-tls 1.0\n' "$FAKE_CAP_TLS_PORT"
      ports+="$FAKE_CAP_TLS_PORT/open/tcp//https//bait-tls 1.0, "
    fi
  } >> "$base.nmap"
  ports=${ports%, }
  printf 'Host: %s ()\tPorts: %s\tIgnored State: closed (1)\n' "$h" "$ports" >> "$base.gnmap"
done
"#;

/// The capture pass end to end: discovery marks the /29 up, a manual
/// rescan (the parameterized fake nmap) ingests http/https services, then
/// `rustrawl web` shoots the registry. Two loopback listeners answer the
/// live targets; the fake chromium's identical PNG bytes collide into one
/// digest (the dedup); the rest run the real hand-rolled HTTP fetch and
/// the real curl into conn-refused rows. The run's files, the manifest,
/// the state, the dashboard routes and the page JS are all pinned. The
/// pass refuses first with no services in the registry — it never
/// discovers anything.
#[test]
fn capture_pass_shoots_the_registry_web_services() {
    let root = temp_root("cap");
    let scope_path = root.join("scope.yaml");
    fs::write(&scope_path, SCOPE).unwrap();
    let perim = root.join("perim");

    // discovery seeds the registry: 8 up hosts, no services anywhere
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

    // no scan yet: the pass refuses instead of probing anything itself
    let out = bin()
        .args(["web", "--out", perim.to_str().unwrap()])
        .output()
        .expect("web launches");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no http/https service in the registry"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // the two pages the pass will shoot: 127.0.0.2:39147 and :39148
    serve_cap_page(39147);
    serve_cap_page(39148);

    // the dashboard on an ephemeral port, with the parameterized fake nmap
    // overriding its own (extra env lands after the helper's default). The
    // fake chromium rides along too: the sheet's per-asset button (below)
    // runs the pass in-server, and its argv lands in a second dump.
    let fake_nmap = root.join("fake-cap-nmap");
    fs::write(&fake_nmap, FAKE_CAP_NMAP).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&fake_nmap, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let fake_chrome = root.join("fake-chrome");
    fs::write(&fake_chrome, FAKE_CHROME).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&fake_chrome, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let ui_argv = root.join("fake-chrome-ui.argv");
    let (child, dport, _stderr_reader) = spawn_dashboard(
        &perim,
        "cap",
        &[
            ("RUSTRAWL_NMAP_BIN", fake_nmap.to_str().unwrap()),
            ("FAKE_CAP_PORTS", "39147 39148"),
            ("FAKE_CAP_TLS_PORT", "39149"),
            ("RUSTRAWL_CHROME_BIN", fake_chrome.to_str().unwrap()),
            ("FAKE_CHROME_ARGV", ui_argv.to_str().unwrap()),
        ],
    );

    // a manual rescan over three hosts: 3 services each (2 http + 1
    // https), 9 rows into the registry, none of them probed by us
    let (status, body) = post(
        dport,
        "/api/scan",
        r#"{"ips":["127.0.0.2","127.0.0.3","127.0.0.4"],"args":""}"#,
        true,
    );
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["count"], 3, "{body}");
    assert_eq!(v["open"], 9, "{body}");
    let (status, body) = get(dport, "/api/services");
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["count"], 9, "{body}");

    // the pass itself: fake chromium in (already on disk above; its argv
    // dump is separate from the dashboard's), real curl for the https rows
    let argv_dump = root.join("fake-chrome.argv");
    let out = bin()
        .args(["web", "--out", perim.to_str().unwrap(), "--threads", "2"])
        .env("RUSTRAWL_CHROME_BIN", &fake_chrome)
        .env("FAKE_CHROME_ARGV", &argv_dump)
        .output()
        .expect("web launches");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr
            .contains("2/9 target(s) captured, 7 failed, 1 duplicate screenshot(s) - evidence in"),
        "{stderr}"
    );

    let mut web_runs: Vec<String> = fs::read_dir(perim.join("runs"))
        .expect("runs dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("web_"))
        .collect();
    assert_eq!(web_runs.len(), 1, "{web_runs:?}");
    let run_id = web_runs.remove(0);
    let run_dir = perim.join("runs").join(&run_id);

    // the state file: finished on its own, the fake resolved as the browser
    let st: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(run_dir.join("cap_state.json")).unwrap()).unwrap();
    assert_eq!(st["done"], true, "{st}");
    assert_eq!(st["interrupted"], false, "{st}");
    assert_eq!(st["threads"], 2, "{st}");
    assert_eq!(st["timeout_secs"], 7, "{st}");
    assert!(
        st["chrome"].as_str().unwrap().ends_with("fake-chrome"),
        "{st}"
    );
    let targets = st["targets"].as_array().unwrap();
    assert_eq!(targets.len(), 9, "{st}");
    assert!(targets.iter().all(|t| t["done"] == true), "{st}");
    assert_eq!(
        targets
            .iter()
            .filter(|t| !t["error"].as_str().unwrap_or("").is_empty())
            .count(),
        7,
        "{st}"
    );

    // the manifest: one row per target, completion order, every field filled
    let manifest = fs::read_to_string(run_dir.join("targets.jsonl")).unwrap();
    let rows: Vec<serde_json::Value> = manifest
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows.len(), 9, "{manifest}");
    let clean: Vec<_> = rows.iter().filter(|r| r["error"] == "").collect();
    assert_eq!(clean.len(), 2, "{manifest}");
    assert_eq!(
        rows.iter().filter(|r| r["error"] == "conn-refused").count(),
        7,
        "{manifest}"
    );
    let by_port = |p: u64| {
        clean
            .iter()
            .find(|r| r["port"].as_u64() == Some(p))
            .unwrap_or_else(|| panic!("no clean row for port {p}: {manifest}"))
    };
    let r47 = by_port(39147);
    let r48 = by_port(39148);
    assert_eq!(r47["url"], "http://127.0.0.2:39147/", "{r47}");
    assert_eq!(r47["title"], "Big Router", "{r47}");
    assert_eq!(r47["label"], "nginx default page", "{r47}");
    assert_eq!(r47["status"], 200, "{r47}");
    assert_eq!(r47["scheme"], "http", "{r47}");
    assert!(
        r47["headers"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("bait-httpd/1.0"),
        "{r47}"
    );
    // both screenshots are byte-identical, so one digest, one stored file,
    // and the later row points at the earlier row's URL
    assert_eq!(r47["sha256"], r48["sha256"], "{r47} {r48}");
    let sha = r47["sha256"].as_str().unwrap().to_string();
    assert_eq!(sha.len(), 64, "{r47}");
    assert_eq!(r47["shot"], format!("{sha}.png"), "{r47}");
    assert_eq!(r48["shot"], r47["shot"], "{r48}");
    let (first, second) = if r47["dup_of"] == "" {
        (r47, r48)
    } else {
        (r48, r47)
    };
    assert_eq!(first["dup_of"], "", "{first}");
    assert_eq!(second["dup_of"], first["url"], "{second}");
    // exactly one PNG on disk, byte-for-byte the fake's output
    let shots: Vec<String> = fs::read_dir(run_dir.join("shots"))
        .expect("shots dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(shots, vec![format!("{sha}.png")], "{shots:?}");
    let png = fs::read(run_dir.join("shots").join(format!("{sha}.png"))).unwrap();
    assert_eq!(png, FAKE_PNG);

    // the fake chromium's argv: two spawns of the pinned CLI shape, shots
    // landing in the worker scratch, the two target URLs as the last args
    let argv = fs::read_to_string(&argv_dump).unwrap();
    let lines: Vec<&str> = argv.lines().collect();
    assert_eq!(lines.len(), 26, "two spawns, 13 args each: {argv:?}");
    assert_eq!(lines.iter().filter(|l| **l == "--headless=new").count(), 2);
    for pin in [
        "--no-sandbox",
        "--disable-gpu",
        "--hide-scrollbars",
        "--ignore-certificate-errors",
        "--window-size=1366,768",
        "--timeout=7000",
        "--virtual-time-budget=5000",
    ] {
        assert_eq!(
            lines.iter().filter(|l| **l == pin).count(),
            2,
            "{pin} once per spawn: {argv:?}"
        );
    }
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.starts_with("--user-agent=Mozilla/5.0"))
            .count(),
        2,
        "{argv:?}"
    );
    let shot_args: Vec<_> = lines
        .iter()
        .filter(|l| l.starts_with("--screenshot="))
        .collect();
    assert_eq!(shot_args.len(), 2, "{argv:?}");
    assert!(
        shot_args.iter().all(|l| l.contains("/tmp/w")),
        "shots land in the worker scratch: {shot_args:?}"
    );
    let mut url_args: Vec<&str> = lines
        .iter()
        .filter(|l| l.starts_with("http://"))
        .copied()
        .collect();
    url_args.sort_unstable();
    assert_eq!(
        url_args,
        vec!["http://127.0.0.2:39147/", "http://127.0.0.2:39148/"],
        "the URL is chromium's last argument: {argv:?}"
    );

    // the dashboard reads the run back: list, rows, shot, refusals
    let (status, body) = get(dport, "/api/captures");
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["count"], 1, "{body}");
    let run0 = &v["runs"][0];
    assert_eq!(run0["run"], run_id.as_str(), "{body}");
    assert_eq!(run0["done"], true, "{body}");
    assert_eq!(run0["interrupted"], false, "{body}");
    assert_eq!(run0["total"], 9, "{body}");
    assert_eq!(run0["done_count"], 9, "{body}");
    assert_eq!(run0["errors"], 7, "{body}");
    assert!(
        run0["chrome"].as_str().unwrap().ends_with("fake-chrome"),
        "{body}"
    );

    let (status, body) = get(dport, &format!("/api/captures/{run_id}"));
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["done"], true, "{body}");
    assert_eq!(v["total"], 9, "{body}");
    assert_eq!(v["done_count"], 9, "{body}");
    let targets = v["targets"].as_array().unwrap();
    assert_eq!(targets.len(), 9, "{body}");
    let t47 = targets.iter().find(|t| t["port"] == 39147).unwrap();
    assert_eq!(t47["title"], "Big Router", "{t47}");
    assert_eq!(t47["label"], "nginx default page", "{t47}");
    assert_eq!(t47["run"], run_id.as_str(), "{t47}");
    assert_eq!(
        t47["shot_url"],
        format!("/shots/{run_id}/{sha}.png"),
        "{t47}"
    );
    let tls = targets.iter().find(|t| t["port"] == 39149).unwrap();
    assert_eq!(tls["scheme"], "https", "{tls}");
    assert_eq!(tls["error"], "conn-refused", "{tls}");
    assert!(!tls["detail"].as_str().unwrap_or("").is_empty(), "{tls}");
    assert!(tls["shot_url"].is_null(), "{tls}");

    let (status, ctype, raw) = get_bytes(dport, &format!("/shots/{run_id}/{sha}.png"));
    assert_eq!(status, 200);
    assert_eq!(ctype, "image/png", "{ctype}");
    assert_eq!(raw, FAKE_PNG, "the shot comes back byte-for-byte");

    // routing refuses junk run ids and junk or absent shot names
    assert_eq!(get(dport, "/api/captures/junk").0, 404);
    assert_eq!(get(dport, &format!("/shots/{run_id}/short.png")).0, 404);
    assert_eq!(
        get(dport, &format!("/shots/{run_id}/{}.png", "z".repeat(64))).0,
        404
    );
    assert_eq!(
        get(dport, &format!("/shots/{run_id}/{}.png", "e".repeat(64))).0,
        404,
        "a valid but absent digest is still a 404"
    );
    assert_eq!(get(dport, &format!("/shots/junk/{sha}.png")).0, 404);

    // the host sheet carries its captures; a capture-less host an empty list
    let (status, body) = get(dport, "/api/host/127.0.0.2");
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let caps = v["captures"].as_array().unwrap();
    assert_eq!(caps.len(), 3, "{body}");
    assert!(caps.iter().all(|c| c["run"] == run_id.as_str()), "{body}");
    assert!(
        caps.iter().any(|c| c["port"] == 39147
            && c["label"] == "nginx default page"
            && c["shot_url"].is_string()),
        "{body}"
    );
    assert!(
        caps.iter()
            .any(|c| c["port"] == 39149 && c["error"] == "conn-refused"),
        "{body}"
    );
    let (status, body) = get(dport, "/api/host/127.0.0.6");
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["captures"].as_array().unwrap().len(), 0, "{body}");

    // ── asset-by-asset: the sheet's button ─────────────────────────────
    // the registry, not the request, picks the targets — same refusals as
    // a rescan: not an up host, then up but nothing web on it
    let (status, body) = post(dport, "/api/capture", r#"{"ip":"127.0.0.9"}"#, true);
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("not an up host in this registry"), "{body}");
    let (status, body) = post(dport, "/api/capture", r#"{"ip":"127.0.0.6"}"#, true);
    assert_eq!(status, 400, "{body}");
    assert!(
        body.contains("no http/https service for 127.0.0.6"),
        "{body}"
    );
    // and the write guard, like every POST
    let (status, _) = post(dport, "/api/capture", r#"{"ip":"127.0.0.2"}"#, false);
    assert_eq!(status, 403);
    // one click, one small run: the host's three web services (two http
    // listeners + the dead https port), none of them re-probed first
    let (status, body) = post(dport, "/api/capture", r#"{"ip":"127.0.0.2"}"#, true);
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["total"], 3, "{body}");
    let run2 = v["run"].as_str().unwrap().to_string();
    assert!(
        run2.starts_with("web_") && run2 != run_id,
        "a second, distinct web run: {body}"
    );
    let caps = v["captured"].as_array().unwrap();
    assert_eq!(caps.len(), 3, "{body}");
    assert!(
        caps.iter().all(|c| c["run"] == run2.as_str()),
        "the response rows carry the fresh run: {body}"
    );
    assert_eq!(
        caps.iter().filter(|c| c["error"] == "").count(),
        2,
        "{body}"
    );
    assert!(
        caps.iter()
            .any(|c| c["port"] == 39149 && c["error"] == "conn-refused"),
        "{body}"
    );
    assert!(
        caps.iter().any(|c| c["port"] == 39147
            && c["shot_url"]
                .as_str()
                .unwrap()
                .starts_with(&format!("/shots/{run2}/"))),
        "{body}"
    );
    // its own run dir, its own dedup: the two live pages share the fake
    // png bytes, so one stored image serves both
    let ui_run_dir = perim.join("runs").join(&run2);
    let st: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(ui_run_dir.join("cap_state.json")).unwrap())
            .unwrap();
    assert_eq!(st["done"], true, "{st}");
    let ui_shots: Vec<String> = fs::read_dir(ui_run_dir.join("shots"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(ui_shots.len(), 1, "{ui_shots:?}");
    // the sheet now walks both runs: 3 rows from the CLI pass + 3 from the
    // click (the 12-run window dwarfs it either way)
    let (status, body) = get(dport, "/api/host/127.0.0.2");
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let caps = v["captures"].as_array().unwrap();
    assert_eq!(caps.len(), 6, "{body}");
    assert!(caps.iter().any(|c| c["run"] == run_id.as_str()), "{body}");
    assert!(caps.iter().any(|c| c["run"] == run2.as_str()), "{body}");
    // a click while the perimeter is locked (the CLI pass, a scan) is a
    // 409, not a queue: the lock is the one-at-a-time truth
    let lockf = fs::File::create(perim.join("run.lock")).unwrap();
    use fs2::FileExt as _;
    lockf.try_lock_exclusive().unwrap();
    let (status, body) = post(dport, "/api/capture", r#"{"ip":"127.0.0.2"}"#, true);
    assert_eq!(status, 409, "{body}");
    assert!(body.contains("one scan per perimeter"), "{body}");
    drop(lockf);

    // the page: the capture tab ships in nav, router, JS and CSS — and the
    // sheet's per-asset write ships with it (helper, button, in-flight label)
    let (status, page) = get(dport, "/");
    assert_eq!(status, 200);
    for key in [
        "#/capture",
        "tab-capture",
        "renderCapture",
        "loadCaptureGrid",
        "startCapturePoll",
        "stopCapturePoll",
        "capTile(",
        "capgrid",
        "captile",
        "capurl",
        "caplabel",
        "caperr",
        "capdup",
        "capheaders",
        "sheetCap(",
        "rustrawl web --out",
    ] {
        assert!(page.contains(key), "capture contract: {key} missing");
    }
    for key in ["postCapture(", "capture this host", "capturing…"] {
        assert!(
            page.contains(key),
            "per-asset capture contract: {key} missing"
        );
    }

    drop(child);
    fs::remove_dir_all(&root).ok();
}

/// The filtered-export POSTs, the range->up-ips resolution and the live
/// output tail, over the wire: what the page displays is what leaves, the
/// ranges chip's queue resolves server-side, and a scan's nmap output is
/// readable while the run is active and stays fetchable after it.
#[test]
fn filtered_exports_up_ips_and_live_output() {
    let root = temp_root("filt");
    let scope_path = root.join("scope.yaml");
    fs::write(&scope_path, SCOPE).unwrap();
    let perim = root.join("perim");
    // discovery seeds the registry: 8 sweep-up hosts under 127.0.0.0/29
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
    // FAKE_NMAP_SLEEP stretches the run so the tail can be watched grow
    let (child, port, _stderr_reader) =
        spawn_dashboard(&perim, "filt", &[("FAKE_NMAP_SLEEP", "2")]);

    // up-ips: the range row's chip resolves its queue server-side — the
    // same intersection the scan would take, no guard header
    let (status, body) = post(port, "/api/up-ips", r#"{"range":"127.0.0.0/29"}"#, false);
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["count"], 8, "{body}");
    let ips = v["ips"].as_array().expect("ips array");
    assert_eq!(ips.len(), 8);
    assert!(
        ips.iter()
            .all(|x| x.as_str().unwrap().starts_with("127.0.0.")),
        "{body}"
    );
    // a junk range names the shape, still a read
    let (status, body) = post(port, "/api/up-ips", r#"{"range":"junk"}"#, false);
    assert_eq!(status, 400);
    assert!(body.contains("bad range"), "{body}");

    // filtered exports: rows ride in body order — the screen order — and
    // no guard header: the exports are reads
    let rows = r#"{"rows":[
        {"ip":"127.0.0.5","port":22,"name":"ssh","version":"OpenSSH 9.2","seen":0,"run":"it"},
        {"ip":"127.0.0.2","port":39145,"name":"http","version":"bait 1.0","seen":0,"run":"it"}
    ]}"#;
    let (status, ctype, bytes) = post_bytes(
        port,
        "/api/export/services.csv",
        "application/json",
        rows.as_bytes(),
        false,
    );
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&bytes));
    assert_eq!(ctype, "text/csv", "{ctype}");
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let mut lines = text.lines();
    assert_eq!(
        lines.next(),
        Some("ip,port,proto,service,version,last_seen,run"),
        "{text:?}"
    );
    // .5 first: the body order, not the numeric one
    assert_eq!(
        lines.next(),
        Some("127.0.0.5,22,tcp,ssh,OpenSSH 9.2,1970-01-01 00:00:00 UTC,it"),
        "{text:?}"
    );
    assert_eq!(
        lines.next(),
        Some("127.0.0.2,39145,tcp,http,bait 1.0,1970-01-01 00:00:00 UTC,it"),
        "{text:?}"
    );
    assert_eq!(lines.next(), None, "{text:?}");

    // the txt of the same rows collapses to the distinct hosts, numeric
    let (status, _, bytes) = post_bytes(
        port,
        "/api/export/services.txt",
        "application/json",
        rows.as_bytes(),
        false,
    );
    assert_eq!(status, 200);
    assert_eq!(String::from_utf8_lossy(&bytes), "127.0.0.2\n127.0.0.5\n");

    // hosts.txt over an ip set: deduped, numeric order
    let (status, _, bytes) = post_bytes(
        port,
        "/api/export/hosts.txt",
        "application/json",
        br#"{"ips":["127.0.0.7","127.0.0.2","127.0.0.7"]}"#,
        false,
    );
    assert_eq!(status, 200);
    assert_eq!(String::from_utf8_lossy(&bytes), "127.0.0.2\n127.0.0.7\n");

    // scan.xml over an ip set: nmap format naming those hosts
    let (status, ctype, bytes) = post_bytes(
        port,
        "/api/export/scan.xml",
        "application/json",
        br#"{"ips":["127.0.0.2"]}"#,
        false,
    );
    assert_eq!(status, 200);
    assert_eq!(ctype, "application/xml", "{ctype}");
    let text = String::from_utf8_lossy(&bytes).into_owned();
    assert!(text.starts_with("<?xml"), "{text:?}");
    assert!(text.contains("<nmaprun"), "{text:?}");
    assert!(text.contains("127.0.0.2"), "{text:?}");

    // the live tail: the POST blocks server-side while the slowed fake
    // nmap "runs"; its echo lands in chunk-0000.out and the route serves
    // it with running:true. Then the run ends and the capture stays.
    let poster = std::thread::spawn(move || {
        post(
            port,
            "/api/scan",
            r#"{"ips":["127.0.0.2","127.0.0.3"],"args":""}"#,
            true,
        )
    });
    let mut saw_running = false;
    let mut saw_text = false;
    let mut run_id = String::new();
    for _ in 0..200 {
        if let Some((200, b)) = try_get(port, "/api/scan/output") {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&b) {
                if v["running"].as_bool() == Some(true) {
                    saw_running = true;
                    if let Some(r) = v["run"].as_str() {
                        run_id = r.to_string();
                    }
                    if v["text"]
                        .as_str()
                        .map(|t| t.contains("fake nmap on"))
                        .unwrap_or(false)
                    {
                        saw_text = true;
                        break;
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(saw_running, "the scan never showed as running");
    assert!(saw_text, "the live tail never showed the fake nmap echo");
    assert!(
        run_id.starts_with("manual_"),
        "the running scan names its run: {run_id:?}"
    );
    let (status, body) = poster.join().unwrap();
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"count\":2"), "{body}");

    // after the run: the flag is down, the tail is retained (the run id
    // stays until the next scan overwrites it), and /api/status carries
    // the same id for a page that navigated away
    let (status, body) = get(port, "/api/scan/output");
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["running"], false, "{body}");
    assert_eq!(v["run"], run_id, "{body}");
    assert!(
        v["text"]
            .as_str()
            .is_some_and(|t| t.contains("fake nmap on")),
        "{body}"
    );
    // the captured command line rides the same answer: the fake's
    // one-token-per-line .argv (its own arguments — the server's writer
    // prefixes the binary, the fake's echo shape need not) joined back
    // into one shell line
    assert!(
        v["cmd"]
            .as_str()
            .is_some_and(|c| c.contains("-Pn -n --open") && c.ends_with("127.0.0.2 127.0.0.3")),
        "{body}"
    );
    let (_, body) = get(port, "/api/status");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["run"], run_id, "{body}");

    drop(child);
    fs::remove_dir_all(&root).ok();
}
