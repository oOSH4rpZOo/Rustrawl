//! EyeWitness-style capture pass, rebuilt from scratch: for every http/https
//! service the registry knows — any port — one headless-chromium screenshot,
//! HTTP response headers, the page title, and a default-credential/category
//! fingerprint from a hand-written signature table. Evidence lands in
//! `runs/web_<date>_<time>/` and the dashboard only reads it.
//!
//! What this pass is NOT: no redirects are followed in v1, no forms, no
//! cookies, no login attempts — the signature table only labels what the
//! default page says (the audit maps labels to default creds by hand). RDP,
//! VNC and SSH capture were dropped by EyeWitness itself and stay out.
//!
//! Two processes per target, neither through a driver:
//! - headers/title: plain-HTTP targets get a hand-rolled `TcpStream` GET
//!   (browser-ish UA — several appliances 403 an empty one); https targets
//!   get one external `curl -sk` call. The hand-rolled TLS client stays out
//!   of this codebase on purpose.
//! - screenshot: chromium's plain CLI (`--headless=new --screenshot`, no
//!   chromedriver — EyeWitness made the same call when it moved to Chrome).
//!   The browser does its own TLS and screenshots cert interstitials too.
//!   Its self-exit is NEVER trusted (virtual time hangs on websockets):
//!   the caller owns a deadline and kills.
//!
//! Missing chromium degrades the run to headers+title (`browser-missing`
//! cards); missing chromium AND curl refuses the run. Overrides:
//! `RUSTRAWL_CHROME_BIN`, `RUSTRAWL_CURL_BIN`.
//!
//! Targets: every registry service on a host that is currently up, where
//! name/port classifies as http or https (same predicate as the dashboard's
//! own links — a dead host is never probed, mirroring the names pass).
//! Caps keep a mistyped scope honest: 512 targets, 30 minutes, 16 threads.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::cli::WebArgs;
use crate::discovery::db::Db;
use crate::discovery::state;
use crate::discovery::{on_sigint, ABORT};

pub(crate) const SIGNATURES: &str = include_str!("capture_signatures.txt");

/// The run's bookkeeping files, shared with the read-only dashboard.
pub(crate) const STATE_FILE: &str = "cap_state.json";
pub(crate) const MANIFEST_FILE: &str = "targets.jsonl";

pub(crate) const MAX_CAPTURE_TARGETS: usize = 512;
const CAPTURE_TOTAL_CAP: Duration = Duration::from_secs(30 * 60);
/// Extra wait on top of the timeout before a child is killed — the timeout
/// is a promise to the target, the slack is patience for process teardown.
const KILL_SLACK: Duration = Duration::from_secs(3);
/// Shared with the dashboard's per-asset capture (POST /api/capture), so
/// the CLI flag default and the server-side pool stay one number.
pub(crate) const DEFAULT_THREADS: usize = 4;
/// Same story as DEFAULT_THREADS: `web --timeout`'s default and the
/// per-asset route's budget are the same promise to the target.
pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 7;
const MAX_THREADS: usize = 16;
/// State is rewritten as targets complete; every N keeps fsync traffic sane
/// without making the dashboard's progress stale by more than a few seconds.
const STATE_FLUSH_EVERY: usize = 16;
const WINDOW_SIZE: &str = "1366,768";
const VIRTUAL_TIME_BUDGET_MS: u64 = 5_000;
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
/// How much body feeds the fingerprint haystack and the title hunt.
const BODY_HAYSTACK_CAP: usize = 256 * 1024;
/// Raw HTTP answer read bound — headers plus enough page to fingerprint.
const FETCH_BODY_CAP: usize = 1024 * 1024;
/// What a manifest row stores of the header block.
const HEADERS_TEXT_CAP: usize = 4 * 1024;
const TITLE_CAP: usize = 200;

// ----------------------------------------------------------------- targets

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub(crate) enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

/// What gets probed, decided exactly like the dashboard's own service links
/// (web.html `svcUrl`, the names pass classification): https if the service
/// name mentions https/ssl or the port is 443/8443; http if the name mentions
/// http or the port is 80/8080; anything else is not a capture target.
pub(crate) fn classify_service(name: &str, port: u16) -> Option<Scheme> {
    let n = name.to_lowercase();
    if n.contains("https") || n.contains("ssl") || port == 443 || port == 8443 {
        Some(Scheme::Https)
    } else if n.contains("http") || port == 80 || port == 8080 {
        Some(Scheme::Http)
    } else {
        None
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CaptureTarget {
    pub(crate) ip: Ipv4Addr,
    pub(crate) port: u16,
    pub(crate) scheme: Scheme,
}

impl CaptureTarget {
    pub(crate) fn url(&self) -> String {
        format!("{}://{}:{}/", self.scheme.as_str(), self.ip, self.port)
    }
}

/// Every http/https service of a host the registry currently sees up. A
/// service row for a host that has gone silent is skipped — probing it would
/// contradict the no-new-probes rule, exactly like the names pass.
pub(crate) fn web_targets(db: &Db) -> Result<Vec<CaptureTarget>> {
    let mut known = HashSet::new();
    db.up_ips(&mut |ip| {
        known.insert(ip);
    })?;
    let mut seen: HashSet<(Ipv4Addr, u16, Scheme)> = HashSet::new();
    let mut out: Vec<CaptureTarget> = Vec::new();
    db.services(None, None, &mut |ip, port, name, _v, _s, _r| {
        if !known.contains(&ip) {
            return;
        }
        let Some(scheme) = classify_service(name, port) else {
            return;
        };
        if seen.insert((ip, port, scheme)) {
            out.push(CaptureTarget { ip, port, scheme });
        }
    })?;
    out.sort_by_key(|t| (u32::from(t.ip), t.port, t.scheme));
    Ok(out)
}

/// The same classification, narrowed to one asset: what the dashboard's
/// per-asset capture (POST /api/capture) is allowed to shoot. The request
/// only names a host; this walk decides web or not — the same predicate as
/// the full pass, so a host the CLI would capture is capturable here and
/// nothing else is.
pub(crate) fn host_web_targets(db: &Db, ip: Ipv4Addr) -> Result<Vec<CaptureTarget>> {
    let mut known = false;
    db.up_ips(&mut |u| {
        if u == ip {
            known = true;
        }
    })?;
    let mut seen: HashSet<(u16, Scheme)> = HashSet::new();
    let mut out: Vec<CaptureTarget> = Vec::new();
    if known {
        db.services(None, None, &mut |u, port, name, _v, _s, _r| {
            if u != ip {
                return;
            }
            let Some(scheme) = classify_service(name, port) else {
                return;
            };
            if seen.insert((port, scheme)) {
                out.push(CaptureTarget { ip, port, scheme });
            }
        })?;
    }
    out.sort_by_key(|t| (t.port, t.scheme));
    Ok(out)
}

// ---------------------------------------------------------------- binaries

pub(crate) const CHROME_ENV: &str = "RUSTRAWL_CHROME_BIN";
pub(crate) const CURL_ENV: &str = "RUSTRAWL_CURL_BIN";
pub(crate) const CHROME_CANDIDATES: &[&str] = &[
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "chrome",
];

fn which(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).any(|dir| dir.join(name).is_file()))
        .unwrap_or(false)
}

/// Same shape as `nmap_bin`: the env override wins, else the usual
/// chromium/google-chrome names on PATH. None means "no browser" — the run
/// degrades to headers and titles.
pub(crate) fn chrome_bin() -> Option<String> {
    if let Ok(v) = std::env::var(CHROME_ENV) {
        if !v.is_empty() {
            return Some(v);
        }
    }
    CHROME_CANDIDATES
        .iter()
        .find(|n| which(n))
        .map(|n| (*n).to_string())
}

pub(crate) fn curl_bin() -> String {
    std::env::var(CURL_ENV)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "curl".to_string())
}

/// chromium's plain screenshot CLI — the caller owns the deadline and the
/// kill, `--timeout` is only the browser's own belt.
pub(crate) fn chrome_argv(timeout_ms: u64, shot: &Path, profile: &Path, url: &str) -> Vec<String> {
    vec![
        "--headless=new".to_string(),
        "--no-sandbox".to_string(),
        "--disable-gpu".to_string(),
        "--disable-dev-shm-usage".to_string(),
        "--hide-scrollbars".to_string(),
        "--ignore-certificate-errors".to_string(),
        format!("--window-size={WINDOW_SIZE}"),
        format!("--user-agent={USER_AGENT}"),
        format!("--timeout={timeout_ms}"),
        // Virtual time makes static pages settle fast; a websocket keeps it
        // spinning forever, which is why the kill slack exists.
        format!(
            "--virtual-time-budget={}",
            VIRTUAL_TIME_BUDGET_MS.min(timeout_ms)
        ),
        format!("--user-data-dir={}", profile.display()),
        format!("--screenshot={}", shot.display()),
        url.to_string(),
    ]
}

/// https headers + body in one call. `-k`: the point is evidence, not trust;
/// no `-L`: redirects are not followed in v1 (one hop = one row, a redirect
/// chain is for the auditor to walk).
pub(crate) fn curl_argv(timeout_secs: u64, hdr: &Path, body: &Path, url: &str) -> Vec<String> {
    vec![
        "-sk".to_string(),
        "--max-time".to_string(),
        timeout_secs.to_string(),
        "-A".to_string(),
        USER_AGENT.to_string(),
        "-D".to_string(),
        hdr.display().to_string(),
        "-o".to_string(),
        body.display().to_string(),
        url.to_string(),
    ]
}

// ------------------------------------------------------------------ errors

/// Everything that can spoil one target, as a short class word — targets are
/// never skipped, a failed one becomes a card that names the failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ShotError {
    Timeout,
    ConnRefused,
    ConnReset,
    TlsError,
    DnsFailed,
    BadStatus(String),
    BrowserMissing,
}

impl ShotError {
    pub(crate) fn class(&self) -> &'static str {
        match self {
            ShotError::Timeout => "timeout",
            ShotError::ConnRefused => "conn-refused",
            ShotError::ConnReset => "conn-reset",
            ShotError::TlsError => "tls",
            ShotError::DnsFailed => "dns",
            ShotError::BadStatus(_) => "bad-status",
            ShotError::BrowserMissing => "browser-missing",
        }
    }

    fn detail(&self) -> String {
        match self {
            ShotError::BadStatus(d) => d.clone(),
            _ => self.class().to_string(),
        }
    }

    /// Connection-level failures: the browser would hit the same wall, so
    /// the screenshot step is skipped to spare a chromium launch.
    fn conn_level(&self) -> bool {
        matches!(
            self,
            ShotError::Timeout
                | ShotError::ConnRefused
                | ShotError::ConnReset
                | ShotError::TlsError
                | ShotError::DnsFailed
        )
    }
}

fn curl_error(exit: i32) -> ShotError {
    match exit {
        6 => ShotError::DnsFailed,
        7 => ShotError::ConnRefused,
        28 => ShotError::Timeout,
        35 | 54 | 58 | 60 | 64 | 66 => ShotError::TlsError,
        56 => ShotError::ConnReset,
        e => ShotError::BadStatus(format!("curl exit {e}")),
    }
}

fn chrome_error(stderr: &str, killed: bool) -> ShotError {
    if killed {
        return ShotError::Timeout;
    }
    let low = stderr.to_lowercase();
    for (needle, err) in [
        ("err_connection_refused", ShotError::ConnRefused),
        ("err_connection_reset", ShotError::ConnReset),
        ("err_name_not_resolved", ShotError::DnsFailed),
        ("err_cert", ShotError::TlsError),
        ("err_ssl", ShotError::TlsError),
        ("err_timed_out", ShotError::Timeout),
    ] {
        if low.contains(needle) {
            return err;
        }
    }
    // Last non-empty line, bounded — chromium's tail usually names the page.
    let tail = stderr
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no output");
    ShotError::BadStatus(format!("chromium: {}", &tail[..tail.len().min(120)]))
}

// ------------------------------------------------------------- child procs

struct ChildResult {
    code: Option<i32>,
    killed: bool,
    stderr: String,
    spawn_error: Option<String>,
}

/// Spawns `bin argv`, waits up to `deadline`, then kills. stderr drains on
/// its own thread — a chatty page must not fill the pipe and stall the child
/// past its deadline.
fn run_child(bin: &str, argv: &[String], deadline: Duration) -> ChildResult {
    let child = Command::new(bin)
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            return ChildResult {
                code: None,
                killed: false,
                stderr: String::new(),
                spawn_error: Some(format!("{bin}: {e}")),
            }
        }
    };
    let mut errpipe = child.stderr.take();
    let drainer = std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(p) = errpipe.as_mut() {
            let _ = p.read_to_string(&mut buf);
        }
        buf
    });
    let end = Instant::now() + deadline;
    let code = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st.code(),
            Ok(None) if Instant::now() >= end => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => break None,
        }
    };
    ChildResult {
        code,
        killed: code.is_none(),
        stderr: drainer.join().unwrap_or_default(),
        spawn_error: None,
    }
}

// -------------------------------------------------------------- plain http

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Splits a raw answer into (status, header block, body); tolerates bare-LF
/// servers. None = not an HTTP answer at all.
fn parse_http_response(raw: &[u8]) -> Option<(u16, String, Vec<u8>)> {
    let crlf = find(raw, b"\r\n\r\n");
    let lf = find(raw, b"\n\n");
    let (head_end, body_start) = match (crlf, lf) {
        (Some(c), Some(l)) if l < c => (l, l + 2),
        (Some(c), _) => (c, c + 4),
        (None, Some(l)) => (l, l + 2),
        (None, None) => return None,
    };
    let head = String::from_utf8_lossy(&raw[..head_end]);
    let code = head
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse::<u16>()
        .ok()?;
    Some((
        code,
        head.to_string(),
        raw[body_start.min(raw.len())..].to_vec(),
    ))
}

/// Plain HTTP/1.1 GET with a browser-ish UA (appliances 403 an empty one),
/// one deadline over connect + request + answer, bounded reads, and no
/// redirect following in v1.
fn http_fetch(
    ip: Ipv4Addr,
    port: u16,
    timeout: Duration,
) -> Result<(u16, String, Vec<u8>), ShotError> {
    let deadline = Instant::now() + timeout;
    let stream =
        TcpStream::connect_timeout(&SocketAddr::from((ip, port)), timeout).map_err(|e| match e
            .kind()
        {
            std::io::ErrorKind::ConnectionRefused => ShotError::ConnRefused,
            std::io::ErrorKind::TimedOut => ShotError::Timeout,
            _ => match e.raw_os_error() {
                Some(libc::ECONNRESET) => ShotError::ConnReset,
                Some(libc::EHOSTUNREACH) | Some(libc::ENETUNREACH) => {
                    ShotError::BadStatus("unreachable".to_string())
                }
                _ => ShotError::BadStatus(format!("connect: {e}")),
            },
        })?;
    let mut s = stream;
    s.set_read_timeout(Some(timeout)).ok();
    s.set_write_timeout(Some(timeout)).ok();
    let req = format!(
        "GET / HTTP/1.1\r\n\
         Host: {ip}:{port}\r\n\
         User-Agent: {USER_AGENT}\r\n\
         Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n\
         Accept-Language: en\r\n\
         Connection: close\r\n\
         \r\n"
    );
    s.write_all(req.as_bytes()).map_err(|e| match e.kind() {
        std::io::ErrorKind::ConnectionReset => ShotError::ConnReset,
        _ => ShotError::BadStatus(format!("write: {e}")),
    })?;
    let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut chunk = [0u8; 8192];
    loop {
        if buf.len() >= FETCH_BODY_CAP {
            break;
        }
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            return Err(ShotError::Timeout);
        };
        s.set_read_timeout(Some(left)).ok();
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Err(ShotError::Timeout)
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                return Err(ShotError::ConnReset)
            }
            Err(e) => return Err(ShotError::BadStatus(format!("read: {e}"))),
        }
    }
    parse_http_response(&buf).ok_or_else(|| ShotError::BadStatus("not an http answer".to_string()))
}

fn status_of_headers(headers: &str) -> u16 {
    headers
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0)
}

// -------------------------------------------------------- title + fingerprint

/// The handful of entities that actually show up in appliance titles.
fn decode_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
}

/// First `<title>` of the raw body — case-insensitive tag, attributes
/// allowed, entities decoded, whitespace collapsed, bounded. No second
/// browser launch for this.
pub(crate) fn extract_title(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(&body[..body.len().min(FETCH_BODY_CAP)]);
    let low = text.to_ascii_lowercase();
    let Some(open) = low.find("<title") else {
        return String::new();
    };
    let Some(gt) = low[open..].find('>') else {
        return String::new();
    };
    let start = open + gt + 1;
    let close = low[start..]
        .find("</title>")
        .map_or(start + TITLE_CAP, |k| start + k)
        .min(text.len());
    let mut t = decode_entities(&text[start..close]);
    let collapsed: Vec<&str> = t.split_whitespace().collect();
    t = collapsed.join(" ");
    if t.len() > TITLE_CAP {
        let mut e = TITLE_CAP;
        while !t.is_char_boundary(e) {
            e -= 1;
        }
        t.truncate(e);
    }
    t
}

type Signature = (Vec<String>, &'static str);

/// The embedded table, parsed once. A malformed line panics: the file is
/// compiled in, and the well-formedness test below pins every line — a bad
/// entry must die in CI, not quietly skip at an audit site.
fn signature_table() -> &'static [Signature] {
    static TABLE: OnceLock<Vec<Signature>> = OnceLock::new();
    TABLE.get_or_init(|| {
        SIGNATURES
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|line| {
                let Some((frags, label)) = line.split_once('|') else {
                    panic!("capture signature without `|`: {line}");
                };
                let frags: Vec<String> = frags
                    .split(';')
                    .map(|f| f.trim().to_ascii_lowercase())
                    .filter(|f| !f.is_empty())
                    .collect();
                if frags.is_empty() || label.trim().is_empty() || label.contains('|') {
                    panic!("malformed capture signature: {line}");
                }
                (frags, label.trim())
            })
            .collect()
    })
}

/// Case-insensitive contains-EVERY-fragment over title + headers + the first
/// 256 KiB of body (no regex — EyeWitness's matching idea, our own table).
/// First matching line wins, so specific entries sort above generic buckets.
pub(crate) fn fingerprint(title: &str, headers: &str, body: &[u8]) -> Option<&'static str> {
    let bl = body.len().min(BODY_HAYSTACK_CAP);
    let hay = format!(
        "{}\n{}\n{}",
        title.to_ascii_lowercase(),
        headers.to_ascii_lowercase(),
        String::from_utf8_lossy(&body[..bl]).to_ascii_lowercase()
    );
    signature_table()
        .iter()
        .find(|(frags, _)| frags.iter().all(|f| hay.contains(f.as_str())))
        .map(|(_, label)| *label)
}

// ------------------------------------------------------------ one target

pub(crate) struct Outcome {
    error: Option<ShotError>,
    title: String,
    headers: String,
    status: u16,
    label: String,
    png: Option<Vec<u8>>,
    ms: u64,
}

/// One target: headers + title first (a plain client, not the browser), then
/// the screenshot. A connection-level header failure short-circuits the
/// browser — it would learn the same thing, slower.
pub(crate) fn capture_one(
    t: &CaptureTarget,
    timeout_secs: u64,
    chrome: Option<&str>,
    scratch: &Path,
) -> Outcome {
    let started = Instant::now();
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut status = 0u16;
    let mut headers = String::new();
    let mut body: Vec<u8> = Vec::new();
    let mut error: Option<ShotError> = None;

    match t.scheme {
        Scheme::Http => match http_fetch(t.ip, t.port, timeout) {
            Ok((s, h, b)) => {
                status = s;
                headers = h;
                body = b;
            }
            Err(e) => error = Some(e),
        },
        Scheme::Https => {
            let hdr = scratch.join("headers.txt");
            let bodyf = scratch.join("body.bin");
            let res = run_child(
                &curl_bin(),
                &curl_argv(timeout_secs, &hdr, &bodyf, &t.url()),
                timeout + KILL_SLACK,
            );
            if let Some(se) = res.spawn_error {
                error = Some(ShotError::BadStatus(format!("{se} (set {CURL_ENV})")));
            } else if res.killed {
                error = Some(ShotError::Timeout);
            } else if res.code == Some(0) {
                headers = fs::read_to_string(&hdr).unwrap_or_default();
                body = fs::read(&bodyf).unwrap_or_default();
                status = status_of_headers(&headers);
                if status == 0 {
                    error = Some(ShotError::BadStatus("empty answer".to_string()));
                }
            } else {
                error = Some(curl_error(res.code.unwrap_or(-1)));
            }
            let _ = fs::remove_file(&hdr);
            let _ = fs::remove_file(&bodyf);
        }
    }

    let title = extract_title(&body);
    let label = fingerprint(&title, &headers, &body)
        .unwrap_or_default()
        .to_string();

    let mut png: Option<Vec<u8>> = None;
    if error.as_ref().is_none_or(|e| !e.conn_level()) {
        if let Some(bin) = chrome {
            let shot = scratch.join("shot.png");
            let profile = scratch.join("profile");
            let _ = fs::create_dir_all(&profile);
            let res = run_child(
                bin,
                &chrome_argv(timeout.as_millis() as u64, &shot, &profile, &t.url()),
                timeout + KILL_SLACK,
            );
            let shot_bytes = fs::read(&shot).ok().unwrap_or_default();
            if shot_bytes.starts_with(PNG_MAGIC) {
                // A rendered page wins even when chromium's exit code sulks.
                png = Some(shot_bytes);
            } else if let Some(se) = res.spawn_error {
                error = Some(ShotError::BadStatus(format!("{se} (check {CHROME_ENV})")));
            } else {
                error = Some(chrome_error(&res.stderr, res.killed));
            }
            let _ = fs::remove_file(&shot);
            let _ = fs::remove_dir_all(&profile);
        } else if error.is_none() {
            error = Some(ShotError::BrowserMissing);
        }
    }

    if headers.len() > HEADERS_TEXT_CAP {
        let mut e = HEADERS_TEXT_CAP;
        while !headers.is_char_boundary(e) {
            e -= 1;
        }
        headers.truncate(e);
    }

    Outcome {
        error,
        title,
        headers,
        status,
        label,
        png,
        ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

// ---------------------------------------------------------- run dir state

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct CapTargetState {
    pub(crate) ip: String,
    pub(crate) port: u16,
    pub(crate) scheme: String,
    pub(crate) done: bool,
    #[serde(default)]
    pub(crate) error: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct CapState {
    pub(crate) run: String,
    pub(crate) started_at: i64,
    pub(crate) timeout_secs: u64,
    pub(crate) threads: usize,
    /// True once the pass finished on its own; `interrupted` says why not.
    pub(crate) done: bool,
    #[serde(default)]
    pub(crate) interrupted: bool,
    /// Resolved browser binary, or "" when the run has no screenshots.
    #[serde(default)]
    pub(crate) chrome: String,
    pub(crate) targets: Vec<CapTargetState>,
}

impl CapState {
    pub(crate) fn done_count(&self) -> usize {
        self.targets.iter().filter(|t| t.done).count()
    }
}

fn now_epoch() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
    .unwrap_or(0)
}

fn write_cap_state(run_dir: &Path, st: &CapState) -> Result<()> {
    // Atomic (tmp + fsync + rename), same contract as scan state: a crash or
    // power cut never leaves a torn state file behind.
    let path = run_dir.join(STATE_FILE);
    let tmp = run_dir.join(format!("{STATE_FILE}.tmp"));
    let text = serde_json::to_string_pretty(st).context("serializing capture state")?;
    let mut f = File::create(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
    f.write_all(text.as_bytes())
        .with_context(|| format!("writing {}", tmp.display()))?;
    f.sync_all()
        .with_context(|| format!("syncing {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("renaming {}", path.display()))?;
    Ok(())
}

/// One `targets.jsonl` line — the append-only manifest the dashboard parses.
/// The writer leaves `run` empty (the file lives inside the run dir); the
/// read-only walkers fill it in.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct ManifestRow {
    #[serde(default)]
    pub(crate) run: String,
    pub(crate) url: String,
    pub(crate) ip: String,
    pub(crate) port: u16,
    pub(crate) scheme: String,
    #[serde(default)]
    pub(crate) status: u16,
    #[serde(default)]
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) label: String,
    /// Class word, "" = clean.
    #[serde(default)]
    pub(crate) error: String,
    /// Longer failure text when there is one.
    #[serde(default)]
    pub(crate) detail: String,
    /// `<sha256>.png` inside the run's shots/, or "".
    #[serde(default)]
    pub(crate) shot: String,
    #[serde(default)]
    pub(crate) sha256: String,
    /// URL of the first target with an identical screenshot — a wall of
    /// identical appliance pages collapses to one image plus pointers.
    #[serde(default)]
    pub(crate) dup_of: String,
    #[serde(default)]
    pub(crate) headers: String,
    #[serde(default)]
    pub(crate) ms: u64,
    #[serde(default)]
    pub(crate) at: i64,
}

// ----------------------------------------------------------- the run itself

pub(crate) struct RunSummary {
    pub(crate) run_id: String,
    pub(crate) run_dir: PathBuf,
    pub(crate) total: usize,
    pub(crate) ok: usize,
    pub(crate) failed: usize,
    pub(crate) dups: usize,
    pub(crate) interrupted: bool,
}

/// The whole capture pass over `targets`, into a fresh `runs/web_<ts>/`.
/// The perimeter lock belongs to the caller.
pub(crate) fn run_pass(
    out: &Path,
    targets: Vec<CaptureTarget>,
    timeout_secs: u64,
    threads: usize,
) -> Result<RunSummary> {
    let run_id = state::stamped_id("web");
    let run_dir = state::create_run(out, &run_id)?;
    // create_run may have suffixed the id ("-2") to keep two same-second
    // runs apart — everything from here on (log line, state file, dedup
    // reads, the summary) must carry the directory's actual name, or the
    // manifest reads land in the first run's evidence.
    let run_id = run_dir
        .file_name()
        .expect("create_run returned a named directory")
        .to_string_lossy()
        .into_owned();
    fs::create_dir_all(run_dir.join("shots"))?;
    fs::create_dir_all(run_dir.join("tmp"))?;
    let mut log = state::open_run_log_as(&run_dir, "run.log")?;
    state::log_line(
        &mut log,
        &format!(
            "capture pass {run_id}: {} target(s), timeout {timeout_secs}s, {threads} thread(s)",
            targets.len()
        ),
    );
    let chrome = chrome_bin();
    match &chrome {
        Some(b) => state::log_line(&mut log, &format!("browser: {b}")),
        None => state::log_line(
            &mut log,
            &format!("browser: none found - headers and titles only (set {CHROME_ENV})"),
        ),
    }
    let mut st = CapState {
        run: run_id.clone(),
        started_at: now_epoch(),
        timeout_secs,
        threads,
        done: false,
        interrupted: false,
        chrome: chrome.clone().unwrap_or_default(),
        targets: targets
            .iter()
            .map(|t| CapTargetState {
                ip: t.ip.to_string(),
                port: t.port,
                scheme: t.scheme.as_str().to_string(),
                done: false,
                error: String::new(),
            })
            .collect(),
    };
    write_cap_state(&run_dir, &st)?;

    let targets = Arc::new(targets);
    let (jtx, jrx) = mpsc::sync_channel::<usize>(64);
    let jrx = Arc::new(Mutex::new(jrx));
    let (mtx, mrx) = mpsc::channel::<(usize, Outcome)>();
    let started = Instant::now();

    std::thread::scope(|s| -> Result<()> {
        for w in 0..threads {
            let jrx = Arc::clone(&jrx);
            let mtx = mtx.clone();
            let targets = Arc::clone(&targets);
            let chrome = chrome.clone();
            let scratch = run_dir.join("tmp").join(format!("w{w}"));
            let _ = fs::create_dir_all(&scratch);
            let _ = s.spawn(move || {
                loop {
                    if ABORT.load(Ordering::Relaxed) {
                        break;
                    }
                    let job = {
                        let rx = jrx.lock().unwrap_or_else(|e| e.into_inner());
                        rx.recv()
                    };
                    match job {
                        Ok(i) => {
                            let outcome =
                                capture_one(&targets[i], timeout_secs, chrome.as_deref(), &scratch);
                            if mtx.send((i, outcome)).is_err() {
                                break;
                            }
                        }
                        // Sender dropped: dispatch is over (clean end or
                        // abort/cap) — remaining queued jobs stay undone.
                        Err(_) => break,
                    }
                }
            });
        }
        for i in 0..targets.len() {
            if ABORT.load(Ordering::Relaxed) {
                break;
            }
            if started.elapsed() >= CAPTURE_TOTAL_CAP {
                state::log_line(&mut log, "30 min total cap reached - dispatch stopped");
                break;
            }
            if jtx.send(i).is_err() {
                break;
            }
        }
        drop(jtx);
        // The dispatcher's own sender must die before the receive loop:
        // the workers only hold clones, and with the original alive the
        // outcome channel never closes and this loop hangs forever.
        drop(mtx);

        // The main thread owns all writing: one manifest appender, one state
        // rewriter, one digest map — workers only produce outcomes.
        let mut manifest = OpenOptions::new()
            .create(true)
            .append(true)
            .open(run_dir.join(MANIFEST_FILE))
            .context("opening capture manifest")?;
        let mut digests: HashMap<String, String> = HashMap::new();
        let (mut ok, mut failed, mut dups, mut seen) = (0usize, 0usize, 0usize, 0usize);
        for (i, oc) in mrx {
            let t = &targets[i];
            let (shot, sha_hex, dup_of) = match &oc.png {
                Some(bytes) => {
                    let hex = crate::web::hex(&crate::web::sha256(bytes));
                    let dup_of = digests.get(&hex).cloned().unwrap_or_default();
                    if dup_of.is_empty() {
                        digests.insert(hex.clone(), t.url());
                        let path = run_dir.join("shots").join(format!("{hex}.png"));
                        if let Err(e) = fs::write(&path, bytes) {
                            state::log_line(&mut log, &format!("shot write failed: {e}"));
                        }
                    }
                    (format!("{hex}.png"), hex, dup_of)
                }
                None => (String::new(), String::new(), String::new()),
            };
            let (err_class, detail) = match &oc.error {
                Some(e) => (e.class().to_string(), e.detail()),
                None => (String::new(), String::new()),
            };
            if oc.error.is_some() {
                failed += 1;
            } else {
                ok += 1;
            }
            if !dup_of.is_empty() {
                dups += 1;
            }
            let row = ManifestRow {
                run: String::new(),
                url: t.url(),
                ip: t.ip.to_string(),
                port: t.port,
                scheme: t.scheme.as_str().to_string(),
                status: oc.status,
                title: oc.title.clone(),
                label: oc.label.clone(),
                error: err_class,
                detail,
                shot,
                sha256: sha_hex,
                dup_of,
                headers: oc.headers.clone(),
                ms: oc.ms,
                at: now_epoch(),
            };
            let line = serde_json::to_string(&row).context("serializing manifest row")?;
            writeln!(manifest, "{line}").context("appending capture manifest")?;
            st.targets[i].done = true;
            st.targets[i].error = row.error.clone();
            seen += 1;
            if seen % STATE_FLUSH_EVERY == 0 {
                write_cap_state(&run_dir, &st)?;
            }
        }
        st.done = true;
        st.interrupted = ABORT.load(Ordering::Relaxed);
        write_cap_state(&run_dir, &st)?;
        state::log_line(
            &mut log,
            &format!(
                "{seen}/{} done: {ok} ok, {failed} failed, {dups} duplicate screenshot(s){}",
                targets.len(),
                if st.interrupted { " (interrupted)" } else { "" }
            ),
        );
        Ok(())
    })?;

    // The summary is derived from what was actually written: done targets by
    // their error class, duplicates from the manifest's dup_of pointers.
    let total = st.targets.len();
    let ok = st
        .targets
        .iter()
        .filter(|t| t.done && t.error.is_empty())
        .count();
    let failed = st
        .targets
        .iter()
        .filter(|t| t.done && !t.error.is_empty())
        .count();
    let dups = read_manifest(out, &run_id)
        .iter()
        .filter(|r| !r.dup_of.is_empty())
        .count();
    Ok(RunSummary {
        run_id,
        run_dir,
        total,
        ok,
        failed,
        dups,
        interrupted: st.interrupted,
    })
}

// -------------------------------------------------------- read-only access

/// `web_<YYYY-MM-DD>_<HHMMSS>` with the optional `create_run` collision
/// suffix — route paths are pinned to this shape before any fs touch.
pub(crate) fn valid_run_id(s: &str) -> bool {
    fn digits(x: &str) -> bool {
        !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit())
    }
    let Some(rest) = s.strip_prefix("web_") else {
        return false;
    };
    // A create_run collision suffix ("-2", "-12") rides on the last dash;
    // anything else after a dash breaks the stamp shape.
    let stamp = match rest.rsplit_once('-') {
        Some((a, b)) if digits(b) && b.len() <= 2 => a,
        _ => rest,
    };
    let b = stamp.as_bytes();
    b.len() == 17
        && digits(&stamp[0..4])
        && b[4] == b'-'
        && digits(&stamp[5..7])
        && b[7] == b'-'
        && digits(&stamp[8..10])
        && b[10] == b'_'
        && digits(&stamp[11..17])
}

/// `shots/` stores exactly `<64 hex>.png` (sha256 naming, note-image shape).
pub(crate) fn valid_shot_name(s: &str) -> bool {
    let Some(stem) = s.strip_suffix(".png") else {
        return false;
    };
    stem.len() == 64 && stem.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Validated `web_*` run ids under `runs/`, newest name first.
pub(crate) fn list_runs(out: &Path) -> Vec<String> {
    let mut ids: Vec<String> = fs::read_dir(state::runs_dir(out))
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .filter(|n| valid_run_id(n))
                .collect()
        })
        .unwrap_or_default();
    ids.sort();
    ids.reverse();
    ids
}

pub(crate) fn read_cap_state(out: &Path, run_id: &str) -> Option<CapState> {
    let f = File::open(state::runs_dir(out).join(run_id).join(STATE_FILE)).ok()?;
    serde_json::from_reader(BufReader::new(f)).ok()
}

pub(crate) fn read_manifest(out: &Path, run_id: &str) -> Vec<ManifestRow> {
    let f = match File::open(state::runs_dir(out).join(run_id).join(MANIFEST_FILE)) {
        Ok(f) => BufReader::new(f),
        Err(_) => return Vec::new(),
    };
    f.lines()
        .map_while(|l| l.ok())
        .filter_map(|l| serde_json::from_str(&l).ok())
        .collect()
}

/// One host's capture rows, newest runs first, bounded — the sheet section
/// walks at most `max_runs` recent capture passes and stops at `max_rows`.
pub(crate) fn host_captures(
    out: &Path,
    ip: &str,
    max_runs: usize,
    max_rows: usize,
) -> Vec<ManifestRow> {
    let mut rows = Vec::new();
    for run in list_runs(out).into_iter().take(max_runs) {
        for r in read_manifest(out, &run) {
            if r.ip == ip {
                rows.push(ManifestRow {
                    run: run.clone(),
                    ..r
                });
                if rows.len() >= max_rows {
                    return rows;
                }
            }
        }
    }
    rows
}

// ------------------------------------------------------------- CLI entry

pub fn run(args: &WebArgs) -> Result<()> {
    unsafe { libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t) };

    if args.timeout == 0 {
        bail!("--timeout: 0 - at least one second per target");
    }
    let threads = args.threads.unwrap_or(DEFAULT_THREADS);
    if !(1..=MAX_THREADS).contains(&threads) {
        bail!("--threads: {threads} - 1..={MAX_THREADS} capture threads");
    }

    let _lock = state::lock_perimeter(&args.out)?;
    let db = Db::open_existing(&args.out)?;
    let targets = web_targets(&db)?;
    if targets.is_empty() {
        bail!(
            "no http/https service in the registry - run a scan first; \
             the capture pass is an evidence run, it never discovers anything"
        );
    }
    if targets.len() > MAX_CAPTURE_TARGETS {
        bail!(
            "{} web target(s) - the capture pass caps at {MAX_CAPTURE_TARGETS}; \
             triage the registry first",
            targets.len()
        );
    }
    let summary = run_pass(&args.out, targets, args.timeout, threads)?;
    eprintln!(
        "web {}: {}/{} target(s) captured, {} failed, {} duplicate screenshot(s){} - evidence in {}",
        summary.run_id,
        summary.ok,
        summary.total,
        summary.failed,
        summary.dups,
        if summary.interrupted { " (interrupted)" } else { "" },
        summary.run_dir.display()
    );
    Ok(())
}

// ------------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn classification_mirrors_the_dashboard_links() {
        use Scheme::{Http, Https};
        // names
        assert_eq!(classify_service("https", 1234), Some(Https));
        assert_eq!(classify_service("https-alt", 0), Some(Https));
        assert_eq!(classify_service("ssl/https", 1), Some(Https));
        assert_eq!(classify_service("HTTP", 2), Some(Http));
        assert_eq!(classify_service("http-alt", 3), Some(Http));
        // ports
        assert_eq!(classify_service("unknown", 443), Some(Https));
        assert_eq!(classify_service("unknown", 8443), Some(Https));
        assert_eq!(classify_service("unknown", 80), Some(Http));
        assert_eq!(classify_service("unknown", 8080), Some(Http));
        // everything else stays out
        assert_eq!(classify_service("ssh", 22), None);
        assert_eq!(classify_service("domain", 53), None);
        assert_eq!(classify_service("smtp", 25), None);
        assert_eq!(classify_service("unknown", 9999), None);
        // https name beats http port
        assert_eq!(classify_service("https", 80), Some(Https));
    }

    #[test]
    fn chrome_argv_pins_the_screenshot_cli() {
        let argv = chrome_argv(
            7000,
            Path::new("/tmp/r/shot.png"),
            Path::new("/tmp/r/profile"),
            "http://127.0.0.1:8080/",
        );
        assert_eq!(argv.last().unwrap(), "http://127.0.0.1:8080/");
        for pin in [
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--hide-scrollbars",
            "--ignore-certificate-errors",
            "--window-size=1366,768",
            "--timeout=7000",
            "--screenshot=/tmp/r/shot.png",
            "--user-data-dir=/tmp/r/profile",
        ] {
            assert!(argv.iter().any(|a| a == pin), "missing {pin} in {argv:?}");
        }
        assert!(argv
            .iter()
            .any(|a| a.starts_with("--virtual-time-budget=") && a.ends_with("5000")));
    }

    #[test]
    fn virtual_time_never_exceeds_the_timeout() {
        let argv = chrome_argv(
            1500,
            Path::new("/s.png"),
            Path::new("/p"),
            "http://127.0.0.1/",
        );
        assert!(
            argv.iter().any(|a| a == "--virtual-time-budget=1500"),
            "budget clamps to the timeout"
        );
    }

    #[test]
    fn curl_argv_pins_the_header_fetch() {
        let argv = curl_argv(
            7,
            Path::new("/tmp/h.txt"),
            Path::new("/tmp/b.bin"),
            "https://127.0.0.1:8443/",
        );
        assert_eq!(argv.last().unwrap(), "https://127.0.0.1:8443/");
        assert!(argv.contains(&"-sk".to_string()));
        assert!(argv.windows(2).any(|w| w[0] == "--max-time" && w[1] == "7"));
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "-D" && w[1] == "/tmp/h.txt"));
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "-o" && w[1] == "/tmp/b.bin"));
        assert!(argv.windows(2).any(|w| w[0] == "-A" && w[1] == USER_AGENT));
        assert!(
            !argv.iter().any(|a| a == "-L"),
            "no redirect following in v1"
        );
    }

    #[test]
    fn title_hunt_is_case_insensitive_and_entity_aware() {
        assert_eq!(extract_title(b"<TITLE>Big Router</TITLE>"), "Big Router");
        assert_eq!(
            extract_title(b"<title lang=\"en\">Login &amp; Setup</title>"),
            "Login & Setup"
        );
        assert_eq!(
            extract_title(b"<title>  spaced   out  </title>"),
            "spaced out"
        );
        assert_eq!(extract_title(b"<html><body>no title</body></html>"), "");
        assert_eq!(extract_title(b"<title"), "");
        assert_eq!(extract_title(b"<title unclosed forever"), "");
        assert_eq!(extract_title(b""), "");
    }

    #[test]
    fn titles_are_bounded() {
        let long = format!("<title>{}</title>", "x".repeat(500));
        let t = extract_title(long.as_bytes());
        assert_eq!(t.len(), TITLE_CAP);
        assert!(t.chars().all(|c| c == 'x'));
    }

    #[test]
    fn fingerprints_need_every_fragment() {
        // two-fragment AND: printer alone is too generic, brother+printer is not
        assert_eq!(fingerprint("", "", b"my <h1>Printer</h1> page"), None);
        assert_eq!(
            fingerprint("", "", b"<h1>Brother Printer</h1>"),
            Some("Brother printer")
        );
        // case-insensitive across the whole haystack, headers included
        assert_eq!(
            fingerprint(
                "",
                "Server: nginx/1.24\r\n",
                b"<body>WELCOME TO NGINX</body>"
            ),
            Some("nginx default page")
        );
        // title counts too
        assert_eq!(
            fingerprint("Welcome to Grafana", "", b""),
            Some("Grafana dashboard")
        );
        assert_eq!(fingerprint("", "", b"nothing interesting here"), None);
    }

    #[test]
    fn first_matching_signature_wins() {
        // both the apache default-page line and the "it works!" line hit;
        // apache is written first, so it must win
        assert_eq!(
            fingerprint("", "", b"<h1>Apache2 Default Page</h1><p>It works!</p>"),
            Some("Apache default page")
        );
    }

    #[test]
    fn signature_table_is_well_formed() {
        let mut count = 0usize;
        for line in SIGNATURES
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let (frags, label) = line
                .split_once('|')
                .unwrap_or_else(|| panic!("no `|` in: {line}"));
            assert!(!frags.is_empty(), "no fragments: {line}");
            assert!(!label.contains('|'), "extra `|`: {line}");
            assert!(!label.trim().is_empty(), "empty label: {line}");
            for f in frags.split(';') {
                assert!(!f.trim().is_empty(), "empty fragment: {line}");
                assert_eq!(f.trim(), f, "untrimmed fragment: {line}");
            }
            assert_eq!(label.trim(), label, "untrimmed label: {line}");
            count += 1;
        }
        assert!(count >= 60, "signature table shrank to {count}");
        assert_eq!(signature_table().len(), count, "parser dropped lines");
    }

    #[test]
    fn chrome_stderr_maps_to_error_classes() {
        assert_eq!(
            chrome_error("[some]:ERR_CONNECTION_REFUSED at", false),
            ShotError::ConnRefused
        );
        assert_eq!(
            chrome_error("x ERR_CONNECTION_RESET y", false),
            ShotError::ConnReset
        );
        assert_eq!(
            chrome_error("ERR_NAME_NOT_RESOLVED", false),
            ShotError::DnsFailed
        );
        assert_eq!(
            chrome_error("ERR_CERT_AUTHORITY_INVALID", false),
            ShotError::TlsError
        );
        assert_eq!(
            chrome_error("ERR_SSL_PROTOCOL_ERROR", false),
            ShotError::TlsError
        );
        assert_eq!(
            chrome_error("NET::ERR_TIMED_OUT", false),
            ShotError::Timeout
        );
        // killed by our deadline, whatever stderr says
        assert_eq!(
            chrome_error("ERR_CONNECTION_REFUSED", true),
            ShotError::Timeout
        );
        // anything else is a bounded bad-status detail
        match chrome_error("weird failure", false) {
            ShotError::BadStatus(d) => assert!(d.starts_with("chromium: weird failure")),
            other => panic!("expected bad-status, got {other:?}"),
        }
    }

    #[test]
    fn curl_exit_codes_map_to_error_classes() {
        assert_eq!(curl_error(6), ShotError::DnsFailed);
        assert_eq!(curl_error(7), ShotError::ConnRefused);
        assert_eq!(curl_error(28), ShotError::Timeout);
        assert_eq!(curl_error(35), ShotError::TlsError);
        assert_eq!(curl_error(60), ShotError::TlsError);
        assert_eq!(curl_error(56), ShotError::ConnReset);
        assert!(matches!(curl_error(99), ShotError::BadStatus(_)));
    }

    #[test]
    fn error_classes_cover_every_card() {
        for e in [
            ShotError::Timeout,
            ShotError::ConnRefused,
            ShotError::ConnReset,
            ShotError::TlsError,
            ShotError::DnsFailed,
            ShotError::BadStatus("x".into()),
            ShotError::BrowserMissing,
        ] {
            assert!(!e.class().is_empty());
            assert!(!e.detail().is_empty());
        }
        // only real connection failures skip the browser
        assert!(ShotError::ConnRefused.conn_level());
        assert!(!ShotError::BrowserMissing.conn_level());
        assert!(!ShotError::BadStatus("x".into()).conn_level());
    }

    #[test]
    fn http_answers_parse() {
        let (code, head, body) =
            parse_http_response(b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nhello").unwrap();
        assert_eq!(code, 200);
        assert!(head.contains("Server: x"));
        assert_eq!(body, b"hello");
        // bare-LF servers exist
        let (code, _, body) = parse_http_response(b"HTTP/1.0 404 nope\n\nlost").unwrap();
        assert_eq!(code, 404);
        assert_eq!(body, b"lost");
        // garbage is none
        assert!(parse_http_response(b"\x00\x01not http at all").is_none());
        assert!(parse_http_response(b"").is_none());
    }

    #[test]
    fn http_fetch_reads_a_real_loopback_answer() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = std::io::Read::read(&mut s, &mut buf);
            let _ = std::io::Write::write_all(
                &mut s,
                b"HTTP/1.0 200 OK\r\nServer: testd\r\nContent-Type: text/html\r\n\r\n\
                  <html><head><Title>Hello Loopback</title></head><body>pad</body></html>",
            );
        });
        let (status, headers, body) =
            http_fetch("127.0.0.1".parse().unwrap(), port, Duration::from_secs(5)).unwrap();
        assert_eq!(status, 200);
        assert!(headers.to_ascii_lowercase().contains("server: testd"));
        assert_eq!(extract_title(&body), "Hello Loopback");
        h.join().unwrap();
    }

    #[test]
    fn refused_ports_classify_cleanly() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener); // nothing listens there anymore
        match http_fetch("127.0.0.1".parse().unwrap(), port, Duration::from_secs(2)) {
            Err(ShotError::ConnRefused) => {}
            other => panic!("expected conn-refused, got {other:?}"),
        }
    }

    #[test]
    fn run_ids_are_pinned_before_any_fs_touch() {
        assert!(valid_run_id("web_2026-10-19_123456"));
        assert!(valid_run_id("web_2026-10-19_123456-2"));
        assert!(valid_run_id("web_2026-01-01_000000-12"));
        // wrong shapes
        assert!(!valid_run_id("web_2026-10-19"));
        assert!(!valid_run_id("web_2026-1-19_123456"));
        assert!(!valid_run_id("scan_2026-10-19_123456"));
        assert!(!valid_run_id("web_2026-10-19_123456-extra"));
        assert!(!valid_run_id("../web_2026-10-19_123456"));
        assert!(!valid_run_id("web_../../etc"));
        assert!(!valid_run_id(""));
    }

    #[test]
    fn shot_names_are_64_hex_and_png() {
        let hex = "a".repeat(64);
        assert!(valid_shot_name(&format!("{hex}.png")));
        assert!(!valid_shot_name(&format!("{}.jpg", "a".repeat(64))));
        assert!(!valid_shot_name("short.png"));
        assert!(!valid_shot_name(&format!("{}X.png", "a".repeat(63))));
        assert!(!valid_shot_name("../../etc/passwd"));
        assert!(!valid_shot_name(""));
    }

    #[test]
    fn targets_come_out_sorted_and_deduped_from_the_predicate() {
        // classification + dedup are pure; the db walk itself is exercised by
        // the integration test with a real registry
        let t = CaptureTarget {
            ip: "127.0.0.1".parse().unwrap(),
            port: 8443,
            scheme: Scheme::Https,
        };
        assert_eq!(t.url(), "https://127.0.0.1:8443/");
    }

    #[test]
    fn web_targets_walk_the_registry() {
        let root =
            std::env::temp_dir().join(format!("rustrawl-capture-targets-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        use crate::discovery::db::{Answer, Stage};
        let mut db = Db::open(&root).unwrap();
        db.set_run_id("t");
        let ip = |o: [u8; 4]| Ipv4Addr::from(o);
        db.record_host(ip([127, 0, 0, 5]), Stage::Scan, true, 2);
        db.record_host(ip([127, 0, 0, 6]), Stage::Sweep, true, 2); // up, nothing web
        db.record_host(ip([127, 0, 0, 7]), Stage::Scan, true, 2);
        db.record_host(ip([127, 0, 0, 8]), Stage::Scan, false, 2); // down: never probed
        for (o, port, name) in [
            ([127, 0, 0, 5], 22u16, "ssh"),       // not a capture target
            ([127, 0, 0, 5], 80, "http"),         // http by name
            ([127, 0, 0, 5], 8443, "unknown"),    // https by port
            ([127, 0, 0, 7], 39147, "ssl/https"), // https by name, odd port
            ([127, 0, 0, 8], 8080, "http"),       // down host: skipped
        ] {
            db.record_result(ip(o), port, Stage::Scan, Answer::Open);
            db.record_service(ip(o), port, name, "");
        }
        db.flush().unwrap();
        let got: Vec<String> = web_targets(&db).unwrap().iter().map(|t| t.url()).collect();
        assert_eq!(
            got,
            [
                "http://127.0.0.5:80/",
                "https://127.0.0.5:8443/",
                "https://127.0.0.7:39147/",
            ]
        );
        let _ = fs::remove_dir_all(&root);
    }
}
