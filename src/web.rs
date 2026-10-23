//! Browser dashboard over one perimeter's registry:
//! `rustrawl db --out <perim> --web` serves a small JSON API and a
//! self-contained page (vanilla JS — sorting, filtering and the per-host
//! pages live client-side, so the server stays a few hundred lines).
//!
//! Reads open the registry read-only per request (WAL lets the dashboard
//! read while a scan writes). The writes are the operator's marks — triage
//! (`POST /api/triage`) and the manual asset type (`POST /api/type`) — the
//! same rows the CLI sets, plus one deliberate escalation: `POST /api/scan`
//! runs nmap once over targets the registry picks — one already-up host, an
//! explicit ip list, or every up host in a range — with operator-typed
//! arguments inside rustrawl's frame (`check_nmap_args` keeps targets and
//! output files pinned — the same rules as the CLI), and `POST /api/scan/stop`
//! is the brake on it: flip the shared abort flag. Scan verdicts stay
//! untouchable otherwise; the rescan writes through the same ingest core as
//! a queue chunk and lands its evidence in its own `manual_<date>_<time>`
//! run directory. The write routes demand a custom `X-Rustrawl: 1` header:
//! a cross-origin "simple request" cannot set one, and no CORS headers are
//! ever emitted, so a hostile page in the auditor's browser cannot write to
//! the loopback dashboard. The bind address defaults to 127.0.0.1 —
//! `--bind` can widen it, the operator owns that decision. The only paths
//! served are the embedded page and the fixed `/api/*` set — the reads
//! include the export downloads (`/api/export/*`), which render the
//! registry into memory behind compile-time-constant filenames — so no
//! request input ever reaches the filesystem (nmap's argv is the one
//! exception, and it is a validated argv, never a shell).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};

use crate::discovery::db::Db;

/// Request-body cap for the JSON writes — the note alone is capped at 64
/// KiB, so anything near this is abuse, not the page.
const BODY_CAP: u64 = 256 * 1024;

/// The screenshot upload carries raw image bytes and gets its own cap: a
/// pasted capture is a few megabytes at most, anything bigger is not a
/// screenshot.
const IMAGE_CAP: u64 = 5 * 1024 * 1024;

/// The filtered exports POST what the page displays — a full-screen
/// /16-scale table is thousands of JSON rows, well past the write cap but
/// still an honest export. Past this the display is too wide to export and
/// the filter should narrow first.
const EXPORT_CAP: u64 = 4 * 1024 * 1024;

/// The embedded dashboard page (vanilla JS, the project's white identity:
/// navy and orange on white, the logo served alongside).
const PAGE: &str = include_str!("web.html");

/// The project logo, served at /logo.png for the banner emblem and the
/// favicon (a hand-downscaled copy of the root's master PNG
/// `rustrawl_logo.png`).
const LOGO: &[u8] = include_bytes!("logo.png");

/// True while a manual rescan's watch loop is waiting on nmap - the stop
/// endpoint answers 409 without it, so the button never fires blind.
static SCANNING: AtomicBool = AtomicBool::new(false);

pub fn serve(out: &Path, bind: IpAddr, port: u16) -> Result<()> {
    // Fail on a typo'd perimeter before binding, like every other db view.
    let probe = Db::open_read_only(out)?;
    drop(probe);
    let listener =
        TcpListener::bind((bind, port)).with_context(|| format!("binding {bind}:{port}"))?;
    let addr = listener.local_addr()?;
    eprintln!(
        "# dashboard: http://{addr}/ - writes: triage, types, bookmark, pwned, tags, notes, screenshots, manual rescans (one host, a list or a range); exports: /api/export/*; ^C stops the server"
    );
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let out = out.to_path_buf();
                std::thread::spawn(move || handle_conn(s, &out));
            }
            Err(e) => eprintln!("# dashboard: accept failed: {e}"),
        }
    }
    Ok(())
}

/// The body cap for one request: the screenshot upload carries raw image
/// bytes, the filtered exports carry the displayed rows, every other route
/// reads the JSON write cap. The request line is parsed before the body,
/// so the cap is known before a byte is read.
fn body_cap(method: &str, path: &str) -> u64 {
    if method == "POST" && path.starts_with("/api/note-image/") {
        IMAGE_CAP
    } else if method == "POST" && path.starts_with("/api/export/") {
        EXPORT_CAP
    } else {
        BODY_CAP
    }
}

fn handle_conn(stream: std::net::TcpStream, out: &Path) {
    // A stuck or slow-loris client must not pin a thread forever.
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut writer = stream;
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    // Drain the headers, capturing the ones this server acts on (names
    // case-insensitive, as HTTP requires). LF counts as a terminator too
    // (minimal clients), and the drain is capped so a header flood cannot
    // grow without bound.
    let mut headers = Headers::default();
    let mut line = String::new();
    for _ in 0..256 {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break, // client closed mid-request
            Ok(_) if line.trim_end().is_empty() => break,
            Ok(_) => headers.absorb(&line),
            Err(_) => return, // timed out or reset — nothing to answer
        }
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let path = target.split('?').next().unwrap_or("");
    let path = percent_decode(path);
    // A well-formed request-target starts with '/' — anything else is a
    // malformed request line, not a route. A declared body over the cap is
    // refused — but drained-and-discarded first (bounded) so the 413 goes
    // out on a clean close instead of behind a RST the client never sees.
    let resp = if !path.starts_with('/') {
        Response::bad_request()
    } else if headers.content_length.unwrap_or(0) > body_cap(method, &path) {
        let _ = std::io::copy(
            &mut reader
                .by_ref()
                .take(headers.content_length.unwrap_or(0).min(8 * 1024 * 1024)),
            &mut std::io::sink(),
        );
        Response::payload_too_large()
    } else {
        // Exactly Content-Length bytes — a client closing mid-body gets no
        // answer (same deal as a reset mid-headers).
        let mut body = Vec::new();
        let want = headers.content_length.unwrap_or(0);
        if want > 0
            && (reader.by_ref().take(want).read_to_end(&mut body).is_err()
                || body.len() as u64 != want)
        {
            return;
        }
        route_req(method, &path, &body, headers.x_rustrawl, out)
    };
    let _ = writer.write_all(&resp.into_http());
}

/// The request headers this server acts on, captured during the header
/// drain.
#[derive(Default)]
struct Headers {
    content_length: Option<u64>,
    /// The write guard: `X-Rustrawl: 1`. A cross-origin "simple request"
    /// cannot set a custom header and no CORS headers are ever emitted —
    /// a hostile page in the auditor's browser cannot write triage rows
    /// to the dashboard.
    x_rustrawl: bool,
}

impl Headers {
    fn absorb(&mut self, line: &str) {
        let (name, value) = match line.split_once(':') {
            Some((n, v)) => (n, v.trim()),
            None => return,
        };
        if name.eq_ignore_ascii_case("content-length") {
            self.content_length = value.parse().ok();
        } else if name.eq_ignore_ascii_case("x-rustrawl") {
            self.x_rustrawl = value == "1";
        }
    }
}

// --------------------------------------------------------------- responses

struct Response {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
    /// Set only on downloads: `into_http` turns it into a
    /// `Content-Disposition: attachment` header. Always a compile-time
    /// constant — nothing from a request ever lands in a filename.
    filename: Option<&'static str>,
}

impl Response {
    fn html(body: String) -> Self {
        Response {
            status: 200,
            reason: "OK",
            content_type: "text/html; charset=utf-8",
            body: body.into_bytes(),
            filename: None,
        }
    }

    fn json(v: &serde_json::Value) -> Self {
        Response {
            status: 200,
            reason: "OK",
            content_type: "application/json",
            body: serde_json::to_vec(v).unwrap_or_else(|_| b"{}".to_vec()),
            filename: None,
        }
    }

    /// Static binary assets: the embedded logo, byte for byte.
    fn png(body: &'static [u8]) -> Self {
        Response {
            status: 200,
            reason: "OK",
            content_type: "image/png",
            body: body.to_vec(),
            filename: None,
        }
    }

    fn text(status: u16, reason: &'static str, body: &str) -> Self {
        Response {
            status,
            reason,
            content_type: "text/plain; charset=utf-8",
            body: body.as_bytes().to_vec(),
            filename: None,
        }
    }

    /// A registry export as a download: the Content-Disposition header
    /// names the file so the browser saves it instead of rendering it.
    fn download(content_type: &'static str, filename: &'static str, body: Vec<u8>) -> Self {
        Response {
            status: 200,
            reason: "OK",
            content_type,
            body,
            filename: Some(filename),
        }
    }

    fn not_found() -> Self {
        Self::text(404, "Not Found", "not found\n")
    }

    fn bad_request() -> Self {
        Self::text(400, "Bad Request", "malformed request line\n")
    }

    fn forbidden() -> Self {
        Self::text(
            403,
            "Forbidden",
            "writes need the X-Rustrawl: 1 request header (a cross-origin page cannot set it)\n",
        )
    }

    /// Declared body over the cap: drain-and-discard (bounded), then 413.
    fn payload_too_large() -> Self {
        Self::text(
            413,
            "Payload Too Large",
            "the request body is over the cap (256 KiB for the JSON writes, 5 MiB for a screenshot)\n",
        )
    }

    fn method_not_allowed() -> Self {
        Self::text(405, "Method Not Allowed", "GET only\n")
    }

    fn server_error(e: anyhow::Error) -> Self {
        Self::text(500, "Internal Server Error", &format!("error: {e:#}\n"))
    }

    fn into_http(self) -> Vec<u8> {
        // Downloads carry the attachment header so the browser saves the
        // body under the fixed name instead of rendering it.
        let disposition = self
            .filename
            .map(|f| format!("Content-Disposition: attachment; filename=\"{f}\"\r\n"))
            .unwrap_or_default();
        let mut out = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
            self.status,
            self.reason,
            self.content_type,
            disposition,
            self.body.len()
        )
        .into_bytes();
        out.extend_from_slice(&self.body);
        out
    }
}

/// The GET-only shape the tests read; the socket path always comes
/// through `route_req`.
#[cfg(test)]
fn route(method: &str, path: &str, out: &Path) -> Response {
    route_req(method, path, &[], false, out)
}

fn route_req(method: &str, path: &str, body: &[u8], x_rustrawl: bool, out: &Path) -> Response {
    match (method, path) {
        ("GET", "/") => Response::html(PAGE.to_string()),
        ("GET", "/logo.png") => Response::png(LOGO),
        ("GET", "/api/hosts") => match hosts_json(out) {
            Ok(v) => Response::json(&v),
            Err(e) => Response::server_error(e),
        },
        ("GET", "/api/services") => match services_json(out) {
            Ok(v) => Response::json(&v),
            Err(e) => Response::server_error(e),
        },
        ("GET", "/api/status") => match status_json(out) {
            Ok(v) => Response::json(&v),
            Err(e) => Response::server_error(e),
        },
        ("GET", "/api/ranges") => match ranges_json(out, 24) {
            Ok(v) => Response::json(&v),
            Err(e) => Response::server_error(e),
        },
        // Re-bucketed triage view: the segment is a prefix, validated by
        // the same gate the CLI's flag uses — junk falls to 404, never a
        // filesystem path.
        ("GET", p) if p.starts_with("/api/ranges/") => {
            let raw = &p["/api/ranges/".len()..];
            match crate::ranges_prefix(Some(raw)) {
                Ok(prefix) => match ranges_json(out, prefix) {
                    Ok(v) => Response::json(&v),
                    Err(e) => Response::server_error(e),
                },
                Err(_) => Response::not_found(),
            }
        }
        ("GET", "/api/export/scan.xml") => {
            export_response("application/xml", "rustrawl-scan.xml", out, |w| {
                crate::render_export_scanxml(w, out)
            })
        }
        ("GET", "/api/export/services.csv") => {
            export_response("text/csv", "rustrawl-services.csv", out, |w| {
                crate::render_services_csv(w, out, &crate::SvcQuery::default())
            })
        }
        ("GET", "/api/export/services.txt") => export_response(
            "text/plain; charset=utf-8",
            "rustrawl-services.txt",
            out,
            |w| crate::render_services_txt(w, out, &crate::SvcQuery::default(), false),
        ),
        ("GET", "/api/export/services.xml") => {
            export_response("application/xml", "rustrawl-services.xml", out, |w| {
                crate::render_services_xml(w, out, &crate::SvcQuery::default())
            })
        }
        ("GET", "/api/export/hosts.txt") => export_response(
            "text/plain; charset=utf-8",
            "rustrawl-hosts.txt",
            out,
            |w| crate::render_hosts_txt(w, out, false),
        ),
        ("GET", "/api/scan-defaults") => Response::json(&scan_defaults(out)),
        // The live tail of the newest manual rescan's captured output - what
        // the rescan tab polls while a run is in flight.
        ("GET", "/api/scan/output") => Response::json(&scan_output_json(out)),
        // The filtered exports POST what the page displays. Reads like the
        // GETs above - no X-Rustrawl guard, no parameters beyond the body,
        // nothing written; fixed download filenames, never request input.
        ("POST", "/api/export/services.csv") => export_post(
            out,
            body,
            "text/csv",
            "rustrawl-services-displayed.csv",
            |w, out, t| export_rows(w, out, t, |w, rows| crate::write_services_csv(w, rows)),
        ),
        ("POST", "/api/export/services.txt") => export_post(
            out,
            body,
            "text/plain; charset=utf-8",
            "rustrawl-services-displayed.txt",
            |w, out, t| {
                export_rows(w, out, t, |w, rows| {
                    crate::write_ip_list(w, &crate::services_ips(rows))
                })
            },
        ),
        ("POST", "/api/export/services.xml") => export_post(
            out,
            body,
            "application/xml",
            "rustrawl-services-displayed.xml",
            |w, out, t| export_rows(w, out, t, |w, rows| crate::write_services_xml(w, rows)),
        ),
        ("POST", "/api/export/scan.xml") => export_post(
            out,
            body,
            "application/xml",
            "rustrawl-scan-displayed.xml",
            |w, out, t| {
                let ips = match t {
                    ExportTargets::Rows(rows) => crate::services_ips(&rows),
                    ExportTargets::Ips(ips) => ips,
                };
                crate::render_scanxml_for_ips(w, out, &ips)
            },
        ),
        ("POST", "/api/export/hosts.txt") => export_post(
            out,
            body,
            "text/plain; charset=utf-8",
            "rustrawl-hosts-displayed.txt",
            |w, _out, t| {
                let mut ips = match t {
                    ExportTargets::Rows(rows) => crate::services_ips(&rows),
                    ExportTargets::Ips(ips) => ips,
                };
                ips.sort_unstable();
                ips.dedup();
                crate::write_ip_list(w, &ips)
            },
        ),
        // Range -> the up hosts inside it: the ranges row's rescan chip
        // resolves its queue here. A read, like the exports.
        ("POST", "/api/up-ips") => match up_ips_post(out, body) {
            Ok(v) => Response::json(&v),
            Err(resp) => resp,
        },
        ("POST", "/api/scan") => {
            if !x_rustrawl {
                return Response::forbidden();
            }
            match scan_post(out, body) {
                Ok(v) => Response::json(&v),
                Err(resp) => resp,
            }
        }
        ("POST", "/api/scan/stop") => {
            if !x_rustrawl {
                return Response::forbidden();
            }
            scan_stop_post()
        }
        ("POST", "/api/triage") => {
            if !x_rustrawl {
                return Response::forbidden();
            }
            match triage_post(out, body) {
                Ok(v) => Response::json(&v),
                Err(resp) => resp,
            }
        }
        ("POST", "/api/type") => {
            if !x_rustrawl {
                return Response::forbidden();
            }
            match type_post(out, body) {
                Ok(v) => Response::json(&v),
                Err(resp) => resp,
            }
        }
        ("POST", "/api/bookmark") => {
            if !x_rustrawl {
                return Response::forbidden();
            }
            match flag_post(out, body, crate::Flag::Bookmark) {
                Ok(v) => Response::json(&v),
                Err(resp) => resp,
            }
        }
        ("POST", "/api/pwned") => {
            if !x_rustrawl {
                return Response::forbidden();
            }
            match flag_post(out, body, crate::Flag::Pwned) {
                Ok(v) => Response::json(&v),
                Err(resp) => resp,
            }
        }
        ("POST", "/api/tag") => {
            if !x_rustrawl {
                return Response::forbidden();
            }
            match tag_post(out, body) {
                Ok(v) => Response::json(&v),
                Err(resp) => resp,
            }
        }
        ("POST", p) if p.starts_with("/api/note-image/") => {
            if !x_rustrawl {
                return Response::forbidden();
            }
            match note_image_post(out, &p["/api/note-image/".len()..], body) {
                Ok(v) => Response::json(&v),
                Err(resp) => resp,
            }
        }
        ("GET", p) if p.starts_with("/notes/") => match note_image_get(out, p) {
            Ok(resp) => resp,
            Err(resp) => resp,
        },
        // The capture pass's read-only views: the run list, one run's
        // manifest rows, and the screenshots themselves. `rustrawl web`
        // (the CLI pass) writes runs/web_*/; the dashboard only reads it.
        // Path segments are pinned (run id, <64 hex>.png) before anything
        // touches the filesystem, exactly like /notes.
        ("GET", "/api/captures") => match captures_json(out) {
            Ok(v) => Response::json(&v),
            Err(e) => Response::server_error(e),
        },
        ("GET", p) if p.starts_with("/api/captures/") => {
            let raw = &p["/api/captures/".len()..];
            if crate::capture::valid_run_id(raw) {
                match captures_run_json(out, raw) {
                    Ok(v) => Response::json(&v),
                    Err(e) => Response::server_error(e),
                }
            } else {
                Response::not_found()
            }
        }
        ("GET", p) if p.starts_with("/shots/") => match shot_get(out, p) {
            Ok(resp) => resp,
            Err(resp) => resp,
        },
        // Asset-by-asset capture: the host sheet's button re-shoots one
        // host's web services. The registry, not the request, picks the
        // targets; the pass is synchronous like a rescan — a host is a
        // handful of targets — and the perimeter lock is the one-at-a-time
        // truth, against the CLI pass and the scans alike. Whole-registry
        // passes stay CLI-side; the read-only views above never launch one.
        ("POST", "/api/capture") => {
            if !x_rustrawl {
                return Response::forbidden();
            }
            match capture_post(out, body) {
                Ok(v) => Response::json(&v),
                Err(resp) => resp,
            }
        }
        (m, p) if p.starts_with("/api/host/") => {
            if m != "GET" {
                return Response::method_not_allowed();
            }
            let raw = &p["/api/host/".len()..];
            match raw.parse::<Ipv4Addr>() {
                Ok(ip) => match host_json(out, ip) {
                    Ok(v) => Response::json(&v),
                    Err(e) => Response::server_error(e),
                },
                Err(_) => Response::not_found(), // never a fs path — parse or 404
            }
        }
        ("GET", _) => Response::not_found(),
        _ => Response::method_not_allowed(),
    }
}

// --------------------------------------------------------------- api bodies

/// The dashboard's one write: a triage mark — the dashboard's triage
/// buttons, through the same merge core. Validation errors come back as 400s;
/// the write lands through the add_service pattern (explicit registry
/// pre-check, run "manual", no perimeter lock — busy_timeout plus WAL
/// carry the concurrency).
fn triage_post(out: &Path, body: &[u8]) -> Result<serde_json::Value, Response> {
    let bad = |msg: String| Response::text(400, "Bad Request", &format!("{msg}\n"));
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad(format!("invalid JSON: {e}")))?;
    let ip: Ipv4Addr = v["ip"]
        .as_str()
        .unwrap_or_default()
        .parse()
        .map_err(|_| bad("ip must be an IPv4 address string".to_string()))?;
    // Marks live on the host only: a port field is refused outright (older
    // pages sent one; the vocabulary collapsed to the host level).
    match v.get("port") {
        None | Some(serde_json::Value::Null) => {}
        Some(p) if p.as_u64() == Some(0) => {}
        _ => {
            return Err(bad(
                "marks live on the host only (drop the port field)".to_string()
            ))
        }
    }
    let status = match v.get("status") {
        // absent/null keeps the row's status, like an absent --status
        None | Some(serde_json::Value::Null) => None,
        Some(s) => match s.as_str() {
            Some("none") => Some("none"),
            Some(s) if crate::TRIAGE_STATUSES.contains(&s) => Some(s),
            _ => {
                return Err(bad(
                    "status takes todo, clean, vuln (or none/null to clear it)".to_string(),
                ))
            }
        },
    };
    let note = match v.get("note") {
        // absent/null keeps the row's note; "" erases it
        None | Some(serde_json::Value::Null) => None,
        Some(s) => match s.as_str() {
            Some(s) if s.len() <= crate::NOTE_CAP => Some(s),
            Some(_) => return Err(bad("the note is capped at 64 KiB".to_string())),
            None => return Err(bad("note must be a string".to_string())),
        },
    };
    if !out.join("scandb.sqlite").exists() {
        return Err(Response::text(
            409,
            "Conflict",
            "no registry here - the dashboard serves one perimeter\n",
        ));
    }
    let mut db = Db::open(out).map_err(Response::server_error)?;
    db.set_run_id("manual");
    let set =
        crate::apply_triage(&mut db, ip, status, note, false).map_err(Response::server_error)?;
    Ok(serde_json::json!({
        "ok": true,
        "ip": ip.to_string(),
        "port": 0,
        "status": set.status,
        "note": set.note,
        "deleted": set.deleted,
    }))
}

/// The second write: the host's asset type — the row the class editor
/// sets. `kind: null` (or an absent kind) withdraws the row, heuristic or
/// manual; anything else must be a class token. Same pattern and guard as
/// the triage write.
fn type_post(out: &Path, body: &[u8]) -> Result<serde_json::Value, Response> {
    let bad = |msg: String| Response::text(400, "Bad Request", &format!("{msg}\n"));
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad(format!("invalid JSON: {e}")))?;
    let ip: Ipv4Addr = v["ip"]
        .as_str()
        .unwrap_or_default()
        .parse()
        .map_err(|_| bad("ip must be an IPv4 address string".to_string()))?;
    let kind = match v.get("kind") {
        // absent/null withdraws the override (heuristic included)
        None | Some(serde_json::Value::Null) => None,
        Some(s) => match s.as_str() {
            Some(k)
                if !k.is_empty()
                    && k.len() <= 32
                    && k.chars().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
                    }) =>
            {
                Some(k.to_string())
            }
            _ => return Err(bad(
                "kind must be a short lowercase token (dc, printer, bastion…) - or null to clear"
                    .to_string(),
            )),
        },
    };
    if !out.join("scandb.sqlite").exists() {
        return Err(Response::text(
            409,
            "Conflict",
            "no registry here - the dashboard serves one perimeter\n",
        ));
    }
    let mut db = Db::open(out).map_err(Response::server_error)?;
    match kind {
        None => {
            let cleared = db.clear_manual_type(ip).map_err(Response::server_error)?;
            Ok(serde_json::json!({
                "ok": true,
                "ip": ip.to_string(),
                "kind": serde_json::Value::Null,
                "cleared": cleared,
            }))
        }
        Some(k) => {
            let basis = v
                .get("basis")
                .and_then(|b| b.as_str())
                .filter(|b| b.len() <= 4096)
                .unwrap_or("");
            db.set_manual_type(ip, &k, basis)
                .map_err(Response::server_error)?;
            Ok(serde_json::json!({
                "ok": true,
                "ip": ip.to_string(),
                "kind": k,
                "cleared": false,
            }))
        }
    }
}

/// The bookmark toggle's and the PW3ND button's shared write — one flag,
/// on or off (the same rows the console's `hosts -c` flips). `on` absent
/// means true: the UI sends bare toggles.
fn flag_post(out: &Path, body: &[u8], flag: crate::Flag) -> Result<serde_json::Value, Response> {
    let bad = |msg: String| Response::text(400, "Bad Request", &format!("{msg}\n"));
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad(format!("invalid JSON: {e}")))?;
    let ip: Ipv4Addr = v["ip"]
        .as_str()
        .unwrap_or_default()
        .parse()
        .map_err(|_| bad("ip must be an IPv4 address string".to_string()))?;
    let on = match v.get("on") {
        None | Some(serde_json::Value::Null) => true,
        Some(b) => b
            .as_bool()
            .ok_or_else(|| bad("on takes true or false".to_string()))?,
    };
    if !out.join("scandb.sqlite").exists() {
        return Err(Response::text(
            409,
            "Conflict",
            "no registry here - the dashboard serves one perimeter\n",
        ));
    }
    let mut db = Db::open(out).map_err(Response::server_error)?;
    db.set_run_id("manual");
    match flag {
        crate::Flag::Bookmark => db.record_bookmark(ip, on),
        crate::Flag::Pwned => db.record_pwned(ip, on),
    }
    db.flush().map_err(Response::server_error)?;
    Ok(serde_json::json!({
        "ok": true,
        "ip": ip.to_string(),
        "flag": flag.word(),
        "on": on,
    }))
}

/// The tag editor's write: adds and removes on one host (the same rows
/// the console's `hosts -ta` / `-td` write). `add` and `remove` take tag
/// token arrays; the tokens
/// normalize exactly like the CLI's.
fn tag_post(out: &Path, body: &[u8]) -> Result<serde_json::Value, Response> {
    let bad = |msg: String| Response::text(400, "Bad Request", &format!("{msg}\n"));
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad(format!("invalid JSON: {e}")))?;
    let ip: Ipv4Addr = v["ip"]
        .as_str()
        .unwrap_or_default()
        .parse()
        .map_err(|_| bad("ip must be an IPv4 address string".to_string()))?;
    let tokens_of = |key: &str| -> Result<Vec<String>, Response> {
        match v.get(key) {
            None | Some(serde_json::Value::Null) => Ok(Vec::new()),
            Some(a) => a
                .as_array()
                .ok_or_else(|| bad(format!("{key} takes an array of tag tokens")))?
                .iter()
                .map(|t| {
                    t.as_str()
                        .map(|s| crate::norm_tag(s).map_err(|e| bad(e.to_string())))
                        .unwrap_or_else(|| Err(bad(format!("{key} takes strings"))))
                })
                .collect(),
        }
    };
    let add = tokens_of("add")?;
    let remove = tokens_of("remove")?;
    if add.is_empty() && remove.is_empty() {
        return Err(bad(
            "nothing to set - give add and/or remove arrays".to_string()
        ));
    }
    for t in &add {
        if remove.contains(t) {
            return Err(bad(format!("{t:?} is in both add and remove")));
        }
    }
    if !out.join("scandb.sqlite").exists() {
        return Err(Response::text(
            409,
            "Conflict",
            "no registry here - the dashboard serves one perimeter\n",
        ));
    }
    let mut db = Db::open(out).map_err(Response::server_error)?;
    db.set_run_id("manual");
    for t in &remove {
        db.record_tag(ip, t, false);
    }
    for t in &add {
        db.record_tag(ip, t, true);
    }
    db.flush().map_err(Response::server_error)?;
    let tags = db.tags_for_ip(ip).map_err(Response::server_error)?;
    let tags = tags.iter().map(|(t, _)| t.as_str()).collect::<Vec<&str>>();
    Ok(serde_json::json!({
        "ok": true,
        "ip": ip.to_string(),
        "tags": tags,
    }))
}

/// The screenshot upload: raw PNG/JPEG bytes posted to
/// /api/note-image/<ip>, stored under notes/<ip>/<sha256>.<ext> inside the
/// perimeter and referenced from the note as ![shot](/notes/<ip>/<file>).
/// The magic bytes decide the type (the client's Content-Type never does),
/// the digest names the file (the same capture twice lands once), and the
/// note row itself still carries only text: images live on the filesystem,
/// inside the perimeter root.
fn note_image_post(out: &Path, raw_ip: &str, body: &[u8]) -> Result<serde_json::Value, Response> {
    let bad = |msg: String| Response::text(400, "Bad Request", &format!("{msg}\n"));
    let ip: Ipv4Addr = raw_ip
        .parse()
        .map_err(|_| bad("the path's ip segment must be an IPv4 address".to_string()))?;
    let Some(ext) = image_kind(body) else {
        return Err(bad(
            "only PNG and JPEG screenshots are stored (the magic bytes decide)".to_string(),
        ));
    };
    if body.is_empty() {
        return Err(bad("the upload carries no bytes".to_string()));
    }
    if !out.join("scandb.sqlite").exists() {
        return Err(Response::text(
            409,
            "Conflict",
            "no registry here - the dashboard serves one perimeter\n",
        ));
    }
    let dir = out.join("notes").join(ip.to_string());
    std::fs::create_dir_all(&dir).map_err(|e| Response::server_error(e.into()))?;
    let file = format!("{}.{ext}", hex(&sha256(body)));
    std::fs::write(dir.join(&file), body).map_err(|e| Response::server_error(e.into()))?;
    Ok(serde_json::json!({
        "ok": true,
        "ip": ip.to_string(),
        "file": file,
        "url": format!("/notes/{ip}/{file}"),
        "bytes": body.len(),
    }))
}

/// Serves a stored screenshot back: /notes/<ip>/<64 hex>.<png|jpg>. Both
/// path segments are pinned to exact shapes before anything touches the
/// filesystem, so the route can never climb out of notes/.
fn note_image_get(out: &Path, path: &str) -> Result<Response, Response> {
    let not_found = || Response::not_found();
    let rest = &path["/notes/".len()..];
    let (raw_ip, file) = rest.split_once('/').ok_or_else(not_found)?;
    let ip: Ipv4Addr = raw_ip.parse().map_err(|_| not_found())?;
    let (stem, ext) = match file.strip_suffix(".png") {
        Some(stem) => (stem, "png"),
        None => match file.strip_suffix(".jpg") {
            Some(stem) => (stem, "jpg"),
            None => return Err(not_found()),
        },
    };
    if stem.len() != 64 || !stem.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(not_found());
    }
    let bytes = std::fs::read(out.join("notes").join(ip.to_string()).join(file))
        .map_err(|_| not_found())?;
    Ok(Response {
        status: 200,
        reason: "OK",
        content_type: if ext == "png" {
            "image/png"
        } else {
            "image/jpeg"
        },
        body: bytes,
        filename: None,
    })
}

/// PNG (89 50 4E 47 0D 0A 1A 0A) or JPEG (FF D8 FF) by magic bytes alone.
fn image_kind(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        Some("png")
    } else if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("jpg")
    } else {
        None
    }
}

// --------------------------------------------------------------- sha256

/// SHA-256 (FIPS 180-4), hand-rolled: the screenshot files are named by
/// content digest and the crate list is frozen. Threat model is naming
/// files inside one perimeter's notes dir, not adversarial hashing.
/// Shared with the capture pass (shots/ carries the same digest naming).
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    // Pad: the 0x80 stop byte, zeros to 56 mod 64, the bit length big-endian.
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for (i, ki) in K.iter().enumerate() {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(*ki)
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (i, v) in [a, b, c, d, e, f, g, hh].iter().enumerate() {
            h[i] = h[i].wrapping_add(*v);
        }
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The rescan form's default: the newest `scan_*` queue run's pinned nmap
/// args (the baseline plan — profile chunks may have run differently,
/// the operator edits from here; the port list rides in the args), or the
/// CLI's own fallback when no scan run exists. Manual runs don't feed
/// this: they inherit, they don't set.
fn scan_defaults(out: &Path) -> serde_json::Value {
    // The shared reader lives in main.rs (the console's `hosts -r` falls
    // back to the same args); the dashboard API keeps its JSON shape.
    serde_json::json!({ "args": crate::scan_defaults(out) })
}

/// The third write: nmap once over a target set the registry resolves —
/// one already-up host (`{ip}`), an explicit list (`{ips}`), or every up
/// host in a range (`{range}`) — with operator-typed arguments inside
/// rustrawl's frame. Validation happens before anything spawns; the run
/// itself carries the perimeter lock (one scan per perimeter — a rescan
/// during a real run is a 409, not a queue jump). Synchronous: the
/// response lands when the rows do, so a dropped connection costs the
/// response, never the rows.
fn scan_post(out: &Path, body: &[u8]) -> Result<serde_json::Value, Response> {
    let bad = |msg: String| Response::text(400, "Bad Request", &format!("{msg}\n"));
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad(format!("invalid JSON: {e}")))?;
    let ip_s = v.get("ip").and_then(|x| x.as_str());
    let range_s = v.get("range").and_then(|x| x.as_str());
    let ips_v = v.get("ips");
    if (ip_s.is_some() as u8 + range_s.is_some() as u8 + ips_v.is_some() as u8) != 1 {
        return Err(bad(
            "give exactly one of ip, range, ips - the rescan needs one target shape".to_string(),
        ));
    }
    if !out.join("scandb.sqlite").exists() {
        return Err(Response::text(
            409,
            "Conflict",
            "no registry here - the dashboard serves one perimeter\n",
        ));
    }
    // Absent/empty args fall back to the last queue's plan (the form is
    // prefilled with it anyway — the operator clears the box to mean "same
    // as last time"). The port list rides in the args.
    let d = scan_defaults(out);
    let args = match v.get("args").and_then(|x| x.as_str()) {
        Some(a) if !a.trim().is_empty() => a.to_string(),
        _ => d["args"].as_str().unwrap_or("-sC -sV").to_string(),
    };
    crate::config::check_nmap_args(&args).map_err(|e| bad(format!("nmap args refused: {e:#}")))?;
    // A rescan re-probes known assets — the registry, not the request,
    // picks the targets: every shape intersects with the up set.
    let db = Db::open_read_only(out).map_err(Response::server_error)?;
    let up = db
        .up_hosts(&[
            crate::discovery::db::Stage::Sweep,
            crate::discovery::db::Stage::Expand,
        ])
        .map_err(Response::server_error)?;
    drop(db);

    // (resolved targets, ip-shape flag, ips not in the up set). `skipped`
    // counts only entries of an explicit ips list that were dropped: a
    // range request reports 0 — hosts outside the range were never asked
    // for, and "248 skipped" for a /24 with 8 up hosts would be noise.
    let (resolved, single, skipped) = if let Some(s) = ip_s {
        let ip: Ipv4Addr = s
            .parse()
            .map_err(|_| bad("ip must be an IPv4 address string".to_string()))?;
        if !up.contains(u32::from(ip)) {
            return Err(bad(format!(
                "{ip} is not an up host in this registry - a rescan re-probes known hosts"
            )));
        }
        (vec![ip], true, 0)
    } else if let Some(list) = ips_v {
        let arr = list
            .as_array()
            .ok_or_else(|| bad("ips must be an array of IPv4 address strings".to_string()))?;
        let mut asked: Vec<Ipv4Addr> = Vec::with_capacity(arr.len());
        for (i, e) in arr.iter().enumerate() {
            let s = e
                .as_str()
                .ok_or_else(|| bad(format!("ips[{i}] must be an IPv4 address string")))?;
            let ip: Ipv4Addr = s
                .parse()
                .map_err(|_| bad(format!("ips[{i}]: {s:?} is not an IPv4 address")))?;
            asked.push(ip);
        }
        asked.sort_unstable();
        asked.dedup();
        let before = asked.len();
        asked.retain(|ip| up.contains(u32::from(*ip)));
        let skipped = before - asked.len();
        (asked, false, skipped)
    } else {
        let range_s = range_s.unwrap_or_default();
        let range = crate::targets::IpRange::parse(range_s)
            .map_err(|e| bad(format!("bad range {range_s:?}: {e:#}")))?;
        let hits = &up & crate::targets::Targets::from_ranges(vec![range]).as_bitmap();
        (hits.iter().map(Ipv4Addr::from).collect(), false, 0)
    };
    if resolved.is_empty() {
        return Err(bad(
            "no up host in this set - a rescan re-probes known hosts".to_string(),
        ));
    }
    if resolved.len() > crate::scan::MANUAL_SCAN_MAX_HOSTS {
        return Err(bad(format!(
            "{} host(s) is past the {}-host rescan ceiling - bigger jobs belong to `rustrawl scan` with its profiles",
            resolved.len(),
            crate::scan::MANUAL_SCAN_MAX_HOSTS
        )));
    }

    // One dashboard scan at a time: the flag is the gate (a second POST
    // is refused before it can touch the perimeter lock), the lock inside
    // manual_scan is the cross-process truth. A stale abort (an earlier
    // stop) must not kill this scan at its first 200 ms tick.
    if SCANNING
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return Err(Response::text(
            409,
            "Conflict",
            "a scan is already running on this dashboard\n",
        ));
    }
    crate::discovery::ABORT.store(false, Ordering::Relaxed);
    let r = crate::scan::manual_scan(out, &resolved, &args);
    SCANNING.store(false, Ordering::Relaxed);
    let r = r.map_err(|e| {
        let msg = format!("{e:#}");
        if msg.contains("one scan per perimeter") {
            Response::text(409, "Conflict", &format!("{msg}\n"))
        } else {
            Response::server_error(anyhow::anyhow!(msg))
        }
    })?;
    if single {
        return Ok(serde_json::json!({
            "ok": true,
            "ip": resolved[0].to_string(),
            "run": r.run_id,
            "open": r.open.len(),
            "services": r.open.iter().map(|(port, service, version)| serde_json::json!({
                "port": port, "service": service, "version": version,
            })).collect::<Vec<_>>(),
        }));
    }
    Ok(serde_json::json!({
        "ok": true,
        "count": resolved.len(),
        "skipped": skipped,
        "run": r.run_id,
        "open": r.open.len(),
    }))
}

/// A registry export as a download: render into memory behind a
/// compile-time-constant filename, serve with Content-Disposition. The
/// exports are reads (no X-Rustrawl) and unfiltered — the console's
/// `-e` flags stay the filtered surface. The renderers' tallies land on
/// the server's stderr, not in the download.
fn export_response(
    content_type: &'static str,
    name: &'static str,
    out: &Path,
    render: impl FnOnce(&mut dyn std::io::Write) -> anyhow::Result<()>,
) -> Response {
    if !out.join("scandb.sqlite").exists() {
        return Response::text(
            409,
            "Conflict",
            "no registry here - the dashboard serves one perimeter\n",
        );
    }
    let mut buf = Vec::new();
    if let Err(e) = render(&mut buf) {
        return Response::server_error(e);
    }
    Response::download(content_type, name, buf)
}

/// What a filtered export renders: the exact rows the page displayed, or a
/// host set to fill from the registry.
enum ExportTargets {
    Rows(Vec<crate::SvcRow>),
    Ips(Vec<Ipv4Addr>),
}

/// The filtered-export POST shape: parse the body, hand the targets to the
/// format's renderer, serve the download. Reads only - no guard, matching
/// the GET exports.
fn export_post(
    out: &Path,
    body: &[u8],
    content_type: &'static str,
    name: &'static str,
    render: impl FnOnce(&mut dyn std::io::Write, &Path, ExportTargets) -> anyhow::Result<()>,
) -> Response {
    match export_post_body(body) {
        Ok(targets) => export_response(content_type, name, out, |w| render(w, out, targets)),
        Err(resp) => resp,
    }
}

fn bad_export(msg: &str) -> Response {
    Response::text(400, "Bad Request", &format!("{msg}\n"))
}

/// Parses `{rows: [...]}` or `{ips: [...]}` - exactly one, entries lenient
/// about missing text fields (`""`/`0`) but strict about ip and port
/// ranges, each error naming its index.
fn export_post_body(body: &[u8]) -> std::result::Result<ExportTargets, Response> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad_export(&format!("invalid JSON: {e}")))?;
    if let Some(rows) = v.get("rows") {
        let arr = rows
            .as_array()
            .ok_or_else(|| bad_export("rows must be an array"))?;
        let mut out = Vec::with_capacity(arr.len());
        for (i, r) in arr.iter().enumerate() {
            let ip: Ipv4Addr = r
                .get("ip")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .parse()
                .map_err(|_| bad_export(&format!("rows[{i}]: bad ip")))?;
            let port = r.get("port").and_then(|x| x.as_u64()).unwrap_or(0);
            let port = u16::try_from(port)
                .map_err(|_| bad_export(&format!("rows[{i}]: port out of range")))?;
            let text = |k: &str| {
                r.get(k)
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string()
            };
            out.push(crate::SvcRow {
                ip,
                port,
                name: text("name"),
                version: text("version"),
                seen: r.get("seen").and_then(|x| x.as_i64()).unwrap_or(0),
                run: text("run"),
            });
        }
        return Ok(ExportTargets::Rows(out));
    }
    if let Some(ips) = v.get("ips") {
        let arr = ips
            .as_array()
            .ok_or_else(|| bad_export("ips must be an array"))?;
        let mut out = Vec::with_capacity(arr.len());
        for (i, r) in arr.iter().enumerate() {
            out.push(
                r.as_str()
                    .unwrap_or_default()
                    .parse::<Ipv4Addr>()
                    .map_err(|_| bad_export(&format!("ips[{i}]: bad ip")))?,
            );
        }
        return Ok(ExportTargets::Ips(out));
    }
    Err(bad_export(
        "give rows or ips - the filtered export renders what the page displays",
    ))
}

/// Row-format exports want rows either way: exact rows stay as sent (screen
/// order), an ip set is filled from the registry (numeric order).
fn export_rows(
    w: &mut dyn std::io::Write,
    out: &Path,
    targets: ExportTargets,
    write: impl FnOnce(&mut dyn std::io::Write, &[crate::SvcRow]) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    match targets {
        ExportTargets::Rows(rows) => write(w, &rows),
        ExportTargets::Ips(ips) => {
            let rows = crate::services_rows_for_ips(out, &ips)?;
            write(w, &rows)
        }
    }
}

/// Range -> the up hosts inside it, the same intersection the rescan POST
/// scans: the ranges row's rescan chip fills its queue here. An empty
/// intersection is a 200 with an empty list - the tab shows an empty queue
/// and the run button refuses on its own terms.
fn up_ips_post(out: &Path, body: &[u8]) -> std::result::Result<serde_json::Value, Response> {
    if !out.join("scandb.sqlite").exists() {
        return Err(Response::text(
            409,
            "Conflict",
            "no registry here - the dashboard serves one perimeter\n",
        ));
    }
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad_export(&format!("invalid JSON: {e}")))?;
    let range = v
        .get("range")
        .and_then(|r| r.as_str())
        .ok_or_else(|| bad_export("give range - the range to resolve"))?;
    let range = crate::targets::IpRange::parse(range)
        .map_err(|_| bad_export("bad range - use a.b.c.d/p"))?;
    let db = Db::open_read_only(out).map_err(Response::server_error)?;
    let up = db
        .up_hosts(&[
            crate::discovery::db::Stage::Sweep,
            crate::discovery::db::Stage::Expand,
        ])
        .map_err(Response::server_error)?;
    let hits = up & crate::targets::Targets::from_ranges(vec![range]).as_bitmap();
    let ips: Vec<String> = hits
        .iter()
        .map(|raw| Ipv4Addr::from(raw).to_string())
        .collect();
    let count = ips.len();
    Ok(serde_json::json!({ "ips": ips, "count": count }))
}

/// Tail window for the live output: a `-v` batch writes tens of MB and this
/// is polled every second, so the read seeks from the end instead of
/// walking the file.
const TAIL_BYTES: u64 = 64 * 1024;

/// The newest manual rescan's captured output. The run id stays set after
/// completion, so a page that navigated away recovers the tail until the
/// next scan overwrites it; a missing capture is an empty text, not an
/// error - the file appears the moment nmap starts writing.
fn out_tail(out: &Path, run: &str) -> (u64, String) {
    use std::io::{Read, Seek, SeekFrom};
    let path = crate::discovery::state::runs_dir(out)
        .join(run)
        .join("scans")
        .join("chunk-0000.out");
    let mut f = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return (0, String::new()),
    };
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    let start = size.saturating_sub(TAIL_BYTES);
    if f.seek(SeekFrom::Start(start)).is_err() {
        return (size, String::new());
    }
    let mut buf = Vec::new();
    let _ = f.read_to_end(&mut buf);
    (size, String::from_utf8_lossy(&buf).into_owned())
}

fn scan_output_json(out: &Path) -> serde_json::Value {
    let run = crate::scan::CURRENT_MANUAL_RUN
        .lock()
        .ok()
        .and_then(|g| g.clone());
    match run {
        Some(run) => {
            let (size, text) = out_tail(out, &run);
            serde_json::json!({
                "run": run,
                "running": SCANNING.load(Ordering::Relaxed),
                "size": size,
                "text": text,
                // the command this run is executing - the tab shows it above
                // the live output
                "cmd": crate::evidence::run_chunk_cmd(out, &run, 0),
            })
        }
        None => serde_json::json!({
            "run": null, "running": false, "size": 0, "text": "", "cmd": ""
        }),
    }
}

/// The brake for the manual rescan: flip the shared abort flag the watch
/// loop polls - nmap is killed within its 200 ms tick and the pending
/// POST /api/scan answers with the interruption, capture left on disk.
/// Nothing running: a 409, so the button never fires blind.
fn scan_stop_post() -> Response {
    if !SCANNING.load(Ordering::Relaxed) {
        return Response::text(409, "Conflict", "no scan is running\n");
    }
    crate::discovery::ABORT.store(true, Ordering::Relaxed);
    Response::json(&serde_json::json!({ "ok": true }))
}

fn hosts_json(out: &Path) -> Result<serde_json::Value> {
    let db = Db::open_read_only(out)?;
    // collected hostnames per asset, empty for registries without the table
    let mut names: std::collections::HashMap<Ipv4Addr, Vec<String>> =
        std::collections::HashMap::new();
    db.names(&mut |ip, name, _source, _seen, _run| {
        names.entry(ip).or_default().push(name.to_string());
    })?;
    // open ports per host — API-only context now, no view renders badges
    let mut ports: std::collections::HashMap<Ipv4Addr, Vec<u16>> = std::collections::HashMap::new();
    db.services(None, None, &mut |ip, port, _, _, _, _| {
        ports.entry(ip).or_default().push(port);
    })?;
    // asset types and host-level marks, one pass each
    let mut types: std::collections::HashMap<Ipv4Addr, serde_json::Value> =
        std::collections::HashMap::new();
    db.types(&mut |ip, kind, basis, source, _| {
        types.insert(
            ip,
            serde_json::json!({"kind": kind, "basis": basis, "source": source}),
        );
    })?;
    let mut states: std::collections::HashMap<Ipv4Addr, serde_json::Value> =
        std::collections::HashMap::new();
    db.triage(&mut |ip, port, status, note, updated| {
        if port == 0 {
            states.insert(
                ip,
                serde_json::json!({
                    "status": status.map(crate::norm_status),
                    "note": note,
                    "updated": updated
                }),
            );
        }
    })?;
    // the operator's flags and tags, one pass each
    let mut bookmarks: std::collections::HashSet<Ipv4Addr> = std::collections::HashSet::new();
    db.bookmarks(&mut |ip, _| {
        bookmarks.insert(ip);
    })?;
    let mut owned: std::collections::HashSet<Ipv4Addr> = std::collections::HashSet::new();
    db.pwned(&mut |ip, _| {
        owned.insert(ip);
    })?;
    let mut tag_map: std::collections::HashMap<Ipv4Addr, Vec<String>> =
        std::collections::HashMap::new();
    db.tags(&mut |ip, tag, _| {
        tag_map.entry(ip).or_default().push(tag.to_string());
    })?;
    let mut hosts = Vec::new();
    db.hosts_overview(&mut |ip, stages, seen, open| {
        let empty: Vec<String> = Vec::new();
        let noports: Vec<u16> = Vec::new();
        let notags: Vec<String> = Vec::new();
        hosts.push(serde_json::json!({
            "ip": ip.to_string(),
            "stages": stages,
            "last_up": seen,
            "open_ports": open,
            "names": names.get(&ip).unwrap_or(&empty),
            "ports": ports.get(&ip).unwrap_or(&noports),
            "type": types.get(&ip),
            "state": states.get(&ip),
            "bookmark": bookmarks.contains(&ip),
            "pwned": owned.contains(&ip),
            "tags": tag_map.get(&ip).unwrap_or(&notags),
        }));
    })?;
    Ok(serde_json::json!({ "hosts": hosts, "count": hosts.len() }))
}

fn services_json(out: &Path) -> Result<serde_json::Value> {
    let db = Db::open_read_only(out)?;
    let mut rows = Vec::new();
    db.services(None, None, &mut |ip, port, name, version, seen, run| {
        rows.push(serde_json::json!({
            "ip": ip.to_string(),
            "port": port,
            "name": name,
            "version": version,
            "seen": seen,
            "run": run,
        }));
    })?;
    Ok(serde_json::json!({ "services": rows, "count": rows.len() }))
}

// ------------------------------------------- capture pass (read-only views)

/// One manifest row as the dashboard reads it. `shot_url` rides along so the
/// page never rebuilds the path shape (null when the target kept no image).
fn capture_row_json(r: &crate::capture::ManifestRow) -> serde_json::Value {
    serde_json::json!({
        "run": r.run,
        "url": r.url,
        "ip": r.ip,
        "port": r.port,
        "scheme": r.scheme,
        "status": r.status,
        "title": r.title,
        "label": r.label,
        "error": r.error,
        "detail": r.detail,
        "shot": r.shot,
        "sha256": r.sha256,
        "dup_of": r.dup_of,
        "shot_url": if r.shot.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::json!(format!("/shots/{}/{}", r.run, r.shot))
        },
        "headers": r.headers,
        "ms": r.ms,
        "at": r.at,
    })
}

/// POST /api/capture {ip}: re-shoot one asset's web services now. The
/// registry decides what is web on that host (the pass's own
/// classification); the request only names an up host. One small
/// `runs/web_<ts>/` per click, synchronous — a host is a handful of
/// targets, each bounded by the per-target timeout — and the perimeter
/// lock held across the pass keeps it exclusive with the CLI pass and
/// the rescans.
fn capture_post(out: &Path, body: &[u8]) -> Result<serde_json::Value, Response> {
    let bad = |msg: String| Response::text(400, "Bad Request", &format!("{msg}\n"));
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad(format!("invalid JSON: {e}")))?;
    let ip: Ipv4Addr = v
        .get("ip")
        .and_then(|x| x.as_str())
        .ok_or_else(|| bad("give an ip".to_string()))?
        .parse()
        .map_err(|_| bad("ip must be an IPv4 address string".to_string()))?;
    // Same gate as a rescan: the registry, not the request. The host must
    // be up (a capture re-shoots known hosts, it probes nothing new) and
    // its web set is the classified one.
    let db = Db::open_read_only(out).map_err(Response::server_error)?;
    let mut up = false;
    db.up_ips(&mut |u| {
        if u == ip {
            up = true;
        }
    })
    .map_err(Response::server_error)?;
    let targets = crate::capture::host_web_targets(&db, ip).map_err(Response::server_error)?;
    drop(db);
    if !up {
        return Err(bad(format!(
            "{ip} is not an up host in this registry - a capture re-shoots known hosts"
        )));
    }
    if targets.is_empty() {
        return Err(bad(format!(
            "no http/https service for {ip} in the registry - nothing to capture"
        )));
    }
    if targets.len() > crate::capture::MAX_CAPTURE_TARGETS {
        return Err(bad(format!(
            "{} web targets for {ip} - over the {}-target cap, triage the registry first",
            targets.len(),
            crate::capture::MAX_CAPTURE_TARGETS
        )));
    }
    // A stale abort from an earlier stop must not kill this pass at tick
    // one — cleared exactly like the rescan does.
    crate::discovery::ABORT.store(false, Ordering::Relaxed);
    // One capture per perimeter: the lock is the cross-process truth (the
    // CLI pass, a scan, another dashboard click).
    let _lock = match crate::discovery::state::lock_perimeter(out) {
        Ok(l) => l,
        Err(e) => {
            let msg = format!("{e:#}");
            if msg.contains("one scan per perimeter") {
                return Err(Response::text(409, "Conflict", &format!("{msg}\n")));
            }
            return Err(Response::server_error(anyhow::anyhow!(msg)));
        }
    };
    let threads = targets.len().min(crate::capture::DEFAULT_THREADS);
    let summary =
        crate::capture::run_pass(out, targets, crate::capture::DEFAULT_TIMEOUT_SECS, threads)
            .map_err(Response::server_error)?;
    let rows = crate::capture::read_manifest(out, &summary.run_id)
        .into_iter()
        .map(|mut r| {
            r.run = summary.run_id.clone();
            capture_row_json(&r)
        })
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "ok": true,
        "ip": ip.to_string(),
        "run": summary.run_id,
        "total": summary.total,
        "captured": rows,
    }))
}

/// The capture run list, newest first — each run's progress straight out of
/// its cap_state.json (an unreadable state drops the run: a torn file is
/// quieter than a wrong count).
fn captures_json(out: &Path) -> Result<serde_json::Value> {
    let runs = crate::capture::list_runs(out)
        .into_iter()
        .filter_map(|run| {
            crate::capture::read_cap_state(out, &run).map(|st| {
                serde_json::json!({
                    "run": run,
                    "done": st.done,
                    "interrupted": st.interrupted,
                    "done_count": st.done_count(),
                    "total": st.targets.len(),
                    "errors": st
                        .targets
                        .iter()
                        .filter(|t| t.done && !t.error.is_empty())
                        .count(),
                    "chrome": st.chrome,
                    "started_at": st.started_at,
                })
            })
        })
        .collect::<Vec<_>>();
    Ok(serde_json::json!({ "runs": runs, "count": runs.len() }))
}

/// One capture run's manifest — every target, captured or failed, in the
/// order the pass walked them.
fn captures_run_json(out: &Path, run: &str) -> Result<serde_json::Value> {
    let rows = crate::capture::read_manifest(out, run);
    let targets = rows
        .iter()
        .map(|r| {
            let mut r = r.clone();
            r.run = run.to_string();
            capture_row_json(&r)
        })
        .collect::<Vec<_>>();
    let st = crate::capture::read_cap_state(out, run);
    Ok(serde_json::json!({
        "run": run,
        "done": st.as_ref().map(|s| s.done).unwrap_or(false),
        "interrupted": st.as_ref().map(|s| s.interrupted).unwrap_or(false),
        "total": st.as_ref().map(|s| s.targets.len()).unwrap_or(targets.len()),
        "done_count": st.as_ref().map(|s| s.done_count()).unwrap_or(0),
        "targets": targets,
    }))
}

/// Serves a capture screenshot: /shots/<web_run>/<64 hex>.png. Both segments
/// are pinned to exact shapes before the filesystem is touched, so the route
/// can never climb out of runs/.
fn shot_get(out: &Path, path: &str) -> Result<Response, Response> {
    let not_found = || Response::not_found();
    let rest = &path["/shots/".len()..];
    let (run, file) = rest.split_once('/').ok_or_else(not_found)?;
    if !crate::capture::valid_run_id(run) || !crate::capture::valid_shot_name(file) {
        return Err(not_found());
    }
    let bytes = std::fs::read(
        crate::discovery::state::runs_dir(out)
            .join(run)
            .join("shots")
            .join(file),
    )
    .map_err(|_| not_found())?;
    Ok(Response {
        status: 200,
        reason: "OK",
        content_type: "image/png",
        body: bytes,
        filename: None,
    })
}

/// One host's sheet: registry detail + the nmap-evidence stack — one block
/// per scan run that queued the host, newest first, capped at
/// [`crate::evidence::SHEET_STACK`]. An empty stack carries `evidence_note`
/// instead (no scan run yet / never queued); a non-empty one may still mix
/// real capture blocks with per-run explanation blocks. The sheet also
/// carries the host's capture rows (the `rustrawl web` passes), newest runs
/// first, bounded — the sheet shows the host's web face next to its evidence.
fn host_json(out: &Path, ip: Ipv4Addr) -> Result<serde_json::Value> {
    let db = Db::open_read_only(out)?;
    let detail = db.host_detail(ip)?;
    let blocks = crate::evidence::collect_host_evidence(out, ip, crate::evidence::SHEET_STACK)?;
    let runs_dir = crate::discovery::state::runs_dir(out);
    let evidence_note = if blocks.is_empty() {
        Some(if crate::evidence::has_scan_runs(&runs_dir) {
            format!("{ip} was never queued in a scan run (discovery-only host)")
        } else {
            "no scan run on this perimeter yet".to_string()
        })
    } else {
        None
    };
    // 12 runs, not 3: per-asset captures (one small web_<ts> run per
    // click) multiply the run count for a host the operator works on.
    let captures = crate::capture::host_captures(out, &ip.to_string(), 12, 20)
        .iter()
        .map(capture_row_json)
        .collect::<Vec<_>>();
    let evidence = blocks
        .iter()
        .map(|b| {
            serde_json::json!({
                "run": b.run_id, "chunk": b.chunk,
                "has_report": b.has_report, "cmd": b.cmd, "text": b.text,
            })
        })
        .collect::<Vec<_>>();
    Ok(match detail {
        None => serde_json::json!({
            "ip": ip.to_string(), "detail": null,
            "evidence": evidence, "evidence_note": evidence_note,
            "captures": captures,
        }),
        Some(d) => serde_json::json!({
            "ip": ip.to_string(),
            "stages": d.stages.iter().map(|(stage, status, seen, run)| serde_json::json!({
                "stage": stage, "status": status, "seen": seen, "run": run,
            })).collect::<Vec<_>>(),
            "ports": d.ports.iter().map(|(port, stage, status, seen, run)| serde_json::json!({
                "port": port, "stage": stage.as_str(), "status": status, "seen": seen, "run": run,
            })).collect::<Vec<_>>(),
            "services": d.services.iter().map(|(port, name, version, seen, run)| serde_json::json!({
                "port": port, "name": name, "version": version, "seen": seen, "run": run,
            })).collect::<Vec<_>>(),
            "names": d.names.iter().map(|(name, source, seen, run)| serde_json::json!({
                "name": name, "source": source, "seen": seen, "run": run,
            })).collect::<Vec<_>>(),
            "type": d.asset_type.as_ref().map(|(kind, basis, source)| serde_json::json!({
                "kind": kind, "basis": basis, "source": source,
            })),
            "bookmark": d.bookmark.is_some(),
            "pwned": d.pwned.is_some(),
            "tags": d.tags.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
            "state": d.triage.iter().find(|(p, _, _, _)| *p == 0).map(|(_, status, note, updated)| serde_json::json!({
                "status": status.as_deref().map(crate::norm_status), "note": note, "updated": updated,
            })),
            "evidence": evidence,
            "evidence_note": evidence_note,
            "captures": captures,
        }),
    })
}

/// Counts (JSON fields) plus the run-outcome table as preformatted text.
/// `runs_text` is API/CLI payload only - no dashboard view renders it
/// (the status page is gone); `status_runs` stays the single renderer.
fn status_json(out: &Path) -> Result<serde_json::Value> {
    let db = Db::open_read_only(out)?;
    let (up, missed, results) = db.counts()?;
    let services = db.services_count()?;
    let mut runs = Vec::new();
    crate::status_runs(out, &mut runs)?;
    Ok(serde_json::json!({
        "perimeter": out.file_name().and_then(|n| n.to_str()).unwrap_or("?"),
        "up": up,
        "no_response": missed,
        "answered": results,
        "services": services,
        "runs_text": String::from_utf8_lossy(&runs),
        // true while a manual rescan holds the perimeter: the views show
        // the running scan (and its stop link) after navigating away
        "scanning": SCANNING.load(Ordering::Relaxed),
        // the newest manual run's id, kept after completion - the rescan
        // tab reconnects to its live output with this
        "run": crate::scan::CURRENT_MANUAL_RUN.lock().ok().and_then(|g| g.clone()),
    }))
}

/// The triage view at a fixed /24 — the same rows the console's `ranges`
/// prints, as JSON (services pre-formatted "name xN", top 5), plus the
/// host-level triage counts the ranges home renders as pastille tallies.
/// The triage view bucketed at a prefix — /24 by default, /api/ranges/<p>
/// re-buckets (1..=32, validated at the route). Triage marks and bookmarks
/// follow the same bucket key as the rows, so the tallies land on the row
/// they belong to at every zoom level.
fn ranges_json(out: &Path, prefix: u32) -> Result<serde_json::Value> {
    let shift = 32 - prefix;
    let rows = crate::collect_ranges(out, prefix)?;
    let db = Db::open_read_only(out)?;
    let mut marks: std::collections::HashMap<u32, [u64; 3]> = std::collections::HashMap::new();
    db.triage(&mut |ip, port, status, _, _| {
        if port == 0 {
            if let Some(i) = status
                .map(crate::norm_status)
                .and_then(|s| crate::TRIAGE_STATUSES.iter().position(|k| *k == s))
            {
                marks.entry(u32::from(ip) >> shift).or_default()[i] += 1;
            }
        }
    })?;
    // the bookmark tally per bucket — kept for the API and the CLI; the
    // dashboard no longer renders it
    let mut bkm: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();
    db.bookmarks(&mut |ip, _| {
        *bkm.entry(u32::from(ip) >> shift).or_default() += 1;
    })?;
    let ranges = rows
        .iter()
        .map(|r| {
            let none = [0u64; 3];
            let c = marks.get(&(u32::from(r.base) >> shift)).unwrap_or(&none);
            serde_json::json!({
                "range": format!("{}/{}", r.base, r.prefix),
                "up": r.up,
                "silent": r.silent,
                "open": r.open,
                "todo": c[0],
                "clean": c[1],
                "vuln": c[2],
                "bookmarks": bkm.get(&(u32::from(r.base) >> shift)).copied().unwrap_or(0),
                "services": r
                    .services
                    .iter()
                    .map(|(n, c)| format!("{n} x{c}"))
                    .collect::<Vec<_>>()
                    .join(", "),
            })
        })
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "prefix": prefix,
        "count": ranges.len(),
        "ranges": ranges,
    }))
}

/// Minimal percent-decoding for the path (the ip segment): %XX only —
/// everything else passes through.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hi = (b.get(i + 1)).and_then(|c| (*c as char).to_digit(16));
            let lo = (b.get(i + 2)).and_then(|c| (*c as char).to_digit(16));
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_perim(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("rustrawl-web-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Registry: 127.0.0.5 (ssh 22 + http 80), 127.0.0.7 (ssh 22), plus a
    /// version carrying HTML that must come back JSON-escaped by serde.
    fn seeded(tag: &str) -> std::path::PathBuf {
        use crate::discovery::db::{Answer, Stage};
        let out = temp_perim(tag);
        let mut db = Db::open(&out).unwrap();
        db.set_run_id("scan_test");
        for ip in ["127.0.0.5", "127.0.0.7"] {
            let ip: Ipv4Addr = ip.parse().unwrap();
            db.record_host(ip, Stage::Scan, true, 2);
            db.record_result(ip, 22, Stage::Scan, Answer::Open);
            db.record_service(ip, 22, "ssh", "OpenSSH 9.2p1");
        }
        let ip5: Ipv4Addr = "127.0.0.5".parse().unwrap();
        db.record_result(ip5, 80, Stage::Scan, Answer::Open);
        db.record_service(ip5, 80, "http", "<script>alert(1)</script>");
        db.record_name(ip5, "web01.corp.example.com", "dns-ptr");
        db.record_name(ip5, "web01", "tls");
        db.flush().unwrap();
        out
    }

    fn body(resp: &Response) -> String {
        String::from_utf8(resp.body.clone()).unwrap()
    }

    /// A fabricated capture run — the exact files `rustrawl web` writes:
    /// two manifest rows (one clean with a shot, one conn-refused), the
    /// state file, and the shot bytes under shots/. Returns (run_id,
    /// shot_hex), the shape the /api/captures* and /shots routes read.
    fn fabricate_capture_run(out: &Path, stamp: &str) -> (String, String) {
        let run_id = format!("web_{stamp}");
        let dir = out.join("runs").join(&run_id);
        std::fs::create_dir_all(dir.join("shots")).unwrap();
        let png = b"\x89PNG\r\n\x1a\nfabricated-frame-bytes";
        let shot_hex = hex(&sha256(png));
        std::fs::write(dir.join("shots").join(format!("{shot_hex}.png")), png).unwrap();
        let rows = serde_json::json!([
            {
                "url": "http://127.0.0.5:80/", "ip": "127.0.0.5", "port": 80,
                "scheme": "http", "status": 200, "title": "Big Router",
                "label": "pfSense firewall", "error": "", "detail": "",
                "shot": format!("{shot_hex}.png"), "sha256": shot_hex,
                "dup_of": "",
                "headers": "HTTP/1.1 200 OK\r\nServer: testd\r\n\r\n",
                "ms": 12, "at": 1767225600
            },
            {
                "url": "https://127.0.0.5:8443/", "ip": "127.0.0.5", "port": 8443,
                "scheme": "https", "status": 0, "title": "", "label": "",
                "error": "conn-refused", "detail": "conn-refused", "shot": "",
                "sha256": "", "dup_of": "", "headers": "", "ms": 3,
                "at": 1767225600
            }
        ]);
        let mut manifest = String::new();
        for r in rows.as_array().unwrap() {
            manifest.push_str(&serde_json::to_string(r).unwrap());
            manifest.push('\n');
        }
        std::fs::write(dir.join(crate::capture::MANIFEST_FILE), manifest).unwrap();
        let state = serde_json::json!({
            "run": run_id, "started_at": 1767225600, "timeout_secs": 7,
            "threads": 4, "done": true, "interrupted": false,
            "chrome": "chromium",
            "targets": [
                {"ip": "127.0.0.5", "port": 80, "scheme": "http", "done": true, "error": ""},
                {"ip": "127.0.0.5", "port": 8443, "scheme": "https", "done": true,
                 "error": "conn-refused"}
            ]
        });
        std::fs::write(
            dir.join(crate::capture::STATE_FILE),
            serde_json::to_string_pretty(&state).unwrap(),
        )
        .unwrap();
        (run_id, shot_hex)
    }

    #[test]
    fn capture_routes_serve_runs_rows_and_shots() {
        let out = seeded("captures");
        // nothing yet: an empty list, not an error
        let resp = route("GET", "/api/captures", &out);
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["count"], 0);

        let (run, shot_hex) = fabricate_capture_run(&out, "2026-01-01_120001");
        let resp = route("GET", "/api/captures", &out);
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["count"], 1);
        assert_eq!(v["runs"][0]["run"], run.as_str());
        assert_eq!(v["runs"][0]["done"], true);
        assert_eq!(v["runs"][0]["total"], 2);
        assert_eq!(v["runs"][0]["done_count"], 2);
        assert_eq!(v["runs"][0]["errors"], 1);

        let resp = route("GET", &format!("/api/captures/{run}"), &out);
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["done"], true);
        assert_eq!(v["total"], 2);
        assert_eq!(v["targets"].as_array().unwrap().len(), 2);
        assert_eq!(v["targets"][0]["title"], "Big Router");
        assert_eq!(v["targets"][0]["label"], "pfSense firewall");
        assert_eq!(
            v["targets"][0]["shot_url"],
            format!("/shots/{run}/{shot_hex}.png")
        );
        assert_eq!(v["targets"][0]["run"], run.as_str());
        assert_eq!(v["targets"][1]["error"], "conn-refused");
        assert_eq!(v["targets"][1]["shot_url"], serde_json::Value::Null);

        // the screenshot itself, by digest
        let resp = route("GET", &format!("/shots/{run}/{shot_hex}.png"), &out);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type, "image/png");
        assert!(resp.body.starts_with(b"\x89PNG\r\n\x1a\n"));

        // every shape outside the pins is a 404, never a path
        for bad in [
            "/api/captures/scan_2026-01-01_120001",
            "/api/captures/web_2026-01-01",
            "/api/captures/web_../../etc",
            format!("/shots/{run}/short.png").as_str(),
            format!("/shots/{run}/{}.png", "z".repeat(64)).as_str(),
            format!("/shots/{run}/{shot_hex}.png/../x").as_str(),
            format!("/shots/junk/{shot_hex}.png").as_str(),
            format!("/shots/web_2026-01-01_999999/{shot_hex}.png").as_str(),
        ] {
            let resp = route("GET", bad, &out);
            assert_eq!(resp.status, 404, "{bad} must be a 404");
        }
        // an unknown-but-valid run id reads as empty rows, not a crash
        let resp = route("GET", "/api/captures/web_2026-01-01_230000", &out);
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["targets"].as_array().unwrap().len(), 0);
    }

    /// The per-asset capture route end to end against a dead port: guard,
    /// registry gates, one honest run, the sheet picking it up — and the
    /// perimeter lock refusing a second click while someone else holds it.
    #[test]
    fn capture_post_shoots_one_asset() {
        use crate::discovery::db::{Answer, Stage};
        use fs2::FileExt;
        let out = temp_perim("capshoot");
        let mut db = Db::open(&out).unwrap();
        db.set_run_id("t");
        let ip5: Ipv4Addr = "127.0.0.5".parse().unwrap();
        let ip6: Ipv4Addr = "127.0.0.6".parse().unwrap();
        db.record_host(ip5, Stage::Scan, true, 2);
        db.record_host(ip6, Stage::Scan, true, 2);
        // .5's one web service, on a port nothing here listens on
        db.record_result(ip5, 39197, Stage::Scan, Answer::Open);
        db.record_service(ip5, 39197, "http", "bait 1.0");
        db.flush().unwrap();
        drop(db);

        // the write guard first: a bare POST is a 403
        let resp = route_req(
            "POST",
            "/api/capture",
            br#"{"ip":"127.0.0.5"}"#,
            false,
            &out,
        );
        assert_eq!(resp.status, 403);
        // junk body, junk ip
        let resp = route_req("POST", "/api/capture", b"not json", true, &out);
        assert_eq!(resp.status, 400);
        assert!(body(&resp).contains("invalid JSON"));
        let resp = route_req("POST", "/api/capture", br#"{"ip":"nope"}"#, true, &out);
        assert_eq!(resp.status, 400);
        assert!(body(&resp).contains("ip must be an IPv4 address string"));
        // up-ness is the registry's call, like a rescan
        let resp = route_req(
            "POST",
            "/api/capture",
            br#"{"ip":"127.0.0.99"}"#,
            true,
            &out,
        );
        assert_eq!(resp.status, 400);
        assert!(body(&resp).contains("not an up host in this registry"));
        // up but nothing web on it
        let resp = route_req("POST", "/api/capture", br#"{"ip":"127.0.0.6"}"#, true, &out);
        assert_eq!(resp.status, 400);
        assert!(body(&resp).contains("no http/https service for 127.0.0.6"));

        // happy path: one click, one small run, the refused row back
        let resp = route_req("POST", "/api/capture", br#"{"ip":"127.0.0.5"}"#, true, &out);
        assert_eq!(resp.status, 200, "{}", body(&resp));
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["ip"], "127.0.0.5");
        assert_eq!(v["total"], 1);
        let run = v["run"].as_str().unwrap().to_string();
        assert!(crate::capture::valid_run_id(&run), "{run}");
        assert!(run.starts_with("web_"), "{run}");
        let rows = v["captured"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["port"], 39197);
        assert_eq!(rows[0]["error"], "conn-refused");
        assert_eq!(rows[0]["run"], run.as_str());
        // evidence on disk: the pass really finished its state file
        let st = crate::capture::read_cap_state(&out, &run).unwrap();
        assert!(st.done && !st.interrupted);
        assert_eq!(st.targets.len(), 1);
        assert!(st.targets[0].done);
        // the sheet serves it
        let resp = route("GET", "/api/host/127.0.0.5", &out);
        assert_eq!(resp.status, 200);
        assert!(body(&resp).contains(&run), "sheet carries the fresh run");

        // the lock held by someone else (the CLI pass, a scan) is a 409
        let lock = std::fs::File::create(out.join("run.lock")).unwrap();
        lock.try_lock_exclusive().unwrap();
        let resp = route_req("POST", "/api/capture", br#"{"ip":"127.0.0.5"}"#, true, &out);
        assert_eq!(resp.status, 409, "{}", body(&resp));
        assert!(body(&resp).contains("one scan per perimeter"));
        drop(lock);
    }

    #[test]
    fn host_sheet_carries_the_host_captures() {
        let out = seeded("sheet-caps");
        fabricate_capture_run(&out, "2026-01-01_120002");
        let resp = route("GET", "/api/host/127.0.0.5", &out);
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["captures"].as_array().unwrap().len(), 2);
        assert_eq!(v["captures"][0]["run"], "web_2026-01-01_120002");
        assert_eq!(v["captures"][0]["title"], "Big Router");
        // the other host has no capture rows
        let resp = route("GET", "/api/host/127.0.0.7", &out);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["captures"].as_array().unwrap().len(), 0);
    }

    /// Up hosts (sweep stage) across two /16s so the /8, /16, /24 and /32
    /// buckets all differ — the fixture the re-bucketing and the
    /// batch-rescan refusals read.
    fn seeded_swept(tag: &str) -> std::path::PathBuf {
        use crate::discovery::db::Stage;
        let out = temp_perim(tag);
        let mut db = Db::open(&out).unwrap();
        db.set_run_id("sweep_test");
        for ip in ["127.0.0.5", "127.0.0.7", "127.1.0.9"] {
            let ip: Ipv4Addr = ip.parse().unwrap();
            db.record_host(ip, Stage::Sweep, true, 2);
        }
        db.flush().unwrap();
        out
    }

    #[test]
    fn the_logo_serves_as_a_static_png() {
        let out = temp_perim("logo");
        let resp = route("GET", "/logo.png", &out);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type, "image/png");
        assert!(
            resp.body.starts_with(b"\x89PNG\r\n\x1a\n"),
            "the embedded asset is a PNG: {} bytes",
            resp.body.len()
        );
    }

    #[test]
    fn api_serves_hosts_services_and_escapes() {
        let out = seeded("api");
        let resp = route("GET", "/api/hosts", &out);
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["count"], 2);
        assert_eq!(v["hosts"][0]["stages"], "scan");

        let resp = route("GET", "/api/services", &out);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["count"], 3);
        // HTML in a banner rides through the JSON as data — the browser
        // never executes it because the page renders every field through
        // textContent and the response is application/json. The contract
        // pinned here: the string survives the round-trip intact.
        assert!(
            body(&resp).contains("<script>alert(1)</script>"),
            "banner data must ride through the JSON untouched: {}",
            body(&resp)
        );
    }

    #[test]
    fn host_and_hosts_json_carry_the_names() {
        let out = seeded("names");
        // the overview: names ride along in (ip, name) table order
        let resp = route("GET", "/api/hosts", &out);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["hosts"][0]["ip"], "127.0.0.5");
        assert_eq!(
            v["hosts"][0]["names"],
            serde_json::json!(["web01", "web01.corp.example.com"])
        );
        let seven = v["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["ip"] == "127.0.0.7")
            .unwrap();
        assert_eq!(seven["names"], serde_json::json!([]));

        // the sheet: full (name, source, seen, run) tuples
        let resp = route("GET", "/api/host/127.0.0.5", &out);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(
            v["names"],
            serde_json::json!([
                {"name": "web01", "source": "tls", "seen": v["names"][0]["seen"], "run": "scan_test"},
                {"name": "web01.corp.example.com", "source": "dns-ptr", "seen": v["names"][1]["seen"], "run": "scan_test"},
            ])
        );

        // a host the registry never saw: detail null, no names field to render
        let resp = route("GET", "/api/host/127.0.0.9", &out);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert!(v["detail"].is_null());
    }

    #[test]
    fn host_sheet_carries_the_evidence_section() {
        let out = seeded("sheet");
        let resp = route("GET", "/api/host/127.0.0.5", &out);
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["services"].as_array().unwrap().len(), 2);
        // no scan run on this perimeter → an empty stack + the note, verbatim
        assert!(v["evidence"].as_array().unwrap().is_empty(), "{v}");
        assert_eq!(
            v["evidence_note"].as_str().unwrap(),
            "no scan run on this perimeter yet"
        );

        // a fabricated scan run: state file + captured .nmap with the block
        let runs = crate::discovery::state::runs_dir(&out);
        let run = runs.join("scan_2026-10-09_120000");
        std::fs::create_dir_all(run.join("scans")).unwrap();
        std::fs::write(
            run.join("scan_state.json"),
            r#"{"ports":[80],"nmap_args":"","queue_hash":0,"chunks":[{"hosts":["127.0.0.5","127.0.0.7"],"done":true,"attempts":0,"skipped":false}],"done":true}"#,
        )
        .unwrap();
        std::fs::write(
            run.join("scans").join("chunk-0000.nmap"),
            "Nmap scan report for 127.0.0.5\nHost is up (0.001s latency).\nPORT   STATE SERVICE\n22/tcp open  ssh\n",
        )
        .unwrap();
        std::fs::write(
            run.join("scans").join("chunk-0000.argv"),
            "nmap -Pn -n --open -oA scans/chunk-0000 -sT --stats-every 30s -sV 127.0.0.5\n",
        )
        .unwrap();
        // a second, older run queues the host too but its capture is empty —
        // the stack tells the truth about that pass instead of hiding it
        let old = runs.join("scan_2026-10-08_090000");
        std::fs::create_dir_all(old.join("scans")).unwrap();
        std::fs::write(
            old.join("scan_state.json"),
            r#"{"ports":[80],"nmap_args":"","queue_hash":0,"chunks":[{"hosts":["127.0.0.5"],"done":true,"attempts":0,"skipped":false}],"done":true}"#,
        )
        .unwrap();
        std::fs::write(old.join("scans").join("chunk-0000.nmap"), "nothing here").unwrap();

        let resp = route("GET", "/api/host/127.0.0.5", &out);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        let ev = v["evidence"].as_array().unwrap();
        assert_eq!(ev.len(), 2, "{v}");
        assert_eq!(ev[0]["run"], "scan_2026-10-09_120000", "newest first: {v}");
        assert_eq!(ev[0]["chunk"], 0);
        assert_eq!(ev[0]["has_report"], true);
        assert!(
            ev[0]["text"]
                .as_str()
                .unwrap()
                .contains("Nmap scan report for 127.0.0.5"),
            "{}",
            ev[0]["text"]
        );
        assert!(ev[0]["text"].as_str().unwrap().contains("22/tcp open  ssh"));
        // the newest run captured its command, the older one predates the
        // capture - its block carries an empty cmd and the page hides the line
        assert_eq!(
            ev[0]["cmd"],
            "nmap -Pn -n --open -oA scans/chunk-0000 -sT --stats-every 30s -sV 127.0.0.5",
            "{v}"
        );
        assert_eq!(ev[1]["cmd"], "", "{}", ev[1]["cmd"]);
        assert_eq!(ev[1]["run"], "scan_2026-10-08_090000");
        assert_eq!(ev[1]["has_report"], false);
        assert!(
            ev[1]["text"]
                .as_str()
                .unwrap()
                .contains("holds no report for 127.0.0.5"),
            "{}",
            ev[1]["text"]
        );
        // a non-empty stack needs no note
        assert!(v["evidence_note"].is_null(), "{v}");

        // queued but absent from the capture → a per-run note block
        let resp = route("GET", "/api/host/127.0.0.7", &out);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        let ev = v["evidence"].as_array().unwrap();
        assert_eq!(ev.len(), 1, "{v}");
        assert_eq!(ev[0]["has_report"], false);
        assert!(
            ev[0]["text"]
                .as_str()
                .unwrap()
                .contains("holds no report for 127.0.0.7"),
            "{}",
            ev[0]["text"]
        );

        // never queued anywhere → an empty stack + the discovery-only note
        let resp = route("GET", "/api/host/127.0.0.6", &out);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert!(v["evidence"].as_array().unwrap().is_empty(), "{v}");
        assert_eq!(
            v["evidence_note"].as_str().unwrap(),
            "127.0.0.6 was never queued in a scan run (discovery-only host)"
        );
    }

    #[test]
    fn host_sheet_shape_matches_what_the_page_reads() {
        let out = seeded("shape");
        // A hit: the detail is flattened — stages/ports/services/evidence at
        // the top level, no "detail" key. The page reads exactly these; a
        // key drift here is an invisible "nothing in the registry" for
        // every host (this test exists because that once shipped green).
        let v: serde_json::Value =
            serde_json::from_str(&body(&route("GET", "/api/host/127.0.0.5", &out))).unwrap();
        assert!(v["stages"].is_array(), "{v}");
        assert!(v["ports"].is_array(), "{v}");
        assert!(v["services"].is_array(), "{v}");
        assert!(v["evidence"].is_array(), "{v}");
        assert!(v["evidence_note"].is_string(), "{v}");
        assert!(v.get("detail").is_none(), "no detail key on a hit: {v}");

        // Unknown host: detail null + the evidence fallback note.
        let v: serde_json::Value =
            serde_json::from_str(&body(&route("GET", "/api/host/127.0.0.99", &out))).unwrap();
        assert!(v["detail"].is_null(), "{v}");
        assert!(
            v["evidence_note"].as_str().unwrap().contains("no scan run"),
            "{v}"
        );
    }

    #[test]
    fn status_folds_counts_and_the_runs_table() {
        let out = seeded("status");
        let resp = route("GET", "/api/status", &out);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["up"], 2);
        assert_eq!(v["services"], 3);
        assert_eq!(v["perimeter"], out.file_name().unwrap().to_str().unwrap());
        // this fixture has no runs/ directory — the runs table still renders
        assert!(v["runs_text"].is_string(), "{}", v["runs_text"]);
    }

    #[test]
    fn ranges_buckets_the_registry_at_a_fixed_24() {
        let out = seeded("ranges");
        let resp = route("GET", "/api/ranges", &out);
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["prefix"], 24);
        assert_eq!(v["count"], 1);
        let row = &v["ranges"][0];
        assert_eq!(row["range"], "127.0.0.0/24");
        // this fixture's hosts are up in the scan stage only: counted via their
        // services, not as up hosts
        assert_eq!(row["up"], 0);
        assert_eq!(row["silent"], 0);
        assert_eq!(row["open"], 3);
        assert_eq!(row["services"], "ssh x2, http x1");
    }

    #[test]
    fn ranges_rebuckets_at_8_16_24_and_32() {
        let out = seeded_swept("rbucket");
        // one mark: its tally must follow the bucket key at every zoom
        {
            let mut db = Db::open(&out).unwrap();
            db.set_run_id("triage_mark");
            db.record_triage("127.0.0.5".parse().unwrap(), Some("todo"), "");
            db.flush().unwrap();
        }
        let v = |p: &str| {
            let resp = route("GET", p, &out);
            assert_eq!(resp.status, 200, "{p}");
            serde_json::from_str::<serde_json::Value>(&body(&resp)).unwrap()
        };
        let v24 = v("/api/ranges");
        assert_eq!(v24["prefix"], 24);
        assert_eq!(v24["count"], 2);
        let row = v24["ranges"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["range"] == "127.0.0.0/24")
            .unwrap();
        assert_eq!(row["up"], 2);
        assert_eq!(row["todo"], 1);

        let v16 = v("/api/ranges/16");
        assert_eq!(v16["prefix"], 16);
        assert_eq!(v16["count"], 2);
        let arr = v16["ranges"].as_array().unwrap();
        let a = arr.iter().find(|r| r["range"] == "127.0.0.0/16").unwrap();
        let b = arr.iter().find(|r| r["range"] == "127.1.0.0/16").unwrap();
        assert_eq!(a["up"], 2);
        assert_eq!(b["up"], 1);
        assert_eq!(a["todo"], 1, "the mark rides the /16 it belongs to");
        assert_eq!(b["todo"], 0);

        let v8 = v("/api/ranges/8");
        assert_eq!(v8["prefix"], 8);
        assert_eq!(v8["count"], 1);
        assert_eq!(v8["ranges"][0]["range"], "127.0.0.0/8");
        assert_eq!(v8["ranges"][0]["up"], 3);

        let v32 = v("/api/ranges/32");
        assert_eq!(v32["count"], 3);
        assert!(v32["ranges"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["up"] == 1));

        // scan-stage hosts (the seeded fixture) are not up at any zoom:
        // re-bucketing must not widen the up definition
        let scan_only = seeded("rbucket-scan");
        let resp = route("GET", "/api/ranges/16", &scan_only);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["ranges"][0]["up"], 0);
    }

    #[test]
    fn ranges_prefix_routes_validate_their_segment() {
        let out = seeded("rpref");
        for ok in [
            "/api/ranges/8",
            "/api/ranges/16",
            "/api/ranges/24",
            "/api/ranges/32",
        ] {
            assert_eq!(route("GET", ok, &out).status, 200, "{ok}");
        }
        for bad in [
            "/api/ranges/0",
            "/api/ranges/33",
            "/api/ranges/junk",
            "/api/ranges/",
        ] {
            assert_eq!(route("GET", bad, &out).status, 404, "{bad}");
        }
        assert_eq!(route("POST", "/api/ranges/16", &out).status, 405);
    }

    #[test]
    fn exports_serve_bodies_and_download_headers() {
        let out = seeded("exports");
        let resp = route("GET", "/api/export/services.csv", &out);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type, "text/csv");
        assert_eq!(resp.filename, Some("rustrawl-services.csv"));
        let text = body(&resp);
        let mut lines = text.lines();
        assert_eq!(
            lines.next(),
            Some("ip,port,proto,service,version,last_seen,run"),
            "{text}"
        );
        assert_eq!(lines.filter(|l| !l.is_empty()).count(), 3, "{text}");

        let resp = route("GET", "/api/export/scan.xml", &out);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type, "application/xml");
        assert_eq!(resp.filename, Some("rustrawl-scan.xml"));
        let text = body(&resp);
        assert!(text.starts_with("<?xml"), "{text}");
        assert!(text.contains("<nmaprun"));
        assert!(text.contains("127.0.0.5"));

        for (p, name) in [
            ("/api/export/services.txt", "rustrawl-services.txt"),
            ("/api/export/services.xml", "rustrawl-services.xml"),
            ("/api/export/hosts.txt", "rustrawl-hosts.txt"),
        ] {
            let resp = route("GET", p, &out);
            assert_eq!(resp.status, 200, "{p}");
            assert_eq!(resp.filename, Some(name), "{p}");
        }
        // the wire form carries the attachment header
        let head =
            String::from_utf8(route("GET", "/api/export/services.csv", &out).into_http()).unwrap();
        assert!(
            head.contains(
                "Content-Disposition: attachment; filename=\"rustrawl-services.csv\"\r\n"
            ),
            "{head}"
        );
        // unknown export → 404, no registry → 409 (the POST variants of
        // these pins live in export_posts_render_displayed_rows)
        assert_eq!(route("GET", "/api/export/nope", &out).status, 404);
        let empty = temp_perim("exports-empty");
        assert_eq!(route("GET", "/api/export/hosts.txt", &empty).status, 409);

        // up semantics: the seeded hosts are scan-stage only, so hosts.txt
        // is empty there while the swept fixture lists every host in order
        let t = body(&route("GET", "/api/export/hosts.txt", &out));
        assert!(t.trim().is_empty(), "{t:?}");
        let swept = seeded_swept("exports-swept");
        let t = body(&route("GET", "/api/export/hosts.txt", &swept));
        let lines: Vec<&str> = t.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines, vec!["127.0.0.5", "127.0.0.7", "127.1.0.9"], "{t:?}");
    }

    /// Process-global scan state (CURRENT_MANUAL_RUN, SCANNING) is shared by
    /// every test binary thread - tests that touch it serialize here.
    static TEST_RUN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn export_posts_render_displayed_rows() {
        let out = seeded("exportposts");
        // rows in a deliberately non-numeric order: the export renders them
        // in body order (screen order), not registry order
        let rows = br#"{"rows":[
            {"ip":"127.0.0.5","port":80,"name":"http","version":"<b>1.2 &amp; 3</b>","seen":0,"run":"scan_test"},
            {"ip":"127.0.0.5","port":22,"name":"ssh","version":"OpenSSH 9.2p1","seen":0,"run":"scan_test"},
            {"ip":"127.0.0.7","port":22,"name":"ssh","version":"OpenSSH 9.2p1","seen":0,"run":"scan_test"}
        ]}"#;
        let resp = route_req("POST", "/api/export/services.csv", rows, false, &out);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type, "text/csv");
        assert_eq!(resp.filename, Some("rustrawl-services-displayed.csv"));
        assert_eq!(
            body(&resp),
            "ip,port,proto,service,version,last_seen,run\n\
             127.0.0.5,80,tcp,http,<b>1.2 &amp; 3</b>,1970-01-01 00:00:00 UTC,scan_test\n\
             127.0.0.5,22,tcp,ssh,OpenSSH 9.2p1,1970-01-01 00:00:00 UTC,scan_test\n\
             127.0.0.7,22,tcp,ssh,OpenSSH 9.2p1,1970-01-01 00:00:00 UTC,scan_test\n"
        );

        // txt collapses the displayed rows to their distinct hosts, numeric
        // order - the same rows come back as two lines, not three
        let resp = route_req("POST", "/api/export/services.txt", rows, false, &out);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.filename, Some("rustrawl-services-displayed.txt"));
        assert_eq!(body(&resp), "127.0.0.5\n127.0.0.7\n");

        // xml pins the escaping on the row fields
        let resp = route_req("POST", "/api/export/services.xml", rows, false, &out);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type, "application/xml");
        assert_eq!(resp.filename, Some("rustrawl-services-displayed.xml"));
        let text = body(&resp);
        assert!(text.contains("<services count=\"3\">"), "{text}");
        assert!(
            text.contains("name=\"http\" version=\"&lt;b&gt;1.2 &amp;amp; 3&lt;/b&gt;\""),
            "{text}"
        );
        assert!(text.trim_end().ends_with("</services>"), "{text}");

        // scan.xml over an ip set: nmap format, only those hosts
        let resp = route_req(
            "POST",
            "/api/export/scan.xml",
            br#"{"ips":["127.0.0.7","127.0.0.5","127.0.0.7"]}"#,
            false,
            &out,
        );
        assert_eq!(resp.status, 200);
        assert_eq!(resp.filename, Some("rustrawl-scan-displayed.xml"));
        let text = body(&resp);
        assert!(text.starts_with("<?xml"), "{text}");
        assert!(text.contains("<nmaprun"), "{text}");
        assert!(text.contains("127.0.0.5"), "{text}");
        assert!(text.contains("127.0.0.7"), "{text}");
        let (five, seven) = (
            text.matches("127.0.0.5").count(),
            text.matches("127.0.0.7").count(),
        );
        assert_eq!(five, seven, "one host block each: {text}");

        // hosts.txt over an ip set: deduped, numeric order, one per line
        let resp = route_req(
            "POST",
            "/api/export/hosts.txt",
            br#"{"ips":["127.0.0.7","127.0.0.5","127.0.0.5"]}"#,
            false,
            &out,
        );
        assert_eq!(resp.status, 200);
        assert_eq!(resp.filename, Some("rustrawl-hosts-displayed.txt"));
        assert_eq!(body(&resp), "127.0.0.5\n127.0.0.7\n");

        // an ip set to a rows format is filled from the registry: the
        // seeded three services, registry (ip, port) order
        let resp = route_req(
            "POST",
            "/api/export/services.csv",
            br#"{"ips":["127.0.0.7","127.0.0.5"]}"#,
            false,
            &out,
        );
        assert_eq!(resp.status, 200);
        let text = body(&resp);
        let mut lines = text.lines().filter(|l| !l.is_empty());
        assert_eq!(
            lines.next(),
            Some("ip,port,proto,service,version,last_seen,run")
        );
        let rows: Vec<Vec<&str>> = lines.map(|l| l.split(',').collect()).collect();
        assert_eq!(rows.len(), 3, "{text}");
        assert_eq!((rows[0][0], rows[0][1]), ("127.0.0.5", "22"));
        assert_eq!((rows[1][0], rows[1][1]), ("127.0.0.5", "80"));
        assert_eq!((rows[2][0], rows[2][1]), ("127.0.0.7", "22"));
        // the version field rides through csv_field: the banner string lands
        // with its <b> intact (CSV quoting only guards , and ")
        assert_eq!(rows[1][3], "http", "{text}");
    }

    #[test]
    fn export_posts_reject_junk() {
        let out = seeded("exportjunk");
        let post = |b: &[u8]| route_req("POST", "/api/export/services.csv", b, false, &out);
        assert_eq!(post(b"{nope").status, 400);
        assert!(body(&post(b"{nope")).contains("invalid JSON"));
        assert_eq!(post(b"{}").status, 400);
        assert!(body(&post(b"{}"))
            .contains("give rows or ips - the filtered export renders what the page displays"));
        // each junk entry names its index
        assert!(
            body(&post(br#"{"rows":[{"ip":"nonsense"}]}"#)).contains("rows[0]: bad ip"),
            "{}",
            body(&post(br#"{"rows":[{"ip":"nonsense"}]}"#))
        );
        assert!(
            body(&post(br#"{"rows":[{"ip":"127.0.0.5","port":70000}]}"#))
                .contains("rows[0]: port out of range")
        );
        assert!(
            body(&post(br#"{"ips":["127.0.0.5","x"]}"#)).contains("ips[1]: bad ip"),
            "{}",
            body(&post(br#"{"ips":["127.0.0.5","x"]}"#))
        );
        assert!(body(&post(br#"{"rows":"nope"}"#)).contains("rows must be an array"));
        assert!(body(&post(br#"{"ips":42}"#)).contains("ips must be an array"));
        // these rode in with no X-Rustrawl and got read-shaped 400s, never
        // the 403 the write routes would give - the exports are reads
        assert_eq!(
            route_req("POST", "/api/export/nope", b"{}", false, &out).status,
            405
        );
        let empty = temp_perim("exportjunk-empty");
        // the 409 needs a parseable body: the shape check runs first
        assert_eq!(
            route_req(
                "POST",
                "/api/export/hosts.txt",
                br#"{"ips":["127.0.0.5"]}"#,
                false,
                &empty
            )
            .status,
            409
        );
        assert!(body(&route_req(
            "POST",
            "/api/export/hosts.txt",
            br#"{"ips":["127.0.0.5"]}"#,
            false,
            &empty
        ))
        .contains("no registry here"));
    }

    #[test]
    fn up_ips_resolves_range_intersections() {
        let out = seeded_swept("upips");
        // two /16s seeded: .5 and .7 land in 127.0.0/16, 127.1.0.9 in 127.1/16
        let resp = route_req(
            "POST",
            "/api/up-ips",
            br#"{"range":"127.0.0.0/16"}"#,
            false,
            &out,
        );
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["count"], 2);
        assert_eq!(v["ips"], serde_json::json!(["127.0.0.5", "127.0.0.7"]));

        let resp = route_req(
            "POST",
            "/api/up-ips",
            br#"{"range":"127.0.0.0/8"}"#,
            false,
            &out,
        );
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["count"], 3);
        assert_eq!(
            v["ips"],
            serde_json::json!(["127.0.0.5", "127.0.0.7", "127.1.0.9"])
        );

        // nothing up inside the range is a 200 with an empty list - the tab
        // shows an empty queue, the run button refuses on its own terms
        let resp = route_req(
            "POST",
            "/api/up-ips",
            br#"{"range":"127.9.0.0/16"}"#,
            false,
            &out,
        );
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["count"], 0);
        assert_eq!(v["ips"], serde_json::json!([]));

        // junk is named, and reads need no guard header
        let t = body(&route_req(
            "POST",
            "/api/up-ips",
            br#"{"range":"junk"}"#,
            false,
            &out,
        ));
        assert!(t.contains("bad range - use a.b.c.d/p"), "{t}");
        assert!(body(&route_req("POST", "/api/up-ips", b"{}", false, &out)).contains("give range"));
        assert!(
            body(&route_req("POST", "/api/up-ips", b"{nope", false, &out)).contains("invalid JSON")
        );

        // a scan-stage registry has no sweep-up hosts at all
        let scanonly = seeded("upips-scanonly");
        let resp = route_req(
            "POST",
            "/api/up-ips",
            br#"{"range":"127.0.0.0/8"}"#,
            false,
            &scanonly,
        );
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["count"], 0);

        // no registry → 409, like every other registry read
        let empty = temp_perim("upips-empty");
        let resp = route_req(
            "POST",
            "/api/up-ips",
            br#"{"range":"127.0.0.0/8"}"#,
            false,
            &empty,
        );
        assert_eq!(resp.status, 409);
        assert!(body(&resp).contains("no registry here"));
    }

    #[test]
    fn scan_output_tails_the_manual_capture() {
        let _guard = TEST_RUN_LOCK.lock().unwrap();
        let out = seeded("scanout");

        // no manual run yet: an empty payload, not an error
        crate::scan::CURRENT_MANUAL_RUN.lock().unwrap().take();
        let resp = route("GET", "/api/scan/output", &out);
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["run"], serde_json::Value::Null);
        assert_eq!(v["running"], false);
        assert_eq!(v["size"], 0);
        assert_eq!(v["text"], "");

        // a run id set and a capture on disk: the tail comes back whole
        let content = "fake nmap on -sV -v 127.0.0.5\nStarting Nmap 7.94\n";
        let scans = crate::discovery::state::runs_dir(&out)
            .join("manual_run1")
            .join("scans");
        std::fs::create_dir_all(&scans).unwrap();
        std::fs::write(scans.join("chunk-0000.out"), content).unwrap();
        *crate::scan::CURRENT_MANUAL_RUN.lock().unwrap() = Some("manual_run1".to_string());
        let resp = route("GET", "/api/scan/output", &out);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["run"], "manual_run1");
        assert_eq!(v["running"], false);
        assert_eq!(v["size"], content.len() as u64);
        assert_eq!(v["text"], content);
        // the command rides along once the chunk's .argv capture exists
        assert_eq!(v["cmd"], "", "{v}");

        // while a scan holds the perimeter the flag says so - and /api/status
        // carries the same run id for a page that navigated away
        SCANNING.store(true, Ordering::Relaxed);
        let resp = route("GET", "/api/scan/output", &out);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["running"], true);
        let resp = route("GET", "/api/status", &out);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["scanning"], true);
        assert_eq!(v["run"], "manual_run1");
        SCANNING.store(false, Ordering::Relaxed);

        // the read is a tail: a capture bigger than the window reports the
        // full size but returns only the last TAIL_BYTES
        let big = "x".repeat(TAIL_BYTES as usize + 100);
        std::fs::write(scans.join("chunk-0000.out"), &big).unwrap();
        let resp = route("GET", "/api/scan/output", &out);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["size"], (TAIL_BYTES + 100));
        assert_eq!(v["text"].as_str().unwrap().len(), TAIL_BYTES as usize);

        // a run id with no capture on disk: empty tail, not an error
        *crate::scan::CURRENT_MANUAL_RUN.lock().unwrap() = Some("manual_run2".to_string());
        let resp = route("GET", "/api/scan/output", &out);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["run"], "manual_run2");
        assert_eq!(v["size"], 0);
        assert_eq!(v["text"], "");

        // the running command: the chunk's .argv capture, one line
        std::fs::write(
            crate::discovery::state::runs_dir(&out)
                .join("manual_run1")
                .join("scans")
                .join("chunk-0000.argv"),
            "nmap -Pn -n --open -oA scans/chunk-0000 -sT --stats-every 30s -sV 127.0.0.5\n",
        )
        .unwrap();
        *crate::scan::CURRENT_MANUAL_RUN.lock().unwrap() = Some("manual_run1".to_string());
        let resp = route("GET", "/api/scan/output", &out);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(
            v["cmd"], "nmap -Pn -n --open -oA scans/chunk-0000 -sT --stats-every 30s -sV 127.0.0.5",
            "{v}"
        );
        // the token-per-line shape the test nmap stand-in writes reads the same
        std::fs::write(
            crate::discovery::state::runs_dir(&out)
                .join("manual_run1")
                .join("scans")
                .join("chunk-0000.argv"),
            "nmap\n-Pn\n-n\n127.0.0.5\n",
        )
        .unwrap();
        let resp = route("GET", "/api/scan/output", &out);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["cmd"], "nmap -Pn -n 127.0.0.5", "{v}");

        crate::scan::CURRENT_MANUAL_RUN.lock().unwrap().take();
    }

    #[test]
    fn scan_post_batch_shapes_refuse_before_spawning() {
        let post = |out: &std::path::Path, b: &[u8]| route_req("POST", "/api/scan", b, true, out);
        let out = seeded("scanbatch");
        // exactly one target shape
        assert!(body(&post(&out, b"{}")).contains("exactly one of ip, range, ips"));
        assert!(
            body(&post(&out, br#"{"ip":"127.0.0.5","range":"127.0.0.0/24"}"#))
                .contains("exactly one of ip, range, ips")
        );
        // bad range text is named
        assert!(body(&post(&out, br#"{"range":"junk"}"#)).contains("bad range"));
        // a range over a registry whose hosts are scan-stage only: nothing up
        assert!(body(&post(&out, br#"{"range":"127.0.0.0/8"}"#)).contains("no up host"));
        // an ips list nothing survives
        assert!(body(&post(&out, br#"{"ips":["127.0.0.99"]}"#)).contains("no up host"));
        assert!(body(&post(&out, br#"{"ips":[]}"#)).contains("no up host"));
        // a junk element is named with its index
        assert!(
            body(&post(&out, br#"{"ips":["127.0.0.5","nonsense"]}"#)).contains("ips[1]"),
            "the junk element must be named"
        );
        // no registry → 409, before anything else
        let empty = temp_perim("scanbatch-empty");
        assert!(body(&post(&empty, br#"{"range":"127.0.0.0/8"}"#)).contains("no registry here"));

        // the ceiling: 1030 sweep-up hosts under one /8 → refused with the cap named
        let big = temp_perim("scanbatch-big");
        {
            use crate::discovery::db::Stage;
            let mut db = Db::open(&big).unwrap();
            db.set_run_id("big_test");
            for i in 0..1030u32 {
                let ip = Ipv4Addr::from([127, 2, (i / 254) as u8, (i % 254 + 1) as u8]);
                db.record_host(ip, Stage::Sweep, true, 2);
            }
            db.flush().unwrap();
        }
        let t = body(&post(&big, br#"{"range":"127.0.0.0/8"}"#));
        assert!(t.contains("past the 1024-host rescan ceiling"), "{t}");

        // the guard header: 403 and no run directory created — nothing spawned
        let before = std::fs::read_dir(crate::discovery::state::runs_dir(&out))
            .map(|d| d.count())
            .unwrap_or(0);
        let resp = route_req(
            "POST",
            "/api/scan",
            br#"{"ips":["127.0.0.5"]}"#,
            false,
            &out,
        );
        assert_eq!(resp.status, 403);
        let after = std::fs::read_dir(crate::discovery::state::runs_dir(&out))
            .map(|d| d.count())
            .unwrap_or(0);
        assert_eq!(before, after, "a refused scan must not create a run");

        // one dashboard scan at a time: the flag gates before the lock
        let swept = seeded_swept("scangate");
        SCANNING.store(true, Ordering::Relaxed);
        let t = body(&post(&swept, br#"{"ip":"127.0.0.5","args":""}"#));
        SCANNING.store(false, Ordering::Relaxed);
        assert!(t.contains("already running"), "{t}");
    }

    #[test]
    fn routing_rejects_what_it_must() {
        let out = seeded("routes");
        assert_eq!(route("GET", "/", &out).status, 200);
        assert_eq!(
            route("GET", "/", &out).content_type,
            "text/html; charset=utf-8"
        );
        assert_eq!(route("GET", "/nope", &out).status, 404);
        assert_eq!(route("GET", "/api/", &out).status, 404);
        assert_eq!(route("GET", "/api/host/not-an-ip", &out).status, 404);
        // a traversal attempt is just a bad ip
        assert_eq!(route("GET", "/api/host/../../etc/passwd", &out).status, 404);
        assert_eq!(route("POST", "/api/hosts", &out).status, 405);
        assert_eq!(route("HEAD", "/", &out).status, 405);
        assert_eq!(route("GET", "/%2Fetc%2Fpasswd", &out).status, 404);
        // the prefix routes and the export paths fold into the same table
        assert_eq!(route("GET", "/api/ranges/16", &out).status, 200);
        assert_eq!(route("GET", "/api/ranges/junk", &out).status, 404);
        assert_eq!(route("GET", "/api/export/nope", &out).status, 404);
        // POST exports are guard-free reads: no body is a 400, not a 403/405
        assert_eq!(route("POST", "/api/export/hosts.txt", &out).status, 400);
        assert_eq!(route("POST", "/api/export/nope", &out).status, 405);
        assert_eq!(route("GET", "/api/scan/output", &out).status, 200);
        assert_eq!(route("POST", "/api/up-ips", &out).status, 400);
    }

    #[test]
    fn percent_decode_handles_the_obvious() {
        assert_eq!(percent_decode("/plain"), "/plain");
        assert_eq!(percent_decode("/a%20b"), "/a b");
        assert_eq!(percent_decode("127.0.0.5"), "127.0.0.5");
        assert_eq!(percent_decode("%zz"), "%zz"); // invalid hex passes through
        assert_eq!(percent_decode("%4"), "%4"); // truncated escape
    }

    #[test]
    fn post_triage_writes_rows_and_guards_hold() {
        let out = seeded("post");
        let post = |body: serde_json::Value, guard: bool| {
            route_req(
                "POST",
                "/api/triage",
                serde_json::to_vec(&body).unwrap().as_slice(),
                guard,
                &out,
            )
        };

        // Without the header: 403 and nothing written.
        let resp = post(
            serde_json::json!({"ip": "127.0.0.5", "status": "todo", "note": "x"}),
            false,
        );
        assert_eq!(resp.status, 403);
        let db = Db::open_read_only(&out).unwrap();
        let mut n = 0;
        db.triage(&mut |_, _, _, _, _| n += 1).unwrap();
        assert_eq!(n, 0, "a guard refusal writes nothing");
        drop(db);

        // The guarded write: host-level mark, echoed as JSON.
        let resp = post(
            serde_json::json!({"ip": "127.0.0.5", "status": "todo", "note": "start here"}),
            true,
        );
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["ip"], "127.0.0.5");
        assert_eq!(v["port"], 0);
        assert_eq!(v["status"], "todo");
        assert_eq!(v["note"], "start here");
        assert_eq!(v["deleted"], false);

        // Marks live on the host only: any port field refuses outright,
        // whatever word rides with it.
        let resp = post(
            serde_json::json!({"ip": "127.0.0.5", "port": 22, "status": "vuln", "note": "no NLA"}),
            true,
        );
        assert_eq!(resp.status, 400, "a port field refuses");
        assert!(body(&resp).contains("host only"), "{}", body(&resp));
        let resp = post(serde_json::json!({"ip": "127.0.0.5", "port": 70000}), true);
        assert_eq!(resp.status, 400, "a nonsense port refuses the same way");

        // The reads carry the host mark in the state slot.
        let v: serde_json::Value =
            serde_json::from_str(&body(&route("GET", "/api/hosts", &out))).unwrap();
        let five = v["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["ip"] == "127.0.0.5")
            .unwrap();
        assert_eq!(five["state"]["status"], "todo");
        assert_eq!(five["state"]["note"], "start here");
        let v: serde_json::Value =
            serde_json::from_str(&body(&route("GET", "/api/host/127.0.0.5", &out))).unwrap();
        assert_eq!(v["state"]["status"], "todo");

        // The merge core: absent fields keep the row's values…
        let resp = route_req(
            "POST",
            "/api/triage",
            serde_json::to_vec(&serde_json::json!({"ip": "127.0.0.5", "status": "clean"}))
                .unwrap()
                .as_slice(),
            true,
            &out,
        );
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["status"], "clean");
        assert_eq!(v["note"], "start here", "the note survived");
        // …and a note-only row holds (status null).
        let resp = route_req(
            "POST",
            "/api/triage",
            serde_json::to_vec(
                &serde_json::json!({"ip": "127.0.0.7", "note": "ask for the vNet map"}),
            )
            .unwrap()
            .as_slice(),
            true,
            &out,
        );
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert!(v["status"].is_null(), "{}", body(&resp));

        // Clearing: status none + empty note deletes; the answer says so.
        let resp = route_req(
            "POST",
            "/api/triage",
            serde_json::to_vec(
                &serde_json::json!({"ip": "127.0.0.5", "status": "none", "note": ""}),
            )
            .unwrap()
            .as_slice(),
            true,
            &out,
        );
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["deleted"], true, "{}", body(&resp));
        let v: serde_json::Value =
            serde_json::from_str(&body(&route("GET", "/api/host/127.0.0.5", &out))).unwrap();
        assert!(v["state"].is_null(), "the cleared host reads null: {v}");

        // The validation matrix — every one a 400, none a 500 or a panic.
        for (payload, why) in [
            (serde_json::json!({"ip": "10.0.0.300"}), "bad ip"),
            (
                serde_json::json!({"ip": "127.0.0.5", "status": "later"}),
                "bad status",
            ),
            (
                serde_json::json!({"ip": "127.0.0.5", "note": 42}),
                "non-string note",
            ),
            (
                serde_json::json!({"ip": "127.0.0.5", "note": "x".repeat(crate::NOTE_CAP + 1)}),
                "over-long note",
            ),
        ] {
            let resp = route_req(
                "POST",
                "/api/triage",
                serde_json::to_vec(&payload).unwrap().as_slice(),
                true,
                &out,
            );
            assert_eq!(resp.status, 400, "{why}: {}", body(&resp));
        }
        let resp = route_req("POST", "/api/triage", b"not json", true, &out);
        assert_eq!(resp.status, 400, "invalid JSON");

        // A directory without a registry: 409, the dashboard serves one
        // perimeter — it never creates one.
        let empty = temp_perim("post-empty");
        let resp = route_req(
            "POST",
            "/api/triage",
            serde_json::to_vec(&serde_json::json!({"ip": "127.0.0.5", "status": "todo"}))
                .unwrap()
                .as_slice(),
            true,
            &empty,
        );
        assert_eq!(resp.status, 409, "{}", body(&resp));
    }

    #[test]
    fn scan_stop_answers_409_when_nothing_runs() {
        let out = temp_perim("scan-stop-409");
        let resp = route_req("POST", "/api/scan/stop", b"{}", true, &out);
        assert_eq!(resp.status, 409);
        assert!(body(&resp).contains("no scan is running"));
    }

    #[test]
    fn post_flags_and_tags_write_and_unmark() {
        let out = seeded("flags-post");

        // The guards hold on the write routes.
        for path in ["/api/bookmark", "/api/pwned", "/api/tag", "/api/scan/stop"] {
            let payload = if path == "/api/tag" {
                serde_json::json!({"ip": "127.0.0.5", "add": ["dc"]})
            } else {
                serde_json::json!({"ip": "127.0.0.5", "on": true})
            };
            let resp = route_req(
                "POST",
                path,
                serde_json::to_vec(&payload).unwrap().as_slice(),
                false,
                &out,
            );
            assert_eq!(resp.status, 403, "{path}");
        }
        let v: serde_json::Value =
            serde_json::from_str(&body(&route("GET", "/api/hosts", &out))).unwrap();
        assert!(
            v["hosts"]
                .as_array()
                .unwrap()
                .iter()
                .all(|h| h["bookmark"] == false
                    && h["pwned"] == false
                    && h["tags"].as_array().unwrap().is_empty()),
            "the refusals wrote nothing: {v}"
        );

        // The bookmark flips on (a bare toggle, no "on" needed) and off.
        let resp = route_req(
            "POST",
            "/api/bookmark",
            serde_json::to_vec(&serde_json::json!({"ip": "127.0.0.5"}))
                .unwrap()
                .as_slice(),
            true,
            &out,
        );
        assert_eq!(resp.status, 200, "{}", body(&resp));
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["flag"], "bookmark");
        assert_eq!(v["on"], true);
        let v: serde_json::Value =
            serde_json::from_str(&body(&route("GET", "/api/host/127.0.0.5", &out))).unwrap();
        assert_eq!(v["bookmark"], true);
        let resp = route_req(
            "POST",
            "/api/bookmark",
            serde_json::to_vec(&serde_json::json!({"ip": "127.0.0.5", "on": false}))
                .unwrap()
                .as_slice(),
            true,
            &out,
        );
        assert_eq!(resp.status, 200);
        let v: serde_json::Value =
            serde_json::from_str(&body(&route("GET", "/api/hosts", &out))).unwrap();
        let five = v["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["ip"] == "127.0.0.5")
            .unwrap();
        assert_eq!(five["bookmark"], false, "{five}");

        // The ranges bookmark tally follows the flag.
        let resp = route_req(
            "POST",
            "/api/bookmark",
            serde_json::to_vec(&serde_json::json!({"ip": "127.0.0.5", "on": true}))
                .unwrap()
                .as_slice(),
            true,
            &out,
        );
        assert_eq!(resp.status, 200);
        let v: serde_json::Value =
            serde_json::from_str(&body(&route("GET", "/api/ranges", &out))).unwrap();
        assert_eq!(v["ranges"][0]["bookmarks"], 1, "{v}");

        // The PW3ND mark rides the same endpoint shape.
        let resp = route_req(
            "POST",
            "/api/pwned",
            serde_json::to_vec(&serde_json::json!({"ip": "127.0.0.5", "on": true}))
                .unwrap()
                .as_slice(),
            true,
            &out,
        );
        assert_eq!(resp.status, 200);
        let v: serde_json::Value =
            serde_json::from_str(&body(&route("GET", "/api/host/127.0.0.5", &out))).unwrap();
        assert_eq!(v["pwned"], true);
        let resp = route_req(
            "POST",
            "/api/pwned",
            serde_json::to_vec(&serde_json::json!({"ip": "127.0.0.5", "on": false}))
                .unwrap()
                .as_slice(),
            true,
            &out,
        );
        assert_eq!(resp.status, 200);
        let v: serde_json::Value =
            serde_json::from_str(&body(&route("GET", "/api/host/127.0.0.5", &out))).unwrap();
        assert_eq!(v["pwned"], false, "the unmark lands: {v}");

        // Tags: add and remove in one call, normalized like the CLI; the
        // answer carries the host's remaining set.
        let resp = route_req(
            "POST",
            "/api/tag",
            serde_json::to_vec(&serde_json::json!({
                "ip": "127.0.0.5", "add": ["#DC", "adcs"], "remove": ["old"]
            }))
            .unwrap()
            .as_slice(),
            true,
            &out,
        );
        assert_eq!(resp.status, 200, "{}", body(&resp));
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["tags"], serde_json::json!(["adcs", "dc"]), "{v}");
        let resp = route_req(
            "POST",
            "/api/tag",
            serde_json::to_vec(&serde_json::json!({"ip": "127.0.0.5", "remove": ["dc", "adcs"]}))
                .unwrap()
                .as_slice(),
            true,
            &out,
        );
        assert_eq!(resp.status, 200);
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert!(v["tags"].as_array().unwrap().is_empty(), "{v}");

        // The validation matrix — every one a 400.
        for (path, payload, why) in [
            (
                "/api/bookmark",
                serde_json::json!({"on": true}),
                "missing ip",
            ),
            (
                "/api/bookmark",
                serde_json::json!({"ip": "127.0.0.5", "on": "yes"}),
                "non-bool on",
            ),
            (
                "/api/tag",
                serde_json::json!({"ip": "127.0.0.5"}),
                "nothing to set",
            ),
            (
                "/api/tag",
                serde_json::json!({"ip": "127.0.0.5", "add": "dc"}),
                "non-array add",
            ),
            (
                "/api/tag",
                serde_json::json!({"ip": "127.0.0.5", "add": [42]}),
                "non-string token",
            ),
            (
                "/api/tag",
                serde_json::json!({"ip": "127.0.0.5", "add": ["###"]}),
                "token normalizes to nothing",
            ),
            (
                "/api/tag",
                serde_json::json!({"ip": "127.0.0.5", "add": ["dc"], "remove": ["dc"]}),
                "token in both arrays",
            ),
        ] {
            let resp = route_req(
                "POST",
                path,
                serde_json::to_vec(&payload).unwrap().as_slice(),
                true,
                &out,
            );
            assert_eq!(resp.status, 400, "{why}: {}", body(&resp));
        }

        // A directory without a registry: 409, never created.
        let empty = temp_perim("flags-empty");
        let resp = route_req(
            "POST",
            "/api/pwned",
            serde_json::to_vec(&serde_json::json!({"ip": "127.0.0.5"}))
                .unwrap()
                .as_slice(),
            true,
            &empty,
        );
        assert_eq!(resp.status, 409, "{}", body(&resp));
        assert!(!empty.join("scandb.sqlite").exists());
    }

    #[test]
    fn sha256_matches_the_nist_vectors() {
        // FIPS 180-4: the empty string, "abc", and the 56-byte string that
        // straddles the block padding.
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn screenshots_upload_serve_and_refuse() {
        let out = seeded("shots");
        let png = [0x89u8, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4];

        // the write guard holds, and junk never lands
        let resp = route_req("POST", "/api/note-image/127.0.0.5", &png, false, &out);
        assert_eq!(resp.status, 403);
        let resp = route_req(
            "POST",
            "/api/note-image/127.0.0.5",
            b"not an image",
            true,
            &out,
        );
        assert_eq!(resp.status, 400, "{}", body(&resp));
        let resp = route_req("POST", "/api/note-image/nonsense", &png, true, &out);
        assert_eq!(resp.status, 400);
        let resp = route_req("POST", "/api/note-image/127.0.0.5", &[], true, &out);
        assert_eq!(resp.status, 400);
        assert!(!out.join("notes").exists(), "the refusals wrote nothing");

        // the upload lands: digest-named file, url back, bytes served back
        let resp = route_req("POST", "/api/note-image/127.0.0.5", &png, true, &out);
        assert_eq!(resp.status, 200, "{}", body(&resp));
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        let url = v["url"].as_str().unwrap().to_string();
        assert!(
            url.starts_with("/notes/127.0.0.5/") && url.ends_with(".png"),
            "{url}"
        );
        assert_eq!(v["bytes"], png.len() as u64);
        // the same capture twice lands on the same digest-named file
        let resp = route_req("POST", "/api/note-image/127.0.0.5", &png, true, &out);
        let v2: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v2["file"], v["file"]);

        let resp = route("GET", &url, &out);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type, "image/png");
        assert_eq!(resp.body, png.to_vec());

        // the file path is pinned to 64 hex + .png/.jpg: anything else is a
        // 404 and never a filesystem read
        for p in [
            "/notes/127.0.0.5/../../scandb.sqlite",
            "/notes/127.0.0.5/short.png",
            "/notes/127.0.0.5/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff.png",
            "/notes/127.0.0.5/nothex.png",
            "/notes/127.0.0.5/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff.jpg",
            "/notes/nope/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff.png",
            "/notes/127.0.0.5",
        ] {
            assert_eq!(route("GET", p, &out).status, 404, "{p}");
        }
    }

    /// The page pins above are substring checks: a broken <script> ships
    /// green. Node's parser catches that class, so where node exists the
    /// embedded page's script must parse. (Shipped broken once: an extra
    /// `} else {` passed every pin.)
    #[test]
    fn the_embedded_page_script_parses() {
        let script = match (PAGE.find("<script>"), PAGE.find("</script>")) {
            (Some(a), Some(b)) if a < b => &PAGE[a + "<script>".len()..b],
            _ => panic!("the page has no script block"),
        };
        let mut path = std::env::temp_dir();
        path.push(format!("rustrawl-page-{}.js", std::process::id()));
        std::fs::write(&path, script).unwrap();
        let check = std::process::Command::new("node")
            .arg("--check")
            .arg(&path)
            .output();
        std::fs::remove_file(&path).ok();
        let out = match check {
            // No node on this box: nothing to check against.
            Err(_) => return,
            Ok(o) => o,
        };
        assert!(
            out.status.success(),
            "the embedded page's script does not parse: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn the_note_cap_is_64_kib() {
        let out = seeded("notecap");
        let ok = serde_json::json!({ "ip": "127.0.0.5", "note": "x".repeat(crate::NOTE_CAP) });
        let resp = route_req(
            "POST",
            "/api/triage",
            serde_json::to_vec(&ok).unwrap().as_slice(),
            true,
            &out,
        );
        assert_eq!(resp.status, 200, "{}", body(&resp));
        let big = serde_json::json!({ "ip": "127.0.0.5", "note": "x".repeat(crate::NOTE_CAP + 1) });
        let resp = route_req(
            "POST",
            "/api/triage",
            serde_json::to_vec(&big).unwrap().as_slice(),
            true,
            &out,
        );
        assert_eq!(resp.status, 400);
        assert!(body(&resp).contains("64 KiB"), "{}", body(&resp));
    }

    #[test]
    fn post_type_forces_and_withdraws_the_host_class() {
        let out = seeded("type-post");

        // The guard holds on the second write route too.
        let resp = route_req(
            "POST",
            "/api/type",
            serde_json::to_vec(&serde_json::json!({"ip": "127.0.0.5", "kind": "bastion"}))
                .unwrap()
                .as_slice(),
            false,
            &out,
        );
        assert_eq!(resp.status, 403);
        let v: serde_json::Value =
            serde_json::from_str(&body(&route("GET", "/api/host/127.0.0.5", &out))).unwrap();
        assert!(v["type"].is_null(), "the refusal wrote nothing: {v}");

        // A forced class lands (source manual), visible on the sheet…
        let resp = route_req(
            "POST",
            "/api/type",
            serde_json::to_vec(&serde_json::json!(
                {"ip": "127.0.0.5", "kind": "bastion", "basis": "jump host"}
            ))
            .unwrap()
            .as_slice(),
            true,
            &out,
        );
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["kind"], "bastion", "{}", body(&resp));
        assert_eq!(v["cleared"], false);
        let v: serde_json::Value =
            serde_json::from_str(&body(&route("GET", "/api/host/127.0.0.5", &out))).unwrap();
        assert_eq!(v["type"]["kind"], "bastion");
        assert_eq!(v["type"]["source"], "manual");
        assert_eq!(v["type"]["basis"], "jump host");

        // …re-forcing replaces even a manual row, and an absent/null kind
        // withdraws it.
        let resp = route_req(
            "POST",
            "/api/type",
            serde_json::to_vec(&serde_json::json!({"ip": "127.0.0.5", "kind": "voip"}))
                .unwrap()
                .as_slice(),
            true,
            &out,
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body(&resp)).unwrap()["kind"],
            "voip"
        );
        let resp = route_req(
            "POST",
            "/api/type",
            serde_json::to_vec(&serde_json::json!({"ip": "127.0.0.5"}))
                .unwrap()
                .as_slice(),
            true,
            &out,
        );
        let v: serde_json::Value = serde_json::from_str(&body(&resp)).unwrap();
        assert_eq!(v["cleared"], true, "{}", body(&resp));
        let v: serde_json::Value =
            serde_json::from_str(&body(&route("GET", "/api/host/127.0.0.5", &out))).unwrap();
        assert!(v["type"].is_null(), "{v}");

        // The validation matrix — every one a 400.
        for (payload, why) in [
            (serde_json::json!({"kind": "dc"}), "missing ip"),
            (
                serde_json::json!({"ip": "127.0.0.5", "kind": "DC"}),
                "uppercase token",
            ),
            (
                serde_json::json!({"ip": "127.0.0.5", "kind": "a".repeat(33)}),
                "33-byte token",
            ),
            (
                serde_json::json!({"ip": "127.0.0.5", "kind": 42}),
                "non-string kind",
            ),
        ] {
            let resp = route_req(
                "POST",
                "/api/type",
                serde_json::to_vec(&payload).unwrap().as_slice(),
                true,
                &out,
            );
            assert_eq!(resp.status, 400, "{why}: {}", body(&resp));
        }

        // A directory without a registry: 409, never created.
        let empty = temp_perim("type-empty");
        let resp = route_req(
            "POST",
            "/api/type",
            serde_json::to_vec(&serde_json::json!({"ip": "127.0.0.5", "kind": "dc"}))
                .unwrap()
                .as_slice(),
            true,
            &empty,
        );
        assert_eq!(resp.status, 409, "{}", body(&resp));
        assert!(!empty.join("scandb.sqlite").exists());
    }

    #[test]
    fn hosts_and_ranges_carry_types_states_and_counts() {
        use crate::discovery::db::Stage;
        let out = seeded("types");
        {
            let mut db = Db::open(&out).unwrap();
            db.set_run_id("scan_test");
            let five: Ipv4Addr = "127.0.0.5".parse().unwrap();
            let eight: Ipv4Addr = "127.0.0.8".parse().unwrap();
            db.record_host(eight, Stage::Scan, true, 0);
            db.record_asset_type(five, "dc", "445+88+389; name dc01", "heuristic");
            db.record_triage(five, Some("clean"), "patched");
            db.record_triage("127.0.0.7".parse().unwrap(), Some("todo"), "");
            // a retired word on purpose: the JSON views normalize it for
            // registries read before the migration touches the row
            db.record_triage(eight, Some("flagged"), "low");
            db.record_bookmark(five, true);
            db.record_pwned(eight, true);
            db.record_tag(five, "dc", true);
            db.record_tag(five, "adcs", true);
            db.record_tag(eight, "low-hanging", true);
            db.flush().unwrap();
        }

        // The overview: ports, type and the host state ride along. The
        // retired word reads through the one vocabulary: flagged shows vuln.
        let v: serde_json::Value =
            serde_json::from_str(&body(&route("GET", "/api/hosts", &out))).unwrap();
        let five = v["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["ip"] == "127.0.0.5")
            .unwrap();
        assert_eq!(five["ports"], serde_json::json!([22, 80]));
        assert_eq!(
            five["type"],
            serde_json::json!({"kind": "dc", "basis": "445+88+389; name dc01", "source": "heuristic"})
        );
        assert_eq!(five["state"]["status"], "clean");
        assert_eq!(five["bookmark"], true, "{five}");
        assert_eq!(five["pwned"], false);
        assert_eq!(five["tags"], serde_json::json!(["adcs", "dc"]));
        let eight = v["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["ip"] == "127.0.0.8")
            .unwrap();
        assert_eq!(
            eight["state"]["status"], "vuln",
            "the retired word reads vuln: {eight}"
        );
        assert_eq!(eight["pwned"], true);
        assert_eq!(eight["bookmark"], false);
        assert_eq!(eight["tags"], serde_json::json!(["low-hanging"]));

        // The sheet: the state is host-level, no per-port list on the side,
        // and the flags/tags ride along.
        let v: serde_json::Value =
            serde_json::from_str(&body(&route("GET", "/api/host/127.0.0.5", &out))).unwrap();
        assert_eq!(v["state"]["status"], "clean");
        assert!(v.get("triage").is_none(), "port marks left the sheet: {v}");
        assert_eq!(v["bookmark"], true);
        assert_eq!(v["pwned"], false);
        assert_eq!(v["tags"], serde_json::json!(["adcs", "dc"]));

        // The ranges tallies count HOST-level marks per /24, plus the
        // bookmark count.
        let v: serde_json::Value =
            serde_json::from_str(&body(&route("GET", "/api/ranges", &out))).unwrap();
        let row = &v["ranges"][0];
        assert_eq!(row["todo"], 1);
        assert_eq!(row["clean"], 1);
        assert_eq!(row["vuln"], 1);
        assert_eq!(row["bookmarks"], 1);
        assert!(
            row.get("wip").is_none() && row.get("flagged").is_none(),
            "the retired words left the tally: {row}"
        );
        assert!(
            row.get("crown").is_none() && row.get("star").is_none(),
            "the ranking left the tally: {row}"
        );

        // hosts with no type still read null on the type key — the page
        // renders "unknown" from null, not from a missing key
        let v: serde_json::Value =
            serde_json::from_str(&body(&route("GET", "/api/hosts", &out))).unwrap();
        let seven = v["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["ip"] == "127.0.0.7")
            .unwrap();
        assert_eq!(seven["state"]["status"], "todo");
        assert!(seven["type"].is_null());

        // The unknown-host sheet still reads fine with the new keys absent.
        let v: serde_json::Value =
            serde_json::from_str(&body(&route("GET", "/api/host/127.0.0.99", &out))).unwrap();
        assert!(v["detail"].is_null(), "{v}");
    }
}
