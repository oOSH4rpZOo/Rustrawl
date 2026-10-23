//! Internal network discovery tool — wide SYN sweep, /24 expansion of live
//! hosts, operator-driven nmap scanning over the discovered up list.

mod capture;
mod cli;
mod config;
mod console;
mod discovery;
mod evidence;
mod names;
mod ports;
mod scan;
mod targets;
mod tui;
mod util;
mod web;

use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use config::{Policy, Scope};

fn main() -> Result<()> {
    let args = cli::Cli::parse();
    match args.command {
        cli::Command::Run(a) => run(&a),
        cli::Command::Scan(a) => scan::run(&a),
        cli::Command::Names(a) => names::run(&a),
        cli::Command::Web(a) => capture::run(&a),
        cli::Command::Db {
            out,
            web,
            port,
            bind,
            command,
        } => match command {
            Some(c) => {
                if web {
                    bail!("--web serves the dashboard - it takes no subcommand");
                }
                db_cmd(&out, &c)
            }
            None if web => web::serve(&out, bind, port),
            None => console::run(&out),
        },
    }
}

fn run(a: &cli::RunArgs) -> Result<()> {
    let scope = config::load(&a.scope).context("loading scope")?;
    let all_targets =
        targets::Targets::build(&scope.includes, &scope.excludes).context("resolving targets")?;
    if all_targets.is_empty() {
        bail!("no targets left after exclusions - check includes/excludes");
    }
    let passives = passive_ranges(&scope, &all_targets)?;
    let scan_set = all_targets.subtract(&passives);
    if scan_set.is_empty() {
        bail!("no scannable targets - the whole perimeter is in passive zones");
    }

    if a.dry_run {
        return dry_run(&scope, &all_targets, &scan_set, &a.out, a.mode, a.force);
    }
    let code = discovery::run_all(&scope, &scan_set, &a.out, a.mode, a.resume, a.force)?;
    std::process::exit(code);
}

/// The one-shot registry views: `stats` (the counts and every run's
/// outcome) and `export` (the whole registry as one nmap-format XML).
/// The rest of the registry lives in the level console (`rustrawl db`).
/// Reads stream row by row through a buffered stdout — a /8 registry
/// exports without materializing. Every arm opens (and therefore
/// requires) the registry it reads — a typo'd perimeter errors instead of
/// materializing an empty database.
fn db_cmd(out: &Path, cmd: &cli::DbCommand) -> Result<()> {
    use std::io::{BufWriter, Write};
    let stdout = std::io::stdout();
    let mut w = BufWriter::new(stdout.lock());
    match cmd {
        cli::DbCommand::Stats => render_status(&mut w, out)?,
        cli::DbCommand::Export => {
            if !out.join("scandb.sqlite").exists() {
                bail!(
                    "no registry at {} - run a scan first (export reads, it never creates)",
                    out.display()
                );
            }
            render_export_scanxml(&mut w, out)?
        }
    }
    w.flush().context("writing to stdout")?;
    Ok(())
}

// ---- one-shot renderers, shared verbatim with the console (`hosts`,
// `services`, …) — the output shape is load-bearing: the integration tests
// pin line counts, tab-separated fields, the CSV header and the nmap tags.

pub(crate) fn render_hosts(
    w: &mut dyn std::io::Write,
    out: &Path,
    target: Option<&str>,
) -> Result<()> {
    let db = discovery::db::Db::open_read_only(out)?;
    match target {
        None => {
            let n = db.hosts_overview(&mut |ip, stages, seen, open| {
                let _ = writeln!(
                    w,
                    "{ip}\t{stages}\tlast up {}\t{open} open port(s)",
                    util::fmt_ts(seen)
                );
            })?;
            writeln!(
                w,
                "# {n} host(s) up - `hosts -i <ip>` for one host's full card"
            )?;
        }
        Some(t) => {
            let ip: Ipv4Addr = t
                .parse()
                .map_err(|_| anyhow!("\"{t}\" is not an IPv4 address"))?;
            match db.host_detail(ip)? {
                None => bail!("{ip}: nothing in the registry for this host"),
                Some(d) => {
                    writeln!(w, "{ip}")?;
                    // Names first: an auditor reads a host by its name before
                    // its ports (the `names` collector's output).
                    for (name, source, seen, run) in &d.names {
                        let _ = writeln!(
                            w,
                            "  name\t{name}\t{source}\t{}\t{run}",
                            util::fmt_ts(*seen)
                        );
                    }
                    // Then the operator's marks: what the host is, where the
                    // verification stands, what it is flagged as, whether it
                    // is owned (the dashboard's triage row).
                    if d.bookmark.is_some() {
                        writeln!(w, "  bookmark\tyes")?;
                    }
                    if d.pwned.is_some() {
                        writeln!(w, "  pwned\tyes")?;
                    }
                    if !d.tags.is_empty() {
                        let tags = d
                            .tags
                            .iter()
                            .map(|(t, _)| format!("#{t}"))
                            .collect::<Vec<_>>()
                            .join(" ");
                        writeln!(w, "  tags\t{tags}")?;
                    }
                    if let Some((kind, basis, source)) = &d.asset_type {
                        writeln!(w, "  type\t{kind} ({basis}) [{source}]")?;
                    }
                    if let Some((_, status, note, updated)) =
                        d.triage.iter().find(|(p, _, _, _)| *p == 0)
                    {
                        let _ = writeln!(
                            w,
                            "  state\t{}\t{}\t{}",
                            status.as_deref().map(norm_status).unwrap_or("none"),
                            note,
                            util::fmt_ts(*updated)
                        );
                    }
                    for (stage, status, seen, run) in &d.stages {
                        let _ = writeln!(
                            w,
                            "  discovery\t{stage}\t{status}\t{}\t{run}",
                            util::fmt_ts(*seen)
                        );
                    }
                    for (port, stage, status, seen, run) in &d.ports {
                        let _ = writeln!(
                            w,
                            "  port {port}\t{}\t{status}\t{}\t{run}",
                            stage.as_str(),
                            util::fmt_ts(*seen)
                        );
                    }
                    for (port, name, version, seen, _run) in &d.services {
                        let _ = writeln!(
                            w,
                            "  service {port}\t{name}\t{version}\t{}",
                            util::fmt_ts(*seen)
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

// ------------------------------------------------------- service queries

/// The `services` view's columns, in schema order (ids 1..=6 for `-o`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SvcCol {
    Host,
    Port,
    Proto,
    Name,
    State,
    Info,
}

impl SvcCol {
    const ALL: [SvcCol; 6] = [
        SvcCol::Host,
        SvcCol::Port,
        SvcCol::Proto,
        SvcCol::Name,
        SvcCol::State,
        SvcCol::Info,
    ];

    fn name(self) -> &'static str {
        match self {
            SvcCol::Host => "host",
            SvcCol::Port => "port",
            SvcCol::Proto => "proto",
            SvcCol::Name => "name",
            SvcCol::State => "state",
            SvcCol::Info => "info",
        }
    }
}

/// One row of the registry's services table (the nmap-observed open
/// services; upsert on ip:port, so one row per open port). `seen`/`run`
/// ride along for the exports; the column view does not show them.
pub(crate) struct SvcRow {
    pub(crate) ip: Ipv4Addr,
    pub(crate) port: u16,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) seen: i64,
    pub(crate) run: String,
}

/// The parsed `services` query, shared by the console's services level and
/// its exports — all of them end in `collect_services`.
#[derive(Debug)]
pub(crate) struct SvcQuery {
    /// Inclusive port ranges (from `-p` and/or the positional spec).
    ports: Vec<(u16, u16)>,
    /// Substring filters across host, service name and banner (`-s` /
    /// positional name); AND-ed together.
    searches: Vec<String>,
    /// Order column (`-o`, default host).
    order: SvcCol,
}

impl Default for SvcQuery {
    fn default() -> Self {
        SvcQuery {
            ports: Vec::new(),
            searches: Vec::new(),
            order: SvcCol::Host,
        }
    }
}

/// Parses a port list like `22,80,1000-2000` — inclusive ranges, `0-65535`
/// covers everything. Whitespace around pieces is tolerated.
pub(crate) fn parse_port_list(spec: &str) -> Result<Vec<(u16, u16)>> {
    let mut out = Vec::new();
    for piece in spec.split(',') {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        match piece.split_once('-') {
            None => {
                let p: u16 = piece
                    .parse()
                    .map_err(|_| anyhow!("bad port {piece:?} in list {spec:?}"))?;
                out.push((p, p));
            }
            Some((a, b)) => {
                let a: u16 = a
                    .trim()
                    .parse()
                    .map_err(|_| anyhow!("bad port {a:?} in range {piece:?}"))?;
                let b: u16 = b
                    .trim()
                    .parse()
                    .map_err(|_| anyhow!("bad port {b:?} in range {piece:?}"))?;
                if a > b {
                    bail!("port range {piece:?} runs backwards");
                }
                out.push((a, b));
            }
        }
    }
    if out.is_empty() {
        bail!("empty port list");
    }
    Ok(out)
}

impl SvcQuery {
    fn port_hit(&self, port: u16) -> bool {
        self.ports.is_empty() || self.ports.iter().any(|&(a, b)| port >= a && port <= b)
    }

    fn text_hit(
        &self,
        ip: Ipv4Addr,
        port: u16,
        name: &str,
        version: &str,
        hostnames: &[String],
    ) -> bool {
        self.searches.iter().all(|t| {
            let t = t.to_lowercase();
            ip.to_string().contains(&t)
                || port.to_string().contains(&t)
                || name.to_lowercase().contains(&t)
                || version.to_lowercase().contains(&t)
                || hostnames.iter().any(|h| h.contains(&t))
        })
    }

    fn matches(&self, r: &SvcRow, hostnames: &[String]) -> bool {
        self.port_hit(r.port) && self.text_hit(r.ip, r.port, &r.name, &r.version, hostnames)
    }

    /// The active filters, for the footer line: ` on port 22`,
    /// ` on ports 22,80-90`, ` matching "ssh"`.
    pub(crate) fn describe(&self) -> String {
        let mut what = String::new();
        if !self.ports.is_empty() {
            let list = self
                .ports
                .iter()
                .map(|(a, b)| {
                    if a == b {
                        a.to_string()
                    } else {
                        format!("{a}-{b}")
                    }
                })
                .collect::<Vec<_>>()
                .join(",");
            let single = self.ports.len() == 1 && self.ports[0].0 == self.ports[0].1;
            what.push_str(
                &(if single {
                    format!(" on port {list}")
                } else {
                    format!(" on ports {list}")
                }),
            );
        }
        if !self.searches.is_empty() {
            let terms = self
                .searches
                .iter()
                .map(|s| format!("\"{s}\""))
                .collect::<Vec<_>>()
                .join(" and ");
            what.push_str(&format!(" matching {terms}"));
        }
        what
    }
}

/// Builds the shared services query from the console level's flags. The
/// positional spec stays backwards compatible: a number (or list) filters
/// ports, anything else is a name/version substring.
pub(crate) fn svc_query(
    spec: Option<&str>,
    order: Option<usize>,
    ports: &[String],
    protocol: Option<&str>,
    searches: &[String],
) -> Result<SvcQuery> {
    let mut q = SvcQuery::default();
    for p in ports {
        q.ports.extend(parse_port_list(p)?);
    }
    if let Some(s) = spec {
        match parse_port_list(s) {
            Ok(pl) => q.ports.extend(pl),
            // Not a port list — but if it is port-SHAPED (digits, dashes,
            // commas only), the parse failure is a typo, not a service
            // name: refuse it instead of searching for the literal string
            // (`services 80-22` must error like `-p 80-22`, not print an
            // empty table that reads as "no such service").
            Err(e)
                if s.chars()
                    .all(|c| c.is_ascii_digit() || c == '-' || c == ',') =>
            {
                return Err(e.context(format!("bad port spec {s:?}")));
            }
            Err(_) => q.searches.push(s.to_string()),
        }
    }
    q.searches.extend(searches.iter().cloned());
    if let Some(n) = order {
        if !(1..=6).contains(&n) {
            bail!("column number {n} is out of range 1..=6 (1 host, 2 port, 3 proto, 4 name, 5 state, 6 info)");
        }
        q.order = SvcCol::ALL[n - 1];
    }
    if let Some(p) = protocol {
        if !p.eq_ignore_ascii_case("tcp") {
            bail!(
                "protocol {p:?} is not in the registry - the scan pass records TCP services only"
            );
        }
    }
    Ok(q)
}

/// The registry's service rows for exactly these hosts, numeric order —
/// the body of the dashboard's hosts-view filtered exports (the page sends
/// ips, the registry fills the rows).
pub(crate) fn services_rows_for_ips(out: &Path, ips: &[Ipv4Addr]) -> Result<Vec<SvcRow>> {
    let db = discovery::db::Db::open_read_only(out)?;
    let want: std::collections::HashSet<Ipv4Addr> = ips.iter().copied().collect();
    let mut rows: Vec<SvcRow> = Vec::new();
    db.services(None, None, &mut |ip, port, name, version, seen, run| {
        if want.contains(&ip) {
            rows.push(SvcRow {
                ip,
                port,
                name: name.to_string(),
                version: version.to_string(),
                seen,
                run: run.to_string(),
            });
        }
    })?;
    rows.sort_by_key(|r| (r.ip, r.port));
    Ok(rows)
}

/// Streams the services table and keeps the rows the query matches, sorted
/// by the query's order column (numeric for port; case-insensitive text
/// otherwise; ties by host then port). The rows are buffered on purpose:
/// the column widths need the full picture.
pub(crate) fn collect_services(out: &Path, q: &SvcQuery) -> Result<Vec<SvcRow>> {
    let db = discovery::db::Db::open_read_only(out)?;
    // -S terms also match the collected hostnames, per asset. Registries
    // without a hostnames table (older scans) simply search without it.
    let mut hostnames: std::collections::HashMap<Ipv4Addr, Vec<String>> =
        std::collections::HashMap::new();
    db.names(&mut |ip, name, _source, _seen, _run| {
        hostnames.entry(ip).or_default().push(name.to_string());
    })?;
    let mut rows: Vec<SvcRow> = Vec::new();
    db.services(None, None, &mut |ip, port, name, version, seen, run| {
        let r = SvcRow {
            ip,
            port,
            name: name.to_string(),
            version: version.to_string(),
            seen,
            run: run.to_string(),
        };
        let empty: Vec<String> = Vec::new();
        if q.matches(&r, hostnames.get(&ip).unwrap_or(&empty)) {
            rows.push(r);
        }
    })?;
    // Host keys are the numeric ip: 10.30.0.2 sorts before 10.30.0.10,
    // like every other view in the tool.
    let ip_key = |r: &SvcRow| u64::from(u32::from(r.ip));
    let port_key = |r: &SvcRow| u64::from(r.port);
    let sort_key = |r: &SvcRow| match q.order {
        SvcCol::Host => (String::new(), ip_key(r), port_key(r)),
        SvcCol::Port => (String::new(), port_key(r), ip_key(r)),
        SvcCol::Proto => ("tcp".to_string(), ip_key(r), port_key(r)),
        SvcCol::Name => (r.name.to_lowercase(), ip_key(r), port_key(r)),
        SvcCol::State => ("open".to_string(), ip_key(r), port_key(r)),
        SvcCol::Info => (r.version.to_lowercase(), ip_key(r), port_key(r)),
    };
    rows.sort_by_key(|a| sort_key(a));
    Ok(rows)
}

/// Terminal columns a string occupies: chars, except the East Asian wide
/// and emoji ranges, which take two cells. `format!("{:<w$}")` counts
/// chars, so a wide banner padded with it shifts every cell after it.
/// Combining marks are not modeled — no registry banner carries them.
fn display_width(s: &str) -> usize {
    s.chars()
        .map(|c| {
            let cp = c as u32;
            let wide = (0x1100..=0x115F).contains(&cp)
                || (0x2E80..=0xA4CF).contains(&cp)
                || (0xAC00..=0xD7A3).contains(&cp)
                || (0xF900..=0xFAFF).contains(&cp)
                || (0xFE30..=0xFE4F).contains(&cp)
                || (0xFF00..=0xFF60).contains(&cp)
                || (0xFFE0..=0xFFE6).contains(&cp)
                || (0x1F300..=0x1F64F).contains(&cp)
                || (0x1F900..=0x1F9FF).contains(&cp)
                || (0x20000..=0x3FFFD).contains(&cp);
            if wide {
                2
            } else {
                1
            }
        })
        .sum()
}

pub(crate) fn render_services(w: &mut dyn std::io::Write, out: &Path, q: &SvcQuery) -> Result<()> {
    let rows = collect_services(out, q)?;
    let cols: &[SvcCol] = &SvcCol::ALL;
    // The display value of one cell — proto/state are constants until a UDP
    // pass ever lands in the registry; the columns are here so the format
    // would not change when it does.
    let value = |r: &SvcRow, c: SvcCol| -> String {
        match c {
            SvcCol::Host => r.ip.to_string(),
            SvcCol::Port => r.port.to_string(),
            SvcCol::Proto => "tcp".to_string(),
            SvcCol::Name => {
                if r.name.is_empty() {
                    "(unnamed)".to_string()
                } else {
                    r.name.clone()
                }
            }
            SvcCol::State => "open".to_string(),
            SvcCol::Info => {
                if r.version.is_empty() {
                    "-".to_string()
                } else {
                    r.version.clone()
                }
            }
        }
    };
    // Column widths from the whole picture (header + every row), so the
    // table is aligned no matter how ragged the banners are. Widths count
    // terminal columns, not bytes — a UTF-8 banner stays aligned, wide
    // CJK/emoji glyphs included (they take two cells).
    let widths: Vec<usize> = cols
        .iter()
        .map(|c| {
            rows.iter()
                .map(|r| display_width(&value(r, *c)))
                .max()
                .unwrap_or(0)
                .max(display_width(c.name()))
        })
        .collect();
    let pad = |v: &str, i: usize| -> String {
        if i + 1 == cols.len() {
            v.to_string()
        } else {
            let fill = widths[i].saturating_sub(display_width(v));
            format!("{v}{}  ", " ".repeat(fill))
        }
    };
    let header: String = cols
        .iter()
        .enumerate()
        .map(|(i, c)| pad(c.name(), i))
        .collect();
    let rule: String = cols
        .iter()
        .enumerate()
        .map(|(i, _)| "-".repeat(widths[i]) + if i + 1 == cols.len() { "" } else { "  " })
        .collect();
    writeln!(w, "{header}")?;
    writeln!(w, "{rule}")?;
    for r in &rows {
        let line: String = cols
            .iter()
            .enumerate()
            .map(|(i, c)| pad(&value(r, *c), i))
            .collect();
        writeln!(w, "{line}")?;
    }
    writeln!(
        w,
        "# {} service row(s){}, sorted by {}",
        rows.len(),
        q.describe(),
        q.order.name()
    )?;
    Ok(())
}

/// The rescan form's default: the newest scan run's recorded nmap args
/// (`-sC -sV` when nothing ran yet) — the port list rides inside them.
/// The dashboard's rescan box prefills from it and the console's
/// `hosts -r` falls back to it — one reader, shared.
pub(crate) fn scan_defaults(out: &Path) -> String {
    let mut latest: Option<std::path::PathBuf> = None;
    if let Ok(rd) = std::fs::read_dir(discovery::state::runs_dir(out)) {
        let mut runs: Vec<std::path::PathBuf> = rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("scan_"))
                    && p.join("scan_state.json").is_file()
            })
            .collect();
        runs.sort();
        latest = runs.pop();
    }
    let state = latest.and_then(|d| {
        std::fs::read_to_string(d.join("scan_state.json"))
            .ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
    });
    match state {
        Some(v) => match v["nmap_args"].as_str() {
            Some(a) if !a.trim().is_empty() => a.to_string(),
            _ => "-sC -sV".to_string(),
        },
        None => "-sC -sV".to_string(),
    }
}

/// One host, by IPv4 or by any collected hostname: `hosts -i dc01` and
/// friends accept both. Exact case-insensitive name match first; a unique
/// case-insensitive substring match second; ambiguous or unknown tokens
/// are errors that say what was seen.
pub(crate) fn resolve_host(db: &discovery::db::Db, token: &str) -> Result<Ipv4Addr> {
    if let Ok(ip) = token.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    let needle = token.to_lowercase();
    let mut names: Vec<(Ipv4Addr, String)> = Vec::new();
    db.names(&mut |ip, name, _src, _seen, _run| {
        names.push((ip, name.to_string()));
    })?;
    // One address or a listing; empty means "nothing matched this pass".
    let one = |mut ips: Vec<Ipv4Addr>, what: &str| -> Result<Option<Ipv4Addr>> {
        ips.sort_unstable();
        ips.dedup();
        match ips.as_slice() {
            [ip] => Ok(Some(*ip)),
            [] => Ok(None),
            many => bail!(
                "\"{token}\" is ambiguous - {} hosts carry this {}: {}",
                many.len(),
                what,
                many.iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    };
    let exact: Vec<Ipv4Addr> = names
        .iter()
        .filter(|(_, n)| n.eq_ignore_ascii_case(token))
        .map(|(ip, _)| *ip)
        .collect();
    if let Some(ip) = one(exact, "name")? {
        return Ok(ip);
    }
    let partial: Vec<Ipv4Addr> = names
        .iter()
        .filter(|(_, n)| n.to_lowercase().contains(&needle))
        .map(|(ip, _)| *ip)
        .collect();
    if let Some(ip) = one(partial, "name fragment")? {
        return Ok(ip);
    }
    bail!("\"{token}\" is not an IPv4 address and matches no collected hostname")
}

/// One host's services as a small aligned table (the `hosts -S` view's
/// first half): port, name, version — the per-host slice of the services
/// table's column set.
pub(crate) fn render_host_services(
    w: &mut dyn std::io::Write,
    db: &discovery::db::Db,
    ip: Ipv4Addr,
) -> Result<usize> {
    let mut rows: Vec<(u16, String, String)> = Vec::new();
    db.services_for_ip(ip, &mut |port, name, version| {
        rows.push((port, name.to_string(), version.to_string()));
    })?;
    if rows.is_empty() {
        writeln!(w, "port  name  version")?;
        writeln!(w, "----  ----  -------")?;
        writeln!(w, "# 0 service(s) on {ip}")?;
        return Ok(0);
    }
    let headers = ["port", "name", "version"];
    let cells = |r: &(u16, String, String), i: usize| -> String {
        match i {
            0 => r.0.to_string(),
            1 => r.1.clone(),
            2 => {
                if r.2.is_empty() {
                    "-".to_string()
                } else {
                    r.2.clone()
                }
            }
            _ => unreachable!("three columns"),
        }
    };
    render_padded_table(w, &headers, |i, r| cells(r, i), &rows)?;
    writeln!(w, "# {} service(s) on {}", rows.len(), ip)?;
    Ok(rows.len())
}

/// `hosts -n`: the host's note, viewed or written. Text writes it (the
/// status row is kept); `-` clears the note; no text just shows it. The
/// row is the operator's, stamped run "manual", written through the same
/// apply_triage core the dashboard's note editor uses.
pub(crate) fn set_note(
    w: &mut dyn std::io::Write,
    out: &Path,
    ip: Ipv4Addr,
    text: Option<&str>,
) -> Result<()> {
    let show = |w: &mut dyn std::io::Write, status: Option<&str>, note: &str| -> Result<()> {
        match (status, note.is_empty()) {
            (Some(s), false) => writeln!(w, "# note {ip}: {note} [{s}]")?,
            (Some(s), true) => writeln!(w, "# note {ip}: (no note) [status {s}]")?,
            (None, false) => writeln!(w, "# note {ip}: {note}")?,
            (None, true) => writeln!(w, "# note {ip}: (none)")?,
        }
        Ok(())
    };
    let Some(text) = text else {
        // View only.
        let db = discovery::db::Db::open_read_only(out)?;
        let mut row: Option<(Option<String>, String)> = None;
        db.triage_for_ip(ip, &mut |port, status, note, _| {
            if port == 0 {
                row = Some((status.map(|s| s.to_string()), note.to_string()));
            }
        })?;
        let (status, note) = row.unwrap_or((None, String::new()));
        return show(w, status.as_deref(), &note);
    };
    if !out.join("scandb.sqlite").exists() {
        bail!(
            "no registry at {} - run a scan first (the note path never creates a perimeter)",
            out.display()
        );
    }
    let clear = text == "-";
    let mut db = discovery::db::Db::open(out)?;
    db.set_run_id("manual");
    let set = apply_triage(
        &mut db,
        ip,
        None,
        Some(if clear { "" } else { text }),
        false,
    )?;
    drop(db);
    if clear {
        writeln!(w, "# note {ip}: cleared")?;
    } else {
        show(w, set.status.as_deref(), &set.note)?;
    }
    Ok(())
}

/// The `hosts -r` rescan — the dashboard's scan form, same validation, same
/// manual_scan path: the registry (not the request) picks the target,
/// arguments stay inside rustrawl's frame, the run carries the perimeter
/// lock (one scan at a time). `paren` is the console's paren payload: pure
/// nmap args (the port list rides in them), empty means the last queue's
/// plan.
pub(crate) fn rescan_host(
    w: &mut dyn std::io::Write,
    out: &Path,
    ip: Ipv4Addr,
    paren: &str,
) -> Result<()> {
    if !out.join("scandb.sqlite").exists() {
        bail!("no registry here - a rescan re-probes known hosts, nothing else");
    }
    let args = if paren.trim().is_empty() {
        scan_defaults(out)
    } else {
        paren.trim().to_string()
    };
    config::check_nmap_args(&args).context("nmap args refused")?;
    let db = discovery::db::Db::open_read_only(out)?;
    let up = db.up_hosts(&[discovery::db::Stage::Sweep, discovery::db::Stage::Expand])?;
    drop(db);
    if !up.contains(u32::from(ip)) {
        bail!("{ip} is not an up host in this registry - a rescan re-probes known hosts");
    }
    writeln!(w, "scanning {ip} - nmap {args} - ctrl-c aborts")?;
    let r = scan::manual_scan(out, std::slice::from_ref(&ip), &args)?;
    writeln!(w, "run {} - {} open port(s)", r.run_id, r.open.len())?;
    for (port, name, version) in &r.open {
        writeln!(
            w,
            "  {port}\t{}\t{}",
            if name.is_empty() {
                "(unnamed)"
            } else {
                name.as_str()
            },
            version
        )?;
    }
    Ok(())
}

// -------------------------------------------------------- triage + marks

/// The one mark vocabulary, host level only (port 0): todo (orange, to
/// check), clean (green, checked sound), vuln (red, found something).
/// `none` is the token that clears a status (the row keeps its note).
pub(crate) const TRIAGE_STATUSES: [&str; 3] = ["todo", "clean", "vuln"];

/// The note's size cap, everywhere the note is written (CLI, console,
/// dashboard): a 64 KiB markdown sheet with embedded screenshot references.
pub(crate) const NOTE_CAP: usize = 64 * 1024;

/// Host rows written by older builds may carry the retired words (wip,
/// flagged); the views normalize them so a registry opened read-only still
/// renders (a write-mode open migrates the rows themselves).
pub(crate) fn norm_status(s: &str) -> &str {
    match s {
        "flagged" => "vuln",
        "wip" => "todo",
        other => other,
    }
}

/// What one triage write left the row as — the CLI confirmation and the
/// dashboard's JSON response both report this.
pub(crate) struct TriageSet {
    pub(crate) status: Option<String>,
    pub(crate) note: String,
    pub(crate) deleted: bool,
}

/// The merge core behind the note/status writes — the dashboard's POST
/// endpoint and the console's `hosts -n` both land here
/// endpoint: read the row, apply the given changes on top of it, write the
/// result. An absent `status` keeps the row's status, an absent `note`
/// keeps its note; a row left with no status and an empty note is deleted
/// (clearing a row is a write too — the flush carries an explicit delete).
/// The caller owns the Db (write mode, run id set) and the argument guards;
/// the flush happens here.
pub(crate) fn apply_triage(
    db: &mut discovery::db::Db,
    ip: Ipv4Addr,
    status: Option<&str>,
    note: Option<&str>,
    clear: bool,
) -> Result<TriageSet> {
    let mut current = (None, String::new());
    db.triage_for_ip(ip, &mut |p, s, n, _| {
        if p == 0 {
            current = (s.map(|s| s.to_string()), n.to_string());
        }
    })?;
    let new_status = match status {
        Some("none") => None,
        Some(s) => Some(s.to_string()),
        None => current.0,
    };
    let new_note = match note {
        Some(n) => n.to_string(),
        None => current.1,
    };
    if clear || (new_status.is_none() && new_note.is_empty()) {
        db.record_triage(ip, None, "");
        db.flush()?;
        return Ok(TriageSet {
            status: None,
            note: String::new(),
            deleted: true,
        });
    }
    db.record_triage(ip, new_status.as_deref(), &new_note);
    db.flush()?;
    Ok(TriageSet {
        status: new_status,
        note: new_note,
        deleted: false,
    })
}

/// Normalizes one tag token: strips the leading `#`/`+`, lowercases, keeps
/// `[a-z0-9._-]`, caps at 32 bytes. Errs with a message that says what a
/// tag may hold.
pub(crate) fn norm_tag(raw: &str) -> Result<String> {
    let t = raw
        .trim_start_matches(['#', '+'])
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
        .collect::<String>();
    if t.is_empty() {
        bail!("{raw:?} is not a tag - letters, digits, dot, underscore, dash");
    }
    if t.len() > 32 {
        bail!("tag {raw:?} is over the 32-character cap");
    }
    Ok(t)
}

/// The two boolean host marks one write path serves: the operator's pwned
/// mark (console `hosts -c`, dashboard POST) and the older bookmark form
/// the dashboard still exposes. The enum picks the registry column and the
/// wording of the confirmation.
pub(crate) enum Flag {
    Bookmark,
    Pwned,
}

impl Flag {
    pub(crate) fn word(self) -> &'static str {
        match self {
            Flag::Bookmark => "bookmark",
            Flag::Pwned => "pwned",
        }
    }
}

/// Sets or flips one host's bookmark or PW3ND mark — the console's
/// `-c` verb and the dashboard's POST endpoints land here.
/// Opens its own write-mode registry: the mark is the operator's, and the
/// path never creates a perimeter. A `None` state means the pwned mark's
/// toggle, resolved atomically inside the write connection (the
/// `Db::toggle_pwned` read and write share one transaction); the bookmark
/// has no toggle surface, absence there just sets it.
pub(crate) fn set_flag(
    w: &mut dyn std::io::Write,
    out: &Path,
    target: &str,
    state: Option<&str>,
    flag: Flag,
) -> Result<()> {
    let ip: Ipv4Addr = target
        .parse()
        .map_err(|_| anyhow!("{target:?} is not an IPv4 address"))?;
    let asked = match state {
        None => None,
        Some("on") | Some("yes") | Some("1") => Some(true),
        Some("off") | Some("no") | Some("0") => Some(false),
        Some(s) => bail!(
            "unknown state {s:?} - {word} takes on or off",
            word = flag.word()
        ),
    };
    if !out.join("scandb.sqlite").exists() {
        bail!(
            "no registry at {} - run a scan first (the {} path never creates a perimeter)",
            out.display(),
            flag.word()
        );
    }
    let mut db = discovery::db::Db::open(out)?;
    db.set_run_id("manual");
    let on = match (asked, &flag) {
        (None, Flag::Pwned) => db.toggle_pwned(ip)?,
        (None, Flag::Bookmark) => {
            db.record_bookmark(ip, true);
            db.flush()?;
            true
        }
        (Some(on), flag) => {
            match flag {
                Flag::Bookmark => db.record_bookmark(ip, on),
                Flag::Pwned => db.record_pwned(ip, on),
            }
            db.flush()?;
            on
        }
    };
    let word = flag.word();
    writeln!(w, "# {word} {ip}: {}", if on { "on" } else { "off" })?;
    Ok(())
}

/// Adds and removes tags on one host — the console's `-ta` / `-td` and the
/// dashboard's POST endpoint land here.
/// `-tag` removes, anything else (with optional `+`/`#`) adds; `--clear`
/// strips the host and takes no tokens. Opens its own write-mode registry
/// path never creates a perimeter.
pub(crate) fn set_tags(
    w: &mut dyn std::io::Write,
    out: &Path,
    target: &str,
    tags: &[String],
    clear: bool,
) -> Result<()> {
    let ip: Ipv4Addr = target
        .parse()
        .map_err(|_| anyhow!("{target:?} is not an IPv4 address"))?;
    if clear && !tags.is_empty() {
        bail!("--clear strips every tag; it takes no tag tokens");
    }
    if !clear && tags.is_empty() {
        bail!("nothing to set - give tags (+tag adds, -tag removes) or --clear");
    }
    if !out.join("scandb.sqlite").exists() {
        bail!(
            "no registry at {} - run a scan first (the tag path never creates a perimeter)",
            out.display()
        );
    }
    let mut ops: Vec<(String, bool)> = Vec::new();
    for raw in tags {
        if raw.starts_with("--") {
            bail!("tags take +tag and -tag tokens (--clear goes before any tags)");
        }
        // A leading `-` marks a removal; `#`/`+` decorations strip off in
        // the normalizer.
        let (token, add) = match raw.strip_prefix('-') {
            Some(rest) => (rest, false),
            None => (raw.as_str(), true),
        };
        ops.push((norm_tag(token)?, add));
    }
    let mut db = discovery::db::Db::open(out)?;
    db.set_run_id("manual");
    if clear {
        // --clear: every tag the host carries goes, one removal op each.
        for (tag, _) in db.tags_for_ip(ip)? {
            ops.push((tag, false));
        }
    }
    for (tag, add) in &ops {
        db.record_tag(ip, tag, *add);
    }
    db.flush()?;
    let kept = db.tags_for_ip(ip)?;
    let line = kept
        .iter()
        .map(|(t, _)| format!("#{t}"))
        .collect::<Vec<_>>()
        .join(" ");
    if line.is_empty() {
        writeln!(w, "# tags {ip}: (none)")?;
    } else {
        writeln!(w, "# tags {ip}: {line}")?;
    }
    Ok(())
}

/// The shared space-padded table body (headers, rule, rows) — the
/// display_width mechanics of render_services, factored once.
fn render_padded_table<T>(
    w: &mut dyn std::io::Write,
    headers: &[&str],
    cells: impl Fn(usize, &T) -> String,
    rows: &[T],
) -> Result<()> {
    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| {
            rows.iter()
                .map(|r| display_width(&cells(i, r)))
                .max()
                .unwrap_or(0)
                .max(display_width(h))
        })
        .collect();
    let pad = |v: &str, i: usize| -> String {
        if i + 1 == headers.len() {
            v.to_string()
        } else {
            let fill = widths[i].saturating_sub(display_width(v));
            format!("{v}{}  ", " ".repeat(fill))
        }
    };
    let header: String = headers.iter().enumerate().map(|(i, h)| pad(h, i)).collect();
    let rule: String = headers
        .iter()
        .enumerate()
        .map(|(i, _)| "-".repeat(widths[i]) + if i + 1 == headers.len() { "" } else { "  " })
        .collect();
    writeln!(w, "{header}")?;
    writeln!(w, "{rule}")?;
    for r in rows {
        let line: String = (0..headers.len()).map(|i| pad(&cells(i, r), i)).collect();
        writeln!(w, "{line}")?;
    }
    Ok(())
}

pub(crate) fn render_status(w: &mut dyn std::io::Write, out: &Path) -> Result<()> {
    let db = discovery::db::Db::open_read_only(out)?;
    let (up, missed, results) = db.counts()?;
    let services = db.services_count()?;
    writeln!(w, "registry: {}", out.join("scandb.sqlite").display())?;
    writeln!(
        w,
        "  hosts up {} · no_response {} · answered probes {} · services {}",
        util::fmt_count(up),
        util::fmt_count(missed),
        util::fmt_count(results),
        util::fmt_count(services),
    )?;
    status_runs(out, w)
}

// ------------------------------------------------------------ ranges view

/// The ranges level's prefix length: default 24, 1..=32 (32 = one host per
/// bucket). Anything else is refused rather than bucketed into nonsense.
pub(crate) fn ranges_prefix(spec: Option<&str>) -> Result<u32> {
    match spec {
        None => Ok(24),
        Some(s) => {
            let p: u32 = s
                .parse()
                .map_err(|_| anyhow!("ranges prefix: \"{s}\" is not a number (e.g. 8, 16, 24)"))?;
            if !(1..=32).contains(&p) {
                bail!("ranges prefix must be 1..=32 (default 24), got {p}");
            }
            Ok(p)
        }
    }
}

/// One prefix bucket of the ranges table: how many hosts are up,
/// how many are silent, how many open ports the scan found and which
/// service names dominate — "which range is what" before per-range profiles.
#[derive(Debug)]
pub(crate) struct RangeRow {
    pub(crate) base: Ipv4Addr,
    pub(crate) prefix: u32,
    pub(crate) up: u64,
    pub(crate) silent: u64,
    pub(crate) open: u64,
    /// Top service names (name, count), largest first, ≤5 entries.
    pub(crate) services: Vec<(String, u64)>,
}

/// Buckets the registry by IP prefix in three read-only passes over the
/// existing queries (no new SQL, no scope needed): the up bitmap, the
/// silent-host stream, the services stream. A registry without a services
/// table (older builds) simply reports zero open ports — `services` handles
/// that itself.
pub(crate) fn collect_ranges(out: &Path, prefix: u32) -> Result<Vec<RangeRow>> {
    let db = discovery::db::Db::open_read_only(out)?;
    let shift = 32 - prefix;
    let key = |ip: Ipv4Addr| u64::from(u32::from(ip)) >> shift;

    let mut up: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
    let ups = db.up_hosts(&[discovery::db::Stage::Sweep, discovery::db::Stage::Expand])?;
    for ip in ups.iter() {
        *up.entry(key(Ipv4Addr::from(ip))).or_insert(0) += 1;
    }

    let mut silent: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
    db.anomalies_silent(&mut |ip| {
        *silent.entry(key(ip)).or_insert(0) += 1;
    })?;

    let mut open: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
    let mut hist: std::collections::HashMap<u64, std::collections::HashMap<String, u64>> =
        std::collections::HashMap::new();
    db.services(None, None, &mut |ip, _port, name, _version, _seen, _run| {
        let k = key(ip);
        *open.entry(k).or_insert(0) += 1;
        let label = if name.is_empty() { "(unnamed)" } else { name };
        *hist
            .entry(k)
            .or_default()
            .entry(label.to_string())
            .or_insert(0) += 1;
    })?;

    let mut keys: std::collections::BTreeSet<u64> = up.keys().copied().collect();
    keys.extend(silent.keys().copied());
    keys.extend(open.keys().copied());
    let mut rows: Vec<RangeRow> = keys
        .into_iter()
        .map(|k| {
            let mut services: Vec<(String, u64)> = hist
                .get(&k)
                .map(|h| h.iter().map(|(n, c)| (n.clone(), *c)).collect())
                .unwrap_or_default();
            services.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            services.truncate(5);
            RangeRow {
                base: Ipv4Addr::from((k << shift) as u32),
                prefix,
                up: up.get(&k).copied().unwrap_or(0),
                silent: silent.get(&k).copied().unwrap_or(0),
                open: open.get(&k).copied().unwrap_or(0),
                services,
            }
        })
        .collect();
    // Busiest bucket first — the triage question is "where do I look".
    rows.sort_by(|a, b| b.up.cmp(&a.up).then(a.base.cmp(&b.base)));
    Ok(rows)
}

pub(crate) fn render_ranges(
    w: &mut dyn std::io::Write,
    out: &Path,
    prefix: Option<&str>,
    search: Option<&str>,
) -> Result<()> {
    let prefix = ranges_prefix(prefix)?;
    let mut rows = collect_ranges(out, prefix)?;
    if let Some(t) = search {
        // `ranges -s corp`: keep the buckets whose base carries the
        // substring (case-insensitive) - the same filter the hosts view
        // applies, one level up.
        let t = t.to_lowercase();
        rows.retain(|r| r.base.to_string().contains(&t));
    }
    writeln!(w, "range\tup\tsilent\topen\ttop services")?;
    for r in &rows {
        let services = if r.services.is_empty() {
            String::from("-")
        } else {
            r.services
                .iter()
                .map(|(n, c)| format!("{n} x{c}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let _ = writeln!(
            w,
            "{}/{}\t{}\t{}\t{}\t{}",
            r.base, r.prefix, r.up, r.silent, r.open, services
        );
    }
    writeln!(
        w,
        "# {} bucket(s) at /{prefix} - sorted by up hosts",
        rows.len()
    )?;
    Ok(())
}

/// The `ranges -S` card: one prefix bucket's counts, its top services and
/// every up host inside it. The spec accepts `10.30.4.0/24`, `10.30.4`
/// (implied /24) or a single host (`10.30.4.7` lands in its /24).
pub(crate) fn render_range_card(w: &mut dyn std::io::Write, out: &Path, spec: &str) -> Result<()> {
    let (base, prefix) = parse_range_spec(spec)?;
    let rows = collect_ranges(out, prefix)?;
    let row = rows.iter().find(|r| r.base == base);
    let db = discovery::db::Db::open_read_only(out)?;
    let ups = db.up_hosts(&[discovery::db::Stage::Sweep, discovery::db::Stage::Expand])?;
    let shift = 32 - prefix;
    let key = u64::from(u32::from(base)) >> shift;
    let hosts: Vec<Ipv4Addr> = ups
        .iter()
        .filter(|i| u64::from(*i) >> shift == key)
        .map(Ipv4Addr::from)
        .collect();
    let silent = row.map(|r| r.silent).unwrap_or(0);
    let open = row.map(|r| r.open).unwrap_or(0);
    let services = match row {
        Some(r) if !r.services.is_empty() => r
            .services
            .iter()
            .map(|(n, c)| format!("{n} x{c}"))
            .collect::<Vec<_>>()
            .join(", "),
        _ => String::from("-"),
    };
    writeln!(w, "range: {base}/{prefix}")?;
    writeln!(w, "up: {} (silent {silent})", hosts.len())?;
    writeln!(w, "open ports: {open}")?;
    writeln!(w, "top services: {services}")?;
    writeln!(w, "hosts:")?;
    let overview: std::collections::HashMap<Ipv4Addr, (String, i64, u64)> = {
        let mut m = std::collections::HashMap::new();
        db.hosts_overview(&mut |ip, stages, seen, open| {
            m.insert(ip, (stages.to_string(), seen, open));
        })?;
        m
    };
    for ip in &hosts {
        match overview.get(ip) {
            Some((stages, seen, open)) => writeln!(
                w,
                "  {ip}\t{stages}\tlast up {}\t{open} open port(s)",
                util::fmt_ts(*seen)
            )?,
            None => writeln!(w, "  {ip}")?,
        }
    }
    writeln!(
        w,
        "# {} up host(s) in {base}/{prefix} - `hosts -i <ip>` for a card",
        hosts.len()
    )?;
    Ok(())
}

/// `10.30.4.0/24`, `10.30.4/24`, `10.30.4` (implied /24) or a bare host
/// address (its /24) - the prefix clamps to 1..=32.
pub(crate) fn parse_range_spec(spec: &str) -> Result<(Ipv4Addr, u32)> {
    let (addr_part, prefix) = match spec.split_once('/') {
        Some((a, p)) => {
            let p: u32 = p
                .parse()
                .map_err(|_| anyhow!("range prefix: \"{p}\" is not a number (e.g. 8, 16, 24)"))?;
            if !(1..=32).contains(&p) {
                bail!("range prefix must be 1..=32, got {p}");
            }
            (a.to_string(), p)
        }
        None => {
            // Three octets mean the /24, four mean that host's /24.
            if spec.matches('.').count() == 2 {
                (format!("{spec}.0"), 24)
            } else {
                (spec.to_string(), 24)
            }
        }
    };
    let ip: Ipv4Addr = addr_part.parse().map_err(|_| {
        anyhow!("\"{spec}\" is not a range (try 10.30.4, 10.30.4.0/24 or 10.30.4.7)")
    })?;
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ok((Ipv4Addr::from(u32::from(ip) & mask), prefix))
}

/// The `hosts -s` view: the up hosts whose ip or any collected name
/// matches the substring (case-insensitive), same line shape as the full
/// list.
pub(crate) fn render_hosts_search(
    w: &mut dyn std::io::Write,
    out: &Path,
    term: &str,
) -> Result<()> {
    let db = discovery::db::Db::open_read_only(out)?;
    let lower = term.to_lowercase();
    let mut names: std::collections::HashMap<Ipv4Addr, Vec<String>> =
        std::collections::HashMap::new();
    db.names(&mut |ip, name, _src, _seen, _run| {
        names.entry(ip).or_default().push(name.to_string());
    })?;
    let mut n = 0u64;
    db.hosts_overview(&mut |ip, stages, seen, open| {
        let hit = ip.to_string().contains(&lower)
            || names
                .get(&ip)
                .is_some_and(|hs| hs.iter().any(|h| h.to_lowercase().contains(&lower)));
        if hit {
            n += 1;
            let _ = writeln!(
                w,
                "{ip}\t{stages}\tlast up {}\t{open} open port(s)",
                util::fmt_ts(seen)
            );
        }
    })?;
    writeln!(w, "# {n} host(s) matching \"{term}\"")?;
    Ok(())
}

/// The `hosts -e` / `ranges -e` export: every up host, one per line,
/// numeric order - feeds `nmap -iL -` and list engines. `--hostnames`
/// swaps the ip for the host's first registry name when it has one (the
/// ip otherwise). Count to stderr so a `> file` redirect stays clean.
pub(crate) fn render_hosts_txt(
    w: &mut dyn std::io::Write,
    out: &Path,
    hostnames: bool,
) -> Result<()> {
    let db = discovery::db::Db::open_read_only(out)?;
    let up = db.up_hosts(&[discovery::db::Stage::Sweep, discovery::db::Stage::Expand])?;
    let mut names: std::collections::HashMap<Ipv4Addr, String> = std::collections::HashMap::new();
    if hostnames {
        db.names(&mut |ip, name, _src, _seen, _run| {
            names.entry(ip).or_insert_with(|| name.to_string());
        })?;
    }
    let mut n = 0usize;
    for raw in up.iter() {
        let ip = Ipv4Addr::from(raw);
        let fallback = ip.to_string();
        let label = names.get(&ip).map(String::as_str).unwrap_or(&fallback);
        writeln!(w, "{label}")?;
        n += 1;
    }
    eprintln!("# {n} up host(s) on stdout");
    Ok(())
}

/// The shared CSV body: one row per service, same column order as the
/// interactive table. Consumed by the console's `services -e csv` and the
/// dashboard's filtered export alike.
fn write_services_csv(w: &mut dyn std::io::Write, rows: &[SvcRow]) -> Result<()> {
    writeln!(w, "ip,port,proto,service,version,last_seen,run")?;
    for r in rows {
        writeln!(
            w,
            "{},{},tcp,{},{},{},{}",
            r.ip,
            r.port,
            csv_field(&r.name),
            csv_field(&r.version),
            csv_field(&util::fmt_ts(r.seen)),
            csv_field(&r.run),
        )?;
    }
    Ok(())
}

/// The distinct hosts of a row set, numeric order — first-occurrence dedup
/// then sort, the order every ip-list consumer expects.
fn services_ips(rows: &[SvcRow]) -> Vec<Ipv4Addr> {
    let mut ips: Vec<Ipv4Addr> = Vec::new();
    for r in rows {
        if !ips.contains(&r.ip) {
            ips.push(r.ip);
        }
    }
    ips.sort_unstable();
    ips
}

/// One ip per line — the targets-file shape `nmap -iL -` and list engines eat.
fn write_ip_list(w: &mut dyn std::io::Write, ips: &[Ipv4Addr]) -> Result<()> {
    for ip in ips {
        writeln!(w, "{ip}")?;
    }
    Ok(())
}

/// The shared table-XML body: the rows exactly as given, one `<service>`
/// element each. The nmap-format document is `scan_xml`'s job — this is the
/// plain serialization of the displayed table.
fn write_services_xml(w: &mut dyn std::io::Write, rows: &[SvcRow]) -> Result<()> {
    writeln!(w, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
    writeln!(w, "<services count=\"{}\">", rows.len())?;
    for r in rows {
        writeln!(
            w,
            "  <service ip=\"{}\" port=\"{}\" proto=\"tcp\" name=\"{}\" version=\"{}\" last_seen=\"{}\" run=\"{}\"/>",
            r.ip,
            r.port,
            xml_escape(&r.name),
            xml_escape(&r.version),
            xml_escape(&util::fmt_ts(r.seen)),
            xml_escape(&r.run),
        )?;
    }
    writeln!(w, "</services>")?;
    Ok(())
}

/// The nmap-format document over exactly these hosts (deduped, numeric
/// order), names and services still read from the registry.
pub(crate) fn render_scanxml_for_ips(
    w: &mut dyn std::io::Write,
    out: &Path,
    ips: &[Ipv4Addr],
) -> Result<()> {
    let mut ips = ips.to_vec();
    ips.sort_unstable();
    ips.dedup();
    let db = discovery::db::Db::open_read_only(out)?;
    scan_xml(w, &db, &ips)
}

/// The `services -e csv` writer — one row per matched service, same column
/// order as the interactive table. Count to stderr so a `> file` redirect
/// stays clean.
pub(crate) fn render_services_csv(
    w: &mut dyn std::io::Write,
    out: &Path,
    q: &SvcQuery,
) -> Result<()> {
    let rows = collect_services(out, q)?;
    let n = rows.len();
    write_services_csv(w, &rows)?;
    eprintln!("# {n} service row(s) as CSV on stdout");
    Ok(())
}

/// The `services -e txt` writer — every host with at least one matched
/// service, one per line, numeric order. `--hostnames` swaps the ip for the
/// host's first registry name when it has one (ip otherwise). Feeds
/// `nmap -iL -`, list engines, one-liners.
pub(crate) fn render_services_txt(
    w: &mut dyn std::io::Write,
    out: &Path,
    q: &SvcQuery,
    hostnames: bool,
) -> Result<()> {
    let rows = collect_services(out, q)?;
    let mut names: std::collections::HashMap<Ipv4Addr, String> = std::collections::HashMap::new();
    if hostnames {
        let db = discovery::db::Db::open_read_only(out)?;
        db.names(&mut |ip, name, _source, _seen, _run| {
            names.entry(ip).or_insert_with(|| name.to_string());
        })?;
    }
    let ips = services_ips(&rows);
    for ip in &ips {
        let fallback = ip.to_string();
        let label = names.get(ip).map(String::as_str).unwrap_or(&fallback);
        writeln!(w, "{label}")?;
    }
    eprintln!("# {} host(s) on stdout", ips.len());
    Ok(())
}

/// The `services -e xml` writer — the matched hosts as an nmap-format
/// document.
pub(crate) fn render_services_xml(
    w: &mut dyn std::io::Write,
    out: &Path,
    q: &SvcQuery,
) -> Result<()> {
    let rows = collect_services(out, q)?;
    let ips = services_ips(&rows);
    let db = discovery::db::Db::open_read_only(out)?;
    scan_xml(w, &db, &ips)
}

/// The `db export` writer — the whole registry as ONE nmap-format document:
/// every discovery-up host plus any host the services table knows (a host
/// can have scan findings while its sweep verdict was never refreshed).
pub(crate) fn render_export_scanxml(w: &mut dyn std::io::Write, out: &Path) -> Result<()> {
    let db = discovery::db::Db::open_read_only(out)?;
    let mut ips = db.up_hosts(&[discovery::db::Stage::Sweep, discovery::db::Stage::Expand])?;
    db.services(None, None, &mut |ip, _, _, _, _, _| {
        ips.insert(u32::from(ip));
    })?;
    let ordered: Vec<Ipv4Addr> = ips.iter().map(Ipv4Addr::from).collect();
    scan_xml(w, &db, &ordered)?;
    eprintln!("# {} host(s) as nmap XML on stdout", ordered.len());
    Ok(())
}

/// One nmap-shaped XML document covering `ips` in numeric order. Everything
/// comes from the registry: ports are tcp and open (nmap parsers key on
/// state), hostnames come from the names table (dns-ptr entries typed PTR,
/// the rest user). Consumed by `msfconsole` `db_import` and standard nmap
/// XML parsers.
pub(crate) fn scan_xml(
    w: &mut dyn std::io::Write,
    db: &discovery::db::Db,
    ips: &[Ipv4Addr],
) -> Result<()> {
    let start = now_secs();
    writeln!(w, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
    writeln!(
        w,
        "<nmaprun scanner=\"nmap\" args=\"rustrawl registry export\" start=\"{start}\" \
         startstr=\"{}\" version=\"1.0\" xmloutputversion=\"1.05\">",
        xml_escape(&util::fmt_ts(start))
    )?;
    for ip in ips {
        writeln!(w, "<host>")?;
        writeln!(w, "  <status state=\"up\" reason=\"registry\"/>")?;
        writeln!(w, "  <address addr=\"{ip}\" addrtype=\"ipv4\"/>")?;
        let mut names: Vec<(String, String)> = Vec::new();
        db.names_for_ip(*ip, &mut |name, source, _seen, _run| {
            names.push((xml_escape(name), source.to_string()));
        })?;
        if !names.is_empty() {
            writeln!(w, "  <hostnames>")?;
            for (name, source) in &names {
                let kind = if *source == "dns-ptr" { "PTR" } else { "user" };
                writeln!(w, "    <hostname name=\"{name}\" type=\"{kind}\"/>")?;
            }
            writeln!(w, "  </hostnames>")?;
        }
        let mut any = false;
        let mut open = 0usize;
        db.services_for_ip(*ip, &mut |port, name, version| {
            if !any {
                any = true;
                let _ = writeln!(w, "  <ports>");
            }
            open += 1;
            let _ = writeln!(w, "    <port protocol=\"tcp\" portid=\"{port}\">");
            let _ = writeln!(w, "      <state state=\"open\"/>");
            let _ = writeln!(
                w,
                "      <service name=\"{}\" version=\"{}\" method=\"probed\" conf=\"10\"/>",
                xml_escape(name),
                xml_escape(version)
            );
            let _ = writeln!(w, "    </port>");
        })?;
        if any {
            writeln!(w, "  </ports>")?;
        }
        writeln!(w, "</host>")?;
    }
    writeln!(
        w,
        "<runstats><finished time=\"{start}\" timestr=\"{}\"/>\
         <hosts up=\"{}\" down=\"0\" total=\"{}\"/></runstats>",
        xml_escape(&util::fmt_ts(start)),
        ips.len(),
        ips.len()
    )?;
    writeln!(w, "</nmaprun>")?;
    Ok(())
}

/// One line per run directory under `<out>/runs` — what each pass covered
/// and where it stopped. Discovery dirs expose their state files (probes
/// sent, done flag, ip-list size); scan dirs expose the chunk queue.
pub(crate) fn status_runs(out: &Path, w: &mut dyn std::io::Write) -> Result<()> {
    let runs = out.join("runs");
    if !runs.is_dir() {
        writeln!(w, "  runs: none yet")?;
        return Ok(());
    }
    let mut dirs: Vec<std::path::PathBuf> = std::fs::read_dir(&runs)
        .with_context(|| format!("listing {}", runs.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    writeln!(w, "  runs/ ({} run(s), oldest first)", dirs.len())?;
    for dir in dirs {
        let name = dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let mut summary = String::new();
        // discovery runs (current and legacy names)
        for (files, label) in [
            (&discovery::state::SWEEP_FILES, "sweep"),
            (&discovery::state::EXPAND_FILES, "expand"),
        ] {
            let path = dir.join(files.state);
            if let Ok(text) = std::fs::read_to_string(&path) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    let sent = v.get("sent").and_then(|x| x.as_u64()).unwrap_or(0);
                    let done = v.get("done").and_then(|x| x.as_bool()).unwrap_or(false);
                    summary.push_str(&format!(
                        "{label} {} {} · ",
                        util::fmt_count(sent),
                        if done { "done" } else { "partial" },
                    ));
                }
            }
        }
        for ipfile in ["ip.txt", "ip_b.txt"] {
            if let Ok(text) = std::fs::read_to_string(dir.join(ipfile)) {
                let n = text.lines().count();
                if n > 0 {
                    summary.push_str(&format!("{ipfile} {} · ", util::fmt_count(n as u64)));
                }
            }
        }
        // scan runs (current and legacy fp_state.json queues)
        for statefile in ["scan_state.json", "fp_state.json"] {
            if let Ok(text) = std::fs::read_to_string(dir.join(statefile)) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    let chunks = v.get("chunks").and_then(|c| c.as_array());
                    let total = chunks.map(|a| a.len()).unwrap_or(0);
                    let done = chunks
                        .map(|a| {
                            a.iter()
                                .filter(|c| {
                                    c.get("done").and_then(|d| d.as_bool()).unwrap_or(false)
                                })
                                .count()
                        })
                        .unwrap_or(0);
                    let skipped = chunks
                        .map(|a| {
                            a.iter()
                                .filter(|c| {
                                    c.get("skipped").and_then(|d| d.as_bool()).unwrap_or(false)
                                })
                                .count()
                        })
                        .unwrap_or(0);
                    let complete = v.get("done").and_then(|d| d.as_bool()).unwrap_or(false);
                    summary.push_str(&format!(
                        "{statefile} {done}/{total} chunks{}{} · ",
                        if skipped > 0 {
                            format!(", {skipped} skipped")
                        } else {
                            String::new()
                        },
                        if complete { " complete" } else { "" },
                    ));
                }
            }
        }
        let summary = summary.trim_end_matches(" · ");
        if summary.is_empty() {
            writeln!(w, "  {name} (no state found)")?;
        } else {
            writeln!(w, "  {name}: {summary}")?;
        }
    }
    Ok(())
}

/// One CSV field: quoted only when the value contains a separator, a quote
/// or a line break (quotes doubled inside).
fn csv_field(v: &str) -> String {
    if v.contains(',') || v.contains('"') || v.contains('\n') || v.contains('\r') {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_string()
    }
}

/// XML text content: the five markup characters escaped and the C0 control
/// characters XML 1.0 forbids in text dropped (\t, \n, \r are the legal ones -
/// banners picked up off the wire can carry anything).
fn xml_escape(v: &str) -> String {
    v.chars()
        .filter(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
        .collect::<String>()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\'', "&apos;")
        .replace('"', "&quot;")
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Ranges of the `passive` zones that actually intersect the perimeter. A
/// declared zone outside the includes is a contract question, not a silence —
/// noted, so a typo'd range cannot quietly stop protecting anything.
fn passive_ranges(scope: &Scope, all: &targets::Targets) -> Result<Vec<targets::IpRange>> {
    let mut out = Vec::new();
    for z in &scope.sensitive_zones {
        if z.policy == Policy::Passive {
            let r = targets::IpRange::parse(&z.range)
                .with_context(|| format!("sensitive zone {}", z.range))?;
            if all.intersects(r) {
                out.push(r);
            } else {
                eprintln!(
                    "note: passive zone {} does not intersect the perimeter - nothing to subtract",
                    z.range
                );
            }
        }
    }
    Ok(out)
}

/// Per-stage target/probe/duration counts, zero packets.
fn dry_run(
    scope: &Scope,
    all_targets: &targets::Targets,
    scan_set: &targets::Targets,
    out: &Path,
    mode: cli::Mode,
    force: bool,
) -> Result<()> {
    let (_, expand_n) = scope
        .discovery
        .expand_ports
        .resolve()
        .context("discovery.expand_ports")?;
    let total = all_targets.total();
    let hosts = scan_set.total();
    let probe_kind = match mode {
        cli::Mode::Syn => "SYN probes",
        cli::Mode::Connect => "TCP connect probes",
        cli::Mode::Auto => "probes (SYN as root, else TCP connect)",
    };

    println!("Scope \"{}\" - dry run, zero packets sent", scope.name);
    println!(
        "Targets            : {} hosts, {} range(s) after merge/exclusions",
        util::fmt_count(total),
        all_targets.ranges().len()
    );

    for z in &scope.sensitive_zones {
        let range = targets::IpRange::parse(&z.range)
            .with_context(|| format!("sensitive zone {}", z.range))?;
        if !all_targets.intersects(range) {
            continue;
        }
        let what = match z.policy {
            Policy::Passive => "passive, zero probes",
            Policy::Light => "light, reduced profile",
        };
        let note = z.note.as_deref().unwrap_or("no note");
        println!("  ⚠ {} - {} ({})", z.range, what, note);
    }

    let rate = u64::from(scope.discovery.rate_pps);
    let groups = discovery::sweep_groups(scope, scan_set)?;
    println!("Discovery - wide sweep, then /24 expansion - {probe_kind}");
    if scope.discovery.icmp && mode != cli::Mode::Connect {
        println!(
            "  ICMP echo pass    : {} probe(s) (one per host, before the sweep)",
            util::fmt_count(hosts)
        );
    }
    let excluded = total - hosts;
    if excluded > 0 {
        println!(
            "  Hosts scanned     : {} ({} excluded in passive zones)",
            util::fmt_count(hosts),
            util::fmt_count(excluded)
        );
    }
    for (i, g) in groups.iter().enumerate() {
        let (_, ports_n) = g.ports.resolve().context("sweep profile ports")?;
        let probes = g.targets.total().saturating_mul(ports_n);
        println!(
            "  Sweep group {} ({}): {} hosts × {} ports = {} probes ≈ {}",
            i + 1,
            g.label,
            util::fmt_count(g.targets.total()),
            util::fmt_count(ports_n),
            util::fmt_count(probes),
            util::format_duration(Duration::from_secs(probes.div_ceil(rate))),
        );
    }
    // The registry already holds verdicts: dry run reads it (never creates it)
    // so the plan says what the run would actually probe. Same gate as the
    // real run (discovery::run_all): --force and rescan.skip_done: false both
    // empty the skip set — the plan must not advertise skips the run would
    // not take.
    let use_memory = !force && scope.rescan.skip_done;
    if out.join("scandb.sqlite").is_file() {
        match discovery::db::Db::open_read_only(out) {
            Ok(db) => {
                let skip = if use_memory {
                    db.skip_set(
                        discovery::db::Stage::Sweep,
                        scope.rescan.no_response_delay()?,
                        scope.rescan.recheck_up_delay()?,
                    )?
                } else {
                    Default::default()
                };
                if use_memory {
                    println!(
                        "  Registry skips    : {} host(s) with a fresh verdict (--force rescans them)",
                        util::fmt_count(skip.len())
                    );
                } else if force {
                    println!("  Registry skips    : none (--force - every host is re-probed)");
                } else {
                    println!(
                        "  Registry skips    : none (rescan.skip_done: false - every host is re-probed)"
                    );
                }
            }
            Err(e) => println!("  Registry skips    : present but unreadable: {e}"),
        }
    } else {
        println!("  Registry skips    : none (no registry yet - a dry run creates nothing)");
    }
    println!(
        "  Rate              : {} pps (jitter ±{}%)",
        util::fmt_count(rate),
        scope.discovery.jitter_pct
    );
    let per_live = 254u64.saturating_mul(expand_n);
    println!(
        "  Expand            : ≤ {} probes per live host's /24 (254 usable hosts × {} ports) + ICMP{}",
        util::fmt_count(per_live),
        util::fmt_count(expand_n),
        if scope.discovery.icmp {
            ""
        } else {
            " (icmp off)"
        }
    );

    println!("Scan - nmap over the up list (`rustrawl scan`)");
    println!(
        "  Queue             : every host up{} - args \"{}\", {} thread(s)",
        match &scope.scan.refresh_after {
            Some(w) => format!(" and stale over {w} (incremental)"),
            None => String::new(),
        },
        scope.scan.resolved_args(),
        scope.scan.threads,
    );
    println!(
        "Perimeter          : {} (scandb.sqlite, runs/discovery_<date>_<time>, run.lock) - not created in dry run",
        out.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_and_xml_escaping() {
        assert_eq!(csv_field("http"), "http");
        assert_eq!(
            csv_field("OpenSSH 9.2p1 Debian 2"),
            "OpenSSH 9.2p1 Debian 2"
        );
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(xml_escape("a<b>&\"c\""), "a&lt;b&gt;&amp;&quot;c&quot;");
        assert_eq!(xml_escape("plain 1.2.3"), "plain 1.2.3");
        // C0 controls are illegal in XML 1.0 text; \t and \n survive.
        assert_eq!(xml_escape("ban\u{7}ner"), "banner");
        assert_eq!(xml_escape("a\tb\nc"), "a\tb\nc");
    }

    #[test]
    fn ranges_prefix_defaults_and_refuses_junk() {
        assert_eq!(ranges_prefix(None).unwrap(), 24);
        for p in ["1", "8", "16", "24", "32"] {
            assert_eq!(
                ranges_prefix(Some(p)).unwrap(),
                p.parse::<u32>().unwrap(),
                "{p}"
            );
        }
        for bad in ["0", "33", "/24", "", "twentyfour", "24.5"] {
            assert!(
                ranges_prefix(Some(bad)).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn collect_ranges_buckets_up_silent_and_services() {
        let root = std::env::temp_dir().join(format!(
            "rustrawl-ranges-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let ip = |o: [u8; 4]| Ipv4Addr::from(o);
        {
            let mut db = discovery::db::Db::open(&root).unwrap();
            db.set_run_id("ranges-test");
            // 10.30.0.0/24: two scanned hosts (4 service rows, http twice)
            // plus one up host the scan could not explain — silent.
            for host in [[10, 30, 0, 1], [10, 30, 0, 2], [10, 30, 0, 3]] {
                db.record_host(ip(host), discovery::db::Stage::Sweep, true, 2);
            }
            db.record_result(
                ip([10, 30, 0, 1]),
                22,
                discovery::db::Stage::Scan,
                discovery::db::Answer::Open,
            );
            db.record_service(ip([10, 30, 0, 1]), 22, "ssh", "OpenSSH 9.2");
            db.record_result(
                ip([10, 30, 0, 1]),
                80,
                discovery::db::Stage::Scan,
                discovery::db::Answer::Open,
            );
            db.record_service(ip([10, 30, 0, 1]), 80, "http", "nginx");
            db.record_result(
                ip([10, 30, 0, 2]),
                80,
                discovery::db::Stage::Scan,
                discovery::db::Answer::Open,
            );
            db.record_service(ip([10, 30, 0, 2]), 80, "http", "");
            db.record_result(
                ip([10, 30, 0, 2]),
                9100,
                discovery::db::Stage::Scan,
                discovery::db::Answer::Open,
            );
            db.record_service(ip([10, 30, 0, 2]), 9100, "printer", "");
            // 10.40.0.0/24: up, its only C row is a closed port — still silent.
            db.record_host(ip([10, 40, 0, 7]), discovery::db::Stage::Expand, true, 2);
            db.record_result(
                ip([10, 40, 0, 7]),
                445,
                discovery::db::Stage::Scan,
                discovery::db::Answer::Closed,
            );
            db.flush().unwrap();
        }
        let rows = collect_ranges(&root, 24).unwrap();
        assert_eq!(rows.len(), 2, "{rows:?}");
        // busiest bucket first
        assert_eq!(rows[0].base, ip([10, 30, 0, 0]));
        assert_eq!(rows[0].up, 3);
        assert_eq!(rows[0].silent, 1, "10.30.0.3 is up with nothing open");
        assert_eq!(rows[0].open, 4);
        assert_eq!(
            rows[0].services,
            vec![
                ("http".to_string(), 2),
                ("printer".to_string(), 1),
                ("ssh".to_string(), 1)
            ],
            "count desc, then name asc"
        );
        assert_eq!(rows[1].base, ip([10, 40, 0, 0]));
        assert_eq!(rows[1].up, 1);
        assert_eq!(rows[1].silent, 1, "a closed C row is not an open port");
        assert_eq!(rows[1].open, 0);
        assert!(rows[1].services.is_empty());

        // the one-shot render: header, tab-separated rows, # footer
        let mut buf: Vec<u8> = Vec::new();
        render_ranges(&mut buf, &root, Some("24"), None).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(
            text.starts_with("range\tup\tsilent\topen\ttop services\n"),
            "{text}"
        );
        assert!(
            text.contains("10.30.0.0/24\t3\t1\t4\thttp x2, printer x1, ssh x1\n"),
            "{text}"
        );
        assert!(text.contains("10.40.0.0/24\t1\t1\t0\t-\n"), "{text}");
        assert!(
            text.ends_with("# 2 bucket(s) at /24 - sorted by up hosts\n"),
            "{text}"
        );

        // /32: one bucket per host, same numbers redistributed
        let rows = collect_ranges(&root, 32).unwrap();
        assert_eq!(rows.len(), 4, "{rows:?}");
        assert!(rows.iter().all(|r| r.up == 1));
        assert_eq!(
            rows.iter().map(|r| r.base).collect::<Vec<_>>(),
            // 10.30.0.1 and 10.30.0.2 are up and non-silent; ordering is
            // up desc, then base asc
            [
                ip([10, 30, 0, 1]),
                ip([10, 30, 0, 2]),
                ip([10, 30, 0, 3]),
                ip([10, 40, 0, 7])
            ]
        );
        std::fs::remove_dir_all(&root).ok();
    }

    // ---- services: the aligned-column view ----

    /// A small registry: 10.30.0.1 (ssh 22, http 80), 10.30.0.2 (ssh 22),
    /// 10.40.0.7 (https 443 with an empty banner).
    fn svc_perim(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "rustrawl-svc-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let ip = |o: &[&str; 4]| {
            Ipv4Addr::new(
                o[0].parse().unwrap(),
                o[1].parse().unwrap(),
                o[2].parse().unwrap(),
                o[3].parse().unwrap(),
            )
        };
        let mut db = discovery::db::Db::open(&root).unwrap();
        db.set_run_id("svc-test");
        for octets in [
            ["10", "30", "0", "1"],
            ["10", "30", "0", "2"],
            ["10", "40", "0", "7"],
        ] {
            db.record_host(ip(&octets), discovery::db::Stage::Sweep, true, 2);
        }
        for (octets, port, name, version) in [
            (["10", "30", "0", "1"], 22u16, "ssh", "OpenSSH 9.2p1"),
            (["10", "30", "0", "1"], 80, "http", "nginx 1.22.1"),
            (["10", "30", "0", "2"], 22, "ssh", "OpenSSH 8.4p1"),
            (["10", "40", "0", "7"], 443, "https", ""),
        ] {
            db.record_result(
                ip(&octets),
                port,
                discovery::db::Stage::Scan,
                discovery::db::Answer::Open,
            );
            db.record_service(ip(&octets), port, name, version);
        }
        db.flush().unwrap();
        root
    }

    fn render(perim: &Path, q: &SvcQuery) -> String {
        let mut buf: Vec<u8> = Vec::new();
        render_services(&mut buf, perim, q).unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn q(spec: Option<&str>) -> SvcQuery {
        svc_query(spec, None, &[], None, &[]).unwrap()
    }

    #[test]
    fn port_lists_parse_with_ranges() {
        assert_eq!(parse_port_list("22").unwrap(), vec![(22, 22)]);
        assert_eq!(
            parse_port_list("22,80,1000-2000").unwrap(),
            vec![(22, 22), (80, 80), (1000, 2000)]
        );
        assert_eq!(parse_port_list(" 0-65535 ").unwrap(), vec![(0, 65535)]);
        assert_eq!(
            parse_port_list("443,,22").unwrap(),
            vec![(443, 443), (22, 22)]
        );
        for bad in ["80-22", "abc", "70000", "22-", "a-b", ""] {
            assert!(parse_port_list(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn svc_query_folds_spec_flags_and_refuses_the_impossible() {
        // a numeric spec is ports, a name spec is a search
        let got = q(Some("22"));
        assert!(got.port_hit(22));
        assert!(!got.port_hit(23));
        let got = q(Some("ssh"));
        assert!(got.text_hit("10.0.0.1".parse().unwrap(), 22, "ssh", "", &[]));
        assert!(!got.text_hit("10.0.0.1".parse().unwrap(), 22, "http", "", &[]));
        // a port-shaped spec that fails to parse stays a port error — it
        // must never degrade into a silent text search
        assert!(
            svc_query(Some("80-22"), None, &[], None, &[]).is_err(),
            "backwards range is a port error, not a search"
        );
        assert!(
            svc_query(Some("70000"), None, &[], None, &[]).is_err(),
            "out-of-range port is a port error, not a search"
        );
        // -p list + -S search + protocol + order
        let got = svc_query(
            Some("ssh"),
            Some(6),
            &["80,443".to_string()],
            Some("tcp"),
            &["nginx".to_string()],
        )
        .unwrap();
        assert_eq!(got.order, SvcCol::Info);
        // refusals
        assert!(svc_query(None, Some(0), &[], None, &[]).is_err());
        assert!(svc_query(None, Some(7), &[], None, &[]).is_err());
        assert!(
            svc_query(None, None, &[], Some("udp"), &[]).is_err(),
            "udp is not in the registry - the error must say so"
        );
        assert!(svc_query(None, None, &["junk".to_string()], None, &[]).is_err());
    }

    #[test]
    fn services_render_as_aligned_columns_without_date_or_run() {
        let root = svc_perim("render");
        let text = render(&root, &q(None));
        // widths: host 9, port 4, proto 5, name 5 (https), state 5, info 13
        let expected = "\
host       port  proto  name   state  info
---------  ----  -----  -----  -----  -------------
10.30.0.1  22    tcp    ssh    open   OpenSSH 9.2p1
10.30.0.1  80    tcp    http   open   nginx 1.22.1
10.30.0.2  22    tcp    ssh    open   OpenSSH 8.4p1
10.40.0.7  443   tcp    https  open   -
# 4 service row(s), sorted by host
";
        assert_eq!(text, expected, "the whole table is load-bearing");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn services_filters_describe_themselves_in_the_footer() {
        let root = svc_perim("filters");
        // -p with one exact port
        let got = svc_query(None, None, &["22".to_string()], None, &[]).unwrap();
        assert_eq!(
            render(&root, &got)
                .lines()
                .filter(|l| l.starts_with("10."))
                .count(),
            2
        );
        assert!(render(&root, &got).contains("# 2 service row(s) on port 22, sorted by host"));
        // -p with ranges: 80 plus 443 falls in 100-500
        let got = svc_query(None, None, &["80,100-500".to_string()], None, &[]).unwrap();
        let text = render(&root, &got);
        assert!(text.contains(" on ports 80,100-500"), "{text}");
        assert_eq!(text.lines().filter(|l| l.starts_with("10.")).count(), 2);
        // -S matches name, version and host fragments, AND-ed
        let got = svc_query(None, None, &[], None, &["ssh".to_string()]).unwrap();
        assert_eq!(
            render(&root, &got)
                .lines()
                .filter(|l| l.starts_with("10."))
                .count(),
            2
        );
        let got = svc_query(
            None,
            None,
            &[],
            None,
            &["ssh".to_string(), "8.4".to_string()],
        )
        .unwrap();
        let text = render(&root, &got);
        assert!(text.contains("10.30.0.2"), "{text}");
        assert_eq!(text.lines().filter(|l| l.starts_with("10.")).count(), 1);
        assert!(text.contains(" matching \"ssh\" and \"8.4\""), "{text}");
        // -S also matches the host: the .7 box only
        let got = svc_query(None, None, &[], None, &["10.40".to_string()]).unwrap();
        let text = render(&root, &got);
        assert_eq!(text.lines().filter(|l| l.starts_with("10.")).count(), 1);
        assert!(text.contains("10.40.0.7"), "{text}");
        // -S also matches the port: same answer the web's bare term gives
        let got = svc_query(None, None, &[], None, &["443".to_string()]).unwrap();
        let text = render(&root, &got);
        assert!(text.contains("10.40.0.7"), "{text}");
        assert_eq!(text.lines().filter(|l| l.starts_with("10.")).count(), 1);
        // -o orders rows by an arbitrary column: info (col 6) sorts as
        // case-insensitive text — the empty banner sorts first (empty
        // string < any text), then nginx < openssh 8.4 < openssh 9.2
        let got = svc_query(None, Some(6), &[], None, &[]).unwrap();
        let text = render(&root, &got);
        let infos: Vec<String> = text
            .lines()
            .filter(|l| l.starts_with("10."))
            .map(|l| l.split("  ").last().unwrap().trim().to_string())
            .collect();
        assert_eq!(
            infos,
            vec!["-", "nginx 1.22.1", "OpenSSH 8.4p1", "OpenSSH 9.2p1"]
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn services_search_matches_collected_hostnames() {
        // -S terms also hit the hostnames table: "dc01" finds the row of
        // the asset that carries that name, even though no service field
        // contains it
        let root = std::env::temp_dir().join(format!(
            "rustrawl-svc-hostname-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut db = discovery::db::Db::open(&root).unwrap();
        db.set_run_id("svc-hostname");
        let a = Ipv4Addr::new(10, 30, 0, 1);
        let b = Ipv4Addr::new(10, 30, 0, 2);
        for ip in [a, b] {
            db.record_host(ip, discovery::db::Stage::Sweep, true, 2);
            db.record_result(
                ip,
                445,
                discovery::db::Stage::Scan,
                discovery::db::Answer::Open,
            );
            db.record_service(ip, 445, "microsoft-ds", "");
        }
        db.record_name(a, "dc01.corp.example.com", "ldap");
        db.flush().unwrap();
        let got = svc_query(None, None, &[], None, &["dc01".to_string()]).unwrap();
        let text = render(&root, &got);
        assert!(text.contains("10.30.0.1"), "{text}");
        assert!(!text.contains("10.30.0.2"), "{text}");
        assert!(
            text.contains("# 1 service row(s) matching \"dc01\""),
            "{text}"
        );
        // a term matching every hostname still ANDs with the other fields:
        // "corp" hits the name, "445" the port
        let got = svc_query(
            None,
            None,
            &[],
            None,
            &["corp".to_string(), "8.9".to_string()],
        )
        .unwrap();
        let text = render(&root, &got);
        assert!(text.contains("# 0 service row(s)"), "{text}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn services_sort_hosts_numerically_not_lexically() {
        // 10.30.0.2 must list before 10.30.0.10 — string order would put
        // ".10" first and disagree with every other view in the tool
        let root = std::env::temp_dir().join(format!(
            "rustrawl-svc-num-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut db = discovery::db::Db::open(&root).unwrap();
        db.set_run_id("svc-num");
        for o in [2u8, 10] {
            let ip = Ipv4Addr::new(10, 30, 0, o);
            db.record_host(ip, discovery::db::Stage::Sweep, true, 2);
            db.record_result(
                ip,
                22,
                discovery::db::Stage::Scan,
                discovery::db::Answer::Open,
            );
            db.record_service(ip, 22, "ssh", "OpenSSH");
        }
        db.flush().unwrap();
        let q = svc_query(None, None, &[], None, &[]).unwrap();
        let hosts: Vec<String> = render(&root, &q)
            .lines()
            .filter(|l| l.starts_with("10."))
            .map(|l| l.split_whitespace().next().unwrap().to_string())
            .collect();
        assert_eq!(hosts, vec!["10.30.0.2", "10.30.0.10"]);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn services_pad_wide_characters_by_display_width() {
        // 4 CJK chars occupy 8 terminal columns, not 4 — a char-count pad
        // would shift every cell after the wide banner
        let root = std::env::temp_dir().join(format!(
            "rustrawl-svc-wide-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut db = discovery::db::Db::open(&root).unwrap();
        db.set_run_id("svc-wide");
        for (ip, name, ver) in [
            (Ipv4Addr::new(10, 30, 0, 1), "ssh", "OpenSSH"),
            (Ipv4Addr::new(10, 30, 0, 2), "http", "中文服务"),
        ] {
            db.record_host(ip, discovery::db::Stage::Sweep, true, 2);
            db.record_result(
                ip,
                22,
                discovery::db::Stage::Scan,
                discovery::db::Answer::Open,
            );
            db.record_service(ip, 22, name, ver);
        }
        db.flush().unwrap();
        let got = svc_query(None, None, &[], None, &[]).unwrap();
        let text = render(&root, &got);
        let expected = "\
host       port  proto  name  state  info
---------  ----  -----  ----  -----  --------
10.30.0.1  22    tcp    ssh   open   OpenSSH
10.30.0.2  22    tcp    http  open   中文服务
# 2 service row(s), sorted by host
";
        assert_eq!(text, expected, "the CJK banner pads by display width");
        std::fs::remove_dir_all(&root).ok();
    }

    /// A registry with collected names: dc01 (ldap + ldap-sam re-observation
    /// of the same name) and two names on web01.
    fn names_perim(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "rustrawl-names-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut db = discovery::db::Db::open(&root).unwrap();
        db.set_run_id("names_2026-10-12_101112");
        // Both hosts are known assets (D2: names only ever attach to hosts
        // the discovery already put in the registry).
        db.record_host(
            Ipv4Addr::new(10, 30, 0, 10),
            discovery::db::Stage::Sweep,
            true,
            2,
        );
        db.record_host(
            Ipv4Addr::new(10, 30, 0, 21),
            discovery::db::Stage::Sweep,
            true,
            2,
        );
        db.record_name(
            Ipv4Addr::new(10, 30, 0, 10),
            "dc01.corp.example.com",
            "ldap",
        );
        db.record_name(
            Ipv4Addr::new(10, 30, 0, 10),
            "dc01.corp.example.com",
            "ldap-sam",
        );
        db.record_name(
            Ipv4Addr::new(10, 30, 0, 21),
            "web01.corp.example.com",
            "dns-ptr",
        );
        db.record_name(Ipv4Addr::new(10, 30, 0, 21), "www.corp.example.com", "tls");
        db.flush().unwrap();
        root
    }

    #[test]
    fn flags_and_tags_set_and_land_in_the_detail() {
        let root = names_perim("flags");
        let ip = "10.30.0.10";

        // The set form; off unmarks.
        let mut buf: Vec<u8> = Vec::new();
        set_flag(&mut buf, &root, ip, Some("on"), Flag::Bookmark).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            format!("# bookmark {ip}: on\n")
        );
        let mut buf: Vec<u8> = Vec::new();
        set_flag(&mut buf, &root, "10.30.0.21", None, Flag::Pwned).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "# pwned 10.30.0.21: on\n".to_string()
        );
        let mut buf: Vec<u8> = Vec::new();
        set_flag(&mut buf, &root, "10.30.0.21", Some("off"), Flag::Pwned).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "# pwned 10.30.0.21: off\n".to_string()
        );

        // The refusals hold.
        let mut buf: Vec<u8> = Vec::new();
        assert!(
            set_flag(&mut buf, &root, ip, Some("maybe"), Flag::Bookmark).is_err(),
            "unknown state bails"
        );

        // Tags: add with or without the `#`, remove with `-`.
        let mut buf: Vec<u8> = Vec::new();
        set_tags(
            &mut buf,
            &root,
            ip,
            &["dc".into(), "#ADCS".into(), "+sql".into()],
            false,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            format!("# tags {ip}: #adcs #dc #sql\n"),
            "tags normalize and answer in tag order"
        );
        let mut buf: Vec<u8> = Vec::new();
        set_tags(&mut buf, &root, ip, &["-dc".into()], false).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            format!("# tags {ip}: #adcs #sql\n")
        );

        // The refusals hold: a token that normalizes to nothing, one over
        // the cap, nothing to set, --clear with company.
        let mut buf: Vec<u8> = Vec::new();
        assert!(
            set_tags(&mut buf, &root, ip, &["###".into()], false).is_err(),
            "a token that normalizes to nothing bails"
        );
        let mut buf: Vec<u8> = Vec::new();
        assert!(
            set_tags(&mut buf, &root, ip, &["a".repeat(33)], false).is_err(),
            "a tag over the cap bails"
        );
        let mut buf: Vec<u8> = Vec::new();
        assert!(
            set_tags(&mut buf, &root, ip, &[], false).is_err(),
            "nothing to set bails"
        );
        let mut buf: Vec<u8> = Vec::new();
        assert!(
            set_tags(&mut buf, &root, ip, &["dc".into()], true).is_err(),
            "--clear refuses tokens"
        );
        // --clear strips the host.
        let mut buf: Vec<u8> = Vec::new();
        set_tags(&mut buf, &root, ip, &[], true).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            format!("# tags {ip}: (none)\n")
        );

        // The detail view carries the operator marks after the names block.
        let mut buf: Vec<u8> = Vec::new();
        set_flag(&mut buf, &root, ip, None, Flag::Bookmark).unwrap();
        set_flag(&mut buf, &root, ip, None, Flag::Pwned).unwrap();
        set_tags(&mut buf, &root, ip, &["adcs".into(), "sql".into()], false).unwrap();
        let mut buf: Vec<u8> = Vec::new();
        render_hosts(&mut buf, &root, Some(ip)).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(
            text.contains("  bookmark\tyes\n")
                && text.contains("  pwned\tyes\n")
                && text.contains("  tags\t#adcs #sql\n"),
            "the flag and tag lines land after the names block: {text}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn hosts_detail_shows_names_block() {
        let root = names_perim("detail");
        let mut buf: Vec<u8> = Vec::new();
        render_hosts(&mut buf, &root, Some("10.30.0.10")).unwrap();
        let text = String::from_utf8(buf).unwrap();
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some("10.30.0.10"), "header line first");
        assert!(
            lines
                .next()
                .unwrap()
                .starts_with("  name\tdc01.corp.example.com\tldap-sam\t"),
            "the names block comes right after the header, newest source"
        );
        assert!(text.contains("discovery"), "the rest of the detail follows");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn resolve_host_exact_then_unique_fragment() {
        let root = names_perim("resolve");
        let db = discovery::db::Db::open_read_only(&root).unwrap();
        // an ip passes through untouched
        assert_eq!(
            resolve_host(&db, "10.30.0.21").unwrap(),
            Ipv4Addr::new(10, 30, 0, 21)
        );
        // exact name, case-insensitive
        assert_eq!(
            resolve_host(&db, "DC01.CORP.EXAMPLE.COM").unwrap(),
            Ipv4Addr::new(10, 30, 0, 10)
        );
        // a fragment that only one host carries
        assert_eq!(
            resolve_host(&db, "web01").unwrap(),
            Ipv4Addr::new(10, 30, 0, 21)
        );
        // a fragment several hosts carry is an error that lists them
        let err = format!("{:#}", resolve_host(&db, "corp.example").unwrap_err());
        assert!(err.contains("ambiguous"), "{err}");
        assert!(
            err.contains("10.30.0.10") && err.contains("10.30.0.21"),
            "{err}"
        );
        // an unknown token is an error, never a silent miss
        assert!(resolve_host(&db, "nope").is_err());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn host_services_and_note_paths() {
        let root = names_perim("hostsvc");
        {
            let mut db = discovery::db::Db::open(&root).unwrap();
            db.set_run_id("manual");
            db.record_service(Ipv4Addr::new(10, 30, 0, 10), 389, "ldap", "OpenLDAP");
            db.flush().unwrap();
        }
        let db = discovery::db::Db::open_read_only(&root).unwrap();
        let mut buf: Vec<u8> = Vec::new();
        let n = render_host_services(&mut buf, &db, Ipv4Addr::new(10, 30, 0, 10)).unwrap();
        assert_eq!(n, 1);
        let text = String::from_utf8(buf).unwrap();
        assert!(text.starts_with("port  name  version\n"), "{text}");
        assert!(text.contains("389   ldap  OpenLDAP"), "{text}");
        assert!(text.ends_with("# 1 service(s) on 10.30.0.10\n"), "{text}");
        // a host with no services renders the empty table, not an error
        let mut buf: Vec<u8> = Vec::new();
        let n = render_host_services(&mut buf, &db, Ipv4Addr::new(10, 30, 0, 21)).unwrap();
        assert_eq!(n, 0);
        assert!(String::from_utf8(buf).unwrap().contains("# 0 service(s)"));

        // note: view (empty), write, clear, view again
        let mut buf: Vec<u8> = Vec::new();
        set_note(&mut buf, &root, Ipv4Addr::new(10, 30, 0, 10), None).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "# note 10.30.0.10: (none)\n"
        );
        let mut buf: Vec<u8> = Vec::new();
        set_note(
            &mut buf,
            &root,
            Ipv4Addr::new(10, 30, 0, 10),
            Some("check wins 2008"),
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "# note 10.30.0.10: check wins 2008\n"
        );
        let mut buf: Vec<u8> = Vec::new();
        set_note(&mut buf, &root, Ipv4Addr::new(10, 30, 0, 10), Some("-")).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "# note 10.30.0.10: cleared\n"
        );
        // clearing the last row deletes it: a fresh view is (none) again
        let mut buf: Vec<u8> = Vec::new();
        set_note(&mut buf, &root, Ipv4Addr::new(10, 30, 0, 10), None).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "# note 10.30.0.10: (none)\n"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn scan_xml_pins_the_nmap_shape() {
        let root = svc_perim("xml");
        {
            let mut db = discovery::db::Db::open(&root).unwrap();
            db.set_run_id("names_t");
            db.record_name(
                Ipv4Addr::new(10, 30, 0, 1),
                "dc01.corp.example.com",
                "dns-ptr",
            );
            db.record_name(Ipv4Addr::new(10, 30, 0, 1), "www.corp.example.com", "tls");
            db.record_service(Ipv4Addr::new(10, 40, 0, 7), 8080, "http", "weird<x>1.0");
            db.flush().unwrap();
        }
        let db = discovery::db::Db::open_read_only(&root).unwrap();
        let mut buf: Vec<u8> = Vec::new();
        scan_xml(
            &mut buf,
            &db,
            &[Ipv4Addr::new(10, 30, 0, 1), Ipv4Addr::new(10, 30, 0, 2)],
        )
        .unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(
            text.starts_with(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nmaprun scanner=\"nmap\" args=\"rustrawl registry export\" start=\""
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "<host>\n  <status state=\"up\" reason=\"registry\"/>\n  <address addr=\"10.30.0.1\" addrtype=\"ipv4\"/>"
            ),
            "{text}"
        );
        assert!(
            text.contains("<hostname name=\"dc01.corp.example.com\" type=\"PTR\"/>"),
            "{text}"
        );
        assert!(
            text.contains("<hostname name=\"www.corp.example.com\" type=\"user\"/>"),
            "{text}"
        );
        assert!(
            text.contains("<port protocol=\"tcp\" portid=\"22\">"),
            "{text}"
        );
        assert!(text.contains("<state state=\"open\"/>"), "{text}");
        assert!(
            text.contains(
                "<service name=\"ssh\" version=\"OpenSSH 9.2p1\" method=\"probed\" conf=\"10\"/>"
            ),
            "{text}"
        );
        assert!(
            text.contains("<hosts up=\"2\" down=\"0\" total=\"2\"/>"),
            "{text}"
        );
        assert!(text.trim_end().ends_with("</nmaprun>"), "{text}");
        // a banner with markup must not inject elements
        let mut buf: Vec<u8> = Vec::new();
        scan_xml(&mut buf, &db, &[Ipv4Addr::new(10, 40, 0, 7)]).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("weird&lt;x&gt;1.0"), "{text}");
        assert!(!text.contains("weird<x>"), "{text}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn services_exports_pin_csv_txt_and_xml() {
        let root = svc_perim("exports");
        let q = svc_query(None, None, &[], None, &[]).unwrap();

        let mut buf: Vec<u8> = Vec::new();
        render_services_csv(&mut buf, &root, &q).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(
            text.starts_with("ip,port,proto,service,version,last_seen,run\n"),
            "{text}"
        );
        assert!(
            text.contains("10.30.0.1,22,tcp,ssh,OpenSSH 9.2p1,"),
            "{text}"
        );
        assert!(text.contains("10.40.0.7,443,tcp,https,,"), "{text}");

        // txt: one host per line, numeric order
        let mut buf: Vec<u8> = Vec::new();
        render_services_txt(&mut buf, &root, &q, false).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "10.30.0.1\n10.30.0.2\n10.40.0.7\n"
        );

        // txt --hostnames: the first registry name, ip when it has none
        {
            let mut db = discovery::db::Db::open(&root).unwrap();
            db.set_run_id("names_t");
            db.record_name(
                Ipv4Addr::new(10, 30, 0, 2),
                "app02.corp.example.com",
                "ldap",
            );
            db.flush().unwrap();
        }
        let mut buf: Vec<u8> = Vec::new();
        render_services_txt(&mut buf, &root, &q, true).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "10.30.0.1\napp02.corp.example.com\n10.40.0.7\n"
        );

        // xml goes through the nmap-shaped core
        let mut buf: Vec<u8> = Vec::new();
        render_services_xml(&mut buf, &root, &q).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("<nmaprun scanner=\"nmap\""), "{text}");
        assert!(
            text.contains("<hosts up=\"3\" down=\"0\" total=\"3\"/>"),
            "{text}"
        );

        // db export = one document over up union service hosts
        let mut buf: Vec<u8> = Vec::new();
        render_export_scanxml(&mut buf, &root).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert_eq!(text.matches("<host>").count(), 3, "{text}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn services_table_xml_pins_rows() {
        let rows = vec![
            SvcRow {
                ip: Ipv4Addr::new(10, 30, 0, 1),
                port: 22,
                name: "ssh".into(),
                version: "OpenSSH <9>".into(),
                seen: 0,
                run: "scan_x".into(),
            },
            SvcRow {
                ip: Ipv4Addr::new(10, 30, 0, 2),
                port: 80,
                name: "http".into(),
                version: String::new(),
                seen: 0,
                run: String::new(),
            },
        ];
        let mut buf: Vec<u8> = Vec::new();
        write_services_xml(&mut buf, &rows).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(
            text.starts_with(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<services count=\"2\">\n"
            ),
            "{text}"
        );
        // rows in body order, proto is tcp, name/version escapes
        assert!(
            text.contains(
                "<service ip=\"10.30.0.1\" port=\"22\" proto=\"tcp\" name=\"ssh\" \
                 version=\"OpenSSH &lt;9&gt;\" last_seen=\"1970-01-01 00:00:00 UTC\" run=\"scan_x\"/>"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "<service ip=\"10.30.0.2\" port=\"80\" proto=\"tcp\" name=\"http\" \
                 version=\"\" last_seen=\"1970-01-01 00:00:00 UTC\" run=\"\"/>"
            ),
            "{text}"
        );
        assert!(text.ends_with("</services>\n"), "{text}");
    }

    #[test]
    fn services_ips_dedups_and_sorts() {
        let row = |ip: Ipv4Addr| SvcRow {
            ip,
            port: 0,
            name: String::new(),
            version: String::new(),
            seen: 0,
            run: String::new(),
        };
        let ips = services_ips(&[
            row(Ipv4Addr::new(10, 0, 0, 9)),
            row(Ipv4Addr::new(10, 0, 0, 2)),
            row(Ipv4Addr::new(10, 0, 0, 9)),
        ]);
        assert_eq!(
            ips,
            vec![Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 9)]
        );
        let mut buf: Vec<u8> = Vec::new();
        write_ip_list(&mut buf, &ips).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "10.0.0.2\n10.0.0.9\n");
    }

    #[test]
    fn range_card_and_spec_parse() {
        let root = svc_perim("card");
        // every spec shape lands on the same /24 bucket
        for spec in ["10.30.0.0/24", "10.30.0", "10.30.0.1"] {
            assert_eq!(
                parse_range_spec(spec).unwrap(),
                (Ipv4Addr::new(10, 30, 0, 0), 24),
                "{spec}"
            );
        }
        assert_eq!(
            parse_range_spec("10.30.0.0/16").unwrap(),
            (Ipv4Addr::new(10, 30, 0, 0), 16)
        );
        assert!(parse_range_spec("10.30.0.0/33").is_err());
        assert!(parse_range_spec("nope").is_err());

        let mut buf: Vec<u8> = Vec::new();
        render_range_card(&mut buf, &root, "10.30.0").unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.starts_with("range: 10.30.0.0/24\n"), "{text}");
        assert!(text.contains("up: 2 (silent 0)\n"), "{text}");
        assert!(text.contains("open ports: 3\n"), "{text}");
        assert!(text.contains("ssh x2"), "{text}");
        assert!(text.contains("\n  10.30.0.1\t"), "{text}");
        assert!(
            text.ends_with("# 2 up host(s) in 10.30.0.0/24 - `hosts -i <ip>` for a card\n"),
            "{text}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn hosts_search_and_txt_export() {
        let root = names_perim("hostsearch");
        let mut buf: Vec<u8> = Vec::new();
        render_hosts_search(&mut buf, &root, "WEB01").unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("10.30.0.21\t"), "{text}");
        assert!(!text.contains("10.30.0.10\t"), "{text}");
        assert!(text.ends_with("# 1 host(s) matching \"WEB01\"\n"), "{text}");

        // a fragment on the ip itself
        let mut buf: Vec<u8> = Vec::new();
        render_hosts_search(&mut buf, &root, "30.0.1").unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("10.30.0.10\t"), "{text}");

        let mut buf: Vec<u8> = Vec::new();
        render_hosts_txt(&mut buf, &root, false).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "10.30.0.10\n10.30.0.21\n");
        let mut buf: Vec<u8> = Vec::new();
        render_hosts_txt(&mut buf, &root, true).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "dc01.corp.example.com\nweb01.corp.example.com\n"
        );
        std::fs::remove_dir_all(&root).ok();
    }
}
