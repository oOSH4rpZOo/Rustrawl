//! The `names` collector: hostnames per known asset, gathered without
//! probing anything the registry does not already list as open. A run
//! touches only endpoints the registry already lists — the resolvers it
//! found (DNS PTR, each name verified by a forward A at the same resolver;
//! zone-transfer attempts over TCP), the HTTPS services (certificate CN
//! and SAN over a TLS 1.2-only handshake that stops at the Certificate
//! message), and the LDAP services (machine accounts over 389 — anonymous
//! or simple bind from RUSTRAWL_LDAP_BIND, cleartext, loudly warned;
//! Kerberos/GSSAPI is v2 behind the LdapAuth seam). Everything is
//! repeatable and idempotent: rows upsert on (ip, name), the latest source
//! observation wins.
//!
//! Shape: the main thread reads one inventory pass from the registry
//! (resolvers, the known-asset set, the cert and LDAP targets), derives
//! the work list, then feeds a fixed pool of worker threads over a job
//! channel in two waves — PTR first (the verified names imply the AXFR
//! zone list), then the transfer attempts, the certificate reads and the
//! LDAP enumerations. Workers only touch the network and report back; the
//! main thread alone writes the registry and names.log, so the
//! buffered-Vec writer never sees two threads. Transport failures never
//! fail the run — they are log lines and summary counts; only registry or
//! configuration errors exit non-zero. Progress goes to names.log only
//! (unlike the engine runs' mirrored stderr: hundreds of endpoints would
//! drown the summary), and one stderr block closes the run.
//!
//! No SIGINT handler: a run lasts seconds (a couple of timeouts per
//! endpoint at worst), and the registry writes are one flush at the end —
//! an interrupted run leaves at most a partial names.log next to an
//! untouched database.
//!
//! Deferred to v2, by design: Kerberos/GSSAPI LDAP (the `LdapAuth` seam in
//! ldap.rs is where a `Gssapi` variant slots in) and names for IPs outside
//! the known-asset set (AXFR discoveries stay log-only, so the per-host
//! views keep meaning "an asset the scan confirmed").

pub(crate) mod dns;
pub(crate) mod ldap;
pub(crate) mod tls_cert;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::cli::NamesArgs;
use crate::discovery::{db::Db, state};

/// Workers processing endpoints concurrently. Every socket carries the
/// run's per-socket timeout, so the pool paces itself; 32 clears a /24 of
/// lookups in a couple of timeout rounds without flooding any one resolver.
const WORKERS: usize = 32;

/// One unit of network work. Resolvers ride in the shared context, not the
/// job — every variant needs them, and the Ptr worker walks the ordered
/// list itself (only a transport failure advances to the next one).
enum Job {
    /// PTR (verified by forward A) for one known asset.
    Ptr { ip: Ipv4Addr },
    /// One zone-transfer attempt: exactly one (resolver, zone) pair.
    Axfr { resolver: SocketAddr, zone: String },
    /// Certificate names off one HTTPS service (TLS 1.2-only handshake).
    Cert { ip: Ipv4Addr, port: u16 },
    /// Machine accounts off one LDAP service (389, cleartext v1).
    Ldap { ip: Ipv4Addr, port: u16 },
}

/// What a worker reports. `Found` rows reach the registry only when the
/// main thread recognizes the IP as a known asset; everything else is a
/// names.log line.
enum Msg {
    Found {
        ip: Ipv4Addr,
        name: String,
        source: &'static str,
    },
    Touched(String),
}

/// Which collectors the run runs — `--sources dns,tls,ldap`, all on by
/// default. `dns` covers PTR and AXFR together; tls and ldap turn on with
/// their collectors (next commits).
#[derive(Debug, Clone, Copy)]
struct Sources {
    dns: bool,
    tls: bool,
    ldap: bool,
}

impl Sources {
    fn parse(specs: &[String]) -> Result<Sources> {
        if specs.is_empty() {
            return Ok(Sources {
                dns: true,
                tls: true,
                ldap: true,
            });
        }
        let mut s = Sources {
            dns: false,
            tls: false,
            ldap: false,
        };
        for spec in specs {
            match spec.as_str() {
                "dns" => s.dns = true,
                "tls" => s.tls = true,
                "ldap" => s.ldap = true,
                other => bail!(
                    "unknown source {other:?} - --sources takes dns, tls, ldap (comma-separated)"
                ),
            }
        }
        Ok(s)
    }

    fn describe(self) -> String {
        let mut on: Vec<&str> = Vec::new();
        if self.dns {
            on.push("dns");
        }
        if self.tls {
            on.push("tls");
        }
        if self.ldap {
            on.push("ldap");
        }
        if on.is_empty() {
            "(none)".to_string()
        } else {
            on.join(",")
        }
    }
}

/// A name from the wire, fit for the registry and the log: lowercased,
/// control characters and whitespace stripped, leading/trailing dots off.
/// Every source's raw values pass through here before anything else sees
/// them — a hostile PTR must not inject a newline into names.log, and
/// `WWW.Corp.Example` and `www.corp.example` are the same name.
pub(crate) fn sanitize_name(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control() && !c.is_whitespace())
        .flat_map(|c| c.to_lowercase())
        .collect::<String>()
        .trim_matches('.')
        .to_string()
}

/// The run's inventory, read once from the registry.
struct Inventory {
    /// Assets the discovery confirmed up — the only IPs a name may attach
    /// to (the per-host views keep meaning "a scan-confirmed asset").
    known: BTreeSet<Ipv4Addr>,
    /// Ordered query targets: --dns entries first, then the registry's
    /// port 53 services.
    resolvers: Vec<SocketAddr>,
    /// How many of those came from the registry rather than --dns.
    registry_resolvers: usize,
    /// HTTPS services to read a certificate from (port 443/8443 or an
    /// https/ssl service name), known assets only.
    cert_targets: Vec<(Ipv4Addr, u16)>,
    /// LDAP services to enumerate machine accounts on (port 389 or an
    /// ldap service name), known assets only.
    ldap_targets: Vec<(Ipv4Addr, u16)>,
}

fn inventory(db: &Db, dns_specs: &[String]) -> Result<Inventory> {
    let mut known = BTreeSet::new();
    db.up_ips(&mut |ip| {
        known.insert(ip);
    })?;

    let mut resolvers: Vec<SocketAddr> = Vec::new();
    for spec in dns_specs {
        let addr = dns::parse_resolver(spec)?;
        if !resolvers.contains(&addr) {
            resolvers.push(addr);
        }
    }
    let mut cert_targets: Vec<(Ipv4Addr, u16)> = Vec::new();
    let mut ldap_targets: Vec<(Ipv4Addr, u16)> = Vec::new();
    let before = resolvers.len();
    db.services(None, None, &mut |ip, port, name, _v, _s, _r| {
        if !known.contains(&ip) {
            // A service row for a host that has since gone silent: probing
            // it would contradict the no-new-probes rule — skip.
            return;
        }
        if port == 53 {
            let addr = SocketAddr::new(IpAddr::V4(ip), port);
            if !resolvers.contains(&addr) {
                resolvers.push(addr);
            }
        }
        if (port == 443 || port == 8443 || name.contains("https") || name.contains("ssl"))
            && !cert_targets.contains(&(ip, port))
        {
            cert_targets.push((ip, port));
        }
        if (port == 389 || name.contains("ldap")) && !ldap_targets.contains(&(ip, port)) {
            ldap_targets.push((ip, port));
        }
    })?;
    Ok(Inventory {
        known,
        registry_resolvers: resolvers.len() - before,
        resolvers,
        cert_targets,
        ldap_targets,
    })
}

/// System resolvers, used only when neither --dns nor the registry listed
/// any — the audit box's own resolver is the last resort, and the log says
/// so. Unparseable lines are skipped (resolv.conf carries options this
/// parser does not model).
fn system_resolvers() -> Vec<SocketAddr> {
    let text = match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some("nameserver") {
            if let Some(ip) = parts.next().and_then(|s| s.parse::<IpAddr>().ok()) {
                out.push(SocketAddr::new(ip, 53));
            }
        }
    }
    out
}

/// Zones the AXFR attempts target: the caller's --zone list plus, for every
/// verified PTR name, everything after its first label (the domain part of
/// the FQDN — `dc01.corp.example.com` implies `corp.example.com`). The
/// reverse zone and one-label fragments are skipped; output is deduped and
/// sorted (a BTreeSet), so a run's work list is stable.
fn derive_zones(explicit: &[String], verified_names: &[String]) -> Vec<String> {
    let mut zones: BTreeSet<String> = BTreeSet::new();
    for z in explicit {
        let clean = sanitize_name(z);
        if !clean.is_empty() {
            zones.insert(clean);
        }
    }
    for name in verified_names {
        if let Some((_, domain)) = name.split_once('.') {
            let reverse = domain == "in-addr.arpa" || domain.ends_with(".in-addr.arpa");
            if domain.contains('.') && !reverse {
                zones.insert(domain.to_string());
            }
        }
    }
    zones.into_iter().collect()
}

/// Everything a worker needs: the resolver order, the per-socket timeout,
/// and the LDAP auth (built once from the env var, shared read-only).
struct RunCtx {
    resolvers: Vec<SocketAddr>,
    timeout: Duration,
    auth: ldap::LdapAuth,
}

/// One PTR job: walk the resolver order until a definitive answer — only a
/// transport failure (or a SERVFUL-class rcode) advances. Verified names
/// report as `dns-ptr` finds; stale ones and empties are log lines.
fn ptr_msgs(ctx: &RunCtx, ip: Ipv4Addr) -> Vec<Msg> {
    let mut msgs = Vec::new();
    for resolver in &ctx.resolvers {
        match dns::query_ptr(*resolver, ip, ctx.timeout) {
            dns::PtrOutcome::Answer { verified, dropped } => {
                for name in &verified {
                    msgs.push(Msg::Touched(format!("ptr {ip} {name} (verified)")));
                    msgs.push(Msg::Found {
                        ip,
                        name: name.clone(),
                        source: "dns-ptr",
                    });
                }
                for name in &dropped {
                    msgs.push(Msg::Touched(format!(
                        "ptr {ip} {name} (dropped: forward A disagrees)"
                    )));
                }
                if verified.is_empty() && dropped.is_empty() {
                    msgs.push(Msg::Touched(format!("ptr {ip} (NXDOMAIN)")));
                }
                return msgs;
            }
            dns::PtrOutcome::Truncated => {
                msgs.push(Msg::Touched(format!(
                    "ptr {ip} via {resolver}: truncated, next resolver"
                )));
            }
            dns::PtrOutcome::Unreachable(why) => {
                msgs.push(Msg::Touched(format!(
                    "ptr {ip} via {resolver}: {why}, next resolver"
                )));
            }
        }
    }
    msgs.push(Msg::Touched(format!(
        "ptr {ip}: no resolver answered definitively"
    )));
    msgs
}

/// One (resolver, zone) transfer attempt, tried exactly once — a refusal is
/// a policy answer, not a flaky link. Each A record in the zone reports as
/// a `dns-axfr` find; the main thread keeps only the known assets.
fn axfr_msgs(ctx: &RunCtx, resolver: SocketAddr, zone: &str) -> Vec<Msg> {
    match dns::try_axfr(resolver, zone, ctx.timeout) {
        dns::AxfrOutcome::Records(records) => {
            let mut msgs = vec![Msg::Touched(format!(
                "axfr {zone} via {resolver}: {} record(s)",
                records.len()
            ))];
            for (name, ip) in records {
                msgs.push(Msg::Found {
                    ip,
                    name,
                    source: "dns-axfr",
                });
            }
            msgs
        }
        dns::AxfrOutcome::Refused(rc) => vec![Msg::Touched(format!(
            "axfr {zone} via {resolver}: refused (rcode {rc})"
        ))],
        dns::AxfrOutcome::Failed(why) => {
            vec![Msg::Touched(format!("axfr {zone} via {resolver}: {why}"))]
        }
    }
}

/// One HTTPS service: a TLS 1.2 handshake that stops at the Certificate
/// message. CN and SAN entries each report as a `tls` find — the registry
/// upsert dedupes when they agree; a skipped handshake is a log line only.
fn cert_msgs(ctx: &RunCtx, ip: Ipv4Addr, port: u16) -> Vec<Msg> {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    match tls_cert::grab_names(addr, ctx.timeout) {
        tls_cert::TlsOutcome::Names(names) => {
            let mut seen: Vec<String> = Vec::new();
            if let Some(cn) = &names.cn {
                if !seen.contains(cn) {
                    seen.push(cn.clone());
                }
            }
            for name in &names.san {
                if !seen.contains(name) {
                    seen.push(name.clone());
                }
            }
            let mut msgs = vec![Msg::Touched(format!(
                "tls {ip}:{port}: cn={} san=[{}]",
                names.cn.as_deref().unwrap_or("-"),
                names.san.join(", ")
            ))];
            for name in seen {
                msgs.push(Msg::Found {
                    ip,
                    name,
                    source: "tls",
                });
            }
            msgs
        }
        tls_cert::TlsOutcome::Skipped(why) => {
            vec![Msg::Touched(format!("tls {ip}:{port}: skipped: {why}"))]
        }
    }
}

/// One LDAP service: bind, rootDSE, paged computer search. Each
/// `dNSHostName` is resolved through the known resolvers (D3) — the name
/// and the machine's sAMAccountName report for the resolved IP and the
/// main thread keeps only known assets; unresolved or hostless accounts
/// are log lines only.
fn ldap_msgs(ctx: &RunCtx, ip: Ipv4Addr, port: u16) -> Vec<Msg> {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    match ldap::ldap_enumerate(addr, &ctx.auth, ctx.timeout) {
        Ok((root, computers, uncontrolled)) => {
            let mut msgs = vec![Msg::Touched(format!(
                "ldap {ip}:{port}: root {}; {} computer(s){}",
                root.as_deref().unwrap_or("-"),
                computers.len(),
                if uncontrolled {
                    " (paged control refused - uncontrolled fallback, first page only)"
                } else {
                    ""
                }
            ))];
            for computer in computers {
                let sam = computer.sam.as_deref().map(sanitize_name);
                let Some(host) = computer.dns_host.as_deref().map(sanitize_name) else {
                    if let Some(sam) = &sam {
                        msgs.push(Msg::Touched(format!(
                            "ldap {ip}:{port}: {sam} (no dNSHostName) - log-only"
                        )));
                    }
                    continue;
                };
                if host.is_empty() {
                    continue;
                }
                // D3: resolve through the known resolvers, first definitive
                // answer wins (Ok(vec![]) is a definitive negative).
                let mut resolved: Vec<Ipv4Addr> = Vec::new();
                for resolver in &ctx.resolvers {
                    match dns::query_a(*resolver, &host, ctx.timeout) {
                        Ok(addrs) => {
                            resolved = addrs;
                            break;
                        }
                        Err(_) => continue, // transport/retryable: next resolver
                    }
                }
                if resolved.is_empty() {
                    msgs.push(Msg::Touched(format!(
                        "ldap {ip}:{port}: {host} unresolved via the known resolvers - log-only"
                    )));
                    continue;
                }
                for target in resolved {
                    msgs.push(Msg::Found {
                        ip: target,
                        name: host.clone(),
                        source: "ldap",
                    });
                    if let Some(sam) = &sam {
                        if !sam.is_empty() {
                            msgs.push(Msg::Found {
                                ip: target,
                                name: sam.clone(),
                                source: "ldap-sam",
                            });
                        }
                    }
                }
            }
            msgs
        }
        Err(e) => vec![Msg::Touched(format!("ldap {ip}:{port}: {e}"))],
    }
}

/// Feeds one wave of jobs to the worker pool and drains the reports through
/// `on_msg` (main thread only — the registry writer and log writer never
/// see a second thread). Blocks until every job is done.
fn run_wave(jobs: Vec<Job>, ctx: Arc<RunCtx>, on_msg: &mut impl FnMut(Msg)) {
    if jobs.is_empty() {
        return;
    }
    let (jtx, jrx) = mpsc::sync_channel::<Option<Job>>(64);
    let (mtx, mrx) = mpsc::channel::<Msg>();
    let jrx = Arc::new(Mutex::new(jrx));
    thread::scope(|s| {
        for _ in 0..WORKERS {
            let jrx = Arc::clone(&jrx);
            let mtx = mtx.clone();
            let ctx = Arc::clone(&ctx);
            s.spawn(move || loop {
                let job = {
                    // Poison recovery: a worker panicking mid-pop must not
                    // wedge the pool — the mutex guard is rebuilt and the
                    // loop carries on (same idiom as the discovery engine).
                    let rx = jrx.lock().unwrap_or_else(|e| e.into_inner());
                    match rx.recv() {
                        Ok(Some(job)) => job,
                        Ok(None) | Err(_) => break,
                    }
                };
                let out = match job {
                    Job::Ptr { ip } => ptr_msgs(&ctx, ip),
                    Job::Axfr { resolver, zone } => axfr_msgs(&ctx, resolver, &zone),
                    Job::Cert { ip, port } => cert_msgs(&ctx, ip, port),
                    Job::Ldap { ip, port } => ldap_msgs(&ctx, ip, port),
                };
                for msg in out {
                    if mtx.send(msg).is_err() {
                        break; // the main thread is gone; stop working
                    }
                }
            });
        }
        // Main's sender clone goes first: when the workers are done, the
        // report channel closes and the drain below ends.
        drop(mtx);
        for job in jobs {
            let _ = jtx.send(Some(job)); // receivers outlive: pool is up
        }
        for _ in 0..WORKERS {
            let _ = jtx.send(None); // one sentinel per worker
        }
        drop(jtx);
        for msg in mrx {
            on_msg(msg);
        }
    });
}

/// Names-only run log: file only — a real perimeter has hundreds of
/// endpoints and the stderr copy belongs to the closing summary.
fn slog(log: &mut std::fs::File, line: &str) {
    let _ = writeln!(log, "{line}");
}

pub fn run(a: &NamesArgs) -> Result<()> {
    let sources = Sources::parse(&a.sources)?;
    let timeout = Duration::from_secs(a.timeout.max(1));

    // Read side first: a typo'd --out must error before any run dir exists.
    let mut db = Db::open_existing(&a.out)?;
    let run_id = state::new_names_id();
    db.set_run_id(&run_id);
    let run_dir = state::create_run(&a.out, &run_id)?;
    let mut log = state::open_run_log_as(&run_dir, "names.log")?;

    slog(
        &mut log,
        &format!(
            "names {run_id}: sources {} timeout {}s",
            sources.describe(),
            a.timeout.max(1)
        ),
    );

    // LDAP auth is config, not transport: a malformed RUSTRAWL_LDAP_BIND
    // must fail the run before any run dir exists.
    let auth = ldap::auth_from_env()?;
    if let ldap::LdapAuth::Simple { who, .. } = &auth {
        eprintln!(
            "WARNING: LDAP simple bind as {who} sends the password in cleartext (port 389) - anyone on the path can read it; prefer a Kerberos capable v2, or an anonymous bind"
        );
    }

    let inv = inventory(&db, &a.dns).context("reading the registry inventory")?;
    let mut resolvers = inv.resolvers.clone();
    if resolvers.is_empty() {
        resolvers = system_resolvers();
        slog(
            &mut log,
            &format!(
                "no resolver in --dns or the registry - falling back to /etc/resolv.conf ({} server(s))",
                resolvers.len()
            ),
        );
    }
    slog(
        &mut log,
        &format!(
            "{} asset(s), {} resolver(s) ({} from the registry)",
            inv.known.len(),
            resolvers.len(),
            inv.registry_resolvers
        ),
    );

    if sources.ldap {
        slog(
            &mut log,
            &format!(
                "ldap: {} target(s), auth {}",
                inv.ldap_targets.len(),
                match &auth {
                    ldap::LdapAuth::Anonymous => "anonymous".to_string(),
                    ldap::LdapAuth::Simple { who, .. } =>
                        format!("simple ({who}) - cleartext on 389"),
                }
            ),
        );
        if let ldap::LdapAuth::Simple { .. } = &auth {
            slog(
                &mut log,
                "WARNING: simple bind sends the password in cleartext over the wire",
            );
        }
    }

    let ctx = Arc::new(RunCtx {
        resolvers: resolvers.clone(),
        timeout,
        auth,
    });

    // Wave 1: one PTR job per known asset. The verified names fall out of
    // the report — they decide the AXFR zone list. Wave 2: one transfer
    // attempt per (resolver, zone). The main thread alone records and logs;
    // each wave gets its own report closure (wave 2 must not hold the
    // mutable borrow of `verified_names` wave 1 just filled).
    let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut run_hosts: BTreeSet<Ipv4Addr> = BTreeSet::new();
    let mut verified_names: Vec<String> = Vec::new();
    let known = &inv.known;
    {
        let db_ref = &mut db;
        let log_ref = &mut log;
        let mut on_msg = |msg: Msg| match msg {
            Msg::Found { ip, name, source } => {
                if known.contains(&ip) {
                    db_ref.record_name(ip, &name, source);
                    *counts.entry(source).or_insert(0) += 1;
                    run_hosts.insert(ip);
                    if source == "dns-ptr" {
                        verified_names.push(name);
                    }
                } else {
                    slog(
                        log_ref,
                        &format!("name {name} for {ip} ({source}) - not a known asset, log-only"),
                    );
                }
            }
            Msg::Touched(line) => slog(log_ref, &line),
        };
        if sources.dns && !ctx.resolvers.is_empty() {
            let jobs: Vec<Job> = inv.known.iter().map(|ip| Job::Ptr { ip: *ip }).collect();
            run_wave(jobs, Arc::clone(&ctx), &mut on_msg);
        }
    }
    // Wave 2: AXFR per (resolver, zone) plus the certificate reads — one
    // pool run for both. `run_wave` early-returns when dns was off or no
    // target came out of the inventory.
    let mut jobs: Vec<Job> = Vec::new();
    if sources.dns && !ctx.resolvers.is_empty() {
        let zones = derive_zones(&a.zone, &verified_names);
        slog(
            &mut log,
            &format!(
                "zones to attempt: {}",
                if zones.is_empty() {
                    "(none)".to_string()
                } else {
                    zones.join(", ")
                }
            ),
        );
        for zone in &zones {
            for resolver in &ctx.resolvers {
                jobs.push(Job::Axfr {
                    resolver: *resolver,
                    zone: zone.clone(),
                });
            }
        }
    }
    if sources.tls {
        slog(
            &mut log,
            &format!("{} tls target(s)", inv.cert_targets.len()),
        );
        for (ip, port) in &inv.cert_targets {
            jobs.push(Job::Cert {
                ip: *ip,
                port: *port,
            });
        }
    }
    if sources.ldap {
        slog(
            &mut log,
            &format!("{} ldap target(s)", inv.ldap_targets.len()),
        );
        for (ip, port) in &inv.ldap_targets {
            jobs.push(Job::Ldap {
                ip: *ip,
                port: *port,
            });
        }
    }
    {
        let db_ref = &mut db;
        let log_ref = &mut log;
        let mut on_msg = |msg: Msg| match msg {
            Msg::Found { ip, name, source } => {
                if known.contains(&ip) {
                    db_ref.record_name(ip, &name, source);
                    *counts.entry(source).or_insert(0) += 1;
                    run_hosts.insert(ip);
                } else {
                    slog(
                        log_ref,
                        &format!("name {name} for {ip} ({source}) - not a known asset, log-only"),
                    );
                }
            }
            Msg::Touched(line) => slog(log_ref, &line),
        };
        run_wave(jobs, Arc::clone(&ctx), &mut on_msg);
    }

    db.flush().context("writing the registry")?;
    db.checkpoint().context("checkpointing the registry")?;

    // New hostnames can flip a type guess (a host with only 445 open that
    // turns out to be named dc01): re-run the classifier over every host
    // this run touched — manual overrides never move.
    for ip in &run_hosts {
        crate::discovery::classify::reclassify_host(&mut db, *ip);
    }
    db.flush().context("writing the asset types")?;

    let total: u64 = counts.values().sum();
    let detail = counts
        .iter()
        .map(|(s, n)| format!("{s} {n}"))
        .collect::<Vec<_>>()
        .join(", ");
    slog(
        &mut log,
        &format!(
            "done: {total} name row(s) across {} host(s) - {detail}",
            run_hosts.len()
        ),
    );
    eprintln!(
        "names: {total} name row(s) on {} host(s){} - log {}",
        run_hosts.len(),
        if detail.is_empty() {
            String::new()
        } else {
            format!(" ({detail})")
        },
        run_dir.join("names.log").display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::db::Stage;

    // -------------------------------------------------- orchestrator end-to-end
    // A fake DNS server (UDP + TCP on one loopback port) answering a
    // verified PTR, a stale PTR and an AXFR zone; `run` must land exactly
    // the verified rows in the registry and the whole trail in names.log.

    fn name_wire(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// Header + echoed question, flags deciding QR/rcode, answer records
    /// appended by the caller.
    fn reply(txid: u16, question: &[u8], rcode: u8, truncated: bool, an: usize) -> Vec<u8> {
        let mut m = Vec::with_capacity(12 + question.len());
        m.extend_from_slice(&txid.to_be_bytes());
        let flags: u16 = 0x8000 | if truncated { 0x0200 } else { 0 } | rcode as u16;
        m.extend_from_slice(&flags.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes()); // qd
        m.extend_from_slice(&(an as u16).to_be_bytes());
        m.extend_from_slice(&[0; 4]); // ns + ar
        m.extend_from_slice(question);
        m
    }

    /// An answer record whose owner is a compression pointer at offset 12.
    fn answer_rr(rtype: u16, rdata: Vec<u8>) -> Vec<u8> {
        let mut r = vec![0xC0, 0x0C];
        r.extend_from_slice(&rtype.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes()); // IN
        r.extend_from_slice(&300u32.to_be_bytes()); // ttl
        r.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        r.extend_from_slice(&rdata);
        r
    }

    fn ptr_rdata(target: &str) -> Vec<u8> {
        name_wire(target)
    }

    /// The fake server: UDP for PTR/A, TCP for the AXFR stream. Serves the
    /// handful of shapes the orchestrator test needs, stops on `stop`.
    fn spawn_fake_dns(stop: Arc<std::sync::atomic::AtomicBool>) -> SocketAddr {
        use std::sync::atomic::Ordering;
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let listener = std::net::TcpListener::bind(udp.local_addr().unwrap()).unwrap();
        let udp_addr = udp.local_addr().unwrap();

        std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            udp.set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            loop {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                // UDP: one query at a time.
                let mut buf = [0u8; 2048];
                if let Ok((n, peer)) = udp.recv_from(&mut buf) {
                    let msg = &buf[..n];
                    if msg.len() < 12 {
                        continue;
                    }
                    let txid = u16::from_be_bytes([msg[0], msg[1]]);
                    // question name: walk labels from offset 12
                    let mut p = 12usize;
                    let mut qname = String::new();
                    while p < msg.len() && msg[p] != 0 {
                        let l = msg[p] as usize;
                        if !qname.is_empty() {
                            qname.push('.');
                        }
                        qname.push_str(&String::from_utf8_lossy(&msg[p + 1..p + 1 + l]));
                        p += 1 + l;
                    }
                    let qtype = u16::from_be_bytes([msg[p + 1], msg[p + 2]]);
                    let question = &msg[12..p + 5];
                    let out = match (qtype, qname.as_str()) {
                        (12, "2.0.0.127.in-addr.arpa") => {
                            // verified: the forward A will confirm 127.0.0.2
                            let mut r = reply(txid, question, 0, false, 1);
                            r.extend_from_slice(&answer_rr(
                                12,
                                ptr_rdata("web01.corp.example.com"),
                            ));
                            r
                        }
                        (12, "3.0.0.127.in-addr.arpa") => {
                            // stale: the forward A comes back NXDOMAIN
                            let mut r = reply(txid, question, 0, false, 1);
                            r.extend_from_slice(&answer_rr(
                                12,
                                ptr_rdata("stale.corp.example.com"),
                            ));
                            r
                        }
                        (1, "web01.corp.example.com") => {
                            let mut r = reply(txid, question, 0, false, 1);
                            r.extend_from_slice(&answer_rr(1, vec![127, 0, 0, 2]));
                            r
                        }
                        (1, "dc01.corp.example.com") => {
                            let mut r = reply(txid, question, 0, false, 1);
                            r.extend_from_slice(&answer_rr(1, vec![127, 0, 0, 2]));
                            r
                        }
                        _ => reply(txid, question, 3, false, 0), // NXDOMAIN
                    };
                    let _ = udp.send_to(&out, peer);
                }
                // TCP: non-blocking accept, one framed AXFR exchange.
                if let Ok((mut sock, _)) = listener.accept() {
                    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                    use std::io::Read;
                    let mut lb = [0u8; 2];
                    if sock.read_exact(&mut lb).is_err() {
                        continue;
                    }
                    let mut skip = vec![0u8; u16::from_be_bytes(lb) as usize];
                    if sock.read_exact(&mut skip).is_err() {
                        continue;
                    }
                    // zone message 1: echoed question + SOA + two A records
                    // (one known asset, one foreign IP the registry must NOT
                    // record)
                    let mut question = name_wire("corp.example.com");
                    question.extend_from_slice(&252u16.to_be_bytes()); // AXFR
                    question.extend_from_slice(&1u16.to_be_bytes()); // IN
                    let mut msg1 = reply(0, &question, 0, false, 3);
                    let mut soa_rr = name_wire("corp.example.com").clone();
                    soa_rr.extend_from_slice(&6u16.to_be_bytes()); // SOA
                    soa_rr.extend_from_slice(&1u16.to_be_bytes()); // IN
                    soa_rr.extend_from_slice(&0u32.to_be_bytes()); // ttl
                    let rd = vec![0u8; 22];
                    soa_rr.extend_from_slice(&(rd.len() as u16).to_be_bytes());
                    soa_rr.extend_from_slice(&rd);
                    msg1[6..8].copy_from_slice(&3u16.to_be_bytes());
                    msg1.extend_from_slice(&soa_rr);
                    for (name, ip) in [
                        ("srv01.corp.example.com", [127, 0, 0, 2]),
                        ("foreign.corp.example.com", [10, 99, 0, 5]),
                    ] {
                        let mut rr = name_wire(name);
                        rr.extend_from_slice(&1u16.to_be_bytes());
                        rr.extend_from_slice(&1u16.to_be_bytes());
                        rr.extend_from_slice(&0u32.to_be_bytes());
                        rr.extend_from_slice(&4u16.to_be_bytes());
                        rr.extend_from_slice(&ip);
                        msg1.extend_from_slice(&rr);
                    }
                    let mut msg2 = vec![0u8; 12];
                    msg2[0..2].copy_from_slice(&0u16.to_be_bytes());
                    msg2[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                    msg2[6..8].copy_from_slice(&1u16.to_be_bytes());
                    let mut soa2 = name_wire("corp.example.com");
                    soa2.extend_from_slice(&6u16.to_be_bytes());
                    soa2.extend_from_slice(&1u16.to_be_bytes());
                    soa2.extend_from_slice(&0u32.to_be_bytes());
                    soa2.extend_from_slice(&[0, 22]);
                    soa2.extend_from_slice(&[0u8; 22]);
                    msg2.extend_from_slice(&soa2);
                    let mut frame = (msg1.len() as u16).to_be_bytes().to_vec();
                    frame.extend_from_slice(&msg1);
                    frame.extend_from_slice(&(msg2.len() as u16).to_be_bytes());
                    frame.extend_from_slice(&msg2);
                    use std::io::Write;
                    let _ = sock.write_all(&frame);
                    // drop closes: the normal end of a transfer
                }
            }
        });
        udp_addr
    }

    #[test]
    fn orchestrator_collects_verified_ptr_and_axfr_only_for_known_assets() {
        use std::sync::atomic::AtomicBool;
        let stop = Arc::new(AtomicBool::new(false));
        let resolver = spawn_fake_dns(Arc::clone(&stop));

        let root = std::env::temp_dir().join(format!(
            "rustrawl-names-e2e-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&root).unwrap();
        {
            let mut db = Db::open(&root).unwrap();
            db.set_run_id("discovery_test");
            // the asset with a verified PTR, the asset with a stale one
            db.record_host(Ipv4Addr::new(127, 0, 0, 2), Stage::Sweep, true, 2);
            db.record_host(Ipv4Addr::new(127, 0, 0, 3), Stage::Sweep, true, 2);
            db.flush().unwrap();
        }

        let args = NamesArgs {
            out: root.clone(),
            dns: vec![resolver.to_string()],
            zone: vec![],
            sources: vec![],
            timeout: 2,
        };
        run(&args).unwrap();
        stop.store(true, std::sync::atomic::Ordering::SeqCst);

        // Registry: the verified PTR row, the AXFR row for the known asset,
        // nothing for the stale name's host, nothing for the foreign IP.
        let db = Db::open_read_only(&root).unwrap();
        let mut rows: Vec<(Ipv4Addr, String, String)> = Vec::new();
        db.names(&mut |ip, name, source, _seen, _run| {
            rows.push((ip, name.to_string(), source.to_string()));
        })
        .unwrap();
        rows.sort_by(|a, b| a.1.cmp(&b.1));
        assert_eq!(
            rows,
            vec![
                (
                    Ipv4Addr::new(127, 0, 0, 2),
                    "srv01.corp.example.com".to_string(),
                    "dns-axfr".to_string()
                ),
                (
                    Ipv4Addr::new(127, 0, 0, 2),
                    "web01.corp.example.com".to_string(),
                    "dns-ptr".to_string()
                ),
            ],
            "verified PTR + AXFR for the known asset; stale and foreign stay out"
        );

        // names.log: the whole trail, including the dropped and log-only
        // lines, in the newest names_ run directory.
        let mut runs: Vec<_> = std::fs::read_dir(root.join("runs"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("names_"))
                    .unwrap_or(false)
            })
            .collect();
        runs.sort();
        let log_path = runs.last().expect("a names_ run dir").join("names.log");
        let log_text = std::fs::read_to_string(log_path).unwrap();
        assert!(
            log_text.contains("ptr 127.0.0.2 web01.corp.example.com (verified)"),
            "{log_text}"
        );
        assert!(
            log_text
                .contains("ptr 127.0.0.3 stale.corp.example.com (dropped: forward A disagrees)"),
            "{log_text}"
        );
        assert!(log_text.contains("axfr corp.example.com via"), "{log_text}");
        assert!(
            log_text.contains("not a known asset, log-only"),
            "the foreign AXFR record must be logged, not stored: {log_text}"
        );
        assert!(log_text.starts_with("names names_"), "{log_text}");
        assert!(log_text.contains("done:"), "{log_text}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn sanitize_lowercases_and_strips_controls_and_edges() {
        assert_eq!(
            sanitize_name("DC01.Corp.Example.COM"),
            "dc01.corp.example.com"
        );
        assert_eq!(sanitize_name("host\n.example"), "host.example");
        assert_eq!(sanitize_name("bad\u{1f}name\tx"), "badnamex");
        assert_eq!(sanitize_name(".corp.example.com."), "corp.example.com");
        assert_eq!(sanitize_name("  spaced name  "), "spacedname");
        assert_eq!(sanitize_name(""), "");
        // A newline-only value must sanitize to nothing — the log-injection
        // defense depends on it.
        assert_eq!(sanitize_name("\n\r\t"), "");
    }

    #[test]
    fn sources_parse_and_refuse_unknowns() {
        let all = Sources::parse(&[]).unwrap();
        assert!(all.dns && all.tls && all.ldap);
        let dns_only = Sources::parse(&["dns".to_string(), "dns".to_string()]).unwrap();
        assert!(dns_only.dns && !dns_only.tls && !dns_only.ldap);
        assert!(Sources::parse(&["kerberos".to_string()]).is_err());
    }

    #[test]
    fn zones_derive_from_verified_names_and_explicit() {
        let zones = derive_zones(
            &["Corp.Example.COM".to_string()],
            &[
                "dc01.corp.example.com".to_string(),
                "mail.corp.example.com".to_string(),
                "4.3.2.1.in-addr.arpa".to_string(),
                "singlelabel".to_string(),
            ],
        );
        assert_eq!(
            zones,
            vec!["corp.example.com".to_string()],
            "domain part of verified names + explicit, deduped; reverse names skipped"
        );
        assert!(derive_zones(&[], &[]).is_empty());
    }

    #[test]
    fn system_resolvers_reads_the_common_shape() {
        // Not pinned to this box's resolv.conf — the parser is exercised via
        // the same code path with a temp file through the public fn? No: the
        // path is fixed, so pin the shape with a hand-rolled line set through
        // a direct parse (kept in sync with system_resolvers).
        let text = "# comment\nnameserver 10.0.0.1\nnameserver 10.0.0.2:53\noptions edns0\nnameserver junk\n";
        let mut got = Vec::new();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            if parts.next() == Some("nameserver") {
                if let Some(ip) = parts.next().and_then(|s| s.parse::<IpAddr>().ok()) {
                    got.push(SocketAddr::new(ip, 53));
                }
            }
        }
        assert_eq!(got.len(), 1, "only the plain v4 nameserver parses");
        assert_eq!(got[0].to_string(), "10.0.0.1:53");
    }

    // --- cert_msgs wiring -------------------------------------------------

    /// DER TLV builder for the fake certificate (short/two-byte long forms).
    fn tls_der(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if body.len() < 0x80 {
            out.push(body.len() as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(body);
        out
    }

    /// Minimal v3 leaf with a CN and SAN entries (see tls_cert::tests for
    /// the byte-level coverage; this one only needs a parseable blob).
    fn fake_leaf(cn: &str, sans: &[&str]) -> Vec<u8> {
        let atv = [
            tls_der(0x06, &[0x55, 0x04, 0x03]).as_slice(),
            tls_der(0x13, cn.as_bytes()).as_slice(),
        ]
        .concat();
        let mut san_blob = Vec::new();
        for s in sans {
            let mut g = vec![0x82, s.len() as u8];
            g.extend_from_slice(s.as_bytes());
            san_blob.extend_from_slice(&g);
        }
        let san_ext = tls_der(
            0x30,
            &[
                tls_der(0x06, &[0x55, 0x1d, 0x11]).as_slice(),
                tls_der(0x04, &tls_der(0x30, &san_blob)).as_slice(),
            ]
            .concat(),
        );
        let tbs = [
            tls_der(0xa0, &tls_der(0x02, &[2])).as_slice(),
            tls_der(0x02, &[1]).as_slice(),
            tls_der(0x30, &tls_der(0x06, &[0x2a])).as_slice(),
            tls_der(0x30, &tls_der(0x31, &tls_der(0x30, &atv))).as_slice(),
            tls_der(
                0x30,
                &[
                    tls_der(0x17, b"250101000000Z").as_slice(),
                    tls_der(0x17, b"260101000000Z").as_slice(),
                ]
                .concat(),
            )
            .as_slice(),
            tls_der(0x30, &tls_der(0x31, &tls_der(0x30, &atv))).as_slice(),
            tls_der(0x30, &[0x00]).as_slice(),
            tls_der(0xa3, &tls_der(0x30, &san_ext)).as_slice(),
        ]
        .concat();
        // Certificate = SEQ { tbsCertificate, signatureAlgorithm, signature }
        tls_der(
            0x30,
            &[
                tls_der(0x30, &tbs).as_slice(),
                tls_der(0x30, &tls_der(0x06, &[0x2a])).as_slice(),
                tls_der(0x03, &[0x00]).as_slice(),
            ]
            .concat(),
        )
    }

    #[test]
    fn cert_msgs_reports_cn_and_san_as_tls_finds() {
        // Fake TLS server: read the hello, answer ServerHello + Certificate
        // for web01, close.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cert = fake_leaf(
            "web01.corp.example.com",
            &["web01.corp.example.com", "alt.corp.example.com"],
        );
        let mut hs = vec![2, 0, 0, 38]; // ServerHello: version+random+session+suite+comp
        hs.extend_from_slice(&[0x03, 0x03]);
        hs.extend_from_slice(&[0u8; 32]);
        hs.push(0);
        hs.extend_from_slice(&[0xc0, 0x13]);
        hs.push(0);
        let cert_msg = {
            // Certificate body: 3-byte list length, 3-byte entry length, DER
            let len3 = [
                (cert.len() >> 16) as u8,
                (cert.len() >> 8) as u8,
                cert.len() as u8,
            ];
            let mut body = len3.to_vec(); // list length
            body.extend_from_slice(&len3); // entry length
            body.extend_from_slice(&cert);
            let mut m = vec![
                11,
                (body.len() >> 16) as u8,
                (body.len() >> 8) as u8,
                body.len() as u8,
            ];
            m.extend_from_slice(&body);
            m
        };
        let mut stream = vec![22, 0x03, 0x03]; // handshake record header
        let payload = [hs.as_slice(), cert_msg.as_slice()].concat();
        stream.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        stream.extend_from_slice(&payload);
        let handle = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            use std::io::Read;
            let mut buf = [0u8; 512];
            let _ = s.read(&mut buf);
            use std::io::Write;
            s.write_all(&stream).unwrap();
        });
        let ctx = RunCtx {
            resolvers: Vec::new(),
            timeout: Duration::from_secs(2),
            auth: ldap::LdapAuth::Anonymous,
        };
        let ip = match addr.ip() {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => unreachable!("test listener binds v4"),
        };
        let msgs = cert_msgs(&ctx, ip, addr.port());
        handle.join().unwrap();
        let mut found: Vec<(Ipv4Addr, String, &'static str)> = Vec::new();
        for m in &msgs {
            match m {
                Msg::Found { ip, name, source } => found.push((*ip, name.clone(), source)),
                Msg::Touched(line) => {
                    assert!(
                        line.contains("cn=web01.corp.example.com")
                            && line.contains("alt.corp.example.com"),
                        "{line}"
                    );
                }
            }
        }
        assert_eq!(
            found,
            vec![
                (ip, "web01.corp.example.com".to_string(), "tls"),
                (ip, "alt.corp.example.com".to_string(), "tls"),
            ],
            "CN first, then the SAN entries, all as tls finds"
        );
    }

    // --- ldap_msgs wiring (D3: dNSHostName resolved via the resolvers) ----

    #[test]
    fn ldap_msgs_resolves_dnshostname_and_records_sam() {
        use std::sync::atomic::Ordering;
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let resolver = spawn_fake_dns(Arc::clone(&stop));
        let script = vec![
            vec![ldap::tests::bind_ok()],
            vec![
                ldap::tests::rootdse_entry("DC=corp,DC=example,DC=com"), // rootDSE
                ldap::tests::done(0, None),
            ],
            vec![
                ldap::tests::entry(Some("DC01$"), Some("dc01.corp.example.com")),
                ldap::tests::done(0, None),
            ],
        ];
        let (laddr, handle) = ldap::tests::fake_ldap(script);
        let ctx = RunCtx {
            resolvers: vec![resolver],
            timeout: Duration::from_secs(2),
            auth: ldap::LdapAuth::Anonymous,
        };
        let lip = match laddr.ip() {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => unreachable!("test listener binds v4"),
        };
        let msgs = ldap_msgs(&ctx, lip, laddr.port());
        handle.join().unwrap();
        stop.store(true, Ordering::SeqCst);
        let mut found: Vec<(Ipv4Addr, String, &'static str)> = Vec::new();
        let mut touched: Vec<String> = Vec::new();
        for m in &msgs {
            match m {
                Msg::Found { ip, name, source } => found.push((*ip, name.clone(), source)),
                Msg::Touched(line) => touched.push(line.clone()),
            }
        }
        assert!(
            touched
                .iter()
                .any(|l| l.contains("root DC=corp,DC=example,DC=com; 1 computer(s)")),
            "{touched:?}"
        );
        assert_eq!(
            found,
            vec![
                (
                    Ipv4Addr::new(127, 0, 0, 2), // the fake resolver's A answer
                    "dc01.corp.example.com".to_string(),
                    "ldap"
                ),
                (Ipv4Addr::new(127, 0, 0, 2), "dc01$".to_string(), "ldap-sam"),
            ],
            "dNSHostName and the machine's sAMAccountName under the resolved IP"
        );
    }

    #[test]
    fn ldap_msgs_logs_only_when_resolution_fails_or_host_is_missing() {
        let script = vec![
            vec![ldap::tests::bind_ok()],
            vec![
                ldap::tests::rootdse_entry("DC=corp,DC=example,DC=com"),
                ldap::tests::done(0, None),
            ],
            vec![
                // one page: the done's empty cookie ends the paged loop
                ldap::tests::entry(Some("DC01$"), Some("lost.corp.example.com")), // NXDOMAIN
                ldap::tests::entry(Some("WEB01$"), None),                         // no dNSHostName
                ldap::tests::done(0, None),
            ],
        ];
        let (laddr, handle) = ldap::tests::fake_ldap(script);
        let ctx = RunCtx {
            resolvers: Vec::new(), // nothing to resolve with
            timeout: Duration::from_secs(2),
            auth: ldap::LdapAuth::Anonymous,
        };
        let lip = match laddr.ip() {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => unreachable!("test listener binds v4"),
        };
        let msgs = ldap_msgs(&ctx, lip, laddr.port());
        handle.join().unwrap();
        let mut found = 0;
        let mut touched: Vec<String> = Vec::new();
        for m in &msgs {
            match m {
                Msg::Found { .. } => found += 1,
                Msg::Touched(line) => touched.push(line.clone()),
            }
        }
        assert_eq!(found, 0, "nothing resolved - nothing stored");
        assert!(
            touched
                .iter()
                .any(|l| l.contains("lost.corp.example.com unresolved via the known resolvers")),
            "{touched:?}"
        );
        assert!(
            touched
                .iter()
                .any(|l| l.contains("web01$ (no dNSHostName) - log-only")),
            "{touched:?}"
        );
    }
}
