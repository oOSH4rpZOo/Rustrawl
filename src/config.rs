use std::path::Path;
use std::time::Duration;

use crate::ports;
use crate::targets::IpRange;
use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

/// Scope YAML — the tool's single entry point. Two sections, one per
/// subcommand: `discovery` drives `rustrawl run` (the wide sweep plus the
/// /24 expansion), `scan` drives `rustrawl scan` (nmap over the up list).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub name: String,
    pub includes: Vec<String>,
    #[serde(default)]
    pub excludes: Vec<String>,
    #[serde(default)]
    pub sensitive_zones: Vec<Zone>,
    #[serde(default)]
    pub discovery: Discovery,
    #[serde(default)]
    pub scan: ScanCfg,
    #[serde(default)]
    pub rescan: Rescan,
}

/// Sensitive zone (seed lesson 6): the tool throttles or refuses per host.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Zone {
    pub range: String,
    pub policy: Policy,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    /// Zero probes.
    Passive,
    /// Reduced port profile only.
    Light,
}

/// A per-range sweep profile: ranges matching `range` (first match wins,
/// entries in YAML order) are swept with `ports` instead of the global
/// `discovery.ports`. The perimeter is partitioned into one sweep group per
/// distinct profile — each group gets its own permutation pass.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SweepProfile {
    pub range: String,
    #[serde(default = "d_profile_ports")]
    pub ports: PortSpec,
}

fn d_profile_ports() -> PortSpec {
    PortSpec::Profile("top25".into())
}

/// The discovery stages (`rustrawl run`): the wide sweep and the /24
/// expansion. Evidence filenames and DB rows keep their internal storage
/// names — the YAML speaks the operator vocabulary.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Discovery {
    #[serde(default = "d_rate")]
    pub rate_pps: u32,
    /// Sweep port profile: topN / full / explicit list — the default for
    /// every range not covered by `sweep_profiles`.
    #[serde(default = "d_ports_sweep")]
    pub ports: PortSpec,
    /// Per-range sweep profiles, e.g. a gentle top5 on 10.0.0.0/8 and a
    /// wider top25 on the office /16s. First matching entry wins; what no
    /// entry covers uses `ports`.
    #[serde(default)]
    pub sweep_profiles: Vec<SweepProfile>,
    /// Expansion liveness probe profile — up or down, no port enumeration:
    /// the real enumeration is the scan, on the up-host list.
    #[serde(default = "d_ports_expand")]
    pub expand_ports: PortSpec,
    /// ICMP echo liveness pass before each sweep group (one echo request per
    /// host, replies matched by source IP). Catches hosts that drop all
    /// inbound TCP; raw mode only — connect mode skips it with a note.
    /// Turn off for networks where ICMP egress is alarmed on.
    #[serde(default = "d_true")]
    pub icmp: bool,
    /// Network interface all discovery probes must leave through
    /// (SO_BINDTODEVICE). The route to the targets is checked against it at
    /// startup — a wrong interface fails fast instead of scanning the
    /// wrong network. Requires root/CAP_NET_RAW.
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default = "d_jitter")]
    pub jitter_pct: u32,
    /// Level-1 permutation block size — consumed by the engines.
    #[serde(default = "d_block")]
    pub block: u32,
    /// Consecutive settled-mute hosts (after a live one) that trip the
    /// filter kill-switch — off by default: the pause must be asked for
    /// explicitly in the scope, because a legitimately dark range pays it
    /// on every trigger. Set it (e.g. 1024) on filtered networks where the
    /// guard earns its keep. Every re-probe that proves the stretch was
    /// merely empty doubles the live budget (capped at 65,536, persisted so
    /// a resume keeps it).
    #[serde(default)]
    pub mute_abort_after: u32,
    /// Seconds the kill-switch pauses before re-probing the last live host.
    #[serde(default = "d_mute_cooldown")]
    pub mute_cooldown_secs: u64,
}

fn d_mute_cooldown() -> u64 {
    60
}

impl Default for Discovery {
    fn default() -> Self {
        Self {
            rate_pps: d_rate(),
            ports: d_ports_sweep(),
            sweep_profiles: Vec::new(),
            expand_ports: d_ports_expand(),
            icmp: true,
            interface: None,
            jitter_pct: d_jitter(),
            block: d_block(),
            mute_abort_after: 0,
            mute_cooldown_secs: d_mute_cooldown(),
        }
    }
}

impl Discovery {
    /// The sweep profile for one address: first matching `sweep_profiles`
    /// entry (YAML order), else the global `ports`. Pinned by tests today;
    /// the planned /24 early-exit feature reads it per neighborhood.
    #[allow(dead_code)]
    pub fn sweep_spec_for(&self, ip: std::net::Ipv4Addr) -> &PortSpec {
        let v = u32::from(ip);
        for p in &self.sweep_profiles {
            if let Ok(r) = IpRange::parse(&p.range) {
                if r.start <= v && v <= r.end {
                    return &p.ports;
                }
            }
        }
        &self.ports
    }
}

/// A per-range scan profile: hosts whose first matching entry is this one
/// are scanned with those `nmap_args` — the port list rides inside them
/// (`-p 80,9100 -sC`); an absent `nmap_args` inherits the baseline
/// (`--nmap-args`/`scan.nmap_args`). Overlapping entries are allowed —
/// first one wins (YAML order; CLI `--profile` entries match before
/// these). A bare entry with empty args just names the range so
/// `--only-profile` can select it without changing the plan — scan
/// economy: a short `-p` list on the printer ranges, `-p-` on a
/// crown-jewel server (/32), the baseline everywhere else.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ScanProfile {
    pub range: String,
    #[serde(default)]
    pub nmap_args: Option<String>,
}

impl ScanProfile {
    /// CLI form of one profile: `<range>=<nmap args>`, e.g.
    /// `"10.30.0.0/24=-p 80,9100 -sC"` (quote it — the value has spaces).
    pub fn parse_cli(s: &str) -> Result<ScanProfile> {
        let (range, args) = s.split_once('=').with_context(|| {
            format!("--profile: \"{s}\" - expected <range>=<nmap args>, e.g. 10.30.0.0/24=-p- -sC")
        })?;
        IpRange::parse(range.trim()).with_context(|| format!("--profile: range of \"{s}\""))?;
        let args = args.trim();
        if args.is_empty() {
            bail!("--profile: \"{s}\" - the args after = are empty");
        }
        Ok(ScanProfile {
            range: range.trim().to_string(),
            nmap_args: Some(args.to_string()),
        })
    }
}

/// The scan stage (`rustrawl scan`): operator-tuned nmap against the up list.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanCfg {
    /// nmap arguments, spliced verbatim into rustrawl's frame — the output
    /// base (-oA), the host list and random/target scanning stay
    /// rustrawl's; the port list is the operator's (`-p-`, `-p 21,22`,
    /// `--exclude-ports`; no `-p` means nmap's own default, the top 1000
    /// TCP ports). `null` means the default below.
    #[serde(default)]
    pub nmap_args: Option<String>,
    /// nmap processes in parallel.
    #[serde(default = "d_threads")]
    pub threads: u32,
    /// Incremental scan window ("30d", "12h"): queue only hosts never
    /// scanned, or whose latest scan row is older than this. `null`/absent
    /// queues every up host — full coverage, the safe default for a one-shot
    /// engagement.
    #[serde(default)]
    pub refresh_after: Option<String>,
    /// Per-range scan profiles (see [`ScanProfile`]): printers → a short
    /// `-p` list, crown jewels → `-p-`, the rest → the baseline args.
    /// Overlapping entries are allowed — first one wins; what none covers
    /// uses the baseline.
    #[serde(default)]
    pub profiles: Vec<ScanProfile>,
}

/// nmap arguments used when neither the YAML nor the CLI overrides them.
pub const DEFAULT_NMAP_ARGS: &str = "-sC -sV";

fn d_threads() -> u32 {
    4
}

impl Default for ScanCfg {
    fn default() -> Self {
        Self {
            nmap_args: None,
            threads: d_threads(),
            refresh_after: None,
            profiles: Vec::new(),
        }
    }
}

impl ScanCfg {
    /// The effective nmap arguments: YAML value or the agreed default.
    pub fn resolved_args(&self) -> String {
        self.nmap_args
            .clone()
            .unwrap_or_else(|| DEFAULT_NMAP_ARGS.to_string())
    }

    /// The incremental window, parsed; None = full queue.
    pub fn refresh_delay(&self) -> Result<Option<Duration>> {
        let d = delay(&self.refresh_after, "scan.refresh_after")?;
        if d.is_some_and(|d| d.is_zero()) {
            bail!("scan.refresh_after: zero window");
        }
        Ok(d)
    }
}

/// Rejects the nmap arguments that would fight rustrawl's own frame: the
/// output base and the host list are rustrawl's — an argument overriding
/// them would break evidence collection or the queue contract. The port
/// list is the operator's (`-p-`, `-p 21,22`, `--exclude-ports` ride in
/// the args verbatim; no `-p` means nmap's own default). Tokens are
/// whitespace-split; glued output frames (`-oNfile`) are caught too, and
/// so is any token that would reach nmap as a scan target.
pub fn check_nmap_args(args: &str) -> Result<()> {
    const FRAMES: &[&str] = &["-oA", "-oN", "-oX", "-oG", "-oS", "-iL"];
    for tok in args.split_whitespace() {
        if tok == "-iR" || tok.starts_with("-iR") {
            bail!(
                "nmap_args: \"{tok}\" - the target list is rustrawl's (-iR scans random hosts, never the scope)"
            );
        }
        for f in FRAMES {
            if tok == *f || tok.starts_with(f) {
                bail!(
                    "nmap_args: \"{tok}\" - output files and host lists are rustrawl's ({f} drives the evidence layout)"
                );
            }
        }
        if is_target_shaped(tok) {
            bail!(
                "nmap_args: \"{tok}\" - the target list is rustrawl's (that token would reach nmap as a host; dotted option values glue with =)"
            );
        }
    }
    Ok(())
}

/// Does the token look like a scan target — an ip, a cidr or a dotted
/// name — rather than an nmap option or its value? Option values that
/// legitimately carry dots (`--script x.nse`) glue to their flag: the `=`
/// marks them as values (`--script=x.nse`).
fn is_target_shaped(tok: &str) -> bool {
    if tok.starts_with('-') || tok.contains('=') {
        return false;
    }
    if tok.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if let Some((ip, _)) = tok.split_once('/') {
        if ip.parse::<std::net::IpAddr>().is_ok() {
            return true;
        }
    }
    tok.contains('.')
}

#[cfg(test)]
mod target_tests {
    use super::{check_nmap_args, is_target_shaped};

    #[test]
    fn targets_look_like_targets_and_values_do_not() {
        // targets: ips, cidrs, dotted names
        assert!(is_target_shaped("10.0.0.9"));
        assert!(is_target_shaped("::1"));
        assert!(is_target_shaped("10.30.0.0/24"));
        assert!(is_target_shaped("dc01.corp.local"));
        // options and glued values pass
        assert!(!is_target_shaped("-sC"));
        assert!(!is_target_shaped("--script=x.nse"));
        assert!(!is_target_shaped("user=admin"));
        // script categories and plain words are not targets
        assert!(!is_target_shaped("vuln"));
        assert!(!is_target_shaped("5"));
    }

    #[test]
    fn nmap_args_reject_targets_but_keep_flags_and_values() {
        assert!(check_nmap_args("-sC -sV").is_ok());
        assert!(check_nmap_args("--script=vuln.nse -T4 --version-light").is_ok());
        for tok in ["10.0.0.9", "dc01.corp.local", "10.30.0.0/24"] {
            let e = check_nmap_args(tok).unwrap_err().to_string();
            assert!(e.contains("target list is rustrawl's"), "{tok}: {e}");
        }
    }
}

/// Port profile: a name ("top25", "top1000", "full") or an explicit list.
///
/// topN profiles resolve against the embedded nmap-services ranking
/// ([`crate::ports::RANKED`], 8387 TCP ports); "full" is 1..=65535.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum PortSpec {
    Profile(String),
    List(Vec<u16>),
}

impl PortSpec {
    /// (explicit list when embedded, port count).
    pub fn resolve(&self) -> Result<(Option<Vec<u16>>, u64)> {
        match self {
            PortSpec::List(l) => {
                if l.is_empty() {
                    bail!("empty port list");
                }
                if l.contains(&0) {
                    bail!("invalid port 0 in list");
                }
                let mut clean = l.clone();
                clean.sort_unstable();
                clean.dedup();
                if clean.len() != l.len() {
                    bail!("duplicate ports in list");
                }
                let n = clean.len() as u64;
                Ok((Some(clean), n))
            }
            PortSpec::Profile(p) => match p.as_str() {
                "full" => Ok((None, 65_535)),
                t => {
                    let n: u64 = t
                        .strip_prefix("top")
                        .filter(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
                        .map(|rest| rest.parse())
                        .transpose()
                        .map_err(|_| anyhow!("unparseable profile \"{t}\" (expected topN, e.g. top1000)"))?
                        .ok_or_else(|| {
                            anyhow!("unknown profile: \"{p}\" (expected topN, full, or an explicit list)")
                        })?;
                    if n == 0 {
                        bail!("profile \"{t}\": 0 ports");
                    }
                    if n as usize > ports::RANKED.len() {
                        bail!(
                            "profile \"{t}\": beyond the embedded ranking ({} ports) - use \"full\" for all 65,535",
                            ports::RANKED.len()
                        );
                    }
                    Ok((Some(ports::top_n(n as usize)), n))
                }
            },
        }
    }
}

fn d_rate() -> u32 {
    10_000
}

fn d_ports_sweep() -> PortSpec {
    PortSpec::Profile("top25".into())
}

fn d_ports_expand() -> PortSpec {
    // top25 rather than a hand-picked short list: the /24 expansion is cheap
    // (255 hosts × 25 ports ≈ 0.6 s per neighborhood at 10k pps) and Windows
    // stealth-firewalls only reveal themselves on an open, allowed port — a
    // wide knock list is the cheapest liveness insurance there is.
    PortSpec::Profile("top25".into())
}

fn d_jitter() -> u32 {
    20
}

fn d_block() -> u32 {
    4096
}

fn d_true() -> bool {
    true
}

fn d_retry() -> Option<String> {
    Some("7d".into())
}

fn d_recheck_up() -> Option<String> {
    Some("30d".into())
}

/// Rescan policies — the DB is the registry, not a run's fuzzy memory.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rescan {
    /// Fresh DB verdicts are skipped by the next run. Consumed by the DB
    /// layer at SELECT time, before every scan decision.
    #[serde(default = "d_true")]
    pub skip_done: bool,
    /// Delay after which a no_response is retried ("7d", "12h"...).
    /// Agreed default: 7 days — a miss is not a verdict, but it ages.
    /// `null` disables the retry: a miss becomes a permanent verdict
    /// (the host is only probed again with `--force`).
    #[serde(default = "d_retry")]
    pub retry_no_response_after: Option<String>,
    /// Delay after which an `up` verdict is re-verified ("30d"...). Agreed
    /// default: 30 days — a machine up since forever may have gone dark.
    #[serde(default = "d_recheck_up")]
    pub recheck_up_after: Option<String>,
}

impl Default for Rescan {
    fn default() -> Self {
        Self {
            skip_done: true,
            retry_no_response_after: d_retry(),
            recheck_up_after: d_recheck_up(),
        }
    }
}

impl Rescan {
    pub fn no_response_delay(&self) -> Result<Option<Duration>> {
        delay(
            &self.retry_no_response_after,
            "rescan.retry_no_response_after",
        )
    }

    pub fn recheck_up_delay(&self) -> Result<Option<Duration>> {
        delay(&self.recheck_up_after, "rescan.recheck_up_after")
    }
}

fn delay(value: &Option<String>, what: &'static str) -> Result<Option<Duration>> {
    match value.as_deref() {
        None => Ok(None),
        Some(s) => crate::util::parse_duration(s).map(Some).context(what),
    }
}

pub fn load(path: &Path) -> Result<Scope> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let scope: Scope = serde_yaml_ng::from_str(&text).map_err(|e| {
        let mut msg = format!("YAML format of {}\n  {e}", path.display());
        // The pre-redesign vocabulary — point at the new section names.
        if ["phase_a", "phase_b", "phase_c"]
            .iter()
            .any(|k| msg.contains(k))
        {
            msg.push_str(
                "\n  note: the section names changed - phase_a/phase_b are now one \
                 `discovery:` section (ports → ports/expand_ports), phase_c is `scan:` \
                 (nmap_args, threads)",
            );
        }
        anyhow!("{msg}")
    })?;
    scope.validate()?;
    Ok(scope)
}

impl Scope {
    fn validate(&self) -> Result<()> {
        if self.includes.is_empty() {
            bail!("includes: at least one entry required");
        }
        if self.discovery.rate_pps == 0 {
            bail!("discovery.rate_pps: 0 pps");
        }
        if self.discovery.jitter_pct > 50 {
            bail!("discovery.jitter_pct: > 50%");
        }
        // Below 16 the level-2 shuffle has nothing to shuffle (the seed lesson
        // wants probe-order randomization per block); above 2^20 the block
        // sweep itself becomes a scanning pattern (sequential-looking bursts).
        if !(16..=1_048_576).contains(&self.discovery.block) {
            bail!(
                "discovery.block: {} - 16..=1,048,576 required (the 2-level permutation block size)",
                self.discovery.block
            );
        }
        self.discovery.ports.resolve().context("discovery.ports")?;
        for (i, p) in self.discovery.sweep_profiles.iter().enumerate() {
            IpRange::parse(&p.range)
                .with_context(|| format!("discovery.sweep_profiles[{}].range", i))?;
            p.ports
                .resolve()
                .with_context(|| format!("discovery.sweep_profiles[{}].ports", i))?;
        }
        if let Some(iface) = &self.discovery.interface {
            if iface.is_empty() || iface.len() > 15 {
                bail!(
                    "discovery.interface: \"{iface}\" - expected a Linux interface name (1..=15 chars, e.g. eth0)"
                );
            }
        }
        self.discovery
            .expand_ports
            .resolve()
            .context("discovery.expand_ports")?;
        if self.discovery.mute_cooldown_secs > 3600 {
            bail!(
                "discovery.mute_cooldown_secs: {} - over an hour of dead air per trigger is not a cooldown",
                self.discovery.mute_cooldown_secs
            );
        }
        if let Some(args) = &self.scan.nmap_args {
            check_nmap_args(args).context("scan.nmap_args")?;
        }
        for (i, p) in self.scan.profiles.iter().enumerate() {
            IpRange::parse(&p.range).with_context(|| format!("scan.profiles[{}].range", i))?;
            if let Some(args) = &p.nmap_args {
                check_nmap_args(args).with_context(|| format!("scan.profiles[{}].nmap_args", i))?;
            }
        }
        if !(1..=64).contains(&self.scan.threads) {
            bail!(
                "scan.threads: {} - 1..=64 nmap processes in parallel",
                self.scan.threads
            );
        }
        self.scan.refresh_delay()?;
        for z in &self.sensitive_zones {
            IpRange::parse(&z.range).with_context(|| format!("sensitive_zones {}", z.range))?;
        }
        if let Some(d) = self.rescan.no_response_delay()? {
            if d.is_zero() {
                bail!("rescan.retry_no_response_after: zero delay");
            }
        }
        if let Some(d) = self.rescan.recheck_up_delay()? {
            if d.is_zero() {
                bail!("rescan.recheck_up_after: zero delay");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(s: &str) -> Scope {
        serde_yaml_ng::from_str(s).unwrap()
    }

    #[test]
    fn agreed_defaults() {
        let s = yaml("name: t\nincludes: [10.0.0.0/24]\n");
        assert!(s.rescan.skip_done);
        assert_eq!(
            s.rescan.no_response_delay().unwrap(),
            Some(Duration::from_secs(604_800))
        );
        assert_eq!(
            s.rescan.recheck_up_delay().unwrap(),
            Some(Duration::from_secs(30 * 86_400))
        );
        assert_eq!(s.discovery.rate_pps, 10_000);
        // the mute kill-switch is opt-in: no pause unless the scope asks
        assert_eq!(s.discovery.mute_abort_after, 0);
        assert_eq!(s.discovery.mute_cooldown_secs, 60);
        assert!(s.discovery.icmp, "icmp liveness defaults to on");
        assert_eq!(s.discovery.expand_ports.resolve().unwrap().1, 25);
        assert_eq!(s.scan.threads, 4);
        assert_eq!(s.scan.resolved_args(), DEFAULT_NMAP_ARGS);
    }

    #[test]
    fn discovery_and_scan_sections() {
        let s = yaml(
            "name: t\nincludes: [10.0.0.0/24]\ndiscovery:\n  rate_pps: 5000\n  ports: top5\n  expand_ports: [22, 80]\nscan:\n  nmap_args: \"-sV -Pn -p-\"\n  threads: 8\n",
        );
        assert_eq!(s.discovery.rate_pps, 5000);
        assert_eq!(s.discovery.ports.resolve().unwrap().1, 5);
        assert_eq!(s.discovery.expand_ports.resolve().unwrap().1, 2);
        assert_eq!(s.scan.nmap_args.as_deref(), Some("-sV -Pn -p-"));
        assert_eq!(s.scan.threads, 8);
        assert!(s.validate().is_ok());
        // a stale scope with `ports:` in the scan section is refused at
        // parse time (deny_unknown_fields) — the port list moved into the
        // nmap args
        let stale =
            "name: t\nincludes: [10.0.0.0/24]\nscan:\n  ports: top100\n  nmap_args: \"-sV\"\n";
        assert!(serde_yaml_ng::from_str::<Scope>(stale).is_err());
    }

    #[test]
    fn sweep_profiles_per_range() {
        let s = yaml(
            "name: t\nincludes: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]\ndiscovery:\n  ports: top25\n  sweep_profiles:\n    - range: 192.168.0.0/16\n      ports: top25\n    - range: 172.16.0.0/12\n      ports: top10\n    - range: 10.0.0.0/8\n      ports: top5\n  interface: eth3\n",
        );
        assert!(s.validate().is_ok());
        assert_eq!(
            s.discovery
                .sweep_spec_for("192.168.5.1".parse().unwrap())
                .resolve()
                .unwrap()
                .1,
            25
        );
        assert_eq!(
            s.discovery
                .sweep_spec_for("172.20.0.1".parse().unwrap())
                .resolve()
                .unwrap()
                .1,
            10
        );
        assert_eq!(
            s.discovery
                .sweep_spec_for("10.255.0.1".parse().unwrap())
                .resolve()
                .unwrap()
                .1,
            5
        );
        // first match wins on overlap
        let ov = yaml(
            "name: t\nincludes: [10.0.0.0/8]\ndiscovery:\n  ports: top100\n  sweep_profiles:\n    - range: 10.0.0.0/16\n      ports: top10\n",
        );
        assert_eq!(
            ov.discovery
                .sweep_spec_for("10.0.0.5".parse().unwrap())
                .resolve()
                .unwrap()
                .1,
            10
        );
        assert_eq!(
            ov.discovery
                .sweep_spec_for("10.1.0.5".parse().unwrap())
                .resolve()
                .unwrap()
                .1,
            100
        );
        // bad profile range refused
        let bad = yaml(
            "name: t\nincludes: [10.0.0.0/8]\ndiscovery:\n  sweep_profiles:\n    - range: nope\n",
        );
        assert!(bad.validate().is_err());
        // empty interface name refused
        let badif = yaml("name: t\nincludes: [10.0.0.0/8]\ndiscovery:\n  interface: \"\"\n");
        assert!(badif.validate().is_err());
    }

    #[test]
    fn mute_knobs() {
        // explicit values pass through; 0 disables the kill-switch legally
        let s = yaml(
            "name: t\nincludes: [10.0.0.0/24]\ndiscovery:\n  mute_abort_after: 0\n  mute_cooldown_secs: 300\n",
        );
        assert_eq!(s.discovery.mute_abort_after, 0);
        assert!(s.validate().is_ok(), "0 = disabled is a legal setting");
        let bad =
            yaml("name: t\nincludes: [10.0.0.0/24]\ndiscovery:\n  mute_cooldown_secs: 7200\n");
        assert!(
            bad.validate().is_err(),
            "an hour+ of dead air is not a cooldown"
        );
    }

    #[test]
    fn scan_section_validation() {
        // the port list is the operator's: -p in every form validates now
        let ports = yaml("name: t\nincludes: [10.0.0.0/24]\nscan:\n  nmap_args: \"-sV -p 22,80 --exclude-ports 655\"\n");
        assert!(
            ports.validate().is_ok(),
            "-p and --exclude-ports are legal args"
        );
        let full = yaml("name: t\nincludes: [10.0.0.0/24]\nscan:\n  nmap_args: \"-p-\"\n");
        assert!(full.validate().is_ok(), "-p- (every port) is legal");
        let glued =
            yaml("name: t\nincludes: [10.0.0.0/24]\nscan:\n  nmap_args: \"-sV -oNout.txt\"\n");
        assert!(glued.validate().is_err(), "glued -oN caught too");
        let bad_threads = yaml("name: t\nincludes: [10.0.0.0/24]\nscan:\n  threads: 0\n");
        assert!(bad_threads.validate().is_err());
        let ok = yaml(
            "name: t\nincludes: [10.0.0.0/24]\nscan:\n  nmap_args: \"-sV --version-light -T4\"\n",
        );
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn scan_profiles_parse_defaults_and_validate() {
        let s = yaml(
            "name: t\nincludes: [10.0.0.0/8]\nscan:\n  profiles:\n    - range: 10.30.0.0/24\n      nmap_args: \"-sV -p 22,80,9100\"\n    - range: 10.10.4.17/32\n      nmap_args: \"-p- -sC\"\n    - range: 10.40.0.0/16\n",
        );
        assert_eq!(s.scan.profiles.len(), 3);
        assert_eq!(
            s.scan.profiles[0].nmap_args.as_deref(),
            Some("-sV -p 22,80,9100"),
            "explicit args on the profile — the port list rides inside"
        );
        // range-only entry: legal, args inherit the baseline
        assert!(s.scan.profiles[2].nmap_args.is_none());
        assert!(s.validate().is_ok());
        // overlap is legal — first match wins is a documented rule, not an error
        let ov = yaml(
            "name: t\nincludes: [10.0.0.0/8]\nscan:\n  profiles:\n    - range: 10.0.0.0/16\n      nmap_args: \"-p 80\"\n    - range: 10.0.0.0/8\n      nmap_args: \"-p 443\"\n",
        );
        assert!(ov.validate().is_ok());
        // unknown fields refused (at parse time — deny_unknown_fields):
        // `ports` is gone from profiles, a stale scope fails loudly
        assert!(serde_yaml_ng::from_str::<Scope>(
            "name: t\nincludes: [10.0.0.0/8]\nscan:\n  profiles:\n    - range: 10.0.0.0/16\n      ports: top10\n"
        )
        .is_err());
    }

    #[test]
    fn scan_profiles_bad_values_refused() {
        let bad_range =
            yaml("name: t\nincludes: [10.0.0.0/8]\nscan:\n  profiles:\n    - range: nope\n");
        let err = format!("{:#}", bad_range.validate().unwrap_err());
        assert!(err.contains("scan.profiles[0].range"), "{err}");
        let bad_args = yaml(
            "name: t\nincludes: [10.0.0.0/8]\nscan:\n  profiles:\n    - range: 10.0.0.0/16\n      nmap_args: \"-sV -iR 100\"\n",
        );
        let err = format!("{:#}", bad_args.validate().unwrap_err());
        assert!(
            err.contains("scan.profiles[0].nmap_args") && err.contains("-iR"),
            "{err}"
        );
    }

    #[test]
    fn scan_profiles_cli_form() {
        let p = ScanProfile::parse_cli("10.30.0.0/24=-p 22,80,9100 -sV").unwrap();
        assert_eq!(p.range, "10.30.0.0/24");
        assert_eq!(
            p.nmap_args.as_deref(),
            Some("-p 22,80,9100 -sV"),
            "everything after = is the args line"
        );
        // a /32 targeting one server, every port
        let p = ScanProfile::parse_cli("10.10.4.17/32=-p- -sC").unwrap();
        assert_eq!(p.nmap_args.as_deref(), Some("-p- -sC"));
        // a bare ip is a legal range form
        let p = ScanProfile::parse_cli("10.10.4.17=-p 445").unwrap();
        assert_eq!(p.nmap_args.as_deref(), Some("-p 445"));
        // malformed forms refused, naming the flag
        for bad in [
            "10.0.0.0/24",
            "=-p 80",
            "nope=-p 80",
            "10.0.0.0/24=",
            "10.0.0.0/24=   ",
        ] {
            let err = format!("{:#}", ScanProfile::parse_cli(bad).unwrap_err());
            assert!(err.contains("--profile"), "{bad}: {err}");
        }
    }

    #[test]
    fn old_section_names_point_at_the_new_ones() {
        let err = crate::config::load(std::path::Path::new("/nonexistent")).unwrap_err();
        assert!(err.to_string().contains("reading"), "{err}");
        // the rename hint fires on the refused legacy section names (quoted
        // verbatim in the hint — the one place the old words may appear)
        let dir = std::env::temp_dir().join(format!("rustrawl-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("old.yaml");
        std::fs::write(
            &p,
            "name: t\nincludes: [10.0.0.0/24]\nphase_a:\n  rate_pps: 100\n",
        )
        .unwrap();
        let err = format!("{}", load(&p).unwrap_err());
        assert!(err.contains("discovery:"), "rename hint missing: {err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rescan_windows() {
        // empty string is not None: a knob set to "" is a config error
        let s = yaml(
            "name: t\nincludes: [10.0.0.0/24]\nrescan:\n  recheck_up_after: null\n  retry_no_response_after: 45m\n",
        );
        assert_eq!(
            s.rescan.recheck_up_delay().unwrap(),
            None,
            "null disables recheck"
        );
        assert_eq!(
            s.rescan.no_response_delay().unwrap(),
            Some(Duration::from_secs(2700))
        );
        let bad = yaml("name: t\nincludes: [10.0.0.0/24]\nrescan:\n  recheck_up_after: 0d\n");
        assert!(bad.validate().is_err(), "zero recheck window rejected");
    }

    #[test]
    fn port_spec_validation() {
        assert!(PortSpec::List(vec![80, 443, 80]).resolve().is_err()); // duplicate
        assert!(PortSpec::List(vec![0]).resolve().is_err()); // port 0
        assert!(PortSpec::List(vec![]).resolve().is_err()); // empty
        assert!(PortSpec::Profile("top70000".into()).resolve().is_err());
        assert!(PortSpec::Profile("top-500".into()).resolve().is_err());
        assert!(PortSpec::Profile("top".into()).resolve().is_err());
        assert!(PortSpec::Profile("top1OO0".into()).resolve().is_err()); // letters
        assert!(PortSpec::Profile("whatever".into()).resolve().is_err());
        let (l, n) = PortSpec::List(vec![443, 80]).resolve().unwrap();
        assert_eq!(n, 2);
        assert_eq!(l, Some(vec![80, 443]));
    }

    #[test]
    fn top_profiles_resolve_against_the_ranking() {
        let (l, n) = PortSpec::Profile("top25".into()).resolve().unwrap();
        assert_eq!(n, 25);
        let l = l.unwrap();
        assert_eq!(l.len(), 25);
        assert_eq!(
            l[0], 80,
            "nmap-services frequency order, not ascending ports"
        );
        assert_eq!(l, ports::top_n(25));

        let (l, n) = PortSpec::Profile("top1000".into()).resolve().unwrap();
        assert_eq!(n, 1000);
        assert_eq!(l.unwrap().len(), 1000);

        // beyond the embedded ranking: refused with a pointer to "full"
        let err = PortSpec::Profile("top9000".into()).resolve().unwrap_err();
        assert!(err.to_string().contains("full"), "got: {err}");

        let (l, n) = PortSpec::Profile("full".into()).resolve().unwrap();
        assert_eq!(n, 65_535);
        assert_eq!(l, None, "full stays count-only (never materialized)");
    }

    #[test]
    fn validation_rejects() {
        let s = yaml("name: t\nincludes: [10.0.0.0/24]\ndiscovery:\n  rate_pps: 0\n");
        assert!(s.validate().is_err());
        let s = yaml("name: t\nincludes: [10.0.0.0/24]\ndiscovery:\n  jitter_pct: 90\n");
        assert!(s.validate().is_err());
        let s = yaml(
            "name: t\nincludes: [10.0.0.0/24]\nsensitive_zones:\n  - range: notanip\n    policy: passive\n",
        );
        assert!(s.validate().is_err());
    }
}
