use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

/// Probing backend for the discovery sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// Raw-socket SYN if root/CAP_NET_RAW, otherwise TCP connect fallback
    Auto,
    /// Raw-socket SYN only (fails without root)
    Syn,
    /// TCP connect fallback (no root needed, slower and noisier)
    Connect,
}

#[derive(Parser)]
#[command(
    name = "rustrawl",
    version,
    about = "Internal network discovery: wide SYN sweep, /24 expansion of live hosts, operator-driven nmap scanning"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Discovery: wide sweep, then /24 expansion of live hosts
    Run(RunArgs),
    /// nmap scan over the discovered up list (alias: fp)
    #[command(alias = "fp")]
    Scan(ScanArgs),
    /// Collect hostnames for the known assets without probing anything new:
    /// DNS PTR through the resolvers already in the registry (verified by a
    /// forward A), AXFR attempts on the zones the names imply, TLS
    /// certificate CN/SAN on the HTTPS services, LDAP machine accounts
    /// (RUSTRAWL_LDAP_BIND env for credentials, never a flag)
    Names(NamesArgs),
    /// EyeWitness-style capture pass over the registry's web services
    /// (any port the registry classifies http/https): one headless-chromium
    /// screenshot, HTTP headers, page title and a default-credential
    /// fingerprint per target, into runs/web_<ts>/. Serves NO dashboard —
    /// `db --web` is the browser dashboard
    Web(WebArgs),
    /// Registry, interactive console and web dashboard: without a
    /// subcommand, the level-based console (ranges, hosts, services, db -
    /// switch levels by name, `h` for the level's help); `--web` serves
    /// the browser dashboard instead; `db stats` and `db export` are the
    /// one-shot views
    Db {
        /// Perimeter root (contains scandb.sqlite)
        #[arg(short, long)]
        out: PathBuf,
        /// Serve the browser dashboard instead of the console (sortable
        /// tables, per-host nmap evidence, triage marks, one-host rescans;
        /// binds 127.0.0.1)
        #[arg(long)]
        web: bool,
        /// Dashboard port (--web)
        #[arg(long, default_value_t = 8391)]
        port: u16,
        /// Dashboard bind address (--web); 127.0.0.1 keeps it local
        #[arg(long, default_value = "127.0.0.1")]
        bind: IpAddr,
        #[command(subcommand)]
        command: Option<DbCommand>,
    },
}

#[derive(clap::Args)]
pub struct RunArgs {
    /// Scope YAML file (ranges, discovery/scan sections)
    pub scope: PathBuf,
    /// Perimeter output root: scandb.sqlite, runs/, run.lock
    #[arg(short, long)]
    pub out: PathBuf,
    /// Resume the last interrupted run of this perimeter
    #[arg(long)]
    pub resume: bool,
    /// Rescan everything, ignoring the database memory
    #[arg(long)]
    pub force: bool,
    /// Simulate: target/probe/duration counts, zero packets
    #[arg(long)]
    pub dry_run: bool,
    /// Probing backend: auto | syn | connect
    #[arg(long, value_enum, default_value_t = Mode::Auto)]
    pub mode: Mode,
}

#[derive(clap::Args)]
pub struct ScanArgs {
    /// Scope YAML file
    pub scope: PathBuf,
    /// Perimeter output root
    #[arg(short, long)]
    pub out: PathBuf,
    /// Resume the interrupted nmap queue
    #[arg(long)]
    pub resume: bool,
    /// Free-form nmap arguments appended to the fixed frame — the port
    /// list rides in them (`-p-`, `-p 21,22`, `--exclude-ports`; no `-p`
    /// means nmap's own default, the top 1000 TCP ports). Default:
    /// scan.nmap_args from the scope, else "-sC -sV"
    #[arg(long)]
    pub nmap_args: Option<String>,
    /// Per-range nmap args, repeatable: <range>=<nmap args>, e.g.
    /// --profile "10.30.0.0/24=-p- -sC" --profile "10.10.4.17/32=-p 445 -sV".
    /// CLI entries match before the scope's scan.profiles (first match
    /// wins); nmap args stay per-range YAML too (scan.profiles[i].nmap_args)
    #[arg(long)]
    pub profile: Vec<String>,
    /// Queue only the hosts whose first-match profile is one of these (a
    /// profile's range as written, or `default` for the rest); repeatable /
    /// comma-separated. Fresh queues only: --resume refuses it (the
    /// interrupted queue re-applies its own recorded selection)
    #[arg(long, value_delimiter = ',')]
    pub only_profile: Vec<String>,
    /// nmap chunks in parallel
    #[arg(long)]
    pub threads: Option<u32>,
    /// Incremental scan: queue only hosts never scanned, or last scanned
    /// longer ago than this window (e.g. 30d, 12h). Default: every up host
    #[arg(long)]
    pub refresh_after: Option<String>,
    /// Simulate the queue without launching nmap
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(clap::Args)]
pub struct NamesArgs {
    /// Perimeter output root: reads scandb.sqlite, writes runs/names_<ts>/
    #[arg(short, long)]
    pub out: PathBuf,
    /// Resolver to query first, repeatable: ip or ip:port (port default 53).
    /// Registry resolvers (the port 53 services) are appended, then - only if
    /// neither listed any - the system's /etc/resolv.conf
    #[arg(long)]
    pub dns: Vec<String>,
    /// Zone to attempt a transfer for, repeatable (default: the last two
    /// labels of every verified PTR name)
    #[arg(long)]
    pub zone: Vec<String>,
    /// Which collectors to run, comma-separated: dns (PTR + AXFR), tls
    /// (certificate names on 443/8443/https), ldap (machine accounts on 389).
    /// Default: all of them
    #[arg(long, value_delimiter = ',')]
    pub sources: Vec<String>,
    /// Per-socket timeout in seconds (connect, read, write)
    #[arg(long, default_value_t = 2)]
    pub timeout: u64,
}

#[derive(clap::Args)]
pub struct WebArgs {
    /// Perimeter output root: reads scandb.sqlite, writes runs/web_<ts>/
    #[arg(short, long)]
    pub out: PathBuf,
    /// Per-target timeout in seconds (connect + answer + screenshot get
    /// this budget each, plus a short kill slack)
    #[arg(long, default_value_t = crate::capture::DEFAULT_TIMEOUT_SECS)]
    pub timeout: u64,
    /// Parallel captures
    #[arg(long)]
    pub threads: Option<usize>,
}

#[derive(Subcommand)]
pub enum DbCommand {
    /// Registry counts and the outcome of every run on this perimeter
    /// (discovery passes and nmap queues, done or interrupted)
    Stats,
    /// The complete registry as ONE nmap-format XML document on stdout
    /// (every up host, its names, its open ports) - feed it to
    /// `msfconsole` db_import or any nmap XML parser
    Export,
}
