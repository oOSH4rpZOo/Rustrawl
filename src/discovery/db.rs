//! scandb.sqlite — the inter-run registry, at the perimeter root. "The DB is
//! the memory of what has already been scanned": it is consulted before every
//! scan decision (skip_done / retry_no_response_after / --force) and written
//! as verdicts settle, so evidence survives crashes and later runs never
//! repeat a fresh answer.
//!
//! Tables:
//! - `results`: one row per ANSWERED probe `(ip, port, stage)` — open/closed.
//!   Per-port misses are deliberately not stored: at /8 scale they are the
//!   default outcome, not the exception, and `host_state` carries the retry
//!   semantics for them.
//! - `host_state`: one row per `(ip, stage)` — `up` or `no_response`, written
//!   when the host settles. This is what skip_done and the no-response retry
//!   delay read.
//! - `services`: one row per `(ip, port)` seen open by the nmap scan —
//!   service name and banner version. Pure inventory, written additively by
//!   scan ingestion; absent from registries last touched by an older build
//!   (the read queries treat a missing table as empty, no migration needed).
//! - `hostnames`: one row per `(ip, name)` collected by the `names` command
//!   (dns-ptr / dns-axfr / tls / ldap sources) — same absence rule as
//!   `services`: created lazily on the next write-mode open, read queries
//!   treat a missing table as empty.
//! - `meta`: schema version.
//!
//! Writes are batched (one transaction per flush) with WAL + synchronous
//! NORMAL: a crash can lose at most the last unflushed batch, never
//! consistency.

use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use roaring::RoaringBitmap;
use rusqlite::Connection;

/// Scan stage a DB row belongs to. Ordered sweep < expand < scan (earlier
/// evidence first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    /// The wide sweep (the run's first pass).
    Sweep,
    /// The /24 expansion (liveness-only neighborhood sweep).
    Expand,
    /// The nmap scan: writes results rows only — it never drives skip sets,
    /// so no host_state rows.
    Scan,
}

impl Stage {
    /// The display name — CLI columns, detail lines, the dashboard JSON.
    /// Never stored: rows keep the short tokens below.
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Sweep => "sweep",
            Stage::Expand => "expand",
            Stage::Scan => "scan",
        }
    }

    /// The storage token — stable single letters so registries written by
    /// any build stay readable without a migration. These never reach a
    /// rendering path.
    pub fn token(self) -> &'static str {
        match self {
            Stage::Sweep => "A",
            Stage::Expand => "B",
            Stage::Scan => "C",
        }
    }

    /// The token back to a stage (rows read from the registry).
    pub fn from_token(t: &str) -> Stage {
        match t {
            "B" => Stage::Expand,
            "C" => Stage::Scan,
            _ => Stage::Sweep,
        }
    }
}

/// Verdict of one answered probe.
#[derive(Debug, Clone, Copy)]
pub enum Answer {
    Open,
    Closed,
}

impl Answer {
    fn as_str(self) -> &'static str {
        match self {
            Answer::Open => "open",
            Answer::Closed => "closed",
        }
    }
}

/// Flush a buffered batch once it holds this many rows.
const FLUSH_THRESHOLD: usize = 2000;

/// Schema this build reads and writes; an older or newer file bails out.
pub(crate) const SCHEMA_VERSION: &str = "1";

pub struct Db {
    conn: Connection,
    run_id: Option<String>,
    hosts: Vec<HostRow>,
    results: Vec<ResultRow>,
    services: Vec<ServiceRow>,
    hostnames: Vec<HostnameRow>,
    triage: Vec<TriageRow>,
    types: Vec<AssetTypeRow>,
    bookmark: Vec<FlagRow>,
    pwned: Vec<FlagRow>,
    tags: Vec<TagRow>,
}

struct HostRow {
    ip: u32,
    stage: Stage,
    up: bool,
    ports_tried: u32,
    seen: i64,
}

struct ResultRow {
    ip: u32,
    port: u16,
    stage: Stage,
    answer: Answer,
    seen: i64,
}

struct ServiceRow {
    ip: u32,
    port: u16,
    name: String,
    version: String,
    seen: i64,
}

struct HostnameRow {
    ip: u32,
    name: String,
    source: String,
    seen: i64,
}

/// One operator triage mark: a status and/or a note on a whole host
/// (the row is stored with `port == 0`; older port-level rows are
/// migrated away on open). `delete` rows remove the key at flush time
/// (clearing a row is a write too).
struct TriageRow {
    ip: u32,
    port: u16,
    status: Option<String>,
    note: String,
    updated: i64,
    delete: bool,
}

/// One asset-type guess or override per host. `delete` rows remove the key
/// at flush time — the classifier's retraction when the evidence no longer
/// points anywhere (never applied to a manual row, see the flush guard).
struct AssetTypeRow {
    ip: u32,
    kind: String,
    basis: String,
    source: String,
    updated: i64,
    delete: bool,
}

/// One binary host flag — the bookmark or the PW3ND mark. `delete: true`
/// removes the key at flush time (unmarking is a write too).
struct FlagRow {
    ip: u32,
    updated: i64,
    delete: bool,
}

/// One custom tag on one host (`#dc`, `#adcs`...). `delete: true` removes
/// the (ip, tag) key at flush time.
struct TagRow {
    ip: u32,
    tag: String,
    updated: i64,
    delete: bool,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Everything the registry holds about one host — the `hosts -i` identity
/// card and the dashboard's host sheet.
pub struct HostDetail {
    /// (stage, status, last_seen, run) per host_state row — display names.
    pub stages: Vec<(String, String, i64, String)>,
    /// (port, stage, status, last_seen, run) per results row.
    pub ports: Vec<(u16, Stage, String, i64, String)>,
    /// (port, name, version, last_seen, run) per services row.
    pub services: Vec<(u16, String, String, i64, String)>,
    /// (name, source, last_seen, run) per hostnames row.
    pub names: Vec<(String, String, i64, String)>,
    /// The host's asset type: (kind, basis, source) — absent when untyped.
    pub asset_type: Option<(String, String, String)>,
    /// The bookmark's stamp — present when the host is bookmarked.
    pub bookmark: Option<i64>,
    /// The PW3ND mark's stamp — present when the host is marked compromised.
    pub pwned: Option<i64>,
    /// (tag, updated) per custom tag on the host, tag ASC.
    pub tags: Vec<(String, i64)>,
    /// (port, status, note, updated) per triage row, port ASC
    /// (port 0 = the host-level mark).
    pub triage: Vec<(u16, Option<String>, String, i64)>,
}

impl Db {
    /// Opens (creating if needed) `<root>/scandb.sqlite` with the schema.
    pub fn open(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
        let path = root.join("scandb.sqlite");
        let conn =
            Connection::open(&path).with_context(|| format!("opening {}", path.display()))?;
        // Another process (a parallel run, an sqlite3 CLI session) may hold
        // the write lock during a flush — wait rather than error out.
        conn.busy_timeout(Duration::from_millis(5000))
            .context("db: busy_timeout")?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS results (
                 ip INTEGER NOT NULL,
                 port INTEGER NOT NULL,
                 phase TEXT NOT NULL,
                 status TEXT NOT NULL,
                 last_seen INTEGER NOT NULL,
                 run_id TEXT NOT NULL,
                 PRIMARY KEY (ip, port, phase)
             ) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS host_state (
                 ip INTEGER NOT NULL,
                 phase TEXT NOT NULL,
                 status TEXT NOT NULL,
                 last_seen INTEGER NOT NULL,
                 run_id TEXT NOT NULL,
                 ports_tried INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (ip, phase)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS idx_host_state_lookup ON host_state (phase, status);
             CREATE TABLE IF NOT EXISTS services (
                 ip INTEGER NOT NULL,
                 port INTEGER NOT NULL,
                 name TEXT NOT NULL,
                 version TEXT NOT NULL,
                 last_seen INTEGER NOT NULL,
                 run_id TEXT NOT NULL,
                 PRIMARY KEY (ip, port)
             ) WITHOUT ROWID;
             -- The PK answers per-host lookups (ip-first); this one answers
             -- the port-filtered service views with a seek.
             -- Name-only and unfiltered passes deliberately ignore it (the
             -- seek shape cannot express them; a whole-index scan plus one
             -- table seek per row measured several times slower than an
             -- inline table scan) - Db::services pins that with +port/+ip.
             CREATE INDEX IF NOT EXISTS idx_services_port ON services (port);
             CREATE TABLE IF NOT EXISTS hostnames (
                 ip INTEGER NOT NULL,
                 name TEXT NOT NULL,
                 source TEXT NOT NULL,
                 last_seen INTEGER NOT NULL,
                 run_id TEXT NOT NULL,
                 PRIMARY KEY (ip, name)
             ) WITHOUT ROWID;
             -- No extra index: the PK answers the ip-first lookups, and
             -- source/name filtering scans a table that stays tiny (a few
             -- thousand rows against millions of results rows).
             CREATE TABLE IF NOT EXISTS triage (
                 ip INTEGER NOT NULL,
                 port INTEGER NOT NULL,
                 status TEXT,
                 note TEXT NOT NULL DEFAULT '',
                 updated INTEGER NOT NULL,
                 PRIMARY KEY (ip, port)
             ) WITHOUT ROWID;
             -- Operator annotations only (the dashboard's triage writes) -
             -- never engine verdicts. A handful of rows; no index beyond
             -- the PK.
             -- One mark vocabulary on the host row: todo, clean, vuln.
             -- Older rows used the retired words (wip, flagged); the move
             -- runs on every write-mode open and is a no-op once done.
             -- Marks live on the host only: port-level rows leave with it.
             UPDATE triage SET status = 'vuln' WHERE status = 'flagged';
             UPDATE triage SET status = 'todo' WHERE status = 'wip';
             DELETE FROM triage WHERE port > 0;
             CREATE TABLE IF NOT EXISTS asset_types (
                 ip INTEGER PRIMARY KEY,
                 kind TEXT NOT NULL,
                 basis TEXT NOT NULL,
                 source TEXT NOT NULL,
                 updated INTEGER NOT NULL
             ) WITHOUT ROWID;
             -- The classifier's guesses (source 'heuristic') never overwrite
             -- an operator override (source 'manual') - the flush upsert
             -- carries the WHERE guard.
             CREATE TABLE IF NOT EXISTS bookmark (
                 ip INTEGER PRIMARY KEY,
                 updated INTEGER NOT NULL
             ) WITHOUT ROWID;
             -- The operator's read-later flag (the dashboard's 🔖 writes
             -- here). A handful of rows; the PK is the whole story.
             CREATE TABLE IF NOT EXISTS pwned (
                 ip INTEGER PRIMARY KEY,
                 updated INTEGER NOT NULL
             ) WITHOUT ROWID;
             -- The compromised flag (the dashboard's pwned dot and the
             -- console's `hosts -c` write here). Separate from the triage
             -- state on purpose: a host can be both todo and owned.
             CREATE TABLE IF NOT EXISTS tags (
                 ip INTEGER NOT NULL,
                 tag TEXT NOT NULL,
                 updated INTEGER NOT NULL,
                 PRIMARY KEY (ip, tag)
             ) WITHOUT ROWID;
             -- The operator's custom tags (#dc, #adcs... - the dashboard's
             -- chip editor and the console's `hosts -ta` / `-td` write
             -- here). The PK
             -- answers per-host lookups; the count-by-tag view scans a
             -- table that stays tiny.
             CREATE TABLE IF NOT EXISTS meta (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );
             INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', '1');",
        )
        .with_context(|| format!("schema of {}", path.display()))?;
        let stored: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .context("db: schema_version read")?;
        if stored != SCHEMA_VERSION {
            bail!(
                "{}: schema version {stored} but this build expects {SCHEMA_VERSION} - \
                 the file format changed; move it aside and rerun with --force",
                path.display()
            );
        }
        // The crown/star ranking became a plain bookmark: a file an older
        // build wrote still carries the `value` table — copy its rows across
        // and drop it. The move cannot live in the batch above: the source
        // table only exists in those files.
        let had_value: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'value'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .context("db: value table probe")?;
        if had_value {
            conn.execute_batch(
                "INSERT OR REPLACE INTO bookmark (ip, updated) SELECT ip, updated FROM value;
                 DROP TABLE value;",
            )
            .context("db: value to bookmark move")?;
        }
        Ok(Self {
            conn,
            run_id: None,
            hosts: Vec::new(),
            results: Vec::new(),
            services: Vec::new(),
            hostnames: Vec::new(),
            triage: Vec::new(),
            types: Vec::new(),
            bookmark: Vec::new(),
            pwned: Vec::new(),
            tags: Vec::new(),
        })
    }

    /// Opens an existing registry read-write (the engines' entry point).
    /// Unlike [`Db::open`] it never creates anything: a typo'd
    /// `--out` must error, not materialize an empty `scandb.sqlite`.
    pub fn open_existing(root: &Path) -> Result<Self> {
        Self::ensure_registry(root)?;
        Self::open(root)
    }

    /// Opens an existing registry read-only: the `db` read commands take no
    /// write lock that way, so a concurrent scan's WAL commits never block
    /// them — and a read command can never create, migrate or journal the
    /// file it only meant to look at.
    pub fn open_read_only(root: &Path) -> Result<Self> {
        Self::ensure_registry(root)?;
        let conn = Connection::open_with_flags(
            root.join("scandb.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .with_context(|| format!("opening {}", root.join("scandb.sqlite").display()))?;
        conn.busy_timeout(Duration::from_millis(5000))
            .context("db: busy_timeout")?;
        Ok(Self {
            conn,
            run_id: None,
            hosts: Vec::new(),
            results: Vec::new(),
            services: Vec::new(),
            hostnames: Vec::new(),
            triage: Vec::new(),
            types: Vec::new(),
            bookmark: Vec::new(),
            pwned: Vec::new(),
            tags: Vec::new(),
        })
    }

    fn ensure_registry(root: &Path) -> Result<()> {
        if !root.join("scandb.sqlite").is_file() {
            bail!(
                "{}: no scandb.sqlite - nothing to read (wrong perimeter root?)",
                root.display()
            );
        }
        Ok(())
    }

    /// Rows recorded by this scan are stamped with the run id.
    pub fn set_run_id(&mut self, run_id: &str) {
        self.run_id = Some(run_id.to_string());
    }

    /// Buffers one answered probe (written at the next flush).
    pub fn record_result(&mut self, ip: Ipv4Addr, port: u16, stage: Stage, answer: Answer) {
        self.results.push(ResultRow {
            ip: u32::from(ip),
            port,
            stage,
            answer,
            seen: now(),
        });
    }

    /// Buffers the final verdict of one host (written at the next flush).
    pub fn record_host(&mut self, ip: Ipv4Addr, stage: Stage, up: bool, ports_tried: u32) {
        self.hosts.push(HostRow {
            ip: u32::from(ip),
            stage,
            up,
            ports_tried,
            seen: now(),
        });
    }

    /// Buffers one service banner from the nmap scan (written at the next
    /// flush). Upsert on (ip, port): the latest observation wins.
    pub fn record_service(&mut self, ip: Ipv4Addr, port: u16, name: &str, version: &str) {
        self.services.push(ServiceRow {
            ip: u32::from(ip),
            port,
            name: name.to_string(),
            version: version.to_string(),
            seen: now(),
        });
    }

    /// Buffers one hostname observed for an already-known asset (written at
    /// the next flush). Upsert on (ip, name): the latest source observation
    /// wins.
    #[allow(dead_code)] // consumed by the names collector (src/names)
    pub fn record_name(&mut self, ip: Ipv4Addr, name: &str, source: &str) {
        self.hostnames.push(HostnameRow {
            ip: u32::from(ip),
            name: name.to_string(),
            source: source.to_string(),
            seen: now(),
        });
    }

    /// Buffers one triage mark (written at the next flush). Upsert on ip:
    /// marks live on the whole host (stored as port 0). `status` `None`
    /// with an empty `note` deletes the row; `None` with a note keeps a
    /// note-only row.
    pub fn record_triage(&mut self, ip: Ipv4Addr, status: Option<&str>, note: &str) {
        self.triage.push(TriageRow {
            ip: u32::from(ip),
            port: 0,
            status: status.map(|s| s.to_string()),
            note: note.to_string(),
            updated: now(),
            delete: status.is_none() && note.is_empty(),
        });
    }

    /// Buffers one asset-type row (written at the next flush). Upsert on ip;
    /// the flush's `WHERE source != 'manual'` guard means heuristic rows
    /// never overwrite an operator override.
    pub fn record_asset_type(&mut self, ip: Ipv4Addr, kind: &str, basis: &str, source: &str) {
        self.types.push(AssetTypeRow {
            ip: u32::from(ip),
            kind: kind.to_string(),
            basis: basis.to_string(),
            source: source.to_string(),
            updated: now(),
            delete: false,
        });
    }

    /// Buffers the retraction of a host's asset-type row — the classifier
    /// learned new evidence that no longer points anywhere. A no-op at
    /// flush time for a `manual` row (the flush delete carries the same
    /// manual guard as the upsert).
    pub fn clear_asset_type(&mut self, ip: Ipv4Addr) {
        self.types.push(AssetTypeRow {
            ip: u32::from(ip),
            kind: String::new(),
            basis: String::new(),
            source: String::new(),
            updated: now(),
            delete: true,
        });
    }

    /// Buffers the host's bookmark (written at the next flush). Upsert on
    /// ip; `false` deletes the row — unmarking is a write too.
    pub fn record_bookmark(&mut self, ip: Ipv4Addr, on: bool) {
        self.bookmark.push(FlagRow {
            ip: u32::from(ip),
            updated: now(),
            delete: !on,
        });
    }

    /// Buffers the host's PW3ND mark (written at the next flush). Upsert on
    /// ip; `false` deletes the row.
    pub fn record_pwned(&mut self, ip: Ipv4Addr, on: bool) {
        self.pwned.push(FlagRow {
            ip: u32::from(ip),
            updated: now(),
            delete: !on,
        });
    }

    /// The pwned mark's atomic flip: the read and the write happen in one
    /// immediate transaction on this write connection, so a concurrent
    /// writer (the dashboard) landing between the two cannot be silently
    /// overwritten. Returns the mark's new state. Buffered rows flush
    /// first — the flip must join the committed state, not the buffer's.
    pub fn toggle_pwned(&mut self, ip: Ipv4Addr) -> Result<bool> {
        self.flush()?;
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .context("db: transaction")?;
        let had: Option<i64> = tx
            .query_row(
                "SELECT updated FROM pwned WHERE ip = ?1",
                [u32::from(ip)],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })
            .context("db: read pwned")?;
        if had.is_some() {
            tx.execute("DELETE FROM pwned WHERE ip = ?1", [u32::from(ip)])
                .context("db: unmark pwned")?;
        } else {
            tx.execute(
                "INSERT INTO pwned (ip, updated) VALUES (?1, ?2)",
                rusqlite::params![u32::from(ip), now()],
            )
            .context("db: mark pwned")?;
        }
        tx.commit().context("db: commit the pwned flip")?;
        Ok(had.is_none())
    }

    /// Buffers one tag add or remove for the host (written at the next
    /// flush). The caller normalizes the token; the store takes it as-is.
    pub fn record_tag(&mut self, ip: Ipv4Addr, tag: &str, add: bool) {
        self.tags.push(TagRow {
            ip: u32::from(ip),
            tag: tag.to_string(),
            updated: now(),
            delete: !add,
        });
    }

    /// Writes an operator's asset type straight through — the
    /// dashboard's class editor POST is the only writer. An explicit
    /// override may replace ANY row,
    /// including another manual one: the flush's `WHERE source != 'manual'`
    /// guards protect heuristic writes, not the operator's own command.
    pub fn set_manual_type(&mut self, ip: Ipv4Addr, kind: &str, basis: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO asset_types (ip, kind, basis, source, updated)
                 VALUES (?1, ?2, ?3, 'manual', ?4)
                 ON CONFLICT(ip) DO UPDATE SET
                     kind = excluded.kind,
                     basis = excluded.basis,
                     source = 'manual',
                     updated = excluded.updated",
                rusqlite::params![u32::from(ip), kind, basis, now()],
            )
            .context("db: write the manual asset type")?;
        Ok(())
    }

    /// Removes ANY asset-type row for the host — the operator withdraws the
    /// override, and the next reclassify (or scan/names evidence) may guess
    /// again. True when a row was removed.
    pub fn clear_manual_type(&mut self, ip: Ipv4Addr) -> Result<bool> {
        let n = self
            .conn
            .execute(
                "DELETE FROM asset_types WHERE ip = ?1",
                rusqlite::params![u32::from(ip)],
            )
            .context("db: clear the asset type")?;
        Ok(n > 0)
    }

    /// Flushes only when the batch reached the threshold — cheap to call on
    /// every housekeeping tick.
    pub fn flush_if_needed(&mut self) -> Result<()> {
        if self.hosts.len()
            + self.results.len()
            + self.services.len()
            + self.hostnames.len()
            + self.triage.len()
            + self.types.len()
            + self.bookmark.len()
            + self.pwned.len()
            + self.tags.len()
            >= FLUSH_THRESHOLD
        {
            self.flush()
        } else {
            Ok(())
        }
    }

    /// Forces the WAL into the main database file (fsync included). The scan
    /// queue leans on this for its "done ⇒ durable" invariant: a chunk is
    /// only marked done in scan_state.json after its rows survive a power cut.
    pub fn checkpoint(&self) -> Result<()> {
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .context("db: wal checkpoint")
    }

    /// Writes every buffered row in one transaction.
    pub fn flush(&mut self) -> Result<()> {
        if self.hosts.is_empty()
            && self.results.is_empty()
            && self.services.is_empty()
            && self.hostnames.is_empty()
            && self.triage.is_empty()
            && self.types.is_empty()
            && self.bookmark.is_empty()
            && self.pwned.is_empty()
            && self.tags.is_empty()
        {
            return Ok(());
        }
        let run_id = self
            .run_id
            .clone()
            .context("db: flush without a run id - scanning runs must set one")?;
        let tx = self.conn.transaction().context("db: transaction")?;
        {
            let mut ins = tx
                .prepare(
                    "INSERT INTO results (ip, port, phase, status, last_seen, run_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(ip, port, phase) DO UPDATE SET
                         status = excluded.status,
                         last_seen = excluded.last_seen,
                         run_id = excluded.run_id",
                )
                .context("db: prepare results")?;
            for r in &self.results {
                ins.execute(rusqlite::params![
                    r.ip,
                    i64::from(r.port),
                    r.stage.token(),
                    r.answer.as_str(),
                    r.seen,
                    run_id
                ])?;
            }
            let mut ups = tx
                .prepare(
                    // Sticky-up: an `up` verdict stays up, and its last_seen
                    // stays pinned to when up was last confirmed — a later
                    // mute run must not make an up host look freshly seen
                    // (that would age out recheck_up_after wrongly).
                    "INSERT INTO host_state (ip, phase, status, last_seen, run_id, ports_tried)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(ip, phase) DO UPDATE SET
                         status = CASE WHEN host_state.status = 'up' OR excluded.status = 'up'
                                       THEN 'up' ELSE 'no_response' END,
                         last_seen = CASE WHEN excluded.status = 'up' OR host_state.status != 'up'
                                          THEN excluded.last_seen ELSE host_state.last_seen END,
                         run_id = excluded.run_id,
                         ports_tried = MAX(host_state.ports_tried, excluded.ports_tried)",
                )
                .context("db: prepare host_state")?;
            for h in &self.hosts {
                ups.execute(rusqlite::params![
                    h.ip,
                    h.stage.token(),
                    if h.up { "up" } else { "no_response" },
                    h.seen,
                    run_id,
                    i64::from(h.ports_tried)
                ])?;
            }
            let mut svc = tx
                .prepare(
                    "INSERT INTO services (ip, port, name, version, last_seen, run_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(ip, port) DO UPDATE SET
                         name = excluded.name,
                         version = excluded.version,
                         last_seen = excluded.last_seen,
                         run_id = excluded.run_id",
                )
                .context("db: prepare services")?;
            for s in &self.services {
                svc.execute(rusqlite::params![
                    s.ip,
                    i64::from(s.port),
                    s.name,
                    s.version,
                    s.seen,
                    run_id
                ])?;
            }
            let mut hn = tx
                .prepare(
                    "INSERT INTO hostnames (ip, name, source, last_seen, run_id)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(ip, name) DO UPDATE SET
                         source = excluded.source,
                         last_seen = excluded.last_seen,
                         run_id = excluded.run_id",
                )
                .context("db: prepare hostnames")?;
            for h in &self.hostnames {
                hn.execute(rusqlite::params![h.ip, h.name, h.source, h.seen, run_id])?;
            }
            // Deletes first, then upserts: a batch that clears a key and
            // re-sets it must not lose the re-set (and one that sets then
            // clears nets to the clear).
            let mut del = tx
                .prepare("DELETE FROM triage WHERE ip = ?1 AND port = ?2")
                .context("db: prepare triage delete")?;
            for t in &self.triage {
                if t.delete {
                    del.execute(rusqlite::params![t.ip, i64::from(t.port)])?;
                }
            }
            let mut tg = tx
                .prepare(
                    "INSERT INTO triage (ip, port, status, note, updated)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(ip, port) DO UPDATE SET
                         status = excluded.status,
                         note = excluded.note,
                         updated = excluded.updated",
                )
                .context("db: prepare triage")?;
            for t in &self.triage {
                if t.delete {
                    continue;
                }
                tg.execute(rusqlite::params![
                    t.ip,
                    i64::from(t.port),
                    t.status,
                    t.note,
                    t.updated
                ])?;
            }
            // Types: retractions first (a clear + a guess in one batch nets
            // to the guess), and a manual override survives both — the
            // delete carries the same guard as the upsert.
            let mut tyd = tx
                .prepare("DELETE FROM asset_types WHERE ip = ?1 AND source != 'manual'")
                .context("db: prepare asset_types delete")?;
            for t in &self.types {
                if t.delete {
                    tyd.execute(rusqlite::params![t.ip])?;
                }
            }
            let mut ty = tx
                .prepare(
                    "INSERT INTO asset_types (ip, kind, basis, source, updated)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(ip) DO UPDATE SET
                         kind = excluded.kind,
                         basis = excluded.basis,
                         source = excluded.source,
                         updated = excluded.updated
                     WHERE asset_types.source != 'manual'",
                )
                .context("db: prepare asset_types")?;
            for t in &self.types {
                if t.delete {
                    continue;
                }
                ty.execute(rusqlite::params![
                    t.ip, t.kind, t.basis, t.source, t.updated
                ])?;
            }
            // Bookmark and PW3ND rows: deletes first, then upserts — same
            // rule as the triage rows (unmark + re-mark in one batch nets
            // to the mark).
            for (rows, table) in [(&self.bookmark, "bookmark"), (&self.pwned, "pwned")] {
                // Last op per ip wins: the batch replays in order and keeps
                // the final verdict, so unmark + re-mark nets to the mark
                // and mark + unmark nets to the unmark.
                let mut latest: Vec<&FlagRow> = Vec::new();
                for f in rows {
                    match latest.iter_mut().find(|p| p.ip == f.ip) {
                        Some(p) => *p = f,
                        None => latest.push(f),
                    }
                }
                let mut fd = tx
                    .prepare(&format!("DELETE FROM {table} WHERE ip = ?1"))
                    .with_context(|| format!("db: prepare {table} delete"))?;
                for f in latest.iter().filter(|f| f.delete) {
                    fd.execute(rusqlite::params![f.ip])?;
                }
                let mut fl = tx
                    .prepare(&format!(
                        "INSERT INTO {table} (ip, updated) VALUES (?1, ?2)
                         ON CONFLICT(ip) DO UPDATE SET updated = excluded.updated"
                    ))
                    .with_context(|| format!("db: prepare {table}"))?;
                for f in latest.iter().filter(|f| !f.delete) {
                    fl.execute(rusqlite::params![f.ip, f.updated])?;
                }
            }
            // Tags: last op per (ip, tag) wins, same rule as the flags;
            // deletes land before upserts so the final state is exactly the
            // last op's verdict.
            let mut latest: Vec<&TagRow> = Vec::new();
            for t in &self.tags {
                match latest.iter_mut().find(|p| p.ip == t.ip && p.tag == t.tag) {
                    Some(p) => *p = t,
                    None => latest.push(t),
                }
            }
            let mut tad = tx
                .prepare("DELETE FROM tags WHERE ip = ?1 AND tag = ?2")
                .context("db: prepare tags delete")?;
            for t in latest.iter().filter(|t| t.delete) {
                tad.execute(rusqlite::params![t.ip, t.tag])?;
            }
            let mut ta = tx
                .prepare(
                    "INSERT INTO tags (ip, tag, updated) VALUES (?1, ?2, ?3)
                     ON CONFLICT(ip, tag) DO UPDATE SET updated = excluded.updated",
                )
                .context("db: prepare tags")?;
            for t in latest.iter().filter(|t| !t.delete) {
                ta.execute(rusqlite::params![t.ip, t.tag, t.updated])?;
            }
        }
        tx.commit().context("db: commit")?;
        self.hosts.clear();
        self.results.clear();
        self.services.clear();
        self.hostnames.clear();
        self.triage.clear();
        self.types.clear();
        self.bookmark.clear();
        self.pwned.clear();
        self.tags.clear();
        Ok(())
    }

    /// Hosts of `stage` whose verdict is fresh enough that skip_done skips
    /// them: `no_response` within the retry delay (or all of them when no
    /// retry delay is configured), and `up` within the re-check delay (or all
    /// of them when no re-check delay is configured — up hosts age out after
    /// `recheck_up_after` so a machine up since forever gets probed again).
    pub fn skip_set(
        &self,
        stage: Stage,
        retry_after: Option<Duration>,
        recheck_up_after: Option<Duration>,
    ) -> Result<RoaringBitmap> {
        let mut out = RoaringBitmap::new();
        let mut stmt = self
            .conn
            .prepare("SELECT ip, status, last_seen FROM host_state WHERE phase = ?1")
            .context("db: skip_set prepare")?;
        let n = now();
        let rows = stmt.query_map([stage.token()], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (ip, status, seen) = row?;
            let fresh = |d: Duration| seen > n - d.as_secs() as i64;
            // no retry delay configured: a no_response is never retried, so it
            // keeps covering the host until --force (same for up/None)
            let skip = match (status.as_str(), retry_after, recheck_up_after) {
                ("no_response", None, _) => true,
                ("no_response", Some(d), _) => fresh(d),
                ("up", _, None) => true,
                ("up", _, Some(d)) => fresh(d),
                _ => false,
            };
            if skip {
                out.insert(ip as u32);
            }
        }
        Ok(out)
    }

    /// Every host currently `up` in the given stages.
    pub fn up_hosts(&self, stages: &[Stage]) -> Result<RoaringBitmap> {
        let mut out = RoaringBitmap::new();
        let list = stages
            .iter()
            .map(|p| p.token())
            .collect::<Vec<_>>()
            .join("', '");
        let sql = format!("SELECT ip FROM host_state WHERE status = 'up' AND phase IN ('{list}')");
        // stage tokens are internal constants — no injection surface
        let mut stmt = self.conn.prepare(&sql).context("db: up_hosts prepare")?;
        let rows = stmt.query_map([], |r| r.get::<_, i64>(0))?;
        for r in rows {
            out.insert(r? as u32);
        }
        Ok(out)
    }

    /// Open-port count per host across the given stages — how the scan
    /// orders its queue (hosts already known to talk get fingerprinted first).
    pub fn open_counts(&self, stages: &[Stage]) -> Result<std::collections::HashMap<u32, u32>> {
        let list = stages
            .iter()
            .map(|p| p.token())
            .collect::<Vec<_>>()
            .join("', '");
        let sql = format!(
            "SELECT ip, COUNT(*) FROM results
             WHERE status = 'open' AND phase IN ('{list}') GROUP BY ip"
        );
        let mut stmt = self.conn.prepare(&sql).context("db: open_counts prepare")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, i64>(0)? as u32, r.get::<_, i64>(1)? as u32))
        })?;
        let mut out = std::collections::HashMap::new();
        for r in rows {
            let (ip, n) = r?;
            out.insert(ip, n);
        }
        Ok(out)
    }

    /// Every distinct host currently up, any stage — streamed to `cb`.
    pub fn up_ips(&self, cb: &mut impl FnMut(Ipv4Addr)) -> Result<usize> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT ip FROM host_state WHERE status = 'up' ORDER BY ip ASC")
            .context("db: up_ips prepare")?;
        let rows = stmt.query_map([], |r| Ok(Ipv4Addr::from(r.get::<_, i64>(0)? as u32)))?;
        let mut n = 0usize;
        for ip in rows {
            cb(ip?);
            n += 1;
        }
        Ok(n)
    }

    // ------------------------------------------------------- db views ----
    // The read-side behind the console's levels, the dashboard's JSON and
    // the scan queue. All stream rows through callbacks (a big perimeter's
    // view is never materialized whole), all are read-only.

    /// True when this registry has the `services` table (older builds' files
    /// do not; the read queries then report nothing rather than error).
    fn has_services(&self) -> bool {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'services'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    /// True when this registry has the `hostnames` table (older builds' files
    /// do not; the names views then report nothing rather than error).
    fn has_hostnames(&self) -> bool {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'hostnames'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    /// True when this registry has the `triage` table (older builds' files
    /// do not; the triage views then report nothing rather than error).
    fn has_triage(&self) -> bool {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'triage'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    /// True when this registry has the `asset_types` table (same deal).
    fn has_types(&self) -> bool {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'asset_types'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    /// True when this registry has the `bookmark` table (older builds'
    /// files do not; the bookmark views then report nothing rather than
    /// error). The pwned and tags tables ride the same schema step, so one
    /// probe covers the three.
    fn has_flags(&self) -> bool {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'bookmark'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    /// Every host currently up: (ip, stages up in, last up-seen, open-port
    /// count) — the hosts list, ordered by IP. `stages` is a
    /// "+"-joined list of display names like "sweep+expand" (the stored
    /// tokens never leave this file).
    pub fn hosts_overview(&self, cb: &mut impl FnMut(Ipv4Addr, &str, i64, u64)) -> Result<usize> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT hs.ip, GROUP_CONCAT(hs.phase), MAX(hs.last_seen),
                        (SELECT COUNT(DISTINCT r.port) FROM results r
                         WHERE r.ip = hs.ip AND r.status = 'open')
                 FROM host_state hs
                 WHERE hs.status = 'up'
                 GROUP BY hs.ip
                 ORDER BY hs.ip ASC",
            )
            .context("db: hosts_overview prepare")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                Ipv4Addr::from(r.get::<_, i64>(0)? as u32),
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)? as u64,
            ))
        })?;
        let mut n = 0usize;
        for row in rows {
            let (ip, tokens, seen, open) = row?;
            // raw storage tokens → display names, joined with "+"
            let stages = tokens
                .split(',')
                .map(Stage::from_token)
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("+");
            cb(ip, &stages, seen, open);
            n += 1;
        }
        Ok(n)
    }

    /// Everything the registry knows about one host: its per-stage verdicts,
    /// its answered probes and its service banners. `None` when the host has
    /// no rows at all.
    pub fn host_detail(&self, ip: Ipv4Addr) -> Result<Option<HostDetail>> {
        let ipi = i64::from(u32::from(ip));
        let mut detail = HostDetail {
            stages: Vec::new(),
            ports: Vec::new(),
            services: Vec::new(),
            names: Vec::new(),
            asset_type: None,
            bookmark: None,
            pwned: None,
            tags: Vec::new(),
            triage: Vec::new(),
        };
        {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT phase, status, last_seen, run_id FROM host_state
                     WHERE ip = ?1 ORDER BY phase ASC",
                )
                .context("db: host_detail prepare")?;
            let rows = stmt.query_map([ipi], |r| {
                Ok((
                    Stage::from_token(&r.get::<_, String>(0)?)
                        .as_str()
                        .to_string(),
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?;
            for row in rows {
                let (stage, status, seen, run) = row?;
                detail.stages.push((stage, status, seen, run));
            }
        }
        {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT port, phase, status, last_seen, run_id FROM results
                     WHERE ip = ?1 ORDER BY port ASC, phase ASC",
                )
                .context("db: host_detail ports prepare")?;
            let rows = stmt.query_map([ipi], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u16,
                    Stage::from_token(&r.get::<_, String>(1)?),
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })?;
            for row in rows {
                let (port, stage, status, seen, run) = row?;
                detail.ports.push((port, stage, status, seen, run));
            }
        }
        if self.has_services() {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT port, name, version, last_seen, run_id FROM services
                     WHERE ip = ?1 ORDER BY port ASC",
                )
                .context("db: host_detail services prepare")?;
            let rows = stmt.query_map([ipi], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u16,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })?;
            for row in rows {
                let (port, name, version, seen, run) = row?;
                detail.services.push((port, name, version, seen, run));
            }
        }
        self.names_for_ip(ip, &mut |name, source, seen, run| {
            detail
                .names
                .push((name.to_string(), source.to_string(), seen, run.to_string()));
        })?;
        detail.asset_type = self.type_for_ip(ip)?;
        detail.bookmark = self.bookmark_for_ip(ip)?;
        detail.pwned = self.pwned_for_ip(ip)?;
        detail.tags = self.tags_for_ip(ip)?;
        self.triage_for_ip(ip, &mut |port, status, note, updated| {
            detail.triage.push((
                port,
                status.map(|s| s.to_string()),
                note.to_string(),
                updated,
            ));
        })?;
        // Triage rows and types are operator annotations, not discovery
        // evidence: they never make an unknown host "known" on their own
        // (an orphaned mark stays visible in the dashboard only).
        if detail.stages.is_empty()
            && detail.ports.is_empty()
            && detail.services.is_empty()
            && detail.names.is_empty()
        {
            return Ok(None);
        }
        Ok(Some(detail))
    }

    /// Service banners, ordered by port then IP; `port` and `name` narrow the
    /// view (exact matches — port number or service-name string). On a
    /// registry without the services table this yields nothing.
    pub fn services(
        &self,
        port: Option<u16>,
        name: Option<&str>,
        cb: &mut impl FnMut(Ipv4Addr, u16, &str, &str, i64, &str),
    ) -> Result<usize> {
        if !self.has_services() {
            return Ok(0);
        }
        // Two statement shapes, because SQLite pins the plan at prepare time:
        // the generic "(?1 IS NULL OR port = ?1)" form must stay valid for a
        // NULL port, so it can never seek idx_services_port — it scans the
        // whole index plus a table seek per row, slower than scanning the
        // table. A plain "port = ?1" searches the index; the name-only and
        // unfiltered passes have no equality to seek and keep the flat form.
        let (sql, vals) = match port {
            Some(p) => (
                "SELECT ip, port, name, version, last_seen, run_id FROM services
                 WHERE port = ?1 AND (?2 IS NULL OR name = ?2)
                 ORDER BY port ASC, ip ASC",
                vec![
                    rusqlite::types::Value::Integer(i64::from(p)),
                    name.map(|n| rusqlite::types::Value::Text(n.to_string()))
                        .unwrap_or(rusqlite::types::Value::Null),
                ],
            ),
            None => (
                // The unary plus on the ORDER BY terms makes them plain
                // expressions, so the planner cannot satisfy the ordering
                // from idx_services_port — it would otherwise scan the whole
                // index and seek the table for every row, several times
                // slower than an inline table scan for the --name views.
                "SELECT ip, port, name, version, last_seen, run_id FROM services
                 WHERE (?1 IS NULL OR name = ?1)
                 ORDER BY +port ASC, +ip ASC",
                vec![name
                    .map(|n| rusqlite::types::Value::Text(n.to_string()))
                    .unwrap_or(rusqlite::types::Value::Null)],
            ),
        };
        stream_services(&self.conn, sql, vals, cb)
    }

    pub fn services_count(&self) -> Result<u64> {
        if !self.has_services() {
            return Ok(0);
        }
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM services", [], |r| r.get::<_, i64>(0))?
            as u64)
    }

    /// One host's service banners, port ASC, streamed to `cb` — the PK is
    /// (ip, port), so this is a single B-tree range scan per host and the
    /// MSF export can walk the up list without materializing the table.
    pub fn services_for_ip(
        &self,
        ip: Ipv4Addr,
        cb: &mut impl FnMut(u16, &str, &str),
    ) -> Result<usize> {
        if !self.has_services() {
            return Ok(0);
        }
        let mut stmt = self
            .conn
            .prepare("SELECT port, name, version FROM services WHERE ip = ?1 ORDER BY port ASC")
            .context("db: services_for_ip prepare")?;
        let rows = stmt.query_map([i64::from(u32::from(ip))], |r| {
            Ok((
                r.get::<_, i64>(0)? as u16,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let mut n = 0usize;
        for row in rows {
            let (port, name, version) = row?;
            cb(port, &name, &version);
            n += 1;
        }
        Ok(n)
    }

    /// Every collected hostname — (ip, name, source, last_seen, run) —
    /// streamed to `cb`, ordered by IP then name. On a registry without the
    /// hostnames table this yields nothing.
    pub fn names(&self, cb: &mut impl FnMut(Ipv4Addr, &str, &str, i64, &str)) -> Result<usize> {
        if !self.has_hostnames() {
            return Ok(0);
        }
        let mut stmt = self
            .conn
            .prepare(
                "SELECT ip, name, source, last_seen, run_id FROM hostnames
                 ORDER BY +ip ASC, +name ASC",
            )
            .context("db: names prepare")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                Ipv4Addr::from(r.get::<_, i64>(0)? as u32),
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;
        let mut n = 0usize;
        for row in rows {
            let (ip, name, source, seen, run) = row?;
            cb(ip, &name, &source, seen, &run);
            n += 1;
        }
        Ok(n)
    }

    /// One host's collected hostnames, name ASC, streamed to `cb`.
    pub fn names_for_ip(
        &self,
        ip: Ipv4Addr,
        cb: &mut impl FnMut(&str, &str, i64, &str),
    ) -> Result<usize> {
        if !self.has_hostnames() {
            return Ok(0);
        }
        let mut stmt = self
            .conn
            .prepare(
                "SELECT name, source, last_seen, run_id FROM hostnames
                 WHERE ip = ?1 ORDER BY +name ASC",
            )
            .context("db: names_for_ip prepare")?;
        let rows = stmt.query_map([i64::from(u32::from(ip))], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        let mut n = 0usize;
        for row in rows {
            let (name, source, seen, run) = row?;
            cb(&name, &source, seen, &run);
            n += 1;
        }
        Ok(n)
    }

    /// Every triage mark — (ip, port, status, note, updated), port 0 =
    /// whole host — streamed to `cb`, ordered by IP then port. On a
    /// registry without the triage table this yields nothing.
    pub fn triage(
        &self,
        cb: &mut impl FnMut(Ipv4Addr, u16, Option<&str>, &str, i64),
    ) -> Result<usize> {
        if !self.has_triage() {
            return Ok(0);
        }
        let mut stmt = self
            .conn
            .prepare(
                "SELECT ip, port, status, note, updated FROM triage
                 ORDER BY +ip ASC, +port ASC",
            )
            .context("db: triage prepare")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                Ipv4Addr::from(r.get::<_, i64>(0)? as u32),
                r.get::<_, i64>(1)? as u16,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })?;
        let mut n = 0usize;
        for row in rows {
            let (ip, port, status, note, updated) = row?;
            cb(ip, port, status.as_deref(), &note, updated);
            n += 1;
        }
        Ok(n)
    }

    /// One host's triage marks, port ASC (port 0 = the host-level row).
    pub fn triage_for_ip(
        &self,
        ip: Ipv4Addr,
        cb: &mut impl FnMut(u16, Option<&str>, &str, i64),
    ) -> Result<usize> {
        if !self.has_triage() {
            return Ok(0);
        }
        let mut stmt = self
            .conn
            .prepare(
                "SELECT port, status, note, updated FROM triage
                 WHERE ip = ?1 ORDER BY +port ASC",
            )
            .context("db: triage_for_ip prepare")?;
        let rows = stmt.query_map([i64::from(u32::from(ip))], |r| {
            Ok((
                r.get::<_, i64>(0)? as u16,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?;
        let mut n = 0usize;
        for row in rows {
            let (port, status, note, updated) = row?;
            cb(port, status.as_deref(), &note, updated);
            n += 1;
        }
        Ok(n)
    }

    /// Every bookmarked host — (ip, updated) — streamed to `cb`, ordered by
    /// IP. On a registry without the flag tables this yields nothing.
    pub fn bookmarks(&self, cb: &mut impl FnMut(Ipv4Addr, i64)) -> Result<usize> {
        if !self.has_flags() {
            return Ok(0);
        }
        let mut stmt = self
            .conn
            .prepare("SELECT ip, updated FROM bookmark ORDER BY +ip ASC")
            .context("db: bookmark prepare")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                Ipv4Addr::from(r.get::<_, i64>(0)? as u32),
                r.get::<_, i64>(1)?,
            ))
        })?;
        let mut n = 0usize;
        for row in rows {
            let (ip, updated) = row?;
            cb(ip, updated);
            n += 1;
        }
        Ok(n)
    }

    /// Every PW3ND-marked host — (ip, updated) — streamed to `cb`, ordered
    /// by IP. Same guard as the bookmark view.
    pub fn pwned(&self, cb: &mut impl FnMut(Ipv4Addr, i64)) -> Result<usize> {
        if !self.has_flags() {
            return Ok(0);
        }
        let mut stmt = self
            .conn
            .prepare("SELECT ip, updated FROM pwned ORDER BY +ip ASC")
            .context("db: pwned prepare")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                Ipv4Addr::from(r.get::<_, i64>(0)? as u32),
                r.get::<_, i64>(1)?,
            ))
        })?;
        let mut n = 0usize;
        for row in rows {
            let (ip, updated) = row?;
            cb(ip, updated);
            n += 1;
        }
        Ok(n)
    }

    /// True when the host carries the bookmark (or the PW3ND mark — one
    /// lookup, the caller says which table).
    fn flag_for_ip(&self, table: &str, ip: Ipv4Addr) -> Result<Option<i64>> {
        if !self.has_flags() {
            return Ok(None);
        }
        match self.conn.query_row(
            &format!("SELECT updated FROM {table} WHERE ip = ?1"),
            [i64::from(u32::from(ip))],
            |r| r.get::<_, i64>(0),
        ) {
            Ok(stamp) => Ok(Some(stamp)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The host's bookmark stamp — present when bookmarked.
    pub fn bookmark_for_ip(&self, ip: Ipv4Addr) -> Result<Option<i64>> {
        self.flag_for_ip("bookmark", ip)
    }

    /// The host's PW3ND stamp — present when marked compromised.
    pub fn pwned_for_ip(&self, ip: Ipv4Addr) -> Result<Option<i64>> {
        self.flag_for_ip("pwned", ip)
    }

    /// Every tag — (ip, tag, updated) — streamed to `cb`, ordered by ip
    /// then tag (the views build their per-host maps from one pass).
    pub fn tags(&self, cb: &mut impl FnMut(Ipv4Addr, &str, i64)) -> Result<usize> {
        if !self.has_flags() {
            return Ok(0);
        }
        let mut stmt = self
            .conn
            .prepare("SELECT ip, tag, updated FROM tags ORDER BY +ip ASC, +tag ASC")
            .context("db: tags prepare")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                Ipv4Addr::from(r.get::<_, i64>(0)? as u32),
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        let mut n = 0usize;
        for row in rows {
            let (ip, tag, updated) = row?;
            cb(ip, &tag, updated);
            n += 1;
        }
        Ok(n)
    }

    /// One host's tags — (tag, updated) — tag ASC.
    pub fn tags_for_ip(&self, ip: Ipv4Addr) -> Result<Vec<(String, i64)>> {
        if !self.has_flags() {
            return Ok(Vec::new());
        }
        let mut stmt = self
            .conn
            .prepare("SELECT tag, updated FROM tags WHERE ip = ?1 ORDER BY +tag ASC")
            .context("db: tags_for_ip prepare")?;
        let rows = stmt.query_map([i64::from(u32::from(ip))], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Every asset type — (ip, kind, basis, source, updated) — streamed to
    /// `cb`, ordered by kind then IP (the dashboard's class view groups by
    /// kind).
    pub fn types(&self, cb: &mut impl FnMut(Ipv4Addr, &str, &str, &str, i64)) -> Result<usize> {
        if !self.has_types() {
            return Ok(0);
        }
        let mut stmt = self
            .conn
            .prepare(
                "SELECT ip, kind, basis, source, updated FROM asset_types
                 ORDER BY +kind ASC, +ip ASC",
            )
            .context("db: types prepare")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                Ipv4Addr::from(r.get::<_, i64>(0)? as u32),
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })?;
        let mut n = 0usize;
        for row in rows {
            let (ip, kind, basis, source, updated) = row?;
            cb(ip, &kind, &basis, &source, updated);
            n += 1;
        }
        Ok(n)
    }

    /// One host's asset type — (kind, basis, source) — or `None`.
    pub fn type_for_ip(&self, ip: Ipv4Addr) -> Result<Option<(String, String, String)>> {
        if !self.has_types() {
            return Ok(None);
        }
        match self.conn.query_row(
            "SELECT kind, basis, source FROM asset_types WHERE ip = ?1",
            [i64::from(u32::from(ip))],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        ) {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Up in discovery (A/B) with zero open scan ports — the hosts a scan
    /// pass could not explain. Streamed to `cb`, ordered by IP; returns the
    /// count.
    pub fn anomalies_silent(&self, cb: &mut impl FnMut(Ipv4Addr)) -> Result<usize> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT DISTINCT hs.ip FROM host_state hs
                 WHERE hs.status = 'up' AND hs.phase IN ('A','B')
                   AND NOT EXISTS (
                       SELECT 1 FROM results r
                       WHERE r.ip = hs.ip AND r.phase = 'C' AND r.status = 'open')
                 ORDER BY hs.ip ASC",
            )
            .context("db: anomalies_silent prepare")?;
        let rows = stmt.query_map([], |r| Ok(Ipv4Addr::from(r.get::<_, i64>(0)? as u32)))?;
        let mut n = 0usize;
        for ip in rows {
            cb(ip?);
            n += 1;
        }
        Ok(n)
    }

    /// The hosts a scan pass should queue: every host up in discovery, or —
    /// with `refresh_after` set (incremental mode) — only those never scanned
    /// (no scan results rows at all) or whose latest scan row is older than
    /// the window. A host scanned but mute (nmap `--open` writes no closed
    /// rows) has no scan rows and therefore re-queues every pass: the silent
    /// ones keep being retried, the explained ones sleep.
    pub fn scan_queue(&self, refresh_after: Option<Duration>) -> Result<RoaringBitmap> {
        let mut out = RoaringBitmap::new();
        let mut stmt = self
            .conn
            .prepare(
                "SELECT hs.ip, MAX(r.last_seen) FROM host_state hs
                 LEFT JOIN results r ON r.ip = hs.ip AND r.phase = 'C'
                 WHERE hs.status = 'up' AND hs.phase IN ('A','B')
                 GROUP BY hs.ip",
            )
            .context("db: scan_queue prepare")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Option<i64>>(1)?))
        })?;
        let cutoff = refresh_after.map(|d| now() - d.as_secs() as i64);
        for row in rows {
            let (ip, last_scan) = row?;
            let queue = match (cutoff, last_scan) {
                // full queue: every up host
                (None, _) => true,
                // never scanned (or scanned but mute): always worth another pass
                (Some(_), None) => true,
                // scanned within the window: skip
                (Some(cutoff), Some(seen)) => seen < cutoff,
            };
            if queue {
                out.insert(ip as u32);
            }
        }
        Ok(out)
    }

    /// (up hosts, no_response hosts, current answered-probe rows — the
    /// latest verdict per (ip, port), not the full result history).
    pub fn counts(&self) -> Result<(u64, u64, u64)> {
        let one = |sql: &str| -> Result<u64> {
            Ok(self.conn.query_row(sql, [], |r| r.get::<_, i64>(0))? as u64)
        };
        Ok((
            one("SELECT COUNT(*) FROM host_state WHERE status = 'up'")?,
            one("SELECT COUNT(*) FROM host_state WHERE status = 'no_response'")?,
            one("SELECT COUNT(*) FROM results")?,
        ))
    }
}

/// Prepares, steps and forwards one services row stream to `cb` — shared by
/// the view shapes in [`Db::services`]. Streaming: rows reach the caller one
/// at a time, nothing materializes.
fn stream_services(
    conn: &Connection,
    sql: &str,
    vals: Vec<rusqlite::types::Value>,
    cb: &mut impl FnMut(Ipv4Addr, u16, &str, &str, i64, &str),
) -> Result<usize> {
    let mut stmt = conn.prepare(sql).context("db: services prepare")?;
    let rows = stmt.query_map(rusqlite::params_from_iter(vals), |r| {
        Ok((
            Ipv4Addr::from(r.get::<_, i64>(0)? as u32),
            r.get::<_, i64>(1)? as u16,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, i64>(4)?,
            r.get::<_, String>(5)?,
        ))
    })?;
    let mut n = 0usize;
    for row in rows {
        let (ip, port, name, version, seen, run) = row?;
        cb(ip, port, &name, &version, seen, &run);
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "rustrawl-db-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|t| t.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn roundtrip_and_skip() {
        let root = tmp_root("roundtrip");
        let mut db = Db::open(&root).unwrap();
        db.set_run_id("run-test");

        db.record_host("10.0.0.1".parse().unwrap(), Stage::Sweep, true, 2);
        db.record_host("10.0.0.2".parse().unwrap(), Stage::Sweep, false, 2);
        // up in expand only (an expand-only port answered): must count as up
        // for the scan input, which unions sweep and expand history
        db.record_host("10.0.0.3".parse().unwrap(), Stage::Expand, true, 4);
        db.record_result("10.0.0.1".parse().unwrap(), 22, Stage::Sweep, Answer::Open);
        db.record_result(
            "10.0.0.1".parse().unwrap(),
            80,
            Stage::Sweep,
            Answer::Closed,
        );
        db.flush().unwrap();

        // idempotent re-record: upsert, no duplicate, monotone up
        db.record_host("10.0.0.2".parse().unwrap(), Stage::Sweep, true, 2);
        db.flush().unwrap();

        let (up, missed, results) = db.counts().unwrap();
        assert_eq!(up, 3, "10.0.0.2 must flip no_response → up; B-up counts");
        assert_eq!(missed, 0);
        assert_eq!(results, 2);

        let skip = db
            .skip_set(Stage::Sweep, Some(Duration::from_secs(3600)), None)
            .unwrap();
        assert_eq!(skip.len(), 2, "expand rows do not cover sweep decisions");

        // up hosts age out after the re-check delay: 30 days fresh → skipped
        let skip_fresh_up = db
            .skip_set(
                Stage::Sweep,
                Some(Duration::from_secs(3600)),
                Some(Duration::from_secs(30 * 86_400)),
            )
            .unwrap();
        assert_eq!(skip_fresh_up.len(), 2);

        let ups_a = db.up_hosts(&[Stage::Sweep]).unwrap();
        assert_eq!(ups_a.len(), 2);
        assert!(ups_a.contains(0x0A00_0001));
        let ups_ab = db.up_hosts(&[Stage::Sweep, Stage::Expand]).unwrap();
        assert_eq!(ups_ab.len(), 3, "the scan input unions both stages");
        assert!(ups_ab.contains(0x0A00_0003));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn services_for_ip_streams_one_host() {
        let root = tmp_root("svc4ip");
        let mut db = Db::open(&root).unwrap();
        db.set_run_id("run-test");
        db.record_service("10.0.0.1".parse().unwrap(), 443, "https", "nginx 1.22.1");
        db.record_service("10.0.0.1".parse().unwrap(), 22, "ssh", "OpenSSH 9.2p1");
        db.record_service("10.0.0.2".parse().unwrap(), 80, "http", "lighttpd");
        db.flush().unwrap();

        let mut rows = Vec::new();
        let n = db
            .services_for_ip("10.0.0.1".parse().unwrap(), &mut |port, name, version| {
                rows.push((port, name.to_string(), version.to_string()));
            })
            .unwrap();
        assert_eq!(n, 2);
        assert_eq!(
            rows,
            vec![
                (22, "ssh".to_string(), "OpenSSH 9.2p1".to_string()),
                (443, "https".to_string(), "nginx 1.22.1".to_string()),
            ],
            "the host's own rows, port ASC, nothing from the neighbors"
        );
        let none = db
            .services_for_ip("10.0.0.9".parse().unwrap(), &mut |_, _, _| {})
            .unwrap();
        assert_eq!(none, 0, "unknown host → no rows");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn names_roundtrip_upsert_and_order() {
        let root = tmp_root("names-rt");
        let mut db = Db::open(&root).unwrap();
        db.set_run_id("names_2026-10-12_101112");
        db.record_name(
            "10.0.0.2".parse().unwrap(),
            "web.corp.example.com",
            "dns-ptr",
        );
        db.record_name("10.0.0.1".parse().unwrap(), "dc01.corp.example.com", "ldap");
        // Same (ip, name) seen again under a fresher source: the latest
        // observation wins, no duplicate row.
        db.record_name(
            "10.0.0.1".parse().unwrap(),
            "dc01.corp.example.com",
            "ldap-sam",
        );
        db.flush().unwrap();

        let mut rows = Vec::new();
        let n = db
            .names(&mut |ip, name, source, _seen, run| {
                rows.push((ip, name.to_string(), source.to_string(), run.to_string()));
            })
            .unwrap();
        assert_eq!(n, 2, "upsert on (ip, name): no duplicate");
        assert_eq!(
            rows,
            vec![
                (
                    "10.0.0.1".parse().unwrap(),
                    "dc01.corp.example.com".to_string(),
                    "ldap-sam".to_string(),
                    "names_2026-10-12_101112".to_string(),
                ),
                (
                    "10.0.0.2".parse().unwrap(),
                    "web.corp.example.com".to_string(),
                    "dns-ptr".to_string(),
                    "names_2026-10-12_101112".to_string(),
                ),
            ],
            "ip ASC then name ASC; second source replaced the first"
        );

        let mut one = Vec::new();
        let n = db
            .names_for_ip(
                "10.0.0.2".parse().unwrap(),
                &mut |name, source, _seen, _run| {
                    one.push((name.to_string(), source.to_string()));
                },
            )
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(
            one,
            vec![("web.corp.example.com".to_string(), "dns-ptr".to_string())]
        );

        // host_detail carries the names block
        let detail = db
            .host_detail("10.0.0.2".parse().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(detail.names.len(), 1);
        assert_eq!(detail.names[0].0, "web.corp.example.com");
        assert_eq!(detail.names[0].1, "dns-ptr");

        // Unknown IP: no rows, and detail is None (names alone cannot make
        // a host known — D2 keeps only registered assets).
        let none = db
            .names_for_ip("10.0.0.9".parse().unwrap(), &mut |_, _, _, _| {})
            .unwrap();
        assert_eq!(none, 0);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn names_guard_on_older_registry() {
        let root = tmp_root("names-old");
        {
            let mut db = Db::open(&root).unwrap();
            db.set_run_id("run-test");
            db.record_host("10.0.0.1".parse().unwrap(), Stage::Sweep, true, 2);
            db.record_name(
                "10.0.0.1".parse().unwrap(),
                "old.corp.example.com",
                "dns-ptr",
            );
            db.flush().unwrap();
        }
        // Simulate an older build's registry: the table does not exist.
        {
            let conn = Connection::open(root.join("scandb.sqlite")).unwrap();
            conn.execute("DROP TABLE hostnames", []).unwrap();
        }
        // Read-only open of the old file: the names views report nothing,
        // no error (the has_hostnames guard).
        {
            let db = Db::open_read_only(&root).unwrap();
            let n = db.names(&mut |_, _, _, _, _| {}).unwrap();
            assert_eq!(n, 0, "older registry reads as empty, never errors");
            let detail = db
                .host_detail("10.0.0.1".parse().unwrap())
                .unwrap()
                .unwrap();
            assert!(detail.names.is_empty());
        }
        // A write-mode open recreates the table and collecting continues.
        {
            let mut db = Db::open(&root).unwrap();
            db.set_run_id("names_2026-10-12_101112");
            db.record_name("10.0.0.1".parse().unwrap(), "new.corp.example.com", "tls");
            db.flush().unwrap();
            let n = db.names(&mut |_, _, _, _, _| {}).unwrap();
            assert_eq!(n, 1);
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn triage_upsert_delete_and_order() {
        let root = tmp_root("triage");
        let ip = Ipv4Addr::new(10, 30, 0, 7);
        {
            let mut db = Db::open(&root).unwrap();
            db.set_run_id("manual");
            // One host-level mark (marks live on the host only).
            db.record_triage(ip, Some("todo"), "check the web app");
            db.flush().unwrap();
        }
        {
            let db = Db::open_read_only(&root).unwrap();
            let mut seen = Vec::new();
            db.triage(&mut |ip, port, status, note, _| {
                seen.push((ip, port, status.map(|s| s.to_string()), note.to_string()))
            })
            .unwrap();
            assert_eq!(
                seen,
                vec![(ip, 0, Some("todo".into()), "check the web app".into())]
            );
            // Triage marks alone never make a host "known" (same rule as the
            // names rows): the detail view of a triage-only host is None.
            assert!(db.host_detail(ip).unwrap().is_none());
            // The detail view carries the row once the host exists.
            {
                let mut db2 = Db::open(&root).unwrap();
                db2.set_run_id("scan_test");
                db2.record_host(ip, Stage::Scan, true, 1);
                db2.flush().unwrap();
            }
            let detail = db.host_detail(ip).unwrap().unwrap();
            assert_eq!(detail.triage.len(), 1);
            assert_eq!(detail.triage[0].0, 0);
        }
        // Upsert: changing the status keeps the row single.
        {
            let mut db = Db::open(&root).unwrap();
            db.set_run_id("manual");
            db.record_triage(ip, Some("clean"), "");
            db.flush().unwrap();
            let db = Db::open_read_only(&root).unwrap();
            let n = db
                .triage_for_ip(ip, &mut |_, status, note, _| {
                    assert_eq!(status, Some("clean"));
                    assert_eq!(note, "");
                })
                .unwrap();
            assert_eq!(n, 1);
        }
        // A note-only row (status cleared, note kept) survives.
        {
            let mut db = Db::open(&root).unwrap();
            db.set_run_id("manual");
            db.record_triage(ip, None, "ask the admin");
            db.flush().unwrap();
            let db = Db::open_read_only(&root).unwrap();
            let n = db
                .triage_for_ip(ip, &mut |_, status, note, _| {
                    assert_eq!(status, None);
                    assert_eq!(note, "ask the admin");
                })
                .unwrap();
            assert_eq!(n, 1);
        }
        // Clearing the last content deletes the row; a batch that deletes
        // then re-sets nets to the re-set.
        {
            let mut db = Db::open(&root).unwrap();
            db.set_run_id("manual");
            db.record_triage(ip, None, "");
            db.record_triage(ip, Some("todo"), "second look");
            db.flush().unwrap();
            let db = Db::open_read_only(&root).unwrap();
            let mut rows = Vec::new();
            db.triage_for_ip(ip, &mut |port, status, note, _| {
                rows.push((port, status.map(|s| s.to_string()), note.to_string()))
            })
            .unwrap();
            assert_eq!(rows, vec![(0, Some("todo".into()), "second look".into())]);
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn port_rows_die_and_retired_words_move_on_write_open() {
        let root = tmp_root("triage-migrate");
        let ip = Ipv4Addr::new(10, 30, 0, 9);
        {
            let mut db = Db::open(&root).unwrap();
            db.set_run_id("manual");
            db.record_host(ip, Stage::Scan, true, 1);
            db.flush().unwrap();
            // rows exactly as an older build wrote them: marks on ports,
            // and the retired host words
            let conn = Connection::open(root.join("scandb.sqlite")).unwrap();
            conn.execute(
                "INSERT INTO triage (ip, port, status, note, updated) VALUES (?1, 22, 'flagged', 'no NLA', 0)",
                [u32::from(ip)],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO triage (ip, port, status, note, updated) VALUES (?1, 80, 'wip', 'mid check', 0)",
                [u32::from(ip)],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO triage (ip, port, status, note, updated) VALUES (?1, 0, 'flagged', 'host row', 0)",
                [u32::from(ip)],
            )
            .unwrap();
        }
        // A write-mode open drops the port rows and moves the host row to
        // the one vocabulary (flagged reads vuln from here on).
        {
            let db = Db::open(&root).unwrap();
            drop(db);
        }
        {
            let db = Db::open_read_only(&root).unwrap();
            let mut rows = Vec::new();
            db.triage_for_ip(ip, &mut |port, status, _, _| {
                rows.push((port, status.map(str::to_string)))
            })
            .unwrap();
            assert_eq!(rows, vec![(0, Some("vuln".into()))]);
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn triage_guard_on_older_registry() {
        let root = tmp_root("triage-old");
        {
            let mut db = Db::open(&root).unwrap();
            db.set_run_id("run-test");
            db.record_host("10.0.0.1".parse().unwrap(), Stage::Sweep, true, 2);
            db.record_triage(
                "10.0.0.1".parse().unwrap(),
                Some("todo"),
                "look at this one",
            );
            db.flush().unwrap();
        }
        // Simulate an older build's registry: the tables do not exist.
        {
            let conn = Connection::open(root.join("scandb.sqlite")).unwrap();
            conn.execute("DROP TABLE triage", []).unwrap();
            conn.execute("DROP TABLE asset_types", []).unwrap();
        }
        // Read-only open of the old file: the triage views report nothing,
        // no error (the has_triage / has_types guards).
        {
            let db = Db::open_read_only(&root).unwrap();
            let n = db.triage(&mut |_, _, _, _, _| {}).unwrap();
            assert_eq!(n, 0, "older registry reads as empty, never errors");
            assert_eq!(db.type_for_ip("10.0.0.1".parse().unwrap()).unwrap(), None);
            let detail = db
                .host_detail("10.0.0.1".parse().unwrap())
                .unwrap()
                .unwrap();
            assert!(detail.triage.is_empty());
            assert!(detail.asset_type.is_none());
        }
        // A write-mode open recreates the tables.
        {
            let mut db = Db::open(&root).unwrap();
            db.set_run_id("manual");
            db.record_triage("10.0.0.1".parse().unwrap(), Some("clean"), "");
            db.flush().unwrap();
            let n = db.triage(&mut |_, _, _, _, _| {}).unwrap();
            assert_eq!(n, 1);
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn flags_upsert_unmark_and_order() {
        let root = tmp_root("flags");
        let ip = Ipv4Addr::new(10, 40, 0, 3);
        let other = Ipv4Addr::new(10, 40, 0, 9);
        {
            let mut db = Db::open(&root).unwrap();
            db.set_run_id("manual");
            db.record_host(ip, Stage::Scan, true, 1);
            db.record_bookmark(ip, true);
            db.record_pwned(ip, true);
            db.record_bookmark(other, true);
            db.record_tag(ip, "dc", true);
            db.record_tag(ip, "adcs", true);
            db.flush().unwrap();
        }
        {
            let db = Db::open_read_only(&root).unwrap();
            let mut marks = Vec::new();
            db.bookmarks(&mut |ip, _| marks.push(ip)).unwrap();
            assert_eq!(marks, vec![ip, other], "bookmarks order by ip");
            let mut owned = Vec::new();
            db.pwned(&mut |ip, _| owned.push(ip)).unwrap();
            assert_eq!(owned, vec![ip]);
            assert!(db.bookmark_for_ip(ip).unwrap().is_some());
            assert!(db
                .bookmark_for_ip(Ipv4Addr::new(10, 40, 0, 99))
                .unwrap()
                .is_none());
            assert!(db.pwned_for_ip(ip).unwrap().is_some());
            assert!(db.pwned_for_ip(other).unwrap().is_none());
            // the detail view carries all three once the host exists
            let detail = db.host_detail(ip).unwrap().unwrap();
            assert!(detail.bookmark.is_some());
            assert!(detail.pwned.is_some());
            assert_eq!(
                detail
                    .tags
                    .iter()
                    .map(|(t, _)| t.as_str())
                    .collect::<Vec<_>>(),
                vec!["adcs", "dc"],
                "tags order by tag"
            );
        }
        // Unmarking is a write too; a batch that unmarks then re-marks nets
        // to the mark, and a tag remove rides the same rule.
        {
            let mut db = Db::open(&root).unwrap();
            db.set_run_id("manual");
            db.record_bookmark(ip, false);
            db.record_bookmark(ip, true);
            db.record_pwned(ip, false);
            db.record_tag(ip, "dc", false);
            db.record_tag(ip, "dc", true);
            db.record_tag(ip, "dc", false);
            db.flush().unwrap();
            let n = db.bookmarks(&mut |_, _| {}).unwrap();
            assert_eq!(
                n, 2,
                "the unmark+re-mark nets to one row, the other survives"
            );
            let n = db.pwned(&mut |_, _| {}).unwrap();
            assert_eq!(n, 0, "the pwned unmark lands");
            assert_eq!(db.tags_for_ip(ip).unwrap().len(), 1, "dc left, adcs stays");
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn toggle_pwned_flips_and_reports_the_new_state() {
        let root = tmp_root("toggle-pwned");
        let mut db = Db::open(&root).unwrap();
        db.set_run_id("t");
        let ip: Ipv4Addr = "10.0.0.5".parse().unwrap();

        // Absent -> on, on -> off, off -> on; each call reports the state
        // it left behind (the console's confirmation prints from it).
        assert!(db.toggle_pwned(ip).unwrap(), "first flip marks");
        db.flush().unwrap();
        assert!(db.pwned_for_ip(ip).unwrap().is_some());

        assert!(!db.toggle_pwned(ip).unwrap(), "second flip unmarks");
        db.flush().unwrap();
        assert!(db.pwned_for_ip(ip).unwrap().is_none());

        assert!(db.toggle_pwned(ip).unwrap(), "third flip marks again");
        db.flush().unwrap();
        assert!(db.pwned_for_ip(ip).unwrap().is_some());

        // Another host is untouched by the flips.
        let other: Ipv4Addr = "10.0.0.6".parse().unwrap();
        assert!(db.pwned_for_ip(other).unwrap().is_none());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn value_marks_become_bookmarks_on_write_open() {
        let root = tmp_root("value-old");
        // Rows exactly as an older build wrote them: a `value` table with
        // the crown/star ranking, no bookmark table.
        {
            let mut db = Db::open(&root).unwrap();
            db.set_run_id("run-test");
            db.record_host("10.0.0.1".parse().unwrap(), Stage::Sweep, true, 2);
            db.flush().unwrap();
            let conn = Connection::open(root.join("scandb.sqlite")).unwrap();
            conn.execute(
                "CREATE TABLE value (ip INTEGER PRIMARY KEY, rank TEXT NOT NULL,
                 updated INTEGER NOT NULL) WITHOUT ROWID",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO value (ip, rank, updated) VALUES (?1, 'crown', 42)",
                [u32::from(Ipv4Addr::new(10, 0, 0, 1))],
            )
            .unwrap();
        }
        // A write-mode open copies the ranking across as bookmarks and
        // drops the old table; a read-only open of the moved file shows it.
        {
            let db = Db::open(&root).unwrap();
            drop(db);
            let db = Db::open_read_only(&root).unwrap();
            let mut marked = Vec::new();
            db.bookmarks(&mut |ip, updated| marked.push((ip, updated)))
                .unwrap();
            assert_eq!(
                marked,
                vec![(Ipv4Addr::new(10, 0, 0, 1), 42)],
                "the crown lands as a bookmark, stamp kept"
            );
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn asset_types_upsert_and_manual_skip() {
        let root = tmp_root("types");
        let ip = Ipv4Addr::new(10, 30, 0, 5);
        {
            let mut db = Db::open(&root).unwrap();
            db.set_run_id("manual");
            db.record_host(ip, Stage::Scan, true, 1);
            db.record_asset_type(ip, "windows", "445+3389", "heuristic");
            db.flush().unwrap();
            // The classifier re-runs and refines its guess: the upsert wins.
            db.record_asset_type(ip, "dc", "445+88+389; name dc01", "heuristic");
            db.flush().unwrap();
        }
        {
            let db = Db::open_read_only(&root).unwrap();
            assert_eq!(
                db.type_for_ip(ip).unwrap(),
                Some((
                    "dc".into(),
                    "445+88+389; name dc01".into(),
                    "heuristic".into()
                ))
            );
            // Detail carries it; an untyped host has None.
            let detail = db.host_detail(ip).unwrap().unwrap();
            assert_eq!(detail.asset_type.as_ref().unwrap().0, "dc");
        }
        // The operator overrides; the classifier must never win again.
        {
            let mut db = Db::open(&root).unwrap();
            db.set_run_id("manual");
            db.record_asset_type(ip, "jump host", "operator said so", "manual");
            db.flush().unwrap();
            db.record_asset_type(ip, "windows", "445+3389", "heuristic");
            db.flush().unwrap();
            let db = Db::open_read_only(&root).unwrap();
            assert_eq!(
                db.type_for_ip(ip).unwrap(),
                Some((
                    "jump host".into(),
                    "operator said so".into(),
                    "manual".into()
                ))
            );
            let mut kinds = Vec::new();
            db.types(&mut |_, kind, _, source, _| {
                kinds.push((kind.to_string(), source.to_string()))
            })
            .unwrap();
            assert_eq!(kinds, vec![("jump host".to_string(), "manual".to_string())]);
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn retry_delay_ages_out() {
        let root = tmp_root("retry");
        let db = Db::open(&root).unwrap();
        let conn_path = root.join("scandb.sqlite");
        // no external conn: write rows with controlled last_seen through SQL
        let conn = Connection::open(&conn_path).unwrap();
        let old = now() - 86_400 * 8; // 8 days ago
        let fresh = now();
        conn.execute(
            "INSERT INTO host_state (ip, phase, status, last_seen, run_id, ports_tried)
             VALUES (167772161, 'A', 'no_response', ?1, 'r', 2)", // 10.0.0.1
            [old],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO host_state (ip, phase, status, last_seen, run_id, ports_tried)
             VALUES (167772162, 'A', 'no_response', ?1, 'r', 2)", // 10.0.0.2
            [fresh],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO host_state (ip, phase, status, last_seen, run_id, ports_tried)
             VALUES (167772163, 'A', 'up', ?1, 'r', 2)", // 10.0.0.3 — up always skips
            [old],
        )
        .unwrap();

        let skip = db
            .skip_set(Stage::Sweep, Some(Duration::from_secs(7 * 86_400)), None)
            .unwrap();
        assert!(
            !skip.contains(167772161),
            "8-day-old no_response must be retried"
        );
        assert!(skip.contains(167772162), "fresh no_response stays skipped");
        assert!(
            skip.contains(167772163),
            "up always skips when no recheck delay is set"
        );

        let skip_all = db.skip_set(Stage::Sweep, None, None).unwrap();
        assert_eq!(skip_all.len(), 3, "no retry delay → everything covers");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn sticky_up_last_seen_and_freshness() {
        let root = tmp_root("sticky");
        let mut db = Db::open(&root).unwrap();
        db.set_run_id("run-2");
        let conn = Connection::open(root.join("scandb.sqlite")).unwrap();
        let old = now() - 86_400 * 8; // 8 days ago
                                      // up 8 days ago, answered port 22 one day BEFORE that
        conn.execute(
            "INSERT INTO host_state (ip, phase, status, last_seen, run_id, ports_tried)
             VALUES (167772161, 'A', 'up', ?1, 'r1', 2)", // 10.0.0.1
            [old],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO results (ip, port, phase, status, last_seen, run_id)
             VALUES (167772161, 22, 'A', 'open', ?1, 'r1')",
            [old - 3600],
        )
        .unwrap();

        // A later run finds the host mute: sticky up — status AND last_seen
        // keep the up verdict, the mute run must not look like a fresh reply
        db.record_host("10.0.0.1".parse().unwrap(), Stage::Sweep, false, 2);
        db.flush().unwrap();
        let (status, seen): (String, i64) = conn
            .query_row(
                "SELECT status, last_seen FROM host_state WHERE ip = 167772161 AND phase = 'A'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(status, "up");
        assert_eq!(
            seen, old,
            "mute run must not refresh an up host's last_seen"
        );

        // the 8-day-old up now ages past a 7-day recheck window → re-probed
        let skip = db
            .skip_set(
                Stage::Sweep,
                Some(Duration::from_secs(7 * 86_400)),
                Some(Duration::from_secs(7 * 86_400)),
            )
            .unwrap();
        assert!(!skip.contains(167772161), "aged-out up must be rechecked");

        // the port answer predates the host verdict and STAYS: a results row
        // is the latest observation of its (ip, port, stage) — filtering by
        // the host's settle time could only drop true findings (a wide
        // connect host answers over minutes; a shrunk profile re-verifies
        // the host without re-probing every port)
        let (up, missed, answered) = db.counts().unwrap();
        assert_eq!((up, missed), (1, 0));
        assert_eq!(answered, 1, "the port answer is the truth about that port");

        // a fresh answer on another port is counted just the same
        db.record_result(
            "10.0.0.1".parse().unwrap(),
            443,
            Stage::Sweep,
            Answer::Closed,
        );
        db.flush().unwrap();
        assert_eq!(db.counts().unwrap().2, 2);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn up_ips_counts_every_up_host() {
        let root = tmp_root("since");
        let db = Db::open(&root).unwrap();
        let conn = Connection::open(root.join("scandb.sqlite")).unwrap();
        conn.execute(
            "INSERT INTO host_state (ip, phase, status, last_seen, run_id, ports_tried)
             VALUES (167772161, 'A', 'up', 1000, 'r1', 2)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO host_state (ip, phase, status, last_seen, run_id, ports_tried)
             VALUES (167772162, 'B', 'up', 2000, 'r2', 4)",
            [],
        )
        .unwrap();
        let mut n_up = 0usize;
        db.up_ips(&mut |_| n_up += 1).unwrap();
        assert_eq!(n_up, 2);
        std::fs::remove_dir_all(&root).ok();
    }
}
