//! The interactive db console — a level-based shell over one perimeter's
//! registry, in the shape of an msfconsole workflow: pick a level
//! (`ranges`, `hosts`, `services`, `db`), get that level's commands, switch
//! levels by typing their name, `..` climbs back up, `q` leaves. Typing a
//! level's name runs its default view (bare `services` lists everything);
//! a payload rides along on the switch (`hosts -s web` from anywhere
//! enters hosts and runs the search). `h` shows the current level's help.
//!
//! Stdin decides the mode: a TTY drives the rustyline loop (prompt
//! `rustrawl(perim) hosts> `, ^C re-prompts, ^D or `q` leaves), anything
//! else is batch mode — commands stream from stdin, the prompt is
//! suppressed and one notice explains it on stderr. That makes
//! `printf 'services\n' | rustrawl db --out perim` work and gives the
//! integration suite its binary-level test path.
//!
//! The session never dies on a bad command: an unknown command, a missing
//! argument or a registry error prints and re-prompts — only `q`, ^D or
//! a broken pipe ends it.

use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use rustyline::error::ReadlineError;
use rustyline::history::FileHistory;
use rustyline::Editor;

use crate::discovery::db::Db;

// --------------------------------------------------------------- entry point

pub fn run(out: &Path) -> Result<()> {
    // Eager open: a typo'd perimeter errors before the first prompt, like
    // the one-shot subcommands.
    let db = Db::open_read_only(out)?;
    let name = out
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("?")
        .to_string();
    let mut con = Console {
        out: out.to_path_buf(),
        db,
        level: Level::Top,
    };
    let prompt = |level: Level| match level {
        Level::Top => format!("rustrawl({name})> "),
        other => format!("rustrawl({name}) {}> ", other.name()),
    };

    if unsafe { libc::isatty(0) } != 1 {
        // Batch mode: prompt suppressed, commands streamed, errors inline.
        // Read whole + split manually so non-UTF-8 bytes degrade per line
        // (lossy) instead of aborting the batch.
        eprintln!(
            "# console: commands read from stdin (not a TTY) - levels: ranges hosts services db"
        );
        let stdout = std::io::stdout();
        let mut w = BufWriter::new(stdout.lock());
        let mut input = Vec::new();
        std::io::stdin().read_to_end(&mut input)?;
        for line in input.split(|b| *b == b'\n') {
            let line = String::from_utf8_lossy(line);
            if !con.exec(&mut w, &line)? {
                break;
            }
        }
        w.flush()?;
        return Ok(());
    }

    // Interactive: rustyline for editing + a per-perimeter history.
    let history_path = out.join(".db_history");
    let mut rl: Editor<(), FileHistory> = Editor::new()?;
    rl.load_history(&history_path).ok(); // first session on this perimeter
    let mut read_errors = 0u32; // a flaky terminal must not spin the loop hot
    loop {
        match rl.readline(&prompt(con.level)) {
            Ok(line) => {
                read_errors = 0;
                let _ = rl.add_history_entry(line.trim());
                let stdout = std::io::stdout();
                let mut w = BufWriter::new(stdout.lock());
                let cont = con.exec(&mut w, &line)?;
                w.flush()?;
                if !cont {
                    break;
                }
            }
            Err(ReadlineError::Interrupted) => {
                // ^C abandons the current line — like msf, the session lives.
                println!("^C");
            }
            Err(ReadlineError::Eof) => break, // ^D = quit
            Err(ReadlineError::Signal(_)) => {
                // Window resize (SIGWINCH): not an error — just re-prompt.
            }
            Err(e) => {
                read_errors += 1;
                eprintln!("# console: read error ({e})");
                if read_errors >= 5 {
                    eprintln!("# console: too many consecutive read errors - leaving");
                    break;
                }
            }
        }
    }
    rl.save_history(&history_path).ok(); // best-effort — losing history must not fail the session
    Ok(())
}

// --------------------------------------------------------------- the session

/// One drill-down of the shell. `Top` only dispatches; the four levels own
/// their grammars. Levels switch by name (the default view prints), `..`
/// climbs up, `q` leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
    Top,
    Ranges,
    Hosts,
    Services,
    Db,
}

impl Level {
    fn name(self) -> &'static str {
        match self {
            Level::Top => "",
            Level::Ranges => "ranges",
            Level::Hosts => "hosts",
            Level::Services => "services",
            Level::Db => "db",
        }
    }

    fn of(s: &str) -> Option<Level> {
        Some(match s {
            "ranges" => Level::Ranges,
            "hosts" => Level::Hosts,
            "services" => Level::Services,
            "db" => Level::Db,
            _ => return None,
        })
    }
}

struct Console {
    out: PathBuf,
    db: Db,
    level: Level,
}

impl Console {
    /// Run one command line. `Ok(true)` keeps the session alive, `Ok(false)`
    /// quits. Unknown commands and runtime errors print to `w` — a typo or
    /// a bad argument must not kill the session.
    fn exec(&mut self, w: &mut dyn std::io::Write, line: &str) -> Result<bool> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return Ok(true);
        }
        // A malformed line (unbalanced quote, bare `>`, unbalanced parens)
        // prints and the session lives — like an unknown command. The
        // parens split first so either order works: `hosts -r ip (-p 445)
        // > file` and `hosts -r ip > file (-p 445)` reach the rescan with
        // the payload and the file each carrying what was typed.
        let (cmd, paren) = match split_parens(line) {
            Ok(r) => r,
            Err(e) => {
                writeln!(w, "error: {e:#}")?;
                return Ok(true);
            }
        };
        let (cmd, redirect) = match split_redirect(&cmd) {
            Ok(r) => r,
            Err(e) => {
                writeln!(w, "error: {e:#}")?;
                return Ok(true);
            }
        };
        let inv = match parse_line(cmd) {
            Ok(i) => i,
            Err(e) => {
                writeln!(w, "error: {e:#}")?;
                return Ok(true);
            }
        };
        if inv.verb.is_empty() {
            return Ok(true);
        }
        // Global tokens, every level: the exits, the help, the climb-up.
        match inv.verb.as_str() {
            "q" | "quit" | "exit" => return Ok(false),
            "h" | "help" | "?" => {
                return self.dispatch(w, redirect, |fw| help(fw, self.level));
            }
            ".." | "back" => {
                if self.level == Level::Top {
                    writeln!(
                        w,
                        "# already at the top - levels: ranges, hosts, services, db"
                    )?;
                } else {
                    self.level = Level::Top;
                    writeln!(
                        w,
                        "# top level - ranges, hosts, services, db, or h for help"
                    )?;
                }
                return Ok(true);
            }
            _ => {}
        }
        // A level name switches levels and runs its view: bare `services`
        // lists everything, `hosts -s web` enters hosts and searches.
        if let Some(lv) = Level::of(&inv.verb) {
            self.level = lv;
            return self.dispatch(w, redirect, |fw| {
                self.run_level(fw, lv, &inv.args, paren.as_deref())
            });
        }
        // Any other word runs in the current level; at the top there is
        // nothing to run it in.
        if self.level == Level::Top {
            writeln!(
                w,
                "unknown command \"{}\" - the levels: ranges, hosts, services, db (h for help)",
                inv.verb
            )?;
            return Ok(true);
        }
        let level = self.level;
        // The verb rides along: inside a level the first word is the
        // command (`-p 80`, a services spec, `db stats`) and a stray word
        // must reach the level's parser, not dissolve into the bare view.
        let mut full: Vec<String> = Vec::with_capacity(inv.args.len() + 1);
        full.push(inv.verb.clone());
        full.extend(inv.args.iter().cloned());
        self.dispatch(w, redirect, |fw| {
            self.run_level(fw, level, &full, paren.as_deref())
        })
    }

    /// Shared tail of `exec`: run the fallible part, report an error
    /// inline (the session lives); with a `> path` redirect, run into the
    /// file instead (the perimeter's own files are refused) and confirm on
    /// the terminal. Either way the session survives a failed command.
    fn dispatch(
        &self,
        w: &mut dyn std::io::Write,
        redirect: Option<PathBuf>,
        f: impl FnOnce(&mut dyn std::io::Write) -> Result<()>,
    ) -> Result<bool> {
        let Some(path) = redirect else {
            if let Err(e) = f(w) {
                writeln!(w, "error: {e:#}")?;
            }
            return Ok(true);
        };
        if let Err(e) = redirect_allowed(&path, &self.out) {
            writeln!(w, "error: {e:#}")?;
            return Ok(true);
        }
        let file = match std::fs::File::create(&path) {
            Ok(f) => f,
            Err(e) => {
                writeln!(w, "error: cannot create {}: {e}", path.display())?;
                return Ok(true);
            }
        };
        let mut fw = BufWriter::new(file);
        let res = f(&mut fw);
        let flushed = fw.flush().is_ok();
        match (res, flushed) {
            (Ok(()), true) => writeln!(w, "# wrote {}", path.display())?,
            (Ok(()), false) => {
                writeln!(
                    w,
                    "error: flush to {} failed - it may be incomplete",
                    path.display()
                )?;
            }
            (Err(e), _) => {
                writeln!(
                    w,
                    "error: {e:#} - {} holds the partial output",
                    path.display()
                )?;
            }
        }
        Ok(true)
    }

    // ------------------------------------------------------------- levels

    fn run_level(
        &self,
        w: &mut dyn std::io::Write,
        level: Level,
        args: &[String],
        paren: Option<&str>,
    ) -> Result<()> {
        match level {
            Level::Top => unreachable!("top dispatches, it never runs"),
            Level::Ranges => self.ranges_level(w, args, paren),
            Level::Hosts => self.hosts_level(w, args, paren),
            Level::Services => self.services_level(w, args, paren),
            Level::Db => self.db_level(w, args, paren),
        }
    }

    /// `ranges`: bare = the /24 table; `-p` groups at another prefix,
    /// `-s` filters the buckets, `-S` prints one bucket's card, `-e`
    /// writes the up-host list.
    fn ranges_level(
        &self,
        w: &mut dyn std::io::Write,
        args: &[String],
        paren: Option<&str>,
    ) -> Result<()> {
        if paren.is_some() {
            bail!("the (…) payload is a `hosts -r` thing - ranges takes plain flags");
        }
        let mut prefix: Option<String> = None;
        let mut search: Option<String> = None;
        let mut show: Option<String> = None;
        let mut export = false;
        let mut hostnames = false;
        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "-p" | "--prefix" => {
                    prefix = Some(flag_value(&mut it, "-p needs a prefix length (8, 16, 24)")?)
                }
                "-s" | "--search" => {
                    search = Some(flag_value(&mut it, "-s needs a filter string")?)
                }
                "-S" | "--show" => {
                    show = Some(flag_value(
                        &mut it,
                        "-S needs a range (10.30.4, 10.30.4.0/24, or a host ip)",
                    )?)
                }
                "-e" | "--export" => export = true,
                "--hostnames" => hostnames = true,
                "txt" => {}
                s if s.starts_with('-') && s != "-" => bail!(
                    "unknown option {s:?} - ranges takes [-p prefix] [-s term] [-S range] [-e [--hostnames]]"
                ),
                s => bail!(
                    "ranges takes flags only - got the positional {s:?} (usage: ranges [-p prefix] [-s term] [-S range] [-e])"
                ),
            }
        }
        if let Some(spec) = show {
            if prefix.is_some() || search.is_some() || export {
                bail!("-S prints one range's card - it combines with nothing");
            }
            return crate::render_range_card(w, &self.out, &spec);
        }
        if export {
            if prefix.is_some() || search.is_some() {
                bail!(
                    "-p and -s shape the table - the -e host list is always every up host \
                     (--hostnames swaps in the names)"
                );
            }
            return crate::render_hosts_txt(w, &self.out, hostnames);
        }
        crate::render_ranges(w, &self.out, prefix.as_deref(), search.as_deref())
    }

    /// `hosts`: bare = the up list; `-s` searches, `-S` shows one host's
    /// services + its nmap evidence stack, `-r` rescans (payload in
    /// parentheses), `-c` toggles the pwned mark, `-ta`/`-td` edit tags,
    /// `-n` views or writes the note, `-i` prints the identity card, `-e`
    /// writes the host list.
    fn hosts_level(
        &self,
        w: &mut dyn std::io::Write,
        args: &[String],
        paren: Option<&str>,
    ) -> Result<()> {
        // The paren payload is the rescan's (nmap args or a port list);
        // everywhere else it would be silently dropped, so refuse it like
        // the sibling levels do.
        if paren.is_some()
            && !matches!(
                args.first().map(String::as_str),
                Some("-r") | Some("--rescan")
            )
        {
            bail!("the (…) payload is a `hosts -r` thing - the other hosts verbs take plain flags");
        }
        if args.is_empty() {
            return crate::render_hosts(w, &self.out, None);
        }
        let mut it = args.iter();
        match it.next().unwrap().as_str() {
            "-s" | "--search" => {
                let term = flag_value(&mut it, "-s needs a search string (ip or name fragment)")?;
                if it.next().is_some() {
                    bail!("-s takes one search string (quote it if it has spaces)");
                }
                crate::render_hosts_search(w, &self.out, &term)
            }
            "-S" | "--show" => {
                let target = flag_value(&mut it, "-S needs an ip or hostname")?;
                let scans: usize = match it.next() {
                    None => 1,
                    Some(n) => {
                        let n: usize = n
                            .parse()
                            .map_err(|_| anyhow!("-S scan count must be a number, got {n:?}"))?;
                        if n == 0 {
                            bail!("-S scan count must be at least 1");
                        }
                        n
                    }
                };
                if it.next().is_some() {
                    bail!("usage: hosts -S <ip|hostname> [scan count]");
                }
                let ip = crate::resolve_host(&self.db, &target)?;
                crate::render_host_services(w, &self.db, ip)?;
                crate::evidence::render_host_evidence_last(w, &self.out, ip, scans)
            }
            "-r" | "--rescan" => {
                let target = flag_value(
                    &mut it,
                    "-r needs an ip or hostname (args go in parentheses)",
                )?;
                if it.next().is_some() {
                    bail!("usage: hosts -r <ip|hostname> (nmap args in parentheses)");
                }
                let ip = crate::resolve_host(&self.db, &target)?;
                crate::rescan_host(w, &self.out, ip, paren.unwrap_or(""))
            }
            "-c" | "--compromised" => {
                let target = flag_value(&mut it, "-c needs an ip or hostname")?;
                let state = match it.next() {
                    None => None, // the write connection flips the mark
                    Some(s) => {
                        if it.next().is_some() {
                            bail!("usage: hosts -c <ip|hostname> [on|off]");
                        }
                        Some(s.clone())
                    }
                };
                let ip = crate::resolve_host(&self.db, &target)?;
                crate::set_flag(
                    w,
                    &self.out,
                    &ip.to_string(),
                    state.as_deref(),
                    crate::Flag::Pwned,
                )
            }
            "-ta" | "--tags-add" => {
                let (ip, tags) =
                    self.tags_target(&mut it, "-ta needs an ip/hostname then tags to add")?;
                crate::set_tags(w, &self.out, &ip, &tags, false)
            }
            "-td" | "--tag-del" => {
                let (ip, tags) =
                    self.tags_target(&mut it, "-td needs an ip/hostname then tags to remove")?;
                // set_tags reads `-tag` as a removal — the -td payload is
                // all removals by construction.
                let removals: Vec<String> = tags
                    .into_iter()
                    .map(|t| {
                        if t.starts_with('-') {
                            t
                        } else {
                            format!("-{t}")
                        }
                    })
                    .collect();
                crate::set_tags(w, &self.out, &ip, &removals, false)
            }
            "-n" | "--note" => {
                let target = flag_value(&mut it, "-n needs an ip or hostname (text after it)")?;
                let ip = crate::resolve_host(&self.db, &target)?;
                let rest: Vec<String> = it.cloned().collect();
                let text = (!rest.is_empty()).then(|| rest.join(" "));
                if text.as_deref() == Some("") {
                    bail!("an empty note clears nothing - use `-` to clear, or write text");
                }
                crate::set_note(w, &self.out, ip, text.as_deref())
            }
            "-e" | "--export" => {
                let mut hostnames = false;
                for a in it.by_ref() {
                    match a.as_str() {
                        "--hostnames" => hostnames = true,
                        "txt" => {}
                        other => bail!(
                            "hosts -e writes the txt host list - got {other:?} \
                             (--hostnames swaps in the names)"
                        ),
                    }
                }
                crate::render_hosts_txt(w, &self.out, hostnames)
            }
            "-i" | "--identity" => {
                let target = flag_value(&mut it, "-i needs an ip or hostname")?;
                if it.next().is_some() {
                    bail!("usage: hosts -i <ip|hostname>");
                }
                let ip = crate::resolve_host(&self.db, &target)?;
                crate::render_hosts(w, &self.out, Some(&ip.to_string()))
            }
            other => bail!(
                "unknown hosts command {other:?} - h shows the level: -s search, -S show, \
                 -r rescan, -c compromised, -ta/-td tags, -n note, -e export, -i identity"
            ),
        }
    }

    /// The shared head of `-ta`/`-td`: one target (ip or hostname,
    /// resolved) then the tag tokens as-is (set_tags normalizes).
    fn tags_target(
        &self,
        it: &mut std::slice::Iter<'_, String>,
        msg: &str,
    ) -> Result<(String, Vec<String>)> {
        let target = flag_value(it, msg)?;
        let ip = crate::resolve_host(&self.db, &target)?;
        let tags: Vec<String> = it.by_ref().cloned().collect();
        if tags.is_empty() {
            bail!("{msg}");
        }
        Ok((ip.to_string(), tags))
    }

    /// `services`: bare = every open service; `-p` ports, `-s` search,
    /// `-o` order, `-r` protocol, `--by name` groups, `-e` exports
    /// csv|xml|txt (`--hostnames` for the txt list).
    fn services_level(
        &self,
        w: &mut dyn std::io::Write,
        args: &[String],
        paren: Option<&str>,
    ) -> Result<()> {
        if paren.is_some() {
            bail!("the (…) payload is a `hosts -r` thing - services takes plain flags");
        }
        let mut spec: Option<String> = None;
        let mut searches: Vec<String> = Vec::new();
        let mut ports: Vec<String> = Vec::new();
        let mut order: Option<usize> = None;
        let mut protocol: Option<String> = None;
        let mut export: Option<String> = None;
        let mut hostnames = false;
        let mut by_name = false;
        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "-p" | "--port" => ports.push(flag_value(
                    &mut it,
                    "-p needs a port or list (22,80,1000-2000)",
                )?),
                "-s" | "--search" => {
                    searches.push(flag_value(&mut it, "-s needs a filter string")?)
                }
                "-o" | "--order" => {
                    let v = flag_value(
                        &mut it,
                        "-o needs a column number (1 host, 2 port, 3 proto, 4 name, 5 state, 6 info)",
                    )?;
                    order = Some(
                        v.parse()
                            .map_err(|_| anyhow!("-o needs a number, got {v:?}"))?,
                    );
                }
                "-r" | "--protocol" => {
                    protocol = Some(flag_value(&mut it, "-r needs a protocol (tcp)")?)
                }
                "-e" | "--export" => {
                    export = Some(flag_value(&mut it, "-e needs a format: csv, xml or txt")?)
                }
                "--hostnames" => hostnames = true,
                "--by" => match it.next().map(String::as_str) {
                    Some("name") => by_name = true,
                    other => bail!("--by knows `name` only (got {other:?})"),
                },
                s if s.starts_with('-') && s != "-" => bail!(
                    "unknown option {s:?} - services takes [spec], -p <ports>, -s <term>, \
                     -o <n>, -r tcp, --by name, -e csv|xml|txt"
                ),
                // one positional only — a second word is almost always a
                // typo, not a second filter
                s if spec.is_some() => bail!("one spec only (got extra {s:?})"),
                s => spec = Some(s.to_string()),
            }
        }
        if let Some(fmt) = export {
            if by_name {
                bail!("-e exports flat rows - --by groups the table view only");
            }
            if hostnames && fmt != "txt" {
                bail!("--hostnames belongs to `-e txt`");
            }
            let q = crate::svc_query(
                spec.as_deref(),
                order,
                &ports,
                protocol.as_deref(),
                &searches,
            )?;
            return match fmt.as_str() {
                "csv" => crate::render_services_csv(w, &self.out, &q),
                "xml" => crate::render_services_xml(w, &self.out, &q),
                "txt" => {
                    if order.is_some() {
                        bail!("-o orders the table - the txt export is one host per line");
                    }
                    crate::render_services_txt(w, &self.out, &q, hostnames)
                }
                other => bail!("export format {other:?} unknown - csv, xml or txt"),
            };
        }
        if hostnames {
            bail!("--hostnames belongs to `-e txt`");
        }
        let q = crate::svc_query(
            spec.as_deref(),
            order,
            &ports,
            protocol.as_deref(),
            &searches,
        )?;
        if by_name {
            self.services_by_name(w, &q)
        } else {
            crate::render_services(w, &self.out, &q)
        }
    }

    /// `services … --by name`: the same rows the column view would print
    /// (same filters), grouped under one header per service name.
    fn services_by_name(&self, w: &mut dyn std::io::Write, q: &crate::SvcQuery) -> Result<()> {
        let rows = crate::collect_services(&self.out, q)?;
        let mut groups: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        for r in &rows {
            let label = if r.name.is_empty() {
                "(unnamed)".to_string()
            } else {
                r.name.clone()
            };
            let version = if r.version.is_empty() {
                "-".to_string()
            } else {
                r.version.clone()
            };
            groups
                .entry(label)
                .or_default()
                .push(format!("  {}:{}\ttcp\topen\t{version}", r.ip, r.port));
        }
        let mut n = 0u64;
        for (name, rs) in &groups {
            writeln!(w, "{name} - {} row(s)", rs.len())?;
            for row in rs {
                writeln!(w, "{row}")?;
            }
            n += rs.len() as u64;
        }
        writeln!(
            w,
            "# {n} service row(s){} in {} group(s)",
            q.describe(),
            groups.len()
        )?;
        Ok(())
    }

    /// `db`: the stripped one-shot surface — bare or `stats` prints the
    /// registry's counts and run outcomes, `export` writes the complete
    /// nmap XML document. Everything else moved into the levels.
    fn db_level(
        &self,
        w: &mut dyn std::io::Write,
        args: &[String],
        paren: Option<&str>,
    ) -> Result<()> {
        if paren.is_some() {
            bail!("the (…) payload is a `hosts -r` thing - db takes stats and export only");
        }
        match args.first().map(String::as_str) {
            None => crate::render_status(w, &self.out),
            Some("stats") => {
                if args.len() != 1 {
                    bail!("usage: db stats");
                }
                crate::render_status(w, &self.out)
            }
            Some("export") => {
                if args.len() != 1 {
                    bail!("usage: db export (> file)");
                }
                crate::render_export_scanxml(w, &self.out)
            }
            Some(_) => bail!(
                "db keeps stats and export only - hosts, services and ranges live in their \
                 levels (h for help)"
            ),
        }
    }
}

// --------------------------------------------------------------- help

fn help(w: &mut dyn std::io::Write, level: Level) -> Result<()> {
    match level {
        Level::Top => writeln!(
            w,
            "levels: ranges, hosts, services, db - type one to enter it (its default view prints)
a payload rides along: `hosts -s web` enters hosts and searches

ranges   per-prefix buckets, one range's card, host list
hosts    search, one host's services + nmap evidence, rescan,
         pwned mark, tags, notes, identity card, host list
services every open service: ports, search, order, exports
db       registry stats and the complete nmap XML export"
        )?,
        Level::Ranges => writeln!(
            w,
            "ranges                     the /24 table: range, up, silent, open, top services
  -p 16                    bucket at another prefix (8, 16, 32)
  -s corp                  only buckets whose base matches the substring
  -S 10.30.4               one range's card: counts, top services, its hosts
  -e [--hostnames]         every up host, one per line (> file to save)"
        )?,
        Level::Hosts => writeln!(
            w,
            "hosts                      the up-host list
  -s web                   hosts whose ip or name matches (case-insensitive)
  -S <ip|host> [n]         services + the n newest nmap evidence blocks (1)
  -r <ip|host> (args)      rescan now; parentheses hold nmap args (the
                           port list rides in them, -p- for every port):
                           hosts -r 10.30.4.7 (-p 445 -sC) | (-p- -sV)
  -c <ip|host> [on|off]    toggle the pwned mark (state optional)
  -ta <ip|host> tag...     add tags   |  -td <ip|host> tag...  remove tags
  -n <ip|host> [text|-]    view the note; text writes it; - clears it
  -i <ip|host>             the identity card (names, marks, discovery, ports)
  -e [--hostnames]         every up host, one per line (> file to save)"
        )?,
        Level::Services => writeln!(
            w,
            "services                   every open service as aligned columns
  -p 22,80,1000-2000       only these ports (positional spec also works)
  -s ssh                   substring over host, service name and banner
  -o 2                     order by column (1 host 2 port 3 proto 4 name 5 state 6 info)
  -r tcp                   protocol filter (the registry records TCP only)
  --by name                same rows, grouped per service name
  -e csv|xml|txt           export the query (csv rows, nmap XML, host list;
                           --hostnames swaps the txt ips for names)"
        )?,
        Level::Db => writeln!(
            w,
            "db                         registry counts + every run's outcome
  stats                    the same card
  export                   ONE nmap XML document of the whole registry
                           (names + open ports; msfconsole db_import eats it)"
        )?,
    }
    writeln!(
        w,
        "
Every command takes `> path` to write its output to a file (paths inside
the perimeter are refused). Switch levels by name, `..` back, `q` quit,
`h` this help. The registry opens read-only; the console writes only your
marks, notes, rescans and the .db_history file."
    )?;
    Ok(())
}

// --------------------------------------------------------------- line parsing

#[derive(Debug, PartialEq, Eq)]
struct Invocation {
    verb: String,
    args: Vec<String>,
}

/// Guard for a `>` target: `File::create` truncates whatever is there, so
/// the registry's own files are refused — by name (a relative target typed
/// from inside the perimeter resolves there too) and by resolved location
/// (any path landing inside the perimeter tree).
fn redirect_allowed(target: &Path, out: &Path) -> Result<()> {
    if let Some(name) = target.file_name().and_then(|n| n.to_str()) {
        if matches!(name, "scandb.sqlite" | "run.lock") {
            bail!("\"{name}\" is registry plumbing - redirect elsewhere");
        }
    }
    let cwd = std::env::current_dir().unwrap_or_default();
    let abs = if target.is_absolute() {
        target.to_path_buf()
    } else {
        cwd.join(target)
    };
    let root = if out.is_absolute() {
        out.to_path_buf()
    } else {
        cwd.join(out)
    };
    let root = root.canonicalize().unwrap_or(root);
    // The target file usually does not exist yet — canonicalize its parent
    // (best effort) and reattach the file name for the containment check.
    let dir = abs
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| abs.clone());
    let dir = dir.canonicalize().unwrap_or(dir);
    let abs = dir.join(abs.file_name().unwrap_or_default());
    if abs.starts_with(&root) {
        bail!(
            "refusing to write inside the perimeter ({}) - redirect elsewhere",
            root.display()
        );
    }
    Ok(())
}

/// Split a trailing unquoted `> path` off the command line.
fn split_redirect(line: &str) -> Result<(&str, Option<PathBuf>)> {
    let mut in_quotes = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            '>' if !in_quotes => {
                let target = line[i + 1..].trim();
                if target.starts_with('>') {
                    bail!("append (>>) is not supported - one `> path` per command");
                }
                if target.is_empty() {
                    bail!("redirect needs a file: `> path`");
                }
                if target.contains('>') {
                    bail!("one redirect per command");
                }
                return Ok((&line[..i], Some(PathBuf::from(target.trim_matches('"')))));
            }
            _ => {}
        }
    }
    Ok((line, None))
}

/// Split a trailing unquoted `(...)` payload off the command line — the
/// `hosts -r` argument form, like the dashboard's scan box: the span
/// inside the outermost parens comes back as the payload, the rest of the
/// line as the command. Quote-aware, so `("a b")` keeps its spaces; an
/// unclosed paren is an error, not a silent prefix.
fn split_parens(line: &str) -> Result<(String, Option<String>)> {
    let mut in_quotes = false;
    let mut depth = 0usize;
    let mut start = 0usize;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            '(' if !in_quotes => {
                if depth == 0 {
                    start = i;
                }
                depth += 1;
            }
            ')' if !in_quotes => {
                if depth == 0 {
                    bail!("unbalanced ) - check the paren payload");
                }
                depth -= 1;
                if depth == 0 {
                    let payload = line[start + 1..i].trim().to_string();
                    let rest = format!("{}{}", &line[..start], &line[i + 1..]);
                    return Ok((rest.trim_end().to_string(), Some(payload)));
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        bail!("unclosed ( - the payload needs its closing paren");
    }
    Ok((line.to_string(), None))
}

/// Whitespace split honoring double quotes — nmap-style targets and service
/// versions with spaces come through as one argument.
fn parse_line(line: &str) -> Result<Invocation> {
    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut any = false;
    for c in line.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                any = true; // "" still delimits an (empty) token
            }
            c if !in_quotes && c.is_whitespace() => {
                if any {
                    tokens.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if in_quotes {
        bail!("unbalanced quote");
    }
    if any {
        tokens.push(cur);
    }
    let mut it = tokens.into_iter();
    let verb = it.next().unwrap_or_default();
    Ok(Invocation {
        verb: verb.to_lowercase(),
        args: it.collect(),
    })
}

/// The value of a console flag (`-p 22`): the next token, or a usage error
/// naming the flag.
fn flag_value(it: &mut std::slice::Iter<'_, String>, msg: &str) -> Result<String> {
    it.next().cloned().ok_or_else(|| anyhow!("{msg}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn parse(s: &str) -> Result<Invocation> {
        parse_line(s)
    }

    #[test]
    fn parser_splits_quotes_and_words() {
        assert_eq!(
            parse("hosts -S 127.0.0.5").unwrap(),
            Invocation {
                verb: "hosts".into(),
                args: vec!["-S".into(), "127.0.0.5".into()]
            }
        );
        assert_eq!(
            parse("services -s \"apache 2.4\"").unwrap(),
            Invocation {
                verb: "services".into(),
                args: vec!["-s".into(), "apache 2.4".into()]
            }
        );
        // extra whitespace collapses; case of the verb folds
        assert_eq!(
            parse("   SERVICES   ").unwrap(),
            Invocation {
                verb: "services".into(),
                args: vec![]
            }
        );
        // unbalanced quote is an error, not a silent token
        assert!(parse("services -s \"oops").is_err());
        assert_eq!(parse("").unwrap().verb, "");
    }

    #[test]
    fn redirect_splits_at_the_last_word() {
        let (cmd, red) = split_redirect("services -e csv > /tmp/x.csv").unwrap();
        assert_eq!(cmd, "services -e csv ");
        assert_eq!(red, Some(PathBuf::from("/tmp/x.csv")));
        // quoted path with spaces
        let (cmd, red) = split_redirect("db export > \"my out.xml\"").unwrap();
        assert_eq!(cmd, "db export ");
        assert_eq!(red, Some(PathBuf::from("my out.xml")));
        // a > inside quotes is not a redirect
        let (cmd, red) = split_redirect("services -s \"a>b\"").unwrap();
        assert_eq!(cmd, "services -s \"a>b\"");
        assert!(red.is_none());
        // a bare > with no target is an error
        assert!(split_redirect("services -e csv >").is_err());
        // no redirect at all
        assert!(split_redirect("hosts").unwrap().1.is_none());
    }

    #[test]
    fn parens_split_off_the_payload() {
        let (cmd, p) = split_parens("hosts -r 10.30.4.7 (-p- -sC)").unwrap();
        assert_eq!(cmd, "hosts -r 10.30.4.7");
        assert_eq!(p.as_deref(), Some("-p- -sC"));
        // nmap args with quotes and spaces survive
        let (cmd, p) = split_parens("hosts -r web01 (-sC -sV -p \"445 1433\")").unwrap();
        assert_eq!(cmd, "hosts -r web01");
        assert_eq!(p.as_deref(), Some("-sC -sV -p \"445 1433\""));
        // no parens, no payload
        assert!(split_parens("hosts -s web").unwrap().1.is_none());
        // unclosed paren is an error
        assert!(split_parens("hosts -r web01 (-p-").is_err());
        // a stray closer is an error
        assert!(split_parens("hosts -r web01 )").is_err());
        // parens inside quotes are not a payload
        let (cmd, p) = split_parens("services -s \"ssh (open)\"").unwrap();
        assert_eq!(cmd, "services -s \"ssh (open)\"");
        assert!(p.is_none());
    }

    #[test]
    fn levels_switch_by_name() {
        assert_eq!(Level::of("ranges"), Some(Level::Ranges));
        assert_eq!(Level::of("services"), Some(Level::Services));
        assert_eq!(Level::of("db"), Some(Level::Db));
        assert_eq!(Level::of("export"), None);
    }

    fn temp_perim(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rustrawl-console-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A tiny registry: 127.0.0.5 (ssh 22, http 80) and 127.0.0.7 (ssh 22),
    /// all up in the scan stage.
    fn seeded_perim(tag: &str) -> PathBuf {
        use crate::discovery::db::{Answer, Stage};
        let out = temp_perim(tag);
        let mut db = Db::open(&out).unwrap();
        db.set_run_id("discovery_test");
        for ip in ["127.0.0.5", "127.0.0.7"] {
            let ip: Ipv4Addr = ip.parse().unwrap();
            db.record_host(ip, Stage::Scan, true, 2);
            db.record_result(ip, 22, Stage::Scan, Answer::Open);
            db.record_service(ip, 22, "ssh", "OpenSSH 9.2p1");
        }
        let ip5: Ipv4Addr = "127.0.0.5".parse().unwrap();
        db.record_result(ip5, 80, Stage::Scan, Answer::Open);
        db.record_service(ip5, 80, "http", "nginx 1.22.1");
        db.record_name(ip5, "web05.corp.example.com", "dns-ptr");
        db.flush().unwrap();
        out
    }

    fn con(out: &Path) -> Console {
        Console {
            out: out.to_path_buf(),
            db: Db::open_read_only(out).unwrap(),
            level: Level::Top,
        }
    }

    /// exec one line, return what it printed (lossy) and whether the
    /// session stays alive.
    fn run_line(c: &mut Console, line: &str) -> (String, bool) {
        let mut buf: Vec<u8> = Vec::new();
        let alive = c.exec(&mut buf, line).unwrap();
        (String::from_utf8_lossy(&buf).into_owned(), alive)
    }

    #[test]
    fn level_switch_default_view_and_quit() {
        let out = seeded_perim("levels");
        let mut c = con(&out);

        // the top refuses junk and names the levels
        let (text, alive) = run_line(&mut c, "nonsense");
        assert!(alive);
        assert!(text.contains("unknown command"), "{text}");
        assert!(text.contains("ranges, hosts, services, db"), "{text}");

        // switch by name: the default view prints (bare services = all)
        let (text, alive) = run_line(&mut c, "services");
        assert!(alive && c.level == Level::Services, "{text}");
        assert!(text.contains("service row(s)"), "{text}");
        assert!(text.contains("OpenSSH"), "{text}");

        // the level answers its flags without repeating the level name
        let (text, alive) = run_line(&mut c, "-p 80");
        assert!(alive);
        assert!(text.contains("127.0.0.5"), "{text}");
        assert!(!text.contains("OpenSSH"), "{text}");

        // `..` climbs back, a level name with a payload runs it there
        let (text, alive) = run_line(&mut c, "..");
        assert!(alive && c.level == Level::Top);
        assert!(text.contains("top level"), "{text}");
        let (text, alive) = run_line(&mut c, "services -p 22");
        assert!(alive && c.level == Level::Services);
        assert!(text.contains("OpenSSH"), "{text}");

        // a word inside a level is that level's input (here a services
        // spec matching nothing), the session lives
        let (text, alive) = run_line(&mut c, "frobnicate");
        assert!(alive);
        assert!(
            text.contains("# 0 service row(s) matching \"frobnicate\""),
            "{text}"
        );

        // q quits from anywhere
        let (_, alive) = run_line(&mut c, "q");
        assert!(!alive);
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn hosts_level_search_show_note_and_pwned() {
        let out = seeded_perim("hostslevel");
        let mut c = con(&out);

        // -s matches the hostname, case-insensitive
        let (text, alive) = run_line(&mut c, "hosts -s WEB05");
        assert!(alive);
        assert!(text.contains("127.0.0.5"), "{text}");
        assert!(text.ends_with("# 1 host(s) matching \"WEB05\"\n"), "{text}");

        // -S by hostname: services table + the no-evidence fallback
        let (text, alive) = run_line(&mut c, "hosts -S web05");
        assert!(alive);
        assert!(text.contains("port  name  version"), "{text}");
        assert!(text.contains("no scan run on this perimeter yet"), "{text}");

        // -n writes, then views
        let (text, alive) = run_line(&mut c, "hosts -n 127.0.0.5 got the creds");
        assert!(alive);
        assert!(text.contains("# note 127.0.0.5: got the creds"), "{text}");
        let (text, alive) = run_line(&mut c, "hosts -n 127.0.0.5");
        assert!(alive);
        assert!(text.contains("# note 127.0.0.5: got the creds"), "{text}");

        // -c toggles the pwned mark, then unmarks
        let (text, alive) = run_line(&mut c, "hosts -c 127.0.0.5");
        assert!(alive);
        assert!(text.contains("# pwned 127.0.0.5: on"), "{text}");
        let (text, alive) = run_line(&mut c, "hosts -c 127.0.0.5");
        assert!(alive);
        assert!(text.contains("# pwned 127.0.0.5: off"), "{text}");

        // -ta/-td add and remove tags
        let (text, alive) = run_line(&mut c, "hosts -ta 127.0.0.5 dc adcs");
        assert!(alive);
        assert!(text.contains("# tags 127.0.0.5"), "{text}");
        let (text, alive) = run_line(&mut c, "hosts -td 127.0.0.5 adcs");
        assert!(alive);
        assert!(text.contains("#dc"), "{text}");

        // -i prints the identity card with the names block
        let (text, alive) = run_line(&mut c, "hosts -i 127.0.0.5");
        assert!(alive);
        assert!(text.contains("  name\tweb05.corp.example.com"), "{text}");

        // unknown flag names the level's commands
        let (text, alive) = run_line(&mut c, "hosts -z");
        assert!(alive);
        assert!(text.contains("unknown hosts command"), "{text}");
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn hosts_level_guards_paren_payload_and_rescan_targets() {
        let out = seeded_perim("hostsguard");
        let mut c = con(&out);

        // The paren payload is a -r thing: every other hosts verb refuses
        // it instead of silently dropping it.
        for line in [
            "hosts (top1000)",
            "hosts -s web (x)",
            "hosts -c 127.0.0.5 (on)",
        ] {
            let (text, alive) = run_line(&mut c, line);
            assert!(alive);
            assert!(
                text.contains("the (…) payload is a `hosts -r` thing"),
                "{line}: {text}"
            );
        }

        // A rescan payload holds nmap args — never a second scan target:
        // the registry picks the host, dotted tokens are refused.
        let (text, alive) = run_line(&mut c, "hosts -r 127.0.0.5 (10.9.9.9)");
        assert!(alive);
        assert!(text.contains("target list is rustrawl's"), "{text}");
        // -p is the operator's now: a pure-args payload passes the frame
        // checks and reaches the registry gate (the seeded registry keeps
        // its hosts in the scan stage, so the rescan stops at "not an up
        // host" — the point is the payload was accepted, not refused).
        let (text, alive) = run_line(&mut c, "hosts -r 127.0.0.5 (-sC -sV -p 445)");
        assert!(alive);
        assert!(
            !text.contains("rustrawl's"),
            "the port list is accepted: {text}"
        );
        assert!(text.contains("not an up host"), "{text}");
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn services_level_exports_use_the_query() {
        let out = seeded_perim("svclevel");
        let mut c = con(&out);

        let (text, alive) = run_line(&mut c, "services -e csv");
        assert!(alive);
        assert!(
            text.starts_with("ip,port,proto,service,version,last_seen,run\n"),
            "{text}"
        );
        assert!(
            text.contains("127.0.0.5,80,tcp,http,nginx 1.22.1,"),
            "{text}"
        );

        // the query filters carry into the export
        let (text, alive) = run_line(&mut c, "services -p 22 -e txt");
        assert!(alive);
        assert_eq!(text, "127.0.0.5\n127.0.0.7\n");

        // xml comes out nmap-shaped
        let (text, alive) = run_line(&mut c, "services -e xml");
        assert!(alive);
        assert!(text.contains("<nmaprun scanner=\"nmap\""), "{text}");

        // an unknown format is refused with the choices
        let (text, alive) = run_line(&mut c, "services -e yaml");
        assert!(alive);
        assert!(text.contains("csv, xml or txt"), "{text}");
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn db_level_keeps_stats_and_export_only() {
        let out = seeded_perim("dblevel");
        let mut c = con(&out);

        // bare db = stats
        let (text, alive) = run_line(&mut c, "db");
        assert!(alive && c.level == Level::Db);
        assert!(text.contains("hosts up"), "{text}");

        let (text, alive) = run_line(&mut c, "db export");
        assert!(alive);
        assert!(text.contains("<nmaprun scanner=\"nmap\""), "{text}");
        assert!(text.contains("</nmaprun>"), "{text}");

        // the retired verbs say where they went
        let (text, alive) = run_line(&mut c, "db triage");
        assert!(alive);
        assert!(text.contains("stats and export"), "{text}");
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn ranges_level_table_search_and_card() {
        let out = seeded_perim("rangeslevel");
        let mut c = con(&out);

        let (text, alive) = run_line(&mut c, "ranges");
        assert!(alive);
        assert!(
            text.starts_with("range\tup\tsilent\topen\ttop services"),
            "{text}"
        );
        assert!(text.contains("127.0.0.0/24"), "{text}");

        let (text, alive) = run_line(&mut c, "ranges -S 127.0.0.5");
        assert!(alive);
        assert!(text.starts_with("range: 127.0.0.0/24"), "{text}");
        assert!(text.contains("top services:"), "{text}");

        // a search that matches nothing still renders (an empty table)
        let (text, alive) = run_line(&mut c, "ranges -s 10.99.");
        assert!(alive);
        assert!(text.contains("# 0 bucket(s)"), "{text}");
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn help_and_up_work_at_every_level() {
        let out = seeded_perim("helplevel");
        let mut c = con(&out);
        let (text, alive) = run_line(&mut c, "h");
        assert!(alive);
        assert!(
            text.contains("levels: ranges, hosts, services, db"),
            "{text}"
        );
        let (_, alive) = run_line(&mut c, "hosts");
        assert!(alive);
        let (text, alive) = run_line(&mut c, "?");
        assert!(alive);
        assert!(text.contains("-r <ip|host>"), "{text}");
        // `..` climbs home, a second one says it is already there
        let (text, alive) = run_line(&mut c, "..");
        assert!(alive && c.level == Level::Top);
        assert!(text.contains("top level"), "{text}");
        let (text, alive) = run_line(&mut c, "..");
        assert!(alive && c.level == Level::Top);
        assert!(text.contains("already at the top"), "{text}");
        let (_, alive) = run_line(&mut c, "services");
        assert!(alive && c.level == Level::Services);
        let (text, alive) = run_line(&mut c, "..");
        assert!(alive && c.level == Level::Top);
        assert!(text.contains("top level"), "{text}");
        std::fs::remove_dir_all(&out).ok();
    }
}
