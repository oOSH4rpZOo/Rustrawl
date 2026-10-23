//! Single-line-pair interactive status for long stages: a progress bar and a
//! stats line, redrawn in place with ANSI carriage returns so normal event
//! lines keep landing in the scrollback above (ssh/tmux/tee friendly — no
//! full-screen mode). The scan adds a live chunk view: `n` cycles the block
//! between the overview and the running chunks' captured nmap output, so the
//! operator can watch a chunk work and come back. Block height varies with
//! the view (overview 2–3 lines, chunk view ~12); the renderer tracks what
//! it drew and clears exactly that. Keys come from a stdin poll loop in raw
//! mode: `p` pause/resume, `s` skip a cooldown pause (operator judges the
//! stretch empty), `k`/`x` kill the oldest running scan chunk (requeue it,
//! or leave it unscanned for the stats), `n` cycle the scan chunk view,
//! `q` graceful stop (same path as ^C).
//!
//! Without a TTY on stdout (pipe, CI, `tee`) nothing changes: events print as
//! plain stderr lines and the counters just sit unused. Termios state is
//! always restored — reference-counted across the stages of one process, and
//! every drop path (error, panic unwind, graceful interrupt) goes through it.

use std::io::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::util::fmt_count;

// ---- process-global key state (one key reader for the whole process) ----

static KEY_PAUSE: AtomicBool = AtomicBool::new(false);
static KEY_SKIP: AtomicBool = AtomicBool::new(false);
/// `k`: kill the oldest running scan chunk(s) and put them back in the
/// queue — a counter, so rapid presses inside one 200 ms poll window each
/// land (a plain boolean would silently coalesce them).
static KEY_KILL_REDO: AtomicU32 = AtomicU32::new(0);
/// `x`: kill the oldest running scan chunk(s), leave them unscanned (stats
/// show them; the next `scan --resume` requeues them). Counter, same reason.
static KEY_KILL_SKIP: AtomicU32 = AtomicU32::new(0);
/// `n`: cycle the scan block between the overview and the running chunks'
/// captured nmap output. Consumed by the renderer at draw time; presses
/// inside one redraw window coalesce (view cycling, unlike kills, loses
/// nothing by coalescing).
static KEY_VIEW: AtomicU32 = AtomicU32::new(0);
/// Reference count of live rendering screens; raw mode is held while > 0.
static SCREENS: AtomicUsize = AtomicUsize::new(0);
static SAVED_TERMIOS: Mutex<Option<libc::termios>> = Mutex::new(None);

/// True while the operator paused the run (`p`).
pub fn paused() -> bool {
    KEY_PAUSE.load(Ordering::Relaxed)
}

/// Consumes pending `s` (cooldown skip) requests.
pub fn take_skip() -> bool {
    KEY_SKIP.swap(false, Ordering::Relaxed)
}

/// Consumes pending `k` presses: how many oldest chunks to kill + requeue.
pub fn take_kill_redo() -> u32 {
    KEY_KILL_REDO.swap(0, Ordering::Relaxed)
}

/// Consumes pending `x` presses: how many oldest chunks to kill + skip.
pub fn take_kill_skip() -> u32 {
    KEY_KILL_SKIP.swap(0, Ordering::Relaxed)
}

fn keys_thread_once() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let _ = std::thread::Builder::new()
            .name("tui-keys".into())
            .spawn(|| {
                let mut pfd = libc::pollfd {
                    fd: 0,
                    events: libc::POLLIN,
                    revents: 0,
                };
                loop {
                    let rc = unsafe { libc::poll(&mut pfd, 1, 150) };
                    if rc <= 0 {
                        continue; // timeout or interrupted poll
                    }
                    let mut b = [0u8; 1];
                    // SAFETY: read of one byte from the (opened) stdin fd.
                    let n = unsafe { libc::read(0, b.as_mut_ptr() as *mut libc::c_void, 1) };
                    if n == 0 {
                        // EOF (stdin closed, /dev/null, dead pipe): no key can
                        // ever arrive again — park this thread instead of
                        // busy-spinning on the always-ready poll.
                        return;
                    }
                    if n < 0 {
                        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
                        {
                            return; // fd gone (POLLNVAL) — same as EOF
                        }
                        continue;
                    }
                    match b[0] {
                        b'p' | b'P' => {
                            KEY_PAUSE.store(!KEY_PAUSE.load(Ordering::Relaxed), Ordering::Relaxed)
                        }
                        b's' | b'S' => KEY_SKIP.store(true, Ordering::Relaxed),
                        b'k' | b'K' => {
                            KEY_KILL_REDO.fetch_add(1, Ordering::Relaxed);
                        }
                        b'x' | b'X' => {
                            KEY_KILL_SKIP.fetch_add(1, Ordering::Relaxed);
                        }
                        b'n' | b'N' => {
                            KEY_VIEW.fetch_add(1, Ordering::Relaxed);
                        }
                        // q exits through the very same flag ^C sets — the
                        // graceful wind-down (state saved, resumable) is shared.
                        b'q' | b'Q' => crate::discovery::ABORT.store(true, Ordering::Relaxed),
                        _ => {}
                    }
                }
            });
    });
}

fn enable_raw() {
    let mut saved = SAVED_TERMIOS.lock().unwrap_or_else(|e| e.into_inner());
    if saved.is_some() {
        return; // already raw
    }
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: tcgetattr on the opened stdin fd with a valid buffer.
    if unsafe { libc::tcgetattr(0, &mut t) } != 0 {
        return; // not a real tty (race with redirected input) — stay plain
    }
    *saved = Some(t);
    // ICANON off = keys arrive without Enter; ECHO off = keys stay invisible.
    // ISIG stays on so ^C keeps working as before.
    t.c_lflag &= !(libc::ICANON | libc::ECHO);
    // SAFETY: tcsetattr with the modified copy.
    unsafe { libc::tcsetattr(0, libc::TCSADRAIN, &t) };
}

fn restore_raw() {
    let mut saved = SAVED_TERMIOS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(t) = saved.take() {
        // SAFETY: tcsetattr with a previously read termios.
        unsafe { libc::tcsetattr(0, libc::TCSADRAIN, &t) };
    }
}

fn stdout_is_tty() -> bool {
    // SAFETY: isatty on the opened stdout fd.
    unsafe { libc::isatty(1) == 1 }
}

/// The counters one stage feeds; the renderer formats them. Cheap atomic
/// stores on the hot path, one 200 ms reader.
pub struct Status {
    total: AtomicU64,
    done: AtomicU64,
    up: AtomicU64,
    mute: AtomicU64,
    unroutable: AtomicU64,
    /// Scan-only: chunks killed from the keyboard and not requeued — the
    /// runs that did not happen, reported in the stats.
    skipped: AtomicU64,
    /// Free-form footer text from the engine (answers per port, …).
    extra: Mutex<String>,
}

impl Status {
    fn new(total: u64) -> Self {
        Self {
            total: AtomicU64::new(total),
            done: AtomicU64::new(0),
            up: AtomicU64::new(0),
            mute: AtomicU64::new(0),
            unroutable: AtomicU64::new(0),
            skipped: AtomicU64::new(0),
            extra: Mutex::new(String::new()),
        }
    }

    pub fn set_done(&self, n: u64) {
        self.done.store(n, Ordering::Relaxed);
    }

    pub fn set_up(&self, n: u64) {
        self.up.store(n, Ordering::Relaxed);
    }

    pub fn set_mute(&self, n: u64) {
        self.mute.store(n, Ordering::Relaxed);
    }

    pub fn set_unroutable(&self, n: u64) {
        self.unroutable.store(n, Ordering::Relaxed);
    }

    pub fn set_skipped(&self, n: u64) {
        self.skipped.store(n, Ordering::Relaxed);
    }

    pub fn set_extra(&self, text: String) {
        *self.extra.lock().unwrap_or_else(|e| e.into_inner()) = text;
    }

    /// Blocks while the operator paused the run (`p`), without losing the
    /// graceful-stop path: ^C / `q` end the pause immediately.
    pub fn wait_while_paused(&self) {
        while KEY_PAUSE.load(Ordering::Relaxed) && !crate::discovery::ABORT.load(Ordering::Relaxed)
        {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

// ---- renderer: one global, owned by whichever screen is live ----

/// Which block the renderer paints: the stage overview, or the captured
/// nmap output of one running scan chunk (`n` cycles).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum View {
    #[default]
    Overview,
    /// Position in the running-chunks snapshot (see [`set_chunks`]).
    Chunk(usize),
}

/// `n` steps this forward, wrapping through the overview.
fn advance_view(view: View, steps: u32, n: usize) -> View {
    let mut v = view;
    for _ in 0..steps {
        v = match (v, n) {
            (View::Overview, m) if m > 0 => View::Chunk(0),
            (View::Chunk(i), m) if i + 1 < m => View::Chunk(i + 1),
            _ => View::Overview,
        };
    }
    v
}

/// A `Chunk(i)` position that no longer exists (the chunk finished or was
/// killed between ticks) falls back to the overview.
fn resolve_view(view: View, n: usize) -> View {
    match view {
        View::Chunk(i) if i >= n => View::Overview,
        v => v,
    }
}

/// One running scan chunk as the renderer draws it — the scan loop
/// refreshes the snapshot every tick from the chunk's captured output.
#[derive(Debug, Clone)]
pub struct ChunkViz {
    pub idx: usize,
    /// The scan group this chunk runs under (a profile's range, or
    /// `default`) — empty when no profile table drives the queue.
    pub profile: String,
    /// Hosts nmap has reported so far ("Nmap scan report for" lines).
    pub hosts_done: usize,
    pub hosts_total: usize,
    /// Last [`TAIL_LINES`] lines of the captured output, oldest first.
    pub tail: Vec<String>,
}

/// Tail lines shown in a chunk view.
pub const TAIL_LINES: usize = 10;

/// Replaces the running-chunk snapshot the renderer draws (scan loop, once
/// per tick). The operator's position survives the update; a position past
/// the new end falls back to the overview at draw time.
pub fn set_chunks(v: Vec<ChunkViz>) {
    *render().chunks.lock().unwrap_or_else(|e| e.into_inner()) = v;
}

struct Out {
    /// Rows the block currently occupies (0 = nothing drawn — replacing the
    /// old boolean, the block is variable-height since the chunk views).
    lines: usize,
    view: View,
    /// Renderer-window probe rate (EMA) and its last sample.
    rate: f64,
    sample: Option<(u64, Instant)>,
}

struct Render {
    out: Mutex<Out>,
    status: Mutex<Option<Arc<Status>>>,
    header: Mutex<(String, Footer)>,
    chunks: Mutex<Vec<ChunkViz>>,
}

/// Which stats line the footer carries — the sweep counts open answers per
/// port, the scan counts nmap chunks and open ports found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Footer {
    Discovery,
    Scan,
}

static RENDER: OnceLock<Render> = OnceLock::new();

fn render() -> &'static Render {
    RENDER.get_or_init(|| Render {
        out: Mutex::new(Out {
            lines: 0,
            view: View::Overview,
            rate: 0.0,
            sample: None,
        }),
        status: Mutex::new(None),
        header: Mutex::new((String::new(), Footer::Discovery)),
        chunks: Mutex::new(Vec::new()),
    })
}

fn fmt_eta(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m}:{s:02}")
    }
}

fn bar(done: u64, total: u64, width: usize) -> String {
    if total == 0 {
        return "░".repeat(width);
    }
    let filled = ((done.min(total) as f64 / total as f64) * width as f64).round() as usize;
    format!(
        "[{}{}]",
        "█".repeat(filled),
        "░".repeat(width - filled.min(width))
    )
}

/// The block the renderer paints for `view` — pure so heights and the view
/// cycling stay unit-testable (no ANSI here; [`draw`] does the moving).
#[allow(clippy::too_many_arguments)] // one flat snapshot of the stage state
fn block_lines(
    view: View,
    paused: bool,
    label: &str,
    status: &Status,
    rate_s: &str,
    eta_s: &str,
    footer: Footer,
    chunks: &[ChunkViz],
) -> Vec<String> {
    let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
    let total = load(&status.total);
    let done = load(&status.done);
    let up = load(&status.up);
    let mute = load(&status.mute);
    let unroutable = load(&status.unroutable);
    let skipped = load(&status.skipped);
    let extra = status
        .extra
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let paused_mark = if paused { "PAUSED (p resumes) · " } else { "" };
    let sep = if extra.is_empty() { "" } else { " · " };
    // `n` cycles the view; the hint says where it goes next.
    let view_hint = if matches!(resolve_view(view, chunks.len()), View::Chunk(_)) {
        "[n] overview"
    } else {
        "[n] view"
    };
    let footer_line = match footer {
        Footer::Discovery => format!(
            "up {} · mute {} · unreachable {}{sep}{extra} · [p]ause [s]kip cooldown [q]uit",
            fmt_count(up),
            fmt_count(mute),
            fmt_count(unroutable),
        ),
        // Scan controls: p pauses the dispatch (running nmaps finish), k
        // kills the oldest running chunk and requeues it, x kills it and
        // leaves it unscanned (reported at the end, requeued by --resume).
        Footer::Scan => format!(
            "chunks {} · running {} · skipped {} · open ports {}{sep}{extra} · [p]ause [k]ill+requeue [x]kill {view_hint} [q]uit",
            fmt_count(done),
            fmt_count(mute),
            fmt_count(skipped),
            fmt_count(up),
        ),
    };
    match resolve_view(view, chunks.len()) {
        View::Chunk(i) => {
            let Some(c) = chunks.get(i) else {
                unreachable!("resolve_view guarantees a live chunk position");
            };
            let mut lines = Vec::with_capacity(c.tail.len() + 2);
            let group = if c.profile.is_empty() {
                String::new()
            } else {
                format!(" · {}", c.profile)
            };
            lines.push(format!(
                "{paused_mark}chunk {:04}{group} · {}/{} hosts reported · nmap output",
                c.idx, c.hosts_done, c.hosts_total
            ));
            lines.extend(c.tail.iter().cloned());
            lines.push(footer_line);
            lines
        }
        View::Overview => {
            let bar_s = bar(done, total, 20);
            let pct = (done.min(total) * 100).checked_div(total).unwrap_or(0);
            let mut lines = Vec::with_capacity(3);
            lines.push(format!(
                "{paused_mark}{label} {bar_s} {pct}% · {}/{} · {rate_s}{eta_s}",
                fmt_count(done),
                fmt_count(total),
            ));
            // Live per-chunk progress — the operator sees nmap working
            // between chunk completions, which whole-chunk counting hides.
            if footer == Footer::Scan && !chunks.is_empty() {
                lines.push(
                    chunks
                        .iter()
                        .map(|c| {
                            if c.profile.is_empty() {
                                format!("chunk-{:04} {}/{}", c.idx, c.hosts_done, c.hosts_total)
                            } else {
                                format!(
                                    "chunk-{:04} ({}) {}/{}",
                                    c.idx, c.profile, c.hosts_done, c.hosts_total
                                )
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(" · "),
                );
            }
            lines.push(footer_line);
            lines
        }
    }
}

fn draw() {
    let Some(status) = render()
        .status
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
    else {
        return;
    };
    let chunks = render()
        .chunks
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    // View cycling + rate/ETA share the renderer-window state.
    let (rate, eta, view) = {
        let mut out = render().out.lock().unwrap_or_else(|e| e.into_inner());
        let view = {
            let advanced =
                advance_view(out.view, KEY_VIEW.swap(0, Ordering::Relaxed), chunks.len());
            out.view = resolve_view(advanced, chunks.len());
            out.view
        };
        let done = status.done.load(Ordering::Relaxed);
        let now = Instant::now();
        let (rate, eta) = {
            let prev = out.sample.replace((done, now));
            match prev {
                Some((pd, pt)) => {
                    let dt = now.duration_since(pt).as_secs_f64();
                    let inst = if dt > 0.2 {
                        (done.saturating_sub(pd)) as f64 / dt
                    } else {
                        0.0
                    };
                    let total = status.total.load(Ordering::Relaxed);
                    let rate = if out.rate == 0.0 {
                        inst
                    } else {
                        out.rate * 0.7 + inst * 0.3
                    };
                    let eta = if rate > 1.0 && done < total {
                        Some(fmt_eta(((total - done) as f64 / rate) as u64))
                    } else {
                        None
                    };
                    (rate, eta)
                }
                None => (0.0, None),
            }
        };
        out.rate = rate;
        (rate, eta, view)
    };

    let paused = KEY_PAUSE.load(Ordering::Relaxed);
    let rate_s = if rate >= 1000.0 {
        format!("{:.1}k/s", rate / 1000.0)
    } else {
        format!("{rate:.0}/s")
    };
    let eta_s = eta.map(|e| format!(" · eta {e}")).unwrap_or_default();
    let (label, footer) = render()
        .header
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let block = block_lines(
        view, paused, &label, &status, &rate_s, &eta_s, footer, &chunks,
    );

    let mut out = render().out.lock().unwrap_or_else(|e| e.into_inner());
    let stdout = std::io::stdout();
    let mut w = stdout.lock();
    if out.lines > 1 {
        let _ = write!(w, "\r\x1b[{}A", out.lines - 1);
    }
    for (i, line) in block.iter().enumerate() {
        if i > 0 {
            let _ = writeln!(w);
        }
        let _ = write!(w, "\r\x1b[2K{line}");
    }
    if block.len() < out.lines {
        // erase the rows a shrunken block vacated — nothing is ever drawn
        // below the block, so erase-to-end-of-screen is exact
        let _ = write!(w, "\x1b[J");
    }
    let _ = w.flush();
    out.lines = block.len();
}

/// Clears the drawn block row by row, ending with the cursor on the block's
/// former top row. Shared by [`event`] (an event line lands where the block
/// was) and [`Screen::drop`].
fn clear_rows(w: &mut impl std::io::Write, l: usize) {
    if l > 1 {
        let _ = write!(w, "\r\x1b[{}A", l - 1);
    }
    for i in 0..l {
        let _ = write!(w, "\r\x1b[2K");
        if i + 1 < l {
            let _ = write!(w, "\x1b[1B");
        }
    }
    if l > 1 {
        let _ = write!(w, "\x1b[{}A", l - 1);
    }
}

fn clear_block() {
    let mut out = render().out.lock().unwrap_or_else(|e| e.into_inner());
    if out.lines == 0 {
        return;
    }
    let stdout = std::io::stdout();
    let mut w = stdout.lock();
    clear_rows(&mut w, out.lines);
    let _ = w.flush();
    out.lines = 0;
    out.rate = 0.0;
    out.sample = None;
}

/// An interactive screen for one stage run. Create it right before the loop,
/// let the engine push counters into [`Screen::status`], drop it before the
/// final summary lines. Inert (and free) without a TTY.
pub struct Screen {
    status: Arc<Status>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    rendered: bool,
}

impl Screen {
    /// Starts the renderer over `total` units of work, headed by `label` and
    /// carrying the `footer` stats line. Event lines keep printing above the
    /// bar.
    pub fn start(label: &str, total: u64, footer: Footer) -> Self {
        let status = Arc::new(Status::new(total));
        if !stdout_is_tty() {
            // No interactive terminal: counters exist but nobody renders them,
            // and stdin stays cooked — plain-line output only.
            return Self {
                status,
                stop: Arc::new(AtomicBool::new(false)),
                handle: None,
                rendered: false,
            };
        }
        keys_thread_once();
        enable_raw();
        // A new stage starts with a clean slate: a `p` (or `k`/`x`/`s`/`n`)
        // pressed during the previous stage.s tail must not leak into this
        // one — the flags are process-global and stages chain in one process.
        KEY_PAUSE.store(false, Ordering::Relaxed);
        KEY_SKIP.store(false, Ordering::Relaxed);
        KEY_KILL_REDO.store(0, Ordering::Relaxed);
        KEY_KILL_SKIP.store(0, Ordering::Relaxed);
        KEY_VIEW.store(0, Ordering::Relaxed);
        SCREENS.fetch_add(1, Ordering::Relaxed);
        *render().status.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&status));
        *render().header.lock().unwrap_or_else(|e| e.into_inner()) = (label.to_string(), footer);
        {
            let mut o = render().out.lock().unwrap_or_else(|e| e.into_inner());
            o.lines = 0;
            o.view = View::Overview;
        }
        render()
            .chunks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_t = Arc::clone(&stop);
        let handle = std::thread::Builder::new()
            .name("tui-render".into())
            .spawn(move || {
                while !stop_t.load(Ordering::Relaxed) {
                    draw();
                    std::thread::sleep(Duration::from_millis(200));
                }
            })
            .expect("spawning the renderer");
        Self {
            status,
            stop,
            handle: Some(handle),
            rendered: true,
        }
    }

    /// The counters this stage.s engine feeds.
    pub fn status(&self) -> &Arc<Status> {
        &self.status
    }

    /// Whether this screen actually renders (a TTY is on stdout) — the scan
    /// loop skips its per-tick chunk-viz reads otherwise.
    pub fn is_live(&self) -> bool {
        self.rendered
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        if self.rendered {
            *render().status.lock().unwrap_or_else(|e| e.into_inner()) = None;
            render()
                .chunks
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            clear_block();
            if SCREENS.fetch_sub(1, Ordering::Relaxed) == 1 {
                restore_raw();
            }
        }
    }
}

/// Routes one event line: above the status block when a screen is live,
/// plain stderr otherwise (the evidence file is written by the caller).
pub fn event(line: &str) {
    if SCREENS.load(Ordering::Relaxed) > 0 && stdout_is_tty() {
        {
            let mut out = render().out.lock().unwrap_or_else(|e| e.into_inner());
            let l = out.lines;
            let stdout = std::io::stdout();
            let mut w = stdout.lock();
            if l == 0 {
                let _ = write!(w, "\r\x1b[2K");
            } else {
                clear_rows(&mut w, l);
            }
            let _ = writeln!(w, "\r\x1b[2K{line}");
            let _ = w.flush();
            // the event line occupies the former top row; the next tick
            // redraws the block below it
            out.lines = 0;
        }
        draw();
    } else {
        // eprintln! panics when stderr is gone (closed pipe, exited pager) —
        // this copy is best-effort, the evidence copy always lands, so
        // ignore write errors instead of aborting the caller.
        let _ = writeln!(std::io::stderr(), "{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn viz(idx: usize, tail_n: usize) -> ChunkViz {
        ChunkViz {
            idx,
            profile: String::new(),
            hosts_done: 1,
            hosts_total: 32,
            tail: vec!["Stats: 0:01:00 elapsed; 1 hosts completed".to_string(); tail_n],
        }
    }

    #[test]
    fn view_cycling_wraps_through_the_overview() {
        // no chunks: `n` cannot leave the overview
        assert_eq!(advance_view(View::Overview, 3, 0), View::Overview);
        // one chunk: overview → chunk → overview
        assert_eq!(advance_view(View::Overview, 1, 1), View::Chunk(0));
        assert_eq!(advance_view(View::Chunk(0), 1, 1), View::Overview);
        // two chunks step through in order
        assert_eq!(advance_view(View::Overview, 2, 2), View::Chunk(1));
        assert_eq!(advance_view(View::Chunk(1), 1, 2), View::Overview);
        // a position whose chunk finished between ticks falls back
        assert_eq!(resolve_view(View::Chunk(3), 2), View::Overview);
        assert_eq!(resolve_view(View::Chunk(1), 2), View::Chunk(1));
    }

    #[test]
    fn block_heights_follow_the_view() {
        let status = Status::new(10);
        status.set_done(2);
        // overview without chunks: bar + footer
        let o = block_lines(
            View::Overview,
            false,
            "scan",
            &status,
            "0/s",
            "",
            Footer::Scan,
            &[],
        );
        assert_eq!(o.len(), 2);
        assert!(o[1].contains("[n] view"));
        // overview with running chunks: the progress line sits between
        let chunks = vec![viz(0, 1), viz(3, 1)];
        let o3 = block_lines(
            View::Overview,
            false,
            "scan",
            &status,
            "0/s",
            "",
            Footer::Scan,
            &chunks,
        );
        assert_eq!(o3.len(), 3);
        assert!(o3[1].contains("chunk-0000 1/32"));
        assert!(o3[1].contains("chunk-0003 1/32"));
        // chunk view: header + tail + footer
        let c = block_lines(
            View::Chunk(0),
            false,
            "scan",
            &status,
            "0/s",
            "",
            Footer::Scan,
            &chunks,
        );
        assert_eq!(c.len(), 3);
        assert!(c[0].contains("chunk 0000 · 1/32 hosts reported"));
        assert!(c[2].contains("[n] overview"));
        // a discovery footer never shows scan hints or chunk progress
        let d = block_lines(
            View::Overview,
            false,
            "sweep",
            &status,
            "0/s",
            "",
            Footer::Discovery,
            &chunks,
        );
        assert_eq!(d.len(), 2);
        assert!(!d[1].contains("[n]"));
    }
}
