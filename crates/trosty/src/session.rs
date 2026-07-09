use anyhow::{Context, Result};
use portable_pty::{native_pty_system, Child, CommandBuilder, PtySize};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use trosty_core::{Audit, ProjectsFile, Scrubber, SecretName};

enum SessionEvent {
    Output(Vec<u8>),
    Eof,
    // Only produced by the unix SIGWINCH thread; on Windows the terminal is
    // polled instead, so the variant is never constructed there.
    #[cfg_attr(windows, allow(dead_code))]
    Resize,
    Peek,
}

struct StatusBar {
    rows: u16,
    cols: u16,
    enabled: bool,
    alt_screen: bool,
    /// Leading "lock" segment of the normal bar text. Normally the locked
    /// emoji; swapped to a degraded-state message (e.g. after a failed
    /// hot-reload) so the failure stays visible in the bar itself rather
    /// than a one-off toast that scrolls away.
    lock: String,
}

impl StatusBar {
    /// `enabled` reflects the user's request (`TROSTY_NO_STATUS` unset/not
    /// present — see `run` below: *any* value, including an empty string,
    /// means "disabled", since the point is opting out, not choosing a
    /// mode). It stays fixed for the life of the session. Whether the bar
    /// is actually drawn also depends on `rows`, which can change on
    /// resize — see `active()`.
    fn new(rows: u16, cols: u16, enabled: bool) -> Self {
        StatusBar {
            rows,
            cols,
            enabled,
            alt_screen: false,
            lock: "🔒".to_string(),
        }
    }

    /// Whether the bar should actually be drawn right now: the user hasn't
    /// opted out, and there's enough room to dedicate a row to it. Below 2
    /// rows there's no sensible split between content and bar, so the bar
    /// is disabled dynamically rather than underflowing `rows - 1`.
    fn active(&self) -> bool {
        self.enabled && self.rows >= 2
    }

    /// Top boundary of the scroll region: rows 1..region_top are content,
    /// the last row is reserved for the bar. Saturating avoids an
    /// underflow panic if `rows` is ever 0 or 1 (see `active`, which
    /// disables the bar in that case anyway, but this keeps the arithmetic
    /// itself safe regardless of call order).
    fn region_top(&self) -> u16 {
        self.rows.saturating_sub(1).max(1)
    }

    fn init(&self, out: &mut dyn Write) -> Result<()> {
        if !self.active() {
            return Ok(());
        }
        // Set scroll region to rows 1..{rows-1}, leaving row {rows} for the bar
        let region_cmd = format!("\x1b[1;{}r", self.region_top());
        out.write_all(region_cmd.as_bytes())?;
        // Move cursor to row 1, col 1
        out.write_all(b"\x1b[1;1H")?;
        out.flush()?;
        Ok(())
    }

    /// Re-assert the scroll region without moving the cursor (unlike
    /// `init`). Used when the child leaves the alt screen: it may have
    /// reset our DECSTBM region as part of restoring its own screen, and
    /// re-asserting it here must not fight the cursor position the child
    /// is already restoring.
    fn reassert_region(&self, out: &mut dyn Write) -> Result<()> {
        if !self.active() {
            return Ok(());
        }
        let region_cmd = format!("\x1b[1;{}r", self.region_top());
        out.write_all(region_cmd.as_bytes())?;
        out.flush()?;
        Ok(())
    }

    fn draw(
        &mut self,
        out: &mut dyn Write,
        project: Option<&str>,
        secret_count: usize,
    ) -> Result<()> {
        let project_name = project.unwrap_or("(none)");
        let text = format!(
            "{} trosty · {} · {} secrets",
            self.lock, project_name, secret_count
        );
        self.draw_text(out, &text)
    }

    /// Write arbitrary text to the bar row (used by both the normal bar and
    /// the transient peek display). No-op when the bar is disabled or the
    /// child has switched to the alt screen.
    fn draw_text(&mut self, out: &mut dyn Write, text: &str) -> Result<()> {
        if !self.active() || self.alt_screen {
            return Ok(());
        }

        // Truncate text by characters (not bytes) to fit in the available cols
        let max_chars = (self.cols as usize).saturating_sub(1);
        let truncated = text.chars().take(max_chars).collect::<String>();

        // Save cursor, move to last row, clear line, write text, restore cursor
        out.write_all(b"\x1b7")?; // Save cursor
        let move_cmd = format!("\x1b[{};1H", self.rows); // Move to last row, col 1
        out.write_all(move_cmd.as_bytes())?;
        out.write_all(b"\x1b[2K")?; // Clear line
        out.write_all(truncated.as_bytes())?;
        out.write_all(b"\x1b8")?; // Restore cursor
        out.flush()?;
        Ok(())
    }

    fn teardown(&self, out: &mut dyn Write) -> Result<()> {
        if !self.active() {
            return Ok(());
        }
        // Reset scroll region
        out.write_all(b"\x1b[r")?;
        // Move to last row and clear it
        let move_cmd = format!("\x1b[{};1H", self.rows);
        out.write_all(move_cmd.as_bytes())?;
        out.write_all(b"\x1b[2K")?;
        out.flush()?;
        Ok(())
    }

    fn on_resize(
        &mut self,
        rows: u16,
        cols: u16,
        out: &mut dyn Write,
        project: Option<&str>,
        secret_count: usize,
    ) -> Result<()> {
        self.rows = rows;
        self.cols = cols;
        if !self.active() {
            return Ok(());
        }
        // Re-init scroll region with new dimensions
        let region_cmd = format!("\x1b[1;{}r", self.region_top());
        out.write_all(region_cmd.as_bytes())?;
        // Redraw the bar
        self.draw(out, project, secret_count)?;
        Ok(())
    }

    /// Returns whether this call flipped `alt_screen` from `true` to
    /// `false` (i.e. the child just left the alt screen — e.g. vim
    /// exiting), so the caller can re-assert the scroll region: vim (and
    /// other full-screen apps) issue `\x1b[r` as part of restoring the
    /// normal screen, which clears our DECSTBM region. Without
    /// re-asserting it, subsequent output — including a peeked secret
    /// value drawn on the bar row — can scroll into terminal scrollback
    /// history instead of staying pinned off-screen.
    fn scan_for_alt_screen(&mut self, chunk: &[u8]) -> bool {
        let was_alt = self.alt_screen;
        // Check for alt-screen enter sequences
        if chunk.windows(8).any(|w| w == b"\x1b[?1049h")
            || chunk.windows(6).any(|w| w == b"\x1b[?47h")
            || chunk.windows(8).any(|w| w == b"\x1b[?1047h")
        {
            self.alt_screen = true;
        }
        // Check for alt-screen exit sequences (same but with 'l' instead of 'h')
        if chunk.windows(8).any(|w| w == b"\x1b[?1049l")
            || chunk.windows(6).any(|w| w == b"\x1b[?47l")
            || chunk.windows(8).any(|w| w == b"\x1b[?1047l")
        {
            self.alt_screen = false;
        }
        was_alt && !self.alt_screen
    }
}

fn shell_command() -> CommandBuilder {
    let shell = std::env::var("TROSTY_SHELL")
        .ok()
        .or_else(|| std::env::var("SHELL").ok())
        .unwrap_or_else(|| {
            if cfg!(windows) {
                "cmd.exe".into()
            } else {
                "/bin/sh".into()
            }
        });
    let mut cmd = CommandBuilder::new(shell);
    // Test-only override (like TROSTY_SEED in main.rs): lets tests script a
    // fake inner "shell" without spawning a real one. Comma-splitting means
    // an argument that itself needs a literal comma is inexpressible by
    // design — acceptable since this knob never runs in production.
    if let Ok(args) = std::env::var("TROSTY_SHELL_ARGS") {
        for a in args.split(',') {
            cmd.arg(a);
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        cmd.cwd(cwd);
    }
    cmd
}

fn term_size() -> PtySize {
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    // known v0.1 limitation: the pty is sized to the full terminal `rows`,
    // not `rows - 1`, even though the status bar reserves the last row via
    // the scroll region. A full-screen child app that queries the pty size
    // directly (rather than trusting the scroll region) may believe the
    // bottom row is usable content space when it's actually the bar row.
    PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    }
}

/// Restores raw mode on drop, so any early return via `?` after raw mode is
/// enabled (e.g. `take_writer`/`try_clone_reader`/`child.wait` failing)
/// still leaves the caller's terminal usable instead of stuck in raw mode.
struct RawModeGuard(bool);

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.0 {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}

/// Mirrors `RawModeGuard` for the status bar's scroll region: best-effort
/// DECSTBM reset (+ clearing the bar row) on drop, so any early `?`-return
/// or panic between `bar.init` and the normal `bar.teardown()` call still
/// leaves the region unset on the user's terminal. Security angle, not
/// just cosmetics: a `?`-return or panic can happen at any point after
/// `init` sets the region — including while a peeked secret is sitting on
/// the bar row — and an un-reset region is what lets that row's contents
/// scroll into terminal history instead of being confined to the bottom
/// line. Snapshotting `rows`/`enabled` at construction (rather than
/// borrowing `StatusBar` live) trades perfect accuracy after a later
/// resize for being usable alongside the mutable borrows `bar` needs
/// throughout the event loop; the normal `bar.teardown()` call already
/// uses live values, so this only matters on the early/panic path.
struct BarGuard {
    enabled: bool,
    rows: u16,
}

impl Drop for BarGuard {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }
        let mut out = std::io::stdout();
        let _ = out.write_all(b"\x1b[r");
        let move_cmd = format!("\x1b[{};1H", self.rows);
        let _ = out.write_all(move_cmd.as_bytes());
        let _ = out.write_all(b"\x1b[2K");
        let _ = out.flush();
    }
}

/// Kills (and reaps) the child shell if dropped before `into_inner` hands
/// it off for the normal, final `wait()`. Several `?`-fallible calls run
/// between spawning the shell and that final wait (`take_writer`,
/// `try_clone_reader`, `Signals::new`); without this guard, an early return
/// through any of them would drop `child` and leak an orphaned shell
/// process instead of terminating it.
struct ChildGuard(Option<Box<dyn Child + Send + Sync>>);

impl ChildGuard {
    fn into_inner(mut self) -> Box<dyn Child + Send + Sync> {
        self.0.take().expect("child present until into_inner")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Peek-expiry + hot-reload housekeeping. Called once at the bottom of
/// every iteration of `run`'s event loop — after `Output`, `Resize`,
/// `Peek`, and the now-empty `Timeout` wakeup alike — rather than only from
/// the `Timeout` arm as it used to be. `Timeout` only fires when the
/// channel goes 250ms without a message; a shell producing output faster
/// than that (a busy build log, a spinner) kept the loop perpetually in
/// the `Output` arm, so a newly-added secret was never noticed and masked
/// while the child stayed busy — hot-reload starved exactly when it
/// mattered most. The `last_stat`/`last_mtime` guards below already
/// rate-limit the actual stat+reload work to at most once a second, so
/// running this unconditionally on every iteration is cheap.
#[allow(clippy::too_many_arguments)]
fn tick(
    bar: &mut StatusBar,
    stdout: &mut dyn Write,
    project: Option<&str>,
    secrets: &mut Vec<(SecretName, String)>,
    scrubber: &mut Arc<Scrubber>,
    stream: &mut trosty_core::SwappableStream,
    peek_deadline: &mut Option<Instant>,
    last_stat: &mut Instant,
    last_mtime: &mut Option<SystemTime>,
    watch: &Option<PathBuf>,
    reload: &impl Fn() -> Result<Vec<(SecretName, String)>>,
    audit: &Audit,
) {
    let now = Instant::now();
    // Peek expiry: redraw the normal bar the first tick past the deadline.
    if let Some(deadline) = *peek_deadline {
        if now >= deadline {
            *peek_deadline = None;
            let _ = bar.draw(stdout, project, secrets.len());
        }
    }
    // Hot-reload: stat at most once a second, and only reload when the
    // mtime actually moved.
    if now.duration_since(*last_stat) >= Duration::from_secs(1) {
        *last_stat = now;
        if let Some(path) = watch {
            if let Ok(mtime) = std::fs::metadata(path).and_then(|m| m.modified()) {
                if *last_mtime != Some(mtime) {
                    match reload() {
                        Ok(new_secrets) => {
                            // Only advance last_mtime on success: a
                            // transient read failure (Err arm below) leaves
                            // it stale so the *next* stat tick retries the
                            // same mtime, instead of a failure silently
                            // "consuming" the change and sticking the bar
                            // at 🔓 until the watched file changes again.
                            *last_mtime = Some(mtime);
                            *secrets = new_secrets;
                            *scrubber = Arc::new(Scrubber::new(secrets));
                            stream.set_scrubber(scrubber.clone());
                            bar.lock = "🔒".to_string();
                            let _ = bar.draw(stdout, project, secrets.len());
                            audit.log("reload_ok", &secrets.len().to_string());
                        }
                        Err(_) => {
                            bar.lock = "🔓 reload failed".to_string();
                            let _ = bar.draw(stdout, project, secrets.len());
                            audit.log("reload_failed", "-");
                        }
                    }
                }
            }
        }
    }
}

/// Run an interactive shell session inside a PTY, masking known secrets on
/// the way to the screen. `collect_secrets` (main.rs) is called by the
/// caller before this runs — this function receives the already-collected
/// secrets so the fail-closed check happens once, in one place, before
/// anything spawns.
pub fn run(
    secrets: &[(SecretName, String)],
    projects: &ProjectsFile,
    audit: &Audit,
    watch: Option<PathBuf>,
    reload: impl Fn() -> Result<Vec<(SecretName, String)>>,
) -> Result<i32> {
    let mut secrets: Vec<(SecretName, String)> = secrets.to_vec();
    let mut scrubber = Arc::new(Scrubber::new(&secrets));
    let project = std::env::current_dir()
        .ok()
        .and_then(|d| projects.project_for(&d));

    let pty = native_pty_system()
        .openpty(term_size())
        .context("open pty")?;
    let child = pty
        .slave
        .spawn_command(shell_command())
        .context("spawn shell in pty")?;
    let child_guard = ChildGuard(Some(child));
    drop(pty.slave);

    audit.log("session_start", project.as_deref().unwrap_or("-"));
    // known v0.1 limitation: written before `bar.init` sets the scroll
    // region, so the banner lives in ordinary scrollback and can be
    // scrolled away (or, in principle, overwritten) by early child output
    // like any other line — it isn't pinned or specially protected.
    let banner = format!(
        "trosty session · project: {} · {} secrets guarded\r\n",
        project.as_deref().unwrap_or("(none)"),
        secrets.len()
    );
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(banner.as_bytes());
    let _ = stdout.flush();

    // Initialize status bar. TROSTY_NO_STATUS: set (any value, including an
    // empty string) = disabled — this is an opt-out switch, not a mode
    // selector, so presence alone is checked rather than its value.
    let status_enabled = std::env::var("TROSTY_NO_STATUS").is_err();
    let size = term_size();
    let mut bar = StatusBar::new(size.rows, size.cols, status_enabled);
    let _ = bar.init(&mut stdout);
    // Guards against a `?`-return or panic between here and the normal
    // `bar.teardown()` call at the bottom of this function leaving the
    // scroll region set on the user's terminal — see `BarGuard`.
    let _bar_guard = BarGuard {
        enabled: bar.active(),
        rows: bar.rows,
    };

    // Raw mode only when stdin is a real TTY (tests drive us inside a PTY,
    // which IS a tty; a plain pipe is not — then skip raw mode). The guard
    // restores it on every exit path, including early returns below.
    let raw = crossterm::terminal::enable_raw_mode().is_ok();
    let _raw_guard = RawModeGuard(raw);

    // stdin → pty (with Ctrl+G interception)
    let mut pty_writer = pty.master.take_writer().context("pty writer")?;
    let (tx, rx) = mpsc::channel::<SessionEvent>();
    let tx_stdin = tx.clone();
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    // Only a read of exactly one byte, equal to 0x07 (BEL),
                    // is treated as the Ctrl+G peek shortcut. In raw mode a
                    // real keypress arrives alone in its own read; anything
                    // that reads more than one byte at once — a paste, an
                    // OSC/DCS terminal reply, readline echoing a literal
                    // ^G — is forwarded to the child byte-for-byte instead,
                    // including any 0x07 buried inside it. Treating every
                    // stray 0x07 as a peek trigger would let an attacker (or
                    // an unlucky paste/terminal reply) pop a secret value
                    // onto the status bar without the user asking for it.
                    if n == 1 && buf[0] == 0x07 {
                        let _ = tx_stdin.send(SessionEvent::Peek);
                    } else if pty_writer.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    });

    // pty → screen (masked). Reader thread sends chunks; main loop writes,
    // so `finish_bytes` can flush the tail after EOF. SessionEvent::Eof is an
    // explicit EOF sentinel from the reader thread — the loop below can't rely
    // on "all senders dropped" to end, since the SIGWINCH thread also holds a
    // sender for the life of the process (it blocks in `signals.forever()`
    // and never exits on its own, so the channel would otherwise never
    // disconnect and the loop would hang forever after the shell exits).
    let mut pty_reader = pty.master.try_clone_reader().context("pty reader")?;
    let tx_reader = tx.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match pty_reader.read(&mut buf) {
                Ok(0) | Err(_) => {
                    let _ = tx_reader.send(SessionEvent::Eof);
                    break;
                }
                Ok(n) => {
                    if tx_reader
                        .send(SessionEvent::Output(buf[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    // On unix, resize the pty exactly when the terminal tells us to (SIGWINCH),
    // via a Resize event on the same channel the reader thread uses —
    // no separate synchronization needed, and no per-chunk poll. Windows has
    // no SIGWINCH, so it keeps the poll-per-chunk fallback below.
    #[cfg(unix)]
    {
        use signal_hook::consts::SIGWINCH;
        use signal_hook::iterator::Signals;
        let mut signals = Signals::new([SIGWINCH]).context("install SIGWINCH handler")?;
        let tx_resize = tx.clone();
        std::thread::spawn(move || {
            for _ in signals.forever() {
                if tx_resize.send(SessionEvent::Resize).is_err() {
                    break;
                }
            }
        });
    }

    let mut stream = trosty_core::SwappableStream::new(scrubber.clone());

    // Peek state: cycles through current secret names on each Ctrl+G, shown
    // on the bar for TROSTY_PEEK_MS (default 3s), then reverts to the normal
    // bar on the first tick past the deadline.
    let peek_ms: u64 = std::env::var("TROSTY_PEEK_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    let mut peek_index: usize = 0;
    let mut peek_deadline: Option<Instant> = None;

    // Hot-reload state: poll `watch`'s mtime at most once a second (not on
    // every 250ms tick), and only act when it actually changed. `last_mtime`
    // is seeded from the current mtime before the loop starts so the first
    // tick never fires a spurious reload for a file that hasn't changed yet.
    let mut last_stat = Instant::now();
    let mut last_mtime: Option<SystemTime> = watch
        .as_ref()
        .and_then(|p| std::fs::metadata(p).ok())
        .and_then(|m| m.modified().ok());

    loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(SessionEvent::Output(chunk)) => {
                // Scan for alt-screen sequences before masking. If this
                // chunk just flipped alt_screen true→false (child exited a
                // full-screen app like vim), the child's own screen-restore
                // sequence may have reset our DECSTBM scroll region as a
                // side effect — re-assert it and redraw the bar immediately,
                // before any more output can scroll past an unprotected
                // bottom row.
                if bar.scan_for_alt_screen(&chunk) {
                    let _ = bar.reassert_region(&mut stdout);
                    let _ = bar.draw(&mut stdout, project.as_deref(), secrets.len());
                }
                let masked = stream.feed_bytes(&chunk);
                if stdout.write_all(&masked).is_err() {
                    break;
                }
                let _ = stdout.flush();
                // Redraw status bar after output (no-op if alt_screen is
                // true, or if a peek is currently being shown — don't let
                // ordinary shell output stomp on the peek before its
                // deadline).
                // known v0.1 limitation: this redraws once per chunk (per
                // reader-thread read, up to 8192 bytes), not once per
                // logical write from the child, so a very bursty child can
                // interleave several bar redraws with its own output
                // instead of one settled redraw — cosmetic flicker, not a
                // masking-correctness issue.
                let peek_active = peek_deadline.is_some_and(|d| Instant::now() < d);
                if !peek_active {
                    let _ = bar.draw(&mut stdout, project.as_deref(), secrets.len());
                }
            }
            Ok(SessionEvent::Eof) => break,
            Ok(SessionEvent::Resize) => {
                let size = term_size();
                let _ = pty.master.resize(size);
                let _ = bar.on_resize(
                    size.rows,
                    size.cols,
                    &mut stdout,
                    project.as_deref(),
                    secrets.len(),
                );
            }
            Ok(SessionEvent::Peek) => {
                if secrets.is_empty() {
                    let _ = bar.draw_text(&mut stdout, "👁 no secrets");
                } else {
                    let idx = peek_index % secrets.len();
                    let (name, value) = &secrets[idx];
                    let text = format!("👁 {name} = {value}");
                    let _ = bar.draw_text(&mut stdout, &text);
                    audit.log("peek", &name.to_string());
                    peek_index = idx + 1;
                }
                peek_deadline = Some(Instant::now() + Duration::from_millis(peek_ms));
            }
            // The peek-expiry + hot-reload work happens in `tick`, called
            // unconditionally below — not here. This arm is now just the
            // periodic wakeup that guarantees `tick` still runs (at its own
            // internal 1s rate limit) even while the channel is otherwise
            // silent.
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
        // Windows has no SIGWINCH; keep polling per chunk so resize still
        // tracks the real terminal there.
        #[cfg(windows)]
        {
            let _ = pty.master.resize(term_size());
        }
        // Run on every iteration (see `tick`'s doc comment for why this
        // must not be limited to the Timeout arm).
        tick(
            &mut bar,
            &mut stdout,
            project.as_deref(),
            &mut secrets,
            &mut scrubber,
            &mut stream,
            &mut peek_deadline,
            &mut last_stat,
            &mut last_mtime,
            &watch,
            &reload,
            audit,
        );
    }
    // Drop the receiver now, before waiting on the shell: this makes every
    // subsequent send from the reader (and SIGWINCH) threads fail and exit
    // promptly. Without it, if the loop above `break`s early (screen write
    // failed) while the shell keeps producing output, those threads would
    // keep sending into an unbounded channel nobody drains, growing memory
    // without limit until the shell eventually exits on its own.
    drop(rx);
    let _ = stdout.write_all(&stream.finish_bytes());
    let _ = stdout.flush();
    let _ = bar.teardown(&mut stdout);

    // Explicit disable on the happy path (in addition to the guard) so the
    // terminal is restored before the shell's exit status is observed, not
    // just at function return; disabling twice is harmless.
    if raw {
        let _ = crossterm::terminal::disable_raw_mode();
    }
    let status = child_guard.into_inner().wait().context("wait for shell")?;
    audit.log("session_end", project.as_deref().unwrap_or("-"));
    Ok(status.exit_code() as i32)
}
