use anyhow::{Context, Result};
use portable_pty::{native_pty_system, Child, CommandBuilder, PtySize};
use std::io::{Read, Write};
use std::sync::mpsc;
use std::time::Duration;
use trosty_core::{Audit, ProjectsFile, Scrubber, SecretName};

enum SessionEvent {
    Output(Vec<u8>),
    Eof,
    Resize,
    Peek,
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

/// Run an interactive shell session inside a PTY, masking known secrets on
/// the way to the screen. `collect_secrets` (main.rs) is called by the
/// caller before this runs — this function receives the already-collected
/// secrets so the fail-closed check happens once, in one place, before
/// anything spawns.
pub fn run(
    secrets: &[(SecretName, String)],
    projects: &ProjectsFile,
    audit: &Audit,
) -> Result<i32> {
    let scrubber = std::sync::Arc::new(Scrubber::new(secrets));
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
    let banner = format!(
        "trosty session · project: {} · {} secrets guarded\r\n",
        project.as_deref().unwrap_or("(none)"),
        secrets.len()
    );
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(banner.as_bytes());
    let _ = stdout.flush();

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
                    let mut start = 0;
                    for i in 0..n {
                        if buf[i] == 0x07 {
                            if pty_writer.write_all(&buf[start..i]).is_err() {
                                return;
                            }
                            let _ = tx_stdin.send(SessionEvent::Peek);
                            start = i + 1;
                        }
                    }
                    if pty_writer.write_all(&buf[start..n]).is_err() {
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
    loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(SessionEvent::Output(chunk)) => {
                let masked = stream.feed_bytes(&chunk);
                if stdout.write_all(&masked).is_err() {
                    break;
                }
                let _ = stdout.flush();
            }
            Ok(SessionEvent::Eof) => break,
            Ok(SessionEvent::Resize) => {
                let _ = pty.master.resize(term_size());
            }
            Ok(SessionEvent::Peek) => {
                // handled in Plan 2b Task 4
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // tick point for later tasks
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
        // Windows has no SIGWINCH; keep polling per chunk so resize still
        // tracks the real terminal there.
        #[cfg(windows)]
        {
            let _ = pty.master.resize(term_size());
        }
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
