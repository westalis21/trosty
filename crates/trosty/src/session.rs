use anyhow::{Context, Result};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{Read, Write};
use std::sync::mpsc;
use trosty_core::{Audit, ProjectsFile, Scrubber, SecretName};

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
    let scrubber = Scrubber::new(secrets);
    let project = std::env::current_dir()
        .ok()
        .and_then(|d| projects.project_for(&d));

    let pty = native_pty_system()
        .openpty(term_size())
        .context("open pty")?;
    let mut child = pty
        .slave
        .spawn_command(shell_command())
        .context("spawn shell in pty")?;
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

    // stdin → pty (verbatim)
    let mut pty_writer = pty.master.take_writer().context("pty writer")?;
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if pty_writer.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    });

    // pty → screen (masked). Reader thread sends chunks; main loop writes,
    // so `finish_bytes` can flush the tail after EOF.
    let mut pty_reader = pty.master.try_clone_reader().context("pty reader")?;
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match pty_reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut stream = scrubber.stream();
    for chunk in rx {
        let masked = stream.feed_bytes(&chunk);
        if stdout.write_all(&masked).is_err() {
            break;
        }
        let _ = stdout.flush();
        // keep pty size in sync with the real terminal (cheap poll per chunk)
        let _ = pty.master.resize(term_size());
    }
    let _ = stdout.write_all(&stream.finish_bytes());
    let _ = stdout.flush();

    // Explicit disable on the happy path (in addition to the guard) so the
    // terminal is restored before the shell's exit status is observed, not
    // just at function return; disabling twice is harmless.
    if raw {
        let _ = crossterm::terminal::disable_raw_mode();
    }
    let status = child.wait().context("wait for shell")?;
    audit.log("session_end", project.as_deref().unwrap_or("-"));
    Ok(status.exit_code() as i32)
}
