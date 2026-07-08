#![cfg(unix)]
use assert_cmd::cargo::cargo_bin;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::Read;

/// Run `trosty` (the session) inside an outer PTY, with an inner shell that
/// prints a secret and exits. The screen must show the placeholder.
#[test]
fn session_masks_secret_on_screen() {
    let dir = tempfile::tempdir().unwrap();
    let pty = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    let mut cmd = CommandBuilder::new(cargo_bin("trosty"));
    cmd.env("TROSTY_CONFIG_DIR", dir.path());
    cmd.env("TROSTY_DATA_DIR", dir.path());
    cmd.env("TROSTY_MEMORY_STORE", "1");
    cmd.env("TROSTY_SEED", "proj/key=supersecret9");
    // inner "shell": prints the secret and exits
    cmd.env("TROSTY_SHELL", "/bin/sh");
    cmd.env("TROSTY_SHELL_ARGS", "-c,echo start supersecret9 end");
    let mut child = pty.slave.spawn_command(cmd).unwrap();
    drop(pty.slave);
    let mut out = String::new();
    let mut reader = pty.master.try_clone_reader().unwrap();
    reader.read_to_string(&mut out).ok(); // EOF when child exits
    let status = child.wait().unwrap();
    assert!(status.success(), "session exited nonzero: {out}");
    assert!(out.contains("{{proj/key}}"), "screen: {out}");
    assert!(
        !out.contains("supersecret9"),
        "secret leaked to screen: {out}"
    );
}
