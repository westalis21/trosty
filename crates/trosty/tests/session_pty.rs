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

/// Fail-closed twin of `exec_refuses_to_run_when_indexed_secret_unreadable`
/// (cli.rs) for the interactive path: a `secrets.toml` index lists a name
/// with no matching keychain entry (no `TROSTY_MEMORY_STORE`, so this
/// exercises the real `KeyringStore`). `collect_secrets` in main.rs must
/// bail before `session::run` ever spawns a shell — proven here not just by
/// checking the screen has no secret, but by scripting the inner "shell" to
/// print a marker and asserting that marker never appears: the shell must
/// never run at all.
#[test]
fn session_refuses_to_run_when_indexed_secret_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("secrets.toml"),
        "names = [\"trosty_test_missing/only_in_index\"]\n",
    )
    .unwrap();
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
    // Deliberately no TROSTY_MEMORY_STORE / TROSTY_SEED: the real keychain
    // has no entry for this name, so the index reference is genuinely
    // unreadable and collect_secrets must refuse.
    cmd.env("TROSTY_SHELL", "/bin/sh");
    cmd.env(
        "TROSTY_SHELL_ARGS",
        "-c,echo INNER_SHELL_MARKER_SHOULD_NEVER_APPEAR",
    );
    let mut child = pty.slave.spawn_command(cmd).unwrap();
    drop(pty.slave);
    let mut out = String::new();
    let mut reader = pty.master.try_clone_reader().unwrap();
    reader.read_to_string(&mut out).ok(); // EOF when child exits
    let status = child.wait().unwrap();
    assert!(
        !status.success(),
        "trosty must exit nonzero when an indexed secret is unreadable: {out}"
    );
    assert!(
        !out.contains("INNER_SHELL_MARKER_SHOULD_NEVER_APPEAR"),
        "inner shell must never spawn — fail-closed check must happen before session::run: {out}"
    );
}
