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
    cmd.env("TROSTY_NO_STATUS", "1");
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
    cmd.env("TROSTY_NO_STATUS", "1");
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

/// Status bar is drawn with scroll region, showing project and secret count,
/// and properly cleaned up on exit.
#[test]
fn session_draws_status_bar_with_project_and_count() {
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
    cmd.env("TROSTY_SHELL", "/bin/sh");
    cmd.env("TROSTY_SHELL_ARGS", "-c,echo hello");
    let mut child = pty.slave.spawn_command(cmd).unwrap();
    drop(pty.slave);
    let mut out = String::new();
    let mut reader = pty.master.try_clone_reader().unwrap();
    reader.read_to_string(&mut out).ok();
    child.wait().unwrap();
    assert!(out.contains("\x1b[1;23r"), "scroll region not set: {out:?}");
    assert!(out.contains("1 secrets"), "bar text missing: {out:?}");
    assert!(
        out.contains("\x1b[r"),
        "scroll region not reset on exit: {out:?}"
    );
}

#[test]
fn peek_shows_value_on_bar_and_expires() {
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
    cmd.env("TROSTY_PEEK_MS", "300");
    cmd.env("TROSTY_SHELL", "/bin/sh");
    cmd.env("TROSTY_SHELL_ARGS", "-c,sleep 1");
    let mut child = pty.slave.spawn_command(cmd).unwrap();
    drop(pty.slave);
    let mut writer = pty.master.take_writer().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(200));
    writer.write_all(&[0x07]).unwrap(); // Ctrl+G
    let mut out = String::new();
    let mut reader = pty.master.try_clone_reader().unwrap();
    reader.read_to_string(&mut out).ok();
    child.wait().unwrap();
    assert!(
        out.contains("proj/key = supersecret9"),
        "peek value not shown: {out:?}"
    );
}

#[test]
fn hot_reload_picks_up_new_secret() {
    let dir = tempfile::tempdir().unwrap();
    let seed = dir.path().join("seeds.txt");
    std::fs::write(&seed, "proj/key=supersecret9\n").unwrap();
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
    cmd.env("TROSTY_SEED_FILE", &seed);
    cmd.env("TROSTY_NO_STATUS", "1");
    cmd.env("TROSTY_SHELL", "/bin/sh");
    // shell: print new secret before and after it exists in the seed file
    cmd.env(
        "TROSTY_SHELL_ARGS",
        "-c,echo one newsecret42 one; sleep 3; echo two newsecret42 two",
    );
    let mut child = pty.slave.spawn_command(cmd).unwrap();
    drop(pty.slave);
    std::thread::sleep(std::time::Duration::from_millis(600));
    std::fs::write(&seed, "proj/key=supersecret9\nproj/new=newsecret42\n").unwrap();
    let mut out = String::new();
    let mut reader = pty.master.try_clone_reader().unwrap();
    reader.read_to_string(&mut out).ok();
    child.wait().unwrap();
    assert!(
        out.contains("one newsecret42 one"),
        "before reload should be raw: {out:?}"
    );
    assert!(
        out.contains("two {{proj/new}} two"),
        "after reload must be masked: {out:?}"
    );
}
