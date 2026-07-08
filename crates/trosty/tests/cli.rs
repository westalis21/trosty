use assert_cmd::Command;

#[test]
fn ls_runs_with_isolated_config() {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::cargo_bin("trosty").unwrap();
    cmd.env("TROSTY_CONFIG_DIR", dir.path())
        .env("TROSTY_DATA_DIR", dir.path())
        .arg("ls")
        .assert()
        .success()
        .stdout("no secrets yet\n");
}

#[test]
fn rm_unknown_fails() {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::cargo_bin("trosty").unwrap();
    cmd.env("TROSTY_CONFIG_DIR", dir.path())
        .env("TROSTY_DATA_DIR", dir.path())
        .env("TROSTY_MEMORY_STORE", "1")
        .args(["rm", "proj/nope"])
        .assert()
        .failure();
}

#[test]
fn import_env_file_reports_names_only() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(&env_path, "STRIPE_KEY=sk_live_abc123\nX=ab\n").unwrap();
    let mut cmd = Command::cargo_bin("trosty").unwrap();
    let assert = cmd
        .env("TROSTY_CONFIG_DIR", dir.path())
        .env("TROSTY_DATA_DIR", dir.path())
        .env("TROSTY_MEMORY_STORE", "1")
        .args([
            "import",
            env_path.to_str().unwrap(),
            "--project",
            "rostyslab",
        ])
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(out.contains("rostyslab/stripe_key"));
    assert!(out.contains("skipped x (too short)"));
    assert!(
        !out.contains("sk_live_abc123"),
        "value must never be printed"
    );
}

#[test]
fn exec_expands_and_masks() {
    let dir = tempfile::tempdir().unwrap();
    // seed a secret via import (memory store persists only per-process, so
    // exec test uses TROSTY_SEED to inject: name=value)
    let mut cmd = Command::cargo_bin("trosty").unwrap();
    let assert = cmd
        .env("TROSTY_CONFIG_DIR", dir.path())
        .env("TROSTY_DATA_DIR", dir.path())
        .env("TROSTY_MEMORY_STORE", "1")
        .env("TROSTY_SEED", "proj/key=supersecret9")
        .args(["exec", "--", "echo", "value is {{proj/key}}"])
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    // echo received the real value, but trosty masked it back on the way out
    assert!(out.contains("value is {{proj/key}}"));
    assert!(!out.contains("supersecret9"));
}

#[test]
fn exec_refuses_to_run_when_indexed_secret_unreadable() {
    // Real KeyringStore (no TROSTY_MEMORY_STORE): the index (secrets.toml)
    // lists a name that has no matching keychain entry. `get_password` for
    // an absent entry returns NoEntry -> Ok(None), which is a read-only,
    // no-prompt path — deterministic and keychain-safe. exec must refuse to
    // run rather than mask with an incomplete secret set.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("secrets.toml"),
        "names = [\"trosty_test_missing/only_in_index\"]\n",
    )
    .unwrap();
    let mut cmd = Command::cargo_bin("trosty").unwrap();
    let assert = cmd
        .env("TROSTY_CONFIG_DIR", dir.path())
        .env("TROSTY_DATA_DIR", dir.path())
        .args(["exec", "--", "echo", "hi"])
        .assert()
        .failure();
    let err = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        err.contains("trosty_test_missing/only_in_index"),
        "stderr should name the unreadable secret, got: {err}"
    );
}

#[test]
fn exec_unknown_placeholder_runs_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::cargo_bin("trosty").unwrap();
    cmd.env("TROSTY_CONFIG_DIR", dir.path())
        .env("TROSTY_DATA_DIR", dir.path())
        .env("TROSTY_MEMORY_STORE", "1")
        .args(["exec", "--", "echo", "{{proj/nope}}"])
        .assert()
        .failure();
}
