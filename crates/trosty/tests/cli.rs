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
