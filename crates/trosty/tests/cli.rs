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
