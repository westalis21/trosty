use assert_cmd::Command;

#[test]
fn hook_masks_bash_output_over_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let input = r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"KEY=s3cretVALUE"}}"#;
    let mut cmd = Command::cargo_bin("trosty").unwrap();
    let assert = cmd
        .env("TROSTY_CONFIG_DIR", dir.path())
        .env("TROSTY_DATA_DIR", dir.path())
        .env("TROSTY_MEMORY_STORE", "1")
        .env("TROSTY_SEED", "demo/token=s3cretVALUE")
        .arg("hook")
        .write_stdin(input)
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(out.contains("{{demo/token}}"), "got: {out}");
    assert!(!out.contains("s3cretVALUE"), "raw value must not appear: {out}");
}
