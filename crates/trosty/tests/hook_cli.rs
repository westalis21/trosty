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
    assert!(
        !out.contains("s3cretVALUE"),
        "raw value must not appear: {out}"
    );
}

#[test]
fn hook_expands_bash_command_over_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let input = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl -H auth: {{demo/token}}"}}"#;
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
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    let command = v["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .unwrap();
    assert!(command.contains("s3cretVALUE"), "got: {out}");
}

#[test]
fn hook_blocks_raw_secret_prompt_over_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let input =
        r#"{"hook_event_name":"UserPromptSubmit","prompt":"use key s3cretVALUE to log in"}"#;
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
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v["decision"], "block", "got: {out}");
}

#[test]
fn install_then_uninstall_preserves_foreign_hooks() {
    let dir = tempfile::tempdir().unwrap();
    let settings = dir.path().join("settings.json");
    std::fs::write(
        &settings,
        r#"{"hooks":{"PostToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/other/tool.sh"}]}]}}"#,
    )
    .unwrap();

    // install
    Command::cargo_bin("trosty")
        .unwrap()
        .env("TROSTY_CLAUDE_SETTINGS", &settings)
        .args(["hook", "install"])
        .assert()
        .success();
    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    // trosty entry present on all three events
    for ev in ["PreToolUse", "PostToolUse", "UserPromptSubmit"] {
        let arr = after["hooks"][ev].as_array().unwrap();
        assert!(arr.iter().any(|e| e["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("trosty")));
    }
    // foreign hook still there
    let post = after["hooks"]["PostToolUse"].as_array().unwrap();
    assert!(post
        .iter()
        .any(|e| e["hooks"][0]["command"] == "/other/tool.sh"));

    // idempotent: install again adds no duplicate
    Command::cargo_bin("trosty")
        .unwrap()
        .env("TROSTY_CLAUDE_SETTINGS", &settings)
        .args(["hook", "install"])
        .assert()
        .success();
    let after2: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    let trosty_count = after2["hooks"]["PostToolUse"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| {
            e["hooks"][0]["command"]
                .as_str()
                .unwrap()
                .contains("trosty")
        })
        .count();
    assert_eq!(trosty_count, 1, "install must be idempotent");

    // uninstall removes only trosty, keeps foreign
    Command::cargo_bin("trosty")
        .unwrap()
        .env("TROSTY_CLAUDE_SETTINGS", &settings)
        .args(["hook", "uninstall"])
        .assert()
        .success();
    let after3: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    let post3 = after3["hooks"]["PostToolUse"].as_array().unwrap();
    assert!(post3
        .iter()
        .any(|e| e["hooks"][0]["command"] == "/other/tool.sh"));
    assert!(!post3.iter().any(|e| e["hooks"][0]["command"]
        .as_str()
        .unwrap()
        .contains("trosty")));
}
