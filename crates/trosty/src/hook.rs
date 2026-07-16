//! claude-adapter: runs `trosty` as a Claude Code hook. Reads the event JSON
//! on stdin, dispatches on `hook_event_name`, writes a decision JSON on
//! stdout. All masking/expansion runs against the full secret store (aligned
//! with the PTY session), and every failure to read secrets fails closed.

use serde_json::{json, Value};
use trosty_core::{CoreError, MemoryStore, Scrubber, SecretName, SecretStore};

/// The `hook_event_name` field, if present.
pub fn event_name(v: &Value) -> Option<&str> {
    v.get("hook_event_name").and_then(Value::as_str)
}

/// Recursively replace secret values with `{{name}}` in every string inside a
/// JSON value, preserving the value's shape. Works whether a tool result is a
/// bare string or a structured object (e.g. Bash `{stdout, stderr}`).
pub fn deep_scrub(v: &Value, scr: &Scrubber) -> Value {
    match v {
        Value::String(s) => Value::String(scr.scrub(s)),
        Value::Array(a) => Value::Array(a.iter().map(|x| deep_scrub(x, scr)).collect()),
        Value::Object(o) => {
            Value::Object(o.iter().map(|(k, x)| (k.clone(), deep_scrub(x, scr))).collect())
        }
        other => other.clone(),
    }
}

/// Read every registered secret's value. Fails closed: a name in the index
/// but unreadable from the keychain (locked / permission) returns an error so
/// the caller suppresses/denies rather than masking against a partial set.
fn load_secrets(store: &dyn SecretStore) -> Result<Vec<(SecretName, String)>, CoreError> {
    let mut out = Vec::new();
    for name in store.list()? {
        match store.get(&name)? {
            Some(value) => out.push((name, value)),
            None => return Err(CoreError::UnknownSecret(name.to_string())),
        }
    }
    Ok(out)
}

/// Build an in-memory store the `expand` helper can read from.
fn scoped_store(secrets: &[(SecretName, String)]) -> MemoryStore {
    let mut store = MemoryStore::new();
    for (name, value) in secrets {
        // values already passed MIN_SECRET_LEN when they were stored
        let _ = store.set(name, value);
    }
    store
}

use trosty_core::Audit;

/// PostToolUse: mask secret values in a Bash tool's output before the model
/// reads it. Non-Bash → passthrough. Locked/unreadable secrets → suppress the
/// entire output (fail-closed: better to drop useful text than risk a leak).
fn post_tool_use(v: &Value, store: &dyn SecretStore, audit: &Audit) -> String {
    if v.get("tool_name").and_then(Value::as_str) != Some("Bash") {
        return "{}".to_string();
    }
    let secrets = match load_secrets(store) {
        Ok(s) => s,
        Err(_) => {
            audit.log("hook_locked", "PostToolUse");
            return json!({"hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "updatedToolOutput": "trosty: vault locked — output suppressed"
            }})
            .to_string();
        }
    };
    let scr = Scrubber::new(&secrets);
    // Accept either the object form (`tool_response`) or a bare string
    // (`tool_output`) — whichever this Claude Code build sends (see Task 1).
    let response = v
        .get("tool_response")
        .or_else(|| v.get("tool_output"))
        .cloned()
        .unwrap_or(Value::Null);
    let masked = deep_scrub(&response, &scr);
    audit.log("hook_mask", "PostToolUse");
    json!({"hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "updatedToolOutput": masked
    }})
    .to_string()
}

use trosty_core::expand;

/// PreToolUse: expand `{{name}}` placeholders in a Bash command into real
/// values before it runs. Non-Bash or no placeholder → passthrough. Unknown
/// placeholder or locked vault → deny (fail-closed, command never runs).
fn pre_tool_use(v: &Value, store: &dyn SecretStore, audit: &Audit) -> String {
    if v.get("tool_name").and_then(Value::as_str) != Some("Bash") {
        return "{}".to_string();
    }
    let command = v
        .get("tool_input")
        .and_then(|ti| ti.get("command"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if !command.contains("{{") {
        return "{}".to_string(); // nothing to expand, leave the call untouched
    }
    let secrets = match load_secrets(store) {
        Ok(s) => s,
        Err(_) => return deny("trosty: vault locked — command blocked"),
    };
    let scoped = scoped_store(&secrets);
    match expand(command, &scoped) {
        Ok(expanded) => {
            audit.log("hook_expand", "PreToolUse");
            let mut ti = v.get("tool_input").cloned().unwrap_or_else(|| json!({}));
            ti["command"] = json!(expanded);
            json!({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "updatedInput": ti
            }})
            .to_string()
        }
        Err(_) => deny("trosty: unknown secret placeholder in command"),
    }
}

fn deny(reason: &str) -> String {
    json!({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason
    }})
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use trosty_core::{Scrubber, SecretName};

    fn scr() -> Scrubber {
        let n = SecretName::from_str("demo/token").unwrap();
        Scrubber::new(&[(n, "s3cretVALUE".into())])
    }

    #[test]
    fn event_name_reads_field() {
        let v: Value = serde_json::from_str(r#"{"hook_event_name":"PostToolUse"}"#).unwrap();
        assert_eq!(event_name(&v), Some("PostToolUse"));
    }

    #[test]
    fn deep_scrub_masks_string_and_nested_object() {
        let v = json!({"stdout": "x=s3cretVALUE", "meta": {"note": "s3cretVALUE!"}, "code": 0});
        let out = deep_scrub(&v, &scr());
        assert_eq!(out["stdout"], "x={{demo/token}}");
        assert_eq!(out["meta"]["note"], "{{demo/token}}!");
        assert_eq!(out["code"], 0);
    }

    use trosty_core::{MemoryStore, SecretStore};

    #[test]
    fn load_secrets_reads_all() {
        let mut s = MemoryStore::new();
        s.set(&SecretName::from_str("a/one").unwrap(), "valueone").unwrap();
        s.set(&SecretName::from_str("b/two").unwrap(), "valuetwo").unwrap();
        let loaded = super::load_secrets(&s).unwrap();
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn scoped_store_roundtrips_for_expand() {
        let secrets = vec![(SecretName::from_str("a/one").unwrap(), "valueone".to_string())];
        let store = super::scoped_store(&secrets);
        assert_eq!(
            store.get(&SecretName::from_str("a/one").unwrap()).unwrap().as_deref(),
            Some("valueone")
        );
    }

    use trosty_core::Audit;

    fn audit_tmp() -> (tempfile::TempDir, Audit) {
        let dir = tempfile::tempdir().unwrap();
        let a = Audit::open(dir.path());
        (dir, a)
    }

    fn store_one() -> MemoryStore {
        let mut s = MemoryStore::new();
        s.set(&SecretName::from_str("demo/token").unwrap(), "s3cretVALUE").unwrap();
        s
    }

    #[test]
    fn post_masks_bash_output() {
        let (_d, audit) = audit_tmp();
        let v = json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_response": {"stdout": "KEY=s3cretVALUE", "stderr": ""}
        });
        let out: Value = serde_json::from_str(&super::post_tool_use(&v, &store_one(), &audit)).unwrap();
        assert_eq!(out["hookSpecificOutput"]["updatedToolOutput"]["stdout"], "KEY={{demo/token}}");
    }

    #[test]
    fn post_non_bash_is_passthrough() {
        let (_d, audit) = audit_tmp();
        let v = json!({"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_response": "x"});
        assert_eq!(super::post_tool_use(&v, &store_one(), &audit), "{}");
    }

    #[test]
    fn post_suppresses_when_secrets_unreadable() {
        let (_d, audit) = audit_tmp();
        // FailingStore simulates a locked keychain: list() ok, get() errors.
        struct FailingStore;
        impl SecretStore for FailingStore {
            fn set(&mut self, _: &SecretName, _: &str) -> Result<(), CoreError> { Ok(()) }
            fn get(&self, _: &SecretName) -> Result<Option<String>, CoreError> {
                Err(CoreError::Keyring("locked".into()))
            }
            fn delete(&mut self, _: &SecretName) -> Result<(), CoreError> { Ok(()) }
            fn list(&self) -> Result<Vec<SecretName>, CoreError> {
                Ok(vec![SecretName::from_str("demo/token").unwrap()])
            }
        }
        let v = json!({"hook_event_name": "PostToolUse", "tool_name": "Bash",
                       "tool_response": {"stdout": "KEY=s3cretVALUE"}});
        let out: Value = serde_json::from_str(&super::post_tool_use(&v, &FailingStore, &audit)).unwrap();
        assert_eq!(
            out["hookSpecificOutput"]["updatedToolOutput"],
            "trosty: vault locked — output suppressed"
        );
    }

    #[test]
    fn pre_no_placeholder_is_passthrough() {
        let (_d, audit) = audit_tmp();
        let v = json!({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                       "tool_input": {"command": "ls -la"}});
        assert_eq!(super::pre_tool_use(&v, &store_one(), &audit), "{}");
    }

    #[test] // [GO-only]
    fn pre_expands_known_placeholder() {
        let (_d, audit) = audit_tmp();
        let v = json!({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                       "tool_input": {"command": "curl -H \"auth: {{demo/token}}\""}});
        let out: Value = serde_json::from_str(&super::pre_tool_use(&v, &store_one(), &audit)).unwrap();
        assert_eq!(
            out["hookSpecificOutput"]["updatedInput"]["command"],
            "curl -H \"auth: s3cretVALUE\""
        );
    }

    #[test]
    fn pre_denies_unknown_placeholder() {
        let (_d, audit) = audit_tmp();
        let v = json!({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                       "tool_input": {"command": "echo {{demo/missing}}"}});
        let out: Value = serde_json::from_str(&super::pre_tool_use(&v, &store_one(), &audit)).unwrap();
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    #[test]
    fn pre_non_bash_is_passthrough() {
        let (_d, audit) = audit_tmp();
        let v = json!({"hook_event_name": "PreToolUse", "tool_name": "Read",
                       "tool_input": {"file_path": "x"}});
        assert_eq!(super::pre_tool_use(&v, &store_one(), &audit), "{}");
    }
}
