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
}
