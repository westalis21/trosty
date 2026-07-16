//! claude-adapter: runs `trosty` as a Claude Code hook. Reads the event JSON
//! on stdin, dispatches on `hook_event_name`, writes a decision JSON on
//! stdout. All masking/expansion runs against the full secret store (aligned
//! with the PTY session), and every failure to read secrets fails closed.

use serde_json::{json, Value};
use trosty_core::Scrubber;

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
}
