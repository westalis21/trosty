use crate::error::CoreError;
use crate::vault::{SecretName, SecretStore};
use std::str::FromStr;

pub fn expand(text: &str, store: &dyn SecretStore) -> Result<String, CoreError> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        match after.find("}}") {
            Some(close) => {
                let inner = &after[..close];
                match SecretName::from_str(inner) {
                    Ok(name) => {
                        let value = store
                            .get(&name)?
                            .ok_or_else(|| CoreError::UnknownSecret(name.to_string()))?;
                        out.push_str(&value);
                    }
                    Err(_) => {
                        out.push_str("{{");
                        out.push_str(inner);
                        out.push_str("}}");
                    }
                }
                rest = &after[close + 2..];
            }
            None => {
                out.push_str(&rest[open..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{MemoryStore, SecretName, SecretStore};
    use std::str::FromStr;

    fn store() -> MemoryStore {
        let mut s = MemoryStore::new();
        s.set(&SecretName::from_str("proj/key").unwrap(), "VAL123")
            .unwrap();
        s
    }

    #[test]
    fn expands_known_placeholder() {
        assert_eq!(expand("x={{proj/key}};", &store()).unwrap(), "x=VAL123;");
    }

    #[test]
    fn unknown_placeholder_fails_closed() {
        let e = expand("{{proj/nope}}", &store()).unwrap_err();
        assert!(matches!(e, crate::CoreError::UnknownSecret(_)));
    }

    #[test]
    fn non_name_braces_untouched() {
        assert_eq!(
            expand("{{ not a name }} {{}}", &store()).unwrap(),
            "{{ not a name }} {{}}"
        );
    }
}
