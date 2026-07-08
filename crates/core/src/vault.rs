use crate::error::CoreError;
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

pub const MIN_SECRET_LEN: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SecretName {
    pub namespace: Option<String>,
    pub key: String,
}

fn valid_segment(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

impl FromStr for SecretName {
    type Err = CoreError;
    fn from_str(s: &str) -> Result<Self, CoreError> {
        let parts: Vec<&str> = s.split('/').collect();
        let (namespace, key) = match parts.as_slice() {
            [k] => (None, *k),
            [ns, k] => (Some(*ns), *k),
            _ => return Err(CoreError::InvalidName(s.into())),
        };
        if !valid_segment(key) || namespace.is_some_and(|_| !valid_segment(parts[0])) {
            return Err(CoreError::InvalidName(s.into()));
        }
        Ok(SecretName {
            namespace: namespace.map(String::from),
            key: key.into(),
        })
    }
}

impl fmt::Display for SecretName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.namespace {
            Some(ns) => write!(f, "{ns}/{}", self.key),
            None => write!(f, "{}", self.key),
        }
    }
}

pub trait SecretStore {
    fn set(&mut self, name: &SecretName, value: &str) -> Result<(), CoreError>;
    fn get(&self, name: &SecretName) -> Result<Option<String>, CoreError>;
    fn delete(&mut self, name: &SecretName) -> Result<(), CoreError>;
    fn list(&self) -> Result<Vec<SecretName>, CoreError>;
}

#[derive(Default)]
pub struct MemoryStore {
    map: BTreeMap<String, String>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for MemoryStore {
    fn set(&mut self, name: &SecretName, value: &str) -> Result<(), CoreError> {
        if value.len() < MIN_SECRET_LEN {
            return Err(CoreError::TooShort);
        }
        self.map.insert(name.to_string(), value.into());
        Ok(())
    }
    fn get(&self, name: &SecretName) -> Result<Option<String>, CoreError> {
        Ok(self.map.get(&name.to_string()).cloned())
    }
    fn delete(&mut self, name: &SecretName) -> Result<(), CoreError> {
        self.map.remove(&name.to_string());
        Ok(())
    }
    fn list(&self) -> Result<Vec<SecretName>, CoreError> {
        self.map.keys().map(|k| SecretName::from_str(k)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn name_parses_namespace_and_key() {
        let n = SecretName::from_str("rostyslab/stripe_key").unwrap();
        assert_eq!(n.namespace.as_deref(), Some("rostyslab"));
        assert_eq!(n.key, "stripe_key");
        assert_eq!(n.to_string(), "rostyslab/stripe_key");
        let bare = SecretName::from_str("stripe_key").unwrap();
        assert_eq!(bare.namespace, None);
        assert_eq!(bare.to_string(), "stripe_key");
    }

    #[test]
    fn name_rejects_invalid() {
        for bad in ["", "a//b", "a/b/c", "UP ER", "з-кирилицею", "a b"] {
            assert!(SecretName::from_str(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn memory_store_roundtrip() {
        let mut s = MemoryStore::new();
        let n = SecretName::from_str("proj/db_url").unwrap();
        assert!(s.set(&n, "abc").is_err()); // < 4 chars → TooShort
        s.set(&n, "postgres://x").unwrap();
        assert_eq!(s.get(&n).unwrap().as_deref(), Some("postgres://x"));
        assert_eq!(s.list().unwrap(), vec![n.clone()]);
        s.delete(&n).unwrap();
        assert_eq!(s.get(&n).unwrap(), None);
    }
}
