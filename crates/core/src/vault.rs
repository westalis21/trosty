use crate::error::CoreError;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
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

pub struct KeyringStore {
    index_path: PathBuf,
    names: Vec<SecretName>,
}

impl KeyringStore {
    pub fn open(config_dir: &Path) -> Result<Self, CoreError> {
        fs::create_dir_all(config_dir)?;
        let index_path = config_dir.join("secrets.toml");
        let names = if index_path.exists() {
            let raw = fs::read_to_string(&index_path)?;
            let doc: toml::Value = toml::from_str(&raw)
                .map_err(|e| CoreError::Keyring(format!("bad secrets.toml: {e}")))?;
            doc.get("names")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .filter_map(|s| SecretName::from_str(s).ok())
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        Ok(Self { index_path, names })
    }

    /// Write `secrets.toml` atomically: write the new contents to a sibling
    /// temp file, then `fs::rename` it over the real path. A plain
    /// `fs::write` truncates the file before writing its new contents, so a
    /// concurrent reader (the session's hot-reload, stat-polling this same
    /// path from another process) can observe a half-written or empty file
    /// that still happens to parse as valid (empty) TOML — silently losing
    /// every secret from the scrubber until the next edit. `rename` within
    /// the same directory is atomic on the filesystems we support (POSIX
    /// same-fs rename, Windows `MoveFileEx` via `fs::rename`), so readers
    /// only ever see the fully-old or fully-new file, never a partial one.
    fn save_index(&self) -> Result<(), CoreError> {
        let names: Vec<String> = self.names.iter().map(|n| n.to_string()).collect();
        let doc = toml::toml! { names = names };
        let dir = self.index_path.parent().ok_or_else(|| {
            CoreError::Keyring(format!(
                "index path {} has no parent directory",
                self.index_path.display()
            ))
        })?;
        let tmp_path = dir.join(format!(
            ".secrets.toml.tmp.{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        fs::write(&tmp_path, doc.to_string())?;
        fs::rename(&tmp_path, &self.index_path)?;
        Ok(())
    }

    pub fn index_add(&mut self, name: &SecretName) -> Result<(), CoreError> {
        if !self.names.contains(name) {
            self.names.push(name.clone());
            self.names.sort();
        }
        self.save_index()
    }

    fn entry(name: &SecretName) -> Result<keyring::Entry, CoreError> {
        keyring::Entry::new("trosty", &name.to_string())
            .map_err(|e| CoreError::Keyring(e.to_string()))
    }
}

impl SecretStore for KeyringStore {
    fn set(&mut self, name: &SecretName, value: &str) -> Result<(), CoreError> {
        if value.len() < MIN_SECRET_LEN {
            return Err(CoreError::TooShort);
        }
        Self::entry(name)?
            .set_password(value)
            .map_err(|e| CoreError::Keyring(e.to_string()))?;
        self.index_add(name)
    }
    fn get(&self, name: &SecretName) -> Result<Option<String>, CoreError> {
        match Self::entry(name)?.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(CoreError::Keyring(e.to_string())),
        }
    }
    fn delete(&mut self, name: &SecretName) -> Result<(), CoreError> {
        match Self::entry(name)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(e) => return Err(CoreError::Keyring(e.to_string())),
        }
        self.names.retain(|n| n != name);
        self.save_index()
    }
    fn list(&self) -> Result<Vec<SecretName>, CoreError> {
        Ok(self.names.clone())
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

    #[test]
    fn keyring_store_index_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = KeyringStore::open(dir.path()).unwrap();
        assert!(s.list().unwrap().is_empty());
        // index-only ops (no keychain touch): load/save names
        s.index_add(&SecretName::from_str("proj/a_key").unwrap())
            .unwrap();
        drop(s);
        let s2 = KeyringStore::open(dir.path()).unwrap();
        assert_eq!(s2.list().unwrap().len(), 1);
    }

    /// Extends the round-trip above to exercise `save_index`'s atomic
    /// write path directly: several saves in a row (add/add/add) must each
    /// leave `secrets.toml` fully readable by a fresh `KeyringStore::open`
    /// (never truncated/partial), and must never leave a stray
    /// `.secrets.toml.tmp.*` file behind in the config dir.
    #[test]
    fn keyring_store_index_atomic_write_leaves_no_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = KeyringStore::open(dir.path()).unwrap();
        for key in ["a_key", "b_key", "c_key"] {
            s.index_add(&SecretName::from_str(&format!("proj/{key}")).unwrap())
                .unwrap();
        }
        drop(s);

        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from("secrets.toml")],
            "no leftover temp file expected: {entries:?}"
        );

        let s2 = KeyringStore::open(dir.path()).unwrap();
        let mut names: Vec<String> = s2.list().unwrap().iter().map(|n| n.to_string()).collect();
        names.sort();
        assert_eq!(names, vec!["proj/a_key", "proj/b_key", "proj/c_key"]);
    }

    #[test]
    #[ignore = "touches the real OS keychain; run manually: cargo test -- --ignored"]
    fn keyring_store_real_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = KeyringStore::open(dir.path()).unwrap();
        let n = SecretName::from_str("trosty_test/tmp_key").unwrap();
        s.set(&n, "value123").unwrap();
        assert_eq!(s.get(&n).unwrap().as_deref(), Some("value123"));
        s.delete(&n).unwrap();
        assert_eq!(s.get(&n).unwrap(), None);
    }
}
