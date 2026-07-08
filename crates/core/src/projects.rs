use crate::error::CoreError;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub fn parse_env(content: &str) -> Vec<(String, String)> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let line = line.strip_prefix("export ").unwrap_or(line);
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (k, v) = line.split_once('=')?;
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                .unwrap_or(v);
            if v.is_empty() {
                return None;
            }
            Some((k.trim().to_ascii_lowercase(), v.to_string()))
        })
        .collect()
}

pub struct ProjectsFile {
    path: PathBuf,
    map: BTreeMap<PathBuf, String>,
}

impl ProjectsFile {
    pub fn open(config_dir: &Path) -> Result<Self, CoreError> {
        fs::create_dir_all(config_dir)?;
        let path = config_dir.join("projects.toml");
        let map = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            let doc: BTreeMap<String, String> = toml::from_str(&raw)
                .map_err(|e| CoreError::Keyring(format!("bad projects.toml: {e}")))?;
            doc.into_iter()
                .map(|(k, v)| (PathBuf::from(k), v))
                .collect()
        } else {
            BTreeMap::new()
        };
        Ok(Self { path, map })
    }

    pub fn set(&mut self, dir: &Path, project: &str) -> Result<(), CoreError> {
        self.map.insert(dir.to_path_buf(), project.to_string());
        let doc: BTreeMap<String, String> = self
            .map
            .iter()
            .map(|(k, v)| (k.display().to_string(), v.clone()))
            .collect();
        fs::write(
            &self.path,
            toml::to_string(&doc).expect("string map serializes"),
        )?;
        Ok(())
    }

    pub fn project_for(&self, cwd: &Path) -> Option<String> {
        self.map
            .iter()
            .filter(|(dir, _)| cwd.starts_with(dir))
            .max_by_key(|(dir, _)| dir.components().count())
            .map(|(_, name)| name.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_env_basics() {
        let env = "# comment\nexport STRIPE_KEY=sk_live_1\nDB_URL=\"postgres://x\"\nEMPTY=\n\nQUOTED='abc'\n";
        assert_eq!(
            parse_env(env),
            vec![
                ("stripe_key".to_string(), "sk_live_1".to_string()),
                ("db_url".to_string(), "postgres://x".to_string()),
                ("quoted".to_string(), "abc".to_string()),
            ]
        );
    }

    #[test]
    fn project_mapping_longest_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = ProjectsFile::open(dir.path()).unwrap();
        p.set(std::path::Path::new("/home/r/code"), "generic")
            .unwrap();
        p.set(std::path::Path::new("/home/r/code/rostyslab"), "rostyslab")
            .unwrap();
        assert_eq!(
            p.project_for(std::path::Path::new("/home/r/code/rostyslab/api")),
            Some("rostyslab".to_string())
        );
        assert_eq!(
            p.project_for(std::path::Path::new("/home/r/code/other")),
            Some("generic".to_string())
        );
        assert_eq!(p.project_for(std::path::Path::new("/tmp")), None);
        // persistence
        let p2 = ProjectsFile::open(dir.path()).unwrap();
        assert_eq!(
            p2.project_for(std::path::Path::new("/home/r/code")),
            Some("generic".to_string())
        );
    }
}
