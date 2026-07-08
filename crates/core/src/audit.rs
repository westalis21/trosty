use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Audit {
    path: PathBuf,
}

impl Audit {
    pub fn open(data_dir: &Path) -> Self {
        let _ = std::fs::create_dir_all(data_dir);
        Self {
            path: data_dir.join("audit.jsonl"),
        }
    }

    /// Best-effort append. Protection matters more than accounting (spec §6):
    /// IO errors are swallowed on purpose.
    pub fn log(&self, event: &str, name: &str) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let line = format!("{{\"ts\":{ts},\"event\":\"{event}\",\"name\":\"{name}\"}}\n");
        if let Ok(mut f) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_events_without_values() {
        let dir = tempfile::tempdir().unwrap();
        let a = Audit::open(dir.path());
        a.log("masked", "proj/key");
        a.log("expanded", "proj/key");
        let raw = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"event\":\"masked\""));
        assert!(lines[0].contains("\"name\":\"proj/key\""));
    }

    #[test]
    fn unwritable_dir_does_not_panic() {
        let a = Audit::open(std::path::Path::new("/nonexistent/really/not"));
        a.log("masked", "x/y"); // must not panic
    }
}
