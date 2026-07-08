//! trosty-core: the engine behind trosty.
//!
//! Modules (implemented incrementally, see the roadmap in README):
//! - `vault`    — secret values live only in the OS keychain
//! - `scrubber` — masks known secret values (and their encodings) in any text stream
//! - `expander` — expands `{{name}}` placeholders at command execution time
//! - `projects` — a directory is a project; `.env` import under a namespace
//! - `audit`    — append-only event log (names, never values)

/// Placeholder syntax used across trosty: `{{namespace/name}}`.
pub const PLACEHOLDER_OPEN: &str = "{{";
pub const PLACEHOLDER_CLOSE: &str = "}}";

/// Render the canonical placeholder for a secret name.
pub fn placeholder(name: &str) -> String {
    format!("{PLACEHOLDER_OPEN}{name}{PLACEHOLDER_CLOSE}")
}

pub mod error;
pub mod vault;

pub use error::CoreError;
pub use vault::{KeyringStore, MemoryStore, SecretName, SecretStore, MIN_SECRET_LEN};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_is_canonical() {
        assert_eq!(
            placeholder("rostyslab/stripe_key"),
            "{{rostyslab/stripe_key}}"
        );
    }
}
