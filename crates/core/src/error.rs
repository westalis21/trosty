use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid secret name: {0:?} (expected [a-z0-9_-]+ or ns/key)")]
    InvalidName(String),
    #[error("secret value too short (min 4 chars)")]
    TooShort,
    #[error("unknown secret: {0}")]
    UnknownSecret(String),
    #[error("keyring: {0}")]
    Keyring(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
