use serde::Serialize;

// Not every variant is produced yet; later tasks (login, use, etc.) add the verbs that do.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    NoSuchSlot,
    ProviderNotInstalled,
    KeychainUnavailable,
    RefreshDenied,
    TokenDead,
    Locked,
    Unsupported,
    Io,
    Http,
    InvalidInput,
}

impl ErrorCode {
    // Not all variants/uses are exercised yet; later tasks (login, use, etc.) add them.
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::NoSuchSlot => "no-such-slot",
            ErrorCode::ProviderNotInstalled => "provider-not-installed",
            ErrorCode::KeychainUnavailable => "keychain-unavailable",
            ErrorCode::RefreshDenied => "refresh-denied",
            ErrorCode::TokenDead => "token-dead",
            ErrorCode::Locked => "locked",
            ErrorCode::Unsupported => "unsupported",
            ErrorCode::Io => "io",
            ErrorCode::Http => "http",
            ErrorCode::InvalidInput => "invalid-input",
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct SwapdError {
    pub code: ErrorCode,
    pub message: String,
}

impl SwapdError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
impl From<std::io::Error> for SwapdError {
    fn from(e: std::io::Error) -> Self {
        Self::new(ErrorCode::Io, e.to_string())
    }
}
impl From<serde_json::Error> for SwapdError {
    fn from(e: serde_json::Error) -> Self {
        Self::new(ErrorCode::InvalidInput, e.to_string())
    }
}
pub type Result<T> = std::result::Result<T, SwapdError>;
