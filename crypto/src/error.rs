//! Crypto error type with stable error codes.
//!
//! EHEX-xxx are container-format errors; EKEY-xxx are key-management
//! errors (EKEY-003 = authentication failure, EKEY-004 = the one-time-key
//! recovery refusal). Failure messages are deliberately generic for
//! authentication failures so attackers cannot learn what was correct.

use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// Stable error code plus human-readable detail.
    Fail { code: &'static str, detail: String },
}

impl CryptoError {
    pub fn fail(code: &'static str, detail: impl Into<String>) -> Self {
        CryptoError::Fail { code, detail: detail.into() }
    }
    pub fn code(&self) -> &'static str {
        match self {
            CryptoError::Fail { code, .. } => code,
        }
    }
    /// The generic message used for any authentication failure so that
    /// decryption failures never reveal partial correctness.
    pub fn auth_failed() -> Self {
        CryptoError::Fail { code: "EKEY-003", detail: "authentication failed".into() }
    }
    pub fn malformed(code: &'static str, detail: impl Into<String>) -> Self {
        CryptoError::Fail { code, detail: detail.into() }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Fail { code, detail } => write!(f, "{}: {}", code, detail),
        }
    }
}

impl std::error::Error for CryptoError {}
