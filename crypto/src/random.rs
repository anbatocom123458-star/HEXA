//! Cryptographically secure random generation.
//!
//! All randomness for keys, nonces, and salts comes from the operating
//! system CSPRNG (getrandom). HEXA never derives cryptographic randomness
//! from time, process ids, counters, or user-seeded pseudo-RNGs.

use crate::error::CryptoError;

/// Fill a buffer with cryptographically secure random bytes.
pub fn fill(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::getrandom(buf)
        .map_err(|e| CryptoError::fail("ERNG-001", format!("CSPRNG failure: {}", e)))
}

/// Produce `n` cryptographically secure random bytes.
pub fn bytes(n: usize) -> Result<Vec<u8>, CryptoError> {
    let mut v = vec![0u8; n];
    fill(&mut v)?;
    Ok(v)
}

/// A fresh 12-byte nonce for AEAD use (unique per encryption call).
pub fn nonce12() -> Result<[u8; 12], CryptoError> {
    let mut n = [0u8; 12];
    fill(&mut n)?;
    Ok(n)
}

/// A fresh 16-byte salt for KDF use.
pub fn salt16() -> Result<[u8; 16], CryptoError> {
    let mut s = [0u8; 16];
    fill(&mut s)?;
    Ok(s)
}
