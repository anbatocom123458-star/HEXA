//! HEXA keys: generation, display encoding, lifecycle.
//!
//! One-time key display: a generated key may be rendered to the user
//! EXACTLY once. After that the displayable copy is destroyed and cannot
//! be recreated. There is intentionally no recovery path (EKEY-004).

use crate::error::CryptoError;
use zeroize::{Zeroize, Zeroizing};

/// A freshly generated symmetric key with a one-time displayable form.
pub struct GeneratedKey {
    raw: Zeroizing<[u8; 32]>,
    displayable: Option<Zeroizing<String>>,
}

impl GeneratedKey {
    /// Generate a new 256-bit key from the OS CSPRNG.
    pub fn generate() -> Result<GeneratedKey, CryptoError> {
        let mut raw = Zeroizing::new([0u8; 32]);
        crate::random::fill(raw.as_mut())?;
        let display = Zeroizing::new(render_display(&raw));
        Ok(GeneratedKey { raw, displayable: Some(display) })
    }

    /// The raw key bytes for actual cryptographic use.
    pub fn raw(&self) -> &[u8; 32] {
        &self.raw
    }

    /// Show the key ONE TIME. The displayable copy is destroyed after this
    /// call; any later attempt returns EKEY-004.
    pub fn display_once(&mut self) -> Result<String, CryptoError> {
        match self.displayable.take() {
            Some(d) => {
                let s = d.to_string();
                Ok(s)
            }
            None => Err(recovery_refused()),
        }
    }

    /// Whether the displayable copy still exists.
    pub fn display_available(&self) -> bool {
        self.displayable.is_some()
    }
}

impl Drop for GeneratedKey {
    fn drop(&mut self) {
        if let Some(mut d) = self.displayable.take() {
            d.as_mut_str().zeroize();
        }
    }
}

/// Render a key in the HEXA display format: HX-<base64url(no padding)>.
pub fn render_display(raw32: &[u8; 32]) -> String {
    format!("HX-{}", crate::encoding::base64url_encode(raw32))
}

/// Parse a displayed key back into raw bytes (used for --prompt-key input).
pub fn parse_display(s: &str) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let s = s.trim();
    let body = s.strip_prefix("HX-").unwrap_or(s);
    let raw = crate::encoding::base64url_decode(body)?;
    if raw.len() != 32 {
        return Err(CryptoError::fail(
            "EKEY-001",
            format!("expected a 32-byte key, got {} bytes", raw.len()),
        ));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&raw);
    Ok(out)
}

/// EKEY-004: the mandated refusal for any key-recovery attempt.
pub fn recovery_refused() -> CryptoError {
    CryptoError::Fail {
        code: "EKEY-004",
        detail: "Generated encryption keys are never recoverable by HEXA. The key was displayed only once.".to_string(),
    }
}

/// Validate a user-chosen symmetric key length in BITS for key generation.
/// Only 128/192/256 are meaningful for the supported AEADs; HEXA defaults
/// to 256. Other sizes are rejected rather than silently rounded.
pub fn validate_key_bits(bits: usize) -> Result<usize, CryptoError> {
    match bits {
        128 | 192 | 256 => Ok(bits),
        _ => Err(CryptoError::fail(
            "EKEY-002",
            format!("unsupported key size {} bits (use 128, 192, or 256; HEXA defaults to 256)", bits),
        ))
    }
}

/// Generate a symmetric key of `bits` size from the CSPRNG.
pub fn generate_symmetric(bits: usize) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let bits = validate_key_bits(bits)?;
    let mut v = Zeroizing::new(vec![0u8; bits / 8]);
    crate::random::fill(v.as_mut())?;
    Ok(v)
}
