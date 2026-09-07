//! Authenticated encryption: AES-256-GCM and ChaCha20-Poly1305.
//!
//! Only authenticated modes are offered. Unauthenticated modes are not
//! implemented and never will be a silent fallback. Each call requires a
//! unique nonce; callers get the nonce back to store with the ciphertext.

use crate::error::CryptoError;
use aes_gcm::aead;
use aead::{generic_array::GenericArray, Aead, KeyInit, Payload};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadId {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl AeadId {
    pub fn name(&self) -> &'static str {
        match self {
            AeadId::Aes256Gcm => "aes256-gcm",
            AeadId::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }
    pub fn from_name(name: &str) -> Option<AeadId> {
        match name.to_ascii_lowercase().as_str() {
            "aes256-gcm" | "aes-256-gcm" | "aesgcm" => Some(AeadId::Aes256Gcm),
            "chacha20-poly1305" | "xchacha20-poly1305" => Some(AeadId::ChaCha20Poly1305),
            _ => None,
        }
    }
    /// Nonce length in bytes for this algorithm.
    pub fn nonce_len(&self) -> usize {
        match self {
            AeadId::Aes256Gcm => 12,
            AeadId::ChaCha20Poly1305 => 12,
        }
    }
    /// Tag length in bytes for this algorithm.
    pub fn tag_len(&self) -> usize {
        16
    }
}

pub struct Sealed {
    /// The algorithm that produced this sealed box.
    pub algorithm: AeadId,
    /// Per-message nonce (unique per encryption; never reused with a key).
    pub nonce: Vec<u8>,
    /// Ciphertext with the 16-byte authentication tag appended.
    pub ciphertext_tag: Vec<u8>,
}

/// Encrypt with an AES-256-GCM or ChaCha20-Poly1305 key (32 bytes).
pub fn encrypt(
    algorithm: AeadId,
    key32: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Sealed, CryptoError> {
    if key32.len() != 32 {
        return Err(CryptoError::fail(
            "EKEY-002",
            format!("{} requires a 32-byte key, got {} bytes", algorithm.name(), key32.len()),
        ));
    }
    if nonce.len() != algorithm.nonce_len() {
        return Err(CryptoError::fail(
            "ENONCE-001",
            format!("{} requires a {}-byte nonce, got {}", algorithm.name(), algorithm.nonce_len(), nonce.len()),
        ));
    }
    let nonce = GenericArray::from_slice(nonce); // unique per message
    let payload = Payload { msg: plaintext, aad };
    let ciphertext_tag = match algorithm {
        AeadId::Aes256Gcm => {
            let cipher = aes_gcm::Aes256Gcm::new_from_slice(key32)
                .map_err(|_| CryptoError::fail("EKEY-002", "bad AES-256 key length"))?;
            cipher
                .encrypt(nonce, payload)
                .map_err(|_| CryptoError::fail("EAES-001", "AES-GCM encryption failed"))?
        }
        AeadId::ChaCha20Poly1305 => {
            let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key32)
                .map_err(|_| CryptoError::fail("EKEY-002", "bad ChaCha20 key length"))?;
            cipher
                .encrypt(nonce, payload)
                .map_err(|_| CryptoError::fail("ECC-001", "ChaCha20-Poly1305 encryption failed"))?
        }
    };
    Ok(Sealed { algorithm, nonce: nonce.as_slice().to_vec(), ciphertext_tag })
}

/// Decrypt. Any failure (wrong key, wrong nonce, tampered data) returns the
/// same generic EKEY-003 authentication failure.
pub fn decrypt(
    algorithm: AeadId,
    key32: &[u8],
    nonce: &[u8],
    ciphertext_tag: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if key32.len() != 32 {
        return Err(CryptoError::auth_failed());
    }
    let nonce = GenericArray::from_slice(nonce);
    let payload = Payload { msg: ciphertext_tag, aad };
    let plaintext = match algorithm {
        AeadId::Aes256Gcm => {
            let cipher = aes_gcm::Aes256Gcm::new_from_slice(key32)
                .map_err(|_| CryptoError::auth_failed())?;
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| CryptoError::auth_failed())?
        }
        AeadId::ChaCha20Poly1305 => {
            let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key32)
                .map_err(|_| CryptoError::auth_failed())?;
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| CryptoError::auth_failed())?
        }
    };
    Ok(Zeroizing::new(plaintext))
}
