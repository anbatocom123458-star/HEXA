//! Key derivation: Argon2id (default), scrypt, PBKDF2, HKDF.
//!
//! A long user password is never used as a raw AES key. It is salted and
//! derived through a memory-hard KDF into a fixed-size cryptographic key.

use crate::error::CryptoError;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdfId {
    Argon2id,
    Scrypt,
    Pbkdf2Sha256,
}

impl KdfId {
    pub fn name(&self) -> &'static str {
        match self {
            KdfId::Argon2id => "argon2id",
            KdfId::Scrypt => "scrypt",
            KdfId::Pbkdf2Sha256 => "pbkdf2-sha256",
        }
    }
    pub fn from_name(name: &str) -> Option<KdfId> {
        match name.to_ascii_lowercase().as_str() {
            "argon2id" | "argon2" => Some(KdfId::Argon2id),
            "scrypt" => Some(KdfId::Scrypt),
            "pbkdf2-sha256" | "pbkdf2" => Some(KdfId::Pbkdf2Sha256),
            _ => None,
        }
    }
}

/// Tunable Argon2id parameters with secure defaults.
#[derive(Clone, Copy, Debug)]
pub struct Argon2Params {
    /// Memory cost in KiB (19 MiB is the OWASP-recommended minimum).
    pub m_cost_kib: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Argon2Params { m_cost_kib: 19456, t_cost: 2, p_cost: 1 }
    }
}

/// Derive a 32-byte key from a password with Argon2id (HEXA default KDF).
pub fn argon2id_key(
    password: &[u8],
    salt: &[u8],
    params: &Argon2Params,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if salt.len() < 8 {
        return Err(CryptoError::fail("EKDF-001", "salt must be at least 8 bytes"));
    }
    let a2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
            .map_err(|e| CryptoError::fail("EKDF-002", format!("bad Argon2id parameters: {}", e)))?,
    );
    let mut out = Zeroizing::new([0u8; 32]);
    a2.hash_password_into(password, salt, out.as_mut())
        .map_err(|e| CryptoError::fail("EKDF-003", format!("Argon2id derivation failed: {}", e)))?;
    Ok(out)
}

#[derive(Clone, Copy, Debug)]
pub struct ScryptParams {
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
}

impl Default for ScryptParams {
    fn default() -> Self {
        ScryptParams { log_n: 15, r: 8, p: 1 }
    }
}

/// Derive a 32-byte key with scrypt.
pub fn scrypt_key(
    password: &[u8],
    salt: &[u8],
    params: &ScryptParams,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let p = scrypt::Params::new(params.log_n, params.r, params.p, 32)
        .map_err(|e| CryptoError::fail("EKDF-002", format!("bad scrypt parameters: {}", e)))?;
    let mut out = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(password, salt, &p, out.as_mut())
        .map_err(|e| CryptoError::fail("EKDF-003", format!("scrypt derivation failed: {}", e)))?;
    Ok(out)
}

#[derive(Clone, Copy, Debug)]
pub struct Pbkdf2Params {
    pub iterations: u32,
}

impl Default for Pbkdf2Params {
    fn default() -> Self {
        Pbkdf2Params { iterations: 600_000 }
    }
}

/// Derive a 32-byte key with PBKDF2-HMAC-SHA256.
pub fn pbkdf2_sha256_key(
    password: &[u8],
    salt: &[u8],
    params: &Pbkdf2Params,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if params.iterations < 100_000 {
        return Err(CryptoError::fail("EKDF-004", "PBKDF2 iteration count too low (minimum 100000)"));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, params.iterations, out.as_mut());
    Ok(out)
}

/// HKDF-SHA256 expand to derive independent layer subkeys from a master key.
pub fn hkdf_sha256_expand(master: &[u8], info: &[u8], out_len: usize) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, master);
    let mut okm = Zeroizing::new(vec![0u8; out_len]);
    hk.expand(info, okm.as_mut_slice())
        .map_err(|e| CryptoError::fail("EKDF-005", format!("HKDF expand failed: {}", e)))?;
    Ok(okm)
}

/// HKDF-SHA256 with an explicit salt (used to derive the master key from
/// the root credential before layer-key expansion).
pub fn hkdf_sha256_extract_expand(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new(vec![0u8; out_len]);
    hk.expand(info, okm.as_mut_slice())
        .map_err(|e| CryptoError::fail("EKDF-005", format!("HKDF expand failed: {}", e)))?;
    Ok(okm)
}

/// Derive a 32-byte key with the identified KDF.
pub fn derive(
    id: KdfId,
    password: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    match id {
        KdfId::Argon2id => argon2id_key(password, salt, &Argon2Params::default()),
        KdfId::Scrypt => scrypt_key(password, salt, &ScryptParams::default()),
        KdfId::Pbkdf2Sha256 => pbkdf2_sha256_key(password, salt, &Pbkdf2Params::default()),
    }
}
