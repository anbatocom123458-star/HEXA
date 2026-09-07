//! High-level .hexa encryption/decryption with a layered key hierarchy.
//!
//! Key hierarchy (never reuse one key across layers):
//!
//!   password (or raw 32-byte key)
//!        |  Argon2id(salt from header)          [password case]
//!        v
//!   intermediate key material (32 bytes)
//!        |  HKDF-SHA256 extract+expand, info = "hexa/master/v1"
//!        v
//!   master key (32 bytes, zeroized on drop)
//!        |  HKDF-SHA256 expand, info = "hexa/layer/<i>/<algo>"
//!        v
//!   layer key i (32 bytes, unique per layer, zeroized on drop)
//!
//! Every layer encrypts the previous layer's ciphertext with its own key
//! and its own fresh random 12-byte nonce, and authenticates the file
//! header as AAD. The header nonce is an HKDF context value, not an AEAD
//! nonce, so there is exactly one nonce per (key, message) pair.
//!
//! Honesty: more layers do NOT meaningfully increase security against a
//! correct key. Layers defend against implementation compromise of a
//! single primitive and demonstrate the hierarchy; the real security
//! comes from the key entropy and the memory-hard KDF.

use crate::aead::{self, AeadId};
use crate::error::CryptoError;
use crate::format::{self, HexaFile, LayerRecord};
use crate::kdf::{self, KdfId};
use crate::secret::ct_eq;
use zeroize::Zeroizing;

pub const MASTER_INFO: &[u8] = b"hexa/master/v1";
pub const DEFAULT_MAX_LAYERS: u32 = 5000;
pub const WARN_LAYER_COUNT: u32 = 100;
pub const WARN_ESTIMATED_SECONDS: f64 = 30.0;

/// Where the master key comes from.
pub enum KeySource {
    /// A 32-byte symmetric key (from `HX-...` display key or CSPRNG).
    RawKey(Vec<u8>),
    /// A user password/credential (any length; entropy is what matters).
    Password(Vec<u8>),
}

/// Encrypt-to-layers policy limits.
#[derive(Clone, Copy, Debug)]
pub struct LayerPolicy {
    pub max_layers: u32,
}

impl Default for LayerPolicy {
    fn default() -> Self {
        LayerPolicy { max_layers: DEFAULT_MAX_LAYERS }
    }
}

/// The one-time displayable key returned by key-generating encryption.
pub struct GeneratedKeyHandle {
    inner: crate::key::GeneratedKey,
}

impl GeneratedKeyHandle {
    /// Display the key ONE TIME. After this the displayable copy is
    /// destroyed and can never be shown again.
    pub fn display_once(&mut self) -> Result<String, CryptoError> {
        self.inner.display_once()
    }
}

/// Encrypt `plaintext` into a .hexa structure using `layers` independent
/// AEAD layers. Returns the file plus a one-time displayable key handle.
pub fn encrypt_with_generated_key(
    plaintext: &[u8],
    layers: u32,
    algorithm: AeadId,
    metadata: &str,
    policy: &LayerPolicy,
) -> Result<(Vec<u8>, GeneratedKeyHandle), CryptoError> {
    let key = crate::key::GeneratedKey::generate()?;
    let raw = key.raw().to_vec();
    let file = encrypt_layers(plaintext, KeySource::RawKey(raw), layers, algorithm, metadata, policy)?;
    Ok((file, GeneratedKeyHandle { inner: key }))
}

/// Encrypt `plaintext` with an explicitly provided key or password.
pub fn encrypt_layers(
    plaintext: &[u8],
    source: KeySource,
    layers: u32,
    algorithm: AeadId,
    metadata: &str,
    policy: &LayerPolicy,
) -> Result<Vec<u8>, CryptoError> {
    if layers == 0 {
        return Err(CryptoError::fail("ECRYPT-001", "at least one encryption layer is required"));
    }
    if layers > policy.max_layers {
        return Err(CryptoError::fail(
            "ECRYPT-001",
            format!(
                "requested {} layers exceeds the configured maximum of {} (see max_crypto_layers policy)",
                layers, policy.max_layers
            ),
        ));
    }
    if metadata.len() as u64 > format::MAX_METADATA_LEN as u64 {
        return Err(CryptoError::fail("EHEX-006", "metadata too large"));
    }
    let (salt, kdf, kdf_param) = match source {
        KeySource::Password(_) => {
            let params = kdf::Argon2Params::default();
            let salt = crate::random::salt16()?;
            (salt.to_vec(), Some(KdfId::Argon2id), format::kdf_param_word(params.m_cost_kib, params.t_cost))
        }
        KeySource::RawKey(_) => {
            let salt = crate::random::salt16()?;
            (salt.to_vec(), None, 0)
        }
    };
    let master = derive_master(&source, &salt)?;

    let mut current = Zeroizing::new(plaintext.to_vec());
    let mut records: Vec<LayerRecord> = Vec::with_capacity(layers as usize);
    // Header nonce: fresh random HKDF context, not an AEAD nonce.
    let outer_nonce = crate::random::nonce12()?;
    let hexa = HexaFile {
        format_version: format::FORMAT_VERSION,
        flags: format::FLAG_AUTHENTICATED,
        algorithm,
        kdf,
        kdf_param,
        salt,
        outer_nonce: outer_nonce.to_vec(),
        layer_count: layers,
        metadata: metadata.to_string(),
        layers: Vec::new(),
    };
    for i in 0..layers {
        let layer_key = layer_key(&master, i, algorithm)?;
        let nonce = crate::random::nonce12()?;
        let sealed = aead::encrypt(algorithm, &*layer_key, &nonce, &current, &header_aad(&hexa, &outer_nonce))?;
        let ct = sealed.ciphertext_tag;
        records.push(LayerRecord { algorithm, nonce: nonce.to_vec(), ciphertext_tag: ct.clone() });
        current = Zeroizing::new(ct);
    }
    let mut hexa = hexa;
    hexa.layers = records;
    format::serialize(&hexa)
}

/// Decrypt a serialized .hexa file. Any wrong key, wrong password,
/// tampered byte, or truncation yields the same generic EKEY-003 error.
pub fn decrypt_bytes(bytes: &[u8], source: &KeySource) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let hexa = format::parse(bytes)?;
    decrypt_file(&hexa, source)
}

/// Decrypt a parsed .hexa structure.
pub fn decrypt_file(hexa: &HexaFile, source: &KeySource) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if hexa.layer_count as usize != hexa.layers.len() {
        return Err(CryptoError::auth_failed());
    }
    let source = match (&hexa.kdf, source) {
        (Some(_), KeySource::Password(_)) => source,
        (None, KeySource::RawKey(_)) => source,
        (Some(k), KeySource::RawKey(_)) => {
            return Err(CryptoError::fail(
                "EKEY-001",
                format!("this file was encrypted with a password (kdf {}); supply --prompt-key", k.name()),
            ))
        }
        (None, KeySource::Password(_)) => {
            return Err(CryptoError::fail(
                "EKEY-001",
                "this file was encrypted with a raw HX- key, not a password",
            ))
        }
    };
    let master = derive_master(source, &hexa.salt)?;
    let mut current = Zeroizing::new(Vec::new());
    for (i, record) in hexa.layers.iter().enumerate().rev() {
        let layer_key = layer_key(&master, i as u32, record.algorithm)?;
        let pt = aead::decrypt(
            record.algorithm,
            &*layer_key,
            &record.nonce,
            if current.is_empty() { &record.ciphertext_tag } else { &current },
            &header_aad(hexa, &hexa.outer_nonce),
        )?;
        current = Zeroizing::new(pt.to_vec());
    }
    Ok(current)
}

fn derive_master(source: &KeySource, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let ikm: Zeroizing<Vec<u8>> = match source {
        KeySource::RawKey(k) => {
            if k.len() != 32 {
                return Err(CryptoError::fail("EKEY-002", "raw keys must be 32 bytes"));
            }
            Zeroizing::new(k.clone())
        }
        KeySource::Password(p) => {
            let (m, t) = (kdf::Argon2Params::default().m_cost_kib, kdf::Argon2Params::default().t_cost);
            let params = kdf::Argon2Params { m_cost_kib: m, t_cost: t, p_cost: 1 };
            let k = kdf::argon2id_key(p, salt, &params)?;
            Zeroizing::new(k.to_vec())
        }
    };
    let master = kdf::hkdf_sha256_extract_expand(salt, &ikm, MASTER_INFO, 32)?;
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&master);
    Ok(out)
}

fn layer_key(master: &[u8; 32], index: u32, algorithm: AeadId) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let info = format!("hexa/layer/{}/{}", index, algorithm.name());
    let okm = kdf::hkdf_sha256_expand(master, info.as_bytes(), 32)?;
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&okm);
    Ok(out)
}

/// The entire logical header is authenticated as AAD on every layer, so
/// ANY tampering with flags, algorithm, kdf, salt, kdf parameters, or
/// metadata breaks authentication on all layers at once.
fn header_aad(hexa: &HexaFile, context_nonce: &[u8]) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(format::MAGIC);
    aad.push(hexa.format_version);
    aad.push(hexa.flags);
    aad.push(format::algo_byte(hexa.algorithm));
    aad.push(match hexa.kdf { Some(k) => format::kdf_byte(k), None => 0 });
    aad.push(hexa.salt.len() as u8);
    aad.extend_from_slice(&hexa.salt);
    aad.extend_from_slice(&hexa.kdf_param.to_be_bytes());
    aad.extend_from_slice(hexa.metadata.as_bytes());
    aad.extend_from_slice(context_nonce);
    aad
}

/// Rough cost estimate for a layer plan. Deliberately conservative and
/// honest: it is an estimate, not a guarantee.
pub fn estimate_cost(layers: u32, payload_len: usize) -> (f64, Vec<String>) {
    let mut warnings = Vec::new();
    // ~1 GB/s AEAD throughput on modern x86-64 (AES-NI); be pessimistic.
    let bytes = payload_len as f64 * layers as f64;
    let aead_seconds = bytes / (1024.0 * 1024.0 * 1024.0);
    let argon_seconds = 0.5; // ~default Argon2id parameters on a modern laptop
    let total = aead_seconds + argon_seconds;
    if layers > WARN_LAYER_COUNT {
        warnings.push(format!(
            "WARNING: {} encryption layers is far beyond what improves security; each layer adds cost without adding meaningful strength.",
            layers
        ));
    }
    if total > WARN_ESTIMATED_SECONDS {
        warnings.push(format!(
            "WARNING: estimated {:.0}s of CPU time for {} layers. Continue? [y/N]",
            total, layers
        ));
    }
    (total, warnings)
}

/// Constant-time comparison exposed for tag checks in tests.
pub fn tags_equal(a: &[u8], b: &[u8]) -> bool {
    ct_eq(a, b)
}
