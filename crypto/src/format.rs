//! The versioned .hexa binary container format (v1).
//!
//! Layout (big-endian multi-byte integers):
//!   offset  size  field
//!   0       5     MAGIC  = "HEXA1\n" (spec says MAGIC then VERSION; the
//!                       trailing '1' is the format version 1 byte, so the
//!                       magic itself pins the major version)
//!   5       1     VERSION = 0x01 (format version, redundant check)
//!   6       1     FLAGS  = 0x01 authenticated payload (always set in v1)
//!   7       1     ALGORITHM id (aead::AeadId)
//!   8       1     KDF id (kdf::KdfId, 0 = raw key)
//!   9       1     SALT length (0..=255)
//!   10      12    NONCE of the OUTER AEAD layer
//!   22      4     LAYER_COUNT (u32, policy-capped)
//!   26      4     METADATA_LENGTH (u32)
//!   30      4     KDF param word (Argon2: m_cost_kib/64 in low 24 bits,
//!                       t_cost in bits 24..31; see kdf_param_word)
//!   34      N     SALT
//!   34+N    M     METADATA (UTF-8, validated before use)
//!   then    L     PAYLOAD: layer records: [u8 algo_id][12 nonce][rest ct+tag]
//!   last 8  8     TRAILER: magic "HEXAEND1" (8 bytes)
//!
//! Every read is bounds-checked; lengths are validated against remaining
//! input; metadata is UTF-8 checked and hard-capped. Malformed input
//! yields structured EHEX-xxx errors, never a panic.

use crate::error::CryptoError;

pub const MAGIC: &[u8; 6] = b"HEXA1\n";
pub const TRAILER: &[u8; 8] = b"HEXAEND1";
pub const FLAG_AUTHENTICATED: u8 = 0x01;
pub const FORMAT_VERSION: u8 = 1;

/// Hard caps so hostile files cannot trigger pathological allocations.
pub const MAX_METADATA_LEN: u32 = 64 * 1024;
pub const MAX_SALT_LEN: usize = 255;
pub const MAX_LAYERS: u32 = 100_000;

/// The parsed contents of a .hexa file.
#[derive(Clone, Debug)]
pub struct HexaFile {
    pub format_version: u8,
    pub flags: u8,
    pub algorithm: crate::aead::AeadId,
    pub kdf: Option<crate::kdf::KdfId>,
    pub kdf_param: u32,
    pub salt: Vec<u8>,
    pub outer_nonce: Vec<u8>,
    pub layer_count: u32,
    pub metadata: String,
    /// Layer records in order: (algorithm, nonce, ciphertext+tag).
    pub layers: Vec<LayerRecord>,
}

#[derive(Clone, Debug)]
pub struct LayerRecord {
    pub algorithm: crate::aead::AeadId,
    pub nonce: Vec<u8>,
    pub ciphertext_tag: Vec<u8>,
}

fn err(code: &'static str, detail: impl Into<String>) -> CryptoError {
    CryptoError::malformed(code, detail)
}

fn take<'a>(input: &mut &'a [u8], n: usize, code: &'static str, what: &str) -> Result<&'a [u8], CryptoError> {
    if input.len() < n {
        return Err(err(code, format!("file truncated while reading {} (need {} bytes, have {})", what, n, input.len())));
    }
    let (head, tail) = input.split_at(n);
    *input = tail;
    Ok(head)
}

fn u8_at(input: &mut &[u8], code: &'static str, what: &str) -> Result<u8, CryptoError> {
    Ok(take(input, 1, code, what)?[0])
}

fn u32_at(input: &mut &[u8], code: &'static str, what: &str) -> Result<u32, CryptoError> {
    let b = take(input, 4, code, what)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Serialize a .hexa file.
pub fn serialize(f: &HexaFile) -> Result<Vec<u8>, CryptoError> {
    if f.format_version != FORMAT_VERSION {
        return Err(err("EHEX-002", "only format version 1 can be written"));
    }
    if f.flags & FLAG_AUTHENTICATED == 0 {
        return Err(err("EHEX-009", "refusing to write an unauthenticated .hexa payload"));
    }
    if f.layer_count as usize != f.layers.len() || f.layers.is_empty() {
        return Err(err("EHEX-007", "layer_count must equal number of layer records (at least 1)"));
    }
    if f.layer_count > MAX_LAYERS {
        return Err(err("EHEX-007", "layer count exceeds format maximum"));
    }
    let md = f.metadata.as_bytes();
    if md.len() as u64 > MAX_METADATA_LEN as u64 {
        return Err(err("EHEX-006", "metadata too large"));
    }
    if f.salt.len() > MAX_SALT_LEN {
        return Err(err("EHEX-005", "salt too long"));
    }
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(f.format_version);
    out.push(f.flags);
    out.push(algo_byte(f.algorithm));
    out.push(match f.kdf { Some(k) => kdf_byte(k), None => 0 });
    out.push(f.salt.len() as u8);
    if f.outer_nonce.len() != 12 {
        return Err(err("ENONCE-001", "outer nonce must be 12 bytes"));
    }
    out.extend_from_slice(&f.outer_nonce);
    out.extend_from_slice(&f.layer_count.to_be_bytes());
    out.extend_from_slice(&(md.len() as u32).to_be_bytes());
    out.extend_from_slice(&f.kdf_param.to_be_bytes());
    out.extend_from_slice(&f.salt);
    out.extend_from_slice(md);
    for layer in &f.layers {
        if layer.nonce.len() != 12 {
            return Err(err("ENONCE-001", "layer nonce must be 12 bytes"));
        }
        out.push(algo_byte(layer.algorithm));
        out.extend_from_slice(&layer.nonce);
        out.extend_from_slice(&layer.ciphertext_tag);
    }
    out.extend_from_slice(TRAILER);
    Ok(out)
}

/// Parse and validate a .hexa file. Never panics on malformed input.
pub fn parse(bytes: &[u8]) -> Result<HexaFile, CryptoError> {
    let mut input = bytes;
    let magic = take(&mut input, 6, "EHEX-001", "magic")?;
    if magic != MAGIC {
        return Err(err("EHEX-001", "not a .hexa file (bad magic)"));
    }
    let version = u8_at(&mut input, "EHEX-002", "format version")?;
    if version != FORMAT_VERSION {
        return Err(err("EHEX-002", format!("unsupported .hexa format version {}", version)));
    }
    let flags = u8_at(&mut input, "EHEX-003", "flags")?;
    if flags & FLAG_AUTHENTICATED == 0 {
        return Err(err("EHEX-003", "unauthenticated .hexa payloads are not supported"));
    }
    let algo_b = u8_at(&mut input, "EHEX-004", "algorithm id")?;
    let algorithm = parse_algo(algo_b)?;
    let kdf_b = u8_at(&mut input, "EHEX-004", "kdf id")?;
    let kdf = parse_kdf(kdf_b)?;
    let salt_len = u8_at(&mut input, "EHEX-005", "salt length")? as usize;
    let outer_nonce = take(&mut input, 12, "EHEX-005", "nonce")?.to_vec();
    let layer_count = u32_at(&mut input, "EHEX-006", "layer count")?;
    if layer_count == 0 || layer_count > MAX_LAYERS {
        return Err(err("EHEX-007", format!("invalid layer count {}", layer_count)));
    }
    let meta_len = u32_at(&mut input, "EHEX-006", "metadata length")?;
    if meta_len > MAX_METADATA_LEN {
        return Err(err("EHEX-006", format!("metadata length {} exceeds cap {}", meta_len, MAX_METADATA_LEN)));
    }
    let kdf_param = u32_at(&mut input, "EHEX-006", "kdf parameters")?;
    let salt = take(&mut input, salt_len, "EHEX-005", "salt")?.to_vec();
    let metadata_bytes = take(&mut input, meta_len as usize, "EHEX-006", "metadata")?;
    let metadata = std::str::from_utf8(metadata_bytes)
        .map_err(|_| err("EHEX-006", "metadata is not valid UTF-8"))?.to_string();

    // Payload layout is structural: each layer record is a 13-byte header
    // ([algo_id][nonce12]) followed by that layer's ciphertext+tag. Every
    // AEAD layer APPENDS a 16-byte tag, so if ct_i is the ciphertext length
    // of record i (in encryption order), then ct_i = ct_0 + 16*i and
    //   payload_len = 13*L + L*ct_0 + 16*(0+1+...+(L-1))
    //               = 13*L + L*ct_0 + 8*L*(L-1)
    //   =>  ct_0 = (payload_len - 13*L - 8*L*(L-1)) / L  (must divide exactly)
    if input.len() < TRAILER.len() {
        return Err(err("EHEX-008", "missing .hexa trailer"));
    }
    let payload_len = (input.len() - TRAILER.len()) as i64;
    let l = layer_count as i64;
    let numer = payload_len - 13 * l - 8 * l * (l - 1);
    if numer < 0 || numer % l != 0 {
        return Err(err("EHEX-008", "payload layout inconsistent with declared layer count"));
    }
    let ct0 = numer / l;
    if ct0 < 16 {
        return Err(err("EHEX-008", "innermost layer payload shorter than an AEAD tag"));
    }
    let mut ct_len = ct0 as usize;
    let mut layers = Vec::with_capacity(layer_count.min(4096) as usize);
    for i in 0..layer_count {
        let algo_b = u8_at(&mut input, "EHEX-004", &format!("layer {} algorithm", i))?;
        let lalgo = parse_algo(algo_b)?;
        let lnonce = take(&mut input, 12, "EHEX-008", &format!("layer {} nonce", i))?.to_vec();
        let ciphertext_tag = take(&mut input, ct_len, "EHEX-008", &format!("layer {} payload", i))?.to_vec();
        if i + 1 < layer_count {
            ct_len = ct_len
                .checked_add(16)
                .ok_or_else(|| err("EHEX-008", "layer payload size overflow"))?;
        }
        layers.push(LayerRecord { algorithm: lalgo, nonce: lnonce, ciphertext_tag });
    }
    let trailer = take(&mut input, TRAILER.len(), "EHEX-008", "trailer")?;
    if trailer != TRAILER {
        return Err(err("EHEX-008", "bad trailer (file is truncated or corrupt)"));
    }
    if !input.is_empty() {
        return Err(err("EHEX-008", "trailing garbage after .hexa trailer"));
    }
    Ok(HexaFile {
        format_version: version,
        flags,
        algorithm,
        kdf,
        kdf_param,
        salt,
        outer_nonce,
        layer_count,
        metadata,
        layers,
    })
}

pub fn algo_byte(a: crate::aead::AeadId) -> u8 {
    match a {
        crate::aead::AeadId::Aes256Gcm => 1,
        crate::aead::AeadId::ChaCha20Poly1305 => 2,
    }
}

fn parse_algo(b: u8) -> Result<crate::aead::AeadId, CryptoError> {
    match b {
        1 => Ok(crate::aead::AeadId::Aes256Gcm),
        2 => Ok(crate::aead::AeadId::ChaCha20Poly1305),
        other => Err(err("EHEX-004", format!("unknown algorithm id {}", other))),
    }
}

pub fn kdf_byte(k: crate::kdf::KdfId) -> u8 {
    match k {
        crate::kdf::KdfId::Argon2id => 1,
        crate::kdf::KdfId::Scrypt => 2,
        crate::kdf::KdfId::Pbkdf2Sha256 => 3,
    }
}

fn parse_kdf(b: u8) -> Result<Option<crate::kdf::KdfId>, CryptoError> {
    match b {
        0 => Ok(None),
        1 => Ok(Some(crate::kdf::KdfId::Argon2id)),
        2 => Ok(Some(crate::kdf::KdfId::Scrypt)),
        3 => Ok(Some(crate::kdf::KdfId::Pbkdf2Sha256)),
        other => Err(err("EHEX-004", format!("unknown kdf id {}", other))),
    }
}

/// Pack Argon2id parameters into the 32-bit kdf_param word:
/// bits 0..23 = m_cost_kib (KiB, stored /64 to widen range), bits 24..31 = t_cost.
pub fn kdf_param_word(m_cost_kib: u32, t_cost: u32) -> u32 {
    let m = (m_cost_kib / 64).min(0xFF_FFFF);
    let t = t_cost.min(0xFF);
    (m & 0x00FF_FFFF) | (t << 24)
}

/// Unpack the kdf_param word.
pub fn kdf_param_unpack(word: u32) -> (u32, u32) {
    let m = (word & 0x00FF_FFFF) * 64;
    let t = word >> 24;
    (m, t)
}
