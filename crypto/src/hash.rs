//! Hash functions: SHA-2, SHA-3, BLAKE2, BLAKE3.
//!
//! Hashing is not encryption and a hash is not a password key: for
//! passwords use the KDF module (memory-hard derivation).

use crate::error::CryptoError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashId {
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_512,
    Blake2s256,
    Blake2b512,
    Blake3,
}

impl HashId {
    pub fn name(&self) -> &'static str {
        match self {
            HashId::Sha256 => "sha256",
            HashId::Sha384 => "sha384",
            HashId::Sha512 => "sha512",
            HashId::Sha3_256 => "sha3-256",
            HashId::Sha3_512 => "sha3-512",
            HashId::Blake2s256 => "blake2s-256",
            HashId::Blake2b512 => "blake2b-512",
            HashId::Blake3 => "blake3",
        }
    }
    pub fn from_name(name: &str) -> Option<HashId> {
        match name.to_ascii_lowercase().as_str() {
            "sha256" | "sha-256" => Some(HashId::Sha256),
            "sha384" | "sha-384" => Some(HashId::Sha384),
            "sha512" | "sha-512" => Some(HashId::Sha512),
            "sha3-256" | "sha3_256" => Some(HashId::Sha3_256),
            "sha3-512" | "sha3_512" => Some(HashId::Sha3_512),
            "blake2s-256" | "blake2s256" => Some(HashId::Blake2s256),
            "blake2b-512" | "blake2b512" => Some(HashId::Blake2b512),
            "blake3" => Some(HashId::Blake3),
            _ => None,
        }
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}

pub fn sha384(data: &[u8]) -> [u8; 48] {
    use sha2::Digest;
    sha2::Sha384::digest(data).into()
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    use sha2::Digest;
    sha2::Sha512::digest(data).into()
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    sha3::Sha3_256::digest(data).into()
}

pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    use sha3::Digest;
    sha3::Sha3_512::digest(data).into()
}

pub fn blake2s256(data: &[u8]) -> [u8; 32] {
    use blake2::Digest;
    blake2::Blake2s256::digest(data).into()
}

pub fn blake2b512(data: &[u8]) -> [u8; 64] {
    use blake2::Digest;
    blake2::Blake2b512::digest(data).into()
}

pub fn blake3(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Hash `data` with the identified algorithm. Unknown ids fail closed.
pub fn hash(id: HashId, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(match id {
        HashId::Sha256 => sha256(data).to_vec(),
        HashId::Sha384 => sha384(data).to_vec(),
        HashId::Sha512 => sha512(data).to_vec(),
        HashId::Sha3_256 => sha3_256(data).to_vec(),
        HashId::Sha3_512 => sha3_512(data).to_vec(),
        HashId::Blake2s256 => blake2s256(data).to_vec(),
        HashId::Blake2b512 => blake2b512(data).to_vec(),
        HashId::Blake3 => blake3(data).to_vec(),
    })
}
