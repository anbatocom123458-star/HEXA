//! Ed25519 digital signatures.

use crate::error::CryptoError;
use ed25519_dalek::Signer;
use ed25519_dalek::Verifier;
use zeroize::Zeroizing;

/// An Ed25519 signing keypair. The seed is zeroized on drop.
pub struct SigningKey {
    seed: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl SigningKey {
    /// Generate a new keypair from the OS CSPRNG.
    pub fn generate() -> Result<SigningKey, CryptoError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        crate::random::fill(seed.as_mut())?;
        Self::from_seed(*seed)
    }

    /// Reconstruct a signing keypair from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Result<SigningKey, CryptoError> {
        let sk = ed25519_dalek::SecretKey::from_bytes(&seed)
            .map_err(|_| CryptoError::fail("EKEY-002", "invalid Ed25519 seed"))?;
        let pk = ed25519_dalek::PublicKey::from(&sk);
        Ok(SigningKey { seed: Zeroizing::new(seed), public: pk.to_bytes() })
    }

    /// Public key bytes (safe to share).
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public
    }

    /// Sign a message, returning the 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], CryptoError> {
        let arr: [u8; 32] = *self.seed;
        let sk = ed25519_dalek::SecretKey::from_bytes(&arr)
            .map_err(|_| CryptoError::fail("EKEY-002", "invalid Ed25519 seed"))?;
        let pk = ed25519_dalek::PublicKey::from_bytes(&self.public)
            .map_err(|_| CryptoError::fail("EKEY-002", "invalid public key"))?;
        let kp = ed25519_dalek::Keypair { secret: sk, public: pk };
        let sig = kp.sign(message);
        Ok(sig.to_bytes())
    }
}

/// Verify an Ed25519 signature. Returns Ok(()) only for valid signatures.
pub fn verify(message: &[u8], signature64: &[u8], public32: &[u8]) -> Result<(), CryptoError> {
    if signature64.len() != 64 || public32.len() != 32 {
        return Err(CryptoError::fail("ESIG-001", "malformed signature or public key"));
    }
    let pk = ed25519_dalek::PublicKey::from_bytes(public32)
        .map_err(|_| CryptoError::fail("ESIG-001", "malformed public key"))?;
    let sig = ed25519_dalek::Signature::from_bytes(signature64.try_into().expect("checked 64-byte length above"))
        .map_err(|_| CryptoError::fail("ESIG-001", "malformed signature"))?;
    pk.verify(message, &sig)
        .map_err(|_| CryptoError::fail("ESIG-002", "signature verification failed"))
}
