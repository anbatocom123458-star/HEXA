//! X25519 key exchange (elliptic-curve Diffie-Hellman).

use crate::error::CryptoError;
use zeroize::Zeroizing;

/// An X25519 secret key. Zeroized on drop (via the zeroize feature).
pub struct ExchangeSecret {
    secret: x25519_dalek::StaticSecret,
}

impl ExchangeSecret {
    /// Generate a new X25519 secret from the OS CSPRNG.
    pub fn generate() -> Result<ExchangeSecret, CryptoError> {
        let mut seed = [0u8; 32];
        crate::random::fill(&mut seed)?;
        Ok(ExchangeSecret { secret: x25519_dalek::StaticSecret::from(seed) })
    }

    /// Reconstruct from 32 secret bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> ExchangeSecret {
        ExchangeSecret { secret: x25519_dalek::StaticSecret::from(bytes) }
    }

    /// Public key bytes (safe to share).
    pub fn public_bytes(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.secret).to_bytes()
    }

    /// Perform the Diffie-Hellman exchange with the peer's public key.
    /// The shared secret is zeroized on drop.
    pub fn diffie_hellman(&self, peer_public: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let pk = x25519_dalek::PublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&pk);
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(shared.as_bytes());
        Ok(out)
    }
}
