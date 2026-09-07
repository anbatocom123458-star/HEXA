//! Secret-memory abstraction.
//!
//! `Secret<T>` wraps a sensitive value so that it must be explicitly used,
//! is redacted in logs/debug output, and is zeroized when destroyed.
//!
//! Honest limitation: zeroization clears the memory HEXA controls. The OS,
//! compiler-produced temporaries, swap, core dumps, and hardware caches may
//! retain copies that no user-space program can guarantee to erase.

use zeroize::{Zeroize, Zeroizing};

/// A wrapper that redacts its contents from any derived output.
pub struct Secret<T: Zeroize> {
    value: Option<T>,
}

impl<T: Zeroize> Secret<T> {
    /// Wrap a sensitive value.
    pub fn create(value: T) -> Secret<T> {
        Secret { value: Some(value) }
    }

    /// Read-only use of the secret.
    pub fn use_value<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        match &self.value {
            Some(v) => f(v),
            None => panic("use of destroyed secret"),
        }
    }

    /// Mutable use of the secret.
    pub fn use_mut<R>(&mut self, f: impl FnOnce(&mut T) -> R) -> R {
        match &mut self.value {
            Some(v) => f(v),
            None => panic("use of destroyed secret"),
        }
    }

    /// Explicitly clear the secret. After this the secret is destroyed.
    pub fn zeroize_now(&mut self) {
        if let Some(v) = &mut self.value {
            v.zeroize();
        }
        self.value = None;
    }

    /// Destroy alias (same semantics as zeroize_now).
    pub fn destroy(&mut self) {
        self.zeroize_now();
    }

    pub fn is_destroyed(&self) -> bool {
        self.value.is_none()
    }

    /// Deliberately unwrap the secret (an explicit, greppable action).
    pub fn into_inner(mut self) -> T {
        match self.value.take() {
            Some(v) => v,
            None => panic("use of destroyed secret"),
        }
    }
}

fn panic(msg: &str) -> ! {
    std::panic::panic_any(format!("hexa-crypto: {}", msg))
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.zeroize_now();
    }
}

// Redacted logging: a Secret never prints its contents.
impl<T: Zeroize> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret(REDACTED)")
    }
}

impl<T: Zeroize> std::fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "REDACTED")
    }
}

/// Common alias: secret byte buffer (zeroized on drop).
pub type SecretBytes = Zeroizing<Vec<u8>>;

/// Common alias: 32-byte symmetric key (zeroized on drop).
pub type SecretKey32 = Zeroizing<[u8; 32]>;

/// Constant-time equality for MAC/tag comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
