//! Standard-library prelude: the signatures of std functions known to the
//! type checker and security analyzer.
//!
//! This is the canonical API surface of the HEXA standard library. The
//! corresponding `std/*.he` reference files document these same signatures.

use crate::types::{SecretKind, Type};

#[derive(Clone, Debug)]
pub struct FnSig {
    pub full_name: &'static str,
    pub params: Vec<(&'static str, Type)>,
    pub ret: Option<Type>,
    /// true if a native runtime binding exists for code generation.
    pub has_runtime: bool,
}

fn seq(name: &'static str, params: Vec<(&'static str, Type)>, ret: Option<Type>) -> FnSig {
    FnSig { full_name: name, params, ret, has_runtime: false }
}

fn any() -> Type { Type::Any }
fn text() -> Type { Type::Text }
fn integer() -> Type { Type::Integer }
fn boolean() -> Type { Type::Boolean }
fn bytes() -> Type { Type::Bytes }
fn unit() -> Type { Type::Unit }
fn plaintext() -> Type { Type::Plaintext }
fn ciphertext() -> Type { Type::Ciphertext }
fn key() -> Type { Type::Secret(SecretKind::Key) }
fn pk() -> Type { Type::Secret(SecretKind::PublicKey) }
fn sk() -> Type { Type::Secret(SecretKind::PrivateKey) }
fn sig() -> Type { Type::Secret(SecretKind::Signature) }
fn password() -> Type { Type::Secret(SecretKind::Password) }

/// The canonical, versioned std function table.
pub fn prelude_fns() -> Vec<FnSig> {
    use Type::*;
    vec![
        // --- io ---
        seq("print", vec![("value", any())], Some(unit())),
        seq("print_line", vec![("value", any())], Some(unit())),
        seq("std.io.print", vec![("value", any())], Some(unit())),
        seq("std.io.println", vec![("value", any())], Some(unit())),
        seq("input.text", vec![("prompt", text())], Some(text())),
        seq("input.integer", vec![("prompt", text())], Some(integer())),
        seq("secret.input", vec![("prompt", text())], Some(password())),
        // --- file system ---
        seq("std.fs.read", vec![("path", text())], Some(text())),
        seq("std.fs.read_bytes", vec![("path", text())], Some(bytes())),
        seq("std.fs.write", vec![("path", text()), ("data", text())], Some(unit())),
        seq("file.read", vec![("path", text())], Some(text())),
        seq("file.read_bytes", vec![("path", text())], Some(bytes())),
        seq("file.write", vec![("path", text()), ("data", any())], Some(unit())),
        // --- high-level crypto ---
        seq("crypto.key.generate", vec![("bits", integer())], Some(key())),
        seq("crypto.key.generate", vec![("entropy", bytes())], Some(key())),
        seq("crypto.encrypt.aes256_gcm", vec![("data", plaintext()), ("key", key())], Some(ciphertext())),
        seq("crypto.encrypt.chacha20_poly1305", vec![("data", plaintext()), ("key", key())], Some(ciphertext())),
        seq("crypto.decrypt.aes256_gcm", vec![("data", ciphertext()), ("key", key())], Some(plaintext())),
        seq("crypto.decrypt.chacha20_poly1305", vec![("data", ciphertext()), ("key", key())], Some(plaintext())),
        seq("crypto.encrypt.layers", vec![("data", plaintext()), ("layers", integer())], Some(ciphertext())),
        // --- hashing ---
        seq("crypto.hash.sha256", vec![("data", bytes())], Some(Secret(SecretKind::Hash))),
        seq("crypto.hash.sha384", vec![("data", bytes())], Some(Secret(SecretKind::Hash))),
        seq("crypto.hash.sha512", vec![("data", bytes())], Some(Secret(SecretKind::Hash))),
        seq("crypto.hash.sha3_256", vec![("data", bytes())], Some(Secret(SecretKind::Hash))),
        seq("crypto.hash.sha3_512", vec![("data", bytes())], Some(Secret(SecretKind::Hash))),
        seq("crypto.hash.blake2b", vec![("data", bytes())], Some(Secret(SecretKind::Hash))),
        seq("crypto.hash.blake3", vec![("data", bytes())], Some(Secret(SecretKind::Hash))),
        // --- KDF ---
        seq("crypto.kdf.argon2id", vec![("password", bytes()), ("salt", bytes())], Some(key())),
        seq("crypto.kdf.scrypt", vec![("password", bytes()), ("salt", bytes())], Some(key())),
        seq("crypto.kdf.pbkdf2", vec![("password", bytes()), ("salt", bytes())], Some(key())),
        seq("crypto.kdf.hkdf", vec![("ikm", bytes()), ("salt", bytes()), ("info", bytes())], Some(key())),
        // --- signatures ---
        seq("crypto.sign.ed25519", vec![("message", bytes()), ("private_key", sk())], Some(sig())),
        seq("crypto.verify.ed25519", vec![("message", bytes()), ("signature", sig()), ("public_key", pk())], Some(boolean())),
        seq("crypto.keypair.ed25519", vec![("seed", bytes())], Some(Tuple(vec![sk(), pk()]))),
        // --- key exchange ---
        seq("crypto.keyexchange.x25519", vec![("private_key", sk()), ("public_key", pk())], Some(key())),
        // --- secret handling ---
        seq("secret.export", vec![("value", any())], Some(text())),
        seq("secret.wipe", vec![("value", any())], Some(unit())),
        // --- encoding ---
        seq("std.encoding.base64_encode", vec![("data", bytes())], Some(text())),
        seq("std.encoding.base64_decode", vec![("data", text())], Some(bytes())),
        seq("std.encoding.hex_encode", vec![("data", bytes())], Some(text())),
        seq("std.encoding.hex_decode", vec![("data", text())], Some(bytes())),
        // --- random ---
        seq("std.random.bytes", vec![("count", integer())], Some(bytes())),
        seq("random.bytes", vec![("count", integer())], Some(bytes())),
        seq("random.seed", vec![("seed", integer())], Some(unit())),
        // --- misc ---
        seq("std.assert", vec![( "condition", boolean())], Some(unit())),
        seq("to_text", vec![("value", any())], Some(text())),
        seq("len", vec![("value", any())], Some(integer())),
    ]
}

/// Look up all std signatures matching a dotted path.
pub fn lookup(full_name: &str) -> Vec<FnSig> {
    prelude_fns().into_iter().filter(|f| f.full_name == full_name).collect()
}
