//! HEXA runtime registry: the C-ABI boundary between HEXA-compiled native
//! programs and the toolchain's cryptography subsystem.
//!
//! Design goals (Phase: packaging/runtime):
//!   * The ABI is versioned (`HEXA_RT_ABI_VERSION`); a mismatch is detected
//!     by the guest via `hexa_sys_init` returning STATUS_EINVAL.
//!   * Every function is `extern "C"`, `#[no_mangle]`, and never panics
//!     across the boundary (all fallible operations return status codes).
//!   * The interface is a provider surface: algorithms are addressed by id,
//!     so new AEAD/KDF/hash providers can be added without changing the ABI.
//!
//! Nothing here is a mock: the implementations call the real
//! AES-256-GCM / ChaCha20-Poly1305 / SHA-2 / BLAKE2 / BLAKE3 / Argon2id /
//! OS-CSPRNG code in the rest of this crate.

use crate::aead::{self, AeadId};
use crate::encoding;
use crate::error::CryptoError;
use crate::hash::{self, HashId};
use crate::kdf::{self, KdfId};
use crate::random;
use crate::{format, key};
use std::cell::RefCell;
use std::collections::HashMap;

/// ABI version of this registry. Bump on any interface change.
pub const HEXA_RT_ABI_VERSION: u64 = 1;

/// Algorithm id bytes, pinned to the .hexa v1 wire format (`format::algo_byte`).
pub const AEAD_AES256_GCM: u8 = 1;
pub const AEAD_CHACHA20_POLY1305: u8 = 2;
/// KDF id bytes, pinned to the .hexa v1 wire format (`format::kdf_byte`).
pub const KDF_ARGON2ID: u8 = 1;
/// Hash provider ids for `hexa_crypto_hash` (runtime-ABI stable numbering).
pub const HASH_SHA256: u8 = 1;
pub const HASH_SHA384: u8 = 2;
pub const HASH_SHA512: u8 = 3;
pub const HASH_SHA3_256: u8 = 4;
pub const HASH_SHA3_512: u8 = 5;
pub const HASH_BLAKE2S256: u8 = 6;
pub const HASH_BLAKE2B512: u8 = 7;
pub const HASH_BLAKE3: u8 = 8;

fn aead_id_from_u8(b: u8) -> Option<AeadId> {
    match b {
        AEAD_AES256_GCM => Some(AeadId::Aes256Gcm),
        AEAD_CHACHA20_POLY1305 => Some(AeadId::ChaCha20Poly1305),
        _ => None,
    }
}

fn hash_id_from_u8(b: u8) -> Option<HashId> {
    match b {
        HASH_SHA256 => Some(HashId::Sha256),
        HASH_SHA384 => Some(HashId::Sha384),
        HASH_SHA512 => Some(HashId::Sha512),
        HASH_SHA3_256 => Some(HashId::Sha3_256),
        HASH_SHA3_512 => Some(HashId::Sha3_512),
        HASH_BLAKE2S256 => Some(HashId::Blake2s256),
        HASH_BLAKE2B512 => Some(HashId::Blake2b512),
        HASH_BLAKE3 => Some(HashId::Blake3),
        _ => None,
    }
}

/// Status codes returned across the C ABI.
pub const STATUS_OK: i64 = 0;
pub const STATUS_EINVAL: i64 = -1; // invalid argument
pub const STATUS_ENOMEM: i64 = -2; // output buffer too small (len returned)
pub const STATUS_EKEY: i64 = -3; // key/auth failure (wrong key, tampered)
pub const STATUS_ECRYPTO: i64 = -4; // other crypto failure

thread_local! {
    /// Error message for the last failed call (read via hexa_rt_last_error).
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
    /// Allocations handed to the guest, tracked for exact-size frees.
    static LIVE_ALLOC: RefCell<HashMap<usize, usize>> = RefCell::new(HashMap::new());
}

fn set_err(e: &CryptoError) -> i64 {
    let msg = e.to_string();
    let code = match msg.split(':').next().unwrap_or("") {
        c if c.starts_with("EKEY") => STATUS_EKEY,
        c if c.starts_with('E') => STATUS_ECRYPTO,
        _ => STATUS_ECRYPTO,
    };
    LAST_ERROR.with(|l| *l.borrow_mut() = Some(msg));
    code
}

/// Validate guest lengths against a hard 1 GiB ceiling.
fn checked_len(len: usize) -> Result<usize, i64> {
    if len > 1 << 30 {
        Err(STATUS_EINVAL)
    } else {
        Ok(len)
    }
}

// ------------------------------------------------------------------ //
// Lifecycle
// ------------------------------------------------------------------ //

/// # Safety
/// `guest_abi` must be the ABI version the guest was linked against.
/// Returns 0 on success, STATUS_EINVAL on an ABI mismatch.
#[no_mangle]
pub unsafe extern "C" fn hexa_sys_init(guest_abi: u64) -> i64 {
    if guest_abi != HEXA_RT_ABI_VERSION {
        return STATUS_EINVAL;
    }
    STATUS_OK
}

/// # Safety
/// Always safe; idempotent.
#[no_mangle]
pub unsafe extern "C" fn hexa_sys_shutdown() -> i64 {
    STATUS_OK
}

/// Copy the last error message (NUL-terminated) into `buf`, truncating to
/// `buf_len`. Returns the full message length. Never panics.
///
/// # Safety
/// `buf` must be writable for `buf_len` bytes (may be null with len 0).
#[no_mangle]
pub unsafe extern "C" fn hexa_rt_last_error(buf: *mut u8, buf_len: usize) -> usize {
    let msg = LAST_ERROR.with(|l| l.borrow().clone()).unwrap_or_default();
    let bytes = msg.as_bytes();
    if !buf.is_null() && buf_len > 0 {
        let n = bytes.len().min(buf_len.saturating_sub(1));
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, n);
        *buf.add(n) = 0;
    }
    bytes.len()
}

// ------------------------------------------------------------------ //
// Memory: exact-size tracked allocations owned by the guest
// ------------------------------------------------------------------ //

/// Allocate `len` bytes for the guest. Returns null on failure/overflow.
#[no_mangle]
pub extern "C" fn hexa_rt_alloc(len: usize) -> *mut u8 {
    if checked_len(len).is_err() {
        return std::ptr::null_mut();
    }
    let layout = match std::alloc::Layout::from_size_align(len.max(1), 8) {
        Ok(l) => l,
        Err(_) => return std::ptr::null_mut(),
    };
    let ptr = unsafe { std::alloc::alloc(layout) };
    if !ptr.is_null() {
        LIVE_ALLOC.with(|m| m.borrow_mut().insert(ptr as usize, len));
    }
    ptr
}

/// Free a pointer obtained from hexa_rt_alloc. Unknown pointers are ignored.
///
/// # Safety
/// `ptr` must be null or a pointer returned by hexa_rt_alloc (not freed).
#[no_mangle]
pub unsafe extern "C" fn hexa_rt_free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    let len = LIVE_ALLOC.with(|m| m.borrow_mut().remove(&(ptr as usize)));
    if let Some(len) = len {
        if let Ok(layout) = std::alloc::Layout::from_size_align(len.max(1), 8) {
            std::alloc::dealloc(ptr, layout);
        }
    }
}

// ------------------------------------------------------------------ //
// CSPRNG
// ------------------------------------------------------------------ //

/// Fill `buf` with OS CSPRNG bytes. Returns STATUS_OK or a negative status.
///
/// # Safety
/// `buf` must be writable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn hexa_sys_random(buf: *mut u8, len: usize) -> i64 {
    if buf.is_null() || checked_len(len).is_err() {
        return STATUS_EINVAL;
    }
    let out = std::slice::from_raw_parts_mut(buf, len);
    match random::fill(out) {
        Ok(()) => STATUS_OK,
        Err(e) => set_err(&e),
    }
}

// ------------------------------------------------------------------ //
// Hashes: id-addressed provider surface
// ------------------------------------------------------------------ //

/// Hash `input` with the hash identified by `hash_id`.
///
/// # Safety
/// `input` readable for `input_len`; `out_len` non-null. Pass `out = null`
/// to query the required digest length (returned as a positive value).
#[no_mangle]
pub unsafe extern "C" fn hexa_crypto_hash(
    hash_id: u8,
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i64 {
    if out_len.is_null() || (input.is_null() && input_len > 0) {
        return STATUS_EINVAL;
    }
    if checked_len(input_len).is_err() {
        return STATUS_EINVAL;
    }
    let data = if input_len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(input, input_len)
    };
    let id = match hash_id_from_u8(hash_id) {
        Some(h) => h,
        None => return STATUS_EINVAL,
    };
    match hash::hash(id, data) {
        Ok(digest) => {
            let want = digest.len();
            if out.is_null() || *out_len < want {
                *out_len = want;
                return if out.is_null() { want as i64 } else { STATUS_ENOMEM };
            }
            std::ptr::copy_nonoverlapping(digest.as_ptr(), out, want);
            *out_len = want;
            STATUS_OK
        }
        Err(e) => set_err(&e),
    }
}

// ------------------------------------------------------------------ //
// AEAD
// ------------------------------------------------------------------ //

/// Authenticated encryption. `nonce_len` must match the algorithm.
///
/// # Safety
/// All pointers valid for their lengths. On success `out` receives
/// ciphertext+tag; `*out_len` is updated to the exact output length.
#[no_mangle]
pub unsafe extern "C" fn hexa_crypto_aead_encrypt(
    algo_id: u8,
    key32: *const u8,
    nonce: *const u8,
    nonce_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    aad: *const u8,
    aad_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i64 {
    if key32.is_null() || nonce.is_null() || out_len.is_null() {
        return STATUS_EINVAL;
    }
    if checked_len(plaintext_len).is_err() || checked_len(aad_len).is_err() || checked_len(nonce_len).is_err() {
        return STATUS_EINVAL;
    }
    let id = match aead_id_from_u8(algo_id) {
        Some(a) => a,
        None => return STATUS_EINVAL,
    };
    let k = std::slice::from_raw_parts(key32, 32);
    let n = std::slice::from_raw_parts(nonce, nonce_len);
    let pt = if plaintext_len == 0 { &[][..] } else { std::slice::from_raw_parts(plaintext, plaintext_len) };
    let ad = if aad_len == 0 { &[][..] } else { std::slice::from_raw_parts(aad, aad_len) };
    match aead::encrypt(id, k, n, pt, ad) {
        Ok(sealed) => {
            let want = sealed.ciphertext_tag.len();
            if out.is_null() || *out_len < want {
                *out_len = want;
                return if out.is_null() { want as i64 } else { STATUS_ENOMEM };
            }
            std::ptr::copy_nonoverlapping(sealed.ciphertext_tag.as_ptr(), out, want);
            *out_len = want;
            STATUS_OK
        }
        Err(e) => set_err(&e),
    }
}

/// Authenticated decryption. Wrong key or tampered data -> STATUS_EKEY.
///
/// # Safety
/// All pointers valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn hexa_crypto_aead_decrypt(
    algo_id: u8,
    key32: *const u8,
    nonce: *const u8,
    nonce_len: usize,
    ct_tag: *const u8,
    ct_tag_len: usize,
    aad: *const u8,
    aad_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i64 {
    if key32.is_null() || nonce.is_null() || out_len.is_null() || ct_tag.is_null() {
        return STATUS_EINVAL;
    }
    if checked_len(ct_tag_len).is_err() || checked_len(aad_len).is_err() || checked_len(nonce_len).is_err() {
        return STATUS_EINVAL;
    }
    let id = match aead_id_from_u8(algo_id) {
        Some(a) => a,
        None => return STATUS_EINVAL,
    };
    if ct_tag_len < id.tag_len() {
        return STATUS_EKEY;
    }
    let k = std::slice::from_raw_parts(key32, 32);
    let n = std::slice::from_raw_parts(nonce, nonce_len);
    let ct = std::slice::from_raw_parts(ct_tag, ct_tag_len);
    let ad = if aad_len == 0 { &[][..] } else { std::slice::from_raw_parts(aad, aad_len) };
    match aead::decrypt(id, k, n, ct, ad) {
        Ok(pt) => {
            let want = pt.len();
            if out.is_null() || *out_len < want {
                *out_len = want;
                return if out.is_null() { want as i64 } else { STATUS_ENOMEM };
            }
            std::ptr::copy_nonoverlapping(pt.as_ptr(), out, want);
            *out_len = want;
            STATUS_OK
        }
        Err(e) => set_err(&e),
    }
}

// ------------------------------------------------------------------ //
// KDF (password-based) — Argon2id only in this ABI version
// ------------------------------------------------------------------ //

/// Derive a 32-byte key from a password+salt. `kdf_id` must be the Argon2id
/// id byte; other ids return STATUS_EINVAL (the .hexa format pins Argon2id).
///
/// # Safety
/// All pointers valid for their lengths; `out` writable for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn hexa_crypto_kdf(
    kdf_id: u8,
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    m_cost_kib: u32,
    t_cost: u32,
    out: *mut u8,
) -> i64 {
    if kdf_id != KDF_ARGON2ID {
        return STATUS_EINVAL;
    }
    if password.is_null() || salt.is_null() || out.is_null() {
        return STATUS_EINVAL;
    }
    if checked_len(password_len).is_err() || salt_len == 0 || salt_len > 255 {
        return STATUS_EINVAL;
    }
    let pw = std::slice::from_raw_parts(password, password_len);
    let st = std::slice::from_raw_parts(salt, salt_len);
    let params = kdf::Argon2Params { m_cost_kib, t_cost, p_cost: 1 };
    match kdf::argon2id_key(pw, st, &params) {
        Ok(k) => {
            std::ptr::copy_nonoverlapping(k.as_ptr(), out, 32);
            STATUS_OK
        }
        Err(e) => set_err(&e),
    }
}

// ------------------------------------------------------------------ //
// .hexa container: multi-layer encrypt/decrypt under a raw 32-byte key
// ------------------------------------------------------------------ //

/// Encrypt `plaintext` into a full .hexa v1 container with `layers` AEAD
/// layers under a caller-supplied 32-byte key. Metadata is authenticated.
///
/// # Safety
/// All pointers valid for their lengths. Pass out=null to size the buffer.
#[no_mangle]
pub unsafe extern "C" fn hexa_crypto_encrypt_file(
    algo_id: u8,
    key32: *const u8,
    layers: u32,
    plaintext: *const u8,
    plaintext_len: usize,
    metadata: *const u8,
    metadata_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i64 {
    if key32.is_null() || out_len.is_null() {
        return STATUS_EINVAL;
    }
    if checked_len(plaintext_len).is_err() || checked_len(metadata_len).is_err() {
        return STATUS_EINVAL;
    }
    let id = match aead_id_from_u8(algo_id) {
        Some(a) => a,
        None => return STATUS_EINVAL,
    };
    let k = std::slice::from_raw_parts(key32, 32).to_vec();
    let pt = if plaintext_len == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(plaintext, plaintext_len).to_vec()
    };
    let md = if metadata_len == 0 {
        String::new()
    } else {
        match String::from_utf8(std::slice::from_raw_parts(metadata, metadata_len).to_vec()) {
            Ok(s) => s,
            Err(_) => return STATUS_EINVAL,
        }
    };
    let policy = crate::cipher::LayerPolicy::default();
    let src = crate::cipher::KeySource::RawKey(k);
    match crate::cipher::encrypt_layers(&pt, src, layers, id, &md, &policy) {
        Ok(bytes) => {
            let want = bytes.len();
            if out.is_null() || *out_len < want {
                *out_len = want;
                return if out.is_null() { want as i64 } else { STATUS_ENOMEM };
            }
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, want);
            *out_len = want;
            STATUS_OK
        }
        Err(e) => set_err(&e),
    }
}

/// Decrypt a full .hexa v1 container under a caller-supplied 32-byte raw key.
/// Wrong key / tampering / truncation -> STATUS_EKEY or STATUS_ECRYPTO.
///
/// # Safety
/// All pointers valid for their lengths. Pass out=null to size the buffer.
#[no_mangle]
pub unsafe extern "C" fn hexa_crypto_decrypt_file(
    data: *const u8,
    data_len: usize,
    key32: *const u8,
    out: *mut u8,
    out_len: *mut usize,
) -> i64 {
    if data.is_null() || key32.is_null() || out_len.is_null() {
        return STATUS_EINVAL;
    }
    if checked_len(data_len).is_err() {
        return STATUS_EINVAL;
    }
    let bytes = std::slice::from_raw_parts(data, data_len);
    let k = std::slice::from_raw_parts(key32, 32).to_vec();
    let src = crate::cipher::KeySource::RawKey(k);
    match crate::cipher::decrypt_bytes(bytes, &src) {
        Ok(pt) => {
            let want = pt.len();
            if out.is_null() || *out_len < want {
                *out_len = want;
                return if out.is_null() { want as i64 } else { STATUS_ENOMEM };
            }
            std::ptr::copy_nonoverlapping(pt.as_ptr(), out, want);
            *out_len = want;
            STATUS_OK
        }
        Err(e) => set_err(&e),
    }
}

/// Render the one-time display form `HX-<hex>` of a 32-byte key into `out`.
/// The guest must display it at most once; this ABI performs no persistence.
///
/// # Safety
/// `key32` readable for 32 bytes; `out` writable for `*out_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn hexa_crypto_key_display(
    key32: *const u8,
    out: *mut u8,
    out_len: *mut usize,
) -> i64 {
    if key32.is_null() || out_len.is_null() {
        return STATUS_EINVAL;
    }
    let k = std::slice::from_raw_parts(key32, 32);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(k);
    let shown = key::render_display(&arr);
    let want = shown.len();
    if out.is_null() || *out_len < want {
        *out_len = want;
        return if out.is_null() { want as i64 } else { STATUS_ENOMEM };
    }
    std::ptr::copy_nonoverlapping(shown.as_ptr(), out, want);
    *out_len = want;
    STATUS_OK
}

/// The container format version this runtime implements (currently 1).
///
/// # Safety
/// Safe.
#[no_mangle]
pub unsafe extern "C" fn hexa_rt_format_version() -> u8 {
    format::FORMAT_VERSION
}

// ------------------------------------------------------------------ //
// Encoding helpers
// ------------------------------------------------------------------ //

/// # Safety
/// `data` readable for `data_len`; `out` writable for `*out_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn hexa_encoding_hex_encode(
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i64 {
    if out_len.is_null() || (data.is_null() && data_len > 0) {
        return STATUS_EINVAL;
    }
    let bytes = if data_len == 0 { &[][..] } else { std::slice::from_raw_parts(data, data_len) };
    let s = encoding::hex_encode(bytes);
    let want = s.len();
    if out.is_null() || *out_len < want {
        *out_len = want;
        return if out.is_null() { want as i64 } else { STATUS_ENOMEM };
    }
    std::ptr::copy_nonoverlapping(s.as_ptr(), out, want);
    *out_len = want;
    STATUS_OK
}

/// # Safety
/// `s` readable for `s_len` bytes (ASCII hex); `out` writable for `*out_len`.
#[no_mangle]
pub unsafe extern "C" fn hexa_encoding_hex_decode(
    s: *const u8,
    s_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i64 {
    if out_len.is_null() || (s.is_null() && s_len > 0) {
        return STATUS_EINVAL;
    }
    let text = if s_len == 0 {
        String::new()
    } else {
        match String::from_utf8(std::slice::from_raw_parts(s, s_len).to_vec()) {
            Ok(t) => t,
            Err(_) => return STATUS_EINVAL,
        }
    };
    match encoding::hex_decode(&text) {
        Ok(bytes) => {
            let want = bytes.len();
            if out.is_null() || *out_len < want {
                *out_len = want;
                return if out.is_null() { want as i64 } else { STATUS_ENOMEM };
            }
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, want);
            *out_len = want;
            STATUS_OK
        }
        Err(e) => set_err(&e),
    }
}

