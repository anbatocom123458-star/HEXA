# tests/reference/hexa_format.py
"""
Independent conformance oracle for the `.hexa` v1 format.

This module re-implements, byte-for-byte, the format and cipher logic of
`crypto/src/format.rs` and `crypto/src/cipher.rs` — alone among the files in
this repository it runs in this environment (Python 3.14 + the `cryptography`
and `argon2-cffi` packages). Its purpose:

  1. Pin the *implemented* binary layout as canonical v1 (the specs that
     described a different layout were wrong — see docs/PHASE2-AUDIT.md).
  2. Generate deterministic test vectors (fixed key/salt/nonce/params →
     fixed KDF output, ciphertext, tag, whole-file bytes).
  3. Generate the binary fixtures under tests/fixtures/.
  4. Property-test rejection behavior (wrong key, tamper, truncation) and
     parser robustness against a hostile-input corpus.

It implements only what the Rust code does — no invented extensions and no
randomness in the vector paths.

Canonical v1 layout (all multi-byte integers BIG-ENDIAN):

    offset  size  field
    0       6     MAGIC = "HEXA1\\n"
    6       1     VERSION = 0x01
    7       1     FLAGS   (bit0 = FLAG_AUTHENTICATED; must be set)
    8       1     ALGORITHM (1 = AES-256-GCM, 2 = ChaCha20-Poly1305)
    9       1     KDF      (0 = raw key, 1 = Argon2id, 2 = scrypt,
                            3 = PBKDF2; only 0/1 are produced today)
    10      1     SALT_LEN (u8)
    11      12    OUTER_NONCE  (header context nonce, authenticated as AAD)
    23      4     LAYER_COUNT  (u32 BE)
    27      4     METADATA_LEN (u32 BE, cap 64 KiB)
    31      4     KDF_PARAM    (u32 BE: low 24 bits = m_cost_kib/64,
                               high 8 bits = t_cost)
    35      N     SALT
    35+N    M     METADATA (UTF-8, validated)
    then    L     layer records: [u8 algo_id][12 nonce][ct || tag]
                       record i has ct||tag length = ct0 + 16*i
    last    8     TRAILER = "HEXAEND1"

Key hierarchy (cipher.rs):

    password / raw 32-byte key
        | (if password: Argon2id(salt, stored kdf_param))
        v
    intermediate key material (32 B)
        | HKDF-SHA256 extract+expand, info "hexa/master/v1", salt from header
        v
    master key (32 B)
        | HKDF-SHA256 expand, info = "hexa/layer/<i>/<algo-name>"
        v
    layer key i (32 B)

Every layer authenticates the whole logical header plus the outer nonce as
AAD, so any header tampering breaks authentication on every layer at once.
Decryption unwraps layers in reverse order.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# --- Format constants (must match crypto/src/format.rs) ---
MAGIC: bytes = b"HEXA1\n"          # 6 bytes: 'HEXA' '1' '\n'
TRAILER: bytes = b"HEXAEND1"       # 8 bytes
FLAG_AUTHENTICATED: int = 0x01
FORMAT_VERSION: int = 1
MAX_METADATA_LEN: int = 64 * 1024
MAX_SALT_LEN: int = 255
MAX_LAYERS: int = 100_000

# --- Argon2id defaults (must match crypto/src/kdf.rs) ---
DEFAULT_M_COST_KIB: int = 19_456
DEFAULT_T_COST: int = 2
DEFAULT_P_COST: int = 1
DEFAULT_HASH_LEN: int = 32

# --- HKDF info constants (must match crypto/src/cipher.rs) ---
MASTER_INFO: bytes = b"hexa/master/v1"

ALGO_BYTE = {"aes256-gcm": 1, "chacha20-poly1305": 2}
KDF_BYTE = {"argon2id": 1, "scrypt": 2, "pbkdf2-sha256": 3}
ALGO_NAME = {v: k for k, v in ALGO_BYTE.items()}
KDF_NAME = {v: k for k, v in KDF_BYTE.items()}

class HexaError(Exception):
    """Structured error mirroring crypto::CryptoError (code + detail)."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class HexaFile:
    """Parsed .hexa contents (mirror of format::HexaFile + LayerRecord)."""

    def __init__(self, format_version, flags, algorithm, kdf, salt,
                 outer_nonce, layer_count, metadata, kdf_param, layers):
        self.format_version = format_version
        self.flags = flags
        self.algorithm = algorithm            # canonical name, e.g. "aes256-gcm"
        self.kdf = kdf                        # canonical name or None (raw key)
        self.salt = salt
        self.outer_nonce = outer_nonce
        self.layer_count = layer_count
        self.metadata = metadata              # str (validated UTF-8)
        self.kdf_param = kdf_param
        self.layers = layers                  # list of LayerRecord


class LayerRecord:
    def __init__(self, algorithm: str, nonce: bytes, ciphertext_tag: bytes):
        self.algorithm = algorithm
        self.nonce = nonce
        self.ciphertext_tag = ciphertext_tag


# ---------------------------------------------------------------------------
# Low-level primitives
# ---------------------------------------------------------------------------


def kdf_param_word(m_cost_kib: int, t_cost: int) -> int:
    m = min(m_cost_kib // 64, 0xFF_FFFF)
    t = min(t_cost, 0xFF)
    return (m & 0x00FF_FFFF) | (t << 24)


def kdf_param_unpack(word: int) -> tuple:
    return (word & 0x00FF_FFFF) * 64, word >> 24


def argon2id(password: bytes, salt: bytes, m_cost_kib=DEFAULT_M_COST_KIB,
             t_cost=DEFAULT_T_COST, p_cost=DEFAULT_P_COST,
             hash_len=DEFAULT_HASH_LEN) -> bytes:
    """Raw Argon2id, type Argon2id / version 0x13 (RFC 9106)."""
    if len(salt) < 8:
        raise HexaError("EKDF-001", "salt must be at least 8 bytes")
    return hash_secret_raw(
        password, salt,
        time_cost=t_cost, memory_cost=m_cost_kib, parallelism=p_cost,
        hash_len=hash_len, type=Argon2Type.ID, version=19,
    )


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, out_len: int) -> bytes:
    if out_len > 255 * hashlib.sha256().digest_size:
        raise ValueError("HKDF output too long")
    okm = b""
    t = b""
    i = 1
    while len(okm) < out_len:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:out_len]


def hkdf_extract_expand(salt: bytes, ikm: bytes, info: bytes, out_len: int) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, out_len)


def aead_encrypt(algorithm: str, key32: bytes, nonce: bytes, plaintext: bytes,
                 aad: bytes) -> bytes:
    """Return ciphertext || tag (16 bytes), matching aead.rs::encrypt."""
    if len(key32) != 32:
        raise HexaError("EKEY-002", f"{algorithm} requires a 32-byte key")
    if len(nonce) != 12:
        raise HexaError("ENONCE-001", f"{algorithm} requires a 12-byte nonce")
    if algorithm == "aes256-gcm":
        return AESGCM(key32).encrypt(nonce, plaintext, aad)
    if algorithm == "chacha20-poly1305":
        return ChaCha20Poly1305(key32).encrypt(nonce, plaintext, aad)
    raise HexaError("EHEX-004", f"unknown algorithm {algorithm}")


def aead_decrypt(algorithm: str, key32: bytes, nonce: bytes,
                 ciphertext_tag: bytes, aad: bytes) -> bytes:
    """Any failure => the generic EKEY-003 authentication failure."""
    if len(key32) != 32 or len(nonce) != 12:
        raise HexaError("EKEY-003", "authentication failed")
    try:
        if algorithm == "aes256-gcm":
            return AESGCM(key32).decrypt(nonce, ciphertext_tag, aad)
        if algorithm == "chacha20-poly1305":
            return ChaCha20Poly1305(key32).decrypt(nonce, ciphertext_tag, aad)
    except (InvalidTag, ValueError) as exc:
        if isinstance(exc, InvalidTag) or isinstance(exc, ValueError):
            pass
        else:  # pragma: no cover
            pass
    raise HexaError("EKEY-003", "authentication failed")

# ---------------------------------------------------------------------------
# Header AAD + key hierarchy (must match crypto/src/cipher.rs)
# ---------------------------------------------------------------------------


def header_aad(h: HexaFile, context_nonce: bytes) -> bytes:
    """Every field of the logical header plus the outer nonce, as AAD."""
    out = bytearray(MAGIC)
    out.append(h.format_version)
    out.append(h.flags)
    out.append(ALGO_BYTE[h.algorithm])
    out.append(KDF_BYTE[h.kdf] if h.kdf is not None else 0)
    out.append(len(h.salt))
    out += h.salt
    out += h.kdf_param.to_bytes(4, "big")
    out += h.metadata.encode("utf-8")
    out += bytes(context_nonce)
    return bytes(out)


def derive_master(raw_key, password, salt, m_cost_kib=DEFAULT_M_COST_KIB,
                  t_cost=DEFAULT_T_COST) -> bytes:
    """Password path: Argon2id(salt) then HKDF; raw path: HKDF only."""
    if password is not None:
        ikm = argon2id(password, salt, m_cost_kib=m_cost_kib, t_cost=t_cost)
    else:
        ikm = raw_key
    return hkdf_extract_expand(salt, ikm, MASTER_INFO, 32)


def layer_key(master: bytes, index: int, algorithm: str) -> bytes:
    info = f"hexa/layer/{index}/{algorithm}".encode("utf-8")
    return hkdf_expand(hkdf_extract(b"", master), info, 32)


# ---------------------------------------------------------------------------
# Serialization / parsing (must match crypto/src/format.rs)
# ---------------------------------------------------------------------------


def serialize(h: HexaFile) -> bytes:
    if h.format_version != FORMAT_VERSION:
        raise HexaError("EHEX-002", "only format version 1 can be written")
    if not (h.flags & FLAG_AUTHENTICATED):
        raise HexaError("EHEX-009", "refusing to write an unauthenticated .hexa payload")
    if h.layer_count != len(h.layers) or len(h.layers) == 0:
        raise HexaError("EHEX-007",
                        "layer_count must equal number of layer records (at least 1)")
    if h.layer_count > MAX_LAYERS:
        raise HexaError("EHEX-007", "layer count exceeds format maximum")
    md = h.metadata.encode("utf-8")
    if len(md) > MAX_METADATA_LEN:
        raise HexaError("EHEX-006", "metadata too large")
    if len(h.salt) > MAX_SALT_LEN:
        raise HexaError("EHEX-005", "salt too long")
    if len(h.outer_nonce) != 12:
        raise HexaError("ENONCE-001", "outer nonce must be 12 bytes")
    out = bytearray(MAGIC)
    out.append(h.format_version)
    out.append(h.flags)
    out.append(ALGO_BYTE[h.algorithm])
    out.append(KDF_BYTE[h.kdf] if h.kdf is not None else 0)
    out.append(len(h.salt))
    out += h.outer_nonce
    out += h.layer_count.to_bytes(4, "big")
    out += len(md).to_bytes(4, "big")
    out += h.kdf_param.to_bytes(4, "big")
    out += h.salt
    out += md
    for layer in h.layers:
        if len(layer.nonce) != 12:
            raise HexaError("ENONCE-001", "layer nonce must be 12 bytes")
        out.append(ALGO_BYTE[layer.algorithm])
        out += layer.nonce
        out += layer.ciphertext_tag
    out += TRAILER
    return bytes(out)


def _take(data: bytearray, n: int, code: str, what: str) -> bytes:
    if len(data) < n:
        raise HexaError(code, f"file truncated while reading {what} "
                              f"(need {n} bytes, have {len(data)})")
    head = bytes(data[:n])
    del data[:n]
    return head


def _u8(data: bytearray, code: str, what: str) -> int:
    return _take(data, 1, code, what)[0]


def _u32(data: bytearray, code: str, what: str) -> int:
    return int.from_bytes(_take(data, 4, code, what), "big")


def parse(raw: bytes) -> HexaFile:
    """Bounds-checked, hard-capped parser; raises HexaError on anything bad."""
    data = bytearray(raw)
    if _take(data, 6, "EHEX-001", "magic") != MAGIC:
        raise HexaError("EHEX-001", "not a .hexa file (bad magic)")
    version = _u8(data, "EHEX-002", "format version")
    if version != FORMAT_VERSION:
        raise HexaError("EHEX-002", f"unsupported .hexa format version {version}")
    flags = _u8(data, "EHEX-003", "flags")
    if not (flags & FLAG_AUTHENTICATED):
        raise HexaError("EHEX-003", "unauthenticated .hexa payloads are not supported")
    algo_b = _u8(data, "EHEX-004", "algorithm id")
    if algo_b not in ALGO_NAME:
        raise HexaError("EHEX-004", f"unknown algorithm id {algo_b}")
    kdf_b = _u8(data, "EHEX-004", "kdf id")
    if kdf_b == 0:
        kdf = None
    elif kdf_b in KDF_NAME:
        kdf = KDF_NAME[kdf_b]
    else:
        raise HexaError("EHEX-004", f"unknown kdf id {kdf_b}")
    salt_len = _u8(data, "EHEX-005", "salt length")
    outer_nonce = _take(data, 12, "EHEX-005", "nonce")
    layer_count = _u32(data, "EHEX-006", "layer count")
    if layer_count == 0 or layer_count > MAX_LAYERS:
        raise HexaError("EHEX-007", f"invalid layer count {layer_count}")
    meta_len = _u32(data, "EHEX-006", "metadata length")
    if meta_len > MAX_METADATA_LEN:
        raise HexaError("EHEX-006", f"metadata length {meta_len} exceeds cap {MAX_METADATA_LEN}")
    kdf_param = _u32(data, "EHEX-006", "kdf parameters")
    salt = _take(data, salt_len, "EHEX-005", "salt")
    metadata_b = _take(data, meta_len, "EHEX-006", "metadata")
    try:
        metadata = metadata_b.decode("utf-8")
    except UnicodeDecodeError:
        raise HexaError("EHEX-006", "metadata is not valid UTF-8")

    # Structural payload layout: payload_len = 13L + L*ct0 + 8L(L-1)
    if len(data) < len(TRAILER):
        raise HexaError("EHEX-008", "missing .hexa trailer")
    payload_len = len(data) - len(TRAILER)
    l = layer_count
    numer = payload_len - 13 * l - 8 * l * (l - 1)
    if numer < 0 or numer % l != 0:
        raise HexaError("EHEX-008", "payload layout inconsistent with declared layer count")
    ct0 = numer // l
    if ct0 < 16:
        raise HexaError("EHEX-008", "innermost layer payload shorter than an AEAD tag")

    layers = []
    ct_len = ct0
    for i in range(layer_count):
        lb = _u8(data, "EHEX-004", f"layer {i} algorithm")
        if lb not in ALGO_NAME:
            raise HexaError("EHEX-004", f"unknown algorithm id {lb}")
        ln = _take(data, 12, "EHEX-008", f"layer {i} nonce")
        ct = _take(data, ct_len, "EHEX-008", f"layer {i} payload")
        layers.append(LayerRecord(ALGO_NAME[lb], ln, ct))
        if i + 1 < layer_count:
            ct_len += 16
    if _take(data, len(TRAILER), "EHEX-008", "trailer") != TRAILER:
        raise HexaError("EHEX-008", "bad trailer (file is truncated or corrupt)")
    if data:
        raise HexaError("EHEX-008", "trailing garbage after .hexa trailer")

    return HexaFile(version, flags, ALGO_NAME[algo_b], kdf, salt, outer_nonce,
                    layer_count, metadata, kdf_param, layers)


# ---------------------------------------------------------------------------
# Encrypt / decrypt layers (must match crypto/src/cipher.rs)
# ---------------------------------------------------------------------------


def encrypt_layers(plaintext: bytes, source, layers: int, algorithm: str,
                   metadata: str, max_layers: int = 5000, *,
                   salt: bytes = None, outer_nonce: bytes = None,
                   layer_nonces=None) -> bytes:
    """
    Encrypt `plaintext` into a serialized .hexa file.

    `source` is ("raw", 32-byte-key) or ("password", bytes).
    When salt/nonces are None they are drawn fresh (random). Passing fixed
    values makes the output fully deterministic (test vectors).
    """
    if layers == 0:
        raise HexaError("ECRYPT-001", "at least one encryption layer is required")
    if layers > max_layers:
        raise HexaError("ECRYPT-001",
                        f"requested {layers} layers exceeds the configured maximum of {max_layers}")
    if len(metadata.encode("utf-8")) > MAX_METADATA_LEN:
        raise HexaError("EHEX-006", "metadata too large")

    kind, credential = source
    if kind == "password":
        kdf = "argon2id"
        kdf_param = kdf_param_word(DEFAULT_M_COST_KIB, DEFAULT_T_COST)
        salt = secrets.token_bytes(16) if salt is None else salt
        master = derive_master(None, credential, salt)
    else:
        if len(credential) != 32:
            raise HexaError("EKEY-002", "raw keys must be 32 bytes")
        kdf = None
        kdf_param = 0
        salt = secrets.token_bytes(16) if salt is None else salt
        master = derive_master(credential, None, salt)

    outer_nonce = secrets.token_bytes(12) if outer_nonce is None else outer_nonce
    layer_nonces = [secrets.token_bytes(12) for _ in range(layers)] \
        if layer_nonces is None else list(layer_nonces)

    hexa = HexaFile(FORMAT_VERSION, FLAG_AUTHENTICATED, algorithm, kdf, salt,
                    outer_nonce, layers, metadata, kdf_param, [])
    aad = header_aad(hexa, outer_nonce)
    current = plaintext
    records = []
    for i in range(layers):
        lk = layer_key(master, i, algorithm)
        ct = aead_encrypt(algorithm, lk, layer_nonces[i], current, aad)
        records.append(LayerRecord(algorithm, layer_nonces[i], ct))
        current = ct
    hexa.layers = records
    return serialize(hexa)


def decrypt_file(hexa: HexaFile, source) -> bytes:
    """
    Mirror cipher.rs::decrypt_file. Returns plaintext bytes.

    Hardening beyond the current Rust implementation (STRICT_RECORD_VERIFY):
    every layer record stores a redundant copy of the ciphertext that the
    NEXT-outer layer authenticates. The Rust code never re-reads those copies,
    so an attacker can corrupt an inner record and decryption still succeeds.
    Here we verify each stored record equals the bytes recovered from the
    outer layer and reject the file otherwise. Honest writers always produce
    matching copies, so this is backward compatible for all valid files.
    """
    STRICT_RECORD_VERIFY = True
    if hexa.layer_count != len(hexa.layers):
        raise HexaError("EKEY-003", "authentication failed")
    kind, credential = source
    wants_password = hexa.kdf is not None
    if wants_password and kind != "password":
        raise HexaError("EKEY-001",
                        f"this file was encrypted with a password (kdf {hexa.kdf}); "
                        "supply --prompt-key")
    if not wants_password and kind != "raw":
        raise HexaError("EKEY-001",
                        "this file was encrypted with a raw HX- key, not a password")

    if kind == "password":
        m, t = kdf_param_unpack(hexa.kdf_param)
        master = derive_master(None, credential, hexa.salt, m_cost_kib=m, t_cost=t)
    else:
        if len(credential) != 32:
            raise HexaError("EKEY-003", "authentication failed")
        master = derive_master(credential, None, hexa.salt)

    aad = header_aad(hexa, hexa.outer_nonce)
    current = b""
    for i, record in reversed(list(enumerate(hexa.layers))):
        if current:
            if STRICT_RECORD_VERIFY and current != record.ciphertext_tag:
                raise HexaError("EKEY-003", "authentication failed")
            ct = current
        else:
            ct = record.ciphertext_tag
        lk = layer_key(master, i, record.algorithm)
        current = aead_decrypt(record.algorithm, lk, record.nonce, ct, aad)
    return current


def decrypt_bytes(raw: bytes, source) -> bytes:
    """Parse then decrypt. Mirrors cipher.rs::decrypt_bytes."""
    return decrypt_file(parse(raw), source)


if __name__ == "__main__":
    # Round-trip self-check (exercises the import path).
    key = bytes(range(32))
    data = encrypt_layers(b"smoke", ("raw", key), 1, "aes256-gcm", "t",
                          salt=bytes(range(16)), outer_nonce=bytes(range(12)),
                          layer_nonces=[bytes(range(12, 24))])
    parsed = parse(data)
    assert parsed.layer_count == 1 and parsed.algorithm == "aes256-gcm"
    assert decrypt_bytes(data, ("raw", key)) == b"smoke"
    print("reference oracle self-check OK")
