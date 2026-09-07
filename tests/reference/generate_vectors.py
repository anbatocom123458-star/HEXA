# tests/reference/generate_vectors.py
"""
Generate deterministic cryptographic test vectors for the `.hexa` v1 toolchain.

Everything below uses FIXED inputs (no randomness):

    plaintext:     hello
    raw key:       00 01 02 ... 1f  (32 bytes)
    password:      "a fixed test password"
    salt:          00 01 02 ... 0f  (16 bytes)
    nonces:        12-byte fixed values, unique per layer
    Argon2id:      m=19456 KiB, t=2, p=1 (the toolchain defaults)

For each vector the file records the full chain of intermediates — Argon2id
output, HKDF master key, per-layer keys, per-layer ciphertext||tag, and the
exact serialized `.hexa` bytes — plus the expected decrypt result and
plaintext hash. These values pin the format and the crypto composition so any
future, accidental change to either breaks the test immediately.

Run:    python3 tests/reference/generate_vectors.py
Writes: tests/vectors/crypto-vectors.json
"""

import base64
import hashlib
import json
from pathlib import Path

import hexa_format as hf

VECTORS_OUT = Path(__file__).resolve().parents[1] / "vectors" / "crypto-vectors.json"

PLAINTEXT = b"hello"
RAW_KEY = bytes(range(32))                    # 00..1f
PASSWORD = b"a fixed test password"
SALT = bytes(range(16))                       # 00..0f
OUTER_NONCE = bytes(range(24, 36))            # deterministic, distinct range

def hexstr(b: bytes) -> str:
    return b.hex()


def build_vector(name, plaintext, algorithm, layers, source, metadata,
                 salt, outer_nonce, layer_nonces):
    """Encrypt with fixed inputs and record every intermediate."""
    kind, credential = source
    argon2_out = None
    if kind == "password":
        argon2_out = hf.argon2id(credential, salt)
        ikm = argon2_out
    else:
        ikm = credential
    master = hf.hkdf_extract_expand(salt, ikm, hf.MASTER_INFO, 32)

    layer_keys = [hf.layer_key(master, i, algorithm) for i in range(layers)]

    kdf = "argon2id" if kind == "password" else None
    kdf_param = (hf.kdf_param_word(hf.DEFAULT_M_COST_KIB, hf.DEFAULT_T_COST)
                 if kdf else 0)
    hexa = hf.HexaFile(hf.FORMAT_VERSION, hf.FLAG_AUTHENTICATED, algorithm, kdf,
                       salt, outer_nonce, layers, metadata, kdf_param, [])
    aad = hf.header_aad(hexa, outer_nonce)

    current = plaintext
    layers_ct = []
    for i in range(layers):
        ct = hf.aead_encrypt(algorithm, layer_keys[i], layer_nonces[i], current, aad)
        layers_ct.append(ct)
        current = ct

    file_bytes = hf.encrypt_layers(
        plaintext, source, layers, algorithm, metadata,
        salt=salt, outer_nonce=outer_nonce, layer_nonces=layer_nonces,
    )

    return {
        "name": name,
        "algorithm": algorithm,
        "layers": layers,
        "kdf": kdf,
        "argon2_params": (
            {"m_cost_kib": hf.DEFAULT_M_COST_KIB, "t_cost": hf.DEFAULT_T_COST,
             "p_cost": hf.DEFAULT_P_COST, "hash_len": hf.DEFAULT_HASH_LEN}
            if kdf else None),
        "kdf_param_word": kdf_param,
        "metadata": metadata,
        "plaintext_hex": hexstr(plaintext),
        "plaintext_sha256": hexstr(hashlib.sha256(plaintext).digest()),
        "key_or_password_hex": hexstr(credential),
        "salt_hex": hexstr(salt),
        "outer_nonce_hex": hexstr(outer_nonce),
        "layer_nonces_hex": [hexstr(n) for n in layer_nonces],
        "expected_argon2_output_hex": hexstr(argon2_out) if argon2_out else None,
        "expected_master_key_hex": hexstr(master),
        "expected_layer_keys_hex": [hexstr(k) for k in layer_keys],
        "expected_layer_ciphertext_tag_hex": [hexstr(c) for c in layers_ct],
        "expected_file_hex": hexstr(file_bytes),
        "file_size": len(file_bytes),
    }


def main() -> None:
    layer_nonces = [bytes(range((i + 1) * 12, (i + 1) * 12 + 12)) for i in range(3)]

    vectors = {
        "schema": "hexa.phase2.crypto-test-vectors",
        "schema_version": 1,
        "format": "hexa-v1-as-implemented",
        "note": (
            "Deterministic regression vectors. Fixed inputs only. Expected "
            "values pin the format layout (big-endian, MAGIC 'HEXA1\\n', layer "
            "records, 'HEXAEND1' trailer) and the cipher composition (Argon2id "
            "-> HKDF master -> HKDF per-layer keys -> layered AEAD with header "
            "AAD). Any change to the format or crypto breaks these. All "
            "keys/passwords here are public test data, never real secrets."
        ),
        "vectors": [],
    }

    # 1-2. Raw-key single-layer round trips (both algorithms).
    for algo in ("aes256-gcm", "chacha20-poly1305"):
        vectors["vectors"].append(build_vector(
            f"{algo}-hello-rawkey", PLAINTEXT, algo, 1, ("raw", RAW_KEY),
            f"v=1;algo={algo};layers=1;original_size=5",
            SALT, OUTER_NONCE, [layer_nonces[0]]))

    # 3. Password (Argon2id at toolchain defaults), single layer.
    vectors["vectors"].append(build_vector(
        "argon2id-hello-password", PLAINTEXT, "aes256-gcm", 1,
        ("password", PASSWORD),
        "v=1;algo=aes256-gcm;layers=1;original_size=5",
        SALT, OUTER_NONCE, [layer_nonces[0]]))

    # 4. Multi-layer (3 layers, all AES-256-GCM).
    vectors["vectors"].append(build_vector(
        "aes256-gcm-hello-3layers", PLAINTEXT, "aes256-gcm", 3,
        ("raw", RAW_KEY), "v=1;algo=aes256-gcm;layers=3;original_size=5",
        SALT, OUTER_NONCE, list(layer_nonces)))

    # 5. Empty plaintext edge case.
    vectors["vectors"].append(build_vector(
        "aes256-gcm-empty-rawkey", b"", "aes256-gcm", 1, ("raw", RAW_KEY),
        "v=1;algo=aes256-gcm;layers=1;original_size=0",
        SALT, OUTER_NONCE, [layer_nonces[2]]))

    # Display-key format vector (HX-<base64url no padding>).
    vectors["display_key"] = {
        "format": "HX-<base64url-no-padding>",
        "key_hex": hexstr(RAW_KEY),
        "expected_display": "HX-" + base64.urlsafe_b64encode(RAW_KEY).rstrip(b"=").decode(),
    }

    VECTORS_OUT.parent.mkdir(parents=True, exist_ok=True)
    VECTORS_OUT.write_text(json.dumps(vectors, indent=2) + "\n", encoding="utf-8")

    # Self-verify every vector before writing.
    for v in vectors["vectors"]:
        file_bytes = bytes.fromhex(v["expected_file_hex"])
        hf.parse(file_bytes)                   # must not raise
        kind = "password" if v["kdf"] else "raw"
        cred = bytes.fromhex(v["key_or_password_hex"])
        plain = hf.decrypt_bytes(file_bytes, (kind, cred))
        assert plain == bytes.fromhex(v["plaintext_hex"]), v["name"]
        assert hashlib.sha256(plain).hexdigest() == v["plaintext_sha256"]
        print(f"vector ok: {v['name']} ({v['file_size']} bytes)")

    print(f"wrote {VECTORS_OUT}")


if __name__ == "__main__":
    main()
