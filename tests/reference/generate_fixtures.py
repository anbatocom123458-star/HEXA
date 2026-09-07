# tests/reference/generate_fixtures.py
"""
Generate the binary fixture set under tests/fixtures/ (deterministic).

The output is a mixture of:
  * plaintext fixtures (small / large / binary / Unicode / empty),
  * valid .hexa containers encrypted with PUBLIC test keys (vectors),
  * corrupt / malformed / truncated containers for negative tests.

No real secrets are used: every key is the public test vector
RAW_KEY = 0001..1f (see tests/vectors/crypto-vectors.json). The manifest
(tests/fixtures/manifest.json) records each file's expected behavior and, for
valid fixtures, the key needed to decrypt it — this doubles as the
integration-test specification for the CLI suite.

Run:    python3 tests/reference/generate_fixtures.py
"""

import json
import shutil
from pathlib import Path

import hexa_format as hf

FIX_DIR = Path(__file__).resolve().parents[1] / "fixtures"

# Public test keys (from tests/vectors/crypto-vectors.json).
KEY = bytes(range(32))
OTHER_KEY = bytes(reversed(range(32)))   # a different fixed key
SALT = bytes(range(16))
OUTER = bytes(range(24, 36))


def w(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def encrypt_fixed(plaintext: bytes, algorithm: str, layers: int,
                  metadata: str, key=KEY) -> bytes:
    return hf.encrypt_layers(
        plaintext, ("raw", key), layers, algorithm, metadata,
        salt=SALT, outer_nonce=OUTER,
        layer_nonces=[bytes(range(12 * (i + 1), 12 * (i + 1) + 12))
                      for i in range(layers)])


def main() -> None:
    manifest = {"about": "test fixtures, public test keys only", "files": {}}

    # --- plaintext fixtures ---------------------------------------------
    plaintexts = {
        "plaintext-small.txt": b"hello from HEXA fixtures\n",
        "plaintext-large.bin": bytes((i * 31 + 7) & 0xFF for i in range(256 * 1024)),
        "plaintext-binary.bin": bytes(range(256)) * 64,
        "plaintext-unicode.txt": (
            "HEXA ✅ unicode: héllo wörld — 日本語テスト 🎉\n").encode("utf-8"),
        "plaintext-empty.bin": b"",
    }
    for name, data in plaintexts.items():
        w(FIX_DIR / name, data)
        manifest["files"][name] = {"kind": "plaintext", "size": len(data)}

    # --- valid .hexa fixtures (decryptable with KEY) --------------------
    valid = [
        ("valid-aes-hello.hexa", b"hello from HEXA fixtures\n",
         "aes256-gcm", 1, "v=1;algo=aes256-gcm;layers=1;original_size=25"),
        ("valid-chacha-hello.hexa", b"hello from HEXA fixtures\n",
         "chacha20-poly1305", 1, "v=1;algo=chacha20-poly1305;layers=1;original_size=25"),
        ("valid-aes-3layers.hexa", b"multi layer payload\n",
         "aes256-gcm", 3, "v=1;algo=aes256-gcm;layers=3;original_size=19"),
        ("valid-unicode.hexa", plaintexts["plaintext-unicode.txt"],
         "aes256-gcm", 1, "v=1;algo=aes256-gcm;layers=1;original_size=50"),
        ("valid-empty.hexa", b"", "aes256-gcm", 1,
         "v=1;algo=aes256-gcm;layers=1;original_size=0"),
        ("valid-aes-hello-otherkey.hexa", b"hello from HEXA fixtures\n",
         "aes256-gcm", 1, "v=1;algo=aes256-gcm;layers=1;original_size=25"),
    ]
    for name, plain, algo, layers, meta in valid:
        key = OTHER_KEY if "otherkey" in name else KEY
        data = encrypt_fixed(plain, algo, layers, meta, key=key)
        w(FIX_DIR / name, data)
        manifest["files"][name] = {
            "kind": "valid-hexa", "algorithm": algo, "layers": layers,
            "key_hex": key.hex(), "plaintext_sha256":
            __import__("hashlib").sha256(plain).hexdigest(),
            "size": len(data),
        }
    # A second valid file for the CLI round-trip (distinct name/size).
    big = plaintexts["plaintext-large.bin"]
    data = encrypt_fixed(big, "aes256-gcm", 1,
                         f"v=1;algo=aes256-gcm;layers=1;original_size={len(big)}",
                         key=KEY)
    w(FIX_DIR / "valid-large.hexa", data)
    manifest["files"]["valid-large.hexa"] = {
        "kind": "valid-hexa", "algorithm": "aes256-gcm", "layers": 1,
        "key_hex": KEY.hex(),
        "plaintext_sha256": __import__("hashlib").sha256(big).hexdigest(),
        "size": len(data),
    }

    base = FIX_DIR / "valid-aes-hello.hexa"
    raw = base.read_bytes()

    # --- corrupted / malformed variants (negative tests) -----------------
    def add(name, data, expect, note):
        w(FIX_DIR / "corrupted" / name, data)
        manifest["files"][f"corrupted/{name}"] = {
            "kind": "corrupt-hexa", "expect": expect, "note": note,
            "size": len(data),
        }

    ct = bytearray(raw)
    ct[-20] ^= 0x01                      # flip a byte inside the payload
    add("bitflip-ciphertext.hexa", bytes(ct), "decrypt-fails", "single bit flip in payload")

    ct = bytearray(raw)
    ct[-1] ^= 0x01                       # A) this hits the TRAILER: parser must reject
    add("bitflip-trailer.hexa", bytes(ct), "parse-rejects",
        "last byte of HEXAEND1 trailer flipped")

    ct = bytearray(raw)
    ct[-9] ^= 0x01                       # B) inside the AEAD tag (before the trailer)
    add("bitflip-tag.hexa", bytes(ct), "decrypt-fails", "single bit flip in AEAD tag")

    # metadata lives at 35 + salt_len; salt_len = 16 (SALT is bytes(range(16)))
    meta_off = 35 + len(SALT)
    assert bytes(raw[meta_off:meta_off + 4]) == b"v=1;", (meta_off, raw[meta_off:meta_off + 4])
    ct = bytearray(raw)
    ct[meta_off] ^= 0x01
    add("bitflip-metadata.hexa", bytes(ct), "parse-ok-decrypt-fails",
        "metadata is header AAD")

    add("truncated-tail.hexa", raw[:-5], "parse-or-decrypt-fails",
        "cut into the trailer")
    add("truncated-half.hexa", raw[: len(raw) // 2], "parse-or-decrypt-fails",
        "cut in half")

    b = bytearray(raw)
    b[6] = 2                             # version byte -> 2
    add("version-2.hexa", bytes(b), "parse-rejects", "EHEX-002 unsupported version")

    b = bytearray(raw)
    b[7] = 0                             # clear authenticated flag
    add("flags-unauthenticated.hexa", bytes(b), "parse-rejects", "EHEX-003")

    b = bytearray(raw)
    b[8] = 0xFE                          # bad algorithm id
    add("algorithm-254.hexa", bytes(b), "parse-rejects", "EHEX-004")

    b = bytearray(raw)
    b[9] = 0x7F                          # bad kdf id
    add("kdf-127.hexa", bytes(b), "parse-rejects", "EHEX-004")

    # Zero layer count with a consistent-looking record body (truncated).
    b = bytearray(raw)
    b[23:27] = (0).to_bytes(4, "big")
    add("zero-layers.hexa", bytes(b), "parse-rejects", "EHEX-007 layer count 0")

    # Huge declared length fields with a tiny file: must be rejected, never crash.
    b = bytearray(raw)
    b[27:31] = (0xFFFF_FFFF).to_bytes(4, "big")   # metadata length ~4 GiB
    add("metadata-len-giant.hexa", bytes(b), "parse-rejects", "EHEX-006 cap")

    b = bytearray(raw)
    b[10] = 255                          # salt length 255 with short file
    add("salt-len-255-short.hexa", bytes(b), "parse-rejects", "EHEX-005 truncated")

    # Malformed UTF-8 metadata: flip bytes inside the metadata region.
    b = bytearray(raw)
    for i in range(meta_off, meta_off + min(4, len(b))):
        b[i] = 0xFF
    add("metadata-bad-utf8.hexa", bytes(b), "parse-rejects", "EHEX-006 bad UTF-8")

    add("trailing-garbage.hexa", raw + b"garbage", "parse-rejects", "EHEX-008")
    add("empty-file.hexa", b"", "parse-rejects", "EHEX-001 truncated magic")
    add("one-byte.hexa", b"H", "parse-rejects", "EHEX-001 truncated magic")
    add("random-256.bin", bytes((i * 13 + 5) & 0xFF for i in range(256)),
        "parse-rejects", "not a .hexa file")

    # A valid file encrypted with KEY, for explicit wrong-key attempts.
    w(FIX_DIR / "wrong-key-target.hexa", raw)
    manifest["files"]["wrong-key-target.hexa"] = {
        "kind": "wrong-key-target", "key_hex": KEY.hex(),
        "wrong_key_hex": OTHER_KEY.hex(),
        "note": "decrypt must fail with wrong_key_hex and succeed with key_hex",
    }

    (FIX_DIR / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"fixtures written to {FIX_DIR}")
    print(f"files: {len(manifest['files'])}")


if __name__ == "__main__":
    main()
