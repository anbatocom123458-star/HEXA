# tests/reference/conformance_test.py
"""
Runnable conformance suite for the `.hexa` v1 format and cipher composition.

Runs four groups of checks against the independent reference oracle
(tests/reference/hexa_format.py):

  1. vectors    — every value in tests/vectors/crypto-vectors.json must
                  reproduce exactly (deterministic regression pins).
  2. fixtures   — every file in tests/fixtures/ must behave as manifest.json
                  declares (valid files decrypt; corrupt files reject).
  3. property   — for many plaintexts x algorithms x layer counts:
                    encrypt(P,K) -> C, decrypt(C,K) -> P;
                    decrypt(C,K_wrong) -> fail;
                    decrypt(C_modified,K) -> fail;
                    decrypt(C_truncated,K) -> fail.
  4. corpus     — hostile inputs (empty, 1 byte, random, giant length fields,
                  bad UTF-8, bad version, trailing garbage, …) must raise
                  structured HexaError only — never an uncontrolled crash.

Run:   python3 tests/reference/conformance_test.py
"""

import hashlib
import json
import random
import sys
from pathlib import Path

import hexa_format as hf

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / "vectors" / "crypto-vectors.json").read_text("utf-8"))
MANIFEST = json.loads((ROOT / "fixtures" / "manifest.json").read_text("utf-8"))
KEY = bytes(range(32))
OTHER_KEY = bytes(reversed(range(32)))

_passed = 0
_failed = 0


def check(name, cond, detail=""):
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  ok    {name}")
    else:
        _failed += 1
        print(f"  FAIL  {name}  {detail}")


def test_vectors() -> None:
    print("[vectors] deterministic regression pins")
    for v in VECTORS["vectors"]:
        key = bytes.fromhex(v["key_or_password_hex"])
        salt = bytes.fromhex(v["salt_hex"])
        outer = bytes.fromhex(v["outer_nonce_hex"])
        nonces = [bytes.fromhex(n) for n in v["layer_nonces_hex"]]
        algo = v["algorithm"]
        layers = v["layers"]
        if v["kdf"] == "argon2id":
            p = v["argon2_params"]
            got = hf.argon2id(key, salt, m_cost_kib=p["m_cost_kib"],
                              t_cost=p["t_cost"], p_cost=p["p_cost"])
            check(f"{v['name']}: argon2 output",
                  got.hex() == v["expected_argon2_output_hex"])
            ikm = got
        else:
            ikm = key
        master = hf.hkdf_extract_expand(salt, ikm, hf.MASTER_INFO, 32)
        check(f"{v['name']}: master key",
              master.hex() == v["expected_master_key_hex"])
        for i in range(layers):
            lk = hf.layer_key(master, i, algo)
            check(f"{v['name']}: layer {i} key",
                  lk.hex() == v["expected_layer_keys_hex"][i])

        file_bytes = bytes.fromhex(v["expected_file_hex"])
        # Independent re-encryption must reproduce the exact same file bytes.
        re_enc = hf.encrypt_layers(
            bytes.fromhex(v["plaintext_hex"]),
            ("password" if v["kdf"] else "raw", key), layers, algo,
            v["metadata"], salt=salt, outer_nonce=outer, layer_nonces=nonces)
        check(f"{v['name']}: serialized file bytes", re_enc == file_bytes)
        # Layer ciphertexts recorded at generation time must match.
        parsed = hf.parse(file_bytes)
        for i, rec in enumerate(parsed.layers):
            check(f"{v['name']}: layer {i} record",
                  rec.ciphertext_tag.hex() == v["expected_layer_ciphertext_tag_hex"][i])
        # Decrypt back to plaintext.
        kind = "password" if v["kdf"] else "raw"
        check(f"{v['name']}: decrypt == plaintext",
              hf.decrypt_bytes(file_bytes, (kind, key)) ==
              bytes.fromhex(v["plaintext_hex"]))
        check(f"{v['name']}: plaintext sha256",
              v["plaintext_sha256"] ==
              hashlib.sha256(bytes.fromhex(v["plaintext_hex"])).hexdigest())
    dk = VECTORS["display_key"]
    import base64
    expect = "HX-" + base64.urlsafe_b64encode(bytes.fromhex(dk["key_hex"])).rstrip(b"=").decode()
    check("display key HX-<base64url>", dk["expected_display"] == expect)


def test_fixtures() -> None:
    print("[fixtures] manifest behavior")
    fix = ROOT / "fixtures"
    for rel, spec in sorted(MANIFEST["files"].items()):
        data = (fix / rel).read_bytes()
        kind = spec["kind"]
        if kind == "plaintext":
            check(f"fixture {rel}: size", len(data) == spec["size"])
        elif kind == "valid-hexa":
            key = bytes.fromhex(spec["key_hex"])
            pt = hf.decrypt_bytes(data, ("raw", key))
            check(f"fixture {rel}: decrypts", hashlib.sha256(pt).hexdigest() ==
                  spec["plaintext_sha256"])
        elif kind == "wrong-key-target":
            ok = hf.decrypt_bytes(data, ("raw", bytes.fromhex(spec["key_hex"])))
            check(f"fixture {rel}: right key decrypts", ok == b"hello from HEXA fixtures\n")
            try:
                hf.decrypt_bytes(data, ("raw", bytes.fromhex(spec["wrong_key_hex"])))
                check(f"fixture {rel}: wrong key fails", False)
            except hf.HexaError as e:
                check(f"fixture {rel}: wrong key fails ({e.code})", e.code == "EKEY-003")
        elif kind == "corrupt-hexa":
            expect = spec["expect"]
            try:
                parsed = hf.parse(data)
            except hf.HexaError:
                check(f"fixture {rel}: parse rejects",
                      expect in ("parse-rejects", "parse-or-decrypt-fails"))
                continue
            except Exception as e:  # uncontrolled crash = fail
                check(f"fixture {rel}: NO crash, got {type(e).__name__}", False)
                continue
            # Parsed but must never decrypt back to the original plaintext.
            try:
                hf.decrypt_bytes(data, ("raw", KEY))
                check(f"fixture {rel}: must not decrypt", False)
            except hf.HexaError:
                check(f"fixture {rel}: decrypt fails",
                      expect in ("decrypt-fails", "parse-ok-decrypt-fails",
                                 "parse-or-decrypt-fails"))
            except Exception as e:
                check(f"fixture {rel}: NO crash, got {type(e).__name__}", False)
        else:
            check(f"fixture {rel}: unknown kind", False)

def test_property() -> None:
    print("[property] round-trip, wrong-key, tamper, truncation")
    rng = random.Random(0x5EED)          # deterministic
    seeds = [
        b"", b"a", b"hello", b"\x00\x00", bytes(511),
        bytes(rng.randrange(0, 256) for _ in range(64)),   # 64 random sizes
    ]
    cases = []
    for pt in seeds:
        for algo in ("aes256-gcm", "chacha20-poly1305"):
            for layers in (1, 2, 5):
                cases.append((pt, algo, layers))
    for pt, algo, layers in cases:
        name = f"{algo} L{layers} len={len(pt)}"
        enc = hf.encrypt_layers(pt, ("raw", KEY), layers, algo,
                                f"prop;layers={layers}")
        check(f"round-trip {name}", hf.decrypt_bytes(enc, ("raw", KEY)) == pt)
        # wrong key
        try:
            hf.decrypt_bytes(enc, ("raw", OTHER_KEY))
            check(f"wrong-key  {name}", False)
        except hf.HexaError as e:
            check(f"wrong-key  {name}", e.code == "EKEY-003")
        # one-byte tamper: header, salt, outer nonce, kdf param, outermost
        # record body, inner record body (strict verification), trailer.
        n = len(enc)
        positions = sorted({0, 6, 8, 12, 30, 34, 35,
                            n - 8 - 1, n - 9, n - 1, n // 2})
        for pos in positions:
            if not (0 <= pos < n):
                continue
            bad = bytearray(enc)
            bad[pos] ^= 0x01
            try:
                hf.decrypt_bytes(bytes(bad), ("raw", KEY))
                check(f"tamper     {name} @{pos}", False,
                      "modified ciphertext returned plaintext")
            except hf.HexaError:
                check(f"tamper     {name} @{pos}", True)
            except Exception as e:
                check(f"tamper     {name} @{pos} crash {type(e).__name__}", False)
        # truncations
        for cut in (1, n // 2, n - 1, n - 4):
            tr = enc[:cut]
            try:
                hf.decrypt_bytes(tr, ("raw", KEY))
                check(f"truncated  {name} cut={cut}", False)
            except hf.HexaError:
                check(f"truncated  {name} cut={cut}", True)
            except Exception as e:
                check(f"truncated  {name} cut={cut} crash {type(e).__name__}", False)


def test_corpus() -> None:
    print("[corpus] hostile inputs must never crash")
    rng = random.Random(0xC0FFEE)
    inputs = []
    inputs.append(b"")
    inputs.append(b"H")
    inputs.append(b"HEXA1\n")
    inputs.append(b"HEXA1\n\x01\x01\x01\x00")
    inputs.append(bytes(1))
    inputs.append(bytes(2))
    inputs += [bytes(rng.randrange(0, 256) for _ in range(n))
               for n in (0, 1, 5, 16, 64, 255, 256, 1024, 4096)]
    # A valid file with a variety of surgical mutilations.
    base = (ROOT / "fixtures" / "valid-aes-hello.hexa").read_bytes()
    muts = []
    muts.append(bytes(base[:6]))                         # magic only
    muts.append(bytes(base[:7]))                         # + version
    muts.append(bytes(base[:9]))                         # + algo
    muts.append(base[:6] + b"\x02" + base[7:])           # version=2
    muts.append(base[:6] + b"\x00" + base[7:])           # version=0
    muts.append(base[:10] + b"\xFE")                     # salt_len=254
    muts.append(base[:23] + (0).to_bytes(4, "big"))      # layer_count=0
    muts.append(base[:23] + (0xFFFF_FFFF).to_bytes(4, "big"))  # huge layers
    muts.append(base[:27] + (0xFFFF_FFFF).to_bytes(4, "big"))  # huge metadata
    muts.append(base + b"x" * 16)                        # trailing garbage
    muts.append(base[:-4])                               # cut trailer
    for i, b in enumerate(inputs + muts):
        try:
            hf.parse(b)
            # parsed: that is fine, but then decrypt must not crash either
            try:
                hf.decrypt_bytes(b, ("raw", KEY))
            except hf.HexaError:
                pass
        except hf.HexaError:
            pass
        except Exception as e:
            check(f"corpus {i} (len={len(b)}): crash {type(e).__name__}: {e}", False)
            continue
        check(f"corpus {i} (len={len(b)}): handled", True)


def main() -> None:
    test_vectors()
    test_fixtures()
    test_property()
    test_corpus()
    print(f"\n{_passed} passed, {_failed} failed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
