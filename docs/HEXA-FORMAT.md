# `.hexa` v1 binary format specification

This document precisely specifies the **`.hexa` version 1 container format**.
All multi-byte integers are **little-endian**. All lengths are in bytes.

The extension for `.hexa` files is `.hexa`. Source files use `.he`.

## Overview

A `.hexa` file is a self-describing, authenticated container:

```
+----------------------------------------------------------------------+
| MAGIC | VERSION | FLAGS | ALGORITHM | KDF | KDF_PARAMS | SALT | NONCE|
+----------------------------------------------------------------------+
| LAYER_COUNT | METADATA | PAYLOAD | AUTH_TAG                             |
+----------------------------------------------------------------------+
```

Every fixed field is followed by a length-prefixed variable field, so a parser
can skip forward deterministically and a future version can extend the schema
without ambiguity (older readers reject higher `VERSION`).

## Byte layout

| Offset | Size | Field | Value |
|-------:|-----:|-------|-------|
| 0 | 4 | `MAGIC` | ASCII `HEXA` = `0x48 0x45 0x58 0x41` |
| 4 | 1 | `VERSION` | `0x01` (v1) |
| 5 | 1 | `FLAGS` | Bit flags, see below |
| 6 | 1 | `ALGORITHM` | Enum, see below |
| 7 | 1 | `KDF` | Enum, see below |
| 8 | 4 | `KDF_PARAMS_LEN` | u32 length of the KDF parameters blob |
| 12 | K | `KDF_PARAMS` | KDF-specific parameter encoding |
| 12+K | 4 | `SALT_LEN` | u32 |
| 16+K | S | `SALT` | KDF salt bytes |
| 16+K+S | 4 | `NONCE_LEN` | u32 |
| 20+K+S | N | `NONCE` | AEAD nonce (single) or layer nonces (concatenated) |
| 20+K+S+N | 4 | `LAYER_COUNT` | u32, number of encryption layers |
| 24+K+S+N | 4 | `METADATA_LEN` | u32 |
| 28+K+S+N | M | `METADATA` | UTF-8 metadata (see below) |
| 28+K+S+N+M | 8 | `PAYLOAD_LEN` | u64, encrypted payload length |
| 36+K+S+N+M | P | `PAYLOAD` | ciphertext payload |
| 36+K+S+N+M+P | 4 | `AUTH_TAG_LEN` | u32 |
| 40+K+S+N+M+P | T | `AUTH_TAG` | AEAD tag (e.g. 16 bytes for GCM/ChaCha20-Poly1305) |

Where `K`, `S`, `N`, `M`, `P`, `T` are the decoded lengths at their positions.
The minimum valid header is 40 bytes plus the KDF/SALT/NONCE/METADATA/PAYLOAD/
AUTH_TAG sections.

## Enumerations

### `FLAGS` (bit 0 = LSB)

| Bit | Meaning |
|-----|---------|
| 0 | `MULTI_LAYER` — payload is multi-layer encrypted; `LAYER_COUNT > 1` |
| 1 | `RESERVED_1` — must be zero in v1 |
| 2 | `RESERVED_2` — must be zero in v1 |
| 3–7 | Reserved — must be zero in v1 |

### `ALGORITHM`

| Value | Algorithm |
|-------|-----------|
| `0x01` | AES-256-GCM |
| `0x02` | ChaCha20-Poly1305 |

### `KDF`

| Value | Name |
|-------|------|
| `0x01` | Argon2id |
| `0x02` | scrypt |
| `0x03` | PBKDF2 |
## SALT
The random salt consumed by the KDF. Recommended 16 bytes; stored verbatim so
the key derivation can be reproduced at decrypt time.

## NONCE
- **Single layer** (`LAYER_COUNT == 1`): one AEAD nonce (12 bytes for GCM,
  12 bytes for ChaCha20-Poly1305).
- **Multi-layer** (`LAYER_COUNT > 1`): exactly `LAYER_COUNT` nonces,
  concatenated in layer order. `NONCE_LEN == LAYER_COUNT * 12`.

## LAYER_COUNT
Number of encryption layers. `1` for standard single-layer encryption, `>1`
for multi-layer (see [15-multi-layer-encryption.md](15-multi-layer-encryption.md)).
When `> 1`, the `MULTI_LAYER` flag must be set.

## METADATA
Optional UTF-8 metadata: original filename, creation timestamp, and any
application info. A length of zero means no metadata. Metadata is not secret —
it travels in cleartext so `hexa inspect` can report it.

## PAYLOAD
The ciphertext. Multi-layer payloads are the result of encrypting layer by
layer; decryption unwraps layers in reverse.

## AUTH_TAG
The authenticator tag of the final AEAD operation — 16 bytes for both
AES-256-GCM and ChaCha20-Poly1305. `AUTH_TAG_LEN` must be 16; tampering or a
wrong key makes tag validation fail and decryption aborts.

## Key hierarchy for multi-layer

The master credential (password or one-time key) →
`Argon2id(master_key, SALT)` → `HKDF` per layer:
```
layer_key_i = HKDF(master_key, salt_i, info = "hexa-layer/" + i)
layer_nonce_i = NONCE[i]
```
Each layer uses `layer_key_i` with the matching `LAYER_COUNT` nonce.

## Parsing rules

1. Read and validate `MAGIC`; mismatch → `EHEX-001`.
2. Read `VERSION`; values other than `0x01` → `EHEX-002`.
3. Read fixed fields and length-prefixed sections; on truncated input →
   `EHEX-003`.
4. `ALGORITHM` / `KDF` out of range → `EHEX-004` / `EHEX-005`.
5. Validate KDF params decode cleanly → else `EHEX-006`.
6. Validate `LAYER_COUNT` and the `MULTI_LAYER`/`NONCE_LEN` consistency
   (multi-layer ⇒ `NONCE_LEN == LAYER_COUNT * 12`) → else `EHEX-010`.
7. Validate `METADATA` UTF-8 → else `EHEX-009`.
8. `PAYLOAD_LEN` consistent with file size → else `EHEX-008`.
9. At decrypt: AEAD open with derived key; tag failure → `EHEX-007`.

## Versioning policy

`VERSION` starts at `1`. Readers must reject unknown versions (`EHEX-002`).
Future readers may add fields **after** `AUTH_TAG` and/or new enum values,
bumping `VERSION`; the length-prefixed encoding keeps older readers able to
skip what they do not use.

## Error codes

See [ERROR-CODES.md](ERROR-CODES.md) for `EHEX-001` … `EHEX-010` and all other
codes.
| `0x04` | HKDF |

## KDF parameter encodings

All integers little-endian.

### Argon2id (`0x01`)
```
offset  size  field
0       4     version      (0x13 = RFC 9106, version 0x13)
4       4     t_cost       (iterations)
8       4     m_cost       (memory in KiB)
12      4     p_cost       (parallelism)
16      4     derived_len  (bytes, typically 32)
20      4     out_len      (same as derived_len; kept explicit)
```
Total: 24 bytes.

### scrypt (`0x02`)
```
0       4     N (cost factor)
4       4     r  (block size)
8       4     p  (parallelization)
12      4     out_len
```
Total: 16 bytes.

### PBKDF2 (`0x03`)
```
0       4     iterations
4       4     out_len
8       4     prf        (1 = HMAC-SHA-256, 2 = HMAC-SHA-512)
```
Total: 12 bytes.

### HKDF (`0x04`)
```
0       4     hash       (1 = HMAC-SHA-256, 2 = HMAC-SHA-512)
4       4     out_len
8       4     info_len
12      I     info bytes
```
Total: 12 + I bytes. `info` carries the layer label for multi-layer derivation;
for single-layer use empty info.