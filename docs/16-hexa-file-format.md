# The `.hexa` file format

Encrypted files, packages, and other payloads produced by HEXA use a binary,
versioned, authenticated container format with the extension `.hexa`. The
current milestone implements **version 1** (`.hexa` v1).

## Purpose

A `.hexa` container is:

- **Binary** — a compact on-disk representation.
- **Versioned** — a `VERSION` field so future format changes are detected.
- **Authenticated** — the payload is integrity-protected by an AEAD tag; any
  tampering is detected.
- **Self-describing** — the header records the algorithm, KDF, and parameters
  needed to reproduce decryption.

## Container fields (v1)

| Field | Description |
|-------|-------------|
| `MAGIC` | The ASCII bytes `HEXA` — file-type identification. |
| `VERSION` | Format version (currently `1`). |
| `FLAGS` | Bit flags (e.g. layer flags, options). |
| `ALGORITHM` | Encryption algorithm id (AES-256-GCM, ChaCha20-Poly1305). |
| `KDF` | Key-derivation function id (Argon2id, scrypt, PBKDF2, HKDF). |
| `KDF params` | KDF parameters (cost, memory, parallelism, length). |
| `SALT` | Random salt used by the KDF. |
| `NONCE` | Random nonce/IV for the AEAD cipher. |
| `LAYER_COUNT` | Number of encryption layers (for multi-layer). |
| `METADATA` | Optional metadata (filename, flags, timestamps). |
| `PAYLOAD` | The encrypted payload. |
| `AUTH_TAG` | The AEAD authentication tag. |

## Lifecycle of a file

1. **Encrypt** builds the container from the plaintext, recording all params.
2. **Inspect** (`hexa inspect`) reads the container and reports its metadata,
   algorithm, KDF, layer count, and header health **without** exposing any key.
3. **Decrypt** reads the container, reproduces the key hierarchy from the
   header + supplied key/password, and validates the `AUTH_TAG` before
   emitting plaintext.

## Versioning & errors

A file whose `MAGIC` or `VERSION` does not match what HEXA understands is
rejected with an `EHEX-0xx` error rather than being misinterpreted. The same is
true for malformed headers or a failed authentication tag.

## The precise binary layout

For the exact byte-by-byte specification — offsets, widths, endianness, and
enum values — see [HEXA-FORMAT.md](HEXA-FORMAT.md).

## Security properties

- **Confidentiality** of the payload (given the key).
- **Integrity & authenticity** — the `AUTH_TAG` proves the payload (and relevant
  header fields) have not been altered.
- **No key material stored** — the header stores *parameters*, never keys,
  passwords, or the one-time key.

Next: [Security model](17-security-model.md).
