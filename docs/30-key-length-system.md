# Key length system

HEXA uses modern key lengths and this document explains the sizing rules behind
the cryptography. Strong key lengths are the difference between *expensive to
brute-force* and *trivially breakable* — and HEXA chooses lengths that make the
attacker's task infeasible, while being honest that nothing is *impossible*.

## Key lengths in use

| Operation | Algorithm | Key/bits |
|-----------|-----------|----------|
| Symmetric encryption | AES-256-GCM | 256-bit key |
| Symmetric encryption (alt) | ChaCha20-Poly1305 | 256-bit key |
| Key generation (default) | random | 256 bits |
| Signing | Ed25519 | 256-bit seed → 256-bit key |
| Key exchange | X25519 | 256-bit (32-byte) scalar |
| KDF output (Argon2id/scrypt/PBKDF2/HKDF) | — | 256-bit derived key |
| Hashes | SHA-256/384/512, SHA3, BLAKE2b/3 | 256–512-bit digests |

The symmetric primitives use **256-bit keys**, and the KDFs produce 256-bit
derived keys. Ed25519 and X25519 use their standard 256-bit (32-byte)
internals.

## Why 256 bits

- **Symmetric keys.** 256-bit keys give roughly 2^256 possible keys. Exhaustive
  search over that space is infeasible with any currently conceivable
  technology; this is the practical security margin the industry converges on
  (AES-256).
- **AES-256-GCM** and **ChaCha20-Poly1305** both take 256-bit keys by design.
- **Ed25519/X25519** use 256-bit (curve25519) elements with ~128-bit effective
  security — the standard, well-analyzed choice for signatures and DH.

## Generating keys

`crypto.key.generate` accepts a bit length, defaulting to 256:

```he
let k: key = crypto.key.generate(256);   // 256-bit symmetric key
```

It can also derive a key from supplied entropy:

```he
let k: key = crypto.key.generate(std.random.bytes(32)); // 32 bytes = 256 bits
```

## Passwords → keys: not a byte-count question

Key *length* only matters once you have a key with real entropy. A human
password is low-entropy regardless of its length, so HEXA does not use password
bytes directly as keys. It runs them through a **memory-hard KDF** (Argon2id
preferred, scrypt/PBKDF2 available) to stretch a low-entropy password into a
high-entropy 256-bit key. See [Passwords](13-passwords.md).

## Honest caveat

- A 256-bit random key makes brute force infeasible **given the key is truly
  random and kept secret**. If the key is guessed, leaked, or captured from the
  terminal/screen, its length is irrelevant.
- HEXA never promises that brute force is *impossible* — only that for strong,
  random 256-bit keys it is *infeasible* with realistic resources. See
  [Security model](17-security-model.md).

## Sizing summary

| Purpose | Recommended length | Algorithm |
|---------|--------------------|-----------|
| Encryption key | 256 bits | AES-256-GCM / ChaCha20-Poly1305 |
| Derived key | 256 bits | Argon2id / scrypt / PBKDF2 / HKDF |
| Signature | 256-bit seed | Ed25519 |
| Shared secret | 256-bit scalar | X25519 |

Next: [docs index](README.md).
