# Cryptography

HEXA ships a cryptography library that programs use through namespaced standard
functions. This milestone implements a focused, modern set of primitives, all
exposed through type-checked signatures so that misuse is caught at compile
time.

## Available primitives

### Authenticated encryption

| Function | Notes |
|----------|-------|
| `crypto.encrypt.aes256_gcm(data, key)` | AES-256 in GCM mode (authenticated) |
| `crypto.encrypt.chacha20_poly1305(data, key)` | ChaCha20-Poly1305 (authenticated) |
| `crypto.decrypt.aes256_gcm(data, key)` | returns `plaintext` |
| `crypto.decrypt.chacha20_poly1305(data, key)` | returns `plaintext` |
| `crypto.encrypt.layers(data, layers)` | multi-layer, see [15](15-multi-layer-encryption.md) |

Authenticated encryption detects both tampering and an incorrect key: the AEAD
authentication tag will not validate, and the operation fails rather than
returning garbage.

### Key derivation functions (KDFs)

| Function | Notes |
|----------|-------|
| `crypto.kdf.argon2id(password, salt)` | memory-hard, recommended for passwords |
| `crypto.kdf.scrypt(password, salt)` | memory-hard alternative |
| `crypto.kdf.pbkdf2(password, salt)` | widely compatible, not memory-hard |
| `crypto.kdf.hkdf(ikm, salt, info)` | key-derivation for key hierarchies |

All KDFs return a `key`. Argon2id is the recommended choice for password
derivation because it is resistant to GPU/ASIC attacks.

### Hashing

| Function | Output |
|----------|--------|
| `crypto.hash.sha256(bytes)` | SHA-256 |
| `crypto.hash.sha384(bytes)` | SHA-384 |
| `crypto.hash.sha512(bytes)` | SHA-512 |
| `crypto.hash.sha3_256(bytes)` | SHA3-256 |
| `crypto.hash.sha3_512(bytes)` | SHA3-512 |
| `crypto.hash.blake2b(bytes)` | BLAKE2b |
| `crypto.hash.blake3(bytes)` | BLAKE3 |

All return `hash`.

### Signatures & key exchange

| Function | Notes |
|----------|-------|
| `crypto.sign.ed25519(message, private_key)` | returns `signature` |
| `crypto.verify.ed25519(message, signature, public_key)` | returns `boolean` |
| `crypto.keypair.ed25519(seed)` | returns `(private_key, public_key)` |
| `crypto.keyexchange.x25519(private_key, public_key)` | returns shared `key` |

## Using the library safely

The security types do real work here. Consider encryption:

```he
fn seal(data: plaintext, k: key) -> ciphertext {
    return crypto.encrypt.aes256_gcm(data, k);
}
```

The checker holds `data` as `plaintext`, `k` as `key`, and the result as
`ciphertext`. You cannot accidentally pass the ciphertext where the plaintext
belongs, or feed a `text` value in as a `key` without an explicit, examined
conversion.

For a KDF, passwords come from `secret.input` as `password`, and the layers rely
on HKDF (see [Multi-layer encryption](15-multi-layer-encryption.md)).

## Generating keys

```he
let k: key = crypto.key.generate(256);           // 256-bit key
let k2: key = crypto.key.generate(std.random.bytes(32)); // from entropy
```

The `crypto.key.generate` overload accepts either a bit length or raw entropy.

## Don't roll your own

Use these primitives rather than reimplementing cryptography. The CLI
(`hexa encrypt`/`decrypt`) already composes them into the authenticated
`.hexa` container with a one-time key and Argon2id-derived master key; the
library functions let programs do the same inside their own logic.

## Honest limits

- HEXA provides well-vetted *algorithms*; it does not make brute-force attacks
  impossible, only expensive. See [Security model](17-security-model.md).
- Key *management* depends on you. The one-time key flow means the key is
  shown once and never stored — losing it loses the data. See
  [Keys](12-keys.md).

Next: [Keys](12-keys.md).
