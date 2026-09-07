# Multi-layer encryption

For extra defense in depth, HEXA supports encrypting data in **multiple
layers**, each with its own key and nonce, so that compromising one layer does
not reveal the plaintext.

## Library API

```he
let protected: ciphertext = crypto.encrypt.layers(plaintext, 4); // 4 layers
```

`crypto.encrypt.layers(data, layers)` returns a `ciphertext` that has been
encrypted `layers` times. Every layer must be stripped in reverse order to
recover the original.

## How layer keys are derived

Multi-layer encryption does **not** reuse one key four times (that would gain
nothing). Instead it builds an **HKDF key hierarchy**:

```
master credential
   │  (Argon2id)
   ▼
master key (MK)
   │  (HKDF, per-layer info)
   ├─────────► layer key 1  +  nonce 1
   ├─────────► layer key 2  +  nonce 2
   ├─────────► layer key 3  +  nonce 3
   └─────────► layer key 4  +  nonce 4
```

Each layer key is an HKDF-derived subkey of the master key, with independent
per-layer info strings and independent random nonces. Concretely:

1. A **master credential** is entered (a password, a one-time key, or file).
2. `Argon2id` derives the **master key** from the credential.
3. `HKDF` expands the master key into **per-layer subkeys**, one per layer.
4. Each layer encrypts with its own subkey and a fresh nonce.

This means an attacker who recovers *one* layer key still cannot decrypt the
other layers, and the layers resist each other's independent failure modes.

## Order of operations

**Encrypt** applies layers from outermost to innermost (or in a fixed defined
order), each with its own cipher (AES-256-GCM or ChaCha20-Poly1305).

**Decrypt** must remove layers in reverse order; each layer's authentication
tag is validated before the next is attempted. A failure at any layer aborts and
reports an `EHEX`/`EKEY` code.

## Metadata in the container

The `.hexa` v1 format records `LAYER_COUNT`, the HKDF salt, and per-layer
parameters so the hierarchy can be reconstructed, but never the keys
themselves. See [HEXA-FORMAT.md](HEXA-FORMAT.md).

## Why multi-layer helps

- **Layered compromise:** each independent key/nonce means a single leaked
  subkey does not expose the data.
- **Key-hierarchy hygiene:** the master key is never directly used for bulk
  encryption; only derived subkeys are.
- **Future migration:** a hierarchy supports rotating or extending layers
  without re-encrypting everything with a single key.

## Honest note

Multi-layer encryption complicates and slows brute-force/partial compromise, but
it does **not** make decryption impossible and does not compensate for a lost
master credential. If the master key is gone, all layers — and the data — are
unrecoverable. See [Security model](17-security-model.md).

Next: [The `.hexa` file format](16-hexa-file-format.md).
