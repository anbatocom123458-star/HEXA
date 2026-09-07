# Keys and key lifecycle

How keys are generated, displayed, used, and — deliberately — never recovered
is fundamental to HEXA's security story. This document explains the **one-time
key lifecycle** that underpins `hexa encrypt`/`decrypt`.

## Key types

- `key` — a secret symmetric key (AES-GCM, ChaCha20-Poly1305, KDF output,
  X25519 shared secret).
- `private_key` — a secret private key (for Ed25519 signing).
- `public_key` — a (shareable) public key.

`private_key` and `key` are in the **never-print** set: they cannot be printed
or cast to ordinary data.

## The one-time key lifecycle

`hexa encrypt file` implements a deliberately strict lifecycle:

1. **Generate.** HEXA generates a fresh random key.
2. **Display exactly once.** HEXA prints the key as `HX-<hex>`, surrounded by a
   prominent `WARNING` banner telling you to copy it now.
3. **Destroy.** HEXA wipes its displayable copy of the key immediately after
   showing it. It does **not** store the key on disk, in the `.hexa` file, or
   anywhere else.
4. **Never recover.** There is no operation that can bring a generated key
   back.

Here is what you see:

```
============================================
  SINGLE-USE ENCRYPTION KEY — COPY IT NOW
============================================

  WARNING: This key is shown ONCE and is never stored by HEXA.
  If you lose it, the ciphertext cannot be recovered — by anyone, ever.

  HX-9f3c1a57b0d24e68c1a5f02d9b3e77c4a6d8b1e0f392a5c7d4e1b0a3c5f7d9e2b

============================================
```

### Why there is no `hexa key show`

Some tools pretend to offer "recover your key" convenience. That convenience is
a vulnerability: if a key is recoverable, an attacker who gains access to the
machine (or the tool's secrets) can recover it too.

There is **no** `hexa key show`, `recover`, or `reveal` command. If you run
`hexa key show`, HEXA fails loudly:

```
ERROR EKEY-004: Generated encryption keys are never recoverable by HEXA.
The key was displayed only once.
```

This is not a missing feature — it is the security model. The entire
`key show` subcommand exists only to *prove* the guarantee by responding with
`EKEY-004`.

## Key-lifecycle error codes

- `EKEY-001` — failure during key generation.
- `EKEY-002` — key not present / key input required to decrypt.
- `EKEY-003` — invalid key format supplied (not a valid `HX-<hex>` key).
- `EKEY-004` — recovery attempted / requested (`key show`); always fails.

## Using keys in programs

Within a program, keys are `key` values:

```he
let k: key = crypto.key.generate(256);
let ct: ciphertext = crypto.encrypt.aes256_gcm(secret.export(plaintext) as bytes, k);
secret.wipe(k); // done with it
```

Keys are never printed. When you finish using a key, wipe it.

## Losing your key means losing your data

Because HEXA never stores generated keys, a lost key is permanently lost. There
is no backdoor, no recovery phrase, no master password to regenerate it. Treat
the `HX-<hex>` display as a credential of the highest value: copy it to a safe
place (ideally an offline password manager) the moment it appears.

Next: [Passwords](13-passwords.md).
