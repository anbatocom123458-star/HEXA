# Modules

Modules let you organize a HEXA program across files and namespaces. This
document describes what is available in the current milestone and what is
planned.

## The standard-library namespaces

The standard library is organised into dotted namespaces, and these are fully
usable today:

```
print, input.text, input.integer, secret.input, secret.export, secret.wipe
crypto.key, crypto.encrypt, crypto.decrypt, crypto.hash, crypto.kdf,
crypto.sign, crypto.verify, crypto.keypair, crypto.keyexchange
std.encoding, std.random, std.fs, std.io, file.*
```

You call a namespaced function by its full dotted path:

```he
let h: hash = crypto.hash.sha3_256(b"message");
let b64: text = std.encoding.base64_encode(b"\x01\x02");
```

The prelude resolves these dotted paths (e.g. `crypto.hash.sha256`), so no
`import` is required to use them.

## User-defined modules

The lexer and parser recognize `module` and `import` keywords. Full,
multi-file module loading and import resolution is **(planned / later phase)**;
in the current milestone a program is expected to live in a single `.he` file,
with the standard-library namespaces available via the prelude.

Planned form (for forward reference):

```he
// (planned / later phase)
module geometry {
    fn area(radius: decimal) -> decimal {
        return radius * radius * 3.14159;
    }
}

import geometry;
```

## Project and package structure

The `hexa package` / `install` / `uninstall` commands manage distribution of
HEXA packages, and the `.hexa` v1 container format can carry source, metadata,
and payloads. See [Package manager](19-package-manager.md) and
[hexa-file-format](16-hexa-file-format.md).

## Grouping related crypto functions

Because crypto functions live under namespaces, grouping is natural:

```he
// hash module
crypto.hash.sha256 / sha384 / sha512 / sha3_256 / sha3_512 / blake2b / blake3

// encryption module
crypto.encrypt.aes256_gcm / chacha20_poly1305 / layers
crypto.decrypt.aes256_gcm / chacha20_poly1305

// kdf module
crypto.kdf.argon2id / scrypt / pbkdf2 / hkdf

// signatures
crypto.sign.ed25519 / crypto.verify.ed25519 / crypto.keypair.ed25519

// key exchange
crypto.keyexchange.x25519
```

Next: [Error handling](09-error-handling.md).
