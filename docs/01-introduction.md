# Introduction to HEXA

HEXA is a **secure programming language and cryptography toolchain**. It exists
to answer a question most languages quietly avoid: *what happens when a program
that must handle secrets is written by a fallible human?*

Most languages answer by warning. HEXA answers by **making the dangerous thing
impossible to express**. If a value is a secret — a password, a key, a private
credential — HEXA's type system refuses to let you print it, log it, or cast it
into ordinary text. The compiler does not *hope* you remember to be careful. It
*will not compile* code that leaks a secret.

## Design philosophy

1. **Safety by construction, not by convention.** The security rules are
   enforced at compile time. A secret cannot silently flow into ordinary data.
2. **Honesty over hype.** HEXA never claims to be "uncrackable," "military
   grade," or "impossible to break." It precisely limits what it protects and
   documents, in plain language, what it cannot (a compromised OS, malware on
   the machine, loss of a one-time key, terminal scrollback, screenshots).
3. **A real toolchain, not a toy.** Programs compile to native `x86_64` machine
   code via emitted assembly and the system `as`/`ld`, with a libc-free runtime
   built on raw syscalls. Encrypted and packaged data use an authenticated,
   versioned `.hexa` binary container.
4. **Independent and self-contained.** HEXA is written in Rust as a bootstrap
   and is designed to one day compile itself (self-hosting is a documented later
   phase).

## What makes HEXA different

HEXA's headline feature is its **security-sensitive type system**. These types
exist in the language:

```
secret, key, public_key, private_key, plaintext, ciphertext,
hash, signature, nonce, salt, apikey, password, credential
```

A value with any of these types is *tainted with sensitivity*. The compiler
enforces two hard rules:

- **No implicit downgrade.** A security type can never be silently converted to
  plain `text` or `bytes`. Doing so requires an explicit `secret.export(...)`
  call — a deliberate, visible act.
- **No printing.** Calling `print(...)` on a secret is a compile error
  (`E2100`). The compiler refuses to build the program.

Because of these rules, common leaks — dumping a password to the logs, echoing a
key back to the user, accidentally serializing a private key — become *build
failures* rather than silent vulnerabilities.

## What HEXA ships with

- A **compiler front end**: lexer, parser, AST, static type checking, and static
  security analysis.
- A **cryptography library**: AES-256-GCM, ChaCha20-Poly1305, Argon2id, scrypt,
  PBKDF2, HKDF, SHA-2/3, BLAKE2b/BLAKE3, Ed25519, X25519.
- A **native backend**: assembly emission to `x86_64` linked with `as`/`ld`,
  libc-free.
- A **CLI** (`hexa`): `version`, `build`, `run`, `check`, `format`, `encrypt`,
  `decrypt`, `inspect`, `key show`, `doctor`, `package`, `install`, `uninstall`,
  `disassemble`, `decompile`.
- An **authenticated container format** (`.hexa` v1) with a one-time key
  lifecycle for encryption.
- **Documentation, examples, reference std library files, and installer
  scripts.**

## Where to go next

- [Installation](02-installation.md) — build and install HEXA.
- [Hello, world](03-hello-world.md) — your first program.
- [Types](06-types.md) — including the security-sensitive types.
- [Cryptography](11-crypto.md) — the primitives and how to use them.
- [Security model](17-security-model.md) — what HEXA protects, and what it
  cannot.
