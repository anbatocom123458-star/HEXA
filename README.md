# HEXA

**HEXA** is a serious, independent, secure programming language and cryptography
toolchain built from the ground up in Rust. It is designed for one purpose above
all others: making it possible to write programs that **handle secrets safely** by
making dangerous operations *impossible to express* rather than merely warning
about them.

HEXA programs are written in `.he` source files and compiled to native
`x86_64` machine code via emitted assembly and the system `as`/`ld` toolchain,
with a libc-free runtime built on raw syscalls. Encrypted and packaged data use
the authenticated, versioned `.hexa` binary format.

> **Honesty first.** HEXA never promises the impossible. It keeps keys out of
> reach of *your own programs* and your own mistakes, but it cannot defend
> against a compromised operating system, malware on the machine, a lost
> one-time key, or someone copying your terminal scrollback. See
> [Security model](docs/17-security-model.md) and
> [Threat model](docs/27-threat-model.md) for exactly what HEXA protects and
> what it cannot.

---

## Quickstart

### 1. Build

HEXA is a Rust workspace. Build the release binary:

```bash
cd HEXA
cargo build --release
```

The compiler and toolchain live at `./target/release/hexa`.

### 2. Hello world

Write `hello.he`:

```he
// hello.he — first HEXA program
fn main() {
    print("Hello, world!");
}
```

```bash
./target/release/hexa build hello.he     # type-check and compile to native code
./target/release/hexa run hello.he       # build and run
./target/release/hexa check hello.he     # type-check + security analysis only
```

Output:

```
Hello, world!
```

### 3. Encrypt a file with the one-time key flow

Encryption in HEXA uses a **one-time key** that is generated, displayed exactly
once, and then destroyed. HEXA never stores it and can never recover it.

```bash
./target/release/hexa encrypt secret.txt
```

```
============================================
  SINGLE-USE ENCRYPTION KEY — COPY IT NOW
============================================

  WARNING: This key is shown ONCE and is never stored by HEXA.
  If you lose it, the ciphertext cannot be recovered — by anyone, ever.

  HX-9f3c1a57b0d24e68c1a5f02d9b3e77c4a6d8b1e0f392a5c7d4e1b0a3c5f7d9e2b

============================================
secret.txt.hexa written (AES-256-GCM, Argon2id-derived master key).
```

Decrypt with the key:

```bash
./target/release/hexa decrypt secret.txt.hexa
# HEXA prompts for the key; it is never echoed.
```

> **There is no `hexa key show`, `recover`, or `reveal`.** Running
> `hexa key show` always fails with:
>
> ```
> ERROR EKEY-004: Generated encryption keys are never recoverable by HEXA.
> The key was displayed only once.
> ```
>
> This is not a limitation — it is the point. See
> [Key lifecycle](docs/12-keys.md).

---

## Feature list (current milestone)

**Front end**
- Lexer, parser, and AST with spans and structured diagnostics.
- `fn`, `let`, `mut`, `const`, `if`/`else`, `for`, `while`, `match`, `return`,
  `struct`, `enum`, comments (`//` and `/* */`).
- Types: `text`, `integer`, `decimal`, `number`, `boolean`, `bytes`, `char`,
  plus the security-sensitive types below.
- Static type checking with precise error codes.

**Security model**
- Security-sensitive types: `secret`, `key`, `public_key`, `private_key`,
  `plaintext`, `ciphertext`, `hash`, `signature`, `nonce`, `salt`, `apikey`,
  `password`, `credential`.
- Secret values **can never be implicitly downgraded** to `text`/`bytes`.
  Printing a secret is a compile error (`E2100`); exporting requires an explicit
  `secret.export(...)`.
- Static security analysis that flags risky patterns.

**Cryptography**
- Authenticated encryption: **AES-256-GCM** and **ChaCha20-Poly1305**.
- Key derivation: **Argon2id**, **scrypt**, **PBKDF2**, **HKDF**.
- Hashing: **SHA-2** (256/384/512), **SHA-3** (256/512), **BLAKE2b**, **BLAKE3**.
- Signatures: **Ed25519**. Key exchange: **X25519**.
- Multi-layer encryption via an HKDF key hierarchy.

**CLI**
`hexa` commands: `version`, `build`, `run`, `check`, `format`, `encrypt`,
`decrypt`, `inspect`, `key show` (fails `EKEY-004` by design), `doctor`,
`package`, `install`, `uninstall`, `disassemble`, `decompile`.

**Toolchain**
- Native `x86_64` compilation via emitted assembly + `as`/`ld`, libc-free
  runtime using raw syscalls.
- Versioned, authenticated `.hexa` v1 binary package format.
- One-time key display lifecycle.

---

## Project layout

```
HEXA/
├── README.md          this file
├── docs/              reference documentation (30 topics + format + errors)
├── examples/          runnable .he example programs
├── std/               standard-library reference files
├── compiler/          Rust crate: lexer, parser, AST, type checker (bootstrap)
├── crypto/            Rust crate: cryptographic primitives
├── runtime/           Rust crate: libc-free native runtime
├── cli/               Rust crate: the `hexa` command-line tool
├── tests/             integration test harness
├── tools/             installer scripts
├── editors/           editor extensions (VS Code: syntax + icons)
└── assets/            icon and graphic assets
```

## Editor support

The VS Code extension in [`editors/vscode-hexa/`](editors/vscode-hexa/) provides:

- **Syntax highlighting** for `.he` sources (keywords, security type lattice,
  strings/byte-strings/chars, nested comments, numbers, prelude functions).
- **Language configuration** — auto-closing pairs, comment toggling, region
  folding.
- **File icons** for `.he`, `.hexa`, `.hxpkg` and `hexa.toml`.

Build and install it:

```bash
cd editors/vscode-hexa
npx @vscode/vsce package        # builds hexa-language-0.1.0.vsix
code --install-extension hexa-language-0.1.0.vsix
# then: Ctrl+Shift+P → "Preferences: File Icon Theme" → HEXA File Icons
```

---

## Status

The **vertically-sliced milestone** is implemented end to end: a real program
can be written, type-checked with the secret-safety rules, compiled to native
code, and encrypted/decrypted with the one-time key flow. Later phases — a
richer IR, self-hosting, higher-level optimizations, a larger standard library
— are fully documented but marked **(planned / later phase)** in the docs
rather than pretended to exist.

## Documentation

- [docs/README.md](docs/README.md) — index of all documentation.
- [docs/01-introduction.md](docs/01-introduction.md) — what HEXA is and why.
- [docs/03-hello-world.md](docs/03-hello-world.md) — first program.
- [docs/11-crypto.md](docs/11-crypto.md) — cryptographic primitives.
- [docs/16-hexa-file-format.md](docs/16-hexa-file-format.md) — the `.hexa` format.
- [docs/18-cli.md](docs/18-cli.md) — the command-line interface.
- [docs/HEXA-FORMAT.md](docs/HEXA-FORMAT.md) — precise binary layout spec.
- [docs/ERROR-CODES.md](docs/ERROR-CODES.md) — every diagnostic code.

## License

Apache-2.0. See [LICENSE](LICENSE).

