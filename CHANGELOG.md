# HEXA Changelog

All notable changes to HEXA are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] — current milestone (unreleased)

The **vertically-sliced milestone**: a complete, honest vertical slice of the
HEXA toolchain. A program can be written in `.he`, type-checked under the
secret-safety rules, compiled to native `x86_64` code, encrypted with a one-time
key, and inspected as an authenticated `.hexa` package.

### Added

#### Front end (compiler crate)
- **Lexer** producing tokens with spans, including string/byte-string/char
  literals, numeric literals, comments (`//` and nested `/* */`), and the full
  keyword set (`fn`, `let`, `mut`, `const`, `if`, `else`, `for`, `while`,
  `match`, `return`, `struct`, `enum`, `trait`, `impl`, `import`, `module`,
  `pub`, `private`, `async`, `await`).
- Lexer diagnostics: `E1001` (unexpected token), `E1002` (unterminated
  string/char), `E1003` (invalid character), `E1004` (invalid numeric literal),
  `E1006` (invalid escape), `E1015` (unterminated block comment).
- **Parser and AST** for expressions, statements, control flow, functions,
  structs, enums, and type expressions.
- **Type system** with ordinary types (`text`, `integer`, `decimal`, `number`,
  `boolean`, `bytes`, `char`, arrays, maps, options, results, tuples, closures)
  and the security-sensitive lattice (`secret`, `key`, `public_key`,
  `private_key`, `plaintext`, `ciphertext`, `hash`, `signature`, `nonce`,
  `salt`, `apikey`, `password`, `credential`).
- **Type checker** resolving names, inferring and validating types, and
  enforcing the security conversion rules.
- **Standard-library prelude**: the canonical signatures of every std function.

#### Secret-safety enforcement
- Security types can never be implicitly downgraded to `text`/`bytes`.
- Printing a secret is a compile error (`E2100`).
- Using a secret where ordinary data is required is a compile error (`E2101`).
- Casting a secret into ordinary data is a compile error (`E2102`); the only
  sanctioned path is `secret.export(...)`.
- Security analysis flags hardcoded secrets and other risky patterns
  (`SEC001`–`SEC006`).

#### Cryptography (crypto crate)
- Authenticated encryption: AES-256-GCM, ChaCha20-Poly1305.
- Key derivation: Argon2id, scrypt, PBKDF2, HKDF.
- Hashing: SHA-2 (256/384/512), SHA-3 (256/512), BLAKE2b, BLAKE3.
- Signatures: Ed25519. Key exchange: X25519.
- Multi-layer encryption using an HKDF key hierarchy with independent
  per-layer derived subkeys and nonces.

#### Native compilation (runtime + toolchain)
- `x86_64` code generation via emitted assembly and the system `as`/`ld`.
- Libc-free runtime using raw syscalls.

#### CLI (`hexa`)
- Commands: `version`, `build`, `run`, `check`, `format`, `encrypt`,
  `decrypt`, `inspect`, `key show`, `doctor`, `package`, `install`,
  `list`, `remove`/`uninstall`, `update`, `uninstall`, `disassemble`,
  `decompile`.
- **One-time key lifecycle**: `hexa encrypt file` generates a key, displays it
  exactly once as `HX-<hex>` with a warning banner, destroys its displayable
  copy, and never stores or recovers it.
- `hexa key show` always fails with `EKEY-004` — there is deliberately no way to
  recover a generated key.
- **Package manager (fail-closed by design)**:
  - `hexa.toml` manifests (`[package]` name/version/entry_point) with strict
    validation; a manifest can also be inferred from a single `.he` file.
  - `.hxpkg` artifact v1 (`HXPKG`): TOML manifest + file table with per-file
    SHA-256 and a whole-file SHA-256 trailer; absolute paths, `..`, hidden
    components and backslashes are rejected; size/count ceilings enforced
    before anything is trusted.
  - `hexa install` fully validates the archive, extracts to a staging
    directory, compiles the packaged entry point with the real compiler and
    only then commits — a package whose program does not compile is never
    installed. Double installs are refused; `hexa update` replaces in place.
  - Install layout under `$HEXA_HOME` (default `~/.hexa`):
    `pkg/<name>/<version>/`, a generated `bin/<name>` launcher shim, an
    append-only JSON-lines registry with removal tombstones, and
    best-effort freedesktop integration (`.desktop` files, MIME type
    `x-hexa/hexa-package`, embedded SVG icons).

#### `.hexa` file format
- Versioned, authenticated binary format: `MAGIC "HEXA"`, `VERSION`, `FLAGS`,
  `ALGORITHM`, `KDF` + params, `SALT`, `NONCE`, `LAYER_COUNT`, `METADATA`,
  `PAYLOAD`, `AUTH_TAG` (via AEAD).

#### Other
- `tools/install.sh` robust installer with uninstall support.
- Full documentation suite under `docs/`.
- Standard-library reference files under `std/`.
- Example programs under `examples/`.
- Apache-2.0 license.

### Planned (later phases)
- Richer intermediate representation and optimization pipeline.
- Self-hosting of the compiler.
- Higher-level standard-library modules (`std/net`, `std/time`, `std/math`,
  `std/collections`, `std/process`, `std/async`) — partially documented as
  **(planned / later phase)**.
- Expanded CLI subcommands and flags beyond the current milestone set.

---

### Legend of error-code families

| Family        | Meaning                                   |
|---------------|-------------------------------------------|
| `E1xxx`       | Lexer errors (`E1001`…`E1015`)            |
| `E2xxx`       | Type-checker errors (`E2000`…`E2007`)     |
| `SEC00x`      | Security-analysis findings (`SEC001`…)    |
| `E21xx`       | Secret-safety violations (`E2100`–`E2102`)|
| `EKEY-00x`    | Key-lifecycle errors (`EKEY-001`–`EKEY-004`)|
| `EHEX-0xx`    | `.hexa` format errors                     |
| `STYLE0xx`    | Style lints (`STYLE001`, `STYLE002`)      |

See [docs/ERROR-CODES.md](docs/ERROR-CODES.md) for the complete reference.
