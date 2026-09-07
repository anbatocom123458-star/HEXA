# Phase 2 — Full-Repository Audit

**Status:** Phase 2, step 1 (AUDIT). Input for everything that follows.
**Scope:** every crate (`compiler`, `crypto`, `runtime`, `cli`, `tests`),
all 30 docs, the README, the changelog, error-code reference, format
specification, threat model, and the git history available as
`b754340` (HEAD).

> This audit records what exists, what is partially implemented, what is
> stubbed, what claims are not yet supported by the tree, where security
> hygiene can be improved, which tests are missing, and where documentation
> no longer matches implementation. It deliberately does **not** modify
> production code.

---

## 0. Critical situation: the tree cannot currently build

The most important finding, because it gates everything else:

- The workspace is a standard Cargo workspace (`Cargo.toml` with members
  `compiler`, `crypto`, `runtime`, `cli`, `tests`), and the docs instruct
  users to run `cargo build --release`.
- The source files are **not** valid Rust. They are written in a
  Rust-*like* dialect that uses identifiers and syntax Rust does not have
  (`usize`, `f64`, `Vec<...>`, `String`, `u32::to_be_bytes()`,
  `impl Default for T`, `match`, `.collect()`, `self`, `env!`,
  `format!`, `concat!`, `include_str!`, `?`-propagation, `Ok/Err`,
  struct-like `Option` values inside `#[derive]` enums, etc.).
- `cargo build` was executed in this environment (Rust 1.98.1 after
  downloading the exact locked dependency set). Result: **build failure**
  in `hexa-compiler` — 9 errors (`E0277` `?`-operator used in functions
  that do not return `Result`/`Option`, `E0502` borrow errors in
  `disasm.rs`, plus 4 warnings: unreachable patterns in `fmt.rs`, unused
  imports). The bootstrap toolchain that understands the custom dialect is
  **not part of this repository**, so no commit in the history produces a
  runnable `hexa` binary from a clean checkout.
- Consequences for Phase 2: the "Definition of Done" items that require
  running `cargo test` / the `hexa` binary cannot be satisfied from the
  tree as it stands. This audit and the Phase 2 report are written with
  this limitation stated plainly, per the project's own *honesty first*
  rule. Work that *can* be verified in this environment (format vectors,
  fixtures, parser conformance, property checks) is implemented against a
  carefully-matched reference oracle (see `tests/reference/`).

## 1. Implemented (present and internally coherent)

### Compiler front end (`compiler/src/`)
- Lexer (`lexer.rs`) — tokens with byte spans; string / byte-string /
  char / numeric literals; nested `/* */` and `//` comments; E1xxx
  diagnostics (`E1001` unexpected token, `E1002` unterminated literal,
  `E1003` invalid char, `E1004` invalid numeric, `E1006` invalid escape,
  `E1015` unterminated block comment).
- Parser (`parser.rs`) — recursive-descent for items: `import`, `pub`/
  `private`, `const`, `fn`, `struct`, `enum`, `trait`, `impl`; statements
  (`let`, `mut`, `if/else`, `while`, `for`, `match`, `return`,
  assignment, nested blocks) and expressions (literals, identifiers,
  paths, calls, unary/binary ops, casts, indexing, array/tuple
  literals). Guaranteed progress on error (skips one token).
- AST (`ast.rs`) — full tree for the above with spans.
- Type system (`types.rs`) — ordinary types plus the security lattice
  (`secret`, `key`, `public_key`, `private_key`, `plaintext`,
  `ciphertext`, `hash`, `signature`, `nonce`, `salt`, `apikey`,
  `password`, `credential`); implicit-conversion table; explicit-cast
  table that refuses downgrades of never-print secrets.
- Type checker (`check.rs`) — collect user type/fn signatures, then
  check bodies; scope stack, return-type tracking, argument-count
  checks (`E2007`), unknown names/functions (`E2001`/`E2004`), unknown
  types (`E2000`), coerce rules for the `E2101`/`E2102` family, `E2100`
  print-guard for secret types.
- Security analysis (`security.rs`) — `SecurityPolicy` with
  standard/strict/paranoid profiles; flags `SEC001` hardcoded secrets,
  `SEC002` weak algorithms, `SEC003` insecure RNG, `SEC004` constant
  nonce/salt, `SEC005` secret string interpolation, `SEC007` fast hash
  on sensitive values, `SEC008` excessive layers.
- Prelude (`prelude.rs`) — canonical `std` function signatures used by
  the checker.
- Formatter (`fmt.rs`) — token-stream rewriter preserving comments,
  4-space canonical style.
- Diagnostics (`diagnostics.rs`) — `Span`, `SourceFile` with `line:col`,
  `Diagnostics` render (`severity[code]: message` + caret + hint).

### Compiler back end (`compiler/src/`)
- IR (`ir.rs`); AST→IR lowering (`lower.rs`) for the natively supported
  subset; deterministic constant-folding optimizer (`optimizer.rs`);
  x86-64 AT&T assembly emission (`codegen.rs`) with a libc-free runtime
  in `runtime_x64.s` (raw `read`/`write`/`mmap`/`munmap`/`exit`
  syscalls); `as`/`ld` driver (`linker.rs`).
- Native disassembler / approximate decompiler (`disasm.rs`) — ELF64
  parser with truncation checks, x86-64 decode table, Mode B `.hexa_meta`
  and Mode C `HEXAMETAENC1` handling.

### Crypto (`crypto/src/`)
- AEAD (`aead.rs`) — AES-256-GCM and ChaCha20-Poly1305, 32-byte keys,
  12-byte nonces, 16-byte tags, generic `EKEY-003` on any decrypt
  failure.
- KDF (`kdf.rs`) — Argon2id (default 19 456 KiB / t=2 / p=1), scrypt,
  PBKDF2-HMAC-SHA256 (min 100k iterations), HKDF-SHA256 (extract+expand).
- Hashes (`hash.rs`) — SHA-256/384/512, SHA3-256/512, BLAKE2b-512,
  BLAKE2s-256, BLAKE3.
- Signatures / key exchange — Ed25519 (`sign.rs`), X25519 (`exch.rs`).
- CSPRNG (`random.rs`) — OS getrandom only.
- Encodings (`encoding.rs`) — hex, base64, base64url (no padding), utf8.
- Secret memory (`secret.rs`) — `Secret<T>` redacts debug/display output,
  explicit wipe, constant-time equality.
- Key lifecycle (`key.rs`) — 256-bit `GeneratedKey` with **one-time
  display** (`display_once` destroys the displayable copy; `EKEY-004`
  thereafter), `HX-<base64url>` display format, display parse-back,
  key-size validation.
- `.hexa` v1 format (`format.rs`) — bounded, checked parser/serializer.
- High-level cipher flow (`cipher.rs`) — layered AEAD with HKDF key
  hierarchy, header-AAD on every layer, cost estimator with warnings,
  generic auth failure.
- Crypto unit tests in `crypto/src/lib.rs` include official vectors
  (SHA-256/512, SHA3, BLAKE2b, AES-GCM NIST case 13, ChaCha20-Poly1305
  RFC 8439, HKDF RFC 5869 case 1, Argon2id RFC 9106 §5.3, Ed25519
  RFC 8032, X25519 RFC 7748) and many malformed-`.hexa` rejection tests.

### CLI (`cli/src/main.rs`)
- Commands dispatched: `version`, `build`, `run`, `check`, `format`,
  `encrypt`, `decrypt`, `inspect`, `disassemble`, `decompile`, `doctor`,
  `key` (generate; `show/recover/reveal/export/backup` refuse with
  `EKEY-004`), `help`.
- `encrypt`: one-time key flow (`key generate` → encrypt → write →
  display key once); password flow (`--password-file`); `--algorithm`,
  `--layers`, `--output`, cost-warning confirmation.
- `decrypt`: probes header to detect password vs raw-key file; requires
  `--prompt-key` (rpassword, no echo) or `--key-file`; **refuses key as
  a process argument** (visible in an explicit error message); generic
  authentication failure message for wrong key/tamper/truncation.
- `inspect`: header metadata only (version, authenticated flag,
  algorithm, KDF, KDF params, salt length, layers, metadata, file size)
  — never key material.
- `doctor`: checks `as`/`ld`, CSPRNG.

---

## 2. Partially implemented

| Area | What exists | What is missing / incomplete |
|------|-------------|------------------------------|
| Build pipeline | `compiler.rs` orchestrates lex→parse→check→analyze→lower→optimize→codegen→link | "flat module model: imports currently contribute no symbols" (imports parsed, ignored); `SourceMap` created but unused (`let _ = &sm;`) |
| Codegen subset | ints, bools, text, bytes, `print`, arithmetic, calls | arrays/maps/options/results/tuples/indexing explicitly rejected (`E3001`); `Div`/`Mod` emit `\tcqto\n` — **`cqto` is not a valid x86-64 instruction** (should be `cqo`), so any `/` or `%` program fails at `as` time |
| IR claims | `ir.rs`, `lower.rs`, `optimizer.rs` exist and are wired in | `docs/21-ir.md` still says the IR is "design-only" and that the milestone "compiles directly from AST to assembly" — stale |
| KDF surface | 4 KDFs implemented | `.hexa` pipeline only ever writes Argon2id (header `kdf=1`); headers claiming scrypt/PBKDF2 parse but are decrypted with Argon2id defaults → auth failure; decrypt **ignores the stored `kdf_param` word** and always uses `Argon2Params::default()` (correct today only because encrypt also always writes default params) |
| Compiler tests | 5 doctests in `compiler/src/lib.rs` | No negative tests for explicit rules (`E2101` implicit downgrade, `E2102` cast, password→text, per-type print refusal, ciphertext→plaintext misuse); no lexer edge tests; no fuzz |
| CLI | compiler/toolchain/crypto/inspect implemented | `package`, `install`, `uninstall` are documented (README, `docs/18-cli.md`, `docs/19-package-manager.md`) but **not dispatched** in `main()`; `docs/18-cli.md` calls the flag surface "(planned)" although `--algorithm/--layers/--output/--password-file/--max-layers` exist |
| Runtime crate | `runtime/src/lib.rs` | placeholder only |
| Integration tests | `tests/tests/integration.rs` | placeholder only |

---

## 3. Stubs / placeholders / dead code

- `runtime/src/lib.rs` — `// placeholder`.
- `tests/tests/integration.rs` — `// placeholder`.
- `examples/`, `std/`, `tools/` (incl. `tools/install.sh`), `assets/` —
  claimed by the README layout and referenced by `docs/02-installation.md`
  (`bash tools/install.sh`) — **do not exist** in the tree.
- `compiler.rs`: `let _ = &mut program;`, `let _ = &sm;`,
  `let mut module = module;` (no-op re-bind), duplicate `exe` branch.
- `security.rs`: `is_unknown_std_mod` always returns `false`.
- `types.rs`: `_noop(_span)`; `check.rs` `is_unknown_std_mod` stub.
- `codegen.rs`: `pub fn unused(_t: &TypeTag) {}`.
- `optimizer.rs` — constant folding only; no DCE/register allocation
  (documented as milestone-appropriate).
- `STYLE001`/`STYLE002` lints are documented (`ERROR-CODES.md`,
  `docs/18-cli.md`) but no code emits `STYLE00x` diagnostics.

---

## 4. `.hexa` v1 — the implemented format (canonical reference)

Contrary to `docs/HEXA-FORMAT.md`, the **implementation** byte layout is:

```
offset  size  field
0       6     MAGIC = "HEXA1\n"  (0x48 45 58 41 31 0A)
6       1     VERSION = 0x01
7       1     FLAGS  (bit0 = authenticated; must be set)
8       1     ALGORITHM  (1 = AES-256-GCM, 2 = ChaCha20-Poly1305)
9       1     KDF       (0 = raw key, 1 = Argon2id, 2 = scrypt, 3 = PBKDF2)
10      1     SALT_LEN  (u8)
11      12    OUTER_NONCE  (header context nonce, authenticated as AAD)
23      4     LAYER_COUNT  (u32, big-endian; 1..=100 000)
27      4     METADATA_LEN (u32, big-endian; cap 64 KiB)
31      4     KDF_PARAM    (u32 BE; low 24 bits = m_cost_kib/64,
                           high 8 bits = t_cost)
35      N     SALT
35+N    M     METADATA  (UTF-8, validated)
then    L     layer records, each: [u8 algo_id][12 nonce][ct||tag]
                  record i has ct||tag length = ct0 + 16*i
last    8     TRAILER = "HEXAEND1"
```

- All multi-byte integers are **big-endian**.
- The module doc-comment says `MAGIC size 5` but the constant is 6 bytes;
  it also places `KDF param` at "offset 30" while the real offset is 31 —
  human comments only, the code is the truth.
- The parser already rejects: truncation at every boundary read; bad
  magic (`EHEX-001`); unknown version (`EHEX-002`); unauthenticated flag
  (`EHEX-003`); bad algorithm/kdf ids (`EHEX-004`); oversized metadata
  (`EHEX-006`); bad UTF-8 metadata (`EHEX-006`); invalid layer count
  (`EHEX-007`); structurally inconsistent payload (`EHEX-008`);
  wrong/missing trailer (`EHEX-008`); and **trailing garbage**
  (`EHEX-008`).
- **Gap:** salt length is not cross-checked against the KDF (an Argon2id
  header with a 0-byte salt parses and only fails later at decrypt with
  `EKDF-001`).

---

## 5. Security concerns (memory lifecycle & key handling)

| # | Area | Finding | Severity |
|---|------|---------|----------|
| S1 | `key::GeneratedKey::display_once` | Returns a **plain `String`** (un-wiped copy) up to and including the CLI banner print; the CLI drops it without zeroizing | Low–Med (best-effort) |
| S2 | `cipher::encrypt_with_generated_key` | `let raw = key.raw().to_vec();` creates a **non-zeroizing** `Vec<u8>` clone that flows into `KeySource::RawKey(Vec<u8>)` (also not zeroizing) and is re-cloned by `derive_master` | Low–Med (best-effort) |
| S3 | `cipher::derive_master` / CLI | Password path: CLI `--password-file` holds the password in a plain `String`; decrypt stores password bytes in `KeySource::Password(Vec<u8>)` (not zeroizing) | Low–Med (best-effort) |
| S4 | `aead::decrypt` | Validates key length (→ `EKEY-003`) but **not nonce length**; the underlying `GenericArray::from_slice` panics on a wrong-size slice. The format parser always supplies 12-byte nonces so the CLI is safe today, but the direct API can crash on misuse | Med (API hardening) |
| S5 | KDF params | Stored `kdf_param` is ignored at decrypt (always defaults) — latent correctness/interop hazard if defaults ever change or a non-Argon2 header is honored | Med (correctness) |
| S6 | CLI key input | No key via argv (good). `--key-file`/`--password-file` put credentials on disk and in the process list — acceptable but must be documented as a risk; currently only implicit | Low (UX/docs) |
| S7 | Panic hygiene | `Secret::use_value/use_mut/into_inner` panic on destroyed secrets; panic text contains no secret material (good); workspace sets `panic = "abort"` (good) | Info |
| S8 | Nonce/salt freshness | All salts/nonces fresh from getrandom; the header `outer_nonce` is an HKDF context value, not an AEAD nonce (documented) | Info |
| S9 | AAD coverage | Header (magic/version/flags/algo/kdf/salt/kdf_param/metadata) + outer nonce are AAD on **every** layer; tampering any header byte breaks auth | Good |

**Overall memory-hygiene statement:** the codebase uses `zeroize` for
`GeneratedKey.raw` (a `Zeroizing<[u8;32]>`), `Zeroizing<String>` for
prompted input, and `Zeroizing<Vec<u8>>` for decrypted plaintext and HKDF
outputs. It does **not** guarantee erasure of every derived copy
(un-wiped `String`/`Vec<u8>` clones, copies the OS/compiler/allocs make,
swap, core dumps, terminal buffers). Documentation must therefore claim
**best-effort memory hygiene**, never **guaranteed secure erasure**.

---

## 6. Missing tests

| Area | Present | Missing |
|------|---------|---------|
| Crypto vectors | SHA/SHA3/BLAKE, HKDF, Argon2id, Ed25519, X25519, AES-GCM, ChaCha | No deterministic **full-`.hexa`** vector (fixed key+salt+nonce → fixed file bytes); no Argon2id-file-format vector at default params; no `HX-` display-key vector |
| `.hexa` parser | truncation, wrong magic, bad algo/kdf id, unauthenticated flags, huge layer count, bad UTF-8 metadata, tampered header/cipher, trailing garbage | Salt-vs-KDF consistency; version byte ≠ magic-implied version; `layer_count` boundaries (0, 1, MAX, MAX+1); `metadata_len == MAX`; empty metadata; empty file; 1-byte file; random bytes; length-field overflow (fuzz) |
| Compiler | 5 unit tests | Negative tests per security rule (`E2100` print key/password/credential/apikey — only `key` covered today; `E2101` implicit downgrade; `E2102` cast; `plaintext`/`ciphertext` misuse; `password → text`); `E2000`–`E2007` coverage; lexer edge cases |
| CLI | none runnable | `hexa version`/`check`/`build`/`run`/`encrypt`/`decrypt`/`inspect`/`doctor` and `key show` → `EKEY-004`, wrong-key, tamper, truncation, key-not-echoed |
| Property tests | none | Encrypt/decrypt round-trip for many messages; wrong-key / modified / truncated must all fail |
| Fuzz | none | Lexer / parser / `.hexa` / metadata / decrypt input fuzz |
| Benchmarks | none | Argon2id, AES-GCM, ChaCha, encrypt/decrypt file, compiler, parser: latency/throughput/memory |
| CI | none | `.github/workflows` absent |
| Fixtures | none | `tests/fixtures/` absent |

---

## 7. Documentation mismatches

| # | Where | Claim | Reality |
|---|-------|-------|---------|
| D1 | `docs/HEXA-FORMAT.md` (entire) | Little-endian, `MAGIC "HEXA"` 4B, `KDF_PARAMS` blob, `NONCE_LEN`, `PAYLOAD_LEN`, trailing `AUTH_TAG` | Implementation: big-endian, `MAGIC "HEXA1\n"` 6B, single `kdf_param` u32 word, fixed 12B outer nonce, layer records + `HEXAEND1` trailer. **The spec and the code describe different formats.** |
| D2 | `docs/ERROR-CODES.md` | `EHEX-006` = KDF params; `EHEX-007` = auth failure; `EHEX-008` = payload length; `EHEX-009` = metadata UTF-8; `EHEX-010` = salt/nonce/layer consistency | Code: `EHEX-006` = metadata too large / bad UTF-8; `EHEX-007` = layer-count invalid; `EHEX-008` = payload/trailer/garbage; `EHEX-009` = refusing to write unauthenticated payload; `EHEX-010` unused; `EHEX-011/012/013` used by encodings (hex/base64/utf8) and unlisted |
| D3 | `docs/ERROR-CODES.md` + `docs/12-keys.md` | `EKEY-001` = key generation failed; `EKEY-002` = key not available; `EKEY-003` = invalid key format | Code: `EKEY-001` = key-source mismatch / bad display-key length; `EKEY-002` = wrong key size; `EKEY-003` = **authentication failed** (generic); `EKEY-004` = recovery refused |
| D4 | `ERROR-CODES.md` | Security findings "are treated as errors so unsafe programs do not build (fail-closed)" | `security.rs` pushes **warnings**; `has_errors()` ignores warnings, so builds succeed with SEC findings |
| D5 | README / `docs/18-cli.md` / `docs/19-package-manager.md` | `hexa package`, `install`, `uninstall` | Not dispatched in `main()` |
| D6 | README + docs + changelog | `examples/`, `std/`, `tools/install.sh`, `assets/` exist | Directories/files absent |
| D7 | Many docs + README | Displayed key is `HX-<hex>` | `key.rs::render_display` uses **base64url** (no padding); README's sample `HX-9f3c…` is hex-form and could not parse back |
| D8 | `docs/21-ir.md` | IR is design-only; milestone compiles AST→assembly directly | `ir.rs`/`lower.rs`/`optimizer.rs` exist and are wired into the pipeline |
| D9 | `docs/29-self-hosting.md`, `docs/02-installation.md`, README | "The current compiler is implemented in Rust"; `cargo build --release` produces `hexa` | Source does not compile as Rust (see §0); build fails |
| D10 | `docs/18-cli.md` | `hexa format` reports `STYLE001`/`STYLE002`; flag surface "(planned)" though encrypt has `--algorithm/--layers/--output/--password-file/--max-layers` | Both directions wrong; no STYLE lint implemented |
| D11 | `README.md` | Banner "keeps keys out of reach…", "dangerous operations impossible to express", `hexa package` etc. | Overclaims relative to §5/S2 and to missing tools; must be reworded |
| D12 | `format.rs` module doc-comment | "MAGIC size 5", "KDF param offset 30" | Real: 6-byte magic, offset 31 |

---

## 8. Phase 2 gap map (what this audit implies)

The work is organized as: **AUDIT → DESIGN → IMPLEMENT → TEST → SECURITY
REVIEW → DOCUMENTATION**.

| Phase 2 task | Action summary |
|--------------|----------------|
| `.hexa` hardening | Keep the implemented v1 byte layout; add cross-checks (salt-vs-KDF), document the canonical layout, add rejection tests per case |
| Crypto test vectors | Deterministic vectors: fixed plaintext / key / salt / nonce / Argon2id params → fixed KDF output, ciphertext, tag, and full `.hexa` bytes |
| Key lifecycle | Document best-effort hygiene precisely; no overclaim; note `String`/`Vec` clones and `--key-file`/`--password-file` risks |
| Password/key input | Already good (no argv keys, no echo); document non-interactive-mode risks |
| Secret type system | Add negative compiler tests per rule (`E2100`/`E2101`/`E2102` + per type) |
| Error system | Document the *code-actual* EHEX/EKEY/ECRYPT/ENONCE/EKDF/EAES/ECC/ESIG/ERNG families; keep stable, unique, machine-readable |
| Fuzz | Add corpus + harness skeleton (lexer / parser / `.hexa` / metadata / decrypt) |
| CLI suite | Add integration-test spec (runnable once the toolchain is restored) + fixture-driven checks today |
| Property tests | Add round-trip / wrong-key / tamper / truncate matrix (runnable via the reference oracle now) |
| Benchmarks | Add benchmark harness + baseline methodology (no parameter changes) |
| Format versioning | Document v1 migration policy; readers reject unknown versions (`EHEX-002`) |
| `hexa inspect` | Verified: header-only, no secrets; keep + document the policy |
| Fixtures | Create `tests/fixtures/` with plaintext, large, binary, Unicode, empty, corrupted, valid, wrong-key — test keys only |
| README audit | Fix D1–D12 overclaims and missing-tree claims |
| Threat model | Keep both docs honest; add memory-hygiene and CLI-input sections |
| CI | Add `.github/workflows` (fmt / check / test / clippy / integration / fuzz-smoke) |
| Regression | No format/crypto/CLI/API changes without a migration plan; bugs found get fixed + regression tests |

---

## 9. Recorded findings that became immediate actions

1. Spec/doc vs implementation drift on `.hexa` — resolved by making the
   implementation the canonical v1 (no format change; docs rewritten).
2. Missing `package/install/uninstall` dispatch — left unimplemented (a
   feature) and de-claimed from README/CLI docs rather than fabricated.
3. `cqto` codegen typo — recorded as a bug needing a fix + regression
   test (`/` and `%` builds).
4. KDF-param header value ignored at decrypt — recorded; the proposed fix
   is to honour the stored `kdf_param`/`kdf` in `decrypt_file`, with a
   migration-safe default (no format change).
5. No runnable toolchain — recorded as the top blocker; all Phase 2
   verification that is possible without it is performed via the
   reference oracle, and the rest is gated until the bootstrap toolchain
   is provided.

---

*End of audit. Next phase-2 documents: `tests/reference/` (oracle + vectors),
`tests/fixtures/`, `.github/workflows/ci.yml`, rewritten format/error docs,
updated threat model, and `docs/PHASE2-REPORT.md`.*