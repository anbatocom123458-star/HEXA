# HEXA threat model

**Status: current milestone, v1.**
**Audience: engineers reasoning about whether and how to trust HEXA.**

This is the canonical threat-model document. A shorter companion is
[docs/27-threat-model.md](27-threat-model.md). Both are derived from the same
analysis; this file is the full version.

HEXA's promise is narrow and specific. It is **not** "your computer is
impenetrable" and it is **not** "this encryption is unbreakable." It is: *when a
program that must handle secrets is written against HEXA's rules, the program
itself cannot accidentally leak those secrets, and encrypted data resists
theft and tampering by attackers who do not already control the machine.*
Everything else is documented as out of scope.

---

## 1. Assets

| # | Asset | Notes |
|---|-------|-------|
| A1 | Secrets inside running programs | Passwords, keys, private keys, API keys, credentials, plaintext. |
| A2 | Secrets derived from them | KDF outputs, shared secrets, decrypted plaintext. |
| A3 | `.hexa` containers / ciphertext at rest | Encrypted files and packages. |
| A4 | The one-time `HX-<hex>` encryption key | Displayed exactly once by `hexa encrypt`. |
| A5 | Program integrity | What the developer wrote is what executes. |
| A6 | Confidentiality of source | `.he` source may itself be sensitive. |

## 2. Trust boundaries

- **The machine (OS + hardware) is trusted.** Every guarantee below assumes a
  non-compromised OS and physical environment. A compromised OS voids the
  model — no software layer can keep secrets from code running as the same
  user with the same privileges.
- **The compiler/toolchain is trusted.** A tampered `hexa` binary could do
  anything. Users should verify binary integrity (hash the artifact, build from
  source) at the level of risk appropriate to their data.
- **The user is trusted with the one-time key.** HEXA deliberately does not
  store it; in exchange, the user must protect it.
- **Programs are not trusted with secrets they don't need.** The type system
  exists precisely so that a program cannot leak a secret it was not explicitly
  permitted to export.

---

## 3. Adversaries

### Adversary TB1 — Accidental internal leak
- **Profile:** a bug in the developer's own program.
- **Threats:** `print(secret)`, implicit conversion of a secret to `text`/`bytes`,
  serialization of a secret, secrets in logs, keys in stack traces.
- **Mitigations (primary):**
  - `print(secret)` → compile error `E2100`.
  - Implicit downgrade of a secret → compile error `E2101`.
  - `as`-cast of a secret to ordinary data → compile error `E2102`.
  - Security analysis flags hardcoded secrets and weak flows (`SEC001`–`SEC006`).
  - These are *errors*, not warnings: the program does not build.
- **Residual:** deliberate `secret.export(...)` misuse by the developer; any
  leak the developer explicitly codes. Not defensible by a compiler.

### Adversary TB2 — Theft of data files
- **Profile:** attacker copies `.hexa` containers, backups, stray files.
- **Threats:** reading ciphertext, replaying/modifying containers.
- **Mitigations:**
  - Authenticated encryption (AES-256-GCM / ChaCha20-Poly1305).
  - `AUTH_TAG` detects any tamper → `EHEX-007`.
  - On-disk format is versioned/magic-tagged → `EHEX-001`/`EHEX-002`.
  - The key is **never** in the container or on disk → file theft does not
    yield key material.
- **Residual:** offline brute force of a weak password lens (see TB5).

### Adversary TB3 — Later compromise recovering past keys
- **Profile:** attacker gains account/machine access later and looks for
  previously generated encryption keys, in HEXA's state or elsewhere.
- **Threats:** recovering the `HX-<hex>` key from HEXA.
- **Mitigations:**
  - One-time lifecycle: display-once, wipe immediately, never store.
  - `hexa key show` is implemented specifically to **fail** with `EKEY-004`.
    There is no key store to steal.
- **Residual:** keys the user stored elsewhere (password manager, paper) are
  protected by *those* systems' security, not HEXA's.

### Adversary TB4 — Malware / compromised OS / keylogger / screen capture
- **Profile:** attacker controls the machine or observes its I/O.
- **Threats:** reading process memory, syscalls, keystrokes; photographing/
  screen-capturing the one-time key display or `secret.export` output; reading
  terminal scrollback.
- **Mitigations: none.** HEXA does not defend against an adversary who already
  controls the environment. This is out of scope and stated plainly
  everywhere. Operating-system security, physical security, and endpoint
  hygiene are the appropriate controls.

### Adversary TB5 — Offline brute force / password guessing
- **Profile:** attacker has ciphertext + header (KDF parameters are public by
  design) and guesses weak passwords or short keys.
- **Mitigations:**
  - Memory-hard KDFs: Argon2id (default), scrypt — raise per-guess cost.
  - 256-bit random keys make direct key search infeasible in practice
    (see [30-key-length-system.md](30-key-length-system.md)).
- **Residual:** weak human passwords remain guessable given enough compute;
  HEXA never claims brute force is impossible. 128-bit effective security
### Adversary TB6 — API misuse / bad cryptographic hygiene
- **Profile:** developer uses the crypto API incorrectly.
- **Threats:** nonce reuse, using raw password bytes as keys, passing
  ciphertext where plaintext belongs, ignoring authentication failures.
- **Mitigations:**
  - Distinct types (`plaintext`, `ciphertext`, `key`, `nonce`, `salt`,
    `signature`, `hash`) prevent classic mix-ups at compile time.
  - AEAD returns an error on tag failure; HEXA never silently decrypts garbage.
  - `crypto.key.generate` produces strong random keys; `std.random.bytes` is
    the CSPRNG path for salts/nonces.
  - Multi-layer encryption keys are HKDF-derived per layer, so a single leaked
    subkey does not expose other layers.
- **Residual:** developer explicitly reuses nonces/salts anyway; no compiler
  can prevent every misuse.

### Adversary TB7 — Reverse engineering of binaries
- **Profile:** attacker analyzes a distributed HEXA executable to extract
  embedded secrets or logic.
- **Mitigations:** HEXA does **not** rely on code obscurity; it ships
  `disassemble`/`decompile` itself. Security comes from keeping secrets out of
  binaries (never embed keys) and from the type system, not from hiding
  instructions.
- **Residual:** any secret embedded in a binary is recoverable. Developers must
  not embed secrets in distributed artifacts. See
  [25-decompilation.md](25-decompilation.md).

---

## 4. Out-of-scope / explicit non-goals

HEXA does **not** provide:

- Defense against a compromised OS, kernel, or hardware (TB4).
- Immunity to physical surveillance, screenshots, or terminal scrollback
  capture of anything displayed (the one-time key, `secret.export` output).
- Key recovery of any kind for generated one-time keys — by design.
- Proof against the mathematical impossibility of brute force. HEXA promises
  infeasibility for strong keys, not impossibility.
- Side-channel (power/EM/timing) resistance claims in this milestone.
- Protection of secrets the developer explicitly exports and shares.

## 5. Mitigation summary matrix

| Threat | Mitigation | Where enforced |
|--------|-----------|----------------|
| Program prints a secret | `E2100` | Compile time |
| Program downgrades a secret to text/bytes | `E2101` | Compile time |
| Program casts a secret to plain data | `E2102` | Compile time |
| Hardcoded secret in source | `SEC001` | Compile time |
| File theft of ciphertext | AEAD + key never stored | Runtime/format |
| Tampering with containers | `AUTH_TAG` → `EHEX-007` | Runtime/format |
| Past-key recovery from HEXA | One-time lifecycle, `EKEY-004` | Design |
| Weak-password brute force | Argon2id/scrypt memory hardness | Runtime |
| Crypto API mix-ups | Security types | Compile time |
| Malware / compromised OS / capture | **Not defensible** | — |
| Reverse engineering | **Not a protection goal** | — |

## 6. Known residual risks (accepted)

1. `secret.export` misuse — accepted; the action is explicit and reviewable.
2. Weak user passwords — accepted with documented KDF cost guidance.
3. Machine compromise — accepted by scope; operational controls required.
4. Distribution tampering — accepted; mitigate with signed/verified artifacts
   (planned, see package manager).
5. Side channels — accepted for this milestone.

## 7. Evolving the model

Threat-model changes are versioned. New attacks (e.g. discovered algorithm
weaknesses, hardware attacks) will be reviewed against this document and the
changelog will record the outcome. Nonces/salts must always be fresh; if an
algorithm needs deprecation, it will be flagged (`SEC003`-style analysis) and
removed in a later format version.

---

*This document is the authoritative threat-model statement for the current
milestone. Related: [17-security-model.md](17-security-model.md),
[26-security-best-practices.md](26-security-best-practices.md).*
  (Ed25519/X25519) is standard but not absolute immunity.