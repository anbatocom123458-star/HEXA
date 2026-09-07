# Threat model

This document is the defensive core of HEXA: a clear, honest statement of who
the adversaries are, what assets we protect, what HEXA defends against, and —
equally important — what it cannot. Read this before trusting HEXA with real
data.

## Assets

1. **Secrets in programs**: passwords, keys, private keys, API keys,
   credentials, plaintext.
2. **Encrypted data**: `.hexa` containers and ciphertext at rest.
3. **The one-time encryption key** shown by `hexa encrypt`.
4. **The integrity of programs**: that what you wrote is what runs.

## Trust boundaries

- **The machine is trusted.** HEXA's guarantees hold on a machine whose OS and
  hardware you trust. If the OS is compromised, everything upstream is moot.
- **The compiler is trusted.** A malicious/buggy compiler could weaken
  guarantees; HEXA's bootstrap aims to be auditable and eventually self-hosting.
- **The user is trusted to hold the one-time key.** HEXA will not store or
  recover it, by design.
- **Programs are NOT trusted with secrets they don't need.** The whole point of
  the secret-safe type system is that a program *cannot* leak what it was not
  allowed to handle.

## Adversaries and countermeasures

### A1. Accidental leaks by the program itself
*Threat:* a program prints, logs, or serializes a password/key accidentally.

*Countermeasure:* **compile-time secret rules.** `print` of a secret (`E2100`),
implicit downgrade (`E2101`), and cast (`E2102`) are build errors. This is
HEXA's strongest guarantee and its flagship feature.

### A2. An attacker who steals the files
*Threat:* someone copies your `.hexa` containers and other data.

*Countermeasure:* **authenticated encryption.** Without the key, ciphertext is
confidential; tampering is detected via the AEAD tag. The one-time key is never
stored in the container or by HEXA, so file theft does not yield the key.

### A3. An attacker who gains access to your account/machine's data later
*Threat:* later compromise tries to recover previously generated keys.

*Countermeasure:* **one-time key lifecycle.** `hexa key show` always fails with
`EKEY-004`. There is no key store to steal, because none exists.

### A4. Brute-force / offline guessing
*Threat:* attacker brute-forces weak passwords or keys.

*Countermeasure:* **memory-hard KDFs** (Argon2id, scrypt) raise the cost of
guessing passwords; 256-bit keys make direct brute force infeasible in
practice. HEXA never claims brute force is *impossible* — only that strong keys
make it infeasible.

### A5. Tampering with data or containers
*Threat:* modifying a `.hexa` file or a message.

*Countermeasure:* **AEAD authentication tags** and the versioned, magic-tagged
header (`EHEX-0xx` detection).

### A6. Misuse of cryptographic APIs
*Threat:* reusing nonces, using raw passwords as keys, mixing up plaintext and
ciphertext.

*Countermeasure:* **type-driven crypto** — `plaintext`/`ciphertext`/`key` are
distinct types; the compiler prevents many classic mistakes. Best practices in
[26-security-best-practices.md](26-security-best-practices.md).

## Explicitly OUT of scope — what HEXA cannot protect

Be direct about these. HEXA does **not** defend against:

- **A compromised operating system or hardware.** Malware, rootkits, and
  keyloggers on the machine can read memory, observe syscalls, and log input.
- **Physical access / screen capture.** The one-time key display and any
  `secret.export` output can be photographed or captured by a screen-grabber.
- **Terminal scrollback.** Exported values are ordinary text and may persist in
  the terminal buffer.
- **Reverse engineering.** Native code can be disassembled/decompiled (two
  commands HEXA ships); security does not rely on hiding code.
- **One-time key loss.** A lost key means unrecoverable data — the accepted cost
  of never storing it.
- **Absolute brute-force impossibility.** No algorithm is "uncrackable"; HEXA
  promises infeasibility for strong keys, not impossibility.
- **Side channels** (power, EM, timing) — not claimed as resistant in this
  milestone.
- **User error beyond what the type system catches** — e.g. deliberately
  calling `secret.export` on a secret and sharing the result.

## Residual risks summary

| Risk | Status |
|------|--------|
| Program leaks a secret it handled | **Mitigated** (compile error) |
| Container stolen | **Mitigated** (authenticated encryption) |
| Key recovered from HEXA | **Mitigated** (one-time lifecycle, `EKEY-004`) |
| Weak password brute-forced | **Reduced** (Argon2id/scrypt) |
| Compromised OS/malware | **Not defensible** — out of scope |
| Physical/screen capture | **Not defensible** — out of scope |
| One-time key lost by user | **Not defensible** — by design |

## Design principle

> HEXA's job is to keep secrets away from **the program's own mistakes** and
> from **casual later compromise of files**, not to defeat an adversary who
> already controls the machine. By being explicit about this boundary, users
> can make informed decisions about where and when to trust HEXA.

Next: [FAQ](28-faq.md).
