# Security best practices

This page collects the practical, day-to-day habits that keep HEXA users safe.
It complements the [Security model](17-security-model.md) and the
[Threat model](27-threat-model.md).

## At the code level

1. **Use security types, and trust the compiler.**

   Let `secret.input`, `password`, `key`, `ciphertext`, and friends carry the
   sensitivity. If the compiler errors with `E2101`, that is not a nuisance —
   it is a leak that did not ship.

2. **Never print or cast secrets.**

   - `print(password_var)` → `E2100`.
   - `let s: text = secret_var` → `E2101`.
   - `secret_var as text` → `E2102`.
   The only sanctioned outward path is `secret.export(...)`, and only when you
   are certain the value is safe to reveal.

3. **Wipe secrets when done.** Use `secret.wipe(value)` so sensitive bytes do
   not linger in memory (see [Memory model](10-memory-model.md)).

4. **Prefer `secret.input` over `input.text`** for anything sensitive, so the
   value is typed as a secret from the moment of collection.

5. **Never hardcode secrets.** Hardcoded passwords and keys in source are
   flagged by security analysis (`SEC00x`). Use `secret.input` or environment/
   key-management inputs instead.

6. **Derive, don't reuse.** Key an encryption key from a password with a
   memory-hard KDF (Argon2id) and a fresh salt. Never use raw password bytes as
   a key. Derive per-layer keys with HKDF for multi-layer encryption.

7. **Use fresh randomness.** Salts and nonces must be fresh and random
   (`std.random.bytes`); never reuse a nonce with the same key.

## At the workflow level

8. **Record the one-time key immediately.** When `hexa encrypt` shows the
   `HX-<hex>` key, copy it to a safe place (an offline password manager) the
   moment it appears. HEXA will never show it or recover it again.

9. **Back up the ciphertext *and* keep the key in a different place** than the
   files. Losing the key is losing the data; losing the ciphertext with the key
   is also losing the data.

10. **Run `hexa doctor`** to confirm the toolchain is healthy before relying on
    it.

11. **Prefer authenticated encryption** (AES-256-GCM / ChaCha20-Poly1305) —
    already the default — so tampering is detected.

## At the environment level

12. **Run on a machine you trust.** Keep the OS updated and free of malware.
    HEXA cannot defend an already-compromised OS.

13. **Mind the terminal.** Anything shown through `secret.export` or the
    one-time key display is ordinary text afterward — it can live in scrollback
    or be captured in screenshots.

14. **Watch physical access and screen sharing.** A shoulder-surfer can read the
    one-time key banner just as well as you.

15. **Disable/acknowledge swap and core dumps** for processes handling highly
    sensitive material, to avoid secret bytes reaching disk.

## A pocket checklist for writing a secure HEXA program

- [ ] Sensitive input uses `secret.input`.
- [ ] No `print`, cast, or implicit conversion of any secret.
- [ ] Every required export is justified and minimal.
- [ ] `secret.wipe` called on each secret when done.
- [ ] KDF produced the encryption/signing keys (no raw-password keys).
- [ ] Fresh random salt and nonce per operation.
- [ ] No hardcoded secrets in source.

See also [26-independent threat analysis](27-threat-model.md) for the defensive
reasoning behind these rules.

Next: [Threat model](27-threat-model.md).
