# HEXA error codes

Every diagnostic produced by HEXA carries a stable error code. Codes are
grouped into families so you can tell at a glance which part of the toolchain
reported the problem.

## Families at a glance

| Family        | Area                  |
|---------------|-----------------------|
| `E1xxx`       | Lexer                 |
| `E2xxx`       | Type checker          |
| `E21xx`       | Secret-safety         |
| `SEC00x`      | Security analysis     |
| `EKEY-00x`    | Key lifecycle         |
| `EHEX-0xx`    | `.hexa` format        |
| `STYLE0xx`    | Style lints           |

---

## Lexer errors (`E1xxx`)

| Code | Meaning | Hint |
|------|---------|------|
| `E1001` | Unexpected / malformed token | Check the token at the caret; a keyword or symbol may be mis-typed. |
| `E1002` | Unterminated string, byte-string, or character literal | Close the literal with the correct quote. |
| `E1003` | Invalid character in source | Remove or replace the offending byte. |
| `E1004` | Invalid numeric literal | Correct the number syntax. |
| `E1006` | Invalid escape sequence (`\x`, `\u`, or unknown `\`-escape) | Use a valid escape (e.g. `\n`, `\t`, `\\`, `\x41`, `\u{1F600}`). |
| `E1015` | Unterminated block comment (`/* ... */` not closed) | Close the comment; block comments nest. |

---

## Type-checker errors (`E2xxx`)

| Code | Meaning | Hint |
|------|---------|------|
| `E2000` | Unknown type `name` | Use a built-in type, a security type, or a declared struct/enum. |
| `E2001` | Cannot find value `name` | The name is not declared in scope. |
| `E2002` | `let` binding requires a type or an initializer | Add either `: type` or `= value`. |
| `E2003` | Type mismatch / bad operator / invalid cast | Align types; check operands and `as` conversions. |
| `E2004` | Unknown function / invalid callee / function used as a value | Call with `(...)`; check the name. |
| `E2005` | Bad indexing or `for` over a non-array | Index arrays/maps/text/bytes only; loop over arrays. |
| `E2006` | Return mismatch (value where none expected, or wrong/missing return) | Return the declared type, or nothing, consistently. |
| `E2007` | Wrong argument count | Pass exactly the declared parameters. |

---

## Secret-safety errors (`E21xx`)

| Code | Meaning | Hint |
|------|---------|------|
| `E2100` | Cannot print a secret type — sensitive values are never printed implicitly | Export with `secret.export(...)` only if certain it is safe to reveal; otherwise never display it. |
| `E2101` | Cannot use a sensitive value where `text`/`bytes` is required without an explicit export | Convert with `secret.export(...)`; implicit downgrades are forbidden. |
| `E2102` | Cannot cast a sensitive value to ordinary data | Sensitive values cannot be downgraded with `as`; use `secret.export(...)` deliberately, or keep the value secret. |

These three codes are the teeth of HEXA's security model: a secret may never
silently become ordinary data.

---

## Security-analysis findings (`SEC001`–`SEC006`)

Static security analysis flags risky patterns. Findings are reported by
`hexa check` and `hexa build`, and are treated as errors so that unsafe
programs do not build (fail-closed).

| Code | Finding | Mitigation |
|------|---------|-----------|
| `SEC001` | Hardcoded secret literal (password/key/API key in source) | Obtain secrets from `secret.input` or a secure store; never embed them. |
| `SEC002` | Sensitive value escaping a secret context without `secret.export` | Restrict the flow or add an explicit, reviewed export. |
| `SEC003` | Weak/discouraged algorithm for the purpose (e.g. non-memory-hard KDF for passwords) | Prefer Argon2id (then scrypt) for passwords; use PBKDF2/HKDF where appropriate. |
| `SEC004` | Sensitive value passed to a function that does not handle secret data | Pass only non-secret data, or use a secret-aware API. |
| `SEC005` | Missing `secret.wipe` on a secret at the end of its use | Call `secret.wipe(value)` when done. |
| `SEC006` | Insecure randomness used for key/secret material | Use `std.random.bytes` or `crypto.key.generate`; never deterministic sources for keys. |

---

## Key-lifecycle errors (`EKEY-001`–`EKEY-004`)

| Code | Meaning | Hint |
|------|---------|------|
| `EKEY-001` | Key generation failed | The RNG/platform source failed; retry/check environment. |
| `EKEY-002` | No key available for the requested operation | A key is required (e.g. decrypt prompt); supply the one-time key. |
| `EKEY-003` | Invalid key format supplied | Expected the `HX-<hex>` form shown at encrypt time. |
| `EKEY-004` | Key recovery is not possible — generated keys are never recoverable by HEXA | Copy the key when it is first displayed. There is **no** `key show`/`recover`/`reveal`; `hexa key show` always fails with this code. |

`EKEY-004` is intentional and immune to removal: the entire purpose of the
---

## `.hexa` format errors (`EHEX-001`–`EHEX-010`)

| Code | Meaning |
|------|---------|
| `EHEX-001` | Bad magic — the file is not a `.hexa` container |
| `EHEX-002` | Unsupported `VERSION` |
| `EHEX-003` | Malformed/truncated header |
| `EHEX-004` | Unsupported `ALGORITHM` |
| `EHEX-005` | Unsupported `KDF` |
| `EHEX-006` | Invalid or undecodable KDF parameters |
| `EHEX-007` | Authentication failure — AEAD tag did not validate (tampering or wrong key) |
| `EHEX-008` | Payload length inconsistent with file size |
| `EHEX-009` | Invalid metadata encoding (not UTF-8) |
| `EHEX-010` | Salt/nonce/layer-count inconsistency (e.g. multi-layer nonce count) |

See [HEXA-FORMAT.md](HEXA-FORMAT.md) for the field layout these validate.

---

## Style lints (`STYLE001`–`STYLE002`)

Reported by `hexa format` (and `hexa check` as warnings).

| Code | Lint |
|------|------|
| `STYLE001` | Indentation is not the canonical 4-space style |
| `STYLE002` | Naming/style conventions not followed (e.g. `snake_case` variables, `SCREAMING_SNAKE_CASE` constants) |

Run `hexa format <file>` to apply canonical style automatically.

---

## Notes

- Codes are stable identifiers; do not change their meaning across versions
  without documenting a rename in the changelog.
- Diagnostics always include the code, message, source span (`file:line:col`),
  a caret snippet, and an optional `help:` hint.
- See [09-error-handling.md](09-error-handling.md) for how diagnostics are
  presented.
one-time lifecycle is that no stored/displayable key remains to be shown.