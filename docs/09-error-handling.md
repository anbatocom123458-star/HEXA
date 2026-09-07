# Error handling

HEXA reports problems at two very different times: **at compile time**, before
your program ever runs, and **at runtime**, while it is executing. The most
important philosophy of HEXA is to turn as many problems as possible into
compile-time errors — especially anything involving secrets.

## Compile-time diagnostics

The compiler produces structured diagnostics with four parts:

1. **Severity** — `error`, `warning`, or `note`.
2. **A stable code** — e.g. `E2003`, `SEC001`, `STYLE001`.
3. **A message** and a **source span** — `file:line:col` with a caret snippet.
4. **An optional hint** — a suggested fix.

Example output:

```
error[E2100]: cannot print secret type `password`
 --> secret.he:7:11
   |
 7 |     print(pw);
   |           ^
   help: Sensitive values are never printed implicitly. Export them
         explicitly with `secret.export(...)` if you are certain.
```

`hexa check` runs the whole compile pipeline up to type-checking and security
analysis and reports all diagnostics without emitting an executable.

## Error-code families

| Family        | Meaning                                 |
|---------------|-----------------------------------------|
| `E1xxx`       | Lexer errors (`E1001`–`E1015`)          |
| `E2xxx`       | Type-checker errors (`E2000`–`E2007`)   |
| `E21xx`       | Secret-safety violations (`E2100`–`E2102`) |
| `SEC001`–`SEC006` | Security-analysis findings          |
| `EKEY-001`–`EKEY-004` | Key-lifecycle errors             |
| `EHEX-0xx`    | `.hexa` format errors                   |
| `STYLE001`,`STYLE002` | Style lints                      |

The full catalog with suggested fixes is in
[ERROR-CODES.md](ERROR-CODES.md).

## Runtime handling with `result`

Many operations that can fail at runtime — reading a file, decoding base64,
decrypting — are designed to communicate success/failure through the
`result<O, E>` type rather than crashing:

```he
let outcome: result<text, text> = file.read("notes.txt");
match outcome {
    "ok" => { // payload available
    }
    "err" => { print("could not read file");
    }
    _ => { }
}
```

Exact result-construction syntax and pattern-matching ergonomics are being
refined in this milestone; cryptographic calls such as
`crypto.decrypt.aes256_gcm(data, key)` return `ciphertext`/`plaintext` values,
and the CLI (`hexa decrypt`) reports authentication failure as an error with an
`EHEX`/`EKEY` code.

## What happens on a check failure

`hexa build` and `hexa run` refuse to proceed if there are errors. Nothing is
emitted for a program that does not type-check or that fails security analysis.
This is the whole idea: bad programs never become executables.

## Handling the unavoidable

Some failure modes cannot be caught at compile time and are instead prevented
by design:

- **A wrong decryption key** → the AEAD authentication tag fails and HEXA
  reports an error; corrupted or mis-keyed ciphertext is rejected, never
  silently mis-decrypted.
- **A lost one-time key** → there is no error-handling path because there is no
  recovery; the ciphertext is simply unrecoverable (see
  [Keys](12-keys.md)).
- **A compromised environment** → HEXA cannot fix a hostile OS (see
  [Threat model](27-threat-model.md)).

Next: [Memory model](10-memory-model.md).
