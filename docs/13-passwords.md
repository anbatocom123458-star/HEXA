# Passwords

HEXA is built to handle passwords and other secrets without leaking them. This
section explains how to collect, store, and verify passwords safely.

## Collecting a password

Use `secret.input` rather than `input.text` for anything sensitive. It returns
a `password` type and (matching practice) does not echo input:

```he
let pw: password = secret.input("Password: ");
```

`secret.input` returns type `password`, which is in the **never-print** set.

Compare with `input.text`, which returns ordinary `text`:

```he
let name: text = input.text("Name: "); // not secret, fine to use freely
```

## Never store the plaintext password

Do not store a recovered password. Store a **derived verifier** instead, using
a memory-hard KDF with a random per-user salt — exactly what
`crypto.kdf.argon2id` is for:

```he
// On enrollment:
let pw: password = secret.input("Choose a password: ");
let salt: bytes = std.random.bytes(16);            // fresh random salt
let verifier: key = crypto.kdf.argon2id(pw as bytes, salt);
std.fs.write("verifier.bin", ...);                 // store salt + verifier
secret.wipe(pw);
```

On login, recompute the verifier from the supplied password and the stored salt,
then compare.

## Rules the compiler enforces for you

- `print(pw)` → **compile error** `E2100`. A password can never be printed.
- `let s: text = pw;` → **compile error** `E2101`. A password never degrades to
  ordinary text implicitly.
- `pw as text` / `pw as bytes` → **compile error** `E2102`. A password cannot be
  cast into ordinary data.

The only way to turn a password into usable bytes is an explicit, examined
path — for example `secret.export(pw)` (which returns `text` and must be used
only when you are certain it is safe) or a KDF/crypto call whose signature
accepts the derived form.

## Deriving keys from passwords

For encryption keyed by a human-chosen password, derive an encryption key with a
KDF — never use the password bytes directly as a key:

```he
let pw: password = secret.input("Password: ");
let salt: bytes = std.random.bytes(16);
let enc_key: key = crypto.kdf.argon2id(secret.export(pw) as bytes, salt);
```

Argon2id is resistant to GPU/ASIC brute force; scrypt is an alternative; PBKDF2
is the most compatible but not memory-hard, so prefer Argon2id where possible.

## Wiping

Secrets should not linger. Call `secret.wipe` when you are done:

```he
secret.wipe(pw);
```

See [Memory model](10-memory-model.md) for what wiping can and cannot guarantee.

## The CLI's use of passwords

`hexa encrypt` derives its master key from a one-time generated key (see
[Keys](12-keys.md)); the CLI can also derive a key from a user password via
Argon2id where appropriate. Either way, the password/KDF parameters are stored
in the `.hexa` header so the same derivation can be reproduced at decrypt time
— but the *password itself* is never stored.

Next: [Encryption](14-encryption.md).
