# Frequently asked questions

### What is HEXA?
HEXA is a secure programming language and cryptography toolchain, written in
Rust as a bootstrap, that compiles `.he` programs to native `x86_64` code and
provides authenticated encryption through `hexa` CLI commands and a
cryptographic standard library.

### Why do security types exist?
So dangerous operations fail to compile. `print(secret)`, casting a secret to
`text`, or using a secret where ordinary data is required are compile errors —
the leak is caught before the program exists.

### Can I print a secret?
No. `print(x)` on a security-sensitive value (`secret`, `key`, `private_key`,
`apikey`, `password`, `credential`) is a compile error (`E2100`). Export via
`secret.export(...)` only when you are certain it is safe.

### What is a one-time key?
When you run `hexa encrypt file`, HEXA generates a key, shows it once as
`HX-<hex>` with a warning, and never stores it. You must copy it somewhere safe
immediately. Losing it means the data is unrecoverable.

### How do I recover a generated key?
You cannot — by design. There is no `hexa key show`/`recover`/`reveal`.
`hexa key show` always fails with `EKEY-004`. If a key were recoverable, an
attacker who compromised the machine could recover it too.

### Is HEXA "uncrackable" or "military grade"?
No, and HEXA refuses to claim so. AES-256-GCM/ChaCha20-Poly1305 with strong
keys make brute force *infeasible*, and memory-hard KDFs make password guessing
expensive — but "impossible" belongs to marketing, not to honest security
engineering. See [Security model](17-security-model.md).

### Can HEXA protect me from malware or a hacked OS?
No. If the operating system or hardware is compromised, the attacker can read
memory and observe everything. HEXA protects against accidents in your own
programs and against casual file theft, not against an adversary who already
controls the machine.

### What algorithms does HEXA implement?
AES-256-GCM, ChaCha20-Poly1305, Argon2id, scrypt, PBKDF2, HKDF, SHA-2
(256/384/512), SHA-3 (256/512), BLAKE2b, BLAKE3, Ed25519, and X25519.

### What is a `.hexa` file?
A versioned, authenticated binary container (v1) carrying magic, version,
algorithm, KDF + params, salt, nonce, layer count, metadata, payload, and an
AEAD auth tag. See [16-hexa-file-format.md](16-hexa-file-format.md) and
[HEXA-FORMAT.md](HEXA-FORMAT.md).

### How is multi-layer encryption keyed?
A master credential → Argon2id → master key → HKDF → independent per-layer
subkeys and nonces. Each layer has its own key/nonce so one leaked subkey
doesn't expose the data. See [15-multi-layer-encryption.md](15-multi-layer-encryption.md).

### How do I install HEXA?
Build with `cargo build --release` (`./target/release/hexa`) or run
`bash tools/install.sh` for a full install. See [Installation](02-installation.md).

### How do I check a program without building it?
`hexa check file.he` runs the full front end (lexer, parser, type checker,
security analysis) and prints diagnostics.

### Why is the runtime libc-free?
Smaller, more auditable, and gives the runtime direct control over where secret
bytes live and how syscalls are made. See [Native compilation](22-native-compilation.md).

### Can I use HEXA on Windows?
Not yet — that is **(planned / later phase)**. Current support is Linux and
macOS on `x86_64`.

### Is HEXA self-hosting?
Not yet. Self-hosting — the compiler compiling itself — is a documented later
phase. See [Self-hosting](29-self-hosting.md).

Next: [Self-hosting](29-self-hosting.md).
