# The `hexa` command-line interface

`hexa` is a single binary exposing the compiler, toolchain, cryptography
commands, and package management. Run `./target/release/hexa` (or the installed
`hexa`) with a subcommand.

```
hexa <command> [args]
```

## Commands (current milestone)

### `version`
Print the HEXA version and, typically, the build/format information.

```bash
hexa version
```

### `build <file.he>`
Type-check, run security analysis, and compile a `.he` program to a native
`x86_64` executable (via emitted assembly + `as`/`ld`).

```bash
hexa build hello.he
```

Fails (and emits no executable) if there are any errors.

### `run <file.he>`
Build the program if needed, then execute it.

```bash
hexa run hello.he
```

### `check <file.he>`
Type-check and run security analysis **without** emitting an executable. Useful
in editors and CI.

```bash
hexa check hello.he
```

### `format <file.he>`
Reformat a source file to canonical style (4-space indentation) and report the
style lints `STYLE001`/`STYLE002`.

### `encrypt <file>`
Encrypt a file with a freshly generated **one-time key**. Prints the key exactly
once as `HX-<hex>` with a warning banner, writes `<file>.hexa`, then destroys
the key.

```bash
hexa encrypt secret.txt
# → secret.txt.hexa
```

### `decrypt <file.hexa>`
Decrypt a `.hexa` container. HEXA prompts for the key (never echoed) and writes
the recovered plaintext. Fails loudly on a wrong/tampered key.

```bash
hexa decrypt secret.txt.hexa
```

### `inspect <file.hexa>`
Read a `.hexa` container and report its metadata: version, algorithm, KDF,
parameters, layer count, payload size, and header health — **without** exposing
any key.

```bash
hexa inspect secret.txt.hexa
```

### `key show`
Displays the one-time key... **it cannot.** By design there is no stored key to
show. This command always fails:

```
ERROR EKEY-004: Generated encryption keys are never recoverable by HEXA.
The key was displayed only once.
```

The command exists solely to make the absence explicit. See [Keys](12-keys.md).

### `doctor`
Diagnose the environment: availability of the assembler (`as`), linker (`ld`),
runtime, and other dependencies; report any problems.

```bash
hexa doctor
```

### `package`, `install`, `uninstall`
Package and manage HEXA packages. `install`/`uninstall` install or remove a
HEXA package (see [Package manager](19-package-manager.md)). The installer
script in `tools/install.sh` also installs the toolchain itself.

### `disassemble <binary>`
Disassemble a compiled HEXA executable (or assembly) to its instructions. See
[Disassembly](24-disassembly.md).

### `decompile <binary>`
Best-effort decompilation of a HEXA binary back toward source-level structure.
See [Decompilation](25-decompilation.md).

## Exit behavior

- Success: exit code `0`.
- Compile/type/security errors, and operational failures: non-zero exit with a
  structured message carrying an error code (e.g. `E2003`, `EKEY-004`,
  `EHEX-001`).

## Flags

The current milestone does **not** define an extensive flag surface; each
command accepts the documented positional arguments. Additional flags
(e.g. output paths, algorithm selection, layer counts on the CLI) are
**(planned / later phase)** — `hexa encrypt`/`decrypt` use their defaults
(AES-256-GCM, Argon2id-derived master key) unless extended later.

## Example session

```bash
$ hexa version
hexa 0.1.0

$ hexa check hello.he   # no output = all good

$ hexa run hello.he
Hello, world!

$ hexa encrypt notes.txt
... one-time key banner ...
notes.txt.hexa written (AES-256-GCM, Argon2id-derived master key).

$ hexa key show
ERROR EKEY-004: Generated encryption keys are never recoverable by HEXA.
The key was displayed only once.
```

Next: [Package manager](19-package-manager.md).
