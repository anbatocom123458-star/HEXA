# Installation

HEXA is distributed as source in a Rust workspace. There are two supported ways
to get a working `hexa` binary: **build it yourself**, or use the **installer
script** to build and install it system-wide.

## Prerequisites

- **Rust toolchain** (`cargo`, `rustc`) — required to build. On Debian/Ubuntu:
  `apt install cargo rustc`. On macOS: `brew install rust`. See
  [rustup.rs](https://rustup.rs).
- **An `x86_64` target** and the system **`as`** (GNU assembler) and **`ld`**
  (linker) toolchains, used by the native backend.
- A POSIX-like operating system (Linux or macOS). Windows is **(planned /
  later phase)**.

## Method 1 — Build from source

```bash
git clone https://github.com/anbatocom123458-star/HEXA.git
cd HEXA
cargo build --release
```

The `hexa` binary is produced at:

```
./target/release/hexa
```

Check it works:

```bash
./target/release/hexa version
```

You can run the binary in place. Optionally copy it somewhere on your `PATH`:

```bash
sudo cp ./target/release/hexa /usr/local/bin/hexa
```

## Method 2 — Installer script

A robust installer is provided at `tools/install.sh`. It:

1. Detects the operating system.
2. Builds the release binary with `cargo` if it is not already present.
3. Installs the `hexa` binary to `/usr/local/bin/hexa` (or builds in place).
4. Installs the standard-library reference files to
   `$PREFIX/share/hexa/std`.
5. Configures `PATH`.
6. Registers `.he` and `.hexa` MIME types and a desktop entry on Linux under
   `~/.local/share`.
7. Creates an uninstall script at `$PREFIX/share/hexa/uninstall.sh` and an
   install log.

```bash
cd HEXA
bash tools/install.sh
```

At the end, the installer prints `hexa version` to confirm the install.

To remove it later:

```bash
bash /usr/local/share/hexa/uninstall.sh
# (or the $PREFIX path used at install time)
```

## Verifying the install

```bash
hexa version
hexa doctor        # checks the toolchain, runtime, and environment
```

`hexa doctor` reports whether all dependencies (assembler, linker, runtime) are
available and detects common problems.

## Source layout after install

The installed tree looks like:

```
$PREFIX/share/hexa/
├── std/        standard-library reference .he files
├── uninstall.sh
└── install.log
```

## Uninstalling manually

Delete the binary, the share directory, and any desktop/MIME entries created by
the installer. The uninstall script automates all of this — prefer using it.

## Supported platforms

| Platform       | Status                        |
|----------------|-------------------------------|
| Linux x86_64   | Supported                     |
| macOS x86_64   | Supported (system toolchain)  |
| Windows        | **(planned / later phase)**   |
| Other arches   | **(planned / later phase)**   |

Next: [Hello, world](03-hello-world.md).
