# Package manager

HEXA can package programs and libraries for distribution, and install/uninstall
them on a machine. The implementation is **fail-closed by design**: an archive
is never trusted until every check passes, and nothing is installed unless the
packaged program actually compiles.

## Commands

### `hexa package [dir]`
Package a project into a distributable `.hxpkg` artifact. The project is
described by a `hexa.toml` manifest; with no manifest, a single top-level
`.he` file is packaged with inferred metadata.

```bash
hexa package mylib.he          # → mylib-0.1.0.hxpkg (inferred manifest)
hexa package ./my-project      # uses ./my-project/hexa.toml
```

Manifest format:

```toml
[package]
name = "mylib"            # lowercase letters, digits, '-' or '_'
version = "1.0.0"         # MAJOR.MINOR.PATCH, numeric, no leading zeros
entry_point = "main.he"   # packaged .he path (relative, no '..')
description = "..."       # optional
license = "MIT"           # optional
```

### `hexa install <package.hxpkg>`
Verify, compile and install a package. The archive is fully validated in
memory first (magic, format version, per-file SHA-256, whole-file SHA-256,
path-safety, resource ceilings), extracted into a staging directory, and the
entry point is compiled with the real compiler. Only on success is the
staging tree committed, a launcher shim written, and the registry updated.
Installing a package whose program does not compile is impossible; installing
over a live package is refused (`hexa update` replaces instead).

```bash
hexa install mylib-1.0.0.hxpkg
```

### `hexa list`
Show installed packages and versions.

### `hexa remove <name>` (alias: `uninstall`)
Remove a package: delete `pkg/<name>/`, remove the launcher shim, tombstone
the registry entry, and clean up desktop entries.

### `hexa update <package.hxpkg>`
Replace an installed package with a new version in one step
(remove + install, with the old version announced).

## Artifact format (`.hxpkg`, version 1)

```text
"HXPKG"          5 bytes magic
version: u16     format version (1, little-endian)
mlen:    u32     manifest length
manifest         UTF-8 TOML ([package] table)
count:   u32     number of packaged files
per file:        plen:u16, path, flen:u64, content, sha256(content)
trailer          sha256 of everything above
```

Security rules enforced at decode time: no absolute paths, no `..`
components, no hidden components, no backslashes or NUL bytes, size/count
ceilings (`MAX_FILES`, `MAX_FILE_SIZE`, `MAX_TOTAL`), and the entry point
must exist among the packaged files.

## Install layout (`$HEXA_HOME`, default `~/.hexa`)

```
$HEXA_HOME/
├── bin/<name>                 launcher shim (exec pkg/<name>/<version>/bin/<name>)
├── pkg/<name>/<version>/      installed package tree
│   └── bin/<name>             native executable built at install time
├── pkg/installed.json         append-only JSON-lines registry (tombstones on removal)
├── share/applications/        freedesktop .desktop entries (best-effort)
├── share/icons/...            embedded SVG icons
└── share/mime/packages/       x-hexa/hexa-package MIME registration
```

Set `HEXA_HOME` to relocate the entire prefix (useful for testing and
per-project sandboxes).

## Relationship to `tools/install.sh`

The shell installer (`tools/install.sh`) installs the **HEXA toolchain itself**
(the `hexa` binary and the `std/` reference files). The `hexa package` /
`install` / `remove` commands manage **HEXA packages** (programs/libraries
written in HEXA).

## Planned direction (later phase)

- Dependency resolution and a package index/registry.
- Semver version constraints and range matching.
- Signing of `.hxpkg` artifacts beyond checksums.

The current milestone's packaging is a working, honest vertical slice; richer
ecosystem features are **(planned / later phase)**.

Next: [The compiler](20-compiler.md).
