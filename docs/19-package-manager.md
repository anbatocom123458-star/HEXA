# Package manager

HEXA can package programs and libraries for distribution, and install/uninstall
them on a machine. This document covers the current milestone's commands and
the planned direction.

## Commands

### `hexa package`
Package a program or library into a distributable `.hexa` container. The
container is the versioned, authenticated format described in
[16-hexa-file-format.md](16-hexa-file-format.md) and
[HEXA-FORMAT.md](HEXA-FORMAT.md), carrying source, metadata, and payload.

```bash
hexa package mylib.he
# → mylib.hexa
```

### `hexa install <package.hexa>`
Install a packaged HEXA program/library. Installed components land under the
HEXA share directory (mirroring `$PREFIX/share/hexa/`) and become usable by
name. An install log is maintained.

```bash
hexa install mylib.hexa
```

### `hexa uninstall <package>`
Remove a previously installed package.

```bash
hexa uninstall mylib
```

## Relationship to `tools/install.sh`

The shell installer (`tools/install.sh`) installs the **HEXA toolchain itself**
(the `hexa` binary and the `std/` reference files). The `hexa install` /
`uninstall` commands manage **HEXA packages** (programs/libraries written in
HEXA). Both share the same on-disk layout under `$PREFIX/share/hexa/`.

## Layout of an installed package

```
$PREFIX/share/hexa/
├── std/            standard-library reference files (toolchain install)
├── pkg/<name>/     installed packages
├── install.log
└── uninstall.sh    toolchain uninstaller
```

## Planned direction (later phase)

- Dependency resolution and a package index/registry.
- Semver version constraints and `hexa update`.
- Offline/vendored dependency caches with integrity verification via the
  `.hexa` authentication tag.

The current milestone's packaging is a working, honest vertical slice; richer
ecosystem features are **(planned / later phase)**.

Next: [The compiler](20-compiler.md).
