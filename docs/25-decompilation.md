# Decompilation

`hexa decompile` is a best-effort tool that reconstructs source-level structure
from a compiled HEXA binary. It is the inverse of the compiler's native backend
and, like all decompilers, is approximate.

## Usage

```bash
hexa decompile ./hello        # attempt to reconstruct structure from a binary
```

The tool analyzes the disassembly, recognizes the calling conventions, syscall
wrappers, and runtime patterns produced by HEXA's code generator, and emits a
best-effort source-like reconstruction.

## What it can recover

- **Function boundaries** — where functions begin and end.
- **Control flow** — branches, loops, and conditional blocks, reconstructed
  into `if`/`while`-like shapes.
- **Calls** — which runtime/std functions are invoked (e.g. a `print` or
  `crypto.hash.sha256` call site).
- **String and byte constants** embedded in the binary.

## Honest limits

Decompilation **cannot** reliably recover:

- **Original variable names** — the compiler does not keep them in machine
  code.
- **High-level type information** — including the security-sensitive types
  (`password`, `key`, ...), which exist only at compile time.
- **Comments and intent** — mechanical reconstruction loses all documentation.
- **Exact source text** — many different sources compile to similar machine
  code.

A decompiled result is a starting point for analysis, never a reproduction of
the original source.

## Security note

HEXA supports this tool internally and transparently. Its existence reinforces
the security model: HEXA does **not** rely on secret-by-obscurity. Protection
comes from the compile-time secret rules and key lifecycle, not from making
binaries hard to read. At the same time, users should assume that any binary
they distribute can be decompiled and analyzed — never put secrets (or the
one-time key) into a distributed artifact.

## Status

Decompilation quality improves with the planned richer IR, which preserves more
semantic structure. The current milestone provides the working best-effort
version.

Next: [Security best practices](26-security-best-practices.md).
