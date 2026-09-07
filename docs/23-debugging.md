# Debugging

Debugging HEXA programs is supported through compile-time diagnostics, the
`check`/`format` commands, and inspection of compiled output. This document
covers the available tooling and current limits.

## Compile-time diagnostics are the primary debugger

Because HEXA pushes so much safety to compile time, most bugs surface *before*
the program runs, with precise source locations:

```
error[E2003]: Cannot use `text` where `integer` is required.
  --> bug.he:5:14
   |
 5 |     let n: integer = name;
   |                  ^
   Expected: integer
   Found: text
```

Run `hexa check file.he` to see every diagnostic without building.

## `hexa format`

Style lints can reveal structure issues. `hexa format file.he` reindents to the
canonical 4-space style and reports `STYLE001` (indentation) and `STYLE002`
(other style) findings.

## `hexa doctor`

If the toolchain itself is misconfigured, `hexa doctor` reports missing tools
(`as`, `ld`, runtime) and environment problems. Run it first if builds fail in
mysterious ways.

## `hexa disassemble` and `hexa decompile`

Two commands help debug generated code:

- `hexa disassemble binary` — prints the disassembly of a compiled HEXA binary
  (or its assembly). Useful to verify what the compiler actually emitted for a
  given source construct.
- `hexa decompile binary` — best-effort reconstruction toward source-level
  structure, useful when you only have a binary.

See [Disassembly](24-disassembly.md) and [Decompilation](25-decompilation.md).

## `print` for ordinary values

For non-secret values, `print(...)` and `to_text(...)` are the basic debug
tools:

```he
let total: integer = 40 + 2;
print("total = " + to_text(total));
```

## Debugging secrets

You cannot `print` a secret — that is a compile error (`E2100`), on purpose. To
inspect *non-secret* derived values (e.g. a hash or public key meant for
sharing), use the explicit cast/export path only when safe. Never log passwords
or keys. Debug a secret workflow by verifying outputs you *can* print (hashes,
lengths, success flags) rather than the secret itself.

## Current limitations

- A full interactive debugger (breakpoints, stepping, watch) is
  **(planned / later phase)**.
- Debug symbols and line-table fidelity are early; improvements accompany the
  planned IR work (see [IR](21-ir.md)).

Next: [Disassembly](24-disassembly.md).
