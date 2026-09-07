# The compiler

HEXA's compiler is a **bootstrap** — written in Rust — that compiles HEXA source
(`.he`) to native code. This document walks through its pipeline.

## Pipeline overview

The compiler is organized as a sequence of stages, each producing a structured
intermediate form and reporting diagnostics:

```
source (.he)
   │  Lexer            (E1xxx)
   ▼
tokens
   │  Parser           (structure)
   ▼
AST
   │  Type checker     (E2xxx, E21xx)
   ▼
typed AST
   │  Security analysis (SEC00x)
   ▼
annotated AST
   │  Native codegen   (emitted assembly)
   ▼
assembly (.s)
   │  as / ld           (system toolchain)
   ▼
native executable
```

Commands map onto this pipeline:

- `hexa check` runs lexer → parser → type checker → security analysis.
- `hexa build` runs the full pipeline to a native executable.
- `hexa run` builds then executes.

## Stages

### 1. Lexer
Reads source text and produces tokens with spans (file, start, end). Handles
strings, byte strings, characters, numbers, identifiers, keywords, and comments
(`//` and nested `/* */`). Reports `E1001`–`E1015` on malformed input.

### 2. Parser
Consumes tokens and produces an **AST** (abstract syntax tree) with spans.
Handles functions, variables, control flow, structs, enums, and type
expressions.

### 3. Type checker
Resolves names, infers expression types, verifies function signatures and
argument counts, and — crucially — enforces the **security-sensitive
conversion rules**. Emits `E2000`–`E2007` and the secret-safety codes
`E2100`–`E2102`.

### 4. Security analysis
A static pass that flags risky patterns: hardcoded secrets, and other
dangerous flows. Emits `SEC001`–`SEC006`.

### 5. Native code generation
Emits `x86_64` assembly from the typed AST, plus the libc-free runtime, and
links it with the system `as`/`ld`. See [Native compilation](22-native-compilation.md).

## Diagnostics

Every stage reports through a shared diagnostics infrastructure: severity,
stable code, source span, snippet+caret, and optional hint. The complete catalog
is in [ERROR-CODES.md](ERROR-CODES.md).

## Design goals

- **One error surface.** All stages funnel into one structured diagnostic
  format.
- **Fail closed.** Any error aborts the build; an unsafe program is never
  emitted.
- **Small, auditable.** A minimilist bootstrap that is eventually self-hosted
  (see [Self-hosting](29-self-hosting.md)).

## Status

The current milestone implements the front end (lexer/parser/AST/type checker),
security analysis, and a working native codegen path. Richer intermediate
representation, advanced optimization, and the full compiler-as-a-library API
are **(planned / later phase)**.

Next: [Intermediate representation](21-ir.md).
