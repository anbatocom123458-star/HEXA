# Self-hosting

HEXA is written in **Rust as a bootstrap**: the current compiler is implemented
in Rust. A long-term goal of the project is for HEXA to **compile itself** —
writing the HEXA compiler in HEXA. This document explains why and what it means.

## Why self-host

1. **Independence.** A self-hosted compiler depends on no other language to
   build HEXA. The toolchain becomes self-contained.
2. **Dogfooding.** The compiler is the most demanding HEXA program there is.
   Writing it in HEXA exercises the language, the security types, the native
   backend, and the standard library far beyond any example program.
3. **Auditability.** A small, self-hosted compiler that a competent engineer
   can read in full is a stronger trust anchor than an opaque one.
4. **Security.** The security-sensitive type system is exactly the kind of code
   that benefits from compile-time secret containment (compiler internals
   often touch keys and credentials).

## The bootstrap path

The standard strategy for a self-hosting language (the "Tombstone"/"T-diagram"
approach):

```
stage 0: HEXA compiler written in Rust   (current milestone — bootstrap)
stage 1: HEXA compiler translated and written in HEXA, built by stage 0
stage 2: stage-1 compiler rebuilds itself, proving it is self-sufficient
```

Once stage 2 builds itself successfully on a clean system, HEXA is self-hosting
in the same sense that C compilers and many language runtimes are.

## What this milestone provides

The current milestone lays the groundwork: a real front end (lexer, parser,
AST, type checker), a security type system rich enough to express a compiler's
data, a working native backend, and a functional standard library. These are
the raw materials a self-hosting compiler needs.

## Status

Self-hosting is **(planned / later phase)**. It requires:

- A complete, expressive type system and module system (multi-file modules are
  planned — see [08-modules.md](08-modules.md)).
- A richer standard library (`std/collections`, `std/fs`, string processing).
- The planned IR for principled code generation (see [21-ir.md](21-ir.md)).
- A full standard-library implementation of the compiler's own runtime needs.

When self-hosting lands, this document will be updated with the stage-1/stage-2
build instructions and proof.

## Why it's not the current priority

Correctness and the security guarantees come first. A self-hosting compiler is
only valuable if the language it is written in is already solid, honest, and
capable of expressing the compiler itself — which is what the current milestone
is building toward.

Next: [Key length system](30-key-length-system.md).
