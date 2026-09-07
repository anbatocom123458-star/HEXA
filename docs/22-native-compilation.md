# Native compilation

HEXA compiles programs to native `x86_64` machine code. It does so by emitting
assembly and driving the system **`as`** (assembler) and **`ld`** (linker),
with a **libc-free runtime** built on raw syscalls.

## The compilation path

```
type-checked AST
   ▼
emit x86_64 assembly (.s)
   ▼
system `as`  ──► object file (.o)
   ▼
system `ld`  ──► native executable
```

`hexa build file.he` performs all of these steps and produces an executable.
`hexa run file.he` builds and then executes it.

## Assembly emission

The code generator walks the typed AST and emits AT&T/GAS-syntax `x86_64`
assembly: labels, instructions for arithmetic/comparison/control flow,
function prologues/epilogues, and calls into the runtime where needed.

Because codegen works from the **typed** AST, the security information is
available: secret buffers are represented so that the runtime can wipe them, and
registers/stack slots holding secrets are handled deliberately.

## The libc-free runtime

The runtime crate implements the small amount of code a program needs that
isn't pure machine code — allocation, syscall wrappers, and crypto entry points:

- **Raw syscalls.** I/O, memory mapping, process exit, and so on are issued
  directly through syscall instructions, not libc. This removes a large,
  opaque dependency and gives the runtime direct control over sensitive bytes.
- **Allocation.** The heap is managed with `mmap`/`munmap` directly (see
  [Memory model](10-memory-model.md)).
- **Crypto.** The runtime links the crypto primitives (
  AES-256-GCM, ChaCha20-Poly1305, Argon2id, scrypt, PBKDF2, HKDF, SHA-2/3,
  BLAKE2/3, Ed25519, X25519).

## Why native?

- **Performance** — no interpreter or VM layer.
- **Control** — the runtime decides exactly how memory and syscalls behave,
  which matters for secrets.
- **Determinism and auditability** — a small runtime is easier to reason about
  than a large one.

## Dependencies

Compilation requires the system toolchain: `as` (GNU assembler or compatible)
and `ld` (linker). `hexa doctor` checks for these and reports problems.

## Honest notes

- Native code can be **disassembled** and analyzed; HEXA's security does not
  rely on hiding code (see [Security model](17-security-model.md)).
- Compilation targets `x86_64` in this milestone. Other architectures are
  **(planned / later phase)**.
- The exact register-allocation and codegen quality are early; optimization
  via an IR is **(planned / later phase)** (see [IR](21-ir.md)).

Next: [Debugging](23-debugging.md).
