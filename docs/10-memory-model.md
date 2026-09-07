# Memory model

HEXA compiles to native `x86_64` code with a **libc-free runtime** built on raw
syscalls. This section explains how memory and values work, and — critically —
what HEXA does about **secret material in memory**.

## Values

- Scalars (`integer`, `decimal`, `boolean`, `char`) live in registers or on the
  stack, as in any native language.
- `text`, `bytes`, and container types are heap-allocated sequences managed by
  the runtime. Indexing `text` yields `char`; indexing `bytes` yields
  `integer`; indexing arrays/maps yields their element/value type.
- `array<T>`, `map<K,V>`, `option<T>`, `result<O,E>`, and tuples are value
  types that refer to managed buffers.

## The heap and the runtime

The runtime performs allocation and deallocation directly through the operating
system (raw `mmap`/`munmap` and related syscalls) rather than through libc. This
keeps the dependency surface small and gives the runtime direct control over
where sensitive bytes live.

## Wiping secrets — `secret.wipe`

Secrets must not linger in memory any longer than necessary. HEXA provides
`secret.wipe(value)` to zero out the backing buffer:

```he
fn verify(pw: password) -> boolean {
    let ok: boolean = do_check(pw);
    secret.wipe(pw);   // zero the password buffer before returning
    return ok;
}
```

Garbage collection of ordinary values is a **(planned / later phase)**; keeping
the runtime simple and deterministic is a goal of this milestone. Wiping is the
explicit tool for secrets in the meantime.

## What the memory model cannot guarantee

Be aware of honest limits:

- **Copies.** If a secret value has been implicitly copied (e.g. duplicated
  into a buffer the program references), wiping one handle does not guarantee
  every copy is gone.
- **The compiler is not a sandbox.** HEXA guarantees what it *can* express at
  the type level: it will not let you print or downgrade a secret. It does not
  stop another privileged process on the same machine from reading process
  memory.
- **Swap and core dumps.** Page-out to swap, and core dumps if a process
  crashes (because `panic = "abort"` and other mitigations, plus the OS
  configuration), can leave secret bytes on disk. See
  [Threat model](27-threat-model.md).
- **Terminal and tools.** Values displayed via `secret.export` are ordinary
  text from that point on — terminal scrollback and screenshots can capture
  them.

## Stack vs. heap

Secrets that fit in registers/stack may avoid the heap entirely, but the native
backend may spill them to the stack. HEXA's design goal is to minimize copies
and to make the explicit wipe the path of least resistance; precise register
allocation and secret-aware codegen are **(planned / later phase)** refinements.

## Determinism and control

Because HEXA avoids a large runtime, runtime behavior is more predictable and
auditable than in a garbage-collected language. This predictability is part of
the security posture — fewer layers between your program and the machine means
fewer places a secret can be copied against your wishes.

Next: [Cryptography](11-crypto.md).
