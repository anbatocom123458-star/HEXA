# Disassembly

`hexa disassemble` shows the machine instructions of a compiled HEXA program.
This is primarily a tool for debugging the compiler's code generation and for
understanding what a binary actually does.

## Usage

```bash
hexa disassemble ./hello        # disassemble a compiled HEXA executable
hexa disassemble program.s      # disassemble an assembly listing
```

The command prints the disassembly of the given binary or assembly source to
standard output, with symbols/labels where they can be recovered.

## What you see

For source like this:

```he
fn main() {
    print("hi");
}
```

the disassembly shows the emitted `x86_64` instructions behind that program —
the syscall setup for output, the string constant, the function prologue/
epilogue, and control flow. Because HEXA compiles to raw syscalls with a
libc-free runtime, the disassembly is compact and traceable to the runtime
contract rather than buried in libc internals.

## Why disassemble?

- **Verify codegen.** Check whether a construct produced the instructions you
  expected.
- **Debug runtime behavior.** Trace what syscalls a program makes.
- **Security realism.** HEXA's security model is honest about the fact that
  native binaries are readable; disassembly is the tool that demonstrates this.
  Seeing your code in disassembly is a good reminder that *hiding code* is not
  part of the threat model.

## Relationship to decompilation

Disassembly is a faithful, mechanical rendering of instructions.
[Decompilation](25-decompilation.md) goes further, reconstructing
higher-level structure — and is consequently best-effort. Both tools operate on
the same input and complement each other.

## Limits

- Disassembly reflects the emitted machine code, which may not map one-to-one
  onto source lines in early codegen (improved with debug info in the planned
  IR phase).
- Symbol recovery depends on what the linker preserved.

Next: [Decompilation](25-decompilation.md).
