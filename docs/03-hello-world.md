# Hello, world

The smallest HEXA program prints a greeting. Create a file named `hello.he`:

```he
// hello.he — first HEXA program
fn main() {
    print("Hello, world!");
}
```

## Anatomy

- `fn main() { ... }` declares the program's entry point. Every executable
  program has a `main` function.
- `print(...)` writes a value to standard output. Here it prints a `text`
  literal `"Hello, world!"`.
- `//` starts a line comment; `/* ... */` is a block comment and may be nested.

## Running it

Three commands matter most in the early days:

```bash
# Type-check + security analysis only (no output file)
./target/release/hexa check hello.he

# Compile to a native executable
./target/release/hexa build hello.he

# Build (if needed) and run
./target/release/hexa run hello.he
```

`hexa run hello.he` prints:

```
Hello, world!
```

## A slightly more interesting program

```he
// greet.he — read input and print a greeting
fn main() {
    let name: text = input.text("What is your name? ");
    print("Hello, " + name + "!");
}
```

## Reading from the command line

```
$ ./target/release/hexa run greet.he
What is your name? Ada
Hello, Ada!
```

## Numbers and arithmetic

```he
// math.he — integer arithmetic
fn main() {
    let a: integer = 20;
    let b: integer = 22;
    print("sum: " + to_text(a + b));
}
```

`to_text(...)` converts a value to `text` for display (and is a safe operation —
it cannot be applied to a secret, which must go through `secret.export`).

## Next steps

- [Syntax](04-syntax.md) — the language grammar and rules.
- [Variables](05-variables.md) — `let`, `mut`, `const`.
- [Types](06-types.md) — including the security-sensitive types.
