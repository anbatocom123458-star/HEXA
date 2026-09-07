# Syntax

This document describes the HEXA language syntax for the current milestone.
It is intentionally concrete and complete for what the compiler accepts today;
features marked **(planned / later phase)** are documented for forward
reference only.

## Program structure

A `.he` file is a sequence of declarations. The top level may contain
`fn`, `struct`, `enum`, `import`, and `module` items. An executable program
must define `fn main()`.

```he
// item comment
fn greet(times: integer) {
    let i: integer = 0;
    while i < times {
        print("hi");
        i = i + 1;
    }
}

fn main() {
    greet(3);
}
```

## Comments

Two forms; block comments nest.

```he
// line comment

/* block comment
   /* nested block comment */
*/
```

## Identifiers and keywords

Identifiers start with a letter or `_` and continue with letters, digits, or
`_`. Reserved keywords include:

```
fn let mut const if else for while match return
struct enum trait impl import module pub private
async await as in true false
```

## Functions

```he
fn name(param: type, other: type) -> return_type {
    // body
}

fn no_params() {
    // body
}
```

Parameters are declared `name: type`. Return type is written with `->`. If
omitted, the function returns nothing (unit). See
[Functions](07-functions.md).

## Variables

```he
let x: integer = 10;      // immutable binding
mut y: integer = 20;      // mutable binding
const MAX: integer = 100; // compile-time constant
```

See [Variables](05-variables.md).

## Control flow

### `if` / `else`

```he
if x > 0 {
    print("positive");
} else if x == 0 {
    print("zero");
} else {
    print("negative");
}
```

### `while`

```he
while x < 10 {
    x = x + 1;
}
```

### `for`

`for` iterates over an array:

```he
let items: array<text> = ["a", "b", "c"];
for item in items {
    print(item);
}
```

### `match`

```he
match code {
    "ok" => { print("fine"); }
    "err" => { print("problem"); }
    _ => { print("unknown"); }
}
```

### `return`

```he
fn double(x: integer) -> integer {
    return x * 2;
}
```

## Types

Type annotations use `name: type`, with the grouped form `array<...>`,
`map<k, v>`, `option<...>`, `result<ok, err>`. See [Types](06-types.md).

| Category | Types |
|----------|-------|
| Ordinary | `text`, `integer`, `decimal`, `number`, `boolean`, `bytes`, `char` |
| Containers | `array<T>`, `map<K,V>`, `set<T>`, `option<T>`, `result<O,E>`, `tuple` |
| Security-sensitive | `secret`, `key`, `public_key`, `private_key`, `plaintext`, `ciphertext`, `hash`, `signature`, `nonce`, `salt`, `apikey`, `password`, `credential` |

## Expressions

- Arithmetic: `+ - * / %` (with `+` also concatenating `text`).
- Comparison: `== != < <= > >=`.
- Logic: `&& || !`.
- Unary: `-` negation, `!` not.
- Casts: `value as type` (subject to security rules, see
  [Secret safety](06-types.md)).
- Calls: `crypto.encrypt.aes256_gcm(data, key)`.
- Compound types: `["a","b"]`, `(1, 2)`.

## Semicolons and indentation

Statements end with `;`. Blocks are delimited by `{ }`; HEXA uses 4-space
indentation by convention (enforced by the formatter's style lints
`STYLE001`/`STYLE002`).

## Error reporting

Malformed source, misplaced tokens, and type mistakes produce structured
diagnostics with a stable error code, a source location (`file:line:col`), a
snippet with a caret, and an optional hint. The full catalog is in
[ERROR-CODES.md](ERROR-CODES.md).

Next: [Variables](05-variables.md).
