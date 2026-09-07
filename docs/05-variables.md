# Variables and binding

HEXA distinguishes three kinds of bindings: immutable `let`, mutable `mut`, and
compile-time `const`. "Binding" is the right word — a name is bound to a value
and, unless declared `mut`, cannot be reassigned.

## `let` — immutable

```he
let name: text = "Ada";
let count: integer = 42;
let ratio: decimal = 3.14;
let ok: boolean = true;
let blob: bytes = b"\x00\x01\x02";
```

A `let` binding cannot be reassigned:

```he
let x: integer = 1;
// x = 2;  // ERROR: cannot assign to immutable binding
```

The type annotation may be omitted when the initializer makes it obvious:

```he
let x = 10;        // inferred as integer
let greeting = "hi"; // inferred as text
```

A `let` with neither a type nor an initializer is an error (`E2002`).

## `mut` — mutable

Use `mut` when the value will change:

```he
mut total: integer = 0;
total = total + 1;
```

## `const` — compile-time constant

```he
const MAX_RETRIES: integer = 5;
const APP_NAME: text = "HEXA";
```

Constants are fixed at compile time and are hoisted, so they can be referenced
before their textual definition in many cases.

## Naming

Identifiers are `snake_case` by convention for variables and functions, and
`SCREAMING_SNAKE_CASE` for constants. These follow from the style lints
`STYLE001`/`STYLE002` applied by `hexa format` and `hexa check`.

## Scope

Bindings live inside the block where they are declared (a `{ ... }` block or a
function body). Inner scopes may shadow outer names:

```he
let x: integer = 1;
{
    let x: integer = 2;  // shadows the outer x inside this block
    print(to_text(x));   // 2
}
print(to_text(x));       // 1
```

## The `print` rule for secrets

A binding with a **security-sensitive type** — `password`, `key`,
`private_key`, and friends — cannot be passed to `print` (or otherwise exposed)
directly. `print(password_var)` is a compile error (`E2100`). If you genuinely
need to show something derived from a secret, use `secret.export(...)` (see
[Types](06-types.md) and [Passwords](13-passwords.md)). Remember that
`secret.export` turns the secret into ordinary `text`, so use it only when you
are certain the value is safe to reveal.

## Acknowledgments

- Trying to use an undeclared name is a compile error (`E2001`).
- Using a name in the wrong place (e.g. a function name as a value) is a
  compile error (`E2004`).

Next: [Types](06-types.md).
