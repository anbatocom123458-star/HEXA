# Functions

Functions are the main unit of reusable logic in HEXA.

## Declaring a function

```he
fn add(a: integer, b: integer) -> integer {
    return a + b;
}
```

- `fn` keyword, then the name.
- Parameters are `name: type`, comma-separated.
- `-> type` declares the return type. Omitted means the function returns
  nothing (unit).
- The body is a `{ ... }` block.

## Calling a function

```he
fn main() {
    let sum: integer = add(2, 3);
    print(to_text(sum)); // 5
}
```

Calling a function with the wrong number of arguments is a compile error
(`E2007`):

```
error[E2007]: function `add` expects 2 argument(s) but found 3
```

## Return values

`return expr;` returns a value. A function declared with `-> integer` must
return an integer; returning nothing, or the wrong type, is an error (`E2006`).

```he
fn classify(x: integer) -> text {
    if x > 0 {
        return "positive";
    }
    return "non-positive";
}
```

## The standard-library functions

Beyond user functions, HEXA ships a prelude of standard functions. Examples:

```he
print("hello");                       // std io
let name: text = input.text("Name: ");
let h: hash = crypto.hash.sha256(b"data");
let ct: ciphertext = crypto.encrypt.aes256_gcm(plaintext, k);
```

The complete signature list is in the [standard-library reference](../std/).

## Parameters and security types

Parameters may be security-sensitive:

```he
fn hash_secret(pw: password) -> hash {
    return crypto.hash.sha256(pw as bytes); // cast password? — see cast rules
}
```

Because passwords cannot be cast to ordinary `bytes`, deriving bytes from a
password normally requires the explicit KDF/export paths. The compiler enforces
these rules, so the exact body above would need adjustment to compile — a good
reminder that handling secrets requires deliberate choices.

## Overloading

The prelude provides a small amount of overloading by argument count and/or
types where signatures differ (for example `crypto.key.generate` accepts either
a bit length or raw entropy bytes). User functions currently do not support
overloading in this milestone.

## Privacy

`pub` and `private` markers on functions are recognized by the lexer/parser;
full module-level access control is **(planned / later phase)**. Within a single
file, all functions are visible.

## Pure helpers and `const`

Helper functions are a natural fit for recomputation. Combine them with
`const` values:

```he
const BASE_RATE: decimal = 0.05;

fn monthly_payment(principal: decimal) -> decimal {
    return principal * BASE_RATE;
}
```

Next: [Modules](08-modules.md).
