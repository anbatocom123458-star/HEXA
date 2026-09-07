# Types

HEXA is statically typed. Every value has a type known at compile time, and the
type checker (`hexa check`) verifies that types line up everywhere. This
document covers the type system, with special attention to the
**security-sensitive types** that make HEXA different.

## Ordinary scalar types

| Type      | Meaning                                | Example                |
|-----------|----------------------------------------|------------------------|
| `text`    | Unicode string                         | `"hello"`              |
| `integer` | Signed integer                         | `-42`, `1024`          |
| `decimal` | Floating-point / fixed decimal         | `3.14`                 |
| `number`  | General numeric (integer or decimal)   | `7`                    |
| `boolean` | `true` or `false`                      | `true`                 |
| `bytes`   | Raw byte sequence                      | `b"\x00\x01"`          |
| `char`    | Single character                       | `'x'`                  |

`integer` converts implicitly to `number` and `decimal`; `decimal` converts to
`number`; `text` and `bytes` convert to `plaintext` when required.

## Container types

```he
let list: array<integer> = [1, 2, 3];
let table: map<text, integer> = { "a" => 1, "b" => 2 };
let maybe: option<text> = null;
let outcome: result<text, text> = err("failed");
let pair: (integer, text) = (1, "one");
```

- `array<T>` — ordered list of `T`. Indexed with `[]`.
- `map<K,V>` — key/value pairs. Indexed with `[]`.
- `set<T>` — unique values. **(planned / later phase for full methods)**
- `option<T>` — a value that may be absent.
- `result<O,E>` — either a success of type `O` or an error of type `E`.
- Tuple types `(A, B, ...)` — fixed grouping.

Indexing rules: `array` → element type; `map` → value type; `text` → `char`;
`bytes` → `integer`. Indexing anything else is an error (`E2005`).

## Function (closure) types

A function value has a closure type:

```
(integer, integer) -> integer
```

The type checker records a function's parameter types and return type.

## Security-sensitive types

This is the heart of HEXA. These types mark data that must be handled
carefully:

```
secret, key, public_key, private_key, plaintext, ciphertext,
hash, signature, nonce, salt, apikey, password, credential
```

The **never-print** subset cannot be printed, logged, or cast into ordinary
data:

```
secret, key, private_key, apikey, password, credential
```

### Rules for security types

1. **No implicit downgrade.** A security type is never silently converted to
   `text`/`bytes`. Using a `password` where a `text` is required is a compile
   error (`E2101`).
2. **No printing.** `print(a_secret)` is a compile error (`E2100`).
3. **No casting down.** `a_key as bytes` is a compile error (`E2102`). Sensitive
   values cannot be cast into ordinary data.
4. **Controlled export.** The single sanctioned escape hatch is
   `secret.export(value) -> text`. This is an explicit, visible act:
   ```he
   let pw: password = secret.input("Password: ");
   // print(pw);            // ERROR E2100
   // let s: text = pw;     // ERROR E2101
   let shown: text = secret.export(pw); // deliberate, allowed
   ```
5. **Wiping.** `secret.wipe(value)` zeroes the value when you are done with it.

### What is and is not secret

- `ciphertext`, `hash`, `signature`, `nonce`, `salt`, `public_key`, and
  `plaintext` are sensitive in the sense that they are constructs of the
  security world, and HEXA keeps them labelled distinctly. Some of these are
  safe to display (a `hash` or `public_key` is meant to be shared) via an
  explicit cast/export path, while the **never-print** set is strictly
  protected.

The full table of what may be cast/exported is implemented in the compiler's
conversion rules; see [EDGE cases and casts](#casts-and-conversions).

## Casts and conversions

A cast uses `as`:

```he
let n: number = 42;
let i: integer = n as integer;
let raw: bytes = b"\x01\x02";
let s: text = raw as text;      // ordinary bytes -> text is allowed
```

HEXA permits ordinary numeric and text/bytes casts, and explicitly-defined
security casts (e.g. `hash`/`public_key`/`signature`→`text` for sharing).
It **forbids** casting a never-print secret into ordinary data — that requires
`secret.export`.

## Type-checking errors

The type checker reports precise codes:

- `E2000` unknown type
- `E2001` cannot find value
- `E2002` binding needs type or initializer
- `E2003` type mismatch / bad operator / bad cast
- `E2004` unknown function / invalid callee
- `E2005` bad indexing / `for` over non-array
- `E2006` return-type mismatch
- `E2007` wrong argument count

See [ERROR-CODES.md](ERROR-CODES.md) for details.

Next: [Functions](07-functions.md).
