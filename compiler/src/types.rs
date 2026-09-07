//! HEXA type system.
//!
//! In addition to ordinary types this module models the security-sensitive
//! types mandated by the spec (secret, key, private_key, plaintext,
//! ciphertext, hash, signature, nonce, salt, apikey, password, credential)
//! and the conversion rules that prevent silent downgrades of secret data.

use crate::ast::TypeExpr;
use crate::diagnostics::{Diagnostic, Diagnostics, Span};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretKind {
    Secret, Key, PublicKey, PrivateKey, Hash, Signature,
    Nonce, Salt, ApiKey, Password, Credential,
}

impl fmt::Display for SecretKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SecretKind::*;
        write!(f, "{}", match self {
            Secret => "secret", Key => "key", PublicKey => "public_key",
            PrivateKey => "private_key", Hash => "hash", Signature => "signature",
            Nonce => "nonce", Salt => "salt", ApiKey => "apikey",
            Password => "password", Credential => "credential",
        })
    }
}

/// A resolved HEXA type. Security-sensitive scalar variants are `Secret(k)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Type {
    Any,          // not yet inferred / polymorphic
    Number,
    Integer,
    Decimal,
    Boolean,
    Text,
    Bytes,
    Char,
    Plaintext,
    Ciphertext,
    Secret(SecretKind),
    Array(Box<Type>),
    Map(Box<Type>, Box<Type>),
    Set(Box<Type>),
    Option(Box<Type>),
    Result(Box<Type>, Box<Type>),
    Tuple(Vec<Type>),
    Named(String),
    Closure(Vec<Type>, Box<Type>),
    Unit,
}

impl Type {
    pub fn from_expr(t: &TypeExpr, diags: &mut Diagnostics, known_user: &[String]) -> Type {
        match t {
            TypeExpr::Named(name, span) => {
                match name.as_str() {
                    "number" | "Number" => Type::Number,
                    "integer" | "int" | "Integer" => Type::Integer,
                    "decimal" | "Decimal" => Type::Decimal,
                    "boolean" | "bool" | "Boolean" => Type::Boolean,
                    "text" | "Text" | "string" => Type::Text,
                    "bytes" | "Bytes" => Type::Bytes,
                    "char" | "Char" => Type::Char,
                    "plaintext" => Type::Plaintext,
                    "ciphertext" => Type::Ciphertext,
                    "secret" => Type::Secret(SecretKind::Secret),
                    "key" => Type::Secret(SecretKind::Key),
                    "public_key" => Type::Secret(SecretKind::PublicKey),
                    "private_key" => Type::Secret(SecretKind::PrivateKey),
                    "hash" => Type::Secret(SecretKind::Hash),
                    "signature" => Type::Secret(SecretKind::Signature),
                    "nonce" => Type::Secret(SecretKind::Nonce),
                    "salt" => Type::Secret(SecretKind::Salt),
                    "apikey" => Type::Secret(SecretKind::ApiKey),
                    "password" => Type::Secret(SecretKind::Password),
                    "credential" => Type::Secret(SecretKind::Credential),
                    _ => {
                        if known_user.iter().any(|u| u == name) {
                            Type::Named(name.clone())
                        } else {
                            diags.push(Diagnostic::error("E2000", format!("unknown type `{}`", name)).at(*span));
                            Type::Any
                        }
                    }
                }
            }
            TypeExpr::Array(i, _) => Type::Array(Box::new(Self::from_expr(i, diags, known_user))),
            TypeExpr::Set(i, _) => Type::Set(Box::new(Self::from_expr(i, diags, known_user))),
            TypeExpr::Map(k, v, _) => Type::Map(
                Box::new(Self::from_expr(k, diags, known_user)),
                Box::new(Self::from_expr(v, diags, known_user)),
            ),
            TypeExpr::Option(i, _) => Type::Option(Box::new(Self::from_expr(i, diags, known_user))),
            TypeExpr::Result(o, e, _) => Type::Result(
                Box::new(Self::from_expr(o, diags, known_user)),
                Box::new(Self::from_expr(e, diags, known_user)),
            ),
            TypeExpr::Tuple(ts, _) => Type::Tuple(ts.iter().map(|x| Self::from_expr(x, diags, known_user)).collect()),
        }
    }

    pub fn name(&self) -> String {
        match self {
            Type::Any => "?".into(),
            Type::Number => "number".into(),
            Type::Integer => "integer".into(),
            Type::Decimal => "decimal".into(),
            Type::Boolean => "boolean".into(),
            Type::Text => "text".into(),
            Type::Bytes => "bytes".into(),
            Type::Char => "char".into(),
            Type::Plaintext => "plaintext".into(),
            Type::Ciphertext => "ciphertext".into(),
            Type::Secret(k) => k.to_string(),
            Type::Array(i) => format!("array<{}>", i.name()),
            Type::Map(k, v) => format!("map<{}, {}>", k.name(), v.name()),
            Type::Set(i) => format!("set<{}>", i.name()),
            Type::Option(i) => format!("option<{}>", i.name()),
            Type::Result(o, e) => format!("result<{}, {}>", o.name(), e.name()),
            Type::Tuple(ts) => format!("({})", ts.iter().map(|x| x.name()).collect::<Vec<_>>().join(", ")),
            Type::Named(n) => n.clone(),
            Type::Closure(ps, r) => format!("({}) -> {}", ps.iter().map(|x| x.name()).collect::<Vec<_>>().join(", "), r.name()),
            Type::Unit => "unit".into(),
        }
    }

    /// True if this type is an ordinary (non-sensitive) scalar data type.
    pub fn is_sensitive(&self) -> bool {
        match self {
            Type::Secret(_) => true,
            _ => false,
        }
    }

    /// True if values of this type must never be printed/logged/exported unless
    /// an explicit controlled export is performed (spec section 5).
    pub fn is_secret_never_print(&self) -> bool {
        match self {
            Type::Secret(SecretKind::Secret)
            | Type::Secret(SecretKind::Key)
            | Type::Secret(SecretKind::PrivateKey)
            | Type::Secret(SecretKind::ApiKey)
            | Type::Secret(SecretKind::Password)
            | Type::Secret(SecretKind::Credential) => true,
            _ => false,
        }
    }

    /// Whether implicit (no annotation) conversion is permitted.
    pub fn converts_implicit(&self, to: &Type) -> bool {
        if self == to {
            return true;
        }
        match (self, to) {
            (Type::Integer, Type::Number) | (Type::Integer, Type::Decimal)
            | (Type::Decimal, Type::Number) => true,
            (Type::Text, Type::Plaintext) | (Type::Bytes, Type::Plaintext) => true,
            _ => false,
        }
    }

    /// Whether an explicit `as` cast is permitted (still forbids downgrading a
    /// secret into ordinary text/bytes, which requires `secret.export`).
    pub fn converts_explicit_cast(&self, to: &Type) -> bool {
        if self == to {
            return true;
        }
        if self.is_secret_never_print() {
            // Sensitive values cannot be cast into plain data, ever.
            return false;
        }
        match (self, to) {
            (Type::Integer, Type::Number) | (Type::Integer, Type::Decimal)
            | (Type::Decimal, Type::Number) | (Type::Number, Type::Integer)
            | (Type::Number, Type::Decimal) | (Type::Decimal, Type::Integer) => true,
            (Type::Text, Type::Bytes) | (Type::Bytes, Type::Text) => true,
            (Type::Text, Type::Plaintext) | (Type::Bytes, Type::Plaintext) => true,
            (Type::Plaintext, Type::Text) | (Type::Plaintext, Type::Bytes) => true,
            (Type::Ciphertext, Type::Text) | (Type::Text, Type::Ciphertext) => true,
            (Type::Secret(SecretKind::Hash), Type::Text)
            | (Type::Secret(SecretKind::Signature), Type::Text)
            | (Type::Secret(SecretKind::Nonce), Type::Text)
            | (Type::Secret(SecretKind::Salt), Type::Text)
            | (Type::Secret(SecretKind::PublicKey), Type::Text) => true,
            _ => false,
        }
    }

    /// Is this type expressible/printable in ordinary output?
    pub fn printable(&self) -> bool {
        !self.is_secret_never_print()
    }
}

/// Literal sink types: used by the security analyzer to reason about
/// hardcoded values of secret-typed slot.
pub fn is_secret_decl_type(t: &Type) -> bool {
    t.is_secret_never_print()
}

pub fn _noop(_span: Span) {}
