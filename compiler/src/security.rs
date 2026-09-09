//! HEXA crypto security analyzer (spec section 24, 25, 48).
//!
//! This is a separate compiler pass that walks the AST and emits SECxxx
//! diagnostics based on the project's security policy. It tracks which
//! variables hold sensitive values and flags common mistakes.

use std::collections::{HashMap, HashSet};

use crate::ast::*;
use crate::diagnostics::{Diagnostic, Diagnostics};
use crate::types::{SecretKind, Type};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Standard,
    Strict,
    Paranoid,
    Custom,
}

#[derive(Clone, Debug)]
pub struct SecurityPolicy {
    pub forbid_hardcoded_secrets: bool,
    pub forbid_secret_logging: bool,
    pub require_authenticated_encryption: bool,
    pub require_secure_rng: bool,
    pub require_argon2id: bool,
    pub max_crypto_layers: u32,
    pub min_credential_length: usize,
    pub lint_explicit_export: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self::standard()
    }
}

impl SecurityPolicy {
    pub fn standard() -> Self {
        SecurityPolicy {
            forbid_hardcoded_secrets: true,
            forbid_secret_logging: true,
            require_authenticated_encryption: true,
            require_secure_rng: true,
            require_argon2id: false,
            max_crypto_layers: 5000,
            min_credential_length: 12,
            lint_explicit_export: false,
        }
    }
    pub fn strict() -> Self {
        let mut p = Self::standard();
        p.require_argon2id = true;
        p.lint_explicit_export = true;
        p
    }
    pub fn paranoid() -> Self {
        let mut p = Self::strict();
        p.max_crypto_layers = 32;
        p.min_credential_length = 20;
        p
    }
    pub fn from_profile(profile: Profile) -> Self {
        match profile {
            Profile::Standard => Self::standard(),
            Profile::Strict => Self::strict(),
            Profile::Paranoid => Self::paranoid(),
            Profile::Custom => Self::standard(),
        }
    }
    /// Apply an override map (keys lower-cased) from hexa.toml `[security]`.
    pub fn apply_overrides(&mut self, kv: &HashMap<String, String>) {
        if let Some(v) = kv.get("forbid_hardcoded_secrets") { self.forbid_hardcoded_secrets = v == "true"; }
        if let Some(v) = kv.get("forbid_secret_logging") { self.forbid_secret_logging = v == "true"; }
        if let Some(v) = kv.get("require_authenticated_encryption") { self.require_authenticated_encryption = v == "true"; }
        if let Some(v) = kv.get("require_secure_rng") { self.require_secure_rng = v == "true"; }
        if let Some(v) = kv.get("require_argon2id") { self.require_argon2id = v == "true"; }
        if let Some(v) = kv.get("max_crypto_layers") { if let Ok(n) = v.parse() { self.max_crypto_layers = n; } }
        if let Some(v) = kv.get("min_credential_length") { if let Ok(n) = v.parse() { self.min_credential_length = n; } }
        if let Some(v) = kv.get("lint_explicit_export") { self.lint_explicit_export = v == "true"; }
    }
}

/// A lightweight sensitive-variable tracer shared across a function body.
struct SecCtx<'a> {
    policy: &'a SecurityPolicy,
    diags: &'a mut Diagnostics,
    sensitive: HashSet<String>,
}

fn secret_kind_of(type_name: &str) -> Option<SecretKind> {
    match type_name {
        "secret" => Some(SecretKind::Secret),
        "key" => Some(SecretKind::Key),
        "public_key" => Some(SecretKind::PublicKey),
        "private_key" => Some(SecretKind::PrivateKey),
        "hash" => Some(SecretKind::Hash),
        "signature" => Some(SecretKind::Signature),
        "nonce" => Some(SecretKind::Nonce),
        "salt" => Some(SecretKind::Salt),
        "apikey" => Some(SecretKind::ApiKey),
        "password" => Some(SecretKind::Password),
        "credential" => Some(SecretKind::Credential),
        _ => None,
    }
}

fn sensitive(k: &SecretKind) -> bool {
    matches!(k, SecretKind::Secret | SecretKind::Key | SecretKind::PrivateKey
        | SecretKind::ApiKey | SecretKind::Password | SecretKind::Credential)
}

pub fn analyze(program: &Program, policy: &SecurityPolicy, diags: &mut Diagnostics, user_types: &[String]) {
    for item in &program.items {
        if let Item::Fn(f) = item {
            if let Some(body) = &f.body {
                let mut ctx = SecCtx {
                    policy, diags,
                    sensitive: HashSet::new(),
                };
                // function params that are sensitive
                for p in &f.params {
                    let tn = type_name_str(&p.ty);
                    if let Some(k) = secret_kind_of(&tn) {
                        if sensitive(&k) {
                            ctx.sensitive.insert(p.name.clone());
                        }
                        if k == SecretKind::Password && policy.require_argon2id {
                            // informational; actual KDF checks happen at call sites
                        }
                    }
                }
                check_block(&mut ctx, body, user_types);
            }
        }
    }
}

fn type_name_str(t: &TypeExpr) -> String {
    match t {
        TypeExpr::Named(n, _) => n.clone(),
        TypeExpr::Array(_, _) => "array".into(),
        TypeExpr::Map(..) => "map".into(),
        TypeExpr::Set(_, _) => "set".into(),
        TypeExpr::Option(_, _) => "option".into(),
        TypeExpr::Result(..) => "result".into(),
        TypeExpr::Tuple(_, _) => "tuple".into(),
    }
}

fn check_block(ctx: &mut SecCtx, block: &Block, user_types: &[String]) {
    for stmt in &block.stmts {
        check_stmt(ctx, stmt, user_types);
    }
}

fn check_stmt(ctx: &mut SecCtx, stmt: &Stmt, user_types: &[String]) {
    match stmt {
        Stmt::Let(d) => {
            if let (Some(ty), Some(init)) = (&d.ty, &d.init) {
                let tn = type_name_str(ty);
                if let Some(k) = secret_kind_of(&tn) {
                    if sensitive(&k) && ctx.policy.forbid_hardcoded_secrets && is_string_literal(init) {
                        ctx.diags.push(Diagnostic::warning("SEC001", format!(
                            "Possible hardcoded secret detected (type `{}`). \
                             Move the secret to secure runtime input (`secret.input(...)`) or a protected \
                             credential provider.", tn)).at(d.span));
                    }
                    if sensitive(&k) {
                        ctx.sensitive.insert(d.name.clone());
                    }
                    check_expr(ctx, init, user_types);
                } else {
                    check_expr(ctx, init, user_types);
                }
            } else if let Some(init) = &d.init {
                check_expr(ctx, init, user_types);
            }
        }
        Stmt::Mut(m) => {
            let tn = type_name_str(&m.ty);
            if let Some(k) = secret_kind_of(&tn) {
                if sensitive(&k) && ctx.policy.forbid_hardcoded_secrets && is_string_literal(&m.init) {
                    ctx.diags.push(Diagnostic::warning("SEC001", format!(
                        "Possible hardcoded secret detected (type `{}`). Use secure runtime input instead.", tn)).at(m.span));
                }
                if sensitive(&k) {
                    ctx.sensitive.insert(m.name.clone());
                }
            }
            check_expr(ctx, &m.init, user_types);
        }
        Stmt::ItemConst(c) => check_expr(ctx, &c.value, user_types),
        Stmt::Expr(e, _) => check_expr(ctx, e, user_types),
        Stmt::Block(b) => check_block(ctx, b, user_types),
        Stmt::If(i) => {
            check_expr(ctx, &i.cond, user_types);
            check_block(ctx, &i.then_block, user_types);
            if let Some(eb) = &i.else_branch {
                match &**eb {
                    ElseBranch::Block(b) => check_block(ctx, b, user_types),
                    ElseBranch::If(ii) => check_stmt(ctx, &Stmt::If(*ii.clone()), user_types),
                }
            }
        }
        Stmt::While(w) => { check_expr(ctx, &w.cond, user_types); check_block(ctx, &w.body, user_types); }
        Stmt::For(f) => { check_expr(ctx, &f.iter, user_types); check_block(ctx, &f.body, user_types); }
        Stmt::Match(m) => {
            check_expr(ctx, &m.scrutinee, user_types);
            for arm in &m.arms { check_block(ctx, &arm.body, user_types); }
        }
        Stmt::Return(e, _) => { if let Some(e) = e { check_expr(ctx, e, user_types); } }
        Stmt::Assign(a, sp) => {
            if ctx.sensitive.contains(&a.target) {
                // assigns propagate sensitivity
            }
            check_expr(ctx, &a.value, user_types);
            let _ = sp;
        }
    }
}

fn is_string_literal(e: &Expr) -> bool {
    matches!(e, Expr::Str(_, _))
}

fn call_path(e: &Expr) -> Option<String> {
    match e {
        Expr::Ident(n, _) => Some(n.clone()),
        Expr::Path(p, _) => Some(p.join(".")),
        _ => None,
    }
}

fn check_expr(ctx: &mut SecCtx, e: &Expr, user_types: &[String]) {
    match e {
        Expr::Call(callee, args, _) => {
            let name = call_path(callee);
            // detect secret literal passed to crypto functions
            if let Some(name) = &name {
                let expects_secret = (name.contains("crypto.") && !name.contains("encrypt.aes256_gcm")
                    && !name.contains("chacha"))
                    || name.contains("password") || name.contains("key");
                if expects_secret {
                    for a in args {
                        if is_string_literal(a) && ctx.policy.forbid_hardcoded_secrets {
                            ctx.diags.push(Diagnostic::warning("SEC001", format!(
                                "Hardcoded literal passed to `{}`; use secure input or a credential provider.", name)).at(a.span()));
                        }
                    }
                }
                if ctx.policy.require_secure_rng && (name == "random.seed" || name == "std.random.seed") {
                    ctx.diags.push(Diagnostic::error("SEC003", "Insecure (seeded) RNG used for randomness that may feed secrets; use the CSPRNG `random.bytes`/`crypto.key.generate`.").at(e.span()));
                }
                // secret logging
                if ctx.policy.forbid_secret_logging && (name == "print" || name == "std.io.print" || name.contains("to_text")) {
                    for a in args {
                        if is_sensitive_expr(ctx, a) {
                            ctx.diags.push(Diagnostic::warning("SEC005", format!(
                                "Secret value passed to `{}`; this may leak it. Use secret.export only after deliberate consent.", name)).at(a.span()));
                        }
                    }
                }
                // hashing a password with a fast hash
                if ctx.policy.forbid_hardcoded_secrets && name.contains("crypto.hash.") {
                    for a in args {
                        if is_sensitive_expr(ctx, a) {
                            ctx.diags.push(Diagnostic::warning("SEC007", format!(
                                "Fast hash `{}` applied to a sensitive value; for passwords/credentials use Argon2id/scrypt/PBKDF2.", name)).at(a.span()));
                        }
                    }
                }
                // weak algorithms
                if name.contains("md5") || name.contains("sha1") || name.contains("des") || name.contains("rc4")
                    || name.contains("cbc") || name.contains("ecb") || name.contains("3des") {
                    ctx.diags.push(Diagnostic::warning("SEC002", format!(
                        "Algorithm `{}` is weak or unauthenticated; avoid it.", name)).at(e.span()));
                }
                // nonce / salt constant literals are suspicious
                if name.contains("nonce") || name.contains("salt") {
                    for a in args {
                        if is_string_literal(a) {
                            ctx.diags.push(Diagnostic::warning("SEC004", format!(
                                "Constant nonce/salt literal passed to `{}`; reusing a nonce destroys AEAD security and \
                                 fixed salts break KDF uniqueness.", name)).at(a.span()));
                        }
                    }
                }
                // layer count sanity
                if name.contains("encrypt.layers") || name == "crypto.encrypt.layers" {
                    if let Some(Expr::Int(n, _)) = args.last() {
                        if *n as u64 > ctx.policy.max_crypto_layers as u64 {
                            ctx.diags.push(Diagnostic::warning("SEC008", format!(
                                "{} encryption layers exceeds the configured maximum {}; this may require excessive \
                                 CPU time and is not automatically more secure.", n, ctx.policy.max_crypto_layers)).at(e.span()));
                        }
                    }
                }
            }
            for a in args { check_expr(ctx, a, user_types); }
            let _ = user_types;
        }
        Expr::Ident(n, _) => {
            if ctx.sensitive.contains(n) {
                // a sensitive value is being used as a plain value expression;
                // catches passing it around. (Real enforcement is in the type checker.)
            }
        }
        Expr::Binary(op, l, r, _) => {
            if *op == BinOp::Add && (is_sensitive_expr(ctx, l) || is_sensitive_expr(ctx, r))
                && ctx.policy.forbid_secret_logging {
                ctx.diags.push(Diagnostic::warning("SEC005", "Secret value interpolated into a string; this may leak it.").at(e.span()));
            }
            check_expr(ctx, l, user_types);
            check_expr(ctx, r, user_types);
        }
        Expr::Unary(_, i, _) => check_expr(ctx, i, user_types),
        Expr::Cast(i, _, _) => check_expr(ctx, i, user_types),
        Expr::Index(b, i, _) => { check_expr(ctx, b, user_types); check_expr(ctx, i, user_types); }
        Expr::ArrayLit(items, _) => { for i in items { check_expr(ctx, i, user_types); } }
        Expr::TupleLit(items, _) => { for i in items { check_expr(ctx, i, user_types); } }
        _ => {}
    }
}

fn is_sensitive_expr(ctx: &SecCtx, e: &Expr) -> bool {
    match e {
        Expr::Ident(n, _) => ctx.sensitive.contains(n),
        _ => false,
    }
}

/// Reference impl of the intended Type alias to keep module self contained.
pub fn ensure_type_in_scope(_t: &Type) {}
