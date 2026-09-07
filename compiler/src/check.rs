//! HEXA type checker + name resolution + secret-safety enforcement.
//!
//! Walks the AST, resolves identifiers, infers expression types, validates
//! conversions (including the security-sensitive type lattice) and emits
//! E2xxx diagnostics.

use std::collections::HashMap;

use crate::ast::*;
use crate::diagnostics::{Diagnostic, Diagnostics, Span};
use crate::prelude::prelude_fns;
use crate::types::Type;

#[derive(Clone, Debug)]
pub struct UserFn {
    pub name: String,
    pub params: Vec<(String, Type)>,
    pub ret: Option<Type>,
    pub is_pub: bool,
    pub has_body: bool,
    pub span: Span,
}

pub struct Ctx<'a> {
    pub diags: &'a mut Diagnostics,
    user_fns: HashMap<String, UserFn>,
    user_types: Vec<String>,
    scopes: Vec<HashMap<String, Type>>,
    ret_type: Option<Type>,
    loop_depth: usize,
}

impl<'a> Ctx<'a> {
    fn push_scope(&mut self) {
        self.scopes.push(HashMap::new());
    }
    fn pop_scope(&mut self) {
        self.scopes.pop();
    }
    fn declare(&mut self, name: &str, ty: Type) {
        if let Some(s) = self.scopes.last_mut() {
            s.insert(name.to_string(), ty);
        }
    }
    fn lookup(&self, name: &str) -> Option<Type> {
        for s in self.scopes.iter().rev() {
            if let Some(t) = s.get(name) {
                return Some(t.clone());
            }
        }
        None
    }
}

pub fn check(program: &Program, users_known_types: &[String], diags: &mut Diagnostics) {
    let mut ctx = Ctx {
        diags,
        user_fns: HashMap::new(),
        user_types: Vec::new(),
        scopes: Vec::new(),
        ret_type: None,
        loop_depth: 0,
    };
    // First pass: collect user types.
    for item in &program.items {
        match item {
            Item::Struct(s) => ctx.user_types.push(s.name.clone()),
            Item::Enum(e) => ctx.user_types.push(e.name.clone()),
            _ => {}
        }
    }
    for t in users_known_types {
        ctx.user_types.push(t.clone());
    }
    // Second pass: collect user function signatures.
    for item in &program.items {
        if let Item::Fn(f) = item {
            let params = f.params.iter().map(|p| {
                let ty = Type::from_expr(&p.ty, ctx.diags, &ctx.user_types);
                (p.name.clone(), ty)
            }).collect::<Vec<_>>();
            let ret = f.ret.as_ref().map(|r| Type::from_expr(r, ctx.diags, &ctx.user_types));
            ctx.user_fns.insert(f.name.clone(), UserFn {
                name: f.name.clone(), params, ret, is_pub: f.is_pub, has_body: f.body.is_some(), span: f.span,
            });
        }
    }
    // Check each fn body.
    for item in &program.items {
        if let Item::Fn(f) = item {
            if let Some(body) = &f.body {
                let sig = ctx.user_fns.get(&f.name).cloned().unwrap();
                ctx.push_scope();
                for (n, t) in &sig.params {
                    ctx.declare(n, t.clone());
                }
                ctx.declare(&f.name, Type::Closure(sig.params.iter().map(|(_, t)| t.clone()).collect(),
                    Box::new(sig.ret.clone().unwrap_or(Type::Unit))));
                let prev_ret = ctx.ret_type.take();
                ctx.ret_type = sig.ret;
                check_block(&mut ctx, body);
                ctx.ret_type = prev_ret;
                ctx.pop_scope();
            }
        }
    }
    let _ = ctx.user_types;
}

fn check_block(ctx: &mut Ctx, block: &Block) {
    ctx.push_scope();
    for stmt in &block.stmts {
        check_stmt(ctx, stmt);
    }
    ctx.pop_scope();
}

fn check_stmt(ctx: &mut Ctx, stmt: &Stmt) {
    match stmt {
        Stmt::Let(d) => {
            let ty = match (&d.ty, &d.init) {
                (Some(t), _) => {
                    let ty = Type::from_expr(t, ctx.diags, &ctx.user_types);
                    if let Some(init) = &d.init {
                        let got = infer(ctx, init);
                        coerce(ctx, init, &got, &ty);
                    }
                    ty
                }
                (None, Some(init)) => infer(ctx, init),
                (None, None) => {
                    ctx.diags.push(Diagnostic::error("E2002", format!("`let {}` requires a type or an initializer", d.name)).at(d.span));
                    Type::Any
                }
            };
            ctx.declare(&d.name, ty);
        }
        Stmt::Mut(d) => {
            let ty = Type::from_expr(&d.ty, ctx.diags, &ctx.user_types);
            let got = infer(ctx, &d.init);
            coerce(ctx, &d.init, &got, &ty);
            ctx.declare(&d.name, ty);
        }
        Stmt::ItemConst(c) => {
            let ty = Type::from_expr(&c.ty, ctx.diags, &ctx.user_types);
            let got = infer(ctx, &c.value);
            coerce(ctx, &c.value, &got, &ty);
            ctx.declare(&c.name, ty);
        }
        Stmt::Expr(e, _) => { infer(ctx, e); }
        Stmt::Block(b) => check_block(ctx, b),
        Stmt::If(i) => {
            let ct = infer(ctx, &i.cond);
            expect_bool(ctx, &i.cond, &ct, i.span);
            check_block(ctx, &i.then_block);
            match &i.else_branch {
                Some(eb) => match &**eb {
                    ElseBranch::Block(b) => check_block(ctx, b),
                    ElseBranch::If(ii) => check_stmt(ctx, &Stmt::If(*ii.clone())),
                },
                None => {}
            }
        }
        Stmt::While(w) => {
            let ct = infer(ctx, &w.cond);
            expect_bool(ctx, &w.cond, &ct, w.span);
            ctx.loop_depth += 1;
            check_block(ctx, &w.body);
            ctx.loop_depth -= 1;
        }
        Stmt::For(f) => {
            let it = infer(ctx, &f.iter);
            if let Type::Array(e) = &it {
                ctx.loop_depth += 1;
                ctx.push_scope();
                ctx.declare(&f.var, (**e).clone());
                check_block(ctx, &f.body);
                ctx.pop_scope();
                ctx.loop_depth -= 1;
            } else {
                ctx.diags.push(Diagnostic::error("E2005", format!("`for` requires an array, found `{}`", it.name())).at(f.span));
            }
        }
        Stmt::Match(m) => {
            let st = infer(ctx, &m.scrutinee);
            for arm in &m.arms {
                for p in &arm.patterns {
                    if let Pattern::Ident(name, _) = p {
                        ctx.push_scope();
                        ctx.declare(name, st.clone());
                        check_block(ctx, &arm.body);
                        ctx.pop_scope();
                        break;
                    } else {
                        check_block(ctx, &arm.body);
                        break;
                    }
                }
            }
        }
        Stmt::Return(e, span) => {
            let got = e.as_ref().map(|x| infer(ctx, x)).unwrap_or(Type::Unit);
            let rt = ctx.ret_type.clone();
            match &rt {
                Some(r) if *r == Type::Unit && e.is_some() => {
                    ctx.diags.push(Diagnostic::error("E2006", "this function returns no value").at(*span));
                }
                Some(r) if *r != Type::Unit && e.is_none() => {
                    ctx.diags.push(Diagnostic::error("E2006", format!("function expects to return `{}`", r.name())).at(*span));
                }
                Some(r) if e.is_some() => { coerce(ctx, e.as_ref().unwrap(), &got, r); }
                _ => {}
            }
        }
        Stmt::Assign(a, _) => {
            let vt = match ctx.lookup(&a.target) {
                Some(t) => t,
                None => {
                    ctx.diags.push(Diagnostic::error("E2001", format!("cannot find value `{}`", a.target)).at(stmt_span(stmt)));
                    return;
                }
            };
            if let Some((idx, _)) = &a.index {
                match &vt {
                    Type::Array(e) => {
                        let _ = infer(ctx, idx.as_ref());
                        let got = infer(ctx, &a.value);
                        coerce(ctx, &a.value, &got, e);
                    }
                    _ => ctx.diags.push(Diagnostic::error("E2005", "index assignment requires an array").at(stmt_span(stmt))),
                }
            } else {
                let got = infer(ctx, &a.value);
                coerce(ctx, &a.value, &got, &vt);
            }
        }
    }
}

fn stmt_span(s: &Stmt) -> Span {
    match s {
        Stmt::Let(d) => d.span,
        Stmt::Mut(d) => d.span,
        Stmt::ItemConst(c) => c.span,
        Stmt::Expr(_, sp) => *sp,
        Stmt::If(i) => i.span,
        Stmt::While(w) => w.span,
        Stmt::For(f) => f.span,
        Stmt::Match(m) => m.span,
        Stmt::Return(_, sp) => *sp,
        Stmt::Assign(_, sp) => *sp,
        Stmt::Block(b) => b.span,
    }
}

// ---------------- expression inference ------------------------------

fn expect_bool(ctx: &mut Ctx, e: &Expr, got: &Type, span: Span) {
    if *got != Type::Boolean && *got != Type::Any {
        ctx.diags.push(Diagnostic::error("E2003", format!(
            "condition must be `boolean`\nExpected: boolean\nFound: {}", got.name())).at(span));
    }
    let _ = e;
}

/// Check that `got` can be used where `expected` is required, following the
/// security-sensitive conversion rules.
pub fn coerce(ctx: &mut Ctx, e: &Expr, got: &Type, expected: &Type) {
    if *expected == Type::Any {
        return;
    }
    if got.converts_implicit(expected) || got == expected {
        return;
    }
    // Secret-sensitive: never silently downgrade.
    if got.is_secret_never_print() && matches!(expected, Type::Text | Type::Bytes) {
        ctx.diags.push(Diagnostic::error("E2101", format!(
            "Cannot use `{}` where `{}` is required without an explicit export.\n\
             Expected: {}\nFound: {}\n\
             Sensitive values must be exported with `secret.export(...)`.\n\
             They are never implicitly converted to ordinary text.",
            got.name(), expected.name(), expected.name(), got.name())).at(e.span()));
        return;
    }
    let _ = e;
    ctx.diags.push(Diagnostic::error("E2003", format!(
        "Cannot use `{}` where `{}` is required.\nExpected: {}\nFound: {}",
        got.name(), expected.name(), expected.name(), got.name())).at(e.span()));
}

fn infer(ctx: &mut Ctx, e: &Expr) -> Type {
    match e {
        Expr::Int(_, _) => Type::Integer,
        Expr::Dec(_, _) => Type::Decimal,
        Expr::Str(_, _) => Type::Text,
        Expr::Bytes(_, _) => Type::Bytes,
        Expr::Bool(_, _) => Type::Boolean,
        Expr::Ident(name, span) => match ctx.lookup(name) {
            Some(t) => t,
            None => {
                ctx.diags.push(Diagnostic::error("E2001", format!("cannot find value `{}`", name)).at(*span));
                Type::Any
            }
        },
        Expr::Path(parts, span) => {
            // A module/function path used as a value. Only meaningful when
            // invoked; otherwise report an unknown-symbol error.
            let dotted = parts.join(".");
            let known = prelude_fns().iter().any(|f| f.full_name == dotted);
            if known && parts.len() >= 2 && parts.last().map(|s| s.as_str()) == Some("generate") {
                // treat as partially-applied; not supported as a bare value
            }
            if parts.len() == 1 {
                ctx.diags.push(Diagnostic::error("E2001", format!("cannot find value `{}`", parts[0])).at(*span));
                Type::Any
            } else {
                ctx.diags.push(Diagnostic::error("E2004", format!(
                    "`{}` names a function, not a value; call it with `(...)`", dotted)).at(*span));
                Type::Any
            }
        }
        Expr::Call(callee, args, _) => infer_call(ctx, callee, args),
        Expr::Unary(op, inner, span) => {
            let t = infer(ctx, inner);
            match op {
                UnOp::Neg => {
                    if !matches!(t, Type::Integer | Type::Decimal | Type::Number | Type::Any) {
                        ctx.diags.push(Diagnostic::error("E2003", format!("cannot negate `{}`", t.name())).at(*span));
                    }
                    t
                }
                UnOp::Not => {
                    if !matches!(t, Type::Boolean | Type::Any) {
                        ctx.diags.push(Diagnostic::error("E2003", format!("cannot negate `{}` with `!`", t.name())).at(*span));
                    }
                    Type::Boolean
                }
            }
        }
        Expr::Binary(op, l, r, span) => {
            let lt = infer(ctx, l);
            let rt = infer(ctx, r);
            use BinOp::*;
            match op {
                And | Or => {
                    expect_bool(ctx, l, &lt, *span);
                    expect_bool(ctx, r, &rt, *span);
                    Type::Boolean
                }
                Eq | Ne | Lt | Le | Gt | Ge => {
                    if !numeric_pair(&lt, &rt) && lt != rt && lt != Type::Any && rt != Type::Any {
                        ctx.diags.push(Diagnostic::error("E2003", format!(
                            "cannot compare `{}` and `{}`", lt.name(), rt.name())).at(*span));
                    }
                    Type::Boolean
                }
                Add | Sub | Mul | Div | Mod => {
                    if Type::Text == lt && *op == BinOp::Add && Type::Text == rt {
                        Type::Text
                    } else if numeric_pair(&lt, &rt) {
                        numeric_result(&lt, &rt)
                    } else {
                        ctx.diags.push(Diagnostic::error("E2003", format!(
                            "cannot apply `{}` to `{}` and `{}`", op_sym(*op), lt.name(), rt.name())).at(*span));
                        Type::Any
                    }
                }
            }
        }
        Expr::Cast(inner, ty, span) => {
            let got = infer(ctx, inner);
            let target = Type::from_expr(ty, ctx.diags, &ctx.user_types);
            if !got.converts_explicit_cast(&target) && got != target {
                if got.is_secret_never_print() {
                    ctx.diags.push(Diagnostic::error("E2102", format!(
                        "Cannot cast `{}` to `{}`.\nSensitive values must be exported explicitly with `secret.export(...)`.\n\
                         They cannot be downgraded to ordinary data with a cast.",
                        got.name(), target.name())).at(*span));
                } else {
                    ctx.diags.push(Diagnostic::error("E2003", format!(
                        "Cannot cast `{}` to `{}`.", got.name(), target.name())).at(*span));
                }
            }
            target
        }
        Expr::Index(base, idx, _) => {
            let bt = infer(ctx, base);
            let _ = infer(ctx, idx);
            match &bt {
                Type::Array(e) => (**e).clone(),
                Type::Map(_, v) => (**v).clone(),
                Type::Text => Type::Char,
                Type::Bytes => Type::Integer,
                _ => {
                    ctx.diags.push(Diagnostic::error("E2005", format!("cannot index into `{}`", bt.name())).at(e.span()));
                    Type::Any
                }
            }
        }
        Expr::ArrayLit(items, _) => {
            if let Some(first) = items.first() {
                Type::Array(Box::new(infer(ctx, first)))
            } else {
                Type::Array(Box::new(Type::Any))
            }
        }
        Expr::TupleLit(items, _) => {
            Type::Tuple(items.iter().map(|x| infer(ctx, x)).collect())
        }
    }
}

fn numeric_pair(a: &Type, b: &Type) -> bool {
    let n = |t: &Type| matches!(t, Type::Integer | Type::Decimal | Type::Number | Type::Any);
    n(a) && n(b)
}

fn numeric_result(a: &Type, b: &Type) -> Type {
    if *a == Type::Decimal || *b == Type::Decimal {
        Type::Decimal
    } else if *a == Type::Number || *b == Type::Number {
        Type::Number
    } else {
        Type::Integer
    }
}

fn op_sym(op: BinOp) -> &'static str {
    use BinOp::*;
    match op { Add => "+", Sub => "-", Mul => "*", Div => "/", Mod => "%",
        Eq => "==", Ne => "!=", Lt => "<", Le => "<=", Gt => ">", Ge => ">=", And => "&&", Or => "||" }
}

fn infer_call(ctx: &mut Ctx, callee: &Expr, args: &[Expr]) -> Type {
    let (name, span) = match callee {
        Expr::Ident(n, sp) => (n.clone(), *sp),
        Expr::Path(parts, sp) => (parts.join("."), *sp),
        _ => {
            ctx.diags.push(Diagnostic::error("E2004", "invalid callee").at(callee.span()));
            return Type::Any;
        }
    };
    // user function?
    if let Some(uf) = ctx.user_fns.get(&name).cloned() {
        if args.len() != uf.params.len() {
            ctx.diags.push(Diagnostic::error("E2007", format!(
                "function `{}` expects {} argument(s) but found {}", name, uf.params.len(), args.len())).at(span));
        } else {
            for (arg, (_, pt)) in args.iter().zip(&uf.params) {
                let got = infer(ctx, arg);
                coerce(ctx, arg, &got, pt);
            }
        }
        return uf.ret.clone().unwrap_or(Type::Unit);
    }
    // prelude function?
    let sigs = crate::prelude::prelude_fns();
    for fs in sigs.iter().filter(|f| f.full_name == name.as_str()) {
        if args.len() != fs.params.len() {
            continue; // try other overloads
        }
        let mut ok = true;
        for (arg, (_, pt)) in args.iter().zip(fs.params.iter()) {
            let got = infer(ctx, arg);
            if *pt == Type::Any {
                // validate printable if this is print
                if name.contains("print") && !got.printable() {
                    ctx.diags.push(Diagnostic::error("E2100", format!(
                        "cannot print secret type `{}`\nSensitive values are never printed implicitly.\n\
                         Export them explicitly with `secret.export(...)` if you are certain.",
                        got.name())).at(arg.span()));
                }
                continue;
            }
            coerce(ctx, arg, &got, pt);
            if !got.converts_implicit(pt) && got != *pt && *pt != Type::Any {
                ok = false;
            }
        }
        let _ = ok;
        return fs.ret.clone().unwrap_or(Type::Unit);
    }
    if is_unknown_std_mod(&name) {
        ctx.diags.push(Diagnostic::error("E2004", format!(
            "unknown std function `{}`", name)).at(span));
    } else {
        ctx.diags.push(Diagnostic::error("E2004", format!("unknown function `{}`", name)).at(span));
    }
    Type::Any
}

fn is_unknown_std_mod(_name: &str) -> bool {
    false
}
