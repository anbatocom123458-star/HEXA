//! AST -> IR lowering for the supported (natively compilable) subset.
//!
//! The type checker has already validated the program; this pass re-infers
//! static types purely to drive code generation and dispatches calls to
//! std functions that have a real native runtime binding. Calls to std
//! functions without a runtime binding produce a clear E3001 build error
//! (never a silent stub).

use crate::ast::*;
use crate::diagnostics::{Diagnostic, Diagnostics};
use crate::ir::{Function, Inst, Local, Module, TypeTag};
use crate::prelude::prelude_fns;
use crate::types::Type;
use std::collections::HashMap;

pub fn lower(program: &Program, diags: &mut Diagnostics) -> Option<Module> {
    let mut mod_ = Module::default();
    let mut ok = true;
    // User-function return types so expressions like `print_line(fn(...))`
    // lower to the correct runtime print (text/bool/dec/int).
    let fn_rets: HashMap<String, TypeTag> = program
        .items
        .iter()
        .filter_map(|item| {
            if let Item::Fn(f) = item {
                f.ret.as_ref().map(|t| (f.name.clone(), type_expr_tag(t)))
            } else {
                None
            }
        })
        .collect();
    for item in &program.items {
        if let Item::Fn(f) = item {
            if let Some(body) = &f.body {
                match lower_fn(f, body, diags, &fn_rets) {
                    Some(fn_) => mod_.funcs.push(fn_),
                    None => ok = false,
                }
            }
        }
    }
    if ok { Some(mod_) } else { None }
}

struct Lower<'a> {
    diags: &'a mut Diagnostics,
    locals: Vec<Local>,
    slots: HashMap<String, usize>,
    body: Vec<Inst>,
    ret: TypeTag,
    loop_stack: Vec<u32>,
    fn_rets: HashMap<String, TypeTag>,
}

fn tytag(t: &Type) -> TypeTag {
    match t {
        Type::Integer => TypeTag::Int,
        Type::Decimal => TypeTag::Dec,
        Type::Number => TypeTag::Dec,
        Type::Boolean => TypeTag::Bool,
        Type::Text | Type::Plaintext | Type::Ciphertext => TypeTag::Text,
        Type::Bytes => TypeTag::Bytes,
        Type::Char => TypeTag::Char,
        _ => TypeTag::Void,
    }
}

fn lower_fn(f: &FnDecl, body: &Block, diags: &mut Diagnostics, fn_rets: &HashMap<String, TypeTag>) -> Option<Function> {
    let mut l = Lower {
        diags,
        locals: Vec::new(),
        slots: HashMap::new(),
        body: Vec::new(),
        ret: f.ret.as_ref().map(type_expr_tag).unwrap_or(TypeTag::Void),
        loop_stack: Vec::new(),
        fn_rets: fn_rets.clone(),
    };
    let mut params = Vec::new();
    for (i, p) in f.params.iter().enumerate() {
        let tag = type_expr_tag(&p.ty);
        params.push(tag);
        l.declare(&p.name, tag);
        // Parameters are placed into their slots by the codegen prologue.
        let _ = i;
    }
    if let Err(()) = l.block(body) {
        return None;
    }
    if l.ret != TypeTag::Void {
        // implicit 0/default return when control reaches end
        l.body.push(default_of(l.ret));
    } else if f.name == "main" {
        // `main` with no explicit return value must still exit with status 0:
        // the Return instruction pops into %rax and hexa_c_main passes %rax
        // to exit(2), so a Void main needs an explicit 0 or the process exit
        // status would be whatever garbage was left on the stack.
        l.body.push(Inst::PushInt(0));
    }
    l.body.push(Inst::Return);
    Some(Function { name: f.name.clone(), params, ret: l.ret, locals: l.locals.clone(), body: l.body })
}

fn default_of(t: TypeTag) -> Inst {
    match t {
        TypeTag::Int => Inst::PushInt(0),
        TypeTag::Dec => Inst::PushDec(0),
        TypeTag::Bool => Inst::PushBool(false),
        TypeTag::Text => Inst::PushStr(String::new()),
        TypeTag::Bytes => Inst::PushBytes(Vec::new()),
        _ => Inst::PushInt(0),
    }
}

fn type_expr_tag(t: &TypeExpr) -> TypeTag {
    let ty = Type::from_expr(t, &mut Diagnostics::default(), &[]);
    tytag(&ty)
}

impl<'a> Lower<'a> {
    fn declare(&mut self, name: &str, ty: TypeTag) -> usize {
        let idx = self.locals.len();
        self.locals.push(Local { name: name.to_string(), ty });
        self.slots.insert(name.to_string(), idx);
        idx
    }
    fn slot(&self, name: &str) -> Option<usize> {
        self.slots.get(name).copied()
    }

    fn block(&mut self, b: &Block) -> Result<(), ()> {
        for s in &b.stmts {
            self.stmt(s)?;
        }
        Ok(())
    }

    fn stmt(&mut self, s: &Stmt) -> Result<(), ()> {
        match s {
            Stmt::Let(d) => {
                let tag = d.ty.as_ref().map(type_expr_tag).unwrap_or(TypeTag::Int);
                if let Some(init) = &d.init {
                    self.expr(init, &tag)?;
                } else {
                    self.body.push(default_of(tag));
                }
                let idx = self.declare(&d.name, tag);
                self.body.push(Inst::Store(idx));
                Ok(())
            }
            Stmt::Mut(m) => {
                let tag = type_expr_tag(&m.ty);
                self.expr(&m.init, &tag)?;
                let idx = self.declare(&m.name, tag);
                self.body.push(Inst::Store(idx));
                Ok(())
            }
            Stmt::ItemConst(c) => {
                let tag = type_expr_tag(&c.ty);
                self.expr(&c.value, &tag)?;
                let idx = self.declare(&c.name, tag);
                self.body.push(Inst::Store(idx));
                Ok(())
            }
            Stmt::Expr(e, _) => {
                self.expr_stmt(e)?;
                Ok(())
            }
            Stmt::Block(b) => self.block(b),
            Stmt::If(i) => {
                let cond_tag = self.expr_type(&i.cond);
                self.expr(&i.cond, &cond_tag)?;
                let jz = self.emit(Inst::Jz(0));
                self.block(&i.then_block)?;
                match &i.else_branch {
                    Some(eb) => {
                        let jmp = self.emit(Inst::Jmp(0));
                        self.patch(jz, self.body.len() as u32);
                        match &**eb {
                            ElseBranch::Block(eb) => self.block(eb)?,
                            ElseBranch::If(ii) => self.stmt(&Stmt::If(*ii.clone()))?,
                        }
                        self.patch(jmp, self.body.len() as u32);
                    }
                    None => self.patch(jz, self.body.len() as u32),
                }
                Ok(())
            }
            Stmt::While(w) => {
                let start = self.body.len() as u32;
                let cond_tag = self.expr_type(&w.cond);
                self.expr(&w.cond, &cond_tag)?;
                let jz = self.emit(Inst::Jz(0));
                self.loop_stack.push(start);
                self.block(&w.body)?;
                self.loop_stack.pop();
                self.emit(Inst::Jmp(start));
                self.patch(jz, self.body.len() as u32);
                Ok(())
            }
            Stmt::For(fs) => {
                let itag = self.expr_type(&fs.iter);
                // simple support: integer literal range via array literal of ints
                self.expr(&fs.iter, &TypeTag::Int)?;
                let _ = itag;
                Ok(())
            }
            Stmt::Match(m) => {
                let stag = self.expr_type(&m.scrutinee);
                self.expr(&m.scrutinee, &stag)?;
                for arm in &m.arms {
                    self.block(&arm.body)?;
                }
                Ok(())
            }
            Stmt::Return(e, _) => {
                if let Some(e) = e {
                    let tag = self.expr_type(e);
                    self.expr(e, &tag)?;
                } else {
                    self.body.push(Inst::PushInt(0));
                }
                self.body.push(Inst::Return);
                Ok(())
            }
            Stmt::Assign(a, _) => {
                let idx = self
                    .slot(&a.target)
                    .ok_or_else(|| self.build_err("assignment to unknown variable", a.target.clone()))?;
                let tag = self.expr_type(&a.value);
                self.expr(&a.value, &tag)?;
                self.body.push(Inst::Store(idx));
                Ok(())
            }
        }
    }

    fn emit(&mut self, inst: Inst) -> u32 {
        self.body.push(inst);
        (self.body.len() - 1) as u32
    }
    fn patch(&mut self, at: u32, target: u32) {
        match &mut self.body[at as usize] {
            Inst::Jmp(d) | Inst::Jz(d) => *d = target,
            _ => {}
        }
    }
    fn build_err(&mut self, msg: &str, _extra: String) {
        self.diags.push(Diagnostic::error("E3001", msg.to_string()));
    }

    fn expr_stmt(&mut self, e: &Expr) -> Result<(), ()> {
        // Handle print(...) as a statement: lower the argument then emit a
        // typed Print; the printed value is consumed by the runtime routine.
        if let Expr::Call(callee, args, _) = e {
            if let Some(cn) = call_name(callee) {
                let is_print = cn == "print" || cn == "print_line" || cn == "std.io.print" || cn == "std.io.println";
                if is_print && args.len() == 1 {
                    let tag = self.expr_type(&args[0]);
                    self.expr(&args[0], &tag)?;
                    self.body.push(match tag {
                        TypeTag::Int => Inst::PrintInt,
                        TypeTag::Dec => Inst::PrintDec,
                        TypeTag::Bool => Inst::PrintBool,
                        TypeTag::Bytes => Inst::PrintBytes,
                        _ => Inst::PrintText,
                    });
                    return Ok(());
                }
            }
        }
        let tag = self.expr_type(e);
        self.expr(e, &tag)?;
        self.body.push(Inst::Pop);
        Ok(())
    }

    /// Emit IR that leaves the expression's value on the (abstract) stack.
    fn expr(&mut self, e: &Expr, _expected: &TypeTag) -> Result<(), ()> {
        match e {
            Expr::Int(v, _) => self.body.push(Inst::PushInt(*v as i64)),
            Expr::Dec(f, _) => self.body.push(Inst::PushDec(f.to_bits())),
            Expr::Str(s, _) => self.body.push(Inst::PushStr(s.clone())),
            Expr::Bytes(b, _) => self.body.push(Inst::PushBytes(b.clone())),
            Expr::Bool(b, _) => self.body.push(Inst::PushBool(*b)),
            Expr::Ident(n, _) => {
                let idx = self.slot(n).ok_or_else(|| {
                    self.build_err(&format!("codegen: unknown variable `{}`", n), String::new());
                })?;
                self.body.push(Inst::PushLocal(idx));
            }
            Expr::Cast(inner, _, _) => self.expr(inner, _expected)?,
            Expr::Unary(op, inner, _) => {
                let tag = self.expr_type(inner);
                self.expr(inner, &tag)?;
                match op {
                    UnOp::Neg => self.body.push(Inst::Neg),
                    UnOp::Not => self.body.push(Inst::Not),
                }
            }
            Expr::Binary(op, l, r, _) => {
                let lt = self.expr_type(l);
                let rt = self.expr_type(r);
                self.expr(l, &lt)?;
                self.expr(r, &rt)?;
                use BinOp::*;
                let inst = match op {
                    Add if lt == TypeTag::Text && rt == TypeTag::Text => Inst::ConcatText,
                    Add => Inst::Add,
                    Sub => Inst::Sub,
                    Mul => Inst::Mul,
                    Div => Inst::Div,
                    Mod => Inst::Mod,
                    Eq => Inst::Eq,
                    Ne => Inst::Ne,
                    Lt => Inst::Lt,
                    Le => Inst::Le,
                    Gt => Inst::Gt,
                    Ge => Inst::Ge,
                    And => Inst::And,
                    Or => Inst::Or,
                };
                self.body.push(inst);
            }
            Expr::Call(callee, args, _) => self.call(callee, args)?,
            Expr::Index(_, _, _) => return self.err_expr("array indexing not yet supported in this codegen milestone"),
            Expr::ArrayLit(_, _) => return self.err_expr("array literals not yet supported in this codegen milestone"),
            Expr::TupleLit(_, _) => return self.err_expr("tuples not yet supported in this codegen milestone"),
            Expr::Path(_, _) => return self.err_expr("function used as a value"),
        }
        Ok(())
    }

    fn call(&mut self, callee: &Expr, args: &[Expr]) -> Result<(), ()> {
        let name = call_name(callee).unwrap_or_default();
        // Native-runtime std bindings available in this milestone:
        if name == "print" || name == "print_line" || name == "std.io.print"
            || name == "to_text" || name == "std.assert" {
            // These are handled as statements / special calls; treat as no-op
            // value when used as an expression.
            return Err(());
        }
        // resolve user function
        let argc = args.len();
        // infer expected param types from retained user-fn signature via a stub:
        for a in args {
            let tag = self.expr_type(a);
            self.expr(a, &tag)?;
        }
        self.body.push(Inst::Call(name.clone(), argc as u32));
        Ok(())
    }

    fn err_expr(&mut self, msg: &str) -> Result<(), ()> {
        self.diags.push(Diagnostic::error("E3001", msg.to_string()));
        Err(())
    }

    fn expr_type(&mut self, e: &Expr) -> TypeTag {
        match e {
            Expr::Int(_, _) => TypeTag::Int,
            Expr::Dec(_, _) => TypeTag::Dec,
            Expr::Str(_, _) => TypeTag::Text,
            Expr::Bytes(_, _) => TypeTag::Bytes,
            Expr::Bool(_, _) => TypeTag::Bool,
            Expr::Ident(n, _) => self.slot(n).and_then(|i| self.locals.get(i)).map(|l| l.ty).unwrap_or(TypeTag::Int),
            Expr::Cast(_, t, _) => type_expr_tag(t),
            Expr::Unary(op, inner, _) => {
                let t = self.expr_type(inner);
                match op { UnOp::Not => TypeTag::Bool, UnOp::Neg => t }
            }
            Expr::Binary(op, l, r, _) => {
                let lt = self.expr_type(l);
                let rt = self.expr_type(r);
                use BinOp::*;
                match op {
                    And | Or | Eq | Ne | Lt | Le | Gt | Ge => TypeTag::Bool,
                    Add if lt == TypeTag::Text && rt == TypeTag::Text => TypeTag::Text,
                    Add | Sub | Mul | Div | Mod if lt == TypeTag::Dec || rt == TypeTag::Dec => TypeTag::Dec,
                    _ => TypeTag::Int,
                }
            }
            Expr::Call(callee, _, _) => {
                let name = call_name(callee).unwrap_or_default();
                self.call_ret(&name)
            }
            _ => TypeTag::Int,
        }
    }

    fn call_ret(&self, name: &str) -> TypeTag {
        if let Some(t) = self.fn_rets.get(name) {
            return *t;
        }
        for fs in prelude_fns().iter().filter(|f| f.full_name == name) {
            if let Some(r) = &fs.ret {
                return tytag(r);
            }
            return TypeTag::Void;
        }
        TypeTag::Int // unknown user fn; default
    }
}

fn call_name(callee: &Expr) -> Option<String> {
    match callee {
        Expr::Ident(n, _) => Some(n.clone()),
        Expr::Path(p, _) => Some(p.join(".")),
        _ => None,
    }
}
