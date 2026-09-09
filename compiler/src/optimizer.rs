//! Deterministic IR optimizer.
//!
//! This milestone implements constant folding of integer arithmetic and
//! boolean logic directly on the IR. It runs before code generation and is
//! deterministic (output depends only on the input program).

use crate::ir::Inst;

/// Optimize a module in place.
pub fn optimize_module(module: &mut crate::ir::Module) {
    for f in &mut module.funcs {
        f.body = fold(f.body.clone());
    }
}

/// One pass of constant folding over an instruction vector.
fn fold(body: Vec<Inst>) -> Vec<Inst> {
    let mut out: Vec<Inst> = Vec::new();
    let mut i = 0usize;
    while i < body.len() {
        let a = &body[i];
        let b = body.get(i + 1);
        let c = body.get(i + 2);
        // PushInt a; PushInt b; <int-binop>
        if let (Inst::PushInt(va), Some(Inst::PushInt(vb)), Some(Inst::Add)) = (a, b, c) {
            out.push(Inst::PushInt(va.wrapping_add(*vb)));
            i += 3;
            continue;
        }
        if let (Inst::PushInt(va), Some(Inst::PushInt(vb)), Some(Inst::Sub)) = (a, b, c) {
            out.push(Inst::PushInt(va.wrapping_sub(*vb)));
            i += 3;
            continue;
        }
        if let (Inst::PushInt(va), Some(Inst::PushInt(vb)), Some(Inst::Mul)) = (a, b, c) {
            out.push(Inst::PushInt(va.wrapping_mul(*vb)));
            i += 3;
            continue;
        }
        // PushBool a; PushBool b; And / Or
        if let (Inst::PushBool(a), Some(Inst::PushBool(b)), Some(Inst::And)) = (a, b, c) {
            out.push(Inst::PushBool(*a && *b));
            i += 3;
            continue;
        }
        if let (Inst::PushBool(a), Some(Inst::PushBool(b)), Some(Inst::Or)) = (a, b, c) {
            out.push(Inst::PushBool(*a || *b));
            i += 3;
            continue;
        }
        // PushBool b; Not
        if let (Inst::PushBool(a), Some(Inst::Not)) = (a, b) {
            out.push(Inst::PushBool(!*a));
            i += 2;
            continue;
        }
        // PushInt v; Neg
        if let (Inst::PushInt(v), Some(Inst::Neg)) = (a, b) {
            out.push(Inst::PushInt(v.wrapping_neg()));
            i += 2;
            continue;
        }
        out.push(a.clone());
        i += 1;
    }
    out
}
