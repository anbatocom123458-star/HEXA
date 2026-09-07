//! HEXA intermediate representation (stack-based, typed).
//!
//! The front-end is lowered into this IR, which is then optimized and
//! lowered to native x86-64 assembly. Keeping an explicit typed IR makes each
//! stage independently testable and paves the way toward self-hosting.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeTag {
    Int,
    Dec,
    Bool,
    Text,
    Bytes,
    Char,
    Void,
}

#[derive(Clone, Debug)]
pub enum Inst {
    PushInt(i64),
    PushDec(u64),          // f64 bit pattern
    PushStr(String),       // text value (null-terminated payload)
    PushBytes(Vec<u8>),
    PushBool(bool),
    PushLocal(usize),      // slot index
    Store(usize),          // pop -> slot
    Pop,                   // discard top of stack
    Add, Sub, Mul, Div, Mod,
    Eq, Ne, Lt, Le, Gt, Ge,
    And, Or,
    Neg, Not,
    ConcatText,
    Jmp(u32),
    Jz(u32),               // pop bool; jump if false
    Call(String, u32),     // function name, argc
    Return,
    PrintInt,
    PrintDec,
    PrintText,
    PrintBool,
    PrintBytes,
}

#[derive(Clone, Debug)]
pub struct Local {
    pub name: String,
    pub ty: TypeTag,
}

#[derive(Clone, Debug)]
pub struct Function {
    pub name: String,
    pub params: Vec<TypeTag>,
    pub ret: TypeTag,
    pub locals: Vec<Local>,
    pub body: Vec<Inst>,
}

#[derive(Clone, Debug, Default)]
pub struct Module {
    pub funcs: Vec<Function>,
}
