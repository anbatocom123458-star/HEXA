//! HEXA abstract syntax tree.

use crate::diagnostics::Span;

#[derive(Clone, Debug)]
pub struct Program {
    pub items: Vec<Item>,
}

#[derive(Clone, Debug)]
pub enum Item {
    Import(ImportDecl),
    Fn(FnDecl),
    Struct(StructDecl),
    Enum(EnumDecl),
    Trait(TraitDecl),
    Impl(ImplDecl),
    Const(ConstDecl),
}

#[derive(Clone, Debug)]
pub struct ImportDecl {
    pub path: Vec<String>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct FnDecl {
    pub name: String,
    pub params: Vec<Param>,
    pub ret: Option<TypeExpr>,
    pub body: Option<Block>,
    pub is_pub: bool,
    pub is_async: bool,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct Param {
    pub name: String,
    pub ty: TypeExpr,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct StructDecl {
    pub name: String,
    pub fields: Vec<StructField>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct StructField {
    pub name: String,
    pub ty: TypeExpr,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct EnumDecl {
    pub name: String,
    pub variants: Vec<EnumVariant>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct EnumVariant {
    pub name: String,
    pub ty: Option<TypeExpr>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct TraitDecl {
    pub name: String,
    pub methods: Vec<FnDecl>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct ImplDecl {
    pub trait_name: Option<String>,
    pub self_ty: String,
    pub methods: Vec<FnDecl>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct ConstDecl {
    pub name: String,
    pub ty: TypeExpr,
    pub value: Expr,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TypeExpr {
    Named(String, Span),
    Array(Box<TypeExpr>, Span),
    Map(Box<TypeExpr>, Box<TypeExpr>, Span),
    Set(Box<TypeExpr>, Span),
    Option(Box<TypeExpr>, Span),
    Result(Box<TypeExpr>, Box<TypeExpr>, Span),
    Tuple(Vec<TypeExpr>, Span),
}

impl TypeExpr {
    pub fn span(&self) -> Span {
        match self {
            TypeExpr::Named(_, s) => *s,
            TypeExpr::Array(_, s) => *s,
            TypeExpr::Map(_, _, s) => *s,
            TypeExpr::Set(_, s) => *s,
            TypeExpr::Option(_, s) => *s,
            TypeExpr::Result(_, _, s) => *s,
            TypeExpr::Tuple(_, s) => *s,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum Stmt {
    Let(LetDecl),
    Mut(MutDecl),
    ItemConst(ConstDecl),
    Expr(Expr, Span),
    If(IfStmt),
    While(WhileStmt),
    For(ForStmt),
    Match(MatchStmt),
    Return(Option<Expr>, Span),
    Assign(Assign, Span),
    Block(Block),
}

#[derive(Clone, Debug)]
pub struct LetDecl {
    pub name: String,
    pub ty: Option<TypeExpr>,
    pub init: Option<Expr>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct MutDecl {
    pub name: String,
    pub ty: TypeExpr,
    pub init: Expr,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct IfStmt {
    pub cond: Expr,
    pub then_block: Block,
    pub else_branch: Option<Box<ElseBranch>>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum ElseBranch {
    Block(Block),
    If(Box<IfStmt>),
}

#[derive(Clone, Debug)]
pub struct WhileStmt {
    pub cond: Expr,
    pub body: Block,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct ForStmt {
    pub var: String,
    pub iter: Expr,
    pub body: Block,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct MatchStmt {
    pub scrutinee: Expr,
    pub arms: Vec<MatchArm>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct MatchArm {
    pub patterns: Vec<Pattern>,
    pub body: Block,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum Pattern {
    Ident(String, Span),
    Int(u64, Span),
    Str(String, Span),
    Wildcard(Span),
}

#[derive(Clone, Debug)]
pub struct Assign {
    pub target: String,
    pub index: Option<(Box<Expr>, Span)>,
    pub value: Expr,
}

#[derive(Clone, Debug)]
pub enum Expr {
    Int(u64, Span),
    Dec(f64, Span),
    Str(String, Span),
    Bytes(Vec<u8>, Span),
    Bool(bool, Span),
    Ident(String, Span),
    Path(Vec<String>, Span),
    Call(Box<Expr>, Vec<Expr>, Span),
    Unary(UnOp, Box<Expr>, Span),
    Binary(BinOp, Box<Expr>, Box<Expr>, Span),
    Cast(Box<Expr>, TypeExpr, Span),
    Index(Box<Expr>, Box<Expr>, Span),
    ArrayLit(Vec<Expr>, Span),
    TupleLit(Vec<Expr>, Span),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    Add, Sub, Mul, Div, Mod,
    Eq, Ne, Lt, Le, Gt, Ge,
    And, Or,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnOp {
    Neg,
    Not,
}

impl Expr {
    pub fn span(&self) -> Span {
        match self {
            Expr::Int(_, s) => *s,
            Expr::Dec(_, s) => *s,
            Expr::Str(_, s) => *s,
            Expr::Bytes(_, s) => *s,
            Expr::Bool(_, s) => *s,
            Expr::Ident(_, s) => *s,
            Expr::Path(_, s) => *s,
            Expr::Call(_, _, s) => *s,
            Expr::Unary(_, _, s) => *s,
            Expr::Binary(_, _, _, s) => *s,
            Expr::Cast(_, _, s) => *s,
            Expr::Index(_, _, s) => *s,
            Expr::ArrayLit(_, s) => *s,
            Expr::TupleLit(_, s) => *s,
        }
    }
}
