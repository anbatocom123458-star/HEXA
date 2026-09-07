//! HEXA recursive-descent parser: tokens -> AST.
//! Yields E1xxx diagnostics for syntax errors.

use crate::ast::*;
use crate::diagnostics::{Diagnostic, Diagnostics, Span};
use crate::lexer::{Lexer, Tok, Token};

pub struct Parser<'a> {
    toks: Vec<Token>,
    pos: usize,
    diags: &'a mut Diagnostics,
}

pub fn parse(file_id: usize, src: &str, diags: &mut Diagnostics) -> Program {
    let mut lex = Lexer::new(file_id, src, diags);
    let toks = lex.tokenize();
    let mut p = Parser { toks, pos: 0, diags };
    p.parse_program()
}

impl<'a> Parser<'a> {
    fn cur(&self) -> &Token {
        &self.toks[self.pos.min(self.toks.len() - 1)]
    }
    fn peek_kind(&self, off: usize) -> Tok {
        let i = (self.pos + off).min(self.toks.len() - 1);
        self.toks[i].kind
    }
    fn at(&self, k: Tok) -> bool {
        self.cur().kind == k
    }
    fn advance(&mut self) -> Token {
        let t = self.cur().clone();
        if self.pos < self.toks.len() - 1 {
            self.pos += 1;
        }
        t
    }
    fn eat(&mut self, k: Tok) -> bool {
        if self.at(k) {
            self.advance();
            true
        } else {
            false
        }
    }
    fn expect(&mut self, k: Tok, what: &str) -> Option<Token> {
        if self.at(k) {
            Some(self.advance())
        } else {
            let t = self.cur().clone();
            self.error("E1001", format!("expected `{}`{} but found `{}`", what, explain(k), t.text));
            None
        }
    }
    fn error(&mut self, code: &str, msg: impl Into<String>) {
        let span = self.cur().span;
        self.diags.push(Diagnostic::error(code, msg).at(span));
    }

    fn parse_program(&mut self) -> Program {
        let mut items = Vec::new();
        while !self.at(Tok::Eof) {
            if let Some(it) = self.parse_item() {
                items.push(it);
            } else {
                // skip one token to guarantee progress
                self.advance();
            }
        }
        Program { items }
    }

    fn parse_item(&mut self) -> Option<Item> {
        let start = self.cur().span;
        match self.cur().kind {
            Tok::Import => {
                self.advance();
                let mut path = Vec::new();
                loop {
                    let id = self.expect(Tok::Ident, "identifier")?;
                    path.push(id.text);
                    if !self.eat(Tok::Dot) {
                        break;
                    }
                }
                self.expect(Tok::Semicolon, ";");
                Some(Item::Import(ImportDecl { path, span: start }))
            }
            Tok::Pub | Tok::Private => {
                let is_pub = self.at(Tok::Pub);
                self.advance();
                let it = self.parse_item_tail(start, is_pub)?;
                Some(it)
            }
            Tok::Const => {
                self.advance();
                let (name, ty, value, span) = self.parse_const_body(start)?;
                Some(Item::Const(ConstDecl { name, ty, value, span }))
            }
            Tok::Fn => self.parse_fn(start, false, false),
            Tok::Struct => self.parse_struct(start),
            Tok::Enum => self.parse_enum(start),
            Tok::Trait => self.parse_trait(start),
            Tok::Impl => self.parse_impl(start),
            Tok::Module => {
                // `module name { ... }` is parsed but flattened into items.
                self.advance();
                self.expect(Tok::Ident, "module name");
                self.expect(Tok::LBrace, "{");
                let mut inner = Vec::new();
                while !self.at(Tok::RBrace) && !self.at(Tok::Eof) {
                    if let Some(it) = self.parse_item() {
                        inner.push(it);
                    } else {
                        self.advance();
                    }
                }
                self.expect(Tok::RBrace, "}");
                // return first inner item (parser model keeps flat scope)
                inner.into_iter().next()
            }
            _ => {
                self.error("E1001", format!("unexpected token `{}` at top level", self.cur().text));
                None
            }
        }
    }

    fn parse_item_tail(&mut self, start: Span, is_pub: bool) -> Option<Item> {
        match self.cur().kind {
            Tok::Fn => self.parse_fn(start, is_pub, false),
            Tok::Struct => self.parse_struct_pub(start, is_pub),
            _ => {
                self.error("E1001", "expected `fn`, `struct`, `enum`, `trait`, `impl` or `const` after visibility");
                None
            }
        }
    }

    fn parse_const_body(&mut self, start: Span) -> Option<(String, TypeExpr, Expr, Span)> {
        let name = self.expect(Tok::Ident, "constant name")?.text;
        self.expect(Tok::Colon, ":");
        let ty = self.parse_type()?;
        self.expect(Tok::Assign, "=");
        let value = self.parse_expr()?;
        self.expect(Tok::Semicolon, ";");
        Some((name, ty, value, start))
    }

    fn parse_fn(&mut self, start: Span, is_pub: bool, _unused: bool) -> Option<Item> {
        self.expect(Tok::Fn, "fn");
        let name = self.expect(Tok::Ident, "function name")?.text;
        let params = self.parse_params()?;
        let ret = if self.eat(Tok::Arrow) {
            self.parse_type()
        } else {
            None
        };
        let body = if self.at(Tok::LBrace) {
            Some(self.parse_block()?)
        } else {
            None
        };
        Some(Item::Fn(FnDecl { name, params, ret, body, is_pub, is_async: false, span: start }))
    }

    fn parse_params(&mut self) -> Option<Vec<Param>> {
        self.expect(Tok::LParen, "(")?;
        let mut params = Vec::new();
        if !self.at(Tok::RParen) {
            loop {
                let start = self.cur().span;
                let name = self.expect(Tok::Ident, "parameter name")?.text;
                self.expect(Tok::Colon, ":");
                let ty = self.parse_type()?;
                params.push(Param { name, ty, span: start });
                if !self.eat(Tok::Comma) {
                    break;
                }
            }
        }
        self.expect(Tok::RParen, ")");
        Some(params)
    }

    fn parse_struct(&mut self, start: Span) -> Option<Item> {
        self.advance();
        self.parse_struct_body(start, false)
    }
    fn parse_struct_pub(&mut self, start: Span, _is_pub: bool) -> Option<Item> {
        self.expect(Tok::Struct, "struct");
        self.parse_struct_body(start, true)
    }
    fn parse_struct_body(&mut self, start: Span, _is_pub: bool) -> Option<Item> {
        let name = self.expect(Tok::Ident, "struct name")?.text;
        let mut fields = Vec::new();
        self.expect(Tok::LBrace, "{");
        while !self.at(Tok::RBrace) && !self.at(Tok::Eof) {
            let fstart = self.cur().span;
            let fname = self.expect(Tok::Ident, "field name")?.text;
            self.expect(Tok::Colon, ":");
            let fty = self.parse_type()?;
            fields.push(StructField { name: fname, ty: fty, span: fstart });
            if !self.eat(Tok::Comma) {
                break;
            }
        }
        self.expect(Tok::RBrace, "}");
        Some(Item::Struct(StructDecl { name, fields, span: start }))
    }

    fn parse_enum(&mut self, start: Span) -> Option<Item> {
        self.advance();
        let name = self.expect(Tok::Ident, "enum name")?.text;
        let mut variants = Vec::new();
        self.expect(Tok::LBrace, "{");
        while !self.at(Tok::RBrace) && !self.at(Tok::Eof) {
            let vstart = self.cur().span;
            let vname = self.expect(Tok::Ident, "variant name")?.text;
            let ty = if self.eat(Tok::LParen) {
                let t = self.parse_type()?;
                self.expect(Tok::RParen, ")");
                Some(t)
            } else {
                None
            };
            variants.push(EnumVariant { name: vname, ty, span: vstart });
            if !self.eat(Tok::Comma) {
                break;
            }
        }
        self.expect(Tok::RBrace, "}");
        Some(Item::Enum(EnumDecl { name, variants, span: start }))
    }

    fn parse_trait(&mut self, start: Span) -> Option<Item> {
        self.advance();
        let name = self.expect(Tok::Ident, "trait name")?.text;
        let mut methods = Vec::new();
        self.expect(Tok::LBrace, "{");
        while !self.at(Tok::RBrace) && !self.at(Tok::Eof) {
            if let Some(Item::Fn(f)) = self.parse_fn(self.cur().span, false, false) {
                methods.push(f);
            } else {
                self.advance();
            }
        }
        self.expect(Tok::RBrace, "}");
        Some(Item::Trait(TraitDecl { name, methods, span: start }))
    }

    fn parse_impl(&mut self, start: Span) -> Option<Item> {
        self.advance();
        let trait_name = if !self.at(Tok::Ident) {
            None
        } else {
            // Peek: `impl Trait for Type` vs `impl Type`
            if self.peek_kind(1) == Tok::For {
                let t = self.advance().text;
                self.advance(); // for
                Some(t)
            } else {
                None
            }
        };
        let self_ty = self.expect(Tok::Ident, "implemented type")?.text;
        let mut methods = Vec::new();
        self.expect(Tok::LBrace, "{");
        while !self.at(Tok::RBrace) && !self.at(Tok::Eof) {
            if let Some(Item::Fn(f)) = self.parse_fn(self.cur().span, false, false) {
                methods.push(f);
            } else {
                self.advance();
            }
        }
        self.expect(Tok::RBrace, "}");
        Some(Item::Impl(ImplDecl { trait_name, self_ty, methods, span: start }))
    }

    fn parse_type(&mut self) -> Option<TypeExpr> {
        if !self.at(Tok::Ident) {
            self.error("E1001", "expected a type name");
            return None;
        }
        let start = self.cur().span;
        let name = self.advance().text;
        if self.eat(Tok::Lt) {
            match name.as_str() {
                "array" => {
                    let inner = self.parse_type()?;
                    self.expect(Tok::Gt, ">");
                    Some(TypeExpr::Array(Box::new(inner), start))
                }
                "set" => {
                    let inner = self.parse_type()?;
                    self.expect(Tok::Gt, ">");
                    Some(TypeExpr::Set(Box::new(inner), start))
                }
                "option" => {
                    let inner = self.parse_type()?;
                    self.expect(Tok::Gt, ">");
                    Some(TypeExpr::Option(Box::new(inner), start))
                }
                "map" => {
                    let k = self.parse_type()?;
                    self.expect(Tok::Comma, ",");
                    let v = self.parse_type()?;
                    self.expect(Tok::Gt, ">");
                    Some(TypeExpr::Map(Box::new(k), Box::new(v), start))
                }
                "result" => {
                    let ok = self.parse_type()?;
                    self.expect(Tok::Comma, ",");
                    let e = self.parse_type()?;
                    self.expect(Tok::Gt, ">");
                    Some(TypeExpr::Result(Box::new(ok), Box::new(e), start))
                }
                _ => {
                    let inner = self.parse_type()?;
                    self.expect(Tok::Gt, ">");
                    Some(TypeExpr::Array(Box::new(inner), start))
                }
            }
        } else if self.eat(Tok::LParen) {
            // tuple type
            let mut tys = Vec::new();
            if !self.at(Tok::RParen) {
                loop {
                    tys.push(self.parse_type()?);
                    if !self.eat(Tok::Comma) {
                        break;
                    }
                }
            }
            self.expect(Tok::RParen, ")");
            Some(TypeExpr::Tuple(tys, start))
        } else {
            Some(TypeExpr::Named(name, start))
        }
    }

    fn parse_block(&mut self) -> Option<Block> {
        let start = self.expect(Tok::LBrace, "{")?.span;
        let mut stmts = Vec::new();
        while !self.at(Tok::RBrace) && !self.at(Tok::Eof) {
            if let Some(s) = self.parse_stmt() {
                stmts.push(s);
            } else {
                self.advance();
            }
        }
        self.expect(Tok::RBrace, "}");
        Some(Block { stmts, span: start })
    }

    fn parse_stmt(&mut self) -> Option<Stmt> {
        let start = self.cur().span;
        match self.cur().kind {
            Tok::Let => {
                self.advance();
                let name = self.expect(Tok::Ident, "variable name")?.text;
                let ty = if self.eat(Tok::Colon) { self.parse_type() } else { None };
                let init = if self.eat(Tok::Assign) { self.parse_expr() } else { None };
                self.expect(Tok::Semicolon, ";");
                Some(Stmt::Let(LetDecl { name, ty, init, span: start }))
            }
            Tok::Mut => {
                self.advance();
                let name = self.expect(Tok::Ident, "variable name")?.text;
                self.expect(Tok::Colon, ":");
                let ty = self.parse_type()?;
                self.expect(Tok::Assign, "=");
                let init = self.parse_expr()?;
                self.expect(Tok::Semicolon, ";");
                Some(Stmt::Mut(MutDecl { name, ty, init, span: start }))
            }
            Tok::Const => {
                self.advance();
                let (name, ty, value, span) = self.parse_const_body(start)?;
                Some(Stmt::ItemConst(ConstDecl { name, ty, value, span }))
            }
            Tok::If => Some(Stmt::If(self.parse_if(start.clone())?)),
            Tok::While => {
                self.advance();
                let cond = self.parse_expr()?;
                let body = self.parse_block()?;
                Some(Stmt::While(WhileStmt { cond, body, span: start }))
            }
            Tok::For => {
                self.advance();
                let var = self.expect(Tok::Ident, "loop variable")?.text;
                self.expect(Tok::In, "in");
                let iter = self.parse_expr()?;
                let body = self.parse_block()?;
                Some(Stmt::For(ForStmt { var, iter, body, span: start }))
            }
            Tok::Match => Some(Stmt::Match(self.parse_match(start)?)),
            Tok::Return => {
                self.advance();
                let e = if self.at(Tok::Semicolon) { None } else { self.parse_expr() };
                self.expect(Tok::Semicolon, ";");
                Some(Stmt::Return(e, start))
            }
            Tok::LBrace => Some(Stmt::Block(self.parse_block()?)),
            _ => {
                // assignment or expression statement
                let e = self.parse_expr()?;
                if self.at(Tok::Assign) {
                    self.advance();
                    let value = self.parse_expr()?;
                    match e {
                        Expr::Ident(name, _) => {
                            self.expect(Tok::Semicolon, ";");
                            Some(Stmt::Assign(Assign { target: name, index: None, value }, start))
                        }
                        Expr::Index(base, idx, _) => {
                            if let Expr::Ident(name, _) = &*base {
                                self.expect(Tok::Semicolon, ";");
                                Some(Stmt::Assign(Assign { target: name.clone(), index: Some((idx, start)), value }, start))
                            } else {
                                self.error("E1001", "invalid assignment target");
                                None
                            }
                        }
                        _ => {
                            self.error("E1001", "invalid assignment target");
                            None
                        }
                    }
                } else {
                    self.expect(Tok::Semicolon, ";");
                    Some(Stmt::Expr(e, start))
                }
            }
        }
    }

    fn parse_if(&mut self, start: Span) -> Option<IfStmt> {
        self.advance(); // if
        let cond = self.parse_expr()?;
        let then_block = self.parse_block()?;
        let else_branch = if self.eat(Tok::Else) {
            if self.at(Tok::If) {
                Some(Box::new(ElseBranch::If(Box::new(self.parse_if(self.cur().span)?))))
            } else {
                Some(Box::new(ElseBranch::Block(self.parse_block()?)))
            }
        } else {
            None
        };
        Some(IfStmt { cond, then_block, else_branch, span: start })
    }

    fn parse_match(&mut self, start: Span) -> Option<MatchStmt> {
        self.advance(); // match
        let scrutinee = self.parse_expr()?;
        self.expect(Tok::LBrace, "{");
        let mut arms = Vec::new();
        while !self.at(Tok::RBrace) && !self.at(Tok::Eof) {
            let astart = self.cur().span;
            // patterns separated by `|`
            let mut patterns = Vec::new();
            loop {
                let p = match self.cur().kind {
                    Tok::Ident => { let t = self.advance(); Pattern::Ident(t.text, t.span) }
                    Tok::Int => { let t = self.advance(); Pattern::Int(t.int_value.unwrap_or(0), t.span) }
                    Tok::Str => { let t = self.advance(); Pattern::Str(t.text, t.span) }
                    _ => Pattern::Wildcard(self.cur().span),
                };
                patterns.push(p);
                if !self.eat(Tok::Pipe) { break; }
            }
            self.expect(Tok::Arrow, "=>");
            let body = if self.at(Tok::LBrace) { self.parse_block()? } else {
                let e = self.parse_expr()?;
                let bspan = e.span();
                Block { stmts: vec![Stmt::Expr(e, bspan)], span: bspan }
            };
            arms.push(MatchArm { patterns, body, span: astart });
            if !self.eat(Tok::Comma) { break; }
        }
        self.expect(Tok::RBrace, "}");
        Some(MatchStmt { scrutinee, arms, span: start })
    }

    fn parse_expr(&mut self) -> Option<Expr> {
        self.parse_binary(1)
    }

    // Precedence climbing. Returns None on parse error.
    fn parse_binary(&mut self, min_prec: u8) -> Option<Expr> {
        let mut lhs = self.parse_unary()?;
        loop {
            let (op, prec) = match self.cur().kind {
                Tok::OrOr => (Some(BinOp::Or), 1),
                Tok::AndAnd => (Some(BinOp::And), 2),
                Tok::Eq => (Some(BinOp::Eq), 3),
                Tok::Ne => (Some(BinOp::Ne), 3),
                Tok::Lt => (Some(BinOp::Lt), 4),
                Tok::Le => (Some(BinOp::Le), 4),
                Tok::Gt => (Some(BinOp::Gt), 4),
                Tok::Ge => (Some(BinOp::Ge), 4),
                Tok::Plus => (Some(BinOp::Add), 5),
                Tok::Minus => (Some(BinOp::Sub), 5),
                Tok::Star => (Some(BinOp::Mul), 6),
                Tok::Slash => (Some(BinOp::Div), 6),
                Tok::Percent => (Some(BinOp::Mod), 6),
                _ => (None, 0),
            };
            let (Some(op), op_prec) = (op, prec) else { break };
            if op_prec < min_prec { break; }
            let op_span = self.advance().span;
            let rhs = self.parse_binary(op_prec + 1)?;
            let span = Span::new(lhs.span().file, lhs.span().start, rhs.span().end);
            let _ = op_span;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs), span);
        }
        Some(lhs)
    }

    fn parse_unary(&mut self) -> Option<Expr> {
        let start = self.cur().span;
        match self.cur().kind {
            Tok::Minus => { self.advance(); let e = self.parse_unary()?; Some(Expr::Unary(UnOp::Neg, Box::new(e), start)) }
            Tok::Bang => { self.advance(); let e = self.parse_unary()?; Some(Expr::Unary(UnOp::Not, Box::new(e), start)) }
            _ => self.parse_postfix(),
        }
    }

    fn parse_postfix(&mut self) -> Option<Expr> {
        let mut e = self.parse_primary()?;
        loop {
            match self.cur().kind {
                Tok::Dot => {
                    self.advance();
                    let id = self.expect(Tok::Ident, "field name")?;
                    match e {
                        Expr::Ident(base, s) => {
                            let span = Span::new(s.file, s.start, id.span.end);
                            e = Expr::Path(vec![base, id.text], span);
                        }
                        Expr::Path(mut parts, s) => {
                            parts.push(id.text);
                            let span = Span::new(s.file, s.start, id.span.end);
                            e = Expr::Path(parts, span);
                        }
                        other => {
                            // field access on arbitrary expression: represent as Path tail
                            let s = other.span();
                            e = Expr::Call(Box::new(other), Vec::new(), s);
                        }
                    }
                }
                Tok::LParen => {
                    let callee = e;
                    let args = self.parse_call_args()?;
                    let s = callee.span();
                    e = Expr::Call(Box::new(callee), args, s);
                }
                Tok::LBracket => {
                    self.advance();
                    let idx = self.parse_expr()?;
                    let end = self.expect(Tok::RBracket, "]")?.span;
                    let s = e.span();
                    let span = Span::new(s.file, s.start, end.end);
                    e = Expr::Index(Box::new(e), Box::new(idx), span);
                }
                Tok::As => {
                    self.advance();
                    let ty = self.parse_type()?;
                    let s = e.span();
                    e = Expr::Cast(Box::new(e), ty, s);
                }
                _ => break,
            }
        }
        Some(e)
    }

    fn parse_call_args(&mut self) -> Option<Vec<Expr>> {
        self.expect(Tok::LParen, "(")?;
        let mut args = Vec::new();
        if !self.at(Tok::RParen) {
            loop {
                args.push(self.parse_expr()?);
                if !self.eat(Tok::Comma) { break; }
            }
        }
        self.expect(Tok::RParen, ")");
        Some(args)
    }

    fn parse_primary(&mut self) -> Option<Expr> {
        let t = self.cur().clone();
        match t.kind {
            Tok::Int => { self.advance(); Some(Expr::Int(t.int_value.unwrap_or(0), t.span)) }
            Tok::Dec => {
                self.advance();
                let v = t.text.replace('_', "");
                let f = t.text.parse::<f64>().unwrap_or(0.0);
                let _ = v;
                Some(Expr::Dec(f, t.span))
            }
            Tok::Str => { self.advance(); Some(Expr::Str(t.text, t.span)) }
            Tok::ByteStr => {
                self.advance();
                Some(Expr::Bytes(t.text.into_bytes(), t.span))
            }
            Tok::Char => { self.advance(); Some(Expr::Str(t.text, t.span)) }
            Tok::True => { self.advance(); Some(Expr::Bool(true, t.span)) }
            Tok::False => { self.advance(); Some(Expr::Bool(false, t.span)) }
            Tok::Ident => {
                self.advance();
                Some(Expr::Ident(t.text, t.span))
            }
            Tok::LParen => {
                self.advance();
                // tuple or grouped expr
                if self.at(Tok::RParen) {
                    self.advance();
                    Some(Expr::TupleLit(Vec::new(), t.span))
                } else {
                    let first = self.parse_expr()?;
                    if self.eat(Tok::Comma) {
                        let mut items = vec![first];
                        if !self.at(Tok::RParen) {
                            loop {
                                items.push(self.parse_expr()?);
                                if !self.eat(Tok::Comma) { break; }
                            }
                        }
                        self.expect(Tok::RParen, ")");
                        Some(Expr::TupleLit(items, t.span))
                    } else {
                        self.expect(Tok::RParen, ")");
                        Some(first)
                    }
                }
            }
            Tok::LBracket => {
                self.advance();
                let mut items = Vec::new();
                if !self.at(Tok::RBracket) {
                    loop {
                        items.push(self.parse_expr()?);
                        if !self.eat(Tok::Comma) { break; }
                    }
                }
                self.expect(Tok::RBracket, "]");
                Some(Expr::ArrayLit(items, t.span))
            }
            _ => {
                self.error("E1001", format!("expected an expression but found `{}`{}", t.text, explain(t.kind)));
                None
            }
        }
    }
}

fn explain(k: Tok) -> String {
    match k {
        Tok::LBrace => " (start of a block)".to_string(),
        Tok::Semicolon => " (end of statement)".to_string(),
        Tok::Assign => " (assignment)".to_string(),
        _ => String::new(),
    }
}
