//! HEXA lexer: source text -> tokens.
//! Produces tokens with spans and E1xxx diagnostics for malformed input.
//! E1001 unexpected token, E1002 unterminated string, E1003 invalid
//! character, E1004 invalid numeric literal, E1006 invalid escape,
//! E1015 unterminated block comment.

use crate::diagnostics::{Diagnostic, Diagnostics, Span};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tok {
    Ident, Int, Dec, Str, ByteStr, Char,
    Fn, Let, Mut, Const, If, Else, For, While, Match, Return,
    Struct, Enum, Trait, Impl, Import, Module, Pub, Private,
    Async, Await, True, False, As,
    Plus, Minus, Star, Slash, Percent,
    Eq, Ne, Lt, Le, Gt, Ge, AndAnd, OrOr, Bang, Ampersand, Pipe,
    Question, Arrow, Assign,
    LParen, RParen, LBrace, RBrace, LBracket, RBracket,
    Comma, Semicolon, Colon, Dot, DotDot, DoubleColon, Hash, Eof,
}

pub const KEYWORD_MAP: &[(&str, Tok)] = &[
    ("fn", Tok::Fn), ("let", Tok::Let), ("mut", Tok::Mut), ("const", Tok::Const),
    ("if", Tok::If), ("else", Tok::Else), ("for", Tok::For), ("while", Tok::While),
    ("match", Tok::Match), ("return", Tok::Return), ("struct", Tok::Struct),
    ("enum", Tok::Enum), ("trait", Tok::Trait), ("impl", Tok::Impl),
    ("import", Tok::Import), ("module", Tok::Module), ("pub", Tok::Pub),
    ("private", Tok::Private), ("async", Tok::Async), ("await", Tok::Await),
    ("as", Tok::As), ("true", Tok::True), ("false", Tok::False),
];

#[derive(Clone, Debug)]
pub struct Token {
    pub kind: Tok,
    pub span: Span,
    pub text: String,
    pub int_value: Option<u64>,
}

pub struct Lexer<'a> {
    file_id: usize,
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
    diags: &'a mut Diagnostics,
}

impl<'a> Lexer<'a> {
    pub fn new(file_id: usize, src: &'a str, diags: &'a mut Diagnostics) -> Self {
        Lexer { file_id, src, bytes: src.as_bytes(), pos: 0, diags }
    }
    fn span(&self, start: usize) -> Span { Span::new(self.file_id, start, self.pos) }
    fn peek(&self) -> u8 { self.bytes.get(self.pos).copied().unwrap_or(0) }
    fn peek2(&self) -> u8 { self.bytes.get(self.pos + 1).copied().unwrap_or(0) }
    fn at_end(&self) -> bool { self.pos >= self.bytes.len() }
    fn bump(&mut self) -> u8 { let b = self.peek(); self.pos += 1; b }
    fn eat(&mut self, b: u8) -> bool {
        if self.peek() == b { self.pos += 1; true } else { false }
    }
    fn is_ident_start(b: u8) -> bool { b.is_ascii_alphabetic() || b == b'_' }
    fn is_ident_cont(b: u8) -> bool { b.is_ascii_alphanumeric() || b == b'_' }
    fn is_digit(b: u8) -> bool { b.is_ascii_digit() }

    fn skip_ws(&mut self) {
        loop {
            match self.peek() {
                p if p == b' ' || p == b'\t' || p == b'\r' || p == b'\n' => self.pos += 1,
                b'/' if self.peek2() == b'/' => {
                    while !self.at_end() && self.peek() != b'\n' { self.pos += 1; }
                }
                b'/' if self.peek2() == b'*' => {
                    let start = self.pos;
                    self.pos += 2;
                    let mut depth = 1;
                    while depth > 0 && !self.at_end() {
                        if self.peek() == b'/' && self.peek2() == b'*' { depth += 1; self.pos += 2; }
                        else if self.peek() == b'*' && self.peek2() == b'/' { depth -= 1; self.pos += 2; }
                        else { self.pos += 1; }
                    }
                    if depth > 0 {
                        self.diags.push(Diagnostic::error("E1015", "unterminated block comment").at(self.span(start)));
                    }
                }
                _ => break,
            }
        }
    }

    pub fn tokenize(&mut self) -> Vec<Token> {
        let mut out = Vec::new();
        loop {
            self.skip_ws();
            let start = self.pos;
            if self.at_end() {
                out.push(Token { kind: Tok::Eof, span: self.span(start), text: String::new(), int_value: None });
                break;
            }
            if let Some(t) = self.scan_token(start) { out.push(t); }
        }
        out
    }

    fn scan_token(&mut self, start: usize) -> Option<Token> {
        let b = self.peek();
        match b {
            b'0'..=b'9' => Some(self.scan_number(start)),
            b'"' => Some(self.scan_string(start)),
            b'\'' => Some(self.scan_char(start)),
            _ if Self::is_ident_start(b) => {
                if b == b'b' && self.peek2() == b'"' {
                    self.pos += 1;
                    return Some(self.scan_byte_string(start));
                }
                while !self.at_end() && Self::is_ident_cont(self.peek()) { self.pos += 1; }
                let word = self.src[start..self.pos].to_string();
                let kind = KEYWORD_MAP.iter().find(|(k, _)| **k == word).map(|(_, k)| *k).unwrap_or(Tok::Ident);
                Some(Token { kind, span: Span::new(self.file_id, start, self.pos), text: word, int_value: None })
            }
            _ => self.scan_punct(start),
        }
    }

    fn tok(&self, start: usize, kind: Tok) -> Token {
        Token { kind, span: Span::new(self.file_id, start, self.pos), text: String::new(), int_value: None }
    }

    fn scan_punct(&mut self, start: usize) -> Option<Token> {
        let b = self.peek();
        let one = |lex: &mut Lexer, kind: Tok| {
            lex.pos += 1;
            Token { kind, span: Span::new(lex.file_id, start, lex.pos), text: String::new(), int_value: None }
        };
        match b {
            b'(' => Some(one(self, Tok::LParen)),
            b')' => Some(one(self, Tok::RParen)),
            b'{' => Some(one(self, Tok::LBrace)),
            b'}' => Some(one(self, Tok::RBrace)),
            b'[' => Some(one(self, Tok::LBracket)),
            b']' => Some(one(self, Tok::RBracket)),
            b',' => Some(one(self, Tok::Comma)),
            b';' => Some(one(self, Tok::Semicolon)),
            b'?' => Some(one(self, Tok::Question)),
            b':' => {
                self.pos += 1;
                if self.eat(b':') { Some(self.tok(start, Tok::DoubleColon)) } else { Some(self.tok(start, Tok::Colon)) }
            }
            b'.' => {
                self.pos += 1;
                if self.eat(b'.') { Some(self.tok(start, Tok::DotDot)) } else { Some(self.tok(start, Tok::Dot)) }
            }
            b'+' => Some(one(self, Tok::Plus)),
            b'-' => {
                self.pos += 1;
                if self.eat(b'>') { Some(self.tok(start, Tok::Arrow)) } else { Some(self.tok(start, Tok::Minus)) }
            }
            b'*' => Some(one(self, Tok::Star)),
            b'/' => Some(one(self, Tok::Slash)),
            b'%' => Some(one(self, Tok::Percent)),
            b'=' => {
                self.pos += 1;
                if self.eat(b'=') { Some(self.tok(start, Tok::Eq)) } else { Some(self.tok(start, Tok::Assign)) }
            }
            b'!' => {
                self.pos += 1;
                if self.eat(b'=') { Some(self.tok(start, Tok::Ne)) } else { Some(self.tok(start, Tok::Bang)) }
            }
            b'<' => {
                self.pos += 1;
                if self.eat(b'=') { Some(self.tok(start, Tok::Le)) } else { Some(self.tok(start, Tok::Lt)) }
            }
            b'>' => {
                self.pos += 1;
                if self.eat(b'=') { Some(self.tok(start, Tok::Ge)) } else { Some(self.tok(start, Tok::Gt)) }
            }
            b'&' => {
                self.pos += 1;
                if self.eat(b'&') { Some(self.tok(start, Tok::AndAnd)) } else { Some(self.tok(start, Tok::Ampersand)) }
            }
            b'|' => {
                self.pos += 1;
                if self.eat(b'|') { Some(self.tok(start, Tok::OrOr)) } else { Some(self.tok(start, Tok::Pipe)) }
            }
            b'#' => {
                self.pos += 1;
                while !self.at_end() && (Self::is_ident_cont(self.peek()) || self.peek() == b'[' || self.peek() == b']') {
                    self.pos += 1;
                }
                Some(Token { kind: Tok::Hash, span: Span::new(self.file_id, start, self.pos), text: self.src[start+1..self.pos].to_string(), int_value: None })
            }
            _ => {
                self.pos += 1;
                let cstr = self.src[start..self.pos].to_string();
                self.diags.push(Diagnostic::error("E1003", format!("invalid character `{}` in source", cstr)).at(self.span(start)));
                None
            }
        }
    }

    fn scan_number(&mut self, start: usize) -> Token {
        if self.peek() == b'0' && (self.peek2() == b'x' || self.peek2() == b'X') {
            self.pos += 2;
            let hstart = self.pos;
            while !self.at_end() && (self.peek().is_ascii_hexdigit() || self.peek() == b'_') { self.pos += 1; }
            if self.pos == hstart {
                self.diags.push(Diagnostic::error("E1004", "invalid hexadecimal literal").at(self.span(start)));
            }
            let digits: String = self.src[hstart..self.pos].chars().filter(|c| *c != '_').collect();
            let val = u64::from_str_radix(&digits, 16).unwrap_or(0);
            return Token { kind: Tok::Int, span: Span::new(self.file_id, start, self.pos), text: self.src[start..self.pos].to_string(), int_value: Some(val) };
        }
        if self.peek() == b'0' && (self.peek2() == b'b' || self.peek2() == b'B') {
            self.pos += 2;
            let bstart = self.pos;
            while !self.at_end() && (self.peek() == b'0' || self.peek() == b'1' || self.peek() == b'_') { self.pos += 1; }
            let digits: String = self.src[bstart..self.pos].chars().filter(|c| *c != '_').collect();
            let val = u64::from_str_radix(&digits, 2).unwrap_or(0);
            return Token { kind: Tok::Int, span: Span::new(self.file_id, start, self.pos), text: self.src[start..self.pos].to_string(), int_value: Some(val) };
        }
        let mut is_dec = false;
        while !self.at_end() && (Self::is_digit(self.peek()) || self.peek() == b'_') { self.pos += 1; }
        if self.peek() == b'.' && self.peek2().is_ascii_digit() {
            is_dec = true;
            self.pos += 1;
            while !self.at_end() && (Self::is_digit(self.peek()) || self.peek() == b'_') { self.pos += 1; }
        }
        if is_dec {
            Token { kind: Tok::Dec, span: Span::new(self.file_id, start, self.pos), text: self.src[start..self.pos].to_string(), int_value: None }
        } else {
            let digits: String = self.src[start..self.pos].chars().filter(|c| *c != '_').collect();
            let val = digits.parse::<u64>().unwrap_or(0);
            Token { kind: Tok::Int, span: Span::new(self.file_id, start, self.pos), text: self.src[start..self.pos].to_string(), int_value: Some(val) }
        }
    }

    fn scan_escape(&mut self, start: usize) -> char {
        let c = self.bump();
        match c {
            b'n' => '\n',
            b't' => '\t',
            b'r' => '\r',
            b'\\' => '\\',
            b'"' => '"',
            b'\'' => '\'',
            b'0' => '\0',
            b'x' => {
                let hi = self.bump();
                let lo = self.bump();
                let s = std::str::from_utf8(&[hi, lo]).unwrap_or("");
                match u8::from_str_radix(s, 16) {
                    Ok(v) => v as char,
                    Err(_) => { self.diags.push(Diagnostic::error("E1006", "invalid \\x escape").at(self.span(start))); '\u{FFFD}' }
                }
            }
            b'u' => {
                if self.eat(b'{') {
                    let mut hex = String::new();
                    while !self.at_end() && self.peek() != b'}' { hex.push(self.bump() as char); }
                    self.eat(b'}');
                    match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                        Some(ch) => ch,
                        None => { self.diags.push(Diagnostic::error("E1006", "invalid \\u escape").at(self.span(start))); '\u{FFFD}' }
                    }
                } else {
                    self.diags.push(Diagnostic::error("E1006", "expected `{` after \\u").at(self.span(start)));
                    '\u{FFFD}'
                }
            }
            _ => {
                self.diags.push(Diagnostic::error("E1006", format!("invalid escape sequence `\\{}`", c as char)).at(self.span(start)));
                c as char
            }
        }
    }

    fn scan_string(&mut self, start: usize) -> Token {
        self.pos += 1;
        let mut value = String::new();
        loop {
            if self.at_end() {
                self.diags.push(Diagnostic::error("E1002", "unterminated string literal").at(self.span(start)));
                break;
            }
            let c = self.bump();
            match c {
                b'"' => break,
                b'\\' => value.push(self.scan_escape(start)),
                b'\n' => { self.diags.push(Diagnostic::error("E1002", "unterminated string literal (newline)").at(self.span(start))); break; }
                _ => value.push(c as char),
            }
        }
        Token { kind: Tok::Str, span: Span::new(self.file_id, start, self.pos), text: value, int_value: None }
    }

    fn scan_byte_string(&mut self, start: usize) -> Token {
        self.pos += 1;
        let mut value = String::new();
        loop {
            if self.at_end() {
                self.diags.push(Diagnostic::error("E1002", "unterminated byte string literal").at(self.span(start)));
                break;
            }
            let c = self.bump();
            match c {
                b'"' => break,
                b'\\' => value.push(self.scan_escape(start)),
                b'\n' => { self.diags.push(Diagnostic::error("E1002", "unterminated byte string literal (newline)").at(self.span(start))); break; }
                _ => value.push(c as char),
            }
        }
        Token { kind: Tok::ByteStr, span: Span::new(self.file_id, start, self.pos), text: value, int_value: None }
    }

    fn scan_char(&mut self, start: usize) -> Token {
        self.pos += 1;
        let ch = if self.peek() == b'\\' {
            self.pos += 1;
            self.scan_escape(start)
        } else if self.at_end() || self.peek() == b'\'' {
            self.diags.push(Diagnostic::error("E1002", "empty character literal").at(self.span(start)));
            '\u{FFFD}'
        } else {
            self.bump() as char
        };
        if !self.eat(b'\'') {
            self.diags.push(Diagnostic::error("E1002", "unterminated character literal").at(self.span(start)));
        }
        Token { kind: Tok::Char, span: Span::new(self.file_id, start, self.pos), text: ch.to_string(), int_value: None }
    }
}
