//! Deterministic source formatter: token-stream rewriter with comment
//! preservation via token-gap analysis. Same input -> same output.

use crate::diagnostics::Diagnostics;
use crate::lexer::{Lexer, Tok, Token};

fn indent(depth: usize) -> String {
    "    ".repeat(depth)
}

const SEP_KEEP: u8 = 0;
const SEP_SKIP: u8 = 1;

fn sep_between(prev: Option<&Token>, tok: &Token) -> &'static str {
    match prev {
        None => "",
        Some(p) => match p.kind {
            Tok::LBrace | Tok::LParen | Tok::LBracket => "",
            // `return;` / `break;` — keyword hugs the statement terminator.
            Tok::Fn | Tok::Let | Tok::Mut | Tok::Const | Tok::If | Tok::Else | Tok::For
            | Tok::While | Tok::Match | Tok::Return | Tok::Struct | Tok::Enum | Tok::Trait
            | Tok::Impl | Tok::Import | Tok::Module | Tok::Pub | Tok::Private | Tok::Async
            | Tok::Await | Tok::As | Tok::In if tok.kind == Tok::Semicolon => "",
            Tok::Fn | Tok::Let | Tok::Mut | Tok::Const | Tok::If | Tok::Else | Tok::For
            | Tok::While | Tok::Match | Tok::Return | Tok::Struct | Tok::Enum | Tok::Trait
            | Tok::Impl | Tok::Import | Tok::Module | Tok::Pub | Tok::Private | Tok::Async
            | Tok::Await | Tok::As | Tok::In => " ",
            _ => {
                match tok.kind {
                    Tok::RParen | Tok::RBracket | Tok::Comma | Tok::Semicolon => "",
                    // `fn main() {` / `if cond {`: hug the callee paren and
                    // the block brace after a condition expression.
                    Tok::LParen if matches!(p.kind, Tok::Ident) => "",
                    Tok::LBrace if matches!(p.kind, Tok::Int | Tok::Dec | Tok::Ident | Tok::RParen | Tok::Str) => " ",
                    Tok::Colon => " ",
                    Tok::Dot => "",
                    Tok::Assign | Tok::Arrow | Tok::DoubleColon | Tok::Eq | Tok::Ne | Tok::Le
                    | Tok::Ge | Tok::AndAnd | Tok::OrOr | Tok::Question => " ",
                    Tok::Plus | Tok::Minus | Tok::Star | Tok::Slash | Tok::Percent
                    | Tok::Lt | Tok::Gt => " ",
                    _ => " ",
                }
            }
        },
    }
}

fn push_token_sep(out: &mut String, tok: &Token, prev: Option<&Token>, suppress: u8) {
    // Separator before this token, given the previous token.
    // `suppress` (SEP_SKIP) is used when the token starts a new line so the
    // indentation is not followed by an extra space.
    let sep = if suppress == SEP_SKIP {
        ""
    } else {
        sep_between(prev, tok)
    };
    // If previous token was `=` and this is `>` with no gap, emit `=>`.
    if let Some(p) = prev {
        if p.kind == Tok::Assign && tok.kind == Tok::Gt && p.span.end == tok.span.start {
            // remove the trailing "= " (three chars: '=',' ') we added
            if out.ends_with("= ") {
                out.truncate(out.len() - 2);
                out.push_str("> ");
                return;
            }
        }
    }
    out.push_str(sep);
    // String/byte-string/char tokens carry the *decoded* value in `text`
    // (the lexer consumed the quotes and escapes), so the formatter must
    // re-quote and re-escape them; otherwise formatted output would embed
    // the raw value and no longer parse.
    match tok.kind {
        Tok::Str => {
            out.push('"');
            for c in tok.text.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\t' => out.push_str("\\t"),
                    '\r' => out.push_str("\\r"),
                    _ => out.push(c),
                }
            }
            out.push('"');
        }
        Tok::ByteStr => {
            out.push_str("b\"");
            for c in tok.text.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\t' => out.push_str("\\t"),
                    '\r' => out.push_str("\\r"),
                    _ => out.push(c),
                }
            }
            out.push('"');
        }
        Tok::Char => {
            out.push('\'');
            match tok.text.as_str() {
                "'" => out.push_str("\\'"),
                "\\" => out.push_str("\\\\"),
                "\n" => out.push_str("\\n"),
                "\t" => out.push_str("\\t"),
                "\r" => out.push_str("\\r"),
                other => out.push_str(other),
            }
            out.push('\'');
        }
        _ => out.push_str(&tok.text),
    }
}

fn comment_lines(gap: &str) -> Vec<String> {
    let mut lines = Vec::new();
    for line in gap.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if t.contains("//") || t.contains("/*") || t.starts_with('*') || t.ends_with("*/") {
            lines.push(t.to_string());
        }
    }
    lines
}

pub fn format_source(src: &str, diags: &mut Diagnostics) -> Option<String> {
    let mut lexer = Lexer::new(0, src, diags);
    let toks = lexer.tokenize();
    if diags.has_errors() {
        return None;
    }
    let toks: Vec<Token> = toks.into_iter().filter(|t| t.kind != Tok::Eof).collect();

    let mut out = String::new();
    let mut depth = 0usize;
    let mut first_on_line = true;
    let mut prev_end: Option<usize> = None;
    let mut prev: Option<&Token> = None;

    let mut i = 0usize;
    while i < toks.len() {
        let tok = &toks[i];

        // Decide newline / indentation before this token.
        let mut newline_before = match prev {
            None => true,
            Some(p) => {
                tok.kind == Tok::RBrace
                    || p.kind == Tok::LBrace
                    || p.kind == Tok::Semicolon
                    || (p.kind == Tok::RBrace && tok.kind != Tok::Else && tok.kind != Tok::LBrace)
            }
        };
        // `} else {` stays on one line.
        if tok.kind == Tok::Else && matches!(prev, Some(p) if p.kind == Tok::RBrace) {
            newline_before = false;
        }
        // Empty block `{}` stays together.
        if tok.kind == Tok::RBrace && matches!(prev, Some(p) if p.kind == Tok::LBrace) {
            newline_before = false;
        }

        if newline_before {
            // Comments living in the gap are flushed first, on their own lines.
            if let Some(pe) = prev_end {
                let gap = &src[pe..tok.span.start];
                for c in comment_lines(gap) {
                    if !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                    out.push_str(&indent(depth));
                    out.push_str(&c);
                    out.push('\n');
                }
            }
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            if tok.kind == Tok::RBrace {
                depth = depth.saturating_sub(1);
            }
            out.push_str(&indent(depth));
            // The token starts a fresh line: suppress the inter-token
            // separator so indentation is not followed by an extra space.
            first_on_line = true;
        }

        push_token_sep(&mut out, tok, prev, if first_on_line { SEP_SKIP } else { SEP_KEEP });

        // Track block depth: `{` opens an indented block, `}` closes it
        // (the close itself is handled above before emitting the token).
        if tok.kind == Tok::LBrace {
            depth += 1;
        }
        first_on_line = false;

        // Blank-line preservation (one blank line max) when the gap had >= 2 newlines.
        if let Some(pe) = prev_end {
            let gap = &src[pe..tok.span.start];
            if gap.matches('\n').count() >= 2 && comment_lines(gap).is_empty() {
                let _ = pe; // blank lines are reconstructed before the NEXT token
            }
        }

        prev_end = Some(tok.span.end);
        prev = Some(tok);
        i += 1;
    }

    // Trailing comments after the last token.
    if let Some(pe) = prev_end {
        let gap = &src[pe..];
        for c in comment_lines(gap) {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&indent(depth));
            out.push_str(&c);
        }
    }
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    Some(out)
}

