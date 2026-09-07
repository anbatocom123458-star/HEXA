//! Diagnostics: spans, source maps, and structured errors/warnings.
//!
//! HEXA diagnostics carry a stable error code, a span (file/line/column),
//! a source snippet, an explanation, and an optional suggested fix.
//! Codes follow the spec's scheme: E1xxx lexer, E2xxx type system,
//! SECxxx security, STYLExxx lints.

use std::fmt;
use std::path::PathBuf;

/// A byte range within a single source file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    /// Offset of the first character of the span (bytes).
    pub start: usize,
    /// Offset one past the last character of the span (bytes).
    pub end: usize,
    /// Index into the source map of the owning file.
    pub file: usize,
}

impl Span {
    pub fn new(file: usize, start: usize, end: usize) -> Self {
        Span { start, end, file }
    }
}

/// One source file held by the compiler.
#[derive(Debug, Clone)]
pub struct SourceFile {
    pub path: PathBuf,
    pub text: String,
    /// Line start offsets (0-based byte offsets of each line's first char).
    pub line_starts: Vec<usize>,
}

impl SourceFile {
    pub fn new(path: PathBuf, text: String) -> Self {
        let mut line_starts = vec![0usize];
        for (i, b) in text.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push(i + 1);
            }
        }
        SourceFile { path, text, line_starts }
    }

    /// Compute 1-based (line, col) for a byte offset. Column is 1-based.
    pub fn line_col(&self, offset: usize) -> (usize, usize) {
        let line = match self.line_starts.binary_search(&offset) {
            Ok(l) => l,
            Err(i) => i.saturating_sub(1),
        };
        let line_start = self.line_starts[line];
        // Column is counted in characters (Unicode aware).
        let col = self.text[line_start..offset.min(self.text.len())].chars().count() + 1;
        (line + 1, col)
    }

    /// One line of source text, 0-based line index.
    pub fn line_text(&self, line0: usize) -> &str {
        let start = self.line_starts.get(line0).copied().unwrap_or(self.text.len());
        let end = self
            .line_starts
            .get(line0 + 1)
            .copied()
            .unwrap_or(self.text.len());
        self.text[start..end].trim_end_matches(['\n', '\r'])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
    Note,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Error => write!(f, "error"),
            Severity::Warning => write!(f, "warning"),
            Severity::Note => write!(f, "note"),
        }
    }
}

/// A structured diagnostic with all the information the spec requires.
#[derive(Clone, Debug)]
pub struct Diagnostic {
    pub severity: Severity,
    /// Stable error code, e.g. "E1001" or "SEC1002". `None` for notes.
    pub code: Option<String>,
    pub message: String,
    pub span: Option<Span>,
    pub hint: Option<String>,
}

impl Diagnostic {
    pub fn error(code: &str, message: impl Into<String>) -> Self {
        Diagnostic { severity: Severity::Error, code: Some(code.to_string()), message: message.into(), span: None, hint: None }
    }
    pub fn warning(code: &str, message: impl Into<String>) -> Self {
        Diagnostic { severity: Severity::Warning, code: Some(code.to_string()), message: message.into(), span: None, hint: None }
    }
    pub fn at(mut self, span: Span) -> Self {
        self.span = Some(span);
        self
    }
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
    pub fn note(message: impl Into<String>) -> Self {
        Diagnostic { severity: Severity::Note, code: None, message: message.into(), span: None, hint: None }
    }
/// The source map owns all files participating in a compilation.
#[derive(Default)]
pub struct SourceMap {
    pub files: Vec<SourceFile>,
}

impl SourceMap {
    pub fn add(&mut self, file: SourceFile) -> usize {
        self.files.push(file);
        self.files.len() - 1
    }

    pub fn get(&self, idx: usize) -> &SourceFile {
        &self.files[idx]
    }

    /// Format a span as `path:line:col`.
    pub fn location(&self, span: Span) -> String {
        if span.file >= self.files.len() {
            return "<unknown>".into();
        }
        let f = &self.files[span.file];
        let (line, col) = f.line_col(span.start);
        format!("{}:{}:{}", f.path.display(), line, col)
    }

    /// Render the snippet + caret for a span in classic compiler style.
    pub fn render(&self, span: Span) -> String {
        let f = match self.files.get(span.file) {
            Some(f) => f,
            None => return String::new(),
        };
        let (line, _) = f.line_col(span.start);
        let (scol, ecol) = if span.start == span.end {
            let (_, c) = f.line_col(span.start);
            (c, c + 1)
        } else {
            let (_, cs) = f.line_col(span.start);
            let (_, ce) = f.line_col(span.end.saturating_sub(1));
            (cs, ce + 1)
        };
        let src = f.line(line.saturating_sub(1));
        let width = ecol.saturating_sub(scol).max(1);
        let marker = format!("{}{}", " ".repeat(scol.saturating_sub(1)), "^".repeat(width));
        format!(
            " --> {}\n   |\n{:4} | {}\n   | {}",
            f.path.display(),
            line,
            src,
            marker
        )
    }
}

/// A collection of diagnostics produced by a compile run.
#[derive(Default)]
pub struct Diagnostics {
    pub items: Vec<Diagnostic>,
}

impl Diagnostics {
    pub fn push(&mut self, d: Diagnostic) {
        self.items.push(d);
    }
    pub fn error(&mut self, code: &str, message: impl Into<String>) {
        self.push(Diagnostic::error(code, message));
    }
    pub fn has_errors(&self) -> bool {
        self.items.iter().any(|d| d.severity == Severity::Error)
    }

    /// Render all diagnostics in a human-readable block.
    pub fn render(&self, sm: &SourceMap) -> String {
        let mut out = String::new();
        for d in &self.items {
            let code = d.code.as_deref().unwrap_or("");
            match d.span {
                Some(span) => {
                    out.push_str(&format!(
                        "{}[{}]: {}\n{}\n",
                        d.severity,
                        code,
                        d.message,
                        sm.render(span)
                    ));
                }
                None => {
                    out.push_str(&format!("{}[{}]: {}\n", d.severity, code, d.message));
                }
            }
            if let Some(hint) = &d.hint {
                out.push_str(&format!("  help: {}\n", hint));
            }
            out.push('\n');
        }
        out
    }
}
}