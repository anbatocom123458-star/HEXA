//! The HEXA compiler driver: orchestrates the full pipeline
//! (source -> lexer -> parser -> AST -> type check -> security analysis
//! -> IR -> optimizer -> native codegen -> assembler -> linker).

use crate::check;
use crate::codegen;
use crate::diagnostics::{Diagnostics, SourceFile, SourceMap};
use crate::linker::{assemble_and_link, BuildTools};
use crate::lower;
use crate::optimizer;
use crate::parser;
use crate::security::analyze;
use crate::security::SecurityPolicy;
use std::path::Path;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BuildMode {
    #[default]
    Check,   // parse + type check + security analysis only
    Build,   // also lower, optimize, generate, link
}

#[derive(Clone, Debug)]
pub struct Options {
    pub mode: BuildMode,
    pub debug: bool,
    pub keep_asm: bool,
    pub output: Option<std::path::PathBuf>,
    pub policy: SecurityPolicy,
}

impl Default for Options {
    fn default() -> Self {
        Options { mode: BuildMode::Check, debug: false, keep_asm: false, output: None, policy: SecurityPolicy::standard() }
    }
}

pub struct Compilation {
    pub ok: bool,
    pub diagnostics: Diagnostics,
    pub executable: Option<std::path::PathBuf>,
}

impl Compilation {
    pub fn rendered(&self) -> String {
        self.diagnostics.render(&SourceMap::default())
    }
}

/// Compile one source file. `policy` is optional (defaults to standard).
pub fn compile(source_text: &str, source_path: &Path, opts: &Options) -> Compilation {
    let mut sm = crate::diagnostics::SourceMap::default();
    let file = SourceFile::new(source_path.to_path_buf(), source_text.to_string());
    let fid = sm.add(file);
    let mut diags = Diagnostics::default();

    let mut program = parser::parse(fid, source_text, &mut diags);
    if diags.has_errors() {
        return Compilation { ok: false, diagnostics: diags, executable: None };
    }
    // flat module model: imports currently contribute no symbols
    let _ = &mut program;

    check::check(&program, &[], &mut diags);
    let _ = &sm;
    crate::security::analyze(&program, &opts.policy, &mut diags, &[]);
    if diags.has_errors() {
        return Compilation { ok: false, diagnostics: diags, executable: None };
    }

    if opts.mode == BuildMode::Check {
        return Compilation { ok: true, diagnostics: diags, executable: None };
    }

    // lower -> IR -> optimize -> native codegen
    let module = match lower::lower(&program, &mut diags) {
        Some(m) => m,
        None => return Compilation { ok: false, diagnostics: diags, executable: None },
    };
    let _ = module;
    let mut module = module;
    optimizer::optimize_module(&mut module);

    let asm = codegen::emit_module(&module, opts.debug);
    let exe = opts
        .output
        .clone()
        .unwrap_or_else(|| source_path.with_extension(if cfg!(windows) { "exe" } else { "" }));
    let tools = BuildTools::detect();
    let exe = if exe.extension().is_none() && cfg!(not(windows)) {
        // `hexa build main.he` -> `main` in the same directory as source.
        exe
    } else {
        exe
    };
    match assemble_and_link(&tools, &asm, &exe, opts.keep_asm) {
        Ok(()) => Compilation { ok: true, diagnostics: diags, executable: Some(exe) },
        Err(err) => {
            diags.error("E3002", format!("native backend failed: {}", err));
            Compilation { ok: false, diagnostics: diags, executable: None }
        }
    }
}
