//! The HEXA bootstrap compiler (front-end + x86-64 native back-end).
//!
//! Pipeline: lexer -> parser -> AST -> type check -> security analysis
//! -> lower to IR -> optimizer -> native codegen -> assembler -> linker.

pub mod diagnostics;
pub mod lexer;
pub mod ast;
pub mod parser;
pub mod types;
pub mod prelude;
pub mod check;
pub mod security;
pub mod ir;
pub mod lower;
pub mod optimizer;
pub mod codegen;
pub mod linker;
pub mod compiler;

#[cfg(test)]
mod tests {
    use crate::compiler::{compile, BuildMode, Options};
    use std::path::Path;
    use std::process::Command;

    #[test]
    fn hello_world_checks() {
        let src = "fn main() {\n    let message: plaintext = \"Hello HEXA\";\n    print(message);\n}\n";
        let opts = Options::default();
        let c = compile(src, Path::new("main.he"), &opts);
        assert!(c.diagnostics.has_errors() == false, "diagnostics: {}", c.diagnostics.render(&crate::diagnostics::SourceMap::default()));
        assert!(c.ok, "hello world must type check but failed");
    }

    #[test]
    fn secret_print_is_rejected() {
        let src = "fn main() {\n    let key: key = crypto.key.generate(256);\n    print(key);\n}\n";
        let mut opts = Options::default();
        opts.mode = BuildMode::Check;
        let c = compile(src, Path::new("bad.he"), &opts);
        assert!(!c.ok, "printing a key must be rejected");
        let text = c.diagnostics.render(&crate::diagnostics::SourceMap::default());
        assert!(text.contains("E2100"), "expected E2100 secret-print error, got: {}", text);
    }

    #[test]
    fn hardcoded_secret_rejected() {
        // Writing a literal directly into a secret-typed slot is a type error:
        // HEXA never silently treats a string literal as a credential.
        let src = "fn main() {\n    let pw: password = \"hunter2\";\n    print(secret.export(pw));\n}\n";
        let opts = Options::default();
        let c = compile(src, Path::new("sec.he"), &opts);
        assert!(!c.ok, "hardcoded secret must be rejected");
        let text = c.diagnostics.render(&crate::diagnostics::SourceMap::default());
        assert!(text.contains("E2003"), "expected E2003 for secret literal, got: {}", text);
    }

    #[test]
    fn insecure_rng_is_flagged() {
        let src = "fn main() {\n    random.seed(1234);\n}\n";
        let mut opts = Options::default();
        opts.mode = BuildMode::Check;
        let c = compile(src, Path::new("rng.he"), &opts);
        assert!(!c.ok, "seeded RNG must be rejected under standard policy");
        let text = c.diagnostics.render(&crate::diagnostics::SourceMap::default());
        assert!(text.contains("SEC003"), "expected SEC003, got: {}", text);
    }

    #[test]
    fn crypto_example_checks() {
        let src = r#"
fn main() {
    let message: plaintext = "Hello HEXA";
    let key = crypto.key.generate(256);
    let encrypted = crypto.encrypt.aes256_gcm(message, key);
    print(to_text(secret.export(key)));
}
"#;
        let mut opts = Options::default();
        opts.mode = BuildMode::Check;
        let c = compile(src, Path::new("crypto.he"), &opts);
        assert!(c.ok, "crypto example must type check: {}", c.diagnostics.render(&crate::diagnostics::SourceMap::default()));
    }

    #[test]
    fn native_build_runs() {
        let src = "fn main() {\n    let message: plaintext = \"Hello HEXA\";\n    print(message);\n}\n";
        let mut opts = Options::default();
        opts.mode = BuildMode::Build;
        opts.output = Some(std::path::PathBuf::from("/tmp/hexa_hello_test"));
        let c = compile(src, Path::new("main.he"), &opts);
        assert!(
            c.ok,
            "native build failed: {}",
            c.diagnostics.render(&crate::diagnostics::SourceMap::default())
        );
        let out = Command::new("/tmp/hexa_hello_test").output().expect("run binary");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "Hello HEXA\n");
        assert_eq!(out.status.code(), Some(0));
    }
}
