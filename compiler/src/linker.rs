//! Native linking: invoke the system assembler (`as`) and linker (`ld`) to
//! turn emitted assembly into a native ELF executable.
//!
//! The assembler/linker are backend tools (standard practice); the actual
//! program is genuine HEXA-emitted machine code, never transpiled source.

use std::fs;
use std::path::Path;
use std::process::Command;

pub struct BuildTools {
    pub asm: String,
    pub linker: String,
}

impl BuildTools {
    pub fn detect() -> Self {
        let asm = std::env::var("HEXA_AS").unwrap_or_else(|_| "as".into());
        let linker = std::env::var("HEXA_LD").unwrap_or_else(|_| "ld".into());
        BuildTools { asm, linker }
    }
}

fn run(cmd: &mut Command) -> Result<(), String> {
    let out = cmd.output().map_err(|e| format!("failed to run `{}`: {}", cmd.get_program().to_string_lossy(), e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(format!("{}{}", stdout, stderr));
    }
    Ok(())
}

/// Assemble `asm` into `object_tmp` then link to `out`.
pub fn assemble_and_link(tools: &BuildTools, asm: &str, out: &Path, keep_asm: bool) -> Result<(), String> {
    let dir = out.parent().unwrap_or(Path::new("."));
    let stem = out
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "program".to_string());
    let obj_path = dir.join(format!("{}.o", stem));
    let asm_src = if keep_asm {
        let p = dir.join(format!("{}.s", stem));
        fs::write(&p, asm).map_err(|e| e.to_string())?;
        p
    } else {
        let p = dir.join(format!(".{}.gen.s", stem));
        fs::write(&p, asm).map_err(|e| e.to_string())?;
        p
    };
    run(Command::new(&tools.asm).arg("-o").arg(&obj_path).arg(&asm_src))?;
    // Link as a dynamic executable: the program loads the shared HEXA
    // runtime library (libhexa_runtime.so) through dlopen/dlsym, which
    // requires libc (the entry handoff is __libc_start_main -> hexa_c_main).
    run(
        Command::new(&tools.linker)
            .arg("-o").arg(out)
            .arg(&obj_path)
            .arg("-e").arg("_start")
            .arg("--dynamic-linker").arg("/lib64/ld-linux-x86-64.so.2")
            .arg("-lc").arg("-ldl")
            .arg("-z").arg("now") // BIND_NOW: resolve PLT eagerly (no lazy GOT[2] trampoline)
            .arg("-L/usr/lib/x86_64-linux-gnu")
            .arg("-L/lib/x86_64-linux-gnu"),
    )?;
    // Also emit an RPATH pointing at the installation lib directory so the
    // runtime library is found both in-tree and after `hexa install`.
    let lib_dir = std::env::var("HEXA_RUNTIME_LIB").unwrap_or_else(|_| {
        // derive from the output path's directory's sibling lib/ when present
        out.parent()
            .and_then(|d| d.parent())
            .map(|p| p.join("lib"))
            .filter(|p| p.exists())
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default()
    });
    if !lib_dir.is_empty() {
        let _ = run(Command::new("patchelf")
            .arg("--set-rpath").arg(&lib_dir)
            .arg(out));
        // patchelf is optional; failure here is not a build failure because
        // LD_LIBRARY_PATH / installed paths also work.
    }
    if !keep_asm {
        let _ = fs::remove_file(&asm_src);
    }
    let _ = fs::remove_file(&obj_path);
    Ok(())
}
