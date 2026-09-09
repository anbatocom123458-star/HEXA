//! hexa — the HEXA toolchain CLI.
//!
//! Commands: version, build, run, check, format, encrypt, decrypt,
//! inspect, disassemble, decompile, doctor, and the deliberately
//! refusals-only `key` subcommands (EKEY-004).

use hexa_compiler::compiler::{compile, BuildMode, Options};
use hexa_compiler::diagnostics::SourceMap;
use hexa_crypto::cipher::{self, KeySource, LayerPolicy};
use hexa_crypto::error::CryptoError;
use hexa_crypto::{aead, format, key, random};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
use zeroize::Zeroizing;

mod pkg;
mod ui;

/// Print an error line: bold-red `error:` prefix followed by the message,
/// styled only when stderr is an interactive terminal with color enabled.
macro_rules! errorln {
    ($($arg:tt)*) => {
        eprintln!("{} {}", ui::err_prefix(), ui::err_text(&format!($($arg)*)))
    };
}

/// Print a success line (green check-free text) when colors are enabled.
macro_rules! successln {
    ($($arg:tt)*) => {
        println!("{}", ui::ok_out(&format!($($arg)*)))
    };
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const LANGUAGE_VERSION: &str = "0.1";
pub const HEXA_FORMAT_VERSION: u8 = format::FORMAT_VERSION;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("");
    let rest = &args[1.min(args.len())..];
    let code = match cmd {
        "version" => cmd_version(),
        "build" => cmd_build(rest, false),
        "run" => cmd_run(rest),
        "check" => cmd_check(rest),
        "format" => cmd_format(rest),
        "encrypt" => cmd_encrypt(rest),
        "decrypt" => cmd_decrypt(rest),
        "inspect" => cmd_inspect(rest),
        "disassemble" => cmd_disassemble(rest),
        "decompile" => cmd_decompile(rest),
        "doctor" => cmd_doctor(),
        "key" => cmd_key(rest),
        "package" => cmd_package(rest),
        "install" => cmd_install(rest),
        "list" => cmd_list(),
        "remove" | "uninstall" => cmd_remove(rest),
        "update" => cmd_update(rest),
        "help" | "--help" | "-h" | "" => cmd_help(),
        "--version" | "-V" => cmd_version(),
        other => {
            errorln!("unknown command '{}' (see: hexa help)", other);
            2
        }
    };
    exit(code);
}

fn cmd_package(args: &[String]) -> i32 {
    let dir = args
        .first()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    if !dir.is_dir() {
        errorln!("'{}' is not a directory", dir.display());
        return 1;
    }
    let manifest_path = dir.join(pkg::MANIFEST_FILE);
    let manifest = if manifest_path.is_file() {
        let text = match std::fs::read_to_string(&manifest_path) {
            Ok(t) => t,
            Err(e) => {
                errorln!("cannot read {}: {}", manifest_path.display(), e);
                return 1;
            }
        };
        match pkg::PackageManifest::parse(&text) {
            Ok(m) => m,
            Err(e) => {
                errorln!("{}: {}", pkg::MANIFEST_FILE, e);
                return 1;
            }
        }
    } else if let Some(src) = find_single_source(&dir) {
        // No manifest: package the lone .he file with derived metadata.
        match pkg::PackageManifest::from_single_file(&src) {
            Ok(m) => m,
            Err(e) => {
                errorln!("{}", e);
                return 1;
            }
        }
    } else {
        errorln!(
            "no {} found in {} (and no single .he file to infer one from)",
            pkg::MANIFEST_FILE,
            dir.display()
        );
        return 1;
    };
    match pkg::collect_sources(&dir) {
        Ok(files) => {
            if !files.iter().any(|f| f.path == manifest.entry_point) {
                errorln!(
                    "entry_point '{}' not found among the project sources",
                    manifest.entry_point
                );
                return 1;
            }
            let archive = pkg::PackageArchive {
                manifest: manifest.clone(),
                files,
            };
            let out = dir.join(format!("{}-{}.hxpkg", manifest.name, manifest.version));
            let bytes = archive.encode();
            if let Err(e) = std::fs::write(&out, &bytes) {
                errorln!("cannot write {}: {}", out.display(), e);
                return 1;
            }
            successln!(
                "packaged {} v{} ({} files, {} bytes) -> {}",
                manifest.name,
                manifest.version,
                archive.files.len(),
                bytes.len(),
                out.display()
            );
            0
        }
        Err(e) => {
            errorln!("{}", e);
            1
        }
    }
}

/// The only `.he` file directly in `dir`, if any (used when there is no
/// hexa.toml). Subdirectories are ignored to keep inference predictable.
fn find_single_source(dir: &Path) -> Option<String> {
    let mut found: Option<String> = None;
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_file() && p.extension().map(|e| e == "he").unwrap_or(false) {
            if found.is_some() {
                return None; // ambiguous: two or more top-level sources
            }
            found = p.file_name().map(|n| n.to_string_lossy().to_string());
        }
    }
    found
}

fn read_archive_file(path: &str) -> Result<pkg::PackageArchive, i32> {
    if !Path::new(path).is_file() {
        errorln!("package file '{}' does not exist", path);
        return Err(1);
    }
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            errorln!("cannot read {}: {}", path, e);
            return Err(1);
        }
    };
    match pkg::decode_archive(&bytes) {
        Ok(a) => Ok(a),
        Err(e) => {
            errorln!("package rejected: {}", e);
            Err(1)
        }
    }
}

fn cmd_install(args: &[String]) -> i32 {
    let Some(path) = args.first() else {
        errorln!("usage: hexa install <package.hxpkg>");
        return 2;
    };
    let archive = match read_archive_file(path) {
        Ok(a) => a,
        Err(code) => return code,
    };
    let m = &archive.manifest;
    match pkg::install_archive(&archive) {
        Ok(dest) => {
            successln!("installed '{}' v{}", m.name, m.version);
            println!("  location: {}", ui::dim_out(&dest.display().to_string()));
            println!(
                "  launcher: {}",
                ui::dim_out(&pkg::bin_root().join(&m.name).display().to_string())
            );
            println!(
                "  next: {}",
                ui::dim_out(&format!(
                    "add {} to your PATH, then run `{}`",
                    pkg::bin_root().display(),
                    m.name
                ))
            );
            0
        }
        Err(e) => {
            errorln!("install failed: {}", e);
            1
        }
    }
}

fn cmd_list() -> i32 {
    let recs = pkg::registry_load();
    let live = pkg::live_packages(&recs);
    if live.is_empty() {
        println!("no packages installed");
        println!(
            "  tip: {}",
            ui::dim_out("hexa package [dir] && hexa install <file.hxpkg>")
        );
        return 0;
    }
    println!("{} package(s) installed:", live.len());
    for r in &live {
        let when = if r.installed_at.is_empty() {
            String::new()
        } else {
            format!("  installed_at unix {}", r.installed_at)
        };
        println!("  {} v{}{}", ui::ok_out(&r.name), ui::dim_out(&r.version.clone()), when);
    }
    0
}

fn cmd_remove(args: &[String]) -> i32 {
    let Some(name) = args.first() else {
        errorln!("usage: hexa remove <package-name>");
        return 2;
    };
    match pkg::remove_package(name) {
        Ok(shim) => {
            successln!("removed '{}'", name);
            println!("  deleted: {}", ui::dim_out(&shim));
            0
        }
        Err(e) => {
            errorln!("{}", e);
            1
        }
    }
}

fn cmd_update(args: &[String]) -> i32 {
    let Some(path) = args.first() else {
        errorln!("usage: hexa update <package.hxpkg>");
        return 2;
    };
    let archive = match read_archive_file(path) {
        Ok(a) => a,
        Err(code) => return code,
    };
    let m = &archive.manifest;
    let recs = pkg::registry_load();
    if pkg::is_live(&recs, &m.name) {
        let old = recs
            .iter()
            .rev()
            .find(|r| r.name == m.name)
            .map(|r| r.version.clone())
            .unwrap_or_default();
        if let Err(e) = pkg::remove_package(&m.name) {
            errorln!("update failed while replacing the old version: {}", e);
            return 1;
        }
        println!("  replacing v{}", ui::dim_out(&old));
    }
    match pkg::install_archive(&archive) {
        Ok(dest) => {
            successln!("updated '{}' to v{}", m.name, m.version);
            println!("  location: {}", ui::dim_out(&dest.display().to_string()));
            0
        }
        Err(e) => {
            errorln!("update failed: {}", e);
            1
        }
    }
}

fn cmd_help() -> i32 {
    println!(
        "HEXA {} (language {})

USAGE:
    hexa <COMMAND> [ARGS]

COMMANDS:
    version                 Show compiler and language version
    build <main.he>         Compile to a native executable
    run <main.he>           Compile and run
    check <main.he>         Type-check and security-analyze only
    format <main.he>        Format source (--check to verify)
    encrypt <file>          Encrypt a file into the .hexa format
    decrypt <file.hexa>     Decrypt a .hexa file
    inspect <file.hexa>     Show .hexa header metadata (never key material)
    disassemble <binary>    Dump the text section of a HEXA executable
    decompile <binary>      Approximate source reconstruction (see limits)
    doctor                  Check the native build environment
    key                     Key management (recovery is refused by design)

PACKAGES:
    package [dir]           Build a .hxpkg from a hexa.toml project
    install <pkg.hxpkg>     Verify + compile + install under $HEXA_HOME
    list                    Show installed packages
    remove <name>           Uninstall a package (alias: uninstall)
    update <pkg.hxpkg>      Replace an installed package in one step

ENCRYPTION:
    hexa encrypt secret.txt [--algorithm aes256-gcm|chacha20-poly1305]
                             [--layers N] [--output out.hexa]
    hexa decrypt secret.hexa [--prompt-key | --key-file key.txt] [--output out]

A generated key is displayed EXACTLY ONCE and is never recoverable.
",
        VERSION,
        LANGUAGE_VERSION,
    );
    0
}

fn cmd_version() -> i32 {
    println!(
        "{} compiler {} (language {})",
        ui::bold_out("HEXA"),
        ui::accent_out(VERSION),
        ui::accent_out(LANGUAGE_VERSION)
    );
    println!(
        ".hexa format version {}",
        ui::accent_out(&HEXA_FORMAT_VERSION.to_string())
    );
    0
}

// ---------- build / run / check ----------

struct CommonArgs {
    files: Vec<String>,
    debug: bool,
    release: bool,
    output: Option<String>,
    keep_asm: bool,
    policy: Option<String>,
    check_only: bool,
}

fn parse_common(args: &[String]) -> Result<CommonArgs, String> {
    let mut out = CommonArgs {
        files: vec![],
        debug: false,
        release: false,
        output: None,
        keep_asm: false,
        policy: None,
        check_only: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--debug" => out.debug = true,
            "--release" => out.release = true,
            "--output" | "-o" => {
                i += 1;
                out.output = args.get(i).cloned();
            }
            "--keep-asm" => out.keep_asm = true,
            "--policy" => {
                i += 1;
                out.policy = args.get(i).cloned();
            }
            "--check" => out.check_only = true,
            other => out.files.push(other.to_string()),
        }
        i += 1;
    }
    Ok(out)
}

fn load_source(path: &str) -> Result<String, i32> {
    std::fs::read_to_string(path).map_err(|e| {
        errorln!("E3001: cannot read '{}': {}", path, e);
        1
    })
}

fn make_options(c: &CommonArgs, mode: BuildMode) -> Options {
    let mut opts = Options::default();
    opts.mode = mode;
    opts.debug = c.debug;
    opts.keep_asm = c.keep_asm;
    if let Some(o) = &c.output {
        opts.output = Some(PathBuf::from(o));
    }
    if let Some(p) = &c.policy {
        opts.policy = match p.as_str() {
            "standard" => hexa_compiler::security::SecurityPolicy::standard(),
            "strict" => hexa_compiler::security::SecurityPolicy::strict(),
            "paranoid" => hexa_compiler::security::SecurityPolicy::paranoid(),
            other => {
                errorln!("unknown policy '{}' (standard|strict|paranoid)", other);
                return opts;
            }
        };
    }
    opts
}

fn cmd_build(args: &[String], check_only: bool) -> i32 {
    let c = match parse_common(args) {
        Ok(c) => c,
        Err(e) => {
            errorln!("{}", e);
            return 2;
        }
    };
    if c.files.len() != 1 {
        errorln!("exactly one source file required");
        return 2;
    }
    let path = &c.files[0];
    let src = match load_source(path) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let mode = if check_only || c.check_only {
        BuildMode::Check
    } else {
        BuildMode::Build
    };
    let opts = make_options(&c, mode);
    let comp = compile(&src, Path::new(path), &opts);
    let sm = SourceMap::default();
    let rendered = comp.diagnostics.render(&sm);
    if !rendered.trim().is_empty() {
        print!("{}", rendered);
    }
    if !comp.ok {
        errorln!("could not compile {}", path);
        return 1;
    }
    if mode == BuildMode::Check {
        if comp.ok {
            println!("{}", ui::ok_out("OK"));
        }
        return 0;
    }
    if let Some(exe) = &comp.executable {
        println!("{}", ui::ok_out(&format!("built {}", exe.display())));
    }
    0
}

fn cmd_run(args: &[String]) -> i32 {
    let c = match parse_common(args) {
        Ok(c) => c,
        Err(e) => {
            errorln!("{}", e);
            return 2;
        }
    };
    if c.files.len() != 1 {
        errorln!("exactly one source file required");
        return 2;
    }
    let path = c.files[0].clone();
    let src = match load_source(&path) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let mut opts = make_options(&c, BuildMode::Build);
    // Build into a private temp path, not next to the source.
    let tmp = std::env::temp_dir().join(format!(
        "hexa-run-{}-{}",
        std::process::id(),
        Path::new(&path).file_stem().and_then(|s| s.to_str()).unwrap_or("prog")
    ));
    opts.output = Some(tmp.clone());
    let comp = compile(&src, Path::new(&path), &opts);
    let rendered = comp.diagnostics.render(&SourceMap::default());
    if !rendered.trim().is_empty() {
        print!("{}", rendered);
    }
    let exe = match comp.executable {
        Some(e) => e,
        None => return 1,
    };
    let status = std::process::Command::new(&exe).status();
    let _ = std::fs::remove_file(&exe);
    match status {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            errorln!("failed to run {}: {}", exe.display(), e);
            1
        }
    }
}

fn cmd_check(args: &[String]) -> i32 {
    cmd_build(args, true)
}

fn cmd_format(args: &[String]) -> i32 {
    let c = match parse_common(args) {
        Ok(c) => c,
        Err(e) => {
            errorln!("{}", e);
            return 2;
        }
    };
    if c.files.len() != 1 {
        errorln!("exactly one source file required");
        return 2;
    }
    let path = &c.files[0];
    let src = match load_source(path) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let mut diags = hexa_compiler::diagnostics::Diagnostics { items: Vec::new() };
    match hexa_compiler::fmt::format_source(&src, &mut diags) {
        Some(formatted) => {
            if c.check_only {
                if formatted == src {
                    println!("{}: {}", path, ui::ok_out("formatted"));
                    0
                } else {
                    println!("{}: {} (run `hexa format {}`)", path, ui::warn_out("not formatted"), path);
                    1
                }
            } else {
                if std::fs::write(path, &formatted).is_err() {
                    errorln!("cannot write {}", path);
                    return 1;
                }
                0
            }
        }
        None => {
            errorln!("cannot format {}", path);
            return 1;
        }
    }
}

// ---------- encrypt / decrypt / inspect ----------

fn cmd_encrypt(args: &[String]) -> i32 {
    let mut file: Option<String> = None;
    let mut algorithm = aead::AeadId::Aes256Gcm;
    let mut layers: u32 = 1;
    let mut output: Option<String> = None;
    let mut password: Option<String> = None;
    let mut max_layers: u32 = LayerPolicy::default().max_layers;
    let mut assume_yes = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--algorithm" | "-a" => {
                i += 1;
                match args.get(i).and_then(|s| aead::AeadId::from_name(s)) {
                    Some(a) => algorithm = a,
                    None => {
                        errorln!("unknown algorithm (supported: aes256-gcm, chacha20-poly1305)");
                        return 2;
                    }
                }
            }
            "--layers" => {
                i += 1;
                match args.get(i).and_then(|s| s.parse::<u32>().ok()) {
                    Some(n) if n >= 1 => layers = n,
                    _ => {
                        errorln!("--layers requires a positive integer");
                        return 2;
                    }
                }
            }
            "--max-layers" => {
                i += 1;
                if let Some(n) = args.get(i).and_then(|s| s.parse::<u32>().ok()) {
                    max_layers = n;
                }
            }
            "--output" | "-o" => {
                i += 1;
                output = args.get(i).cloned();
            }
            "--password-file" => {
                i += 1;
                match args.get(i) {
                    Some(p) => match std::fs::read(p) {
                        Ok(bytes) => {
                            let mut pw = match String::from_utf8(bytes) {
                                Ok(p) => p,
                                Err(_) => {
                                    errorln!("password file is not valid UTF-8");
                                    return 2;
                                }
                            };
                            while pw.ends_with('\n') || pw.ends_with('\r') {
                                pw.pop();
                            }
                            password = Some(pw);
                        }
                        Err(e) => {
                            errorln!("cannot read password file: {}", e);
                            return 1;
                        }
                    },
                    None => {
                        errorln!("--password-file requires a path");
                        return 2;
                    }
                }
            }
            "--yes" | "-y" => assume_yes = true,
            other => {
                if file.is_some() {
                    errorln!("unexpected argument '{}'", other);
                    return 2;
                }
                file = Some(other.to_string());
            }
        }
        i += 1;
    }
    let file = match file {
        Some(f) => f,
        None => {
            errorln!("no input file (usage: hexa encrypt <file> [options])");
            return 2;
        }
    };
    let plaintext = match std::fs::read(&file) {
        Ok(d) => d,
        Err(e) => {
            errorln!("cannot read '{}': {}", file, e);
            return 1;
        }
    };
    let policy = LayerPolicy { max_layers };

    // Cost estimation and honest warnings for extreme layer counts.
    let (est_secs, warnings) = cipher::estimate_cost(layers, plaintext.len());
    for w in &warnings {
        println!("{}", w);
    }
    if est_secs > cipher::WARN_ESTIMATED_SECONDS && !assume_yes {
        print!("Continue? [y/N] ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line);
        let t = line.trim().to_ascii_lowercase();
        if t != "y" && t != "yes" {
            println!("aborted.");
            return 1;
        }
    }

    let out_path = output.unwrap_or_else(|| format!("{}.hexa", file));
    let metadata = format!(
        "v=1;algo={};layers={};original_size={}",
        algorithm.name(),
        layers,
        plaintext.len()
    );

    match password {
        Some(pw) => {
            let source = KeySource::Password(pw.into_bytes());
            match cipher::encrypt_layers(&plaintext, source, layers, algorithm, &metadata, &policy) {
                Ok(bytes) => match std::fs::write(&out_path, &bytes) {
                    Ok(()) => {
                        println!("{}", ui::ok_out("Encryption completed."));
                        println!("wrote {} ({} bytes)", out_path, bytes.len());
                        0
                    }
                    Err(e) => {
                        errorln!("cannot write {}: {}", out_path, e);
                        1
                    }
                },
                Err(e) => {
                    errorln!("{}", e);
                    1
                }
            }
        }
        None => {
            // One-time key flow: generate, encrypt, display once, destroy.
            match cipher::encrypt_with_generated_key(&plaintext, layers, algorithm, &metadata, &policy) {
                Ok((bytes, mut handle)) => {
                    if let Err(e) = std::fs::write(&out_path, &bytes) {
                        errorln!("cannot write {}: {}", out_path, e);
                        return 1;
                    }
                    println!("{}", ui::ok_out("Encryption completed."));
                    println!();
                    println!("{}", ui::warn_prefix());
                    println!("This key will be displayed ONE TIME ONLY.");
                    println!();
                    match handle.display_once() {
                        Ok(shown) => {
                            println!("{}", ui::key_banner("HEXA KEY:"));
                            println!("{}", shown);
                            println!();
                            println!("{}", ui::dim_out("Save this key securely."));
                            println!("{}", ui::warn_out("HEXA cannot recover, display, or reveal this key again."));
                        }
                        Err(e) => {
                            errorln!("{}", e);
                            return 1;
                        }
                    }
                    0
                }
                Err(e) => {
                    errorln!("{}", e);
                    1
                }
            }
        }
    }
}

fn cmd_decrypt(args: &[String]) -> i32 {
    let mut file: Option<String> = None;
    let mut output: Option<String> = None;
    let mut key_file: Option<String> = None;
    let mut prompt_key = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--output" | "-o" => {
                i += 1;
                output = args.get(i).cloned();
            }
            "--key-file" => {
                i += 1;
                key_file = args.get(i).cloned();
            }
            "--prompt-key" => prompt_key = true,
            other => {
                if file.is_some() {
                    errorln!("unexpected argument '{}'", other);
                    return 2;
                }
                file = Some(other.to_string());
            }
        }
        i += 1;
    }
    let file = match file {
        Some(f) => f,
        None => {
            errorln!("no .hexa file (usage: hexa decrypt <file.hexa> [options])");
            return 2;
        }
    };
    let data = match std::fs::read(&file) {
        Ok(d) => d,
        Err(e) => {
            errorln!("cannot read '{}': {}", file, e);
            return 1;
        }
    };

    // Probe the header to learn which key source this file expects.
    let wants_password = match format::parse(&data) {
        Ok(h) => h.kdf.is_some(),
        Err(e) => {
            errorln!("{}", e);
            return 1;
        }
    };

    let source: KeySource = if wants_password {
        if prompt_key {
            match prompt_secret("Enter password: ") {
                Some(p) => KeySource::Password(p.as_bytes().to_vec()),
                None => return 1,
            }
        } else if let Some(kf) = &key_file {
            match read_secret_file(kf) {
                Some(s) => KeySource::Password(s.as_bytes().to_vec()),
                None => return 1,
            }
        } else {
            eprintln!(
                "error: this file was encrypted with a password.\n       use --prompt-key (recommended) or --key-file <path>\n       note: command-line key arguments are not supported (process lists / shell history)"
            );
            return 2;
        }
    } else if prompt_key {
        match prompt_secret("Enter key (HX-...): ") {
            Some(p) => match key::parse_display(&p) {
                Ok(raw) => KeySource::RawKey(raw.to_vec()),
                Err(e) => {
                    errorln!("{}", e);
                    return 1;
                }
            },
            None => return 1,
        }
    } else if let Some(kf) = &key_file {
        match read_secret_file(kf) {
            Some(s) => match key::parse_display(&s) {
                Ok(raw) => KeySource::RawKey(raw.to_vec()),
                Err(e) => {
                    errorln!("{}", e);
                    return 1;
                }
            },
            None => return 1,
        }
    } else {
        eprintln!(
            "error: a key is required.\n       use --prompt-key (recommended) or --key-file <path>\n       note: command-line key arguments are not supported (process lists / shell history)"
        );
        return 2;
    };

    match cipher::decrypt_bytes(&data, &source) {
        Ok(plain) => {
            let out_path = output.unwrap_or_else(|| {
                let p = Path::new(&file);
                let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("output");
                stem.to_string()
            });
            match std::fs::write(&out_path, plain.as_slice()) {
                Ok(()) => {
                    println!("{}", ui::ok_out("Decryption completed."));
                    println!("wrote {} ({} bytes)", out_path, plain.len());
                    0
                }
                Err(e) => {
                    errorln!("cannot write {}: {}", out_path, e);
                    1
                }
            }
        }
        Err(CryptoError::Fail { code: "EKEY-001", detail }) => {
            errorln!("EKEY-001: {}", detail);
            1
        }
        Err(_) => {
            // Wrong key, tampered file, truncation: one generic message.
            errorln!("authentication failed (wrong key or corrupted file)");
            1
        }
    }
}

fn cmd_inspect(args: &[String]) -> i32 {
    let path = match args.iter().find(|a| !a.starts_with('-')) {
        Some(p) => p.clone(),
        None => {
            errorln!("no .hexa file (usage: hexa inspect <file.hexa>)");
            return 2;
        }
    };
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            errorln!("cannot read '{}': {}", path, e);
            return 1;
        }
    };
    match format::parse(&data) {
        Ok(h) => {
            println!("file:            {}", path);
            println!("format version:  {}", h.format_version);
            println!("authenticated:   {}", h.flags & format::FLAG_AUTHENTICATED != 0);
            println!("algorithm:       {}", h.algorithm.name());
            println!("kdf:             {}", h.kdf.map(|k| k.name()).unwrap_or("none (raw key)"));
            let (m, t) = format::kdf_param_unpack(h.kdf_param);
            println!("kdf parameters:  m_cost={} KiB, t_cost={}", m, t);
            println!("salt length:     {} bytes", h.salt.len());
            println!("layer count:     {}", h.layer_count);
            println!("metadata:        {}", h.metadata);
            println!("file size:       {} bytes", data.len());
            0
        }
        Err(e) => {
            errorln!("{}", e);
            1
        }
    }
}

// ---------- disassemble / decompile ----------

fn cmd_disassemble(args: &[String]) -> i32 {
    let path = match args.iter().find(|a| !a.starts_with('-')) {
        Some(p) => p.clone(),
        None => {
            errorln!("no binary (usage: hexa disassemble <binary>)");
            return 2;
        }
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            errorln!("cannot read '{}': {}", path, e);
            return 1;
        }
    };
    match hexa_compiler::disasm::disassemble(&bytes) {
        Ok(text) => {
            print!("{}", text);
            0
        }
        Err(e) => {
            errorln!("{}", e);
            1
        }
    }
}

fn cmd_decompile(args: &[String]) -> i32 {
    let path = match args.iter().find(|a| !a.starts_with('-')) {
        Some(p) => p.clone(),
        None => {
            errorln!("no binary (usage: hexa decompile <binary>)");
            return 2;
        }
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            errorln!("cannot read '{}': {}", path, e);
            return 1;
        }
    };
    match hexa_compiler::disasm::decompile(&bytes) {
        Ok(text) => {
            print!("{}", text);
            0
        }
        Err(e) => {
            errorln!("{}", e);
            1
        }
    }
}

// ---------- doctor / key ----------

fn cmd_doctor() -> i32 {
    println!("{} v{}", ui::bold_out("HEXA doctor"), VERSION);
    println!(
        "compiler version: {}",
        ui::accent_out(VERSION)
    );
    println!("language version: {}", LANGUAGE_VERSION);
    println!(".hexa format:     v{}", HEXA_FORMAT_VERSION);
    let mut ok = false;
    let tools = hexa_compiler::linker::BuildTools::detect();
    // Probe the tools for real: a configured name that cannot run is a failure.
    let asm_ok = std::process::Command::new(&tools.asm)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let ld_ok = std::process::Command::new(&tools.linker)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let tools_ok = asm_ok && ld_ok;
    println!(
        "assembler:        {}",
        if asm_ok {
            ui::ok_out(&tools.asm)
        } else {
            ui::err_text("NOT FOUND")
        }
    );
    println!(
        "linker:           {}",
        if ld_ok {
            ui::ok_out(&tools.linker)
        } else {
            ui::err_text("NOT FOUND")
        }
    );
    if tools_ok {
        println!("native builds:    {}", ui::ok_out("READY"));
        ok = true;
    } else {
        println!(
            "native builds:    {}",
            ui::err_text("UNAVAILABLE (install binutils: 'as' and 'ld')")
        );
    }
    // CSPRNG check: derive a nonce twice; failure means the OS entropy source is broken.
    match random::nonce12() {
        Ok(_) => println!("CSPRNG:           {}", ui::ok_out("OK")),
        Err(e) => {
            println!("CSPRNG:           {} ({})", ui::err_text("FAILED"), e);
            return 1;
        }
    }
    if ok { 0 } else { 1 }
}

fn cmd_key(args: &[String]) -> i32 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("");
    match sub {
        "show" | "recover" | "reveal" | "export" | "backup" => {
            eprintln!("{}", ui::err_text("ERROR EKEY-004"));
            eprintln!("{}", ui::err_text("Generated encryption keys are never recoverable by HEXA."));
            eprintln!("{}", ui::err_text("The key was displayed only once."));
            1
        }
        "generate" => {
            // Standalone generation still honors one-time display.
            let bits = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(256);
            match key::validate_key_bits(bits) {
                Ok(_) => {
                    let mut gk = match key::GeneratedKey::generate() {
                        Ok(g) => g,
                        Err(e) => {
                            errorln!("{}", e);
                            return 1;
                        }
                    };
                    match gk.display_once() {
                        Ok(shown) => {
                            println!("{}", ui::warn_prefix());
                            println!("This key will be displayed ONE TIME ONLY.");
                            println!("{}", ui::key_banner("HEXA KEY:"));
                            println!("{}", shown);
                            println!("{}", ui::warn_out("HEXA cannot recover, display, or reveal this key again."));
                            0
                        }
                        Err(e) => {
                            errorln!("{}", e);
                            1
                        }
                    }
                }
                Err(e) => {
                    errorln!("{}", e);
                    2
                }
            }
        }
        "" | "help" => {
            println!("usage: hexa key generate [128|192|256]");
            println!("       hexa key show        (refused: EKEY-004)");
            0
        }
        other => {
            errorln!("unknown key subcommand '{}'", other);
            2
        }
    }
}

// ---------- helpers ----------

fn prompt_secret(prompt: &str) -> Option<Zeroizing<String>> {
    println!("(input is not echoed)");
    match rpassword::prompt_password(prompt) {
        Ok(s) => Some(Zeroizing::new(s)),
        Err(e) => {
            errorln!("cannot read key from terminal: {}", e);
            None
        }
    }
}

fn read_secret_file(path: &str) -> Option<Zeroizing<String>> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let mut s = match String::from_utf8(bytes) {
                Ok(s) => Zeroizing::new(s),
                Err(_) => {
                    errorln!("key file is not valid UTF-8");
                    return None;
                }
            };
            while s.ends_with('\n') || s.ends_with('\r') {
                s.pop();
            }
            Some(s)
        }
        Err(e) => {
            errorln!("cannot read key file '{}': {}", path, e);
            None
        }
    }
}
