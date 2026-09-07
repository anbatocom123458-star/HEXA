//! hexa — the HEXA toolchain CLI.
//!
//! Commands: version, build, run, check, format, encrypt, decrypt,
//! inspect, disassemble, decompile, doctor, and the deliberately
//! refusals-only `key` subcommands (EKEY-004).

use hexa_compiler::compiler::{compile, BuildMode, Options};
use hexa_compiler::diagnostics::SourceMap;
use hexa_crypto::cipher::{self, KeySource, LayerPolicy};
use hexa_crypto::error::CryptoError;
use hexa_crypto::{aead, encoding, format, key, random};
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
use zeroize::Zeroizing;

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
        "help" | "--help" | "-h" | "" => cmd_help(),
        "--version" | "-V" => cmd_version(),
        other => {
            eprintln!("error: unknown command '{}' (see: hexa help)", other);
            2
        }
    };
    exit(code);
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

ENCRYPTION:
    hexa encrypt secret.txt [--algorithm aes256-gcm|chacha20-poly1305]
                             [--layers N] [--output out.hexa]
    hexa decrypt secret.hexa [--prompt-key | --key-file key.txt] [--output out]

A generated key is displayed EXACTLY ONCE and is never recoverable.
",
        VERSION
    );
    0
}

fn cmd_version() -> i32 {
    println!("HEXA compiler {} (language {})", VERSION, LANGUAGE_VERSION);
    println!(".hexa format version {}", HEXA_FORMAT_VERSION);
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
        eprintln!("error[E3001]: cannot read '{}': {}", path, e);
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
                eprintln!("error: unknown policy '{}' (standard|strict|paranoid)", other);
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
            eprintln!("error: {}", e);
            return 2;
        }
    };
    if c.files.len() != 1 {
        eprintln!("error: exactly one source file required");
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
        eprintln!("error: could not compile {}", path);
        return 1;
    }
    if mode == BuildMode::Check {
        return 0;
    }
    if let Some(exe) = &comp.executable {
        println!("built {}", exe.display());
    }
    0
}

fn cmd_run(args: &[String]) -> i32 {
    let c = match parse_common(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {}", e);
            return 2;
        }
    };
    if c.files.len() != 1 {
        eprintln!("error: exactly one source file required");
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
            eprintln!("error: failed to run {}: {}", exe.display(), e);
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
            eprintln!("error: {}", e);
            return 2;
        }
    };
    if c.files.len() != 1 {
        eprintln!("error: exactly one source file required");
        return 2;
    }
    let path = &c.files[0];
    let src = match load_source(path) {
        Ok(s) => s,
        Err(code) => return code,
    };
    match hexa_compiler::parser::format_source(&src) {
        Ok(formatted) => {
            if c.check_only {
                if formatted == src {
                    println!("{}: formatted", path);
                    0
                } else {
                    println!("{}: not formatted (run `hexa format {}`)", path, path);
                    1
                }
            } else {
                std::fs::write(path, &formatted).map_err(|e| {
                    eprintln!("error: cannot write {}: {}", path, e);
                    1
                })?;
                0
            }
        }
        Err(_) => return 1,
    }
    0
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
                        eprintln!("error: unknown algorithm (supported: aes256-gcm, chacha20-poly1305)");
                        return 2;
                    }
                }
            }
            "--layers" => {
                i += 1;
                match args.get(i).and_then(|s| s.parse::<u32>().ok()) {
                    Some(n) if n >= 1 => layers = n,
                    _ => {
                        eprintln!("error: --layers requires a positive integer");
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
                            let mut pw = String::from_utf8(bytes).map_err(|_| {
                                eprintln!("error: password file is not valid UTF-8");
                                2
                            })?;
                            while pw.ends_with('\n') || pw.ends_with('\r') {
                                pw.pop();
                            }
                            password = Some(pw);
                        }
                        Err(e) => {
                            eprintln!("error: cannot read password file: {}", e);
                            return 1;
                        }
                    },
                    None => {
                        eprintln!("error: --password-file requires a path");
                        return 2;
                    }
                }
            }
            "--yes" | "-y" => assume_yes = true,
            other => {
                if file.is_some() {
                    eprintln!("error: unexpected argument '{}'", other);
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
            eprintln!("error: no input file (usage: hexa encrypt <file> [options])");
            return 2;
        }
    };
    let plaintext = match std::fs::read(&file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: cannot read '{}': {}", file, e);
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
                        println!("Encryption completed.");
                        println!("wrote {} ({} bytes)", out_path, bytes.len());
                        0
                    }
                    Err(e) => {
                        eprintln!("error: cannot write {}: {}", out_path, e);
                        1
                    }
                },
                Err(e) => {
                    eprintln!("error: {}", e);
                    1
                }
            }
        }
        None => {
            // One-time key flow: generate, encrypt, display once, destroy.
            match cipher::encrypt_with_generated_key(&plaintext, layers, algorithm, &metadata, &policy) {
                Ok((bytes, mut handle)) => {
                    if let Err(e) = std::fs::write(&out_path, &bytes) {
                        eprintln!("error: cannot write {}: {}", out_path, e);
                        return 1;
                    }
                    println!("Encryption completed.");
                    println!();
                    println!("WARNING:");
                    println!("This key will be displayed ONE TIME ONLY.");
                    println!();
                    match handle.display_once() {
                        Ok(shown) => {
                            println!("HEXA KEY:");
                            println!("{}", shown);
                            println!();
                            println!("Save this key securely.");
                            println!("HEXA cannot recover, display, or reveal this key again.");
                        }
                        Err(e) => {
                            eprintln!("error: {}", e);
                            return 1;
                        }
                    }
                    0
                }
                Err(e) => {
                    eprintln!("error: {}", e);
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
    let mut password: Option<Zeroizing<String>> = None;
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
                    eprintln!("error: unexpected argument '{}'", other);
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
            eprintln!("error: no .hexa file (usage: hexa decrypt <file.hexa> [options])");
            return 2;
        }
    };
    let data = match std::fs::read(&file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: cannot read '{}': {}", file, e);
            return 1;
        }
    };

    // Probe the header to learn which key source this file expects.
    let wants_password = match format::parse(&data) {
        Ok(h) => h.kdf.is_some(),
        Err(e) => {
            eprintln!("error: {}", e);
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
                    eprintln!("error: {}", e);
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
                    eprintln!("error: {}", e);
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
                    println!("Decryption completed.");
                    println!("wrote {} ({} bytes)", out_path, plain.len());
                    0
                }
                Err(e) => {
                    eprintln!("error: cannot write {}: {}", out_path, e);
                    1
                }
            }
        }
        Err(CryptoError::Fail { code: "EKEY-001", detail }) => {
            eprintln!("error: EKEY-001: {}", detail);
            1
        }
        Err(_) => {
            // Wrong key, tampered file, truncation: one generic message.
            eprintln!("error: authentication failed (wrong key or corrupted file)");
            1
        }
    }
}

fn cmd_inspect(args: &[String]) -> i32 {
    let path = match args.iter().find(|a| !a.starts_with('-')) {
        Some(p) => p.clone(),
        None => {
            eprintln!("error: no .hexa file (usage: hexa inspect <file.hexa>)");
            return 2;
        }
    };
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: cannot read '{}': {}", path, e);
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
            eprintln!("error: {}", e);
            1
        }
    }
}

// ---------- disassemble / decompile ----------

fn cmd_disassemble(args: &[String]) -> i32 {
    let path = match args.iter().find(|a| !a.starts_with('-')) {
        Some(p) => p.clone(),
        None => {
            eprintln!("error: no binary (usage: hexa disassemble <binary>)");
            return 2;
        }
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read '{}': {}", path, e);
            return 1;
        }
    };
    match hexa_compiler::disasm::disassemble(&bytes) {
        Ok(text) => {
            print!("{}", text);
            0
        }
        Err(e) => {
            eprintln!("error: {}", e);
            1
        }
    }
}

fn cmd_decompile(args: &[String]) -> i32 {
    let path = match args.iter().find(|a| !a.starts_with('-')) {
        Some(p) => p.clone(),
        None => {
            eprintln!("error: no binary (usage: hexa decompile <binary>)");
            return 2;
        }
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read '{}': {}", path, e);
            return 1;
        }
    };
    match hexa_compiler::disasm::decompile(&bytes) {
        Ok(text) => {
            print!("{}", text);
            0
        }
        Err(e) => {
            eprintln!("error: {}", e);
            1
        }
    }
}

// ---------- doctor / key ----------

fn cmd_doctor() -> i32 {
    println!("HEXA doctor");
    println!("compiler version: {}", VERSION);
    println!("language version: {}", LANGUAGE_VERSION);
    println!(".hexa format:     v{}", HEXA_FORMAT_VERSION);
    let tools = hexa_compiler::linker::BuildTools::detect();
    println!("assembler:        {}", tools.assembler.as_deref().unwrap_or("NOT FOUND"));
    println!("linker:           {}", tools.linker.as_deref().unwrap_or("NOT FOUND"));
    let ok = tools.assembler.is_some() && tools.linker.is_some();
    if ok {
        println!("native builds:    READY");
    } else {
        println!("native builds:    UNAVAILABLE (install binutils: 'as' and 'ld')");
    }
    // CSPRNG check: derive a nonce twice; failure means the OS entropy source is broken.
    match random::nonce12() {
        Ok(_) => println!("CSPRNG:           OK"),
        Err(e) => {
            println!("CSPRNG:           FAILED ({})", e);
            return 1;
        }
    }
    if ok { 0 } else { 1 }
}

fn cmd_key(args: &[String]) -> i32 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("");
    match sub {
        "show" | "recover" | "reveal" | "export" | "backup" => {
            eprintln!("ERROR EKEY-004");
            eprintln!("Generated encryption keys are never recoverable by HEXA.");
            eprintln!("The key was displayed only once.");
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
                            eprintln!("error: {}", e);
                            return 1;
                        }
                    };
                    match gk.display_once() {
                        Ok(shown) => {
                            println!("WARNING: This key will be displayed ONE TIME ONLY.");
                            println!("HEXA KEY:");
                            println!("{}", shown);
                            println!("HEXA cannot recover, display, or reveal this key again.");
                            0
                        }
                        Err(e) => {
                            eprintln!("error: {}", e);
                            1
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: {}", e);
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
            eprintln!("error: unknown key subcommand '{}'", other);
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
            eprintln!("error: cannot read key from terminal: {}", e);
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
                    eprintln!("error: key file is not valid UTF-8");
                    return None;
                }
            };
            while s.ends_with('\n') || s.ends_with('\r') {
                s.pop();
            }
            Some(s)
        }
        Err(e) => {
            eprintln!("error: cannot read key file '{}': {}", path, e);
            None
        }
    }
}
