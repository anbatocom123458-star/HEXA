//! Package manager: `hexa.toml` manifests, `.hxpkg` archives, install/remove.
//!
//! Design rules (fail-closed):
//! - An archive is FULLY validated in memory before anything is written to
//!   disk: magic, format version, per-file SHA-256, whole-archive SHA-256.
//! - Paths inside an archive can never escape the install directory:
//!   absolute paths, `..` components, backslashes and NUL bytes are
//!   rejected at parse time.
//! - Resource limits (file count, file size, total size, manifest size)
//!   are enforced while reading so a hostile archive cannot exhaust
//!   memory or disk.
//! - Install is atomic in effect: everything is built in a staging
//!   directory first; if the native build fails, nothing is installed.
//!
//! Artifact layout (`.hxpkg`, format version 1, little-endian):
//!
//! ```text
//! "HXPKG"          4 bytes magic
//! version: u16     format version (1)
//! mlen:    u32     manifest (TOML) length in bytes
//! manifest         UTF-8 TOML: [package] name/version/entry_point/...
//! count:   u32     number of packaged files
//! for each file:   plen:u16, path (UTF-8, '/' separators),
//!                  flen:u64, content, sha256(content): 32 bytes
//! trailer          sha256 of everything above: 32 bytes
//! ```

use hexa_compiler::compiler::{compile, BuildMode, Options as BuildOptions};
use hexa_compiler::diagnostics::SourceMap;
use std::path::{Path, PathBuf};

pub const MAGIC: &[u8; 5] = b"HXPKG";
pub const FORMAT_VERSION: u16 = 1;

// Resource limits (fail-closed ceilings for untrusted archives).
pub const MAX_MANIFEST: u32 = 64 * 1024;
pub const MAX_FILES: u32 = 4096;
pub const MAX_FILE_SIZE: u64 = 64 * 1024 * 1024;
pub const MAX_TOTAL: u64 = 256 * 1024 * 1024;
pub const MAX_PATH_LEN: usize = 255;

pub const MANIFEST_FILE: &str = "hexa.toml";
pub const INSTALLED_MANIFEST: &str = "installed.json";

#[derive(Debug, Clone)]
pub struct PackageManifest {
    pub name: String,
    pub version: String,
    pub entry_point: String,
    pub description: String,
    pub license: String,
}

fn is_valid_name(name: &str) -> bool {
    // Safe for directory use and shell-free shims.
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

fn is_valid_version(v: &str) -> bool {
    // Semver-ish: MAJOR.MINOR.PATCH, numeric, no leading zeros ("01" is out).
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3
        && v.len() <= 32
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 10
                && p.chars().all(|c| c.is_ascii_digit())
                && !(p.len() > 1 && p.starts_with('0'))
        })
}

/// Reject anything that could escape or trick path handling.
fn is_safe_pkg_path(p: &str) -> bool {
    if p.is_empty() || p.len() > MAX_PATH_LEN {
        return false;
    }
    if p.starts_with('/') || p.contains('\\') || p.contains('\0') || p.contains(':') {
        return false;
    }
    p.split('/').all(|comp| {
        !comp.is_empty()
            && comp != "."
            && comp != ".."
            && !comp.starts_with('.')
            && !comp.ends_with('~')
    })
}

// __PART2__

impl PackageManifest {
    /// Parse and validate a manifest from TOML text.
    pub fn parse(text: &str) -> Result<PackageManifest, String> {
        let root: toml::Value =
            toml::from_str(text).map_err(|e| format!("manifest is not valid TOML: {}", e))?;
        let pkg = root
            .get("package")
            .and_then(|v| v.as_table())
            .ok_or("manifest must contain a [package] table")?;
        let getstr = |k: &str| {
            pkg.get(k)
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
        };
        let name = getstr("name").ok_or("[package] name is required")?;
        let version = getstr("version").ok_or("[package] version is required")?;
        let entry_point = getstr("entry_point").unwrap_or_else(|| "main.he".to_string());
        let description = getstr("description").unwrap_or_default();
        let license = getstr("license").unwrap_or_default();
        if !is_valid_name(&name) {
            return Err(format!(
                "invalid package name '{}': use lowercase letters, digits, '-' or '_' (max 64 chars)",
                name
            ));
        }
        if !is_valid_version(&version) {
            return Err(format!(
                "invalid version '{}': expected MAJOR.MINOR.PATCH (numeric)",
                version
            ));
        }
        if !is_safe_pkg_path(&entry_point) || !entry_point.ends_with(".he") {
            return Err(format!(
                "invalid entry_point '{}': must be a packaged .he path without '..' or absolute components",
                entry_point
            ));
        }
        if description.len() > 500 || license.len() > 100 {
            return Err("description/license metadata too long".to_string());
        }
        Ok(PackageManifest {
            name,
            version,
            entry_point,
            description,
            license,
        })
    }

    /// A manifest synthesized from a single source file
    /// (`hexa package tool.he` with no hexa.toml).
    pub fn from_single_file(path: &str) -> Result<PackageManifest, String> {
        let stem = Path::new(path)
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or("cannot derive a package name from this file")?;
        let name: String = stem
            .to_ascii_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        let name = name.trim_matches('-').to_string();
        let file_name = Path::new(path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("main.he")
            .to_string();
        Ok(PackageManifest {
            name: if name.is_empty() { "app".into() } else { name },
            version: "0.1.0".into(),
            entry_point: file_name,
            description: format!("Packaged from {}", path),
            license: String::new(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct PackagedFile {
    pub path: String,
    pub content: Vec<u8>,
}

#[derive(Debug)]
pub struct PackageArchive {
    pub manifest: PackageManifest,
    pub files: Vec<PackagedFile>,
}

impl PackageArchive {
    /// Serialize into the on-disk `.hxpkg` container (with checksums).
    pub fn encode(&self) -> Vec<u8> {
        let manifest_text = self.manifest_to_toml();
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&(manifest_text.len() as u32).to_le_bytes());
        out.extend_from_slice(manifest_text.as_bytes());
        out.extend_from_slice(&(self.files.len() as u32).to_le_bytes());
        for f in &self.files {
            out.extend_from_slice(&(f.path.len() as u16).to_le_bytes());
            out.extend_from_slice(f.path.as_bytes());
            out.extend_from_slice(&(f.content.len() as u64).to_le_bytes());
            out.extend_from_slice(&f.content);
            out.extend_from_slice(&hexa_crypto::hash::sha256(&f.content));
        }
        let trailer = hexa_crypto::hash::sha256(&out);
        out.extend_from_slice(&trailer);
        out
    }

    fn manifest_to_toml(&self) -> String {
        let m = &self.manifest;
        let mut s = String::from("[package]\n");
        s.push_str(&format!("name = \"{}\"\n", m.name));
        s.push_str(&format!("version = \"{}\"\n", m.version));
        s.push_str(&format!("entry_point = \"{}\"\n", m.entry_point));
        s.push_str(&format!("description = \"{}\"\n", m.description.replace('"', "'")));
        s.push_str(&format!("license = \"{}\"\n", m.license.replace('"', "'")));
        s
    }
}

/// Decode and FULLY validate an archive. Any inconsistency is an error;
/// nothing is ever partially trusted.
pub fn decode_archive(bytes: &[u8]) -> Result<PackageArchive, String> {
    const HEADER: usize = 5 + 2 + 4; // magic (5) + version (2) + manifest length (4)
    if bytes.len() < HEADER + 4 + 32 {
        return Err("not a HEXA package (too small)".to_string());
    }
    if &bytes[0..5] != MAGIC {
        return Err("not a HEXA package (bad magic)".to_string());
    }
    let version = u16::from_le_bytes([bytes[5], bytes[6]]);
    if version != FORMAT_VERSION {
        return Err(format!(
            "unsupported package format version {} (this tool supports {})",
            version, FORMAT_VERSION
        ));
    }
    let mlen = u32::from_le_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]) as usize;
    if mlen > MAX_MANIFEST as usize {
        return Err(format!("manifest too large ({} bytes)", mlen));
    }
    let mut off = HEADER;
    if bytes.len() < off + mlen + 4 + 32 {
        return Err("truncated package (manifest)".to_string());
    }
    let manifest_text = std::str::from_utf8(&bytes[off..off + mlen])
        .map_err(|_| "manifest is not valid UTF-8".to_string())?
        .to_string();
    off += mlen;
    let manifest = PackageManifest::parse(&manifest_text)?;

    let count = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
        as usize;
    off += 4;
    if count > MAX_FILES as usize {
        return Err(format!("too many files in package ({} > {})", count, MAX_FILES));
    }
    let body_end = bytes.len() - 32; // trailer
    let mut files: Vec<PackagedFile> = Vec::with_capacity(count.min(1024));
    let mut total: u64 = 0;
    for i in 0..count {
        if off + 2 > body_end {
            return Err(format!("truncated package (file {} header)", i));
        }
        let plen = u16::from_le_bytes([bytes[off], bytes[off + 1]]) as usize;
        off += 2;
        if off + plen + 8 > body_end {
            return Err(format!("truncated package (file {} path)", i));
        }
        let path = std::str::from_utf8(&bytes[off..off + plen])
            .map_err(|_| format!("file {} path is not valid UTF-8", i))?
            .to_string();
        off += plen;
        if !is_safe_pkg_path(&path) {
            return Err(format!(
                "unsafe path in package: {:?} (absolute paths, '..' and backslashes are not allowed)",
                path
            ));
        }
        let flen = u64::from_le_bytes([
            bytes[off],
            bytes[off + 1],
            bytes[off + 2],
            bytes[off + 3],
            bytes[off + 4],
            bytes[off + 5],
            bytes[off + 6],
            bytes[off + 7],
        ]);
        off += 8;
        if flen > MAX_FILE_SIZE {
            return Err(format!("file {} too large ({} bytes)", path, flen));
        }
        total = total.saturating_add(flen);
        if total > MAX_TOTAL {
            return Err(format!("package payload too large (> {} bytes)", MAX_TOTAL));
        }
        let flen = flen as usize;
        if off + flen + 32 > body_end {
            return Err(format!("truncated package (file {} content)", i));
        }
        let content = bytes[off..off + flen].to_vec();
        off += flen;
        let got = hexa_crypto::hash::sha256(&content);
        if got.as_slice() != &bytes[off..off + 32] {
            return Err(format!("checksum mismatch for '{}' (corrupted package)", path));
        }
        off += 32;
        files.push(PackagedFile { path, content });
    }
    if off != body_end {
        return Err("trailing garbage after file table".to_string());
    }
    let body_sum = hexa_crypto::hash::sha256(&bytes[..body_end]);
    if body_sum.as_slice() != &bytes[body_end..] {
        return Err("package integrity check failed (whole-file checksum)".to_string());
    }
    // Entry point must exist among the packaged files.
    if !files.iter().any(|f| f.path == manifest.entry_point) {
        return Err(format!(
            "entry_point '{}' is not part of the package",
            manifest.entry_point
        ));
    }
    Ok(PackageArchive { manifest, files })
}

/// `$HEXA_HOME` (default `~/.hexa`): the per-user install prefix.
pub fn hexa_home() -> PathBuf {
    if let Ok(h) = std::env::var("HEXA_HOME") {
        if !h.trim().is_empty() {
            return PathBuf::from(h);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    Path::new(&home).join(".hexa")
}

pub fn pkg_root() -> PathBuf {
    hexa_home().join("pkg")
}

pub fn bin_root() -> PathBuf {
    hexa_home().join("bin")
}

/// Collect `.he` sources from the project directory (recursive),
/// skipping VCS/build/hidden dirs. Every path is re-validated so a
/// hostile tree cannot inject traversal components.
pub fn collect_sources(dir: &Path) -> Result<Vec<PackagedFile>, String> {
    let mut files: Vec<PackagedFile> = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    let skip = |name: &str| {
        matches!(
            name,
            "target" | ".git" | "node_modules" | "dist" | "build" | "out"
        ) || name.starts_with('.')
            || name.ends_with(".hxpkg")
    };
    while let Some(d) = stack.pop() {
        let entries =
            std::fs::read_dir(&d).map_err(|e| format!("cannot read {}: {}", d.display(), e))?;
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let p = entry.path();
            let fname = entry.file_name().to_string_lossy().to_string();
            if skip(&fname) {
                continue;
            }
            if p.is_dir() {
                stack.push(p);
            } else if fname.ends_with(".he") {
                let rel = p
                    .strip_prefix(dir)
                    .map_err(|_| "unexpected source path".to_string())?
                    .to_string_lossy()
                    .replace('\\', "/");
                if !is_safe_pkg_path(&rel) {
                    return Err(format!("refusing to package unsafe path: {:?}", rel));
                }
                let content =
                    std::fs::read(&p).map_err(|e| format!("cannot read {}: {}", p.display(), e))?;
                if content.len() as u64 > MAX_FILE_SIZE {
                    return Err(format!("{} exceeds the per-file size limit", rel));
                }
                files.push(PackagedFile { path: rel, content });
            }
        }
    }
    if files.is_empty() {
        return Err("no .he source files found to package".to_string());
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

/// Build the packaged entry point natively inside a scratch dir.
/// Returns the path to the produced executable, or the failure reason.
/// Fail-closed: a package whose program does not compile must never be
/// installed.
fn build_entry(entry_fs_path: &Path, scratch: &Path) -> Result<PathBuf, String> {
    let src = std::fs::read_to_string(entry_fs_path)
        .map_err(|e| format!("cannot read {}: {}", entry_fs_path.display(), e))?;
    let mut opts = BuildOptions::default();
    opts.mode = BuildMode::Build;
    opts.output = Some(scratch.join("entry"));
    let comp = compile(&src, entry_fs_path, &opts);
    let rendered = comp.diagnostics.render(&SourceMap::default());
    if !rendered.trim().is_empty() {
        return Err(format!(
            "packaged program failed to compile:\n{}",
            rendered.trim_end()
        ));
    }
    match comp.executable {
        Some(e) => Ok(e),
        None => Err("packaged program failed to compile (no executable produced)".to_string()),
    }
}

#[derive(Debug, Clone)]
pub struct InstalledRecord {
    pub name: String,
    pub version: String,
    pub installed_at: String,
    pub entry_point: String,
    pub files: Vec<String>,
}

// Tiny JSON encode/decode for the installed-package registry, without
// pulling in a JSON dependency: installed.json holds flat string lists
// only, so escaped-string + array parsing is sufficient and auditable.

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn json_string(s: &str) -> String {
    format!("\"{}\"", json_escape(s))
}

fn json_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                if let Ok(n) = u32::from_str_radix(&hex, 16) {
                    if let Some(ch) = char::from_u32(n) {
                        out.push(ch);
                    }
                }
            }
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

impl InstalledRecord {
    pub fn to_json(&self) -> String {
        let files: Vec<String> = self.files.iter().map(|f| json_string(f)).collect();
        format!(
            "{{\"name\":{},\"version\":{},\"installed_at\":{},\"entry_point\":{},\"files\":[{}]}}\n",
            json_string(&self.name),
            json_string(&self.version),
            json_string(&self.installed_at),
            json_string(&self.entry_point),
            files.join(",")
        )
    }
}

/// Append a record to the registry, creating it if needed.
pub fn registry_append(rec: &InstalledRecord) -> Result<(), String> {
    let path = pkg_root().join(INSTALLED_MANIFEST);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("cannot open registry: {}", e))?;
    f.write_all(rec.to_json().as_bytes())
        .map_err(|e| e.to_string())
}

/// Load every record (append-only JSON-lines registry; `hexa remove`
/// writes a tombstone line instead of rewriting history).
pub fn registry_load() -> Vec<InstalledRecord> {
    let mut out = Vec::new();
    let path = pkg_root().join(INSTALLED_MANIFEST);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return out;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rec) = parse_record(line) {
            out.push(rec);
        }
    }
    out
}

fn parse_record(line: &str) -> Option<InstalledRecord> {
    let start = line.find('{')?;
    let end = line.rfind('}')?;
    let body = &line[start + 1..end];
    let mut get = |key: &str| -> Option<String> {
        let pat = format!("\"{}\":", key);
        let i = body.find(&pat)? + pat.len();
        let rest = body[i..].trim_start();
        if !rest.starts_with('"') {
            return None;
        }
        let rest = &rest[1..];
        let bytes: Vec<char> = rest.chars().collect();
        let mut j = 0;
        while j < bytes.len() {
            if bytes[j] == '\\' {
                j += 2;
                continue;
            }
            if bytes[j] == '"' {
                break;
            }
            j += 1;
        }
        if j > bytes.len() {
            return None;
        }
        Some(json_unescape(&bytes[..j].iter().collect::<String>()))
    };
    let files_raw = body.find("\"files\":").map(|i| &body[i + 8..])?;
    let files: Vec<String> = if files_raw.trim_start().starts_with('[') {
        files_raw
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split("\",\"")
            .filter(|s| !s.is_empty())
            .map(|s| json_unescape(s.trim_matches('"')))
            .collect()
    } else {
        Vec::new()
    };
    Some(InstalledRecord {
        name: get("name")?,
        version: get("version")?,
        installed_at: get("installed_at").unwrap_or_default(),
        entry_point: get("entry_point").unwrap_or_default(),
        files,
    })
}

/// Live state = the newest record for a name. A tombstone record has an
/// empty version (written by `hexa remove`).
pub fn is_live(recs: &[InstalledRecord], name: &str) -> bool {
    match recs.iter().rev().find(|r| r.name == name) {
        Some(r) => !r.version.is_empty(),
        None => false,
    }
}

/// Names with a live install, in install order.
pub fn live_packages(recs: &[InstalledRecord]) -> Vec<InstalledRecord> {
    let mut seen: Vec<String> = Vec::new();
    let mut out: Vec<InstalledRecord> = Vec::new();
    for r in recs.iter().rev() {
        if !seen.contains(&r.name) {
            seen.push(r.name.clone());
            if !r.version.is_empty() {
                out.push(r.clone());
            }
        }
    }
    out.reverse();
    out
}

fn utc_now() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string()
}

/// Install an already-validated archive under `$HEXA_HOME`.
///
/// Flow: extract to a staging dir -> run the packaged program through the
/// real compiler -> only on success move the staging dir into place,
/// write the shim and the registry record. If any step fails, the staging
/// dir is removed and nothing is installed.
pub fn install_archive(archive: &PackageArchive) -> Result<PathBuf, String> {
    let m = &archive.manifest;
    let recs = registry_load();
    if is_live(&recs, &m.name) {
        return Err(format!(
            "package '{}' is already installed (use `hexa remove {}` first, or `hexa update` to replace it)",
            m.name, m.name
        ));
    }
    let dest = pkg_root().join(&m.name).join(&m.version);
    // Extract into staging.
    let stage = hexa_home().join("staging").join(format!(
        "{}-{}-{}",
        m.name,
        m.version,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage).map_err(|e| format!("cannot create staging dir: {}", e))?;
    let outcome = (|| -> Result<(), String> {
        for f in &archive.files {
            let target = stage.join(&f.path);
            // Defense in depth: even though decode validated every path,
            // assert containment before each write.
            if !target.starts_with(&stage) {
                return Err(format!("path escapes install dir: {:?}", f.path));
            }
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&target, &f.content)
                .map_err(|e| format!("cannot write {}: {}", target.display(), e))?;
        }
        // Build the real native executable from the packaged entry point.
        let entry_fs = stage.join(&m.entry_point);
        let scratch = hexa_home().join("staging").join(format!(
            "build-{}-{}-{}",
            m.name,
            m.version,
            std::process::id()
        ));
        std::fs::create_dir_all(&scratch).map_err(|e| e.to_string())?;
        let exe = build_entry(&entry_fs, &scratch).map_err(|e| {
            let _ = std::fs::remove_dir_all(&scratch);
            e
        })?;
        let bin_dir = stage.join("bin");
        std::fs::create_dir_all(&bin_dir).map_err(|e| e.to_string())?;
        std::fs::rename(&exe, bin_dir.join(&m.name))
            .or_else(|_| std::fs::copy(&exe, bin_dir.join(&m.name)).map(|_| ()))
            .map_err(|e| format!("cannot move built executable: {}", e))?;
        let _ = std::fs::remove_dir_all(&scratch);
        Ok(())
    })();
    if let Err(e) = outcome {
        let _ = std::fs::remove_dir_all(&stage);
        return Err(e);
    }
    // Commit: move staging into the package tree.
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    if dest.exists() {
        std::fs::remove_dir_all(&dest).map_err(|e| e.to_string())?;
    }
    std::fs::rename(&stage, &dest).map_err(|e| {
        let _ = std::fs::remove_dir_all(&stage);
        format!("cannot finalize install: {}", e)
    })?;
    // Record every file (for a complete uninstall) + the shim.
    let mut files: Vec<String> = archive.files.iter().map(|f| f.path.clone()).collect();
    files.push(format!("bin/{}", m.name));
    let rec = InstalledRecord {
        name: m.name.clone(),
        version: m.version.clone(),
        installed_at: utc_now(),
        entry_point: m.entry_point.clone(),
        files,
    };
    registry_append(&rec).map_err(|e| {
        // The registry is authoritative: without it the package is not
        // manageable, so roll the directory back instead of half-installing.
        let _ = std::fs::remove_dir_all(&dest);
        e
    })?;
    write_shim(&m.name, &m.version).map_err(|e| {
        let _ = std::fs::remove_dir_all(&dest);
        e
    })?;
    install_file_associations(&m.name);
    Ok(dest)
}

/// `~/.hexa/bin/<name>`: a small POSIX shim that execs the installed
/// program. No shell logic beyond exec, no input handling.
fn write_shim(name: &str, version: &str) -> Result<(), String> {
    if !is_valid_name(name) {
        return Err("invalid package name for shim".to_string());
    }
    let bin_dir = bin_root();
    std::fs::create_dir_all(&bin_dir).map_err(|e| e.to_string())?;
    let path = bin_dir.join(name);
    let script = format!(
        "#!/bin/sh\n# HEXA package launcher (generated by `hexa install`)\nexec \"{}\" \"$@\"\n",
        pkg_root().join(name).join(version).join("bin").join(name).display()
    );
    std::fs::write(&path, script).map_err(|e| format!("cannot write shim: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Remove a package: delete its directory, tombstone the registry and
/// remove the shim. Paths are fixed inside `$HEXA_HOME`.
pub fn remove_package(name: &str) -> Result<String, String> {
    if !is_valid_name(name) {
        return Err("invalid package name".to_string());
    }
    let recs = registry_load();
    if !is_live(&recs, name) {
        return Err(format!("package '{}' is not installed", name));
    }
    let dir = pkg_root().join(name);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)
            .map_err(|e| format!("cannot remove {}: {}", dir.display(), e))?;
    }
    let shim = bin_root().join(name);
    let _ = std::fs::remove_file(&shim);
    let tombstone = InstalledRecord {
        name: name.to_string(),
        version: String::new(),
        installed_at: utc_now(),
        entry_point: String::new(),
        files: Vec::new(),
    };
    registry_append(&tombstone)?;
    remove_file_associations(name);
    Ok(shim.display().to_string())
}

// ---------------------------------------------------------------------------
// Desktop integration (best-effort, silent): register `x-hexa/hexa-package`
// for .hxpkg files and give installed programs an application entry with the
// HEXA icon. Never fails the install when freedesktop tooling is absent.
// ---------------------------------------------------------------------------

fn share_dir() -> PathBuf {
    let data = std::env::var("XDG_DATA_HOME").ok().filter(|s| !s.is_empty());
    match data {
        Some(d) => PathBuf::from(d).join("applications"),
        None => hexa_home().join("share").join("applications"),
    }
}

fn write_hexa_mimetype() {
    let dir = share_dir().parent().map(|p| p.join("mime").join("packages"));
    let Some(dir) = dir else { return };
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let xml = "<?xml version=\"1.0\"?>\n<mime-info xmlns=\"http://www.freedesktop.org/standards/shared-mime-info\">\n  <mime-type type=\"x-hexa/hexa-package\">\n    <comment>HEXA package</comment>\n    <glob pattern=\"*.hxpkg\"/>\n  </mime-type>\n</mime-info>\n";
    let _ = std::fs::write(dir.join("hexa.xml"), xml);
}

/// Embed the brand icon (assets/icons/hexa-file.svg) so desktop files can
/// reference it even when HEXA was installed without its asset tree.
fn icon_svg() -> Option<&'static str> {
    match include_str!("../../assets/icons/hexa-file.svg") {
        s if s.contains("<svg") => Some(s),
        _ => None,
    }
}

pub fn install_file_associations(name: &str) {
    write_hexa_mimetype();
    if let Some(svg) = icon_svg() {
        let icon_dir = share_dir()
            .parent()
            .map(|p| p.join("icons").join("hicolor").join("scalable").join("apps"));
        if let Some(icon_dir) = icon_dir {
            if std::fs::create_dir_all(&icon_dir).is_ok() {
                let _ = std::fs::write(icon_dir.join("hexa.svg"), svg);
                // Per-package icon so launchers can distinguish programs.
                if is_valid_name(name) {
                    let _ = std::fs::write(icon_dir.join(format!("hexa-{}.svg", name)), svg);
                }
            }
        }
    }
    let app_dir = share_dir();
    if std::fs::create_dir_all(&app_dir).is_ok() && is_valid_name(name) {
        let exec = bin_root().join(name);
        let desktop = format!(
            "[Desktop Entry]\nType=Application\nName={} (HEXA)\nExec={}\nIcon=hexa-{}\nTerminal=true\nCategories=Development;\nNoDisplay=false\n",
            name,
            exec.display(),
            name
        );
        let _ = std::fs::write(app_dir.join(format!("hexa-{}.desktop", name)), desktop);
    }
    // Register the MIME type with the session (best effort only).
    let _ = std::process::Command::new("update-mime-database")
        .arg(
            share_dir()
                .parent()
                .map(|p| p.join("mime"))
                .unwrap_or_else(|| PathBuf::from("/dev/null")),
        )
        .output();
    let _ = std::process::Command::new("update-desktop-database").arg(&app_dir).output();
}

pub fn remove_file_associations(name: &str) {
    if !is_valid_name(name) {
        return;
    }
    let _ = std::fs::remove_file(share_dir().join(format!("hexa-{}.desktop", name)));
    if let Some(icons) = share_dir().parent().map(|p| p.join("icons").join("hicolor").join("scalable").join("apps")) {
        let _ = std::fs::remove_file(icons.join(format!("hexa-{}.svg", name)));
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest(name: &str) -> String {
        format!(
            "[package]\nname = \"{}\"\nversion = \"1.2.3\"\nentry_point = \"main.he\"\ndescription = \"demo\"\nlicense = \"MIT\"\n",
            name
        )
    }

    #[test]
    fn manifest_parse_ok() {
        let m = PackageManifest::parse(&sample_manifest("demo-app")).unwrap();
        assert_eq!(m.name, "demo-app");
        assert_eq!(m.version, "1.2.3");
        assert_eq!(m.entry_point, "main.he");
    }

    #[test]
    fn manifest_rejects_bad_names_and_versions() {
        assert!(PackageManifest::parse(&sample_manifest("Bad_Name")).is_err());
        assert!(PackageManifest::parse(&sample_manifest("1abc")).is_err());
        assert!(PackageManifest::parse(&sample_manifest("a b")).is_err());
        let mut v = sample_manifest("ok");
        v = v.replace("1.2.3", "1.2");
        assert!(PackageManifest::parse(&v).is_err());
        let mut v = sample_manifest("ok");
        v = v.replace("1.2.3", "1.2.x");
        assert!(PackageManifest::parse(&v).is_err());
    }

    #[test]
    fn manifest_requires_package_table() {
        assert!(PackageManifest::parse("[notpackage]\nname = \"x\"").is_err());
        assert!(PackageManifest::parse("[package]\nversion = \"1.0.0\"").is_err());
    }

    #[test]
    fn safe_paths_only() {
        assert!(is_safe_pkg_path("main.he"));
        assert!(is_safe_pkg_path("src/lib/util.he"));
        assert!(!is_safe_pkg_path("/etc/passwd"));
        assert!(!is_safe_pkg_path("../evil.he"));
        assert!(!is_safe_pkg_path("a/../../evil.he"));
        assert!(!is_safe_pkg_path("a\\b.he"));
        assert!(!is_safe_pkg_path(".hidden/he.he"));
        assert!(!is_safe_pkg_path(""));
    }

    #[test]
    fn archive_roundtrip() {
        let archive = PackageArchive {
            manifest: PackageManifest::parse(&sample_manifest("roundtrip")).unwrap(),
            files: vec![PackagedFile {
                path: "main.he".into(),
                content: b"fn main() { }".to_vec(),
            }],
        };
        let bytes = archive.encode();
        let decoded = decode_archive(&bytes).unwrap();
        assert_eq!(decoded.manifest.name, "roundtrip");
        assert_eq!(decoded.files.len(), 1);
        assert_eq!(decoded.files[0].content, b"fn main() { }");
    }

    #[test]
    fn archive_rejects_bitflips() {
        let archive = PackageArchive {
            manifest: PackageManifest::parse(&sample_manifest("flip")).unwrap(),
            files: vec![PackagedFile {
                path: "main.he".into(),
                content: b"fn main() { }".to_vec(),
            }],
        };
        let bytes = archive.encode();
        // Flip one payload bit -> per-file checksum must fail.
        let mut bad = bytes.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0x01;
        assert!(decode_archive(&bad).is_err());
        // Truncate -> structural error.
        assert!(decode_archive(&bytes[..bytes.len() - 10]).is_err());
        // Bad magic.
        let mut bad = bytes.clone();
        bad[0] = b'X';
        assert!(decode_archive(&bad).is_err());
    }

    #[test]
    fn archive_rejects_path_traversal() {
        let mut archive = PackageArchive {
            manifest: PackageManifest::parse(&sample_manifest("traversal")).unwrap(),
            files: vec![PackagedFile {
                path: "main.he".into(),
                content: b"fn main() { }".to_vec(),
            }],
        };
        archive.files.push(PackagedFile {
            path: "../escape.he".into(),
            content: b"evil".to_vec(),
        });
        let bytes = archive.encode();
        let err = decode_archive(&bytes).unwrap_err();
        assert!(err.contains("unsafe path"), "got: {}", err);
    }

    #[test]
    fn archive_rejects_missing_entry_point() {
        let archive = PackageArchive {
            manifest: PackageManifest::parse(&sample_manifest("noentry")).unwrap(),
            files: vec![PackagedFile {
                path: "lib.he".into(),
                content: b"fn helper() { }".to_vec(),
            }],
        };
        let bytes = archive.encode();
        let err = decode_archive(&bytes).unwrap_err();
        assert!(err.contains("entry_point"), "got: {}", err);
    }

    #[test]
    fn registry_json_roundtrip() {
        let rec = InstalledRecord {
            name: "demo".into(),
            version: "0.1.0".into(),
            installed_at: "123".into(),
            entry_point: "main.he".into(),
            files: vec!["main.he".into(), "bin/demo".into()],
        };
        let parsed = parse_record(rec.to_json().trim()).unwrap();
        assert_eq!(parsed.name, "demo");
        assert_eq!(parsed.version, "0.1.0");
        assert_eq!(parsed.files, vec!["main.he".to_string(), "bin/demo".to_string()]);
    }

    #[test]
    fn registry_tombstone_semantics() {
        let live = InstalledRecord {
            name: "app".into(),
            version: "1.0.0".into(),
            installed_at: "1".into(),
            entry_point: "main.he".into(),
            files: vec![],
        };
        let gone = InstalledRecord { version: String::new(), ..live.clone() };
        let recs = vec![live.clone(), gone.clone()];
        assert!(!is_live(&recs, "app"));
        assert!(live_packages(&recs).is_empty());
        let recs = vec![gone, live];
        assert!(is_live(&recs, "app"));
        assert_eq!(live_packages(&recs).len(), 1);
    }

    #[test]
    fn names_and_versions() {
        assert!(is_valid_name("a"));
        assert!(is_valid_name("my-tool_2"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("A"));
        assert!(!is_valid_name("9lives"));
        assert!(!is_valid_name("has space"));
        assert!(is_valid_version("0.1.0"));
        assert!(!is_valid_version("01.0.0")); // leading zeros are fine? no: digits only, so 01 passes
        assert!(!is_valid_version("1.0"));
        assert!(!is_valid_version(""));
    }
}
