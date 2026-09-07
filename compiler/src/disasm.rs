//! Native binary analysis: ELF64 parsing, symbol extraction, x86-64
//! disassembly, and approximate decompilation (spec sections 31-32).
//!
//! Mode A (native analysis): ELF -> symbols -> instruction decode.
//! Mode B (debug metadata): the .hexa_meta section (emitted by --debug
//!   builds) carries function signatures; bodies are NOT recoverable and
//!   this is stated honestly in the output.
//! Mode C (protected metadata): encrypted .hexa_meta (marker
//!   "HEXAMETAENC1\0") requires an explicit credential; it is never
//!   recoverable without it and never contains one-time keys.

struct Section {
    name: String,
    sh_type: u32,
    addr: u64,
    offset: usize,
    size: usize,
    link: u32,
    entsize: usize,
}

struct Symbol {
    name: String,
    value: u64,
    size: u64,
    is_func: bool,
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8).map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

fn cstr(b: &[u8], off: usize) -> String {
    let start = off.min(b.len());
    let end = b[start..].iter().position(|&c| c == 0).map(|p| start + p).unwrap_or(b.len());
    String::from_utf8_lossy(&b[start..end]).to_string()
}

fn parse_elf(bytes: &[u8]) -> Result<(Vec<Section>, Vec<Symbol>), String> {
    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" {
        return Err("not an ELF binary".into());
    }
    if bytes[4] != 2 {
        return Err("unsupported ELF class (expected ELF64)".into());
    }
    if bytes[5] != 1 {
        return Err("unsupported ELF endianness (expected little-endian)".into());
    }
    let machine = u16_at(bytes, 18).ok_or("truncated ELF header")?;
    if machine != 62 {
        return Err(format!("unsupported machine {} (only x86-64 is implemented)", machine));
    }
    let shoff = u64_at(bytes, 0x28).ok_or("truncated ELF header")? as usize;
    let shentsize = u16_at(bytes, 0x3a).ok_or("truncated ELF header")? as usize;
    let shnum = u16_at(bytes, 0x3c).ok_or("truncated ELF header")? as usize;
    let shstrndx = u16_at(bytes, 0x3e).ok_or("truncated ELF header")? as usize;
    if shentsize < 64 || shnum == 0 {
        return Err("ELF has no section headers".into());
    }
    let mut sections = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let base = shoff.checked_add(i.checked_mul(shentsize).ok_or("section overflow")?)
            .ok_or("section offset overflow")?;
        if base + 64 > bytes.len() {
            return Err("truncated section header table".into());
        }
        sections.push(Section {
            name: String::new(),
            sh_type: u32_at(bytes, base + 4).unwrap_or(0),
            addr: u64_at(bytes, base + 16).unwrap_or(0),
            offset: u64_at(bytes, base + 24).unwrap_or(0) as usize,
            size: u64_at(bytes, base + 32).unwrap_or(0) as usize,
            link: u32_at(bytes, base + 40).unwrap_or(0),
            entsize: u64_at(bytes, base + 56).unwrap_or(0) as usize,
        });
    }
    if shstrndx >= sections.len() {
        return Err("invalid section name string table index".into());
    }
    let strt = &sections[shstrndx];
    if strt.offset + strt.size > bytes.len() {
        return Err("section name string table out of range".into());
    }
    for (i, s) in sections.iter_mut().enumerate() {
        let base = shoff + i * shentsize;
        let name_off = u32_at(bytes, base).unwrap_or(0) as usize;
        s.name = cstr(&bytes[strt.offset..strt.offset + strt.size], name_off);
    }

    // Symbols from .symtab (sh_type 2) using its linked strtab.
    let mut symbols = Vec::new();
    for s in &sections {
        if s.sh_type != 2 || s.entsize == 0 || s.link as usize >= sections.len() {
            continue;
        }
        let st = &sections[s.link as usize];
        if st.offset + st.size > bytes.len() || s.offset + s.size > bytes.len() {
            continue; // malformed symtab: skip, never panic
        }
        let strtab = &bytes[st.offset..st.offset + st.size];
        let count = s.size / s.entsize;
        for i in 0..count {
            let base = s.offset + i * s.entsize;
            if base + 24 > bytes.len() {
                break;
            }
            let name_off = u32_at(bytes, base).unwrap_or(0) as usize;
            let info = bytes[base + 4];
            symbols.push(Symbol {
                name: cstr(strtab, name_off),
                value: u64_at(bytes, base + 8).unwrap_or(0),
                size: u64_at(bytes, base + 16).unwrap_or(0),
                is_func: info & 0xf == 2,
            });
        }
    }
    Ok((sections, symbols))
}

// ---------------- x86-64 instruction decoding ----------------

const REG64: [&str; 8] = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"];

/// Decode the subset of x86-64 emitted by the HEXA backend plus common
/// prologue/epilogue patterns; fall back to `.byte` honestly for the rest.
/// Returns (text, instruction length).
fn decode(b: &[u8]) -> (String, usize) {
    if b.is_empty() {
        return ("<eof>".into(), 0);
    }
    let raw = |n: usize| -> String {
        format!(
            ".byte {}",
            b[..n.min(b.len())].iter().map(|x| format!("0x{:02x}", x)).collect::<Vec<_>>().join(", ")
        )
    };
    match b[0] {
        0x55 => ("pushq %rbp".into(), 1),
        0x5d => ("popq %rbp".into(), 1),
        0xc3 => ("ret".into(), 1),
        0x50..=0x57 => (format!("pushq %{}", REG64[(b[0] - 0x50) as usize]), 1),
        0x58..=0x5f => (format!("popq %{}", REG64[(b[0] - 0x58) as usize]), 1),
        0xb8 => (format!("movl $0x{:x}, %eax", u32_at(b, 1).unwrap_or(0)), 5),
        0xe8 => {
            let rel = i32::from_le_bytes([*b.get(1)?, *b.get(2)?, *b.get(3)?, *b.get(4)?]);
            (format!("call {:+#x}", rel as i64), 5)
        }
        0xeb => (format!("jmp .+{}", b[1] as i8 as i64 + 2), 2),
        0xe9 => {
            let rel = i32::from_le_bytes([*b.get(1)?, *b.get(2)?, *b.get(3)?, *b.get(4)?]);
            (format!("jmp .+{}", rel as i64 + 5), 5)
        }
        0x31 if b.get(1) == Some(&0xc0) => ("xorl %eax, %eax".into(), 2),
        0x34 => (format!("xorb $0x{:x}, %al", b.get(1).copied().unwrap_or(0)), 2),
        0x0f if b.len() > 2 => match b[1] {
            0x84 => (format!("jz .+{}", i32::from_le_bytes([b[2], b[3], b[4], b[5]]) as i64 + 6), 6),
            0x94 if b[2] == 0xc0 => ("sete %al".into(), 3),
            0x95 if b[2] == 0xc0 => ("setne %al".into(), 3),
            0x9c if b[2] == 0xc0 => ("setl %al".into(), 3),
            0x9e if b[2] == 0xc0 => ("setle %al".into(), 3),
            0x9f if b[2] == 0xc0 => ("setg %al".into(), 3),
            0x9d if b[2] == 0xc0 => ("setge %al".into(), 3),
            0xb6 if b[2] == 0xc0 => ("movzbl %al, %eax".into(), 3),
            0xaf if b[2] == 0xc1 => ("imulq %rcx, %rax".into(), 3),
            _ => (raw(1), 1),
        },
        0x48 | 0x49 if b.len() > 1 => {
            let rest = &b[1..];
            match rest[0] {
                0x89 | 0x8b if rest.len() > 1 && (rest[1] & 0xc7) == 0x45 => {
                    // mov reg, disp32(%rbp) with 1-byte disp
                    let reg = ((rest[1] >> 3) & 7) as usize;
                    let disp = rest.get(2).copied().unwrap_or(0) as i8;
                    let m = if rest[0] == 0x89 {
                        format!("movq %{}, {}(%rbp)", REG64[reg], disp)
                    } else {
                        format!("movq {}(%rbp), %{}", disp, REG64[reg])
                    };
                    (m, 4)
                }
                0x85 if rest.len() > 1 && rest[1] == 0xc0 => ("testq %rax, %rax".into(), 3),
                0x39 if rest.len() > 1 && rest[1] == 0xc8 => ("cmpq %rcx, %rax".into(), 3),
                0x01 if rest.len() > 1 && rest[1] == 0xc8 => ("addq %rcx, %rax".into(), 3),
                0x29 if rest.len() > 1 && rest[1] == 0xc8 => ("subq %rcx, %rax".into(), 3),
                0x99 => ("cqto".into(), 2),
                0xf7 if rest.len() > 1 && rest[1] == 0xf9 => ("idivq %rcx".into(), 3),
                0xf7 if rest.len() > 1 && rest[1] == 0xd8 => ("negq %rax".into(), 3),
                0xb8..=0xbf => {
                    let imm = u64_at(b, 2).unwrap_or(0);
                    (format!("movabsq $0x{:x}, %{}", imm, REG64[(rest[0] - 0xb8) as usize]), 10)
                }
                _ => (raw(2), 2),
            }
        }
        _ => (raw(1), 1),
    }
}

// ---------------- public API ----------------

fn functions_of(symbols: &[Symbol]) -> Vec<&Symbol> {
    let mut funcs: Vec<&Symbol> = symbols.iter().filter(|s| s.is_func && s.size > 0).collect();
    funcs.sort_by_key(|s| s.value);
    funcs
}

/// Disassemble a HEXA native executable (spec section 32):
/// address, instruction, operands, symbol.
pub fn disassemble(bytes: &[u8]) -> Result<String, String> {
    let (sections, symbols) = parse_elf(bytes)?;
    let funcs = functions_of(&symbols);
    if funcs.is_empty() {
        return Err("no function symbols found (stripped binary?)".into());
    }
    let mut out = String::from("; HEXA disassembly\n");
    for f in funcs {
        out.push_str(&format!("\n{:016x} <{}> ({} bytes):\n", f.value, f.name, f.size));
        let start = f.value as usize;
        let end = start.saturating_add(f.size as usize);
        let mut pc = start;
        while pc < end {
            let off = sections
                .iter()
                .find(|s| s.sh_type != 8 && pc >= s.addr as usize && pc < s.addr as usize + s.size)
                .map(|s| pc - s.addr as usize + s.offset)
                .unwrap_or(pc);
            if off >= bytes.len() {
                break;
            }
            let (text, len) = decode(&bytes[off..]);
            out.push_str(&format!("  {:08x}: {:<44} ; {}\n", pc, text, f.name));
            if len == 0 {
                break;
            }
            pc += len;
        }
    }
    Ok(out)
}

/// Decompile a HEXA native executable (spec section 31).
pub fn decompile(bytes: &[u8]) -> Result<String, String> {
    let (sections, symbols) = parse_elf(bytes)?;
    let mut out = String::new();
    // Mode C: protected (encrypted) metadata section.
    if let Some(sec) = sections.iter().find(|s| s.name == ".hexa_meta") {
        if sec.offset + sec.size <= bytes.len() {
            let meta = &bytes[sec.offset..sec.offset + sec.size];
            if meta.starts_with(b"HEXAMETAENC1\0") {
                out.push_str("// Protected HEXA metadata detected (Mode C).\n");
                out.push_str("// This build embeds ENCRYPTED debug metadata.\n");
                out.push_str("// Decryption requires the explicit developer credential;\n");
                out.push_str("// a wrong credential fails authentication by design.\n");
                out.push_str("// NOTE: this section never contains one-time keys.\n");
                return Ok(out);
            }
            // Mode B: plaintext debug metadata.
            let text = String::from_utf8_lossy(meta);
            out.push_str("// Reconstructed from debug metadata (.hexa_meta, Mode B).\n");
            out.push_str("// Signatures are exact; function bodies are NOT recoverable\n");
            out.push_str("// from metadata alone and are shown as placeholders.\n\n");
            for line in text.lines() {
                let line = line.trim();
                if !line.is_empty() {
                    out.push_str(line);
                    out.push('\n');
                }
            }
            return Ok(out);
        }
    }
    // Mode A: native analysis, approximate.
    out.push_str("// Approximate reconstruction from native code (Mode A).\n");
    out.push_str("// Lossless source recovery from optimized native binaries is NOT\n");
    out.push_str("// possible; this is a best-effort approximation.\n\n");
    let funcs = functions_of(&symbols);
    if funcs.is_empty() {
        return Err("no function symbols found (stripped binary?)".into());
    }
    for f in funcs {
        let name = if f.name == "hexa_main" {
            "main".to_string()
        } else {
            f.name.strip_prefix("hexa_fn_").unwrap_or(&f.name).to_string()
        };
        out.push_str(&format!("fn {}() {{ /* native code, {} bytes */ }}\n", name, f.size));
    }
    Ok(out)
}
