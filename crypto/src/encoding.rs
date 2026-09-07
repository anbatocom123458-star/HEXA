//! Canonical encodings: hex, base64, base64url, utf8.
//!
//! Encoding is NOT encryption. These helpers exist so programs can move
//! data between bytes and textual representations without confusing the two.

use crate::error::CryptoError;

pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, CryptoError> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return Err(CryptoError::malformed("EHEX-011", "hex string has odd length"));
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for i in (0..clean.len()).step_by(2) {
        match u8::from_str_radix(&clean[i..i + 2], 16) {
            Ok(v) => out.push(v),
            Err(_) => return Err(CryptoError::malformed("EHEX-011", "invalid hex character")),
        }
    }
    Ok(out)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn base64_encode(data: &[u8]) -> String {
    b64_encode(data, B64, true)
}

pub fn base64url_encode(data: &[u8]) -> String {
    b64_encode(data, B64URL, false)
}

fn b64_encode(data: &[u8], alphabet: &[u8; 64], padded: bool) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(alphabet[(n >> 18) as usize & 63] as char);
        out.push(alphabet[(n >> 12) as usize & 63] as char);
        out.push(alphabet[(n >> 6) as usize & 63] as char);
        out.push(alphabet[n as usize & 63] as char);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let b = data[i];
        out.push(alphabet[(b >> 2) as usize] as char);
        out.push(alphabet[((b & 3) << 4) as usize] as char);
        if padded { out.push('='); out.push('='); }
    } else if rem == 2 {
        let b = [data[i], data[i + 1]];
        let n = ((b[0] as u32) << 8) | b[1] as u32;
        out.push(alphabet[(n >> 10) as usize & 63] as char);
        out.push(alphabet[(n >> 4) as usize & 63] as char);
        out.push(alphabet[((n & 15) << 2) as usize] as char);
        if padded { out.push('='); }
    }
    out
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>, CryptoError> {
    b64_decode(s, B64)
}

pub fn base64url_decode(s: &str) -> Result<Vec<u8>, CryptoError> {
    b64_decode(s, B64URL)
}

fn b64_decode(s: &str, alphabet: &[u8; 64]) -> Result<Vec<u8>, CryptoError> {
    let mut rev = [0u8; 256];
    for (i, c) in alphabet.iter().enumerate() {
        rev[*c as usize] = i as u8;
    }
    let clean: String = s.chars().filter(|c| !c.is_whitespace() && *c != '=').collect();
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in clean.as_bytes() {
        if rev[c as usize] == 0 && alphabet[0] != c {
            return Err(CryptoError::malformed("EHEX-012", "invalid base64 character"));
        }
        acc = (acc << 6) | rev[c as usize] as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits >= 6 {
        return Err(CryptoError::malformed("EHEX-012", "invalid base64 padding"));
    }
    Ok(out)
}

pub fn utf8_encode(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

pub fn utf8_decode(b: &[u8]) -> Result<String, CryptoError> {
    String::from_utf8(b.to_vec()).map_err(|_| CryptoError::malformed("EHEX-013", "invalid UTF-8"))
}
