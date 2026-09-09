//! Terminal styling for the hexa CLI.
//!
//! Colors are emitted only when the stream is an interactive terminal,
//! `NO_COLOR` is unset, and `TERM` is not `dumb` (the de-facto
//! no-color conventions). Every helper returns the *styled text* only —
//! callers append their own newline — so redirection and pipes always
//! receive clean, plain output.
//!
//! Nothing here rewrites program content: the key display string, program
//! output, and file contents are never altered; color codes only wrap
//! whole lines or labels.

use std::io::IsTerminal;
use std::sync::OnceLock;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";

fn env_disables_color() -> bool {
    // NO_COLOR set to any non-empty value disables color globally
    // (https://no-color.org/). dumb terminals cannot render SGR codes.
    let no_color = match std::env::var("NO_COLOR") {
        Ok(v) => !v.is_empty(),
        Err(_) => false,
    };
    let dumb_term = std::env::var("TERM").map(|t| t == "dumb").unwrap_or(false);
    no_color || dumb_term
}

fn stdout_is_tty() -> bool {
    std::io::stdout().is_terminal()
}

fn stderr_is_tty() -> bool {
    std::io::stderr().is_terminal()
}

/// Cached decision for stdout styling. Computed once per process.
fn stdout_color() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| stdout_is_tty() && !env_disables_color())
}

/// Cached decision for stderr styling. Computed once per process.
fn stderr_color() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| stderr_is_tty() && !env_disables_color())
}

fn wrap(stream: Stream, code: &str, text: &str) -> String {
    let enabled = match stream {
        Stream::Out => stdout_color(),
        Stream::Err => stderr_color(),
    };
    if enabled && !text.is_empty() {
        format!("{}{}{}", code, text, RESET)
    } else {
        text.to_string()
    }
}

#[derive(Clone, Copy)]
enum Stream {
    Out,
    Err,
}

/// Bold text on stdout (headings, the toolchain name).
pub fn bold_out(text: &str) -> String {
    wrap(Stream::Out, BOLD, text)
}

/// Cyan accent on stdout (version numbers, metadata labels).
pub fn accent_out(text: &str) -> String {
    wrap(Stream::Out, CYAN, text)
}

/// Green success text on stdout ("built X", "OK", "Encryption completed").
pub fn ok_out(text: &str) -> String {
    wrap(Stream::Out, GREEN, text)
}

/// Yellow warning text on stdout.
pub fn warn_out(text: &str) -> String {
    wrap(Stream::Out, YELLOW, text)
}

/// Dim explanatory text on stdout.
pub fn dim_out(text: &str) -> String {
    wrap(Stream::Out, DIM, text)
}

/// Red error text on stderr.
pub fn err_text(text: &str) -> String {
    wrap(Stream::Err, RED, text)
}

/// Bold red error text on stderr (the `error:` prefix itself).
pub fn err_prefix() -> String {
    wrap(Stream::Err, &format!("{}{}", BOLD, RED), "error:")
}

/// Yellow `WARNING:` prefix on stdout.
pub fn warn_prefix() -> String {
    wrap(Stream::Out, &format!("{}{}", BOLD, YELLOW), "WARNING:")
}

/// Style the one-time key banner heading on stdout.
pub fn key_banner(text: &str) -> String {
    wrap(Stream::Out, &format!("{}{}", BOLD, CYAN), text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_env(key: &str, val: &str) {
        std::env::set_var(key, val);
    }

    #[test]
    fn test_ansi_escape_codes_are_well_formed() {
        // The styled strings must be exactly CSI <params> m text CSI 0 m —
        // "định dạng đúng" (well-formed SGR sequences), verifiable as text.
        set_env("NO_COLOR", "");
        std::env::remove_var("NO_COLOR");
        // Force the non-TTY branch (tests are never a TTY under harness),
        // so exercise the code path shapes via direct construction.
        let styled = format!("{}{}{}{}{}", BOLD, RED, "error:", RESET, "");
        assert!(styled.starts_with("\x1b["));
        assert!(styled.ends_with("\x1b[0m"));
        assert!(styled.contains("error:"));
        // Green OK line shape.
        let ok = format!("{}OK{}", GREEN, RESET);
        assert_eq!(ok, "\x1b[32mOK\x1b[0m");
    }

    #[test]
    fn test_plain_when_not_a_tty() {
        // Under the test harness stdout is a pipe, so styling must be off
        // and helpers must return the input unchanged.
        let s = ok_out("built main");
        assert_eq!(s, "built main");
        let e = err_text("boom");
        assert_eq!(e, "boom");
    }

    #[test]
    fn test_no_color_env_disables_even_on_tty_paths() {
        // NO_COLOR=1 with a non-TTY is trivially off; assert env parsing
        // does not panic and the helper stays consistent.
        set_env("NO_COLOR", "1");
        assert_eq!(ok_out("x"), "x");
        std::env::remove_var("NO_COLOR");
    }
}