//! Utility functions replacing several external dependencies.
//!
//! Provides local implementations of `hex_encode`, `constant_time_eq`,
//! `json_escape_string`, `config_dir`, `data_dir`, `home_dir`, and
//! `ascii85_decode` to reduce the crate's dependency footprint.

use anyhow::Result;
use std::path::PathBuf;

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

/// Encode bytes as a lowercase hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    s
}

/// Compare two byte slices in constant time.
///
/// Returns `true` if the slices have the same length and equal contents.
/// The comparison time is independent of the position of the first mismatch,
/// but does depend on slice length.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Escape a string value for JSON, producing a quoted JSON string literal.
///
/// Handles `"`, `\`, and control characters (`\n`, `\r`, `\t`, and
/// other control chars as `\uXXXX`).  The returned string includes
/// surrounding double-quote characters, matching the output of
/// `serde_json::to_string` for a `String` value.
pub fn json_escape_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 2);
    result.push('"');
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result.push('"');
    result
}

/// Return the XDG config directory (`$XDG_CONFIG_HOME` or `$HOME/.config`).
pub fn config_dir() -> Option<PathBuf> {
    if let Ok(val) = std::env::var("XDG_CONFIG_HOME") {
        let p = PathBuf::from(val);
        if p.is_absolute() {
            return Some(p);
        }
    }
    home_dir().map(|h| h.join(".config"))
}

/// Return the XDG data directory (`$XDG_DATA_HOME` or `$HOME/.local/share`).
pub fn data_dir() -> Option<PathBuf> {
    if let Ok(val) = std::env::var("XDG_DATA_HOME") {
        let p = PathBuf::from(val);
        if p.is_absolute() {
            return Some(p);
        }
    }
    home_dir().map(|h| h.join(".local").join("share"))
}

/// Return the home directory.
///
/// Checks `$HOME` first; on Unix, falls back to reading `/etc/passwd` to
/// find the home directory for the current user.
pub fn home_dir() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        return Some(PathBuf::from(home));
    }
    #[cfg(unix)]
    {
        // Fallback: read /etc/passwd to find the current user's home dir
        let current_user = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .ok()?;
        let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() > 5 && parts[0] == current_user {
                return Some(PathBuf::from(parts[5].to_string()));
            }
        }
    }
    None
}

/// Decode an ASCII85-encoded string to bytes.
///
/// Handles the optional `<~` / `~>` delimiters, `z` for four zero bytes,
/// and final partial groups.  Whitespace is ignored.  Returns an error on
/// invalid characters or malformed input.
pub fn ascii85_decode(data: &str) -> Result<Vec<u8>> {
    let mut chars = data.chars().filter(|c| !c.is_ascii_whitespace()).peekable();

    // skip optional "<~" prefix
    if chars.peek() == Some(&'<') {
        chars.next();
        if chars.peek() == Some(&'~') {
            chars.next();
        }
    }

    let mut result = Vec::new();
    let mut buf = [0u8; 5];
    let mut count = 0;

    loop {
        match chars.next() {
            None | Some('~') => break,
            Some('z') => {
                if count > 0 {
                    anyhow::bail!("ascii85: 'z' not at group boundary");
                }
                result.extend_from_slice(&[0, 0, 0, 0]);
            }
            Some(c) => {
                let val = c as u8;
                if !(33..=117).contains(&val) {
                    anyhow::bail!("ascii85: invalid character '{}'", c);
                }
                buf[count] = val - 33;
                count += 1;
                if count == 5 {
                    let word = buf[0] as u64 * 85u64.pow(4)
                        + buf[1] as u64 * 85u64.pow(3)
                        + buf[2] as u64 * 85u64.pow(2)
                        + buf[3] as u64 * 85
                        + buf[4] as u64;
                    result.extend_from_slice(&(word as u32).to_be_bytes());
                    count = 0;
                }
            }
        }
    }

    if count > 0 {
        for item in buf.iter_mut().skip(count) {
            *item = 84; // 'u' - 33  (padding with highest value)
        }
        let word = buf[0] as u64 * 85u64.pow(4)
            + buf[1] as u64 * 85u64.pow(3)
            + buf[2] as u64 * 85u64.pow(2)
            + buf[3] as u64 * 85
            + buf[4] as u64;
        let bytes = (word as u32).to_be_bytes();
        result.extend_from_slice(&bytes[..count - 1]);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{encode_payload, Algorithm, AlgorithmList};

    fn ascii85_encode_for_test(data: &[u8]) -> String {
        let alg_list = AlgorithmList::new(vec![Algorithm::Ascii85]);
        let encoded = encode_payload(&alg_list, data).unwrap();
        String::from_utf8(encoded).unwrap()
    }

    // ── hex_encode ──────────────────────────────────────────────────────

    #[test]
    fn test_hex_encode_empty() {
        assert_eq!(hex_encode(b""), "");
    }

    #[test]
    fn test_hex_encode_hello() {
        assert_eq!(hex_encode(b"hello"), "68656c6c6f");
    }

    #[test]
    fn test_hex_encode_bytes() {
        let bytes = [0xde, 0xad, 0xbe, 0xef];
        assert_eq!(hex_encode(&bytes), "deadbeef");
    }

    #[test]
    fn test_hex_encode_all_byte_values() {
        let bytes: Vec<u8> = (0..=255).collect();
        let hex = hex_encode(&bytes);
        assert_eq!(hex.len(), 512);
        assert!(hex.starts_with("000102"));
        assert!(hex.ends_with("ff"));
    }

    // ── constant_time_eq ────────────────────────────────────────────────

    #[test]
    fn test_ct_eq_equal() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn test_ct_eq_different() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn test_ct_eq_different_lengths() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn test_ct_eq_both_empty() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_ct_eq_zero_bytes() {
        assert!(constant_time_eq(&[0, 0, 0], &[0, 0, 0]));
        assert!(!constant_time_eq(&[0, 0, 0], &[0, 0, 1]));
    }

    // ── json_escape_string ──────────────────────────────────────────────

    #[test]
    fn test_json_escape_simple() {
        assert_eq!(json_escape_string("hello"), r#""hello""#);
    }

    #[test]
    fn test_json_escape_quotes() {
        assert_eq!(json_escape_string(r#"say "hello""#), r#""say \"hello\"""#);
    }

    #[test]
    fn test_json_escape_backslash() {
        assert_eq!(json_escape_string(r"a\b"), r#""a\\b""#);
    }

    #[test]
    fn test_json_escape_newline() {
        assert_eq!(json_escape_string("a\nb"), r#""a\nb""#);
    }

    #[test]
    fn test_json_escape_carriage_return() {
        assert_eq!(json_escape_string("a\rb"), r#""a\rb""#);
    }

    #[test]
    fn test_json_escape_tab() {
        assert_eq!(json_escape_string("a\tb"), r#""a\tb""#);
    }

    #[test]
    fn test_json_escape_control() {
        let s = String::from("a\x00b");
        assert_eq!(json_escape_string(&s), r#""a\u0000b""#);
    }

    #[test]
    fn test_json_escape_empty() {
        assert_eq!(json_escape_string(""), r#""""#);
    }

    // ── config_dir / data_dir / home_dir ────────────────────────────────

    #[test]
    fn test_home_dir_uses_env() {
        let orig = std::env::var_os("HOME");
        std::env::set_var("HOME", "/tmp/test-pqp-home");
        assert_eq!(home_dir(), Some(PathBuf::from("/tmp/test-pqp-home")));
        if let Some(h) = orig {
            std::env::set_var("HOME", h);
        } else {
            std::env::remove_var("HOME");
        }
    }

    #[test]
    fn test_config_dir_default() {
        let orig_home = std::env::var_os("HOME");
        let orig_xdg = std::env::var_os("XDG_CONFIG_HOME");
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::set_var("HOME", "/home/user");
        assert_eq!(config_dir(), Some(PathBuf::from("/home/user/.config")));
        if let Some(h) = orig_home {
            std::env::set_var("HOME", h);
        }
        if let Some(x) = orig_xdg {
            std::env::set_var("XDG_CONFIG_HOME", x);
        }
    }

    #[test]
    fn test_config_dir_xdg_override() {
        let orig = std::env::var_os("XDG_CONFIG_HOME");
        std::env::set_var("XDG_CONFIG_HOME", "/custom/config");
        assert_eq!(config_dir(), Some(PathBuf::from("/custom/config")));
        if let Some(x) = orig {
            std::env::set_var("XDG_CONFIG_HOME", x);
        } else {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }

    #[test]
    fn test_data_dir_default() {
        let orig_home = std::env::var_os("HOME");
        let orig_xdg = std::env::var_os("XDG_DATA_HOME");
        std::env::remove_var("XDG_DATA_HOME");
        std::env::set_var("HOME", "/home/user");
        assert_eq!(data_dir(), Some(PathBuf::from("/home/user/.local/share")));
        if let Some(h) = orig_home {
            std::env::set_var("HOME", h);
        }
        if let Some(x) = orig_xdg {
            std::env::set_var("XDG_DATA_HOME", x);
        }
    }

    #[test]
    fn test_data_dir_xdg_override() {
        let orig = std::env::var_os("XDG_DATA_HOME");
        std::env::set_var("XDG_DATA_HOME", "/custom/data");
        assert_eq!(data_dir(), Some(PathBuf::from("/custom/data")));
        if let Some(x) = orig {
            std::env::set_var("XDG_DATA_HOME", x);
        } else {
            std::env::remove_var("XDG_DATA_HOME");
        }
    }

    // ── ascii85_decode ──────────────────────────────────────────────────

    #[test]
    fn test_ascii85_decode_empty() {
        let decoded = ascii85_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_ascii85_decode_delimiters_only() {
        let decoded = ascii85_decode("<~~>").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_ascii85_decode_zero() {
        let encoded = ascii85_encode_for_test(&[0, 0, 0, 0]);
        let decoded = ascii85_decode(&encoded).unwrap();
        assert_eq!(decoded, &[0, 0, 0, 0]);
    }

    #[test]
    fn test_ascii85_decode_multiple_zeroes() {
        let encoded = ascii85_encode_for_test(&[0u8; 8]);
        let decoded = ascii85_decode(&encoded).unwrap();
        assert_eq!(decoded, &[0u8; 8]);
    }

    #[test]
    fn test_ascii85_decode_roundtrip() {
        let test_cases: &[&[u8]] = &[
            b"hello",
            b"a",
            b"ab",
            b"abc",
            b"abcd",
            b"",
            b"Hello, World!",
            b"\x00\x01\x02\x03",
            &[0xff; 16],
        ];
        for data in test_cases {
            let encoded = ascii85_encode_for_test(data);
            let decoded = ascii85_decode(&encoded).unwrap();
            assert_eq!(
                &decoded, data,
                "roundtrip failed for {:?} encoded as {}",
                data, encoded
            );
        }
    }

    #[test]
    fn test_ascii85_decode_invalid_char() {
        let result = ascii85_decode("<~invalid!~>");
        assert!(result.is_err());
    }

    #[test]
    fn test_ascii85_decode_z_not_at_boundary() {
        // 'z' in middle of a partial group should fail
        let result = ascii85_decode("<~abz~>");
        assert!(result.is_err());
    }

    #[test]
    fn test_ascii85_decode_ignores_whitespace() {
        let raw = b"Hello!";
        let encoded = ascii85_encode_for_test(raw);
        // Remove delimiters, then space-separate each char, re-wrap
        let body = encoded
            .strip_prefix("<~")
            .and_then(|s| s.strip_suffix("~>"))
            .unwrap();
        let with_spaces = format!(
            "<~{}~>",
            body.chars().map(|c| format!(" {}", c)).collect::<String>()
        );
        let decoded = ascii85_decode(&with_spaces).unwrap();
        assert_eq!(decoded, raw);
    }
}
