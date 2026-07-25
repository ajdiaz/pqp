//! ASCII-armor encoding for public key export/import.
//!
//! Wraps base64- or ascii85-encoded data in `-----BEGIN <marker>-----` and
//! `-----END <marker>-----` delimiters, with 64-char line wrapping.

use anyhow::{Context, Result};

const LINE_WIDTH: usize = 64;

/// Encoding algorithm for the armored payload body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Base64,
    Ascii85,
}

impl Encoding {
    /// Returns the canonical name (e.g. "BASE64").
    pub fn as_str(self) -> &'static str {
        match self {
            Encoding::Base64 => "BASE64",
            Encoding::Ascii85 => "ASCII85",
        }
    }

    /// Parse a canonical name into an encoding variant.
    pub fn parse(s: &str) -> Option<Self> {
        use std::str::FromStr;
        Self::from_str(s).ok()
    }
}

impl std::str::FromStr for Encoding {
    type Err = &'static str;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "BASE64" => Ok(Encoding::Base64),
            "ASCII85" => Ok(Encoding::Ascii85),
            _ => Err("unknown encoding"),
        }
    }
}

/// Encode binary data as an ASCII-armored string with the given marker, encoding,
/// and optional metadata headers.
///
/// Metadata headers are inserted between the BEGIN line and the encoded body as
/// `Key: Value` lines.
pub fn armor(
    data: &[u8],
    marker: &str,
    encoding: &Encoding,
    metadata: &[(String, String)],
) -> Result<String> {
    let encoded = match encoding {
        Encoding::Base64 => {
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data)
        }
        Encoding::Ascii85 => ascii85_encode(data),
    };

    let mut result = String::new();
    result.push_str(&format!("-----BEGIN {}-----\n", marker));

    for (k, v) in metadata {
        for line in v.lines() {
            result.push_str(&format!("{}: {}\n", k, line));
        }
    }

    for chunk in encoded.as_bytes().chunks(LINE_WIDTH) {
        result.push_str(&String::from_utf8_lossy(chunk));
        result.push('\n');
    }

    result.push_str(&format!("-----END {}-----\n", marker));
    Ok(result)
}

/// Decode an ASCII-armored string back into binary data, returning the marker,
/// payload, and any metadata header lines.
///
/// Header lines are `Key: Value` pairs between the BEGIN line and the encoded body.
/// Lines that don't start with `-----` or contain `: ` are treated as body data.
#[allow(clippy::type_complexity)]
pub fn unarmor(armored: &str) -> Result<(String, Vec<u8>, Vec<(String, String)>)> {
    let trimmed = armored.trim();

    let begin_marker = "-----BEGIN ";
    let end_marker = "-----END ";

    let begin_pos = trimmed.find(begin_marker).context("missing begin marker")?;
    let after_begin = &trimmed[begin_pos + begin_marker.len()..];
    let marker_end = after_begin
        .find("-----")
        .context("malformed begin marker")?;
    let marker = after_begin[..marker_end].to_string();

    let end_pos = trimmed
        .find(&format!("{}{}-----", end_marker, marker))
        .context("missing end marker")?;

    let body_start = begin_pos + begin_marker.len() + marker.len() + "-----\n".len();
    let body_end = end_pos;

    let body = &trimmed[body_start..body_end];

    let mut metadata = Vec::new();
    let mut clean = String::new();
    for line in body.lines() {
        if line.starts_with("-----") {
            continue;
        }
        if let Some(pos) = line.find(": ") {
            let key = &line[..pos];
            let value = &line[pos + 2..];
            if !key.contains(' ') && !key.is_empty() {
                metadata.push((key.to_string(), value.to_string()));
                continue;
            }
        }
        clean.push_str(line);
    }
    let clean: String = clean.chars().filter(|c| !c.is_whitespace()).collect();

    let decoded = base64_decode(&clean).or_else(|_| ascii85_decode(&clean))?;

    Ok((marker, decoded, metadata))
}

fn ascii85_encode(data: &[u8]) -> String {
    let mut result = String::new();

    let mut i = 0;
    while i < data.len() {
        let chunk_end = (i + 4).min(data.len());
        let chunk = &data[i..chunk_end];
        i = chunk_end;

        if chunk.len() == 4 {
            let val = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            if val == 0 {
                result.push('z');
            } else {
                let c0 = ((val / 85u32.pow(4)) % 85) as u8 + 33;
                let c1 = ((val / 85u32.pow(3)) % 85) as u8 + 33;
                let c2 = ((val / 85u32.pow(2)) % 85) as u8 + 33;
                let c3 = ((val / 85) % 85) as u8 + 33;
                let c4 = (val % 85) as u8 + 33;
                result.push(c0 as char);
                result.push(c1 as char);
                result.push(c2 as char);
                result.push(c3 as char);
                result.push(c4 as char);
            }
        } else {
            let mut padded = [0u8; 4];
            padded[..chunk.len()].copy_from_slice(chunk);
            let mut val = u32::from_be_bytes(padded);
            let count = chunk.len() + 1;
            let mut tmp = [0u8; 5];
            for j in (0..5).rev() {
                tmp[j] = (val % 85) as u8 + 33;
                val /= 85;
            }
            for &b in &tmp[..count] {
                result.push(b as char);
            }
        }
    }

    result
}

fn base64_decode(data: &str) -> Result<Vec<u8>> {
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, data)
        .context("base64 decode failed")
}

fn ascii85_decode(data: &str) -> Result<Vec<u8>> {
    let mut expanded = String::with_capacity(data.len());
    for c in data.chars() {
        if c == 'z' {
            expanded.push_str("!!!!!");
        } else {
            expanded.push(c);
        }
    }
    ascii85::decode(&expanded).map_err(|e| anyhow::anyhow!("ascii85 decode failed: {}", e))
}
