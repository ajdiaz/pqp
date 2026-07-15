use anyhow::{Context, Result};

const LINE_WIDTH: usize = 64;

pub fn armor(data: &[u8], marker: &str) -> Result<String> {
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data);

    let mut result = String::new();
    result.push_str(&format!("-----BEGIN {}-----\n", marker));

    for chunk in encoded.as_bytes().chunks(LINE_WIDTH) {
        result.push_str(&String::from_utf8_lossy(chunk));
        result.push('\n');
    }

    result.push_str(&format!("-----END {}-----\n", marker));
    Ok(result)
}

pub fn unarmor(armored: &str) -> Result<(String, Vec<u8>)> {
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
    let clean: String = body
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .concat()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &clean)
        .context("base64 decode failed in armor")?;

    Ok((marker, decoded))
}
