//! File format for encrypted/signed payloads.
//!
//! All serialized payloads use the format `AlgorithmList::EncodedPayload`.
//! The [`AlgorithmList`] describes which algorithms were applied (KEM,
//! symmetric cipher, compression, encoding). The payload is processed
//! in reverse order during encoding and forward during decoding.

use anyhow::{Context, Result};
use std::str::FromStr;

const SEPARATOR: &str = "::";

/// Canonical algorithm identifiers used in [`AlgorithmList`].
#[derive(Debug, Clone, PartialEq)]
pub enum Algorithm {
    MlKem,
    MlDsa,
    XChaCha20Poly1305,
    Aes256Gcm,
    Sha3256,
    Argon2id,
    Zstd,
    Deflate,
    Base64,
    Ascii85,
}

impl Algorithm {
    /// Return the canonical string name for this algorithm.
    pub fn canonical_name(&self) -> &'static str {
        match self {
            Algorithm::MlKem => "ML-KEM",
            Algorithm::MlDsa => "ML-DSA",
            Algorithm::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            Algorithm::Aes256Gcm => "AES-256-GCM",
            Algorithm::Sha3256 => "SHA3-256",
            Algorithm::Argon2id => "Argon2id",
            Algorithm::Zstd => "ZSTD",
            Algorithm::Deflate => "DEFLATE",
            Algorithm::Base64 => "BASE64",
            Algorithm::Ascii85 => "ASCII85",
        }
    }
}

impl FromStr for Algorithm {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "ML-KEM" => Ok(Algorithm::MlKem),
            "ML-DSA" => Ok(Algorithm::MlDsa),
            "XChaCha20-Poly1305" => Ok(Algorithm::XChaCha20Poly1305),
            "AES-256-GCM" => Ok(Algorithm::Aes256Gcm),
            "SHA3-256" => Ok(Algorithm::Sha3256),
            "Argon2id" => Ok(Algorithm::Argon2id),
            "ZSTD" => Ok(Algorithm::Zstd),
            "DEFLATE" => Ok(Algorithm::Deflate),
            "BASE64" => Ok(Algorithm::Base64),
            "ASCII85" => Ok(Algorithm::Ascii85),
            _ => Err(anyhow::anyhow!("unknown algorithm: {}", s)),
        }
    }
}

/// Ordered list of algorithms applied to a payload.
///
/// The encoding algorithm always appears last in the list.
/// Compression and encoding steps are applied inside-out during
/// encoding and outside-in during decoding.
#[derive(Debug, Clone)]
pub struct AlgorithmList {
    algorithms: Vec<Algorithm>,
}

impl AlgorithmList {
    /// Create a new algorithm list from the given algorithms in canonical order.
    pub fn new(algorithms: Vec<Algorithm>) -> Self {
        Self { algorithms }
    }

    /// Return a slice of all algorithms in this list.
    pub fn algorithms(&self) -> &[Algorithm] {
        &self.algorithms
    }

    /// Return the encoding algorithm (the last in the list), if any.
    pub fn encoding(&self) -> Option<&Algorithm> {
        self.algorithms.last()
    }

    /// Parse a `+`-separated algorithm string into an [`AlgorithmList`].
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('+').collect();
        if parts.is_empty() {
            return Err(anyhow::anyhow!("empty algorithm list"));
        }
        let algorithms: Vec<Algorithm> = parts
            .iter()
            .map(|p| Algorithm::from_str(p.trim()))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { algorithms })
    }
}

/// Parse a `+`-separated algorithm string.
impl FromStr for AlgorithmList {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        AlgorithmList::parse(s)
    }
}

/// Format as `+`-separated canonical names.
impl std::fmt::Display for AlgorithmList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.algorithms
                .iter()
                .map(|a| a.canonical_name())
                .collect::<Vec<_>>()
                .join("+")
        )
    }
}

fn ascii85_encode(data: &[u8]) -> String {
    let mut result = String::new();
    result.push_str("<~");

    let mut i = 0;
    while i < data.len() {
        let chunk_end = (i + 4).min(data.len());
        let chunk = &data[i..chunk_end];

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
            let val = u32::from_be_bytes(padded);
            let count = chunk.len() + 1;
            let c0 = ((val / 85u32.pow(4)) % 85) as u8 + 33;
            let c1 = ((val / 85u32.pow(3)) % 85) as u8 + 33;
            let c2 = ((val / 85u32.pow(2)) % 85) as u8 + 33;
            let c3 = ((val / 85) % 85) as u8 + 33;
            let c4 = (val % 85) as u8 + 33;
            for j in 0..count {
                match j {
                    0 => result.push(c0 as char),
                    1 => result.push(c1 as char),
                    2 => result.push(c2 as char),
                    3 => result.push(c3 as char),
                    4 => result.push(c4 as char),
                    _ => {}
                }
            }
        }

        i += 4;
    }

    result.push_str("~>");
    result
}

fn encode_raw(data: &[u8], alg: &Algorithm) -> Result<Vec<u8>> {
    match alg {
        Algorithm::Base64 => Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            data,
        )
        .into_bytes()),
        Algorithm::Ascii85 => {
            let encoded = ascii85_encode(data);
            Ok(encoded.into_bytes())
        }
        _ => Err(anyhow::anyhow!(
            "algorithm {} is not an encoding algorithm",
            alg.canonical_name()
        )),
    }
}

fn decode_raw(data: &[u8], alg: &Algorithm) -> Result<Vec<u8>> {
    match alg {
        Algorithm::Base64 => {
            let s = std::str::from_utf8(data).context("base64 input is not valid UTF-8")?;
            let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s)
                .context("base64 decode failed")?;
            Ok(bytes)
        }
        Algorithm::Ascii85 => {
            let s = std::str::from_utf8(data).context("ascii85 input is not valid UTF-8")?;
            let bytes =
                ascii85::decode(s).map_err(|e| anyhow::anyhow!("ascii85 decode failed: {}", e))?;
            Ok(bytes)
        }
        _ => Err(anyhow::anyhow!(
            "algorithm {} is not an encoding algorithm",
            alg.canonical_name()
        )),
    }
}

fn compress(data: &[u8], alg: &Algorithm) -> Result<Vec<u8>> {
    match alg {
        Algorithm::Zstd => {
            let compressed = zstd::encode_all(std::io::Cursor::new(data), 3)
                .context("zstd compression failed")?;
            Ok(compressed)
        }
        Algorithm::Deflate => {
            let mut encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            use std::io::Write;
            encoder
                .write_all(data)
                .context("deflate compression failed")?;
            let compressed = encoder
                .finish()
                .context("deflate compression finish failed")?;
            Ok(compressed)
        }
        _ => Err(anyhow::anyhow!(
            "algorithm {} is not a compression algorithm",
            alg.canonical_name()
        )),
    }
}

fn decompress(data: &[u8], alg: &Algorithm) -> Result<Vec<u8>> {
    match alg {
        Algorithm::Zstd => {
            let decompressed = zstd::decode_all(std::io::Cursor::new(data))
                .context("zstd decompression failed")?;
            Ok(decompressed)
        }
        Algorithm::Deflate => {
            let mut decoder = flate2::read::ZlibDecoder::new(std::io::Cursor::new(data));
            let mut decompressed = Vec::new();
            use std::io::Read;
            decoder
                .read_to_end(&mut decompressed)
                .context("deflate decompression failed")?;
            Ok(decompressed)
        }
        _ => Err(anyhow::anyhow!(
            "algorithm {} is not a compression algorithm",
            alg.canonical_name()
        )),
    }
}

/// Compose a payload by applying all algorithms in the list.
pub fn encode_payload(algorithms: &AlgorithmList, data: &[u8]) -> Result<Vec<u8>> {
    let mut payload = data.to_vec();

    for alg in algorithms.algorithms().iter().rev().skip(1) {
        match alg {
            Algorithm::Zstd | Algorithm::Deflate => {
                payload = compress(&payload, alg)?;
            }
            Algorithm::Base64 | Algorithm::Ascii85 => {
                payload = encode_raw(&payload, alg)?;
            }
            _ => {}
        }
    }

    let encoding_alg = algorithms
        .encoding()
        .ok_or_else(|| anyhow::anyhow!("no encoding algorithm"))?;
    payload = encode_raw(&payload, encoding_alg)?;

    Ok(payload)
}

/// Reverse the [`encode_payload`] transform to recover original data.
pub fn decode_payload(algorithms: &AlgorithmList, data: &[u8]) -> Result<Vec<u8>> {
    let encoding_alg = algorithms
        .encoding()
        .ok_or_else(|| anyhow::anyhow!("no encoding algorithm"))?;
    let mut payload = decode_raw(data, encoding_alg)?;

    for alg in algorithms.algorithms().iter().rev().skip(1) {
        match alg {
            Algorithm::Base64 | Algorithm::Ascii85 => {
                payload = decode_raw(&payload, alg)?;
            }
            Algorithm::Zstd | Algorithm::Deflate => {
                payload = decompress(&payload, alg)?;
            }
            _ => {}
        }
    }

    Ok(payload)
}

/// Encode and format as `AlgorithmList::EncodedPayload`.
#[allow(dead_code)]
pub fn serialize(algorithms: &AlgorithmList, data: &[u8]) -> Result<Vec<u8>> {
    let encoded = encode_payload(algorithms, data)?;
    let header = algorithms.to_string();
    let mut result = header.into_bytes();
    result.extend_from_slice(SEPARATOR.as_bytes());
    result.extend_from_slice(&encoded);
    Ok(result)
}

/// Parse `AlgorithmList::EncodedPayload` and return the algorithms and decoded payload.
pub fn deserialize(data: &[u8]) -> Result<(AlgorithmList, Vec<u8>)> {
    let text = std::str::from_utf8(data).context("not valid UTF-8")?;

    let pos = text
        .find(SEPARATOR)
        .ok_or_else(|| anyhow::anyhow!("missing separator in format"))?;

    let alg_str = &text[..pos];
    let encoded = &text[pos + SEPARATOR.len()..];

    let algorithms = AlgorithmList::parse(alg_str)?;
    let payload = decode_payload(&algorithms, encoded.as_bytes())?;

    Ok((algorithms, payload))
}
