//! File format for encrypted/signed payloads.
//!
//! All serialized payloads use the format `AlgorithmList::EncodedPayload`.
//! The [`AlgorithmList`] describes which algorithms were applied (KEM,
//! symmetric cipher, compression, encoding).
//!
//! Compression is at the plaintext level (applied before encryption or
//! after decryption) and is handled by the caller via [`compress`] and
//! [`decompress`]. The [`encode_payload`]/[`decode_payload`] functions
//! only handle encoding (BASE64, ASCII85). The compression algorithm
//! name in the AlgorithmList serves as metadata so that decrypt can
//! auto-detect which decompression to use.

use anyhow::{Context, Result};
use std::str::FromStr;

/// Maximum allowed decompressed output size (100 MiB) to prevent
/// decompression bomb denial-of-service attacks.
const MAX_DECOMPRESSED_SIZE: u64 = 100 * 1024 * 1024;

const SEPARATOR: &str = "::";

/// Canonical algorithm identifiers used in [`AlgorithmList`].
///
/// Includes generic algorithm names (e.g. `ML-KEM`, `BASE64`) and
/// variant-specific names (e.g. `ML-KEM-768`, `ML-DSA-65`) so that
/// the format string can encode exact key algorithm variants.
#[derive(Debug, Clone, PartialEq)]
pub enum Algorithm {
    MlKem,
    MlKem512,
    MlKem768,
    MlKem1024,
    MlDsa,
    MlDsa44,
    MlDsa65,
    MlDsa87,
    XChaCha20Poly1305,
    Aes256Gcm,
    Sha3256,
    Argon2id,
    Zstd,
    Deflate,
    Gzip,
    Bzip2,
    Lzma,
    Base64,
    Ascii85,
}

impl Algorithm {
    /// Return `true` if this is a compression algorithm.
    pub fn is_compression(&self) -> bool {
        matches!(
            self,
            Algorithm::Zstd
                | Algorithm::Deflate
                | Algorithm::Gzip
                | Algorithm::Bzip2
                | Algorithm::Lzma
        )
    }

    /// Return the canonical string name for this algorithm.
    pub fn canonical_name(&self) -> &'static str {
        match self {
            Algorithm::MlKem => "ML-KEM",
            Algorithm::MlKem512 => "ML-KEM-512",
            Algorithm::MlKem768 => "ML-KEM-768",
            Algorithm::MlKem1024 => "ML-KEM-1024",
            Algorithm::MlDsa => "ML-DSA",
            Algorithm::MlDsa44 => "ML-DSA-44",
            Algorithm::MlDsa65 => "ML-DSA-65",
            Algorithm::MlDsa87 => "ML-DSA-87",
            Algorithm::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            Algorithm::Aes256Gcm => "AES-256-GCM",
            Algorithm::Sha3256 => "SHA3-256",
            Algorithm::Argon2id => "Argon2id",
            Algorithm::Zstd => "ZSTD",
            Algorithm::Deflate => "DEFLATE",
            Algorithm::Gzip => "GZIP",
            Algorithm::Bzip2 => "BZIP2",
            Algorithm::Lzma => "LZMA",
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
            "ML-KEM-512" => Ok(Algorithm::MlKem512),
            "ML-KEM-768" => Ok(Algorithm::MlKem768),
            "ML-KEM-1024" => Ok(Algorithm::MlKem1024),
            "ML-DSA" => Ok(Algorithm::MlDsa),
            "ML-DSA-44" => Ok(Algorithm::MlDsa44),
            "ML-DSA-65" => Ok(Algorithm::MlDsa65),
            "ML-DSA-87" => Ok(Algorithm::MlDsa87),
            "XChaCha20-Poly1305" => Ok(Algorithm::XChaCha20Poly1305),
            "AES-256-GCM" => Ok(Algorithm::Aes256Gcm),
            "SHA3-256" => Ok(Algorithm::Sha3256),
            "Argon2id" => Ok(Algorithm::Argon2id),
            "ZSTD" => Ok(Algorithm::Zstd),
            "DEFLATE" => Ok(Algorithm::Deflate),
            "GZIP" => Ok(Algorithm::Gzip),
            "BZIP2" => Ok(Algorithm::Bzip2),
            "LZMA" => Ok(Algorithm::Lzma),
            "BASE64" => Ok(Algorithm::Base64),
            "ASCII85" => Ok(Algorithm::Ascii85),
            _ => Err(anyhow::anyhow!("unknown algorithm: {}", s)),
        }
    }
}

impl Algorithm {
    /// If this is a KEM-variant algorithm, return the corresponding `KemVariant`.
    pub fn to_kem_variant(&self) -> Option<crate::crypto::KemVariant> {
        match self {
            Algorithm::MlKem512 => Some(crate::crypto::KemVariant::MlKem512),
            Algorithm::MlKem768 => Some(crate::crypto::KemVariant::MlKem768),
            Algorithm::MlKem1024 => Some(crate::crypto::KemVariant::MlKem1024),
            _ => None,
        }
    }

    /// If this is a DSA-variant algorithm, return the corresponding `DsaVariant`.
    pub fn to_dsa_variant(&self) -> Option<crate::crypto::DsaVariant> {
        match self {
            Algorithm::MlDsa44 => Some(crate::crypto::DsaVariant::MlDsa44),
            Algorithm::MlDsa65 => Some(crate::crypto::DsaVariant::MlDsa65),
            Algorithm::MlDsa87 => Some(crate::crypto::DsaVariant::MlDsa87),
            _ => None,
        }
    }

    /// Create a KEM-variant algorithm from a `KemVariant`.
    pub fn from_kem_variant(v: crate::crypto::KemVariant) -> Self {
        match v {
            crate::crypto::KemVariant::MlKem512 => Algorithm::MlKem512,
            crate::crypto::KemVariant::MlKem768 => Algorithm::MlKem768,
            crate::crypto::KemVariant::MlKem1024 => Algorithm::MlKem1024,
        }
    }

    /// Create a DSA-variant algorithm from a `DsaVariant`.
    pub fn from_dsa_variant(v: crate::crypto::DsaVariant) -> Self {
        match v {
            crate::crypto::DsaVariant::MlDsa44 => Algorithm::MlDsa44,
            crate::crypto::DsaVariant::MlDsa65 => Algorithm::MlDsa65,
            crate::crypto::DsaVariant::MlDsa87 => Algorithm::MlDsa87,
        }
    }
}

/// Ordered list of algorithms applied to a payload.
///
/// The encoding algorithm always appears last in the list.
/// Compression algorithm names in the list serve as metadata for
/// auto-detection during decrypt — the compression itself is handled
/// by the caller via [`compress`]/[`decompress`].
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

    /// Return the first compression algorithm found in the list, if any.
    pub fn compression(&self) -> Option<&Algorithm> {
        self.algorithms.iter().find(|alg| alg.is_compression())
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

/// Compress `data` using the given compression algorithm.
///
/// Supported algorithms: [`Zstd`](Algorithm::Zstd), [`Deflate`](Algorithm::Deflate),
/// [`Gzip`](Algorithm::Gzip), [`Bzip2`](Algorithm::Bzip2), [`Lzma`](Algorithm::Lzma).
pub fn compress(data: &[u8], alg: &Algorithm) -> Result<Vec<u8>> {
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
        Algorithm::Gzip => {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            use std::io::Write;
            encoder.write_all(data).context("gzip compression failed")?;
            let compressed = encoder.finish().context("gzip compression finish failed")?;
            Ok(compressed)
        }
        Algorithm::Bzip2 => {
            let mut encoder =
                bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
            use std::io::Write;
            encoder
                .write_all(data)
                .context("bzip2 compression failed")?;
            let compressed = encoder
                .finish()
                .context("bzip2 compression finish failed")?;
            Ok(compressed)
        }
        Algorithm::Lzma => {
            let mut compressed = Vec::new();
            lzma_rs::lzma_compress(&mut std::io::Cursor::new(data), &mut compressed)
                .context("lzma compression failed")?;
            Ok(compressed)
        }
        _ => Err(anyhow::anyhow!(
            "algorithm {} is not a compression algorithm",
            alg.canonical_name()
        )),
    }
}

/// Decompress `data` using the given compression algorithm.
///
/// Supported algorithms: [`Zstd`](Algorithm::Zstd), [`Deflate`](Algorithm::Deflate),
/// [`Gzip`](Algorithm::Gzip), [`Bzip2`](Algorithm::Bzip2), [`Lzma`](Algorithm::Lzma).
/// Returns an error if the decompressed output exceeds [`MAX_DECOMPRESSED_SIZE`].
pub fn decompress(data: &[u8], alg: &Algorithm) -> Result<Vec<u8>> {
    let decompressed = match alg {
        Algorithm::Zstd => {
            zstd::decode_all(std::io::Cursor::new(data)).context("zstd decompression failed")?
        }
        Algorithm::Deflate => {
            let mut decoder = flate2::read::ZlibDecoder::new(std::io::Cursor::new(data));
            let mut out = Vec::new();
            use std::io::Read;
            decoder
                .read_to_end(&mut out)
                .context("deflate decompression failed")?;
            out
        }
        Algorithm::Gzip => {
            let mut decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(data));
            let mut out = Vec::new();
            use std::io::Read;
            decoder
                .read_to_end(&mut out)
                .context("gzip decompression failed")?;
            out
        }
        Algorithm::Bzip2 => {
            let mut decoder = bzip2::read::BzDecoder::new(std::io::Cursor::new(data));
            let mut out = Vec::new();
            use std::io::Read;
            decoder
                .read_to_end(&mut out)
                .context("bzip2 decompression failed")?;
            out
        }
        Algorithm::Lzma => {
            let mut out = Vec::new();
            lzma_rs::lzma_decompress(&mut std::io::Cursor::new(data), &mut out)
                .context("lzma decompression failed")?;
            out
        }
        _ => {
            return Err(anyhow::anyhow!(
                "algorithm {} is not a compression algorithm",
                alg.canonical_name()
            ))
        }
    };
    if decompressed.len() > MAX_DECOMPRESSED_SIZE as usize {
        anyhow::bail!(
            "decompressed data too large: {} bytes (max {})",
            decompressed.len(),
            MAX_DECOMPRESSED_SIZE,
        );
    }
    Ok(decompressed)
}

/// Compose a payload by applying all encoding algorithms in the list.
///
/// Only encoding algorithms (BASE64, ASCII85) are applied. Compression
/// is handled separately by the caller via [`compress`]/[`decompress`].
pub fn encode_payload(algorithms: &AlgorithmList, data: &[u8]) -> Result<Vec<u8>> {
    let mut payload = data.to_vec();

    for alg in algorithms.algorithms().iter().rev().skip(1) {
        if let Algorithm::Base64 | Algorithm::Ascii85 = alg {
            payload = encode_raw(&payload, alg)?;
        }
    }

    let encoding_alg = algorithms
        .encoding()
        .ok_or_else(|| anyhow::anyhow!("no encoding algorithm"))?;
    payload = encode_raw(&payload, encoding_alg)?;

    Ok(payload)
}

/// Reverse the [`encode_payload`] transform to recover original data.
///
/// Only encoding algorithms are reversed. Compression is handled
/// separately via [`compress`]/[`decompress`].
pub fn decode_payload(algorithms: &AlgorithmList, data: &[u8]) -> Result<Vec<u8>> {
    let encoding_alg = algorithms
        .encoding()
        .ok_or_else(|| anyhow::anyhow!("no encoding algorithm"))?;
    let mut payload = decode_raw(data, encoding_alg)?;

    for alg in algorithms.algorithms().iter().rev().skip(1) {
        if let Algorithm::Base64 | Algorithm::Ascii85 = alg {
            payload = decode_raw(&payload, alg)?;
        }
    }

    Ok(payload)
}

/// Encode and format as `AlgorithmList::EncodedPayload`.
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
