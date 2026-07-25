//! Key store management in `~/.pqp/keys/`.
//!
//! Each key pair is stored in its own directory named by a 16-hex-char
//! key ID. The directory contains:
//! - `pqp-public.der` — plain public key bytes
//! - `pqp-secret.der` — passphrase-encrypted secret key (Argon2id +
//!   XChaCha20-Poly1305)
//! - `pqp.conf` — TOML metadata (key ID, creation date, user ID,
//!   algorithm identifiers)
//!
//! Identifier resolution ([`resolve_key_id`]) accepts either a key ID
//! (directory name) or a user ID (from `pqp.conf` metadata) for all
//! commands that take a key reference.

use crate::armor;
use crate::armor::Encoding;
use crate::crypto::{keygen, sym};
use crate::crypto::{DsaVariant, KemVariant};
use crate::expiry;
use crate::format;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::OnceLock;
use zeroize::Zeroize;

/// Optional override for the keyring directory path, set via
/// [`set_keyring_override`]. When set, all keyring operations use this
/// path instead of the default XDG / legacy / PQP_HOME resolution.
static KEYRING_OVERRIDE: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Override the keyring directory path for all subsequent keyring operations.
///
/// Pass `None` to clear any override and use the default resolution. This
/// must be called before any keyring operation — it has no effect once
/// keyring functions have been called.
pub fn set_keyring_override(path: Option<PathBuf>) {
    let _ = KEYRING_OVERRIDE.set(path);
}

/// A key-value metadata pair associated with a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataEntry {
    pub key: String,
    pub value: String,
}

/// Metadata for a key pair stored in the keyring.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub key_id: String,
    pub created_at: String,
    pub user_id: String,
    pub kem_algorithm: String,
    pub sign_algorithm: String,
    #[serde(default = "default_encoding")]
    pub encoding_algorithm: String,
    #[serde(default = "default_compress")]
    pub compress_algorithm: String,
    #[serde(default = "default_expiration")]
    pub expiration_date: String,
    #[serde(default)]
    pub metadata: Vec<MetadataEntry>,
    #[serde(default = "default_argon2_mem")]
    pub argon2_mem: u32,
    #[serde(default = "default_argon2_time")]
    pub argon2_time: u32,
    #[serde(default = "default_argon2_par")]
    pub argon2_par: u32,
    /// SHA3-256 fingerprint of the public key material, hex-encoded.
    /// Computed as `hex(SHA3-256(kem_pk || sign_pk))`. Empty for keys
    /// generated before this field was added.
    #[serde(default)]
    pub fingerprint: String,
}

fn default_encoding() -> String {
    "BASE64".into()
}

fn default_compress() -> String {
    "none".into()
}

fn default_expiration() -> String {
    "expired".into()
}

fn default_argon2_mem() -> u32 {
    crate::crypto::sym::DEFAULT_ARGON2_MEM
}

fn default_argon2_time() -> u32 {
    crate::crypto::sym::DEFAULT_ARGON2_TIME
}

fn default_argon2_par() -> u32 {
    crate::crypto::sym::DEFAULT_ARGON2_PAR
}

/// Enriched key information including key type and algorithm details.
#[derive(Debug, Serialize)]
pub struct KeyInfo {
    pub key_id: String,
    pub user_id: String,
    pub created_at: String,
    pub has_public: bool,
    pub has_secret: bool,
    pub kem_algorithm: String,
    pub sign_algorithm: String,
    #[serde(default = "default_encoding")]
    pub encoding_algorithm: String,
    #[serde(default = "default_compress")]
    pub compress_algorithm: String,
    #[serde(default = "default_expiration")]
    pub expiration_date: String,
    #[serde(default)]
    pub metadata: Vec<MetadataEntry>,
    #[serde(default = "default_argon2_mem")]
    pub argon2_mem: u32,
    #[serde(default = "default_argon2_time")]
    pub argon2_time: u32,
    #[serde(default = "default_argon2_par")]
    pub argon2_par: u32,
    #[serde(default)]
    pub fingerprint: String,
}

/// XDG data directory for pqp (`~/.local/share/pqp/`), with
/// `PQP_HOME` override (`$PQP_HOME/.pqp/`) and legacy fallback
/// (`~/.pqp/`) for backward compatibility.
fn pqp_dir() -> Result<PathBuf> {
    // PQP_HOME takes precedence over XDG
    if let Ok(pqp_home) = std::env::var("PQP_HOME") {
        return Ok(PathBuf::from(pqp_home).join(".pqp"));
    }
    let xdg = crate::util::data_dir()
        .context("cannot determine XDG data directory")?
        .join("pqp");
    if xdg.exists() {
        return Ok(xdg);
    }
    let home = crate::util::home_dir().context("cannot determine home directory")?;
    let legacy = home.join(".pqp");
    if legacy.exists() {
        return Ok(legacy);
    }
    Ok(xdg)
}

fn keys_dir() -> Result<PathBuf> {
    if let Some(Some(override_path)) = KEYRING_OVERRIDE.get() {
        return Ok(override_path.clone());
    }
    if let Ok(env_path) = std::env::var("KEYRING_PATH") {
        return Ok(PathBuf::from(env_path));
    }
    Ok(pqp_dir()?.join("keys"))
}

fn timestamp_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let Ok(dur) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return "1970-01-01T00:00:00Z".into();
    };
    let secs = dur.as_secs();
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let remaining = remaining % 3600;
    let minutes = remaining / 60;
    let seconds = remaining % 60;

    let (year, month, day) = days_to_date(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_date(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let (m, y) = if mp < 10 {
        (mp + 3, y)
    } else {
        (mp - 9, y + 1)
    };

    (y, m, d)
}

/// Parse a `KemVariant` from its canonical name string.
pub fn parse_kem_variant(s: &str) -> Option<KemVariant> {
    KemVariant::parse(s)
}

/// Parse a `DsaVariant` from its canonical name string.
pub fn parse_dsa_variant(s: &str) -> Option<DsaVariant> {
    DsaVariant::parse(s)
}

/// Parse an `Encoding` from its canonical name string.
pub fn parse_encoding(s: &str) -> Option<Encoding> {
    Encoding::parse(s)
}

/// Parse a `pqp.conf` file as TOML.
fn parse_conf(content: &str) -> Result<KeyMetadata> {
    toml::from_str(content).context("failed to parse pqp.conf as TOML")
}

/// Read metadata for a key.
pub fn read_metadata(key_id: &str) -> Result<KeyMetadata> {
    let dir = keys_dir()?.join(key_id);
    let conf_path = dir.join("pqp.conf");
    let content =
        std::fs::read_to_string(&conf_path).context(format!("reading {}", conf_path.display()))?;
    parse_conf(&content).context(format!("parsing {}", conf_path.display()))
}

/// Resolve a key identifier (key ID or user ID) to a single key ID.
///
/// First checks if `identifier` is a key ID (directory name). If not,
/// searches all keys for a matching `user_id` in `pqp.conf` metadata.
pub fn resolve_key_id(identifier: &str) -> Result<String> {
    let dir = keys_dir()?;
    if !dir.exists() {
        return Err(anyhow::anyhow!("key not found: {}", identifier));
    }

    let key_dir = dir.join(identifier);
    if key_dir.is_dir() && key_dir.join("pqp.conf").exists() {
        validate_key_id(identifier)?;
        return Ok(identifier.to_string());
    }

    for entry in std::fs::read_dir(&dir).context("reading keys directory")? {
        let entry = entry?;
        let conf_path = entry.path().join("pqp.conf");
        if conf_path.exists() {
            let content = std::fs::read_to_string(&conf_path)
                .context(format!("reading {}", conf_path.display()))?;
            let meta = parse_conf(&content).context(format!("parsing {}", conf_path.display()))?;
            if meta.user_id == identifier {
                return Ok(meta.key_id);
            }
        }
    }

    Err(anyhow::anyhow!(
        "key not found by identifier: {}",
        identifier
    ))
}

/// List all keys in the keyring, sorted by creation date.
///
/// Returns a [`KeyInfo`] for each key that has a `pqp.conf` file,
/// including whether the public and/or secret key files exist.
pub fn list_keys() -> Result<Vec<KeyInfo>> {
    let dir = keys_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut keys = Vec::new();
    for entry in std::fs::read_dir(&dir).context("reading keys directory")? {
        let entry = entry?;
        let conf_path = entry.path().join("pqp.conf");
        if conf_path.exists() {
            let content = std::fs::read_to_string(&conf_path)
                .context(format!("reading {}", conf_path.display()))?;
            let meta: KeyMetadata =
                parse_conf(&content).context(format!("parsing {}", conf_path.display()))?;
            let has_public = entry.path().join("pqp-public.der").exists();
            let has_secret = entry.path().join("pqp-secret.der").exists();
            keys.push(KeyInfo {
                key_id: meta.key_id,
                user_id: meta.user_id,
                created_at: meta.created_at,
                has_public,
                has_secret,
                kem_algorithm: meta.kem_algorithm,
                sign_algorithm: meta.sign_algorithm,
                encoding_algorithm: meta.encoding_algorithm,
                compress_algorithm: meta.compress_algorithm,
                expiration_date: meta.expiration_date,
                metadata: meta.metadata,
                argon2_mem: meta.argon2_mem,
                argon2_time: meta.argon2_time,
                argon2_par: meta.argon2_par,
                fingerprint: meta.fingerprint,
            });
        }
    }
    keys.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Ok(keys)
}

/// Generate a new key pair and store it in the keyring.
///
/// Accepts algorithm variants and an optional encoding. Defaults to
/// ML-KEM-768, ML-DSA-65, and BASE64 if variants are not specified.
#[allow(clippy::too_many_arguments)]
pub fn generate_key(
    user_id: &str,
    passphrase: &str,
    kem_variant: KemVariant,
    dsa_variant: DsaVariant,
    encoding: Encoding,
    compress: &str,
    expiration_date: &str,
    metadata: Vec<MetadataEntry>,
    argon2_mem: u32,
    argon2_time: u32,
    argon2_par: u32,
) -> Result<KeyMetadata> {
    let keypair = keygen::generate(kem_variant, dsa_variant)?;

    let key_id = generate_key_id()?;
    let now = timestamp_iso8601();

    let public_bytes = [
        keypair.kem_public.as_bytes(),
        keypair.sign_public.as_bytes(),
    ]
    .concat();

    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(&public_bytes);
    let fingerprint = crate::util::hex_encode(&hasher.finalize());

    let meta = KeyMetadata {
        key_id: key_id.clone(),
        created_at: now,
        user_id: user_id.to_string(),
        kem_algorithm: kem_variant.as_str().into(),
        sign_algorithm: dsa_variant.as_str().into(),
        encoding_algorithm: encoding.as_str().into(),
        compress_algorithm: compress.to_string(),
        expiration_date: expiry::parse_expiration(expiration_date)
            .context("parsing expiration date")?,
        metadata,
        argon2_mem,
        argon2_time,
        argon2_par,
        fingerprint,
    };

    let dir = keys_dir()?.join(&key_id);
    std::fs::create_dir_all(&dir).context("creating key directory")?;

    std::fs::write(dir.join("pqp-public.der"), &public_bytes).context("writing public key")?;

    let secret_bytes = [
        keypair.kem_secret.as_bytes(),
        keypair.sign_secret.as_bytes(),
    ]
    .concat();
    let salt = generate_salt()?;
    let wrapping_key = sym::derive_key(passphrase, &salt, argon2_mem, argon2_time, argon2_par)?;
    let (nonce, encrypted_secret) = sym::encrypt(&wrapping_key, &secret_bytes)?;

    let mut wrapped = Vec::new();
    wrapped.extend_from_slice(&salt);
    wrapped.extend_from_slice(&nonce);
    wrapped.extend_from_slice(&encrypted_secret);

    let secret_path = dir.join("pqp-secret.der");
    std::fs::write(&secret_path, &wrapped).context("writing secret key")?;
    std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))?;

    let conf_path = dir.join("pqp.conf");
    let conf_toml = toml::to_string_pretty(&meta).context("serializing key metadata")?;
    std::fs::write(&conf_path, &conf_toml).context("writing key config")?;
    std::fs::set_permissions(&conf_path, std::fs::Permissions::from_mode(0o600))?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;

    Ok(meta)
}

/// Load a public key from the keyring, returning raw bytes and algorithm info.
///
/// Returns `(kem_pk_bytes, sign_pk_bytes, kem_algorithm, sign_algorithm)`.
pub fn load_public_key(key_id: &str) -> Result<(Vec<u8>, Vec<u8>, String, String)> {
    let meta = read_metadata(key_id)?;
    let kem_variant = KemVariant::parse(&meta.kem_algorithm)
        .context(format!("unknown KEM algorithm: {}", meta.kem_algorithm))?;
    let dsa_variant = DsaVariant::parse(&meta.sign_algorithm)
        .context(format!("unknown sign algorithm: {}", meta.sign_algorithm))?;

    let dir = keys_dir()?.join(key_id);
    let public_path = dir.join("pqp-public.der");
    let data = std::fs::read(&public_path).context(format!("reading {}", public_path.display()))?;

    let kem_pk_len = kem_variant.public_key_len();
    let sign_pk_len = dsa_variant.public_key_len();
    if data.len() < kem_pk_len + sign_pk_len {
        return Err(anyhow::anyhow!("public key data too short"));
    }
    let kem_pk = data[..kem_pk_len].to_vec();
    let sign_pk = data[kem_pk_len..kem_pk_len + sign_pk_len].to_vec();

    Ok((kem_pk, sign_pk, meta.kem_algorithm, meta.sign_algorithm))
}

/// Load and decrypt a secret key from the keyring.
///
/// Returns `(kem_sk_bytes, sign_sk_bytes, kem_algorithm, sign_algorithm)`.
/// The file format is: salt (16) || nonce (24) || XChaCha20-Poly1305 ciphertext.
pub fn load_secret_key(
    key_id: &str,
    passphrase: &str,
) -> Result<(Vec<u8>, Vec<u8>, String, String)> {
    let meta = read_metadata(key_id)?;
    let kem_variant = KemVariant::parse(&meta.kem_algorithm)
        .context(format!("unknown KEM algorithm: {}", meta.kem_algorithm))?;

    let dir = keys_dir()?.join(key_id);
    let secret_path = dir.join("pqp-secret.der");
    let wrapped =
        std::fs::read(&secret_path).context(format!("reading {}", secret_path.display()))?;

    let salt_len = 16;
    let nonce_len = 24;
    if wrapped.len() < salt_len + nonce_len {
        return Err(anyhow::anyhow!("wrapped secret key too short"));
    }

    let salt = &wrapped[..salt_len];
    let nonce_arr: [u8; 24] = wrapped[salt_len..salt_len + nonce_len]
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid nonce length"))?;
    let encrypted = &wrapped[salt_len + nonce_len..];

    let wrapping_key = sym::derive_key(
        passphrase,
        salt,
        meta.argon2_mem,
        meta.argon2_time,
        meta.argon2_par,
    )?;
    let mut secret_bytes = sym::decrypt(&wrapping_key, &nonce_arr, encrypted)?;

    let kem_sk_len = kem_variant.secret_key_len();
    let sign_sk_len = 32;
    if secret_bytes.len() < kem_sk_len + sign_sk_len {
        return Err(anyhow::anyhow!("decrypted secret key data too short"));
    }
    let kem_sk = secret_bytes[..kem_sk_len].to_vec();
    let sign_sk = secret_bytes[kem_sk_len..kem_sk_len + sign_sk_len].to_vec();

    secret_bytes.zeroize();

    Ok((kem_sk, sign_sk, meta.kem_algorithm, meta.sign_algorithm))
}

/// Export a public key as an ASCII-armored string, using the key's preferred encoding.
///
/// The armor includes system metadata headers (User-ID, Expiration-Date, Created, KEM,
/// DSA, Compress, Encoding, Argon2-*) so import can restore the original key metadata.
pub fn export_public_key(key_id: &str) -> Result<String> {
    let meta = read_metadata(key_id)?;
    let encoding = Encoding::parse(&meta.encoding_algorithm)
        .context(format!("unknown encoding: {}", meta.encoding_algorithm))?;

    let dir = keys_dir()?.join(key_id);
    let public_bytes = std::fs::read(dir.join("pqp-public.der"))
        .context(format!("reading public key for {}", key_id))?;

    let marker = format!("PQP PUBLIC KEY {}", key_id);

    // System metadata headers first, then user-defined metadata
    let mut meta_pairs: Vec<(String, String)> = vec![
        ("User-ID".into(), meta.user_id),
        ("Created".into(), meta.created_at),
        ("Expiration-Date".into(), meta.expiration_date),
        ("KEM".into(), meta.kem_algorithm),
        ("DSA".into(), meta.sign_algorithm),
        ("Compress".into(), meta.compress_algorithm),
        ("Encoding".into(), meta.encoding_algorithm),
        ("Argon2-Mem".into(), meta.argon2_mem.to_string()),
        ("Argon2-Time".into(), meta.argon2_time.to_string()),
        ("Argon2-Par".into(), meta.argon2_par.to_string()),
        ("Fingerprint".into(), meta.fingerprint),
    ];
    for entry in &meta.metadata {
        meta_pairs.push((entry.key.clone(), entry.value.clone()));
    }
    armor::armor(&public_bytes, &marker, &encoding, &meta_pairs)
}

/// Pack public key bytes with metadata into a payload for PQP format.
///
/// Format: `b"PQPM"` + 4-byte BE TOML length + TOML metadata + key bytes.
fn pack_pqp_payload(meta: &KeyMetadata, key_bytes: &[u8]) -> Result<Vec<u8>> {
    let meta_toml = toml::to_string_pretty(meta)?;
    let meta_bytes = meta_toml.as_bytes();
    let len = meta_bytes.len() as u32;
    let mut payload = Vec::with_capacity(8 + meta_bytes.len() + key_bytes.len());
    payload.extend_from_slice(b"PQPM");
    payload.extend_from_slice(&len.to_be_bytes());
    payload.extend_from_slice(meta_bytes);
    payload.extend_from_slice(key_bytes);
    Ok(payload)
}

/// Unpack metadata and key bytes from a PQP payload.
///
/// Detects the new format (magic `b"PQPM"` prefix) vs. old format (raw key bytes).
/// Returns (KeyMetadata, key_bytes) where the key_id in metadata is from the
/// exported key (caller should override it).
fn unpack_pqp_payload(
    payload: &[u8],
    kem_alg: &str,
    dsa_alg: &str,
) -> Result<(KeyMetadata, Vec<u8>)> {
    // Try new format with magic prefix
    if payload.starts_with(b"PQPM") && payload.len() >= 8 {
        let meta_len = u32::from_be_bytes(
            payload[4..8]
                .try_into()
                .expect("4 bytes for metadata length"),
        ) as usize;
        if 8 + meta_len <= payload.len() {
            let meta_str = std::str::from_utf8(&payload[8..8 + meta_len])
                .context("PQP metadata is not valid UTF-8")?;
            if let Ok(meta) = toml::from_str::<KeyMetadata>(meta_str) {
                let key_bytes = payload[8 + meta_len..].to_vec();
                return Ok((meta, key_bytes));
            }
        }
    }
    // Fallback: old format — entire payload is key bytes, use defaults for metadata
    let now = timestamp_iso8601();
    let meta = KeyMetadata {
        key_id: String::new(),
        created_at: now,
        user_id: "imported".into(),
        kem_algorithm: kem_alg.into(),
        sign_algorithm: dsa_alg.into(),
        encoding_algorithm: "BASE64".into(),
        compress_algorithm: "none".into(),
        expiration_date: default_expiration(),
        metadata: Vec::new(),
        argon2_mem: default_argon2_mem(),
        argon2_time: default_argon2_time(),
        argon2_par: default_argon2_par(),
        fingerprint: String::new(),
    };
    Ok((meta, payload.to_vec()))
}

/// Export a public key in PQP format (`AlgorithmList::EncodedPayload`).
///
/// The format embeds KEM and DSA variant names in the algorithm string,
/// making it self-describing. Example:
/// `ML-KEM-768+ML-DSA-65+ZSTD+BASE64::<base64 payload>`
///
/// If `compress` is `Some(alg)`, the key bytes are compressed with the
/// given algorithm before encoding. The compression algorithm name is
/// included in the AlgorithmList so import can auto-detect it.
pub fn export_public_key_pqp(key_id: &str, compress: Option<&format::Algorithm>) -> Result<String> {
    let meta = read_metadata(key_id)?;
    let kem_variant = KemVariant::parse(&meta.kem_algorithm)
        .context(format!("unknown KEM algorithm: {}", meta.kem_algorithm))?;
    let dsa_variant = DsaVariant::parse(&meta.sign_algorithm)
        .context(format!("unknown sign algorithm: {}", meta.sign_algorithm))?;
    let encoding = Encoding::parse(&meta.encoding_algorithm)
        .context(format!("unknown encoding: {}", meta.encoding_algorithm))?;

    let dir = keys_dir()?.join(key_id);
    let public_bytes = std::fs::read(dir.join("pqp-public.der"))
        .context(format!("reading public key for {}", key_id))?;

    // Pack metadata + key bytes into a single payload
    let packed = pack_pqp_payload(&meta, &public_bytes)?;

    let data = if let Some(alg) = compress {
        format::compress(&packed, alg)?
    } else {
        packed
    };

    let mut alg_vec = vec![
        format::Algorithm::from_kem_variant(kem_variant),
        format::Algorithm::from_dsa_variant(dsa_variant),
    ];
    if let Some(alg) = compress {
        alg_vec.push(alg.clone());
    }
    alg_vec.push(match encoding {
        Encoding::Base64 => format::Algorithm::Base64,
        Encoding::Ascii85 => format::Algorithm::Ascii85,
    });

    let algorithms = format::AlgorithmList::new(alg_vec);
    let serialized = format::serialize(&algorithms, &data)?;
    Ok(String::from_utf8(serialized)?)
}

/// Import a public key from PQP format (`AlgorithmList::EncodedPayload`).
///
/// Returns the imported key ID. The KEM and DSA variants are extracted
/// from the algorithm string. If the payload was compressed, it is
/// automatically decompressed using the algorithm stored in the list.
/// Metadata (user_id, expiration_date, etc.) is restored from the payload.
pub fn import_public_key_from_pqp(data: &str) -> Result<String> {
    let (algorithms, mut payload) =
        format::deserialize(data.as_bytes()).context("parsing PQP key data")?;

    let kem_variant = algorithms
        .algorithms()
        .iter()
        .find_map(|a| a.to_kem_variant())
        .context("no KEM variant found in PQP key data")?;
    let dsa_variant = algorithms
        .algorithms()
        .iter()
        .find_map(|a| a.to_dsa_variant())
        .context("no DSA variant found in PQP key data")?;

    if let Some(alg) = algorithms.compression() {
        payload = format::decompress(&payload, alg)?;
    }

    // Unpack metadata + key bytes (handles both new and old format)
    let (exported_meta, key_bytes) =
        unpack_pqp_payload(&payload, kem_variant.as_str(), dsa_variant.as_str())?;

    let kem_pk_len = kem_variant.public_key_len();
    let dsa_pk_len = dsa_variant.public_key_len();
    if key_bytes.len() < kem_pk_len + dsa_pk_len {
        return Err(anyhow::anyhow!("public key payload too short"));
    }

    let key_id = generate_key_id()?;
    let dir = keys_dir()?.join(&key_id);
    std::fs::create_dir_all(&dir).context("creating key directory for import")?;

    let pub_path = dir.join("pqp-public.der");
    std::fs::write(&pub_path, &key_bytes)?;
    std::fs::set_permissions(&pub_path, std::fs::Permissions::from_mode(0o644))?;

    // Use exported metadata fields, but always generate a fresh key_id
    let meta = KeyMetadata {
        key_id: key_id.clone(),
        created_at: exported_meta.created_at,
        user_id: exported_meta.user_id,
        kem_algorithm: kem_variant.as_str().into(),
        sign_algorithm: dsa_variant.as_str().into(),
        encoding_algorithm: exported_meta.encoding_algorithm,
        compress_algorithm: exported_meta.compress_algorithm,
        expiration_date: exported_meta.expiration_date,
        metadata: exported_meta.metadata,
        argon2_mem: exported_meta.argon2_mem,
        argon2_time: exported_meta.argon2_time,
        argon2_par: exported_meta.argon2_par,
        fingerprint: exported_meta.fingerprint,
    };
    let conf_path = dir.join("pqp.conf");
    let conf_toml = toml::to_string_pretty(&meta)?;
    std::fs::write(&conf_path, &conf_toml)?;
    std::fs::set_permissions(&conf_path, std::fs::Permissions::from_mode(0o600))?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;

    Ok(key_id)
}

fn validate_key_id(key_id: &str) -> Result<()> {
    if key_id.len() == 16 && key_id.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(anyhow::anyhow!("invalid key ID: {}", key_id))
    }
}

/// Import an ASCII-armored public key into the keyring.
///
/// Restores system metadata (user_id, expiration_date, algorithm variants, etc.) from
/// the armor headers. Returns the imported key ID.
pub fn import_public_key(armored: &str) -> Result<String> {
    let (marker, decoded, armored_metadata) = armor::unarmor(armored)?;

    let key_id = marker
        .strip_prefix("PQP PUBLIC KEY ")
        .ok_or_else(|| anyhow::anyhow!("invalid marker: {}", marker))?
        .trim()
        .to_string();
    validate_key_id(&key_id).context("invalid key ID in armor marker")?;

    let dir = keys_dir()?.join(&key_id);
    std::fs::create_dir_all(&dir).context("creating key directory for import")?;

    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;

    let metadata_path = dir.join("pqp.conf");
    if !metadata_path.exists() {
        // Parse system headers from armor metadata
        let mut user_id = "imported".to_string();
        let mut created_at = timestamp_iso8601();
        let mut kem_algorithm = "ML-KEM-768".to_string();
        let mut sign_algorithm = "ML-DSA-65".to_string();
        let mut encoding_algorithm = "BASE64".to_string();
        let mut compress_algorithm = "none".to_string();
        let mut expiration_date = default_expiration();
        let mut argon2_mem = default_argon2_mem();
        let mut argon2_time = default_argon2_time();
        let mut argon2_par = default_argon2_par();
        let mut fingerprint = String::new();
        let mut user_metadata: Vec<MetadataEntry> = Vec::new();

        for (k, v) in armored_metadata {
            match k.as_str() {
                "User-ID" => user_id = v,
                "Created" => created_at = v,
                "Expiration-Date" => expiration_date = v,
                "KEM" => kem_algorithm = v,
                "DSA" => sign_algorithm = v,
                "Compress" => compress_algorithm = v,
                "Encoding" => encoding_algorithm = v,
                "Argon2-Mem" => {
                    argon2_mem = v.parse().unwrap_or(default_argon2_mem());
                }
                "Argon2-Time" => {
                    argon2_time = v.parse().unwrap_or(default_argon2_time());
                }
                "Argon2-Par" => {
                    argon2_par = v.parse().unwrap_or(default_argon2_par());
                }
                "Fingerprint" => fingerprint = v,
                _ => user_metadata.push(MetadataEntry { key: k, value: v }),
            }
        }

        let meta = KeyMetadata {
            key_id: key_id.clone(),
            created_at,
            user_id,
            kem_algorithm,
            sign_algorithm,
            encoding_algorithm,
            compress_algorithm,
            expiration_date,
            metadata: user_metadata,
            argon2_mem,
            argon2_time,
            argon2_par,
            fingerprint,
        };
        let conf_toml = toml::to_string_pretty(&meta)?;
        std::fs::write(&metadata_path, &conf_toml)?;
        std::fs::set_permissions(&metadata_path, std::fs::Permissions::from_mode(0o600))?;
    }

    let pub_path = dir.join("pqp-public.der");
    std::fs::write(&pub_path, &decoded)?;
    std::fs::set_permissions(&pub_path, std::fs::Permissions::from_mode(0o644))?;

    Ok(key_id)
}

/// Resolve an identifier to all matching key IDs.
///
/// If `identifier` is a key ID (directory name), returns a single-element
/// vector. Otherwise, finds all keys whose `user_id` matches.
pub fn resolve_key_ids(identifier: &str) -> Result<Vec<String>> {
    let dir = keys_dir()?;
    if !dir.exists() {
        return Err(anyhow::anyhow!("key not found: {}", identifier));
    }

    let key_dir = dir.join(identifier);
    if key_dir.is_dir() && key_dir.join("pqp.conf").exists() {
        validate_key_id(identifier)?;
        return Ok(vec![identifier.to_string()]);
    }

    let mut matches = Vec::new();
    for entry in std::fs::read_dir(&dir).context("reading keys directory")? {
        let entry = entry?;
        let conf_path = entry.path().join("pqp.conf");
        if conf_path.exists() {
            let content = std::fs::read_to_string(&conf_path)
                .context(format!("reading {}", conf_path.display()))?;
            let meta: KeyMetadata =
                parse_conf(&content).context(format!("parsing {}", conf_path.display()))?;
            if meta.user_id == identifier {
                matches.push(meta.key_id);
            }
        }
    }

    if matches.is_empty() {
        return Err(anyhow::anyhow!("key not found: {}", identifier));
    }

    Ok(matches)
}

/// Remove a key from the keyring by key ID.
///
/// Always removes the public key and metadata. If `remove_private` is
/// `true`, also removes the secret key. Only removes the key directory
/// if it becomes empty after file removal.
pub fn remove_key(key_id: &str, remove_private: bool) -> Result<()> {
    let dir = keys_dir()?.join(key_id);

    if !dir.exists() {
        return Err(anyhow::anyhow!(
            "key directory not found: {}",
            dir.display()
        ));
    }

    let pub_path = dir.join("pqp-public.der");
    if pub_path.exists() {
        std::fs::remove_file(&pub_path).context(format!("removing {}", pub_path.display()))?;
    }

    if remove_private {
        let sec_path = dir.join("pqp-secret.der");
        if sec_path.exists() {
            std::fs::remove_file(&sec_path).context(format!("removing {}", sec_path.display()))?;
        }
    }

    let conf_path = dir.join("pqp.conf");
    if conf_path.exists() {
        std::fs::remove_file(&conf_path).context(format!("removing {}", conf_path.display()))?;
    }

    // Only remove directory if it's now empty
    if dir.exists()
        && dir
            .read_dir()
            .map(|mut it| it.next().is_none())
            .unwrap_or(false)
    {
        std::fs::remove_dir(&dir).context(format!("removing directory {}", dir.display()))?;
    }

    Ok(())
}

/// Remove all keys from the keyring.
///
/// Iterates all keys and removes each one. If `remove_private` is `true`,
/// also removes private keys. Returns the number of keys removed.
pub fn purge_keys(remove_private: bool) -> Result<usize> {
    let keys = list_keys()?;
    let count = keys.len();
    for key in &keys {
        remove_key(&key.key_id, remove_private)?;
    }
    Ok(count)
}

/// Check whether a key is expired based on its stored metadata.
///
/// Returns `None` if the metadata cannot be read or has no valid
/// expiration date; otherwise returns `Some(true)` if expired.
pub fn check_key_expired(key_id: &str) -> Result<bool> {
    let meta = read_metadata(key_id)?;
    Ok(expiry::is_expired(&meta.expiration_date))
}

fn generate_key_id() -> Result<String> {
    let mut buf = [0u8; 8];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut buf);
    Ok(crate::util::hex_encode(&buf))
}

fn generate_salt() -> Result<[u8; 16]> {
    let mut salt = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut salt);
    Ok(salt)
}
