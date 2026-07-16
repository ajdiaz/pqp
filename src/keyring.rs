//! Key store management in `~/.pqp/keys/`.
//!
//! Each key pair is stored in its own directory named by a 16-hex-char
//! key ID. The directory contains:
//! - `pqp-public.der` — plain public key bytes
//! - `pqp-secret.der` — passphrase-encrypted secret key (Argon2id +
//!   XChaCha20-Poly1305)
//! - `pqp.conf` — JSON metadata (key ID, creation date, user ID)
//!
//! Identifier resolution ([`resolve_key_id`]) accepts either a key ID
//! (directory name) or a user ID (from `pqp.conf` metadata) for all
//! commands that take a key reference.

use crate::armor;
use crate::crypto::{keygen, sym};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::Zeroize;

/// Metadata for a key pair stored in the keyring.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub key_id: String,
    pub created_at: String,
    pub user_id: String,
    pub kem_algorithm: String,
    pub sign_algorithm: String,
}

fn pqp_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("cannot determine home directory")?;
    Ok(home.join(".pqp"))
}

fn keys_dir() -> Result<PathBuf> {
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

pub fn resolve_key_id(identifier: &str) -> Result<String> {
    let dir = keys_dir()?;
    if !dir.exists() {
        return Err(anyhow::anyhow!("key not found: {}", identifier));
    }

    let key_dir = dir.join(identifier);
    if key_dir.is_dir() && key_dir.join("pqp.conf").exists() {
        return Ok(identifier.to_string());
    }

    for entry in std::fs::read_dir(&dir).context("reading keys directory")? {
        let entry = entry?;
        let conf_path = entry.path().join("pqp.conf");
        if conf_path.exists() {
            let content = std::fs::read_to_string(&conf_path)
                .context(format!("reading {}", conf_path.display()))?;
            let meta: KeyMetadata = serde_json::from_str(&content)
                .context(format!("parsing {}", conf_path.display()))?;
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

pub fn list_keys() -> Result<Vec<KeyMetadata>> {
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
            let meta: KeyMetadata = serde_json::from_str(&content)
                .context(format!("parsing {}", conf_path.display()))?;
            keys.push(meta);
        }
    }
    keys.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Ok(keys)
}

pub fn generate_key(user_id: &str, passphrase: &str) -> Result<KeyMetadata> {
    let keypair = keygen::generate()?;

    let key_id = generate_key_id()?;
    let now = timestamp_iso8601();

    let meta = KeyMetadata {
        key_id: key_id.clone(),
        created_at: now,
        user_id: user_id.to_string(),
        kem_algorithm: "ML-KEM-768".into(),
        sign_algorithm: "ML-DSA-65".into(),
    };

    let dir = keys_dir()?.join(&key_id);
    std::fs::create_dir_all(&dir).context("creating key directory")?;

    let public_bytes = [
        keypair.kem_public.as_bytes(),
        keypair.sign_public.as_bytes(),
    ]
    .concat();
    std::fs::write(dir.join("pqp-public.der"), &public_bytes).context("writing public key")?;

    let secret_bytes = [
        keypair.kem_secret.as_bytes(),
        keypair.sign_secret.as_bytes(),
    ]
    .concat();
    let salt = generate_salt()?;
    let wrapping_key = sym::derive_key(passphrase, &salt)?;
    let (nonce, encrypted_secret) = sym::encrypt(&wrapping_key, &secret_bytes)?;

    let mut wrapped = Vec::new();
    wrapped.extend_from_slice(&salt);
    wrapped.extend_from_slice(&nonce);
    wrapped.extend_from_slice(&encrypted_secret);

    std::fs::write(dir.join("pqp-secret.der"), &wrapped).context("writing secret key")?;

    let conf_json = serde_json::to_string_pretty(&meta).context("serializing key metadata")?;
    std::fs::write(dir.join("pqp.conf"), &conf_json).context("writing key config")?;

    Ok(meta)
}

pub fn load_public_key(key_id: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let dir = keys_dir()?.join(key_id);
    let public_path = dir.join("pqp-public.der");
    let data = std::fs::read(&public_path).context(format!("reading {}", public_path.display()))?;

    let kem_pk_len = 1184;
    if data.len() < kem_pk_len {
        return Err(anyhow::anyhow!("public key data too short"));
    }
    let kem_pk = data[..kem_pk_len].to_vec();
    let sign_pk = data[kem_pk_len..].to_vec();

    Ok((kem_pk, sign_pk))
}

/// Load and decrypt a secret key from the keyring.
///
/// Returns (kem_sk_bytes, sign_sk_bytes). The file format is:
/// salt (16) || nonce (24) || XChaCha20-Poly1305 ciphertext.
pub fn load_secret_key(key_id: &str, passphrase: &str) -> Result<(Vec<u8>, Vec<u8>)> {
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

    let wrapping_key = sym::derive_key(passphrase, salt)?;
    let mut secret_bytes = sym::decrypt(&wrapping_key, &nonce_arr, encrypted)?;

    let kem_sk_len = 64;
    let sign_sk_len = 32;
    if secret_bytes.len() < kem_sk_len + sign_sk_len {
        return Err(anyhow::anyhow!("decrypted secret key data too short"));
    }
    let kem_sk = secret_bytes[..kem_sk_len].to_vec();
    let sign_sk = secret_bytes[kem_sk_len..kem_sk_len + sign_sk_len].to_vec();

    secret_bytes.zeroize();

    Ok((kem_sk, sign_sk))
}

/// Export a public key as an ASCII-armored string.
pub fn export_public_key(key_id: &str) -> Result<String> {
    let dir = keys_dir()?.join(key_id);
    let public_bytes = std::fs::read(dir.join("pqp-public.der"))
        .context(format!("reading public key for {}", key_id))?;

    let marker = format!("PQP PUBLIC KEY {}", key_id);
    armor::armor(&public_bytes, &marker)
}

/// Import an ASCII-armored public key into the keyring.
///
/// Returns the imported key ID.
pub fn import_public_key(armored: &str) -> Result<String> {
    let (marker, decoded) = armor::unarmor(armored)?;

    let key_id = marker
        .strip_prefix("PQP PUBLIC KEY ")
        .ok_or_else(|| anyhow::anyhow!("invalid marker: {}", marker))?
        .trim()
        .to_string();

    let dir = keys_dir()?.join(&key_id);
    std::fs::create_dir_all(&dir).context("creating key directory for import")?;

    let metadata_path = dir.join("pqp.conf");
    if !metadata_path.exists() {
        let meta = KeyMetadata {
            key_id: key_id.clone(),
            created_at: timestamp_iso8601(),
            user_id: "imported".into(),
            kem_algorithm: "ML-KEM-768".into(),
            sign_algorithm: "ML-DSA-65".into(),
        };
        let conf_json = serde_json::to_string_pretty(&meta)?;
        std::fs::write(&metadata_path, &conf_json)?;
    }

    std::fs::write(dir.join("pqp-public.der"), &decoded)?;

    Ok(key_id)
}

fn generate_key_id() -> Result<String> {
    let mut buf = [0u8; 8];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut buf);
    Ok(hex::encode(buf))
}

fn generate_salt() -> Result<[u8; 16]> {
    let mut salt = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut salt);
    Ok(salt)
}
