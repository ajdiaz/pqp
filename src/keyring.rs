use crate::armor;
use crate::crypto::{keygen, sym};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::Zeroize;

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

fn days_to_date(mut days: u64) -> (u64, u64, u64) {
    let y400 = 400 * 365 + 97;
    let y100 = 100 * 365 + 24;
    let y4 = 4 * 365 + 1;
    let y1 = 365;

    let mut year = 0u64;

    year += (days / y400) * 400;
    days %= y400;

    year += (days / y100) * 100;
    days %= y100;

    year += (days / y4) * 4;
    days %= y4;

    year += days / y1;
    days %= y1;

    let leap = is_leap_year(year);
    if days >= 59 + leap as u64 {
        days += 2 - leap as u64;
    }

    let month_days: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u64;
    for (i, &md) in month_days.iter().enumerate() {
        if days < md {
            month = i as u64 + 1;
            break;
        }
        days -= md;
    }
    let day = days + 1;

    (year, month, day)
}

fn is_leap_year(year: u64) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
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

pub fn export_public_key(key_id: &str) -> Result<String> {
    let dir = keys_dir()?.join(key_id);
    let public_bytes = std::fs::read(dir.join("pqp-public.der"))
        .context(format!("reading public key for {}", key_id))?;

    let marker = format!("PQP PUBLIC KEY {}", key_id);
    armor::armor(&public_bytes, &marker)
}

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
