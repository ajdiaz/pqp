//! Binary entry point for the `pqp` CLI tool.
//!
//! Parses command-line arguments via [`cli`](pqp::cli), dispatches to
//! the appropriate handler, and manages keyring, crypto, and I/O.

use anyhow::{Context, Result};
use clap::Parser;
use pqp::armor::Encoding;
use pqp::cli::{Cli, Commands};
use pqp::config;
use pqp::crypto::sign;
use pqp::crypto::sym;
use pqp::crypto::DsaVariant;
use pqp::crypto::KemVariant;
use pqp::{crypto, format, keyring};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;
use zeroize::Zeroize;

fn read_passphrase(prompt: &str) -> Result<String> {
    match rpassword::prompt_password(prompt) {
        Ok(p) => Ok(p),
        Err(_e) => Err(anyhow::anyhow!(
            "cannot read passphrase without a TTY (try --no-passphrase)"
        )),
    }
}

fn confirm_import(key_id: &str) -> Result<bool> {
    let prompt = format!("Import key {}? [y/N] ", key_id);
    eprint!("{}", prompt);
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_lowercase();
    Ok(answer == "y" || answer == "yes")
}

fn read_input(input: &Option<String>) -> Result<Vec<u8>> {
    match input {
        Some(path) if path != "-" => {
            let mut file = std::fs::File::open(path).context(format!("opening {}", path))?;
            let mut data = Vec::new();
            file.read_to_end(&mut data)
                .context(format!("reading {}", path))?;
            Ok(data)
        }
        _ => {
            let mut data = Vec::new();
            std::io::stdin()
                .read_to_end(&mut data)
                .context("reading from stdin")?;
            Ok(data)
        }
    }
}

fn read_file(path: &str) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open(path).context(format!("opening {}", path))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .context(format!("reading {}", path))?;
    Ok(data)
}

fn write_file(path: &str, data: &[u8]) -> Result<()> {
    std::fs::write(path, data).context(format!("writing {}", path))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let cfg = config::load()?;

    // Resolve keyring path: CLI --keyring-path > KEYRING_PATH env > config [keyring].path > default
    let keyring_path = cli
        .keyring_path
        .clone()
        .or_else(|| std::env::var("KEYRING_PATH").ok())
        .or_else(|| {
            config::section(&cfg, "keyring")
                .and_then(|s| s.get("path"))
                .and_then(|v| v.as_str().map(String::from))
        });
    if let Some(ref path) = keyring_path {
        keyring::set_keyring_override(Some(PathBuf::from(path)));
    }

    match cli.command {
        Commands::GenKey {
            user,
            no_passphrase,
            mut kem,
            mut dsa,
            mut encoding,
            mut compress,
            mut expiration_date,
            metadata,
            mut argon2_mem,
            mut argon2_time,
            mut argon2_par,
        } => {
            if cli.dry_run {
                eprintln!("[dry-run] would gen-key: no action taken");
                return Ok(());
            }
            let cmd_cfg = config::section(&cfg, "gen-key");
            kem = config::apply_str(&kem, cmd_cfg, "kem", "ML-KEM-768");
            dsa = config::apply_str(&dsa, cmd_cfg, "dsa", "ML-DSA-65");
            encoding = config::apply_str(&encoding, cmd_cfg, "encoding", "BASE64");
            compress = config::apply_str(&compress, cmd_cfg, "compress", "none");
            expiration_date = config::apply_str(&expiration_date, cmd_cfg, "expiration-date", "5y");
            let kem_variant =
                KemVariant::parse(&kem).with_context(|| format!("unknown KEM variant: {}", kem))?;
            let dsa_variant =
                DsaVariant::parse(&dsa).with_context(|| format!("unknown DSA variant: {}", dsa))?;
            let encoding = Encoding::parse(&encoding)
                .with_context(|| format!("unknown encoding: {}", encoding))?;

            let passphrase = if no_passphrase {
                String::new()
            } else {
                let passphrase = read_passphrase("Enter passphrase for new key: ")?;
                let passphrase2 = read_passphrase("Confirm passphrase: ")?;
                if passphrase != passphrase2 {
                    return Err(anyhow::anyhow!("passphrases do not match"));
                }
                passphrase
            };
            argon2_mem = config::apply_u32(
                argon2_mem,
                cmd_cfg,
                "argon2-mem",
                pqp::crypto::sym::DEFAULT_ARGON2_MEM,
            );
            argon2_time = config::apply_u32(
                argon2_time,
                cmd_cfg,
                "argon2-time",
                pqp::crypto::sym::DEFAULT_ARGON2_TIME,
            );
            argon2_par = config::apply_u32(
                argon2_par,
                cmd_cfg,
                "argon2-par",
                pqp::crypto::sym::DEFAULT_ARGON2_PAR,
            );
            let metadata_entries: Vec<keyring::MetadataEntry> = metadata
                .iter()
                .filter_map(|s| {
                    let mut parts = s.splitn(2, '=');
                    let k = parts.next()?;
                    let v = parts.next().unwrap_or("");
                    if k.is_empty() {
                        None
                    } else {
                        Some(keyring::MetadataEntry {
                            key: k.to_string(),
                            value: v.to_string(),
                        })
                    }
                })
                .collect();
            let meta = keyring::generate_key(
                &user,
                &passphrase,
                kem_variant,
                dsa_variant,
                encoding,
                &compress,
                &expiration_date,
                metadata_entries,
                argon2_mem,
                argon2_time,
                argon2_par,
            )?;
            // passphrase consumed by generate_key above; zeroize after last use
            let mut passphrase_bytes = passphrase.into_bytes();
            passphrase_bytes.zeroize();
            println!("Generated key pair: key-id={}", meta.key_id);
            println!("  user-id: {}", meta.user_id);
            println!("  created: {}", meta.created_at);
            println!("  kem: {}", meta.kem_algorithm);
            println!("  dsa: {}", meta.sign_algorithm);
            println!("  encoding: {}", meta.encoding_algorithm);
            println!("  compress: {}", meta.compress_algorithm);
            println!("  expires: {}", meta.expiration_date);
            for entry in &meta.metadata {
                println!("  {}: {}", entry.key, entry.value);
            }
        }
        Commands::ListKeys { mut format } => {
            if cli.dry_run {
                eprintln!("[dry-run] would list-keys: no action taken");
                return Ok(());
            }
            let cmd_cfg = config::section(&cfg, "list-keys");
            format = config::apply_str(&format, cmd_cfg, "format", "table");
            let keys = keyring::list_keys()?;
            if keys.is_empty() {
                println!("No keys in keyring.");
            } else {
                match format.as_str() {
                    "json" => {
                        let mut items = Vec::new();
                        for key in &keys {
                            let kt = if key.has_secret && key.has_public {
                                "pub+sec"
                            } else if key.has_secret {
                                "sec"
                            } else {
                                "pub"
                            };
                            let expired = pqp::expiry::is_expired(&key.expiration_date);
                            let meta_json: String = if key.metadata.is_empty() {
                                String::new()
                            } else {
                                let entries: Vec<String> = key
                                    .metadata
                                    .iter()
                                    .map(|e| {
                                        let k = pqp::util::json_escape_string(&e.key);
                                        let v = pqp::util::json_escape_string(&e.value);
                                        format!("    {{ \"key\": {}, \"value\": {} }}", k, v)
                                    })
                                    .collect();
                                format!(",\n    \"metadata\": [\n{}\n    ]", entries.join(",\n"))
                            };
                            items.push(format!(
                                r#"  {{
    "key_id": "{}",
    "user_id": "{}",
    "created_at": "{}",
    "has_public": {},
    "has_secret": {},
    "type": "{}",
    "kem_algorithm": "{}",
    "sign_algorithm": "{}",
    "compress_algorithm": "{}",
    "expiration_date": "{}",
    "expired": {}
  {} }}"#,
                                key.key_id,
                                key.user_id,
                                key.created_at,
                                key.has_public,
                                key.has_secret,
                                kt,
                                key.kem_algorithm,
                                key.sign_algorithm,
                                key.compress_algorithm,
                                key.expiration_date,
                                expired,
                                meta_json,
                            ));
                        }
                        println!("[\n{}\n]", items.join(",\n"));
                    }
                    "no-headers" | "noheader" | "no-head" => {
                        for key in &keys {
                            let kt = if key.has_secret && key.has_public {
                                "pub+sec"
                            } else if key.has_secret {
                                "sec"
                            } else {
                                "pub"
                            };
                            let expired = pqp::expiry::is_expired(&key.expiration_date);
                            let status = if expired { "expired" } else { "valid" };
                            println!(
                                "{} {} {} {} {} {} {} {} {}",
                                key.key_id,
                                key.user_id,
                                key.created_at,
                                kt,
                                key.kem_algorithm,
                                key.sign_algorithm,
                                key.compress_algorithm,
                                key.expiration_date,
                                status,
                            );
                        }
                    }
                    _ => {
                        let uid_width = keys
                            .iter()
                            .map(|k| k.user_id.len())
                            .chain(std::iter::once("User ID".len()))
                            .max()
                            .unwrap_or(20)
                            .max(8);
                        let total = 16
                            + 1
                            + uid_width
                            + 1
                            + 26
                            + 1
                            + 8
                            + 1
                            + 14
                            + 1
                            + 14
                            + 1
                            + 10
                            + 1
                            + 10
                            + 1
                            + 10;
                        println!(
                            "{:<16} {:<uid_w$} {:<26} {:<8} {:<14} {:<14} {:<10} {:<10} {:<10}",
                            "Key ID",
                            "User ID",
                            "Created",
                            "Type",
                            "KEM",
                            "Sign",
                            "Compress",
                            "Expires",
                            "Status",
                            uid_w = uid_width,
                        );
                        println!("{}", "-".repeat(total));
                        for key in &keys {
                            let kt = if key.has_secret && key.has_public {
                                "pub+sec"
                            } else if key.has_secret {
                                "sec"
                            } else {
                                "pub"
                            };
                            let expired = pqp::expiry::is_expired(&key.expiration_date);
                            let status = if expired { "expired" } else { "valid" };
                            let expires_display = if key.expiration_date.len() > 10 {
                                &key.expiration_date[..10]
                            } else {
                                &key.expiration_date
                            };
                            println!(
                                "{:<16} {:<uid_w$} {:<26} {:<8} {:<14} {:<14} {:<10} {:<10} {:<10}",
                                key.key_id,
                                key.user_id,
                                key.created_at,
                                kt,
                                key.kem_algorithm,
                                key.sign_algorithm,
                                key.compress_algorithm,
                                expires_display,
                                status,
                                uid_w = uid_width,
                            );
                        }
                    }
                }
            }
        }
        Commands::Encrypt {
            recipient,
            output,
            input,
            sign,
            signer,
            mut compress,
            allow_expired,
        } => {
            if cli.dry_run {
                eprintln!("[dry-run] would encrypt: no action taken");
                return Ok(());
            }
            let cmd_cfg = config::section(&cfg, "encrypt");
            compress = config::apply_str(&compress, cmd_cfg, "compress", "zstd");
            let allow_expired = config::apply_bool(allow_expired, cmd_cfg, "allow-expired", false);
            let recipient_id =
                keyring::resolve_key_id(&recipient).context("resolving recipient key")?;

            if keyring::check_key_expired(&recipient_id)? {
                let msg = format!("Warning: key {} is expired", recipient_id);
                if allow_expired {
                    eprintln!("{}; proceeding with --allow-expired", msg);
                } else {
                    anyhow::bail!("{}. Use --allow-expired to force", msg);
                }
            }

            let signer_id = match &signer {
                Some(s) => Some(keyring::resolve_key_id(s).context("resolving signer key")?),
                None => None,
            };

            if sign {
                let sid = signer_id.as_deref().unwrap_or(&recipient_id);
                if keyring::check_key_expired(sid)? {
                    let msg = format!("Warning: signing key {} is expired", sid);
                    if allow_expired {
                        eprintln!("{}; proceeding with --allow-expired", msg);
                    } else {
                        anyhow::bail!("{}. Use --allow-expired to force", msg);
                    }
                }
            }

            let passphrase = if sign {
                let sid = signer_id.as_deref().unwrap_or(&recipient_id);
                Some(read_passphrase(&format!(
                    "Enter passphrase for key {}: ",
                    sid
                ))?)
            } else {
                None
            };

            let data = read_input(&input)?;
            let input_name = input.as_deref().unwrap_or("stdin");

            let compress_alg = if compress.eq_ignore_ascii_case("none") {
                None
            } else {
                let alg_str = compress.to_uppercase();
                eprintln!(
                    "Warning: compression before encryption can leak plaintext length \
                     (CRIME/BREACH attack). Avoid compressing data that mixes \
                     attacker-controlled and secret content."
                );
                Some(
                    format::Algorithm::from_str(&alg_str)
                        .context("unknown compression algorithm")?,
                )
            };

            let plaintext = if let Some(ref alg) = compress_alg {
                format::compress(&data, alg)?
            } else {
                data
            };

            let (mut kem_pk_bytes, _, kem_alg, _) =
                keyring::load_public_key(&recipient_id).context("loading recipient public key")?;
            let kem_variant = KemVariant::parse(&kem_alg)
                .context(format!("unknown KEM algorithm: {}", kem_alg))?;
            let kem_pk = crypto::kem::PublicKey::from_bytes(&kem_pk_bytes, kem_variant)?;
            kem_pk_bytes.zeroize();

            let (ct, mut shared_secret) = crypto::kem::encapsulate(&kem_pk)?;

            // KEM shared secret → symmetric key via SHA3-256 KDF (NIST SP 800-56C)
            use sha3::{Digest, Sha3_256};
            let mut kdf = Sha3_256::new();
            kdf.update(b"pqp-kem-encrypt-v1");
            kdf.update(shared_secret);
            let sym_key = kdf.finalize();
            shared_secret.zeroize();
            let mut sym_key_arr = [0u8; 32];
            sym_key_arr.copy_from_slice(&sym_key);

            let (nonce, ciphertext) =
                sym::encrypt(&sym_key_arr, &plaintext).context("symmetric encryption failed")?;
            sym_key_arr.zeroize();

            let mut payload = ct.to_vec();
            payload.extend_from_slice(&nonce);
            payload.extend_from_slice(&ciphertext);

            let mut alg_vec = vec![
                format::Algorithm::MlKem,
                format::Algorithm::XChaCha20Poly1305,
            ];
            if let Some(ref alg) = compress_alg {
                alg_vec.push(alg.clone());
            }
            alg_vec.push(format::Algorithm::Base64);
            let algorithms = format::AlgorithmList::new(alg_vec);

            if sign {
                let sid = signer_id.as_deref().unwrap_or(&recipient_id);
                let mut passphrase = passphrase.unwrap();
                let (mut kem_sk_bytes, mut sign_sk_bytes, _sign_alg_kem, sign_alg) =
                    keyring::load_secret_key(sid, &passphrase)
                        .context("loading signer secret key")?;
                passphrase.zeroize();

                let dsa_variant = DsaVariant::parse(&sign_alg)
                    .context(format!("unknown sign algorithm: {}", sign_alg))?;
                let sign_sk = crypto::sign::SecretKey::from_bytes(&sign_sk_bytes)?;
                let signature = sign::sign(&sign_sk, &payload, dsa_variant)?;
                drop(sign_sk);
                sign_sk_bytes.zeroize();
                kem_sk_bytes.zeroize();
                payload.extend_from_slice(&signature);
            }

            let encoded =
                format::encode_payload(&algorithms, &payload).context("encoding payload")?;

            let mut serialized = algorithms.to_string().into_bytes();
            serialized.extend_from_slice(b"::");
            serialized.extend_from_slice(&encoded);

            let out_path = output.unwrap_or_else(|| format!("{}.pqp.enc", input_name));
            write_file(&out_path, &serialized)?;
            println!("Encrypted: {}", out_path);
        }
        Commands::Decrypt {
            output,
            input,
            no_passphrase,
        } => {
            if cli.dry_run {
                eprintln!("[dry-run] would decrypt: no action taken");
                return Ok(());
            }
            let passphrase = if no_passphrase {
                String::new()
            } else {
                read_passphrase("Enter passphrase for secret key: ")?
            };

            let data = read_input(&input)?;
            let input_name = input.as_deref().unwrap_or("stdin");

            let (algorithms, payload) =
                format::deserialize(&data).context("parsing encrypted file")?;

            let compress_alg = algorithms.compression();

            let nonce_len = 24;

            if payload.len() < nonce_len {
                return Err(anyhow::anyhow!("payload too short"));
            }

            let mut passphrase_vec = passphrase.into_bytes();
            let keys = keyring::list_keys()?;
            let mut decrypted = None;
            for key in &keys {
                let pp = std::str::from_utf8(&passphrase_vec)?;
                if let Ok((mut kem_sk_bytes, _, kem_alg, _)) =
                    keyring::load_secret_key(&key.key_id, pp)
                {
                    if let Some(kem_variant) = KemVariant::parse(&kem_alg) {
                        let ct_len = kem_variant.ciphertext_len();
                        if payload.len() < ct_len + nonce_len {
                            kem_sk_bytes.zeroize();
                            continue;
                        }
                        let ct = &payload[..ct_len];
                        let nonce_arr: [u8; 24] =
                            match payload[ct_len..ct_len + nonce_len].try_into() {
                                Ok(n) => n,
                                Err(_) => {
                                    kem_sk_bytes.zeroize();
                                    continue;
                                }
                            };
                        let sym_ciphertext = &payload[ct_len + nonce_len..];
                        let kem_sk = match crypto::kem::SecretKey::from_bytes(&kem_sk_bytes) {
                            Ok(sk) => sk,
                            Err(_) => {
                                kem_sk_bytes.zeroize();
                                continue;
                            }
                        };
                        kem_sk_bytes.zeroize();
                        if let Ok(shared) = crypto::kem::decapsulate(&kem_sk, ct, kem_variant) {
                            // KDF shared secret to symmetric key (NIST SP 800-56C)
                            use sha3::{Digest, Sha3_256};
                            let mut kdf = Sha3_256::new();
                            kdf.update(b"pqp-kem-encrypt-v1");
                            kdf.update(shared);
                            let sym_key = kdf.finalize();
                            let mut sym_key_arr = [0u8; 32];
                            sym_key_arr.copy_from_slice(&sym_key);
                            if let Ok(plaintext) =
                                sym::decrypt(&sym_key_arr, &nonce_arr, sym_ciphertext)
                            {
                                sym_key_arr.zeroize();
                                decrypted = Some(plaintext);
                                break;
                            }
                            sym_key_arr.zeroize();
                        }
                    }
                }
            }

            passphrase_vec.zeroize();

            let mut plaintext = decrypted.ok_or_else(|| {
                anyhow::anyhow!("decryption failed: no matching key or wrong passphrase")
            })?;

            if let Some(alg) = compress_alg {
                plaintext = format::decompress(&plaintext, alg)?;
            }

            let out_path = output.unwrap_or_else(|| {
                let stripped = input_name.strip_suffix(".pqp.enc").unwrap_or(input_name);
                stripped.to_string()
            });
            write_file(&out_path, &plaintext)?;
            println!("Decrypted: {}", out_path);
        }
        Commands::Sign {
            user,
            output,
            input,
            no_passphrase,
            allow_expired,
        } => {
            if cli.dry_run {
                eprintln!("[dry-run] would sign: no action taken");
                return Ok(());
            }
            let user_id = keyring::resolve_key_id(&user).context("resolving signing key")?;
            if keyring::check_key_expired(&user_id)? {
                let msg = format!("Warning: signing key {} is expired", user_id);
                if allow_expired {
                    eprintln!("{}; proceeding with --allow-expired", msg);
                } else {
                    anyhow::bail!("{}. Use --allow-expired to force", msg);
                }
            }
            let passphrase = if no_passphrase {
                String::new()
            } else {
                read_passphrase("Enter passphrase for signing key: ")?
            };
            let data = read_input(&input)?;
            let input_name = input.as_deref().unwrap_or("stdin");

            let mut passphrase_vec = passphrase.into_bytes();
            let pp = std::str::from_utf8(&passphrase_vec)?;
            let (_, mut sign_sk_bytes, _, sign_alg) =
                keyring::load_secret_key(&user_id, pp).context("loading secret key")?;
            passphrase_vec.zeroize();
            let dsa_variant = DsaVariant::parse(&sign_alg)
                .context(format!("unknown sign algorithm: {}", sign_alg))?;

            let sign_sk = crypto::sign::SecretKey::from_bytes(&sign_sk_bytes)?;
            sign_sk_bytes.zeroize();

            use sha3::{Digest, Sha3_256};
            let mut hasher = Sha3_256::new();
            hasher.update(&data);
            let hash = hasher.finalize();

            let signature = sign::sign(&sign_sk, &hash, dsa_variant)?;

            let algorithms = format::AlgorithmList::new(vec![
                format::Algorithm::MlDsa,
                format::Algorithm::Sha3256,
                format::Algorithm::Base64,
            ]);

            let mut payload = hash.to_vec();
            payload.extend_from_slice(&signature);

            let encoded = format::encode_payload(&algorithms, &payload)?;

            let mut serialized = algorithms.to_string().into_bytes();
            serialized.extend_from_slice(b"::");
            serialized.extend_from_slice(&encoded);

            let out_path = output.unwrap_or_else(|| format!("{}.pqp.sig", input_name));
            write_file(&out_path, &serialized)?;
            println!("Signed: {}", out_path);
        }
        Commands::Verify { signature, input } => {
            if cli.dry_run {
                eprintln!("[dry-run] would verify: no action taken");
                return Ok(());
            }
            let sig_data = read_file(&signature)?;
            let orig_data = read_input(&input)?;

            let (_algorithms, payload) =
                format::deserialize(&sig_data).context("parsing signature file")?;

            let hash_len = 32;
            if payload.len() < hash_len {
                return Err(anyhow::anyhow!("signature payload too short"));
            }

            let stored_hash = &payload[..hash_len];
            let sig_bytes = &payload[hash_len..];

            use sha3::{Digest, Sha3_256};
            let mut hasher = Sha3_256::new();
            hasher.update(&orig_data);
            let computed_hash = hasher.finalize();

            if !pqp::util::constant_time_eq(stored_hash, computed_hash.as_slice()) {
                return Err(anyhow::anyhow!("hash mismatch: file has been modified"));
            }

            let keys = keyring::list_keys()?;
            let mut verified = false;
            for key in &keys {
                let (_, sign_pk, _, sign_alg) = keyring::load_public_key(&key.key_id)?;
                if let Some(dsa_variant) = DsaVariant::parse(&sign_alg) {
                    if let Ok(sign_pk) = crypto::sign::PublicKey::from_bytes(&sign_pk, dsa_variant)
                    {
                        if let Ok(true) = sign::verify(&sign_pk, stored_hash, sig_bytes) {
                            verified = true;
                            println!("Verified: signed by key-id={}", key.key_id);
                            break;
                        }
                    }
                }
            }

            if !verified {
                return Err(anyhow::anyhow!(
                    "verification failed: no matching signer key found"
                ));
            }
        }
        Commands::RemoveKey {
            key_id,
            dont_ask,
            remove_private_key,
        } => {
            if cli.dry_run {
                eprintln!("[dry-run] would remove-key: no action taken");
                return Ok(());
            }
            let key_ids = keyring::resolve_key_ids(&key_id)?;

            for kid in &key_ids {
                let meta = keyring::read_metadata(kid)?;
                if !dont_ask {
                    let prompt = format!("Remove key {} (user: {})? [y/N] ", kid, meta.user_id);
                    eprint!("{}", prompt);
                    std::io::stderr().flush()?;
                    let mut answer = String::new();
                    std::io::stdin().read_line(&mut answer)?;
                    let answer = answer.trim().to_lowercase();
                    if answer != "y" && answer != "yes" {
                        println!("Skipped key {}.", kid);
                        continue;
                    }
                }

                keyring::remove_key(kid, remove_private_key)?;
                let removed = if remove_private_key {
                    "public and private"
                } else {
                    "public"
                };
                println!("Removed {} key {}/{}", removed, kid, meta.user_id);
            }
        }
        Commands::Export {
            key_id,
            output,
            mut format_,
            mut compress,
        } => {
            if cli.dry_run {
                eprintln!("[dry-run] would export: no action taken");
                return Ok(());
            }
            let cmd_cfg = config::section(&cfg, "export");
            format_ = config::apply_str(&format_, cmd_cfg, "format", "pqp");
            compress = config::apply_str(&compress, cmd_cfg, "compress", "zstd");
            let resolved_id = keyring::resolve_key_id(&key_id)?;
            match format_.as_str() {
                "pqp" => {
                    let compress_alg = if compress.eq_ignore_ascii_case("none") {
                        None
                    } else {
                        let alg_str = compress.to_uppercase();
                        Some(
                            format::Algorithm::from_str(&alg_str)
                                .context("unknown compression algorithm")?,
                        )
                    };
                    let pqp_data =
                        keyring::export_public_key_pqp(&resolved_id, compress_alg.as_ref())?;
                    let out_path = output.unwrap_or_else(|| format!("{}.pqp.pub", key_id));
                    write_file(&out_path, pqp_data.as_bytes())?;
                    println!("Exported (PQP format): {}", out_path);
                }
                _ => {
                    let armored = keyring::export_public_key(&resolved_id)?;
                    let out_path = output.unwrap_or_else(|| format!("{}.pqp.asc", key_id));
                    write_file(&out_path, armored.as_bytes())?;
                    println!("Exported: {}", out_path);
                }
            }
        }
        Commands::Import {
            input,
            url,
            dont_ask_confirmation,
        } => {
            if cli.dry_run {
                eprintln!("[dry-run] would import: no action taken");
                return Ok(());
            }
            let data = if let Some(url) = &url {
                let agent: ureq::Agent = ureq::Agent::config_builder()
                    .timeout_global(Some(std::time::Duration::from_secs(30)))
                    .build()
                    .into();
                let response = agent.get(url).call().context(format!("fetching {}", url))?;
                response
                    .into_body()
                    .read_to_string()
                    .context("reading response body")?
            } else {
                let bytes = read_input(&input)?;
                String::from_utf8(bytes).context("import data is not valid UTF-8")?
            };

            // Auto-detect format: try armor first, then PQP
            if let Ok((marker, _, _)) = pqp::armor::unarmor(&data) {
                let import_key_id = marker
                    .strip_prefix("PQP PUBLIC KEY ")
                    .unwrap_or(&marker)
                    .to_string();
                if !dont_ask_confirmation && !confirm_import(&import_key_id)? {
                    println!("Import cancelled.");
                    return Ok(());
                }
                let key_id = keyring::import_public_key(&data)?;
                println!("Imported: key-id={}", key_id);
            } else {
                let key_id = keyring::import_public_key_from_pqp(&data)?;
                if !dont_ask_confirmation && !confirm_import(&key_id)? {
                    println!("Import cancelled.");
                    return Ok(());
                }
                println!("Imported (PQP format): key-id={}", key_id);
            }
        }
    }

    Ok(())
}
