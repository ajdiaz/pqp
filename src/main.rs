//! Binary entry point for the `pqp` CLI tool.
//!
//! Parses command-line arguments via [`cli`](pqp::cli), dispatches to
//! the appropriate handler, and manages keyring, crypto, and I/O.

use anyhow::{Context, Result};
use clap::Parser;
use pqp::armor::Encoding;
use pqp::cli::{Cli, Commands};
use pqp::crypto::sign;
use pqp::crypto::sym;
use pqp::crypto::DsaVariant;
use pqp::crypto::KemVariant;
use pqp::{crypto, format, keyring};
use std::io::{Read, Write};
use std::str::FromStr;
use zeroize::Zeroize;

fn read_passphrase(prompt: &str) -> Result<String> {
    let result = rpassword::prompt_password(prompt);
    match result {
        Ok(p) => Ok(p),
        Err(_e) => {
            eprint!("{}", prompt);
            let mut pass = String::new();
            std::io::stdin().read_line(&mut pass)?;
            if pass.ends_with('\n') {
                pass.pop();
                if pass.ends_with('\r') {
                    pass.pop();
                }
            }
            Ok(pass)
        }
    }
}

fn confirm_import(key_id: &str) -> Result<bool> {
    let prompt = format!("Import key {}? [y/N] ", key_id);
    #[cfg(unix)]
    {
        let mut tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .context("opening /dev/tty for confirmation")?;
        tty.write_all(prompt.as_bytes())?;
        let mut answer = String::new();
        tty.read_to_string(&mut answer)?;
        let answer = answer.trim().to_lowercase();
        Ok(answer == "y" || answer == "yes")
    }
    #[cfg(not(unix))]
    {
        eprint!("{}", prompt);
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        let answer = answer.trim().to_lowercase();
        Ok(answer == "y" || answer == "yes")
    }
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

    match cli.command {
        Commands::GenKey {
            user,
            no_passphrase,
            kem,
            dsa,
            encoding,
        } => {
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
            let meta =
                keyring::generate_key(&user, &passphrase, kem_variant, dsa_variant, encoding)?;
            println!("Generated key pair: key-id={}", meta.key_id);
            println!("  user-id: {}", meta.user_id);
            println!("  created: {}", meta.created_at);
            println!("  kem: {}", meta.kem_algorithm);
            println!("  dsa: {}", meta.sign_algorithm);
            println!("  encoding: {}", meta.encoding_algorithm);
        }
        Commands::ListKeys { format } => {
            let keys = keyring::list_keys()?;
            if keys.is_empty() {
                println!("No keys in keyring.");
            } else {
                match format.as_str() {
                    "json" => {
                        let json = serde_json::to_string_pretty(&keys)?;
                        println!("{json}");
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
                            println!(
                                "{} {} {} {} {} {}",
                                key.key_id,
                                key.user_id,
                                key.created_at,
                                kt,
                                key.kem_algorithm,
                                key.sign_algorithm,
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
                        let total = 16 + 1 + uid_width + 1 + 26 + 1 + 8 + 1 + 14 + 1 + 14;
                        println!(
                            "{:<16} {:<uid_w$} {:<26} {:<8} {:<14} {:<14}",
                            "Key ID",
                            "User ID",
                            "Created",
                            "Type",
                            "KEM",
                            "Sign",
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
                            println!(
                                "{:<16} {:<uid_w$} {:<26} {:<8} {:<14} {:<14}",
                                key.key_id,
                                key.user_id,
                                key.created_at,
                                kt,
                                key.kem_algorithm,
                                key.sign_algorithm,
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
            compress,
        } => {
            let recipient_id =
                keyring::resolve_key_id(&recipient).context("resolving recipient key")?;

            let signer_id = match &signer {
                Some(s) => Some(keyring::resolve_key_id(s).context("resolving signer key")?),
                None => None,
            };

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

            let (kem_pk, _, kem_alg, _) =
                keyring::load_public_key(&recipient_id).context("loading recipient public key")?;
            let kem_variant = KemVariant::parse(&kem_alg)
                .context(format!("unknown KEM algorithm: {}", kem_alg))?;
            let kem_pk = crypto::kem::PublicKey::from_bytes(&kem_pk, kem_variant)?;

            let (ct, shared_secret) = crypto::kem::encapsulate(&kem_pk)?;

            let (nonce, ciphertext) =
                sym::encrypt(&shared_secret, &plaintext).context("symmetric encryption failed")?;

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
                let (_, sign_sk, _sign_alg_kem, sign_alg) =
                    keyring::load_secret_key(sid, &passphrase)
                        .context("loading signer secret key")?;
                passphrase.zeroize();

                let dsa_variant = DsaVariant::parse(&sign_alg)
                    .context(format!("unknown sign algorithm: {}", sign_alg))?;
                let sign_sk = crypto::sign::SecretKey::from_bytes(&sign_sk)?;
                let signature = sign::sign(&sign_sk, &payload, dsa_variant)?;
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

            let keys = keyring::list_keys()?;
            let mut decrypted = None;
            for key in &keys {
                if let Ok((kem_sk, _, kem_alg, _)) =
                    keyring::load_secret_key(&key.key_id, &passphrase)
                {
                    if let Some(kem_variant) = KemVariant::parse(&kem_alg) {
                        let ct_len = kem_variant.ciphertext_len();
                        if payload.len() < ct_len + nonce_len {
                            continue;
                        }
                        let ct = &payload[..ct_len];
                        let nonce_arr: [u8; 24] =
                            match payload[ct_len..ct_len + nonce_len].try_into() {
                                Ok(n) => n,
                                Err(_) => continue,
                            };
                        let sym_ciphertext = &payload[ct_len + nonce_len..];
                        let kem_sk = match crypto::kem::SecretKey::from_bytes(&kem_sk) {
                            Ok(sk) => sk,
                            Err(_) => continue,
                        };
                        if let Ok(shared) = crypto::kem::decapsulate(&kem_sk, ct, kem_variant) {
                            if let Ok(plaintext) = sym::decrypt(&shared, &nonce_arr, sym_ciphertext)
                            {
                                decrypted = Some(plaintext);
                                break;
                            }
                        }
                    }
                }
            }

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
        } => {
            let user_id = keyring::resolve_key_id(&user).context("resolving signing key")?;
            let passphrase = if no_passphrase {
                String::new()
            } else {
                read_passphrase("Enter passphrase for signing key: ")?
            };
            let data = read_input(&input)?;
            let input_name = input.as_deref().unwrap_or("stdin");

            let (_, sign_sk, _, sign_alg) =
                keyring::load_secret_key(&user_id, &passphrase).context("loading secret key")?;
            let dsa_variant = DsaVariant::parse(&sign_alg)
                .context(format!("unknown sign algorithm: {}", sign_alg))?;

            let sign_sk = crypto::sign::SecretKey::from_bytes(&sign_sk)?;

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

            if stored_hash != computed_hash.as_slice() {
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
            let key_ids = keyring::resolve_key_ids(&key_id)?;

            for kid in &key_ids {
                let meta = keyring::read_metadata(kid)?;
                if !dont_ask {
                    let prompt = format!("Remove key {} (user: {})? [y/N] ", kid, meta.user_id);
                    #[cfg(unix)]
                    {
                        let mut tty = std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open("/dev/tty")
                            .context("opening /dev/tty for confirmation")?;
                        tty.write_all(prompt.as_bytes())?;
                        let mut answer = String::new();
                        tty.read_to_string(&mut answer)?;
                        let answer = answer.trim().to_lowercase();
                        if answer != "y" && answer != "yes" {
                            println!("Skipped key {}.", kid);
                            continue;
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        eprint!("{}", prompt);
                        let mut answer = String::new();
                        std::io::stdin().read_line(&mut answer)?;
                        let answer = answer.trim().to_lowercase();
                        if answer != "y" && answer != "yes" {
                            println!("Skipped key {}.", kid);
                            continue;
                        }
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
        Commands::Export { key_id, output } => {
            let resolved_id = keyring::resolve_key_id(&key_id)?;
            let armored = keyring::export_public_key(&resolved_id)?;
            let out_path = output.unwrap_or_else(|| format!("{}.pqp.asc", key_id));
            write_file(&out_path, armored.as_bytes())?;
            println!("Exported: {}", out_path);
        }
        Commands::Import {
            input,
            url,
            dont_ask_confirmation,
        } => {
            let armored = if let Some(url) = &url {
                let response = ureq::get(url).call().context(format!("fetching {}", url))?;
                response
                    .into_body()
                    .read_to_string()
                    .context("reading response body")?
            } else {
                let data = read_input(&input)?;
                String::from_utf8(data).context("import data is not valid UTF-8")?
            };

            let (marker, _) = pqp::armor::unarmor(&armored).context("invalid armored key data")?;
            let import_key_id = marker
                .strip_prefix("PQP PUBLIC KEY ")
                .unwrap_or(&marker)
                .to_string();

            if !dont_ask_confirmation && !confirm_import(&import_key_id)? {
                println!("Import cancelled.");
                return Ok(());
            }

            let key_id = keyring::import_public_key(&armored)?;
            println!("Imported: key-id={}", key_id);
        }
    }

    Ok(())
}
