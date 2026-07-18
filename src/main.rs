use anyhow::{Context, Result};
use clap::Parser;
use pqp::cli::{Cli, Commands};
use pqp::crypto::sign;
use pqp::crypto::sym;
use pqp::{crypto, format, keyring};
use std::io::{Read, Write};
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
        } => {
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
            let meta = keyring::generate_key(&user, &passphrase)?;
            println!("Generated key pair: key-id={}", meta.key_id);
            println!("  user-id: {}", meta.user_id);
            println!("  created: {}", meta.created_at);
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

            let (kem_pk, _) =
                keyring::load_public_key(&recipient_id).context("loading recipient public key")?;
            let kem_pk = crypto::kem::PublicKey::from_bytes(&kem_pk)?;

            let (ct, shared_secret) = crypto::kem::encapsulate(&kem_pk)?;

            let (nonce, ciphertext) =
                sym::encrypt(&shared_secret, &data).context("symmetric encryption failed")?;

            let mut payload = ct.to_vec();
            payload.extend_from_slice(&nonce);
            payload.extend_from_slice(&ciphertext);

            let algorithms = format::AlgorithmList::new(vec![
                format::Algorithm::MlKem,
                format::Algorithm::XChaCha20Poly1305,
                format::Algorithm::Base64,
            ]);

            if sign {
                let sid = signer_id.as_deref().unwrap_or(&recipient_id);
                let mut passphrase = passphrase.unwrap();
                let (_, sign_sk) = keyring::load_secret_key(sid, &passphrase)
                    .context("loading signer secret key")?;
                passphrase.zeroize();

                let sign_sk = crypto::sign::SecretKey::from_bytes(&sign_sk)?;
                let signature = sign::sign(&sign_sk, &payload)?;
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

            let (_algorithms, payload) =
                format::deserialize(&data).context("parsing encrypted file")?;

            let ct_len = 1088;
            let nonce_len = 24;

            if payload.len() < ct_len + nonce_len {
                return Err(anyhow::anyhow!("payload too short"));
            }

            let ct = &payload[..ct_len];
            let nonce_arr: [u8; 24] = payload[ct_len..ct_len + nonce_len].try_into().unwrap();
            let sym_ciphertext = &payload[ct_len + nonce_len..];

            let keys = keyring::list_keys()?;
            let mut decrypted = None;
            for key in &keys {
                if let Ok((kem_sk, _)) = keyring::load_secret_key(&key.key_id, &passphrase) {
                    let kem_sk = crypto::kem::SecretKey::from_bytes(&kem_sk)?;
                    if let Ok(shared) = crypto::kem::decapsulate(&kem_sk, ct) {
                        if let Ok(plaintext) = sym::decrypt(&shared, &nonce_arr, sym_ciphertext) {
                            decrypted = Some(plaintext);
                            break;
                        }
                    }
                }
            }

            let plaintext = decrypted.ok_or_else(|| {
                anyhow::anyhow!("decryption failed: no matching key or wrong passphrase")
            })?;

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

            let (_, sign_sk) =
                keyring::load_secret_key(&user_id, &passphrase).context("loading secret key")?;

            let sign_sk = crypto::sign::SecretKey::from_bytes(&sign_sk)?;

            use sha3::{Digest, Sha3_256};
            let mut hasher = Sha3_256::new();
            hasher.update(&data);
            let hash = hasher.finalize();

            let signature = sign::sign(&sign_sk, &hash)?;

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
                let (_, sign_pk) = keyring::load_public_key(&key.key_id)?;
                let sign_pk = crypto::sign::PublicKey::from_bytes(&sign_pk)?;
                if let Ok(true) = sign::verify(&sign_pk, stored_hash, sig_bytes) {
                    verified = true;
                    println!("Verified: signed by key-id={}", key.key_id);
                    break;
                }
            }

            if !verified {
                return Err(anyhow::anyhow!(
                    "verification failed: no matching signer key found"
                ));
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
