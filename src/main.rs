use anyhow::{Context, Result};
use clap::Parser;
use pqp::cli::{Cli, Commands};
use pqp::crypto::sign;
use pqp::crypto::sym;
use pqp::{crypto, format, keyring};
use std::io::Read;
use zeroize::Zeroize;

fn read_passphrase(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).context("reading passphrase")
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
        Commands::GenKey { user } => {
            let passphrase = read_passphrase("Enter passphrase for new key: ")?;
            let passphrase2 = read_passphrase("Confirm passphrase: ")?;
            if passphrase != passphrase2 {
                return Err(anyhow::anyhow!("passphrases do not match"));
            }
            let meta = keyring::generate_key(&user, &passphrase)?;
            println!("Generated key pair: key-id={}", meta.key_id);
            println!("  user-id: {}", meta.user_id);
            println!("  created: {}", meta.created_at);
        }
        Commands::ListKeys => {
            let keys = keyring::list_keys()?;
            if keys.is_empty() {
                println!("No keys in keyring.");
            } else {
                println!("Key ID        User ID               Created");
                println!("{}", "-".repeat(55));
                for key in &keys {
                    println!("{:<14} {:<20} {}", key.key_id, key.user_id, key.created_at);
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

            let data = read_file(&input)?;

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

            let out_path = output.unwrap_or_else(|| format!("{}.pqp.enc", input));
            write_file(&out_path, &serialized)?;
            println!("Encrypted: {}", out_path);
        }
        Commands::Decrypt { output, input } => {
            let passphrase = read_passphrase("Enter passphrase for secret key: ")?;

            let data = read_file(&input)?;

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
                let stripped = input.strip_suffix(".pqp.enc").unwrap_or(&input);
                stripped.to_string()
            });
            write_file(&out_path, &plaintext)?;
            println!("Decrypted: {}", out_path);
        }
        Commands::Sign {
            user,
            output,
            input,
        } => {
            let user_id = keyring::resolve_key_id(&user).context("resolving signing key")?;
            let passphrase = read_passphrase("Enter passphrase for signing key: ")?;
            let data = read_file(&input)?;

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

            let out_path = output.unwrap_or_else(|| format!("{}.pqp.sig", input));
            write_file(&out_path, &serialized)?;
            println!("Signed: {}", out_path);
        }
        Commands::Verify { signature, input } => {
            let sig_data = read_file(&signature)?;
            let orig_data = read_file(&input)?;

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
        Commands::Import { input } => {
            let armored = std::fs::read_to_string(&input).context(format!("reading {}", input))?;
            let key_id = keyring::import_public_key(&armored)?;
            println!("Imported: key-id={}", key_id);
        }
    }

    Ok(())
}
