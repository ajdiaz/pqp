use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn pqp_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pqp"))
}

fn run_pqp(args: &[&str], stdin: Option<&str>) -> Result<String, String> {
    let mut cmd = Command::new(pqp_binary());
    cmd.args(args);
    cmd.env_remove("HOME");

    if let Some(input) = stdin {
        let mut child = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn failed: {}", e))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(input.as_bytes())
                .map_err(|e| format!("stdin write failed: {}", e))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("wait failed: {}", e))?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(format!(
                "exit code: {}\nstdout: {}\nstderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    } else {
        let output = cmd.output().map_err(|e| format!("output failed: {}", e))?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(format!(
                "exit code: {}\nstdout: {}\nstderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }
}

#[test]
fn test_gen_key_and_list_keys() {
    let meta = pqp::keyring::generate_key("test@example.com", "testpass").unwrap();
    assert_eq!(meta.user_id, "test@example.com");
    assert!(!meta.key_id.is_empty());
}

#[test]
fn test_cli_help() {
    let output = run_pqp(&["--help"], None).unwrap();
    assert!(output.contains("pqp"));
    assert!(output.contains("gen-key"));
    assert!(output.contains("encrypt"));
    assert!(output.contains("decrypt"));
    assert!(output.contains("sign"));
    assert!(output.contains("verify"));
    assert!(output.contains("export"));
    assert!(output.contains("import"));
    assert!(output.contains("list-keys"));
}

#[test]
fn test_format_algorithm_list() {
    let alg_str = "ML-KEM+XChaCha20-Poly1305+BASE64";
    let list = pqp::format::AlgorithmList::parse(alg_str).unwrap();
    assert_eq!(list.algorithms().len(), 3);
    assert_eq!(list.to_string(), alg_str);
}

#[test]
fn test_format_payload_roundtrip() {
    let algorithms = pqp::format::AlgorithmList::new(vec![pqp::format::Algorithm::Base64]);
    let data = b"Hello, PQ world!";
    let encoded = pqp::format::encode_payload(&algorithms, data).unwrap();
    let decoded = pqp::format::decode_payload(&algorithms, &encoded).unwrap();
    assert_eq!(data.to_vec(), decoded);
}

#[test]
fn test_format_ascii85_roundtrip() {
    let algorithms = pqp::format::AlgorithmList::new(vec![pqp::format::Algorithm::Ascii85]);
    let data = b"Hello, ASCII85 world!";
    let encoded = pqp::format::encode_payload(&algorithms, data).unwrap();
    let decoded = pqp::format::decode_payload(&algorithms, &encoded).unwrap();
    assert_eq!(data.to_vec(), decoded);
}

#[test]
fn test_format_zstd_roundtrip() {
    let algorithms = pqp::format::AlgorithmList::new(vec![
        pqp::format::Algorithm::Zstd,
        pqp::format::Algorithm::Base64,
    ]);
    let data = vec![42u8; 1024];
    let encoded = pqp::format::encode_payload(&algorithms, &data).unwrap();
    let decoded = pqp::format::decode_payload(&algorithms, &encoded).unwrap();
    assert_eq!(data, decoded);
}

#[test]
fn test_format_deflate_roundtrip() {
    let algorithms = pqp::format::AlgorithmList::new(vec![
        pqp::format::Algorithm::Deflate,
        pqp::format::Algorithm::Base64,
    ]);
    let data = vec![42u8; 1024];
    let encoded = pqp::format::encode_payload(&algorithms, &data).unwrap();
    let decoded = pqp::format::decode_payload(&algorithms, &encoded).unwrap();
    assert_eq!(data, decoded);
}

#[test]
fn test_format_serialize_deserialize() {
    let algorithms = pqp::format::AlgorithmList::new(vec![pqp::format::Algorithm::Base64]);
    let data = b"round trip test data";
    let serialized = pqp::format::serialize(&algorithms, data).unwrap();
    let (parsed_algs, deserialized) = pqp::format::deserialize(&serialized).unwrap();
    assert_eq!(algorithms.to_string(), parsed_algs.to_string());
    assert_eq!(data.to_vec(), deserialized);
}

#[test]
fn test_armor_roundtrip() {
    let data = b"armor test data";
    let marker = "TEST KEY";
    let armored = pqp::armor::armor(data, marker).unwrap();
    assert!(armored.contains(&format!("-----BEGIN {}-----", marker)));
    assert!(armored.contains(&format!("-----END {}-----", marker)));

    let (parsed_marker, decoded) = pqp::armor::unarmor(&armored).unwrap();
    assert_eq!(marker, parsed_marker);
    assert_eq!(data.to_vec(), decoded);
}

#[test]
fn test_kem_roundtrip() {
    let (sk, pk) = pqp::crypto::kem::keypair().unwrap();
    let (ct, shared1) = pqp::crypto::kem::encapsulate(&pk).unwrap();
    let shared2 = pqp::crypto::kem::decapsulate(&sk, &ct).unwrap();
    assert_eq!(shared1, shared2);
}

#[test]
fn test_sign_roundtrip() {
    let (sk, pk) = pqp::crypto::sign::keypair().unwrap();
    let msg = b"test message for signing";
    let sig = pqp::crypto::sign::sign(&sk, msg).unwrap();
    let result = pqp::crypto::sign::verify(&pk, msg, &sig).unwrap();
    assert!(result);
}

#[test]
fn test_sign_rejects_tampered() {
    let (sk, pk) = pqp::crypto::sign::keypair().unwrap();
    let msg = b"test message";
    let sig = pqp::crypto::sign::sign(&sk, msg).unwrap();
    let wrong_msg = b"wrong message";
    let result = pqp::crypto::sign::verify(&pk, wrong_msg, &sig).unwrap();
    assert!(!result);
}

#[test]
fn test_sym_encrypt_decrypt() {
    let key = [0x42u8; 32];
    let plaintext = b"sensitive data for symmetric encryption";
    let (nonce, ciphertext) = pqp::crypto::sym::encrypt(&key, plaintext).unwrap();
    assert_ne!(ciphertext, plaintext);

    let decrypted = pqp::crypto::sym::decrypt(&key, &nonce, &ciphertext).unwrap();
    assert_eq!(plaintext.to_vec(), decrypted);
}

#[test]
fn test_sym_encrypt_wrong_key() {
    let key1 = [0x42u8; 32];
    let key2 = [0x24u8; 32];
    let plaintext = b"test data";
    let (nonce, ciphertext) = pqp::crypto::sym::encrypt(&key1, plaintext).unwrap();
    let result = pqp::crypto::sym::decrypt(&key2, &nonce, &ciphertext);
    assert!(result.is_err());
}

#[test]
fn test_key_derivation() {
    let passphrase = "my-secure-passphrase";
    let salt = [0xABu8; 16];
    let key = pqp::crypto::sym::derive_key(passphrase, &salt).unwrap();
    assert_eq!(key.len(), 32);

    let key2 = pqp::crypto::sym::derive_key(passphrase, &salt).unwrap();
    assert_eq!(key, key2);

    let salt2 = [0xBAu8; 16];
    let key3 = pqp::crypto::sym::derive_key(passphrase, &salt2).unwrap();
    assert_ne!(key, key3);
}

#[test]
fn test_keygen_produces_valid_keys() {
    let kp = pqp::crypto::keygen::generate().unwrap();

    let (ct, shared1) = pqp::crypto::kem::encapsulate(&kp.kem_public).unwrap();
    let shared2 = pqp::crypto::kem::decapsulate(&kp.kem_secret, &ct).unwrap();
    assert_eq!(shared1, shared2);

    let msg = b"keygen integration test";
    let sig = pqp::crypto::sign::sign(&kp.sign_secret, msg).unwrap();
    let valid = pqp::crypto::sign::verify(&kp.sign_public, msg, &sig).unwrap();
    assert!(valid);
}

#[test]
fn test_cli_encrypt_decrypt_stdin() {
    let meta = pqp::keyring::generate_key("stdin-test@example.com", "testpass").unwrap();

    let outdir = std::env::temp_dir().join(format!("pqp_stdin_{}", meta.key_id));
    let _ = std::fs::remove_dir_all(&outdir);
    std::fs::create_dir_all(&outdir).unwrap();
    let enc_path = outdir.join("out.pqp.enc");
    let dec_path = outdir.join("out.txt");

    let mut child = std::process::Command::new(pqp_binary())
        .args([
            "encrypt",
            "-r",
            &meta.key_id,
            "-o",
            &enc_path.to_string_lossy(),
        ])
        .env_remove("HOME")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"hello from stdin")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "encrypt stdin failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut child = std::process::Command::new(pqp_binary())
        .args([
            "decrypt",
            "-o",
            &dec_path.to_string_lossy(),
            &enc_path.to_string_lossy(),
        ])
        .env_remove("HOME")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"testpass\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "decrypt failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let decrypted = std::fs::read_to_string(&dec_path).unwrap();
    assert_eq!(decrypted, "hello from stdin");
    let _ = std::fs::remove_dir_all(&outdir);
}

#[test]
fn test_cli_sign_verify_stdin() {
    let meta = pqp::keyring::generate_key("sign-stdin@example.com", "testpass").unwrap();

    let outdir = std::env::temp_dir().join(format!("pqp_sign_stdin_{}", meta.key_id));
    let _ = std::fs::remove_dir_all(&outdir);
    std::fs::create_dir_all(&outdir).unwrap();
    let sig_path = outdir.join("msg.txt.pqp.sig");
    let data_path = outdir.join("msg.txt");
    std::fs::write(&data_path, b"sign me via stdin").unwrap();

    let mut child = std::process::Command::new(pqp_binary())
        .args([
            "sign",
            "-u",
            &meta.key_id,
            "-o",
            &sig_path.to_string_lossy(),
            &data_path.to_string_lossy(),
        ])
        .env_remove("HOME")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"testpass\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "sign stdin failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut child = std::process::Command::new(pqp_binary())
        .args([
            "verify",
            &sig_path.to_string_lossy(),
            &data_path.to_string_lossy(),
        ])
        .env_remove("HOME")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"dummy\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "verify stdin failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("Verified"));

    let _ = std::fs::remove_dir_all(&outdir);
}

#[test]
fn test_gen_key_no_passphrase() {
    let meta = pqp::keyring::generate_key("nopass@example.com", "").unwrap();
    assert_eq!(meta.user_id, "nopass@example.com");
    let (_kem_sk, _sign_sk) = pqp::keyring::load_secret_key(&meta.key_id, "").unwrap();
}

#[test]
fn test_cli_gen_key_no_passphrase() {
    let outdir = std::env::temp_dir().join("pqp_cli_gen_nopass");
    let _ = std::fs::remove_dir_all(&outdir);
    std::fs::create_dir_all(&outdir).unwrap();
    let home = outdir.to_string_lossy().to_string();

    let output = std::process::Command::new(pqp_binary())
        .args(["gen-key", "-u", "cli-nopass@example.com", "--no-passphrase"])
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "gen-key --no-passphrase failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("cli-nopass@example.com"));

    let output = std::process::Command::new(pqp_binary())
        .args(["list-keys", "--format", "no-headers"])
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("cli-nopass@example.com"));

    let _ = std::fs::remove_dir_all(&outdir);
}

#[test]
fn test_cli_encrypt_decrypt_no_passphrase_key() {
    let outdir = std::env::temp_dir().join("pqp_enc_nopass");
    let _ = std::fs::remove_dir_all(&outdir);
    std::fs::create_dir_all(&outdir).unwrap();
    let home = outdir.to_string_lossy().to_string();

    let output = std::process::Command::new(pqp_binary())
        .args(["gen-key", "-u", "enc-nopass@example.com", "--no-passphrase"])
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(output.status.success(), "gen-key failed");

    let output = std::process::Command::new(pqp_binary())
        .args(["list-keys", "--format", "no-headers"])
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(output.status.success());
    let key_id = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();

    let enc_path = outdir.join("data.txt.pqp.enc");
    let mut child = std::process::Command::new(pqp_binary())
        .args(["encrypt", "-r", &key_id, "-o", &enc_path.to_string_lossy()])
        .env("HOME", &home)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"data with no passphrase")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "encrypt with nopass key failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let dec_path = outdir.join("data.txt");
    let output = std::process::Command::new(pqp_binary())
        .args([
            "decrypt",
            "--no-passphrase",
            "-o",
            &dec_path.to_string_lossy(),
            &enc_path.to_string_lossy(),
        ])
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "decrypt with nopass key failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        out.status.success(),
        "decrypt with nopass key failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let decrypted = std::fs::read_to_string(&dec_path).unwrap();
    assert_eq!(decrypted, "data with no passphrase");

    let _ = std::fs::remove_dir_all(&outdir);
}
