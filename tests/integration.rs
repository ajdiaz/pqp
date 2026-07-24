use pqp::armor::Encoding;
use pqp::crypto::kem;
use pqp::crypto::keygen;
use pqp::crypto::sign;
use pqp::crypto::{DsaVariant, KemVariant};
use std::path::PathBuf;
use std::process::Command;

fn pqp_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pqp"))
}

#[test]
fn test_gen_key_and_list_keys() {
    let meta = pqp::keyring::generate_key(
        "test@example.com",
        "testpass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
    )
    .unwrap();
    assert_eq!(meta.user_id, "test@example.com");
    assert!(!meta.key_id.is_empty());
}

#[test]
fn test_cli_help() {
    let output = Command::new(pqp_binary())
        .args(["--help"])
        .env_remove("HOME")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("pqp"));
    assert!(stdout.contains("gen-key"));
    assert!(stdout.contains("encrypt"));
    assert!(stdout.contains("decrypt"));
    assert!(stdout.contains("sign"));
    assert!(stdout.contains("verify"));
    assert!(stdout.contains("export"));
    assert!(stdout.contains("import"));
    assert!(stdout.contains("list-keys"));
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
fn test_compress_decompress_zstd() {
    let data = vec![42u8; 1024];
    let compressed = pqp::format::compress(&data, &pqp::format::Algorithm::Zstd).unwrap();
    assert!(
        compressed.len() < data.len(),
        "zstd should compress repetitive data"
    );
    let decompressed = pqp::format::decompress(&compressed, &pqp::format::Algorithm::Zstd).unwrap();
    assert_eq!(data, decompressed);
}

#[test]
fn test_compress_decompress_deflate() {
    let data = vec![42u8; 1024];
    let compressed = pqp::format::compress(&data, &pqp::format::Algorithm::Deflate).unwrap();
    assert!(
        compressed.len() < data.len(),
        "deflate should compress repetitive data"
    );
    let decompressed =
        pqp::format::decompress(&compressed, &pqp::format::Algorithm::Deflate).unwrap();
    assert_eq!(data, decompressed);
}

#[test]
fn test_compress_decompress_gzip() {
    let data = vec![42u8; 1024];
    let compressed = pqp::format::compress(&data, &pqp::format::Algorithm::Gzip).unwrap();
    assert!(
        compressed.len() < data.len(),
        "gzip should compress repetitive data"
    );
    let decompressed = pqp::format::decompress(&compressed, &pqp::format::Algorithm::Gzip).unwrap();
    assert_eq!(data, decompressed);
}

#[test]
fn test_compress_decompress_bzip2() {
    let data = vec![42u8; 1024];
    let compressed = pqp::format::compress(&data, &pqp::format::Algorithm::Bzip2).unwrap();
    assert!(
        compressed.len() < data.len(),
        "bzip2 should compress repetitive data"
    );
    let decompressed =
        pqp::format::decompress(&compressed, &pqp::format::Algorithm::Bzip2).unwrap();
    assert_eq!(data, decompressed);
}

#[test]
fn test_compress_decompress_lzma() {
    let data = vec![42u8; 1024];
    let compressed = pqp::format::compress(&data, &pqp::format::Algorithm::Lzma).unwrap();
    assert!(
        compressed.len() < data.len(),
        "lzma should compress repetitive data"
    );
    let decompressed = pqp::format::decompress(&compressed, &pqp::format::Algorithm::Lzma).unwrap();
    assert_eq!(data, decompressed);
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
    let armored = pqp::armor::armor(data, marker, &Encoding::Base64, &[]).unwrap();
    assert!(armored.contains(&format!("-----BEGIN {}-----", marker)));
    assert!(armored.contains(&format!("-----END {}-----", marker)));

    let (parsed_marker, decoded, meta) = pqp::armor::unarmor(&armored).unwrap();
    assert_eq!(marker, parsed_marker);
    assert_eq!(data.to_vec(), decoded);
    assert!(meta.is_empty());
}

#[test]
fn test_kem_roundtrip() {
    let (sk, pk) = kem::keypair(KemVariant::MlKem768).unwrap();
    let (ct, shared1) = kem::encapsulate(&pk).unwrap();
    let shared2 = kem::decapsulate(&sk, &ct, KemVariant::MlKem768).unwrap();
    assert_eq!(shared1, shared2);
}

#[test]
fn test_sign_roundtrip() {
    let (sk, pk) = sign::keypair(DsaVariant::MlDsa65).unwrap();
    let msg = b"test message for signing";
    let sig = sign::sign(&sk, msg, DsaVariant::MlDsa65).unwrap();
    let result = sign::verify(&pk, msg, &sig).unwrap();
    assert!(result);
}

#[test]
fn test_sign_rejects_tampered() {
    let (sk, pk) = sign::keypair(DsaVariant::MlDsa65).unwrap();
    let msg = b"test message";
    let sig = sign::sign(&sk, msg, DsaVariant::MlDsa65).unwrap();
    let wrong_msg = b"wrong message";
    let result = sign::verify(&pk, wrong_msg, &sig).unwrap();
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
    let kp = keygen::generate(KemVariant::MlKem768, DsaVariant::MlDsa65).unwrap();

    let (ct, shared1) = kem::encapsulate(&kp.kem_public).unwrap();
    let shared2 = kem::decapsulate(&kp.kem_secret, &ct, KemVariant::MlKem768).unwrap();
    assert_eq!(shared1, shared2);

    let msg = b"keygen integration test";
    let sig = sign::sign(&kp.sign_secret, msg, DsaVariant::MlDsa65).unwrap();
    let valid = sign::verify(&kp.sign_public, msg, &sig).unwrap();
    assert!(valid);
}

#[test]
fn test_cli_sign_verify_stdin() {
    let meta = pqp::keyring::generate_key(
        "sign-stdin@example.com",
        "",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
    )
    .unwrap();

    let outdir = std::env::temp_dir().join(format!("pqp_sign_stdin_{}", meta.key_id));
    let _ = std::fs::remove_dir_all(&outdir);
    std::fs::create_dir_all(&outdir).unwrap();
    let sig_path = outdir.join("msg.txt.pqp.sig");
    let data_path = outdir.join("msg.txt");
    std::fs::write(&data_path, b"sign me via stdin").unwrap();

    let output = Command::new(pqp_binary())
        .args([
            "sign",
            "-u",
            &meta.key_id,
            "--no-passphrase",
            "-o",
            &sig_path.to_string_lossy(),
            &data_path.to_string_lossy(),
        ])
        .env_remove("HOME")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::new(pqp_binary())
        .args([
            "verify",
            &sig_path.to_string_lossy(),
            &data_path.to_string_lossy(),
        ])
        .env_remove("HOME")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Verified"));

    let _ = std::fs::remove_dir_all(&outdir);
}

#[test]
fn test_gen_key_no_passphrase() {
    let meta = pqp::keyring::generate_key(
        "nopass@example.com",
        "",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
    )
    .unwrap();
    assert_eq!(meta.user_id, "nopass@example.com");
    let (_kem_sk, _sign_sk, _, _) = pqp::keyring::load_secret_key(&meta.key_id, "").unwrap();
}

#[test]
fn test_cli_gen_key_no_passphrase() {
    let outdir = std::env::temp_dir().join("pqp_cli_gen_nopass");
    let _ = std::fs::remove_dir_all(&outdir);
    std::fs::create_dir_all(&outdir).unwrap();
    let home = outdir.to_string_lossy().to_string();

    let output = Command::new(pqp_binary())
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

    let output = Command::new(pqp_binary())
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

    let output = Command::new(pqp_binary())
        .args(["gen-key", "-u", "enc-nopass@example.com", "--no-passphrase"])
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(output.status.success(), "gen-key failed");

    let output = Command::new(pqp_binary())
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

    let plain_path = outdir.join("data.txt");
    std::fs::write(&plain_path, b"data with no passphrase").unwrap();

    let enc_path = outdir.join("data.txt.pqp.enc");
    let output = Command::new(pqp_binary())
        .args([
            "encrypt",
            "-r",
            &key_id,
            "-o",
            &enc_path.to_string_lossy(),
            &plain_path.to_string_lossy(),
        ])
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "encrypt with nopass key failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let dec_path = outdir.join("data.dec");
    let output = Command::new(pqp_binary())
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

    let decrypted = std::fs::read_to_string(&dec_path).unwrap();
    assert_eq!(decrypted, "data with no passphrase");

    let _ = std::fs::remove_dir_all(&outdir);
}

#[test]
fn test_cli_encrypt_decrypt_with_compression() {
    let outdir = std::env::temp_dir().join("pqp_compress");
    let _ = std::fs::remove_dir_all(&outdir);
    std::fs::create_dir_all(&outdir).unwrap();
    let home = outdir.to_string_lossy().to_string();

    let output = Command::new(pqp_binary())
        .args(["gen-key", "-u", "compress@example.com", "--no-passphrase"])
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(output.status.success(), "gen-key failed");

    let output = Command::new(pqp_binary())
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

    let data = b"AAAAAABBBBBBCCCCCCDDDDDDEEEEEEFFFFFGGGGGHHHHHIIIIIJJJJJKKKKKLLLLL"; // repetitive
    let plain_path = outdir.join("data.txt");
    std::fs::write(&plain_path, data).unwrap();

    for algo in &["zstd", "gzip", "bzip2", "lzma"] {
        let enc_path = outdir.join(format!("data.{}.pqp.enc", algo));
        let output = Command::new(pqp_binary())
            .args([
                "encrypt",
                "-r",
                &key_id,
                "--compress",
                algo,
                "-o",
                &enc_path.to_string_lossy(),
                &plain_path.to_string_lossy(),
            ])
            .env("HOME", &home)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "encrypt with --compress {} failed: {}",
            algo,
            String::from_utf8_lossy(&output.stderr)
        );

        let dec_path = outdir.join(format!("data.{}.dec", algo));
        let output = Command::new(pqp_binary())
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
            "decrypt with compress {} failed: {}",
            algo,
            String::from_utf8_lossy(&output.stderr)
        );

        let decrypted = std::fs::read_to_string(&dec_path).unwrap();
        assert_eq!(
            decrypted,
            std::str::from_utf8(data).unwrap(),
            "mismatch for compress {}",
            algo
        );
    }

    let _ = std::fs::remove_dir_all(&outdir);
}

#[test]
fn test_format_algorithm_list_compression() {
    let alg_str = "ML-KEM+XChaCha20-Poly1305+ZSTD+BASE64";
    let list = pqp::format::AlgorithmList::parse(alg_str).unwrap();
    assert_eq!(list.algorithms().len(), 4);
    assert_eq!(list.compression(), Some(&pqp::format::Algorithm::Zstd));
    assert_eq!(list.to_string(), alg_str);
}

#[test]
fn test_dry_run_gen_key() {
    let output = Command::new(pqp_binary())
        .args(["--dry-run", "gen-key", "-u", "dry@example.com"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("dry-run"), "stderr: {stderr}");
    assert!(stderr.contains("gen-key"), "stderr: {stderr}");
}

#[test]
fn test_dry_run_list_keys() {
    let output = Command::new(pqp_binary())
        .args(["--dry-run", "list-keys"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("list-keys"));
}

#[test]
fn test_dry_run_encrypt() {
    let output = Command::new(pqp_binary())
        .args(["--dry-run", "encrypt", "-r", "deadbeef", "-o", "/dev/null"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("encrypt"));
}

#[test]
fn test_dry_run_decrypt() {
    let output = Command::new(pqp_binary())
        .args(["--dry-run", "decrypt", "-o", "/dev/null"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("decrypt"));
}

#[test]
fn test_dry_run_sign() {
    let output = Command::new(pqp_binary())
        .args(["--dry-run", "sign", "-u", "deadbeef", "-o", "/dev/null"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("sign"));
}

#[test]
fn test_dry_run_verify() {
    let output = Command::new(pqp_binary())
        .args(["--dry-run", "verify", "/dev/null"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("verify"));
}

#[test]
fn test_dry_run_remove_key() {
    let output = Command::new(pqp_binary())
        .args(["--dry-run", "remove-key", "deadbeef"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("remove-key"));
}

#[test]
fn test_dry_run_export() {
    let output = Command::new(pqp_binary())
        .args(["--dry-run", "export", "deadbeef"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("export"));
}

#[test]
fn test_dry_run_import() {
    let output = Command::new(pqp_binary())
        .args(["--dry-run", "import"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("import"));
}

#[test]
fn test_dry_run_short_flag() {
    let output = Command::new(pqp_binary())
        .args(["-n", "list-keys"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("dry-run"));
}

#[test]
fn test_encode_payload_ignores_compression() {
    let algorithms = pqp::format::AlgorithmList::new(vec![
        pqp::format::Algorithm::Zstd,
        pqp::format::Algorithm::Base64,
    ]);
    let data = b"hello world";
    let encoded = pqp::format::encode_payload(&algorithms, data).unwrap();
    // encode_payload now only applies BASE64, so decoded should be the original
    let decoded = pqp::format::decode_payload(&algorithms, &encoded).unwrap();
    assert_eq!(data.to_vec(), decoded);
}

fn tmp_home(name: &str) -> String {
    let dir = std::env::temp_dir().join(format!("pqp_int_{}", name));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.to_string_lossy().to_string()
}

fn get_key_id(pqp_home_val: &str) -> String {
    let output = Command::new(pqp_binary())
        .args(["list-keys", "--format", "no-headers"])
        .env("PQP_HOME", pqp_home_val)
        .output()
        .unwrap();
    assert!(output.status.success(), "list-keys failed");
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

fn gen_expired_key(pqp_home_val: &str, user: &str) -> String {
    let output = Command::new(pqp_binary())
        .args([
            "gen-key",
            "-u",
            user,
            "--no-passphrase",
            "--expiration-date",
            "2000-01-01",
        ])
        .env("PQP_HOME", pqp_home_val)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "gen-key for expired key failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    get_key_id(pqp_home_val)
}

#[test]
fn test_cli_gen_key_expiration_relative() {
    let home = tmp_home("gen_exp_rel");
    let output = Command::new(pqp_binary())
        .args([
            "gen-key",
            "-u",
            "exp-rel@example.com",
            "--no-passphrase",
            "--expiration-date",
            "30d",
        ])
        .env("PQP_HOME", &home)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "gen-key with --expiration-date 30d failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("exp-rel@example.com"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("expires"),
        "output should show expiration: {}",
        stdout
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn test_cli_gen_key_expiration_absolute() {
    let home = tmp_home("gen_exp_abs");
    let output = Command::new(pqp_binary())
        .args([
            "gen-key",
            "-u",
            "exp-abs@example.com",
            "--no-passphrase",
            "--expiration-date",
            "2035-12-31",
        ])
        .env("PQP_HOME", &home)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "gen-key with --expiration-date 2035-12-31 failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("2035-12-31"),
        "output should show year 2035: {}",
        stdout
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn test_cli_gen_key_default_expiration() {
    let home = tmp_home("gen_exp_def");
    let output = Command::new(pqp_binary())
        .args(["gen-key", "-u", "exp-def@example.com", "--no-passphrase"])
        .env("PQP_HOME", &home)
        .output()
        .unwrap();
    assert!(output.status.success(), "gen-key default failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("expires"),
        "output should show expiration: {}",
        stdout
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn test_cli_encrypt_rejects_expired_key() {
    let home = tmp_home("enc_exp_rej");
    let key_id = gen_expired_key(&home, "expired@example.com");

    let plain_path = std::path::Path::new(&home).join("data.txt");
    std::fs::write(&plain_path, b"test data").unwrap();

    let enc_out = std::path::Path::new(&home).join("out.pqp.enc");
    let output = Command::new(pqp_binary())
        .args([
            "encrypt",
            "-r",
            &key_id,
            "-o",
            enc_out.to_str().unwrap(),
            plain_path.to_str().unwrap(),
        ])
        .env("PQP_HOME", &home)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "encrypt should reject expired key, but succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("expired"),
        "stderr should mention expired: {}",
        stderr
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn test_cli_encrypt_allow_expired() {
    let home = tmp_home("enc_exp_allow");
    let key_id = gen_expired_key(&home, "exp-allowed@example.com");

    let plain_path = std::path::Path::new(&home).join("data.txt");
    std::fs::write(&plain_path, b"test data").unwrap();

    let enc_out = std::path::Path::new(&home).join("out.pqp.enc");
    let output = Command::new(pqp_binary())
        .args([
            "encrypt",
            "-r",
            &key_id,
            "--allow-expired",
            "-o",
            enc_out.to_str().unwrap(),
            plain_path.to_str().unwrap(),
        ])
        .env("PQP_HOME", &home)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "encrypt with --allow-expired should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("expired"),
        "stderr should warn about expired: {}",
        stderr
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn test_cli_sign_rejects_expired_key() {
    let home = tmp_home("sig_exp_rej");
    let key_id = gen_expired_key(&home, "sig-expired@example.com");

    let data_path = std::path::Path::new(&home).join("data.txt");
    std::fs::write(&data_path, b"sign me").unwrap();

    let sig_out = std::path::Path::new(&home).join("data.txt.pqp.sig");
    let output = Command::new(pqp_binary())
        .args([
            "sign",
            "-u",
            &key_id,
            "--no-passphrase",
            "-o",
            sig_out.to_str().unwrap(),
            data_path.to_str().unwrap(),
        ])
        .env("PQP_HOME", &home)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "sign should reject expired key, but succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("expired"),
        "stderr should mention expired: {}",
        stderr
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn test_cli_sign_allow_expired() {
    let home = tmp_home("sig_exp_allow");
    let key_id = gen_expired_key(&home, "sig-exp-allowed@example.com");

    let data_path = std::path::Path::new(&home).join("data.txt");
    std::fs::write(&data_path, b"sign me anyway").unwrap();

    let sig_out = std::path::Path::new(&home).join("data.txt.pqp.sig");
    let output = Command::new(pqp_binary())
        .args([
            "sign",
            "-u",
            &key_id,
            "--no-passphrase",
            "--allow-expired",
            "-o",
            sig_out.to_str().unwrap(),
            data_path.to_str().unwrap(),
        ])
        .env("PQP_HOME", &home)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sign with --allow-expired should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("expired"),
        "stderr should warn about expired: {}",
        stderr
    );

    let output = Command::new(pqp_binary())
        .args([
            "verify",
            sig_out.to_str().unwrap(),
            data_path.to_str().unwrap(),
        ])
        .env("PQP_HOME", &home)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "verify should succeed for signature made with --allow-expired: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Verified"));
    let _ = std::fs::remove_dir_all(&home);
}
