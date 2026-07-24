use pqp::armor::Encoding;
use pqp::crypto::{DsaVariant, KemVariant};
use std::path::PathBuf;

/// RAII guard for a temporary keyring directory.
///
/// Creates a unique temp directory, sets it as the keyring override
/// via [`pqp::keyring::set_keyring_override`], and removes it on Drop.
/// For CLI subprocess tests, use [`path()`](TestKeyring::path) and pass
/// it via `KEYRING_PATH` env var.
struct TestKeyring {
    path: PathBuf,
}

impl TestKeyring {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("pqp_kr_{}", name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Use KEYRING_PATH env var so both direct library calls (via keys_dir())
        // and CLI subprocess calls (via main.rs startup) resolve to this directory.
        std::env::set_var("KEYRING_PATH", &dir);
        TestKeyring { path: dir }
    }

    fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl Drop for TestKeyring {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[test]
fn test_list_keys_empty() {
    let _k = TestKeyring::new("list_empty");
    let keys = pqp::keyring::list_keys().unwrap();
    assert!(keys.is_empty());
}

#[test]
fn test_generate_and_export() {
    let k = TestKeyring::new("gen_export");
    let meta = pqp::keyring::generate_key(
        "test@example.com",
        "testpass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();
    assert_eq!(meta.user_id, "test@example.com");
    assert!(!meta.key_id.is_empty());

    // Verify key exists on disk at the overridden keyring path
    let key_dir = k.path().join(&meta.key_id);
    assert!(
        key_dir.join("pqp.conf").exists(),
        "key directory should exist"
    );

    let keys = pqp::keyring::list_keys().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].key_id, meta.key_id);

    let armored = pqp::keyring::export_public_key(&meta.key_id).unwrap();
    assert!(armored.contains("-----BEGIN PQP PUBLIC KEY"));
    assert!(armored.contains(&meta.key_id));
}

#[test]
fn test_generate_and_load_keys() {
    let _k = TestKeyring::new("gen_load");
    let meta = pqp::keyring::generate_key(
        "load-test@example.com",
        "mypass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();

    let (kem_pk, sign_pk, kem_alg, sign_alg) = pqp::keyring::load_public_key(&meta.key_id).unwrap();
    assert!(!kem_pk.is_empty());
    assert!(!sign_pk.is_empty());
    assert_eq!(kem_alg, "ML-KEM-768");
    assert_eq!(sign_alg, "ML-DSA-65");

    let (kem_sk, sign_sk, _, _) = pqp::keyring::load_secret_key(&meta.key_id, "mypass").unwrap();
    assert!(!kem_sk.is_empty());
    assert!(!sign_sk.is_empty());

    let pk = pqp::crypto::kem::PublicKey::from_bytes(&kem_pk, KemVariant::MlKem768).unwrap();
    let sk = pqp::crypto::kem::SecretKey::from_bytes(&kem_sk).unwrap();
    let (ct, shared1) = pqp::crypto::kem::encapsulate(&pk).unwrap();
    let shared2 = pqp::crypto::kem::decapsulate(&sk, &ct, KemVariant::MlKem768).unwrap();
    assert_eq!(shared1, shared2);

    let sign_pk = pqp::crypto::sign::PublicKey::from_bytes(&sign_pk, DsaVariant::MlDsa65).unwrap();
    let sign_sk = pqp::crypto::sign::SecretKey::from_bytes(&sign_sk).unwrap();
    let msg = b"stored key test";
    let sig = pqp::crypto::sign::sign(&sign_sk, msg, DsaVariant::MlDsa65).unwrap();
    assert!(pqp::crypto::sign::verify(&sign_pk, msg, &sig).unwrap());
}

#[test]
fn test_key_info_fields() {
    let _k = TestKeyring::new("key_info");
    let meta = pqp::keyring::generate_key(
        "info@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();

    let keys = pqp::keyring::list_keys().unwrap();
    assert_eq!(keys.len(), 1);
    let info = &keys[0];

    assert!(info.has_public);
    assert!(info.has_secret);
    assert_eq!(info.kem_algorithm, "ML-KEM-768");
    assert_eq!(info.sign_algorithm, "ML-DSA-65");
    assert_eq!(info.encoding_algorithm, "BASE64");
    assert_eq!(info.key_id, meta.key_id);
    assert_eq!(info.user_id, "info@example.com");
}

#[test]
fn test_key_expiration_relative() {
    let _k = TestKeyring::new("exp_rel");
    let meta = pqp::keyring::generate_key(
        "exp-rel@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "30d",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();
    assert!(!meta.expiration_date.is_empty());
    assert!(meta.expiration_date.contains('T'));
    assert!(meta.expiration_date.ends_with('Z'));
    assert_eq!(meta.expiration_date.len(), 20);
    assert!(!pqp::expiry::is_expired(&meta.expiration_date));
    let keys = pqp::keyring::list_keys().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].expiration_date, meta.expiration_date);
}

#[test]
fn test_key_expiration_absolute() {
    let _k = TestKeyring::new("exp_abs");
    let meta = pqp::keyring::generate_key(
        "exp-abs@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "2030-06-15",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();
    assert!(meta.expiration_date.starts_with("2030-06-15"));
    assert!(!pqp::expiry::is_expired(&meta.expiration_date));
    let keys = pqp::keyring::list_keys().unwrap();
    assert_eq!(keys[0].expiration_date, meta.expiration_date);
}

#[test]
fn test_key_expired_check() {
    let _k = TestKeyring::new("exp_chk");
    let meta = pqp::keyring::generate_key(
        "exp-chk@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "2000-01-01",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();
    assert!(pqp::expiry::is_expired(&meta.expiration_date));
    assert!(pqp::keyring::check_key_expired(&meta.key_id).unwrap());
}

#[test]
fn test_resolve_key_id_by_key_id() {
    let _k = TestKeyring::new("resolve_id");
    let meta = pqp::keyring::generate_key(
        "resolve@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();

    let resolved = pqp::keyring::resolve_key_id(&meta.key_id).unwrap();
    assert_eq!(resolved, meta.key_id);
}

#[test]
fn test_resolve_key_id_by_user_id() {
    let _k = TestKeyring::new("resolve_user");
    pqp::keyring::generate_key(
        "alice@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();

    let resolved = pqp::keyring::resolve_key_id("alice@example.com").unwrap();
    let keys = pqp::keyring::list_keys().unwrap();
    assert_eq!(resolved, keys[0].key_id);
}

#[test]
fn test_resolve_key_id_not_found() {
    let _k = TestKeyring::new("resolve_nf");
    let result = pqp::keyring::resolve_key_id("nonexistent");
    assert!(result.is_err());
}

#[test]
fn test_key_info_public_only_key() {
    let k = TestKeyring::new("pub_only");
    let meta = pqp::keyring::generate_key(
        "pubonly@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();

    std::fs::remove_file(k.path().join(&meta.key_id).join("pqp-secret.der")).unwrap();

    let keys = pqp::keyring::list_keys().unwrap();
    assert!(keys[0].has_public);
    assert!(!keys[0].has_secret);
}

#[test]
fn test_import_with_confirmation() {
    let k = TestKeyring::new("import_confirm");
    let meta = pqp::keyring::generate_key(
        "export@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();
    let armored = pqp::keyring::export_public_key(&meta.key_id).unwrap();
    let key_file = k.path().join("export_key.pqp.asc");
    std::fs::write(&key_file, &armored).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqp"))
        .args([
            "import",
            "--dont-ask-confirmation",
            &key_file.to_string_lossy(),
        ])
        .env("KEYRING_PATH", k.path().to_string_lossy().to_string())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains(&meta.key_id));
}

#[test]
fn test_remove_key_public_only() {
    let k = TestKeyring::new("remove_pub");
    let meta = pqp::keyring::generate_key(
        "remove-pub@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();
    let key_id = meta.key_id.clone();

    assert!(pqp::keyring::list_keys().unwrap().len() == 1);

    pqp::keyring::remove_key(&key_id, false).unwrap();

    let keys = pqp::keyring::list_keys().unwrap();
    assert!(keys.is_empty(), "key should be removed from listing");

    // Secret file remains but no public + conf, so list_keys won't find it
    let dir = k.path().join(&key_id);
    assert!(
        dir.join("pqp-secret.der").exists(),
        "secret key should remain"
    );
}

#[test]
fn test_remove_key_public_and_private() {
    let k = TestKeyring::new("remove_both");
    let meta = pqp::keyring::generate_key(
        "remove-both@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();
    let key_id = meta.key_id.clone();

    pqp::keyring::remove_key(&key_id, true).unwrap();

    let keys = pqp::keyring::list_keys().unwrap();
    assert!(keys.is_empty(), "key should be removed completely");

    let dir = k.path().join(&key_id);
    assert!(!dir.exists(), "key directory should be removed");
}

#[test]
fn test_remove_key_nonexistent() {
    let _k = TestKeyring::new("remove_nonexistent");
    let result = pqp::keyring::remove_key("nonexistent-key-id", false);
    assert!(result.is_err());
}

#[test]
fn test_resolve_key_ids_by_key_id() {
    let _k = TestKeyring::new("res_ids_id");
    let meta = pqp::keyring::generate_key(
        "resolve-ids@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();

    let ids = pqp::keyring::resolve_key_ids(&meta.key_id).unwrap();
    assert_eq!(ids, vec![meta.key_id]);
}

#[test]
fn test_resolve_key_ids_by_user_id() {
    let _k = TestKeyring::new("res_ids_user");
    pqp::keyring::generate_key(
        "multi@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();
    pqp::keyring::generate_key(
        "multi@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();

    let ids = pqp::keyring::resolve_key_ids("multi@example.com").unwrap();
    assert_eq!(ids.len(), 2, "should find both keys with same user ID");
    assert_ne!(ids[0], ids[1], "key IDs should be different");
}

#[test]
fn test_resolve_key_ids_not_found() {
    let _k = TestKeyring::new("res_ids_nf");
    let result = pqp::keyring::resolve_key_ids("nonexistent");
    assert!(result.is_err());
}

#[test]
fn test_cli_remove_key_public_only() {
    let k = TestKeyring::new("cli_remove_pub");
    let meta = pqp::keyring::generate_key(
        "cli-remove-pub@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();
    let key_id = meta.key_id.clone();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqp"))
        .args(["remove-key", "--dont-ask", &key_id])
        .env("KEYRING_PATH", k.path().to_string_lossy().to_string())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "remove-key failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let keys = pqp::keyring::list_keys().unwrap();
    assert!(keys.is_empty(), "key should be removed via CLI");
}

#[test]
fn test_cli_remove_key_public_and_private() {
    let k = TestKeyring::new("cli_remove_both");
    let meta = pqp::keyring::generate_key(
        "cli-remove-both@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();
    let key_id = meta.key_id.clone();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqp"))
        .args(["remove-key", "--dont-ask", "--remove-private-key", &key_id])
        .env("KEYRING_PATH", k.path().to_string_lossy().to_string())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "remove-key with private failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let keys = pqp::keyring::list_keys().unwrap();
    assert!(keys.is_empty(), "key should be removed completely via CLI");
}

#[test]
fn test_cli_remove_key_by_user_id() {
    let k = TestKeyring::new("cli_remove_user");
    pqp::keyring::generate_key(
        "remove-by-user@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();
    pqp::keyring::generate_key(
        "remove-by-user@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();

    assert_eq!(pqp::keyring::list_keys().unwrap().len(), 2);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqp"))
        .args(["remove-key", "--dont-ask", "remove-by-user@example.com"])
        .env("KEYRING_PATH", k.path().to_string_lossy().to_string())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "remove-key by user ID failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let keys = pqp::keyring::list_keys().unwrap();
    assert!(keys.is_empty(), "all keys for user ID should be removed");
}

#[test]
fn test_cli_remove_key_not_found() {
    let k = TestKeyring::new("cli_remove_nf");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqp"))
        .args(["remove-key", "--dont-ask", "nonexistent-key"])
        .env("KEYRING_PATH", k.path().to_string_lossy().to_string())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not found"));
}

#[test]
fn test_list_keys_json_format() {
    let k = TestKeyring::new("list_json");
    pqp::keyring::generate_key(
        "json@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqp"))
        .args(["list-keys", "--format", "json"])
        .env("KEYRING_PATH", k.path().to_string_lossy().to_string())
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("json@example.com"));
    assert!(stdout.contains("ML-KEM-768"));
    assert!(stdout.contains("has_public"));
    assert!(stdout.contains("has_secret"));
}

#[test]
fn test_list_keys_no_headers_format() {
    let k = TestKeyring::new("list_nohead");
    pqp::keyring::generate_key(
        "nohead@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqp"))
        .args(["list-keys", "--format", "no-headers"])
        .env("KEYRING_PATH", k.path().to_string_lossy().to_string())
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("Key ID"));
    assert!(stdout.contains("nohead@example.com"));
    assert!(stdout.contains("pub+sec"));
}

#[test]
fn test_import_from_stdin() {
    let k = TestKeyring::new("import_stdin");
    let meta = pqp::keyring::generate_key(
        "stdinimport@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();
    let armored = pqp::keyring::export_public_key(&meta.key_id).unwrap();
    let key_file = k.path().join("import_key.pqp.asc");
    std::fs::write(&key_file, &armored).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqp"))
        .args([
            "import",
            "--dont-ask-confirmation",
            &key_file.to_string_lossy(),
        ])
        .env("KEYRING_PATH", k.path().to_string_lossy().to_string())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "import from stdin failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains(&meta.key_id));
}

#[test]
fn test_export_public_key_pqp_format() {
    let _k = TestKeyring::new("export_pqp");
    let meta = pqp::keyring::generate_key(
        "pqp-export@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();

    let pqp_data = pqp::keyring::export_public_key_pqp(&meta.key_id, None).unwrap();
    assert!(pqp_data.contains("::"));
    assert!(pqp_data.contains("ML-KEM-768"));
    assert!(pqp_data.contains("ML-DSA-65"));
    assert!(pqp_data.contains("BASE64"));

    // Verify it can be deserialized back
    let (algorithms, payload) = pqp::format::deserialize(pqp_data.as_bytes()).unwrap();
    assert!(algorithms
        .algorithms()
        .iter()
        .any(|a| a.to_kem_variant() == Some(KemVariant::MlKem768)));
    assert!(algorithms
        .algorithms()
        .iter()
        .any(|a| a.to_dsa_variant() == Some(DsaVariant::MlDsa65)));
    assert!(!payload.is_empty());
}

#[test]
fn test_import_public_key_from_pqp() {
    let _k = TestKeyring::new("import_pqp");
    let meta = pqp::keyring::generate_key(
        "pqp-import@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();

    let pqp_data = pqp::keyring::export_public_key_pqp(&meta.key_id, None).unwrap();

    // Import into a different keyring
    let _import_k = TestKeyring::new("import_pqp_dest");

    let imported_id = pqp::keyring::import_public_key_from_pqp(&pqp_data).unwrap();
    assert!(!imported_id.is_empty());
    assert_ne!(imported_id, meta.key_id, "imported key should get a new ID");

    // Verify the imported key works
    let (kem_pk, sign_pk, kem_alg, sign_alg) = pqp::keyring::load_public_key(&imported_id).unwrap();
    assert!(!kem_pk.is_empty());
    assert!(!sign_pk.is_empty());
    assert_eq!(kem_alg, "ML-KEM-768");
    assert_eq!(sign_alg, "ML-DSA-65");

    let pk = pqp::crypto::kem::PublicKey::from_bytes(&kem_pk, KemVariant::MlKem768).unwrap();
    let (ct, _shared1) = pqp::crypto::kem::encapsulate(&pk).unwrap();
    assert!(!ct.is_empty());

    let _sign_pk = pqp::crypto::sign::PublicKey::from_bytes(&sign_pk, DsaVariant::MlDsa65).unwrap();
}

#[test]
fn test_cli_export_pqp_format() {
    let k = TestKeyring::new("cli_export_pqp");
    let meta = pqp::keyring::generate_key(
        "cli-pqp-export@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();

    let out_file = k.path().join("exported.pqp.pub");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqp"))
        .args([
            "export",
            "--format",
            "pqp",
            "-o",
            &out_file.to_string_lossy(),
            &meta.key_id,
        ])
        .env("KEYRING_PATH", k.path().to_string_lossy().to_string())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "export --format pqp failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let file_content = std::fs::read_to_string(&out_file).unwrap();
    assert!(file_content.contains("ML-KEM-768"));
    assert!(file_content.contains("ML-DSA-65"));
    assert!(file_content.contains("::"));
}

#[test]
fn test_cli_import_pqp_format() {
    let k = TestKeyring::new("cli_import_pqp");
    let meta = pqp::keyring::generate_key(
        "cli-pqp-import@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();

    let pqp_data = pqp::keyring::export_public_key_pqp(&meta.key_id, None).unwrap();
    let key_file = k.path().join("key.pqp.pub");
    std::fs::write(&key_file, &pqp_data).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqp"))
        .args([
            "import",
            "--dont-ask-confirmation",
            &key_file.to_string_lossy(),
        ])
        .env("KEYRING_PATH", k.path().to_string_lossy().to_string())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "import PQP format failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("PQP format"));
}

#[test]
fn test_pqp_format_roundtrip() {
    let _k = TestKeyring::new("pqp_roundtrip");
    let meta = pqp::keyring::generate_key(
        "roundtrip@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();

    let pqp_data = pqp::keyring::export_public_key_pqp(&meta.key_id, None).unwrap();

    // Import into the same keyring (override already set)
    let imported_id = pqp::keyring::import_public_key_from_pqp(&pqp_data).unwrap();

    let (kem_pk, _sign_pk, _, _) = pqp::keyring::load_public_key(&imported_id).unwrap();
    let pk = pqp::crypto::kem::PublicKey::from_bytes(&kem_pk, KemVariant::MlKem768).unwrap();
    let (ct, shared1) = pqp::crypto::kem::encapsulate(&pk).unwrap();

    // Load original's secret key to decapsulate and verify KEM roundtrip
    let (kem_sk, _, _, _) = pqp::keyring::load_secret_key(&meta.key_id, "pass").unwrap();
    let sk = pqp::crypto::kem::SecretKey::from_bytes(&kem_sk).unwrap();
    let shared2 = pqp::crypto::kem::decapsulate(&sk, &ct, KemVariant::MlKem768).unwrap();
    assert_eq!(
        shared1, shared2,
        "export->import roundtrip should preserve key material"
    );
}

#[test]
fn test_pqp_format_compressed_roundtrip() {
    for (suffix, name, alg) in &[
        ("zstd", "ZSTD", pqp::format::Algorithm::Zstd),
        ("gzip", "GZIP", pqp::format::Algorithm::Gzip),
        ("deflate", "DEFLATE", pqp::format::Algorithm::Deflate),
    ] {
        let _gen_k = TestKeyring::new(&format!("pqp_compress_gen_{}", suffix));
        let meta = pqp::keyring::generate_key(
            &format!("compress-{}@example.com", suffix),
            "pass",
            KemVariant::MlKem768,
            DsaVariant::MlDsa65,
            Encoding::Base64,
            "none",
            "5y",
            Vec::new(),
            pqp::crypto::sym::DEFAULT_ARGON2_MEM,
            pqp::crypto::sym::DEFAULT_ARGON2_TIME,
            pqp::crypto::sym::DEFAULT_ARGON2_PAR,
        )
        .unwrap();

        let pqp_data = pqp::keyring::export_public_key_pqp(&meta.key_id, Some(alg)).unwrap();
        assert!(
            pqp_data.contains(name),
            "compressed PQP data should contain {}",
            name
        );

        let _import_k = TestKeyring::new(&format!("pqp_compress_imp_{}", suffix));
        let imported_id = pqp::keyring::import_public_key_from_pqp(&pqp_data).unwrap();

        let (kem_pk, sign_pk, _, _) = pqp::keyring::load_public_key(&imported_id).unwrap();
        let pk = pqp::crypto::kem::PublicKey::from_bytes(&kem_pk, KemVariant::MlKem768).unwrap();
        let (ct, _) = pqp::crypto::kem::encapsulate(&pk).unwrap();
        assert!(!ct.is_empty());

        let _sign_pk =
            pqp::crypto::sign::PublicKey::from_bytes(&sign_pk, DsaVariant::MlDsa65).unwrap();

        // _gen_k and _import_k are dropped here, cleaning up their directories
    }
}

#[test]
fn test_cli_export_pqp_with_compression() {
    let k = TestKeyring::new("cli_pqp_compr");
    let meta = pqp::keyring::generate_key(
        "cli-pqp-compress@example.com",
        "pass",
        KemVariant::MlKem768,
        DsaVariant::MlDsa65,
        Encoding::Base64,
        "none",
        "5y",
        Vec::new(),
        pqp::crypto::sym::DEFAULT_ARGON2_MEM,
        pqp::crypto::sym::DEFAULT_ARGON2_TIME,
        pqp::crypto::sym::DEFAULT_ARGON2_PAR,
    )
    .unwrap();

    let out_file = k.path().join("compressed.pqp.pub");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqp"))
        .args([
            "export",
            "--format",
            "pqp",
            "--compress",
            "zstd",
            "-o",
            &out_file.to_string_lossy(),
            &meta.key_id,
        ])
        .env("KEYRING_PATH", k.path().to_string_lossy().to_string())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "export --format pqp --compress zstd failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let file_content = std::fs::read_to_string(&out_file).unwrap();
    assert!(file_content.contains("ZSTD"));
    assert!(file_content.contains("ML-KEM-768"));

    // Re-import the compressed key to verify roundtrip
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqp"))
        .args([
            "import",
            "--dont-ask-confirmation",
            &out_file.to_string_lossy(),
        ])
        .env("KEYRING_PATH", k.path().to_string_lossy().to_string())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "import compressed PQP failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
