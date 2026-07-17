use std::io::Write;
use std::path::PathBuf;

fn test_keyring_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pqp_kr_{}", name));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::env::set_var("HOME", &dir);
    dir
}

fn find_key_id() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    let keys_dir = PathBuf::from(&home).join(".pqp").join("keys");
    if !keys_dir.exists() {
        return None;
    }
    for entry in std::fs::read_dir(&keys_dir).ok()? {
        let entry = entry.ok()?;
        let conf = entry.path().join("pqp.conf");
        if conf.exists() {
            return entry.file_name().into_string().ok();
        }
    }
    None
}

#[test]
fn test_list_keys_empty() {
    let _d = test_keyring_dir("list_empty");
    let keys = pqp::keyring::list_keys().unwrap();
    assert!(keys.is_empty());
}

#[test]
fn test_generate_and_export() {
    let _d = test_keyring_dir("gen_export");
    let meta = pqp::keyring::generate_key("test@example.com", "testpass").unwrap();
    assert_eq!(meta.user_id, "test@example.com");
    assert!(!meta.key_id.is_empty());

    let key_id = find_key_id().expect("key should exist on disk");
    assert_eq!(meta.key_id, key_id);

    let keys = pqp::keyring::list_keys().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].key_id, meta.key_id);

    let armored = pqp::keyring::export_public_key(&meta.key_id).unwrap();
    assert!(armored.contains("-----BEGIN PQP PUBLIC KEY"));
    assert!(armored.contains(&meta.key_id));
}

#[test]
fn test_generate_and_load_keys() {
    let _d = test_keyring_dir("gen_load");
    let meta = pqp::keyring::generate_key("load-test@example.com", "mypass").unwrap();

    let (kem_pk, sign_pk) = pqp::keyring::load_public_key(&meta.key_id).unwrap();
    assert!(!kem_pk.is_empty());
    assert!(!sign_pk.is_empty());

    let (kem_sk, sign_sk) = pqp::keyring::load_secret_key(&meta.key_id, "mypass").unwrap();
    assert!(!kem_sk.is_empty());
    assert!(!sign_sk.is_empty());

    let pk = pqp::crypto::kem::PublicKey::from_bytes(&kem_pk).unwrap();
    let sk = pqp::crypto::kem::SecretKey::from_bytes(&kem_sk).unwrap();
    let (ct, shared1) = pqp::crypto::kem::encapsulate(&pk).unwrap();
    let shared2 = pqp::crypto::kem::decapsulate(&sk, &ct).unwrap();
    assert_eq!(shared1, shared2);

    let sign_pk = pqp::crypto::sign::PublicKey::from_bytes(&sign_pk).unwrap();
    let sign_sk = pqp::crypto::sign::SecretKey::from_bytes(&sign_sk).unwrap();
    let msg = b"stored key test";
    let sig = pqp::crypto::sign::sign(&sign_sk, msg).unwrap();
    assert!(pqp::crypto::sign::verify(&sign_pk, msg, &sig).unwrap());
}

#[test]
fn test_key_info_fields() {
    let _d = test_keyring_dir("key_info");
    let meta = pqp::keyring::generate_key("info@example.com", "pass").unwrap();

    let keys = pqp::keyring::list_keys().unwrap();
    assert_eq!(keys.len(), 1);
    let info = &keys[0];

    assert!(info.has_public);
    assert!(info.has_secret);
    assert_eq!(info.kem_algorithm, "ML-KEM-768");
    assert_eq!(info.sign_algorithm, "ML-DSA-65");
    assert_eq!(info.key_id, meta.key_id);
    assert_eq!(info.user_id, "info@example.com");
}

#[test]
fn test_resolve_key_id_by_key_id() {
    let _d = test_keyring_dir("resolve_id");
    let meta = pqp::keyring::generate_key("resolve@example.com", "pass").unwrap();

    let resolved = pqp::keyring::resolve_key_id(&meta.key_id).unwrap();
    assert_eq!(resolved, meta.key_id);
}

#[test]
fn test_resolve_key_id_by_user_id() {
    let _d = test_keyring_dir("resolve_user");
    pqp::keyring::generate_key("alice@example.com", "pass").unwrap();

    let resolved = pqp::keyring::resolve_key_id("alice@example.com").unwrap();
    let keys = pqp::keyring::list_keys().unwrap();
    assert_eq!(resolved, keys[0].key_id);
}

#[test]
fn test_resolve_key_id_not_found() {
    let _d = test_keyring_dir("resolve_nf");
    let result = pqp::keyring::resolve_key_id("nonexistent");
    assert!(result.is_err());
}

#[test]
fn test_key_info_public_only_key() {
    let _d = test_keyring_dir("pub_only");
    let meta = pqp::keyring::generate_key("pubonly@example.com", "pass").unwrap();

    std::fs::remove_file(
        std::env::var("HOME").unwrap() + "/.pqp/keys/" + &meta.key_id + "/pqp-secret.der",
    )
    .unwrap();

    let keys = pqp::keyring::list_keys().unwrap();
    assert!(keys[0].has_public);
    assert!(!keys[0].has_secret);
}

#[test]
fn test_import_with_confirmation() {
    let d = test_keyring_dir("import_confirm");
    let meta = pqp::keyring::generate_key("export@example.com", "pass").unwrap();
    let armored = pqp::keyring::export_public_key(&meta.key_id).unwrap();

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_pqp"))
        .args(["import", "--dont-ask-confirmation"])
        .env("HOME", d.to_string_lossy().to_string())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    child
        .stdin
        .take()
        .unwrap()
        .write_all(armored.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains(&meta.key_id));
}

#[test]
fn test_list_keys_json_format() {
    let d = test_keyring_dir("list_json");
    pqp::keyring::generate_key("json@example.com", "pass").unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqp"))
        .args(["list-keys", "--format", "json"])
        .env("HOME", d.to_string_lossy().to_string())
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
    let d = test_keyring_dir("list_nohead");
    pqp::keyring::generate_key("nohead@example.com", "pass").unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqp"))
        .args(["list-keys", "--format", "no-headers"])
        .env("HOME", d.to_string_lossy().to_string())
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
    let d = test_keyring_dir("import_stdin");
    let meta = pqp::keyring::generate_key("stdinimport@example.com", "pass").unwrap();
    let armored = pqp::keyring::export_public_key(&meta.key_id).unwrap();

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_pqp"))
        .args(["import", "--dont-ask-confirmation", "-"])
        .env("HOME", d.to_string_lossy().to_string())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    child
        .stdin
        .take()
        .unwrap()
        .write_all(armored.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "import from stdin failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains(&meta.key_id));
}
