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
