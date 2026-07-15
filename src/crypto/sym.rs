use super::CryptoError;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
#[allow(dead_code)]
pub const TAG_LEN: usize = 16;

pub fn encrypt(
    key: &[u8; KEY_LEN],
    plaintext: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::Encrypt(format!("invalid key: {}", e)))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::try_from(&nonce_bytes[..])
        .map_err(|_| CryptoError::Encrypt("invalid nonce length".into()))?;

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::Encrypt(format!("encryption failed: {}", e)))?;

    Ok((nonce_bytes, ciphertext))
}

pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::Decrypt(format!("invalid key: {}", e)))?;

    let nonce = XNonce::try_from(&nonce[..])
        .map_err(|_| CryptoError::Decrypt("invalid nonce length".into()))?;

    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| CryptoError::Decrypt(format!("decryption failed: {}", e)))?;

    Ok(plaintext)
}

pub fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], CryptoError> {
    use argon2::Argon2;

    let argon2 = Argon2::default();
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| CryptoError::Encrypt(format!("key derivation failed: {}", e)))?;
    Ok(key)
}
