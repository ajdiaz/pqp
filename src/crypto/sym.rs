//! XChaCha20-Poly1305 symmetric encryption and Argon2id key derivation.
//!
//! Provides authenticated encryption with 24-byte nonces. Key derivation
//! uses Argon2id to turn passphrases into 32-byte symmetric keys.

use super::CryptoError;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;

/// Key length in bytes (32 bytes = 256 bits).
pub const KEY_LEN: usize = 32;
/// Nonce length in bytes (24 bytes for XChaCha20).
pub const NONCE_LEN: usize = 24;
/// Authentication tag length in bytes (16 bytes).
#[allow(dead_code)]
pub const TAG_LEN: usize = 16;

/// Encrypt plaintext with XChaCha20-Poly1305 using the given key.
///
/// Returns (nonce, ciphertext_with_tag). A fresh random nonce is
/// generated for each call.
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

/// Decrypt an XChaCha20-Poly1305 ciphertext using the given key and nonce.
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

/// Derive a 32-byte symmetric key from a passphrase and salt using Argon2id.
pub fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], CryptoError> {
    use argon2::Argon2;

    let argon2 = Argon2::default();
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| CryptoError::Encrypt(format!("key derivation failed: {}", e)))?;
    Ok(key)
}
