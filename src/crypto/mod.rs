//! Post-quantum cryptographic primitives.
//!
//! This module provides safe wrappers around:
//! - [`kem`] — ML-KEM (Kyber) key encapsulation
//! - [`sign`] — ML-DSA (Dilithium) digital signatures
//! - [`sym`] — XChaCha20-Poly1305 symmetric encryption
//! - [`keygen`] — Combined PQ key pair generation

pub mod kem;
pub mod keygen;
pub mod sign;
pub mod sym;

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("key generation failed: {0}")]
    #[allow(dead_code)]
    KeyGeneration(String),
    #[error("encryption failed: {0}")]
    Encrypt(String),
    #[error("decryption failed: {0}")]
    Decrypt(String),
    #[error("signing failed: {0}")]
    Sign(String),
    #[error("verification failed: {0}")]
    Verify(String),
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
