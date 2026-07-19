//! Combined key pair generation for ML-KEM and ML-DSA.
//!
//! Generates both a Kyber KEM keypair and a Dilithium signing keypair
//! in a single operation, using the requested parameter set variants.
//! The resulting [`KeyPair`] bundles all four key components.

use super::kem;
use super::sign;
use super::CryptoError;
use super::DsaVariant;
use super::KemVariant;

/// A combined PQ key pair containing ML-KEM and ML-DSA keys.
pub struct KeyPair {
    pub kem_public: kem::PublicKey,
    pub kem_secret: kem::SecretKey,
    pub sign_public: sign::PublicKey,
    pub sign_secret: sign::SecretKey,
}

/// Generate a combined PQ key pair using the given algorithm variants.
pub fn generate(kem_variant: KemVariant, dsa_variant: DsaVariant) -> Result<KeyPair, CryptoError> {
    let (kem_secret, kem_public) = kem::keypair(kem_variant)?;
    let (sign_secret, sign_public) = sign::keypair(dsa_variant)?;

    Ok(KeyPair {
        kem_public,
        kem_secret,
        sign_public,
        sign_secret,
    })
}
