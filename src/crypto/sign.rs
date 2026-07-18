//! ML-DSA (CRYSTALS-Dilithium) FIPS 204 digital signatures.
//!
//! Uses ML-DSA-65 (security level 3). Public keys are 1952 bytes,
//! secret keys (seeds) are 32 bytes, and signatures are 3290 bytes.

use super::CryptoError;
use ml_dsa::common::Key;
use ml_dsa::*;
use zeroize::Zeroize;

pub struct PublicKey(Vec<u8>);

#[allow(dead_code)]
impl PublicKey {
    /// Build a [`PublicKey`] from raw bytes, validating length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let vk_arr = <Key<VerifyingKey<MlDsa65>>>::try_from(bytes)
            .map_err(|_| CryptoError::InvalidKey("invalid public key length".into()))?;
        let _vk = VerifyingKey::<MlDsa65>::new(&vk_arr);
        Ok(Self(bytes.to_vec()))
    }

    /// View the raw public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Clone the raw public key bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// An ML-DSA secret key (seed), 32 bytes. Zeroized on drop.
pub struct SecretKey(Vec<u8>);

#[allow(dead_code)]
impl SecretKey {
    /// Build a [`SecretKey`] from raw bytes, validating length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey(
                "ML-DSA secret key must be 32 bytes".into(),
            ));
        }
        Ok(Self(bytes.to_vec()))
    }

    /// View the raw secret key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Clone the raw secret key bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Generate a new ML-DSA-65 keypair.
pub fn keypair() -> Result<(SecretKey, PublicKey), CryptoError> {
    let signing_key = SigningKey::<MlDsa65>::generate();
    let verifying_key = signing_key.verifying_key();

    let seed: Seed = signing_key.to_bytes();
    let vk_key: Key<VerifyingKey<MlDsa65>> = verifying_key.to_bytes();

    Ok((SecretKey(seed.to_vec()), PublicKey(vk_key.to_vec())))
}

/// Sign a message with an ML-DSA secret key.
pub fn sign(sk: &SecretKey, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let seed_arr = <Seed>::try_from(&sk.0[..32])
        .map_err(|_| CryptoError::Sign("invalid signing key seed".into()))?;
    let signing_key = SigningKey::<MlDsa65>::new(&seed_arr);

    let signature: Signature<MlDsa65> = signing_key.sign(message);
    let sig_encoded: EncodedSignature<MlDsa65> = signature.encode();

    Ok(sig_encoded.to_vec())
}

/// Verify a signature against a message using an ML-DSA public key.
pub fn verify(pk: &PublicKey, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
    let vk_arr = <Key<VerifyingKey<MlDsa65>>>::try_from(&pk.0[..])
        .map_err(|_| CryptoError::Verify("invalid verifying key length".into()))?;
    let verifying_key = VerifyingKey::<MlDsa65>::new(&vk_arr);

    let sig_encoded = <EncodedSignature<MlDsa65>>::try_from(signature)
        .map_err(|_| CryptoError::Verify("invalid signature length".into()))?;
    let sig = Signature::<MlDsa65>::decode(&sig_encoded)
        .ok_or_else(|| CryptoError::Verify("invalid signature encoding".into()))?;

    match verifying_key.verify(message, &sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}
