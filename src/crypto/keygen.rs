use super::kem;
use super::sign;
use super::CryptoError;

pub struct KeyPair {
    pub kem_public: kem::PublicKey,
    pub kem_secret: kem::SecretKey,
    pub sign_public: sign::PublicKey,
    pub sign_secret: sign::SecretKey,
}

pub fn generate() -> Result<KeyPair, CryptoError> {
    let (kem_secret, kem_public) = kem::keypair()?;
    let (sign_secret, sign_public) = sign::keypair()?;

    Ok(KeyPair {
        kem_public,
        kem_secret,
        sign_public,
        sign_secret,
    })
}
