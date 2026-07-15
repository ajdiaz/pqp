use super::CryptoError;
use ml_kem::*;
use zeroize::Zeroize;

pub const SHARED_SECRET_LEN: usize = 32;

pub struct PublicKey(Vec<u8>);

#[allow(dead_code)]
impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let key_arr = <kem::Key<EncapsulationKey<MlKem768>>>::try_from(bytes)
            .map_err(|_| CryptoError::InvalidKey("invalid public key length".into()))?;
        EncapsulationKey::<MlKem768>::new(&key_arr)
            .map_err(|e| CryptoError::InvalidKey(format!("invalid public key: {}", e)))?;
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

pub struct SecretKey(Vec<u8>);

#[allow(dead_code)]
impl SecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidKey(
                "ML-KEM secret key must be 64 bytes".into(),
            ));
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub fn keypair() -> Result<(SecretKey, PublicKey), CryptoError> {
    let (decap, encap) = MlKem768::generate_keypair();

    let seed: Seed = decap.to_bytes();
    let encap_key: kem::Key<EncapsulationKey<MlKem768>> = encap.to_bytes();

    Ok((SecretKey(seed.to_vec()), PublicKey(encap_key.to_vec())))
}

pub fn encapsulate(pk: &PublicKey) -> Result<(Vec<u8>, [u8; SHARED_SECRET_LEN]), CryptoError> {
    let ek_arr = <kem::Key<EncapsulationKey<MlKem768>>>::try_from(&pk.0[..])
        .map_err(|_| CryptoError::Encrypt("invalid encapsulation key length".into()))?;
    let encap = EncapsulationKey::<MlKem768>::new(&ek_arr)
        .map_err(|e| CryptoError::Encrypt(format!("invalid encapsulation key: {}", e)))?;

    let (ct, shared) = encap.encapsulate();

    Ok((ct.to_vec(), shared.into()))
}

pub fn decapsulate(
    sk: &SecretKey,
    ciphertext: &[u8],
) -> Result<[u8; SHARED_SECRET_LEN], CryptoError> {
    let seed_arr = <Seed>::try_from(&sk.0[..64])
        .map_err(|_| CryptoError::Decrypt("invalid secret key seed".into()))?;
    let decap = DecapsulationKey::<MlKem768>::from_seed(seed_arr);

    let ct_arr = <kem::Ciphertext<MlKem768>>::try_from(ciphertext)
        .map_err(|_| CryptoError::Decrypt("invalid ciphertext length".into()))?;

    let shared = decap.decapsulate(&ct_arr);
    Ok(shared.into())
}
