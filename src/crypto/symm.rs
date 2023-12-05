use anyhow::Context;
use openssl::symm::{self};

use super::{
    algorithm::{select_cipher, EncryptoAdaptor, KeyAlgorithmFactory},
    types::KeyAlgorithm,
};
use crate::common::{
    errors::{Result, ServiceError},
    utils::{self},
};

pub struct CipherAlgorithmFactory {
    alg: KeyAlgorithm,
}

pub struct AEADAlgorithmFactory {
    alg: KeyAlgorithm,
}

impl CipherAlgorithmFactory {
    pub fn new(alg: KeyAlgorithm) -> Self {
        Self { alg }
    }
}

impl AEADAlgorithmFactory {
    pub fn new(alg: KeyAlgorithm) -> Self {
        Self { alg }
    }
}

pub fn aes_iv_generate(size: usize) -> Result<Vec<u8>> {
    utils::generate_key(size)
}

impl KeyAlgorithmFactory for AEADAlgorithmFactory {
    fn encrypt(
        &self,
        key: &[u8],
        plaintext: &[u8],
        e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        let ccipher = select_cipher(key.len(), self.alg)?;
        let kits = e.kits.unwrap();
        Ok(symm::encrypt_aead(
            ccipher,
            key,
            Some(&kits[0]),
            &kits[1],
            plaintext,
            &mut kits[2].clone(),
        )
        .context(format!("{:?} aead encrypt failed", self.alg))?)
    }

    fn decrypt(
        &self,
        key: &[u8],
        cipher: &[u8],
        e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        let ccipher = select_cipher(key.len(), self.alg)?;
        let kits = e.kits.unwrap();

        Ok(symm::decrypt_aead(
            ccipher,
            key,
            Some(&kits[0]),
            &kits[1],
            cipher,
            &kits[2].clone(),
        )
        .context(format!("{:?} aead decrypt failed", self.alg))?)
    }

    fn sign(
        &self,
        _pri_key: &[u8],
        _plaintext: &[u8],
        _e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        Err(ServiceError::Unsupported(
            "aead is unsupported sign action".to_owned(),
        ))
    }

    fn verify(
        &self,
        _pub_key: &[u8],
        _plaintext: &[u8],
        _signature: &[u8],
        _e: EncryptoAdaptor,
    ) -> Result<bool> {
        Err(ServiceError::Unsupported(
            "aead is unsupported verify action".to_owned(),
        ))
    }
}

impl KeyAlgorithmFactory for CipherAlgorithmFactory {
    fn sign(
        &self,
        _pri_key: &[u8],
        _plaintext: &[u8],
        _e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        Err(ServiceError::Unsupported(
            "cipher is unsupported sign action".to_owned(),
        ))
    }

    fn verify(
        &self,
        _pub_key: &[u8],
        _plaintext: &[u8],
        _signature: &[u8],
        _e: EncryptoAdaptor,
    ) -> Result<bool> {
        Err(ServiceError::Unsupported(
            "cipher is unsupported verify action".to_owned(),
        ))
    }

    fn encrypt(
        &self,
        key: &[u8],
        plaintext: &[u8],
        e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        let ccipher = select_cipher(key.len(), self.alg)?;
        Ok(
            symm::encrypt(ccipher, key, Some(&e.kits.unwrap()[0]), plaintext)
                .context(format!("{:?} encrypt failed", self.alg))?,
        )
    }

    fn decrypt(
        &self,
        key: &[u8],
        cipher: &[u8],
        e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        let ccipher = select_cipher(key.len(), self.alg)?;
        Ok(
            symm::decrypt(ccipher, key, Some(&e.kits.unwrap()[0]), cipher)
                .context(format!("{:?} encrypt failed", self.alg))?,
        )
    }
}
