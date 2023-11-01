use anyhow::Context;
use openssl::symm::{self, Cipher};

use super::types::{EncryptoAdaptor, KeyAlgorithmFactory};
use crate::common::{
    errors::{Result, ServiceError},
    utils::{self},
};

#[derive(Default)]
pub struct AesCbcAlgorithm {}

#[derive(Default)]
pub struct AesGcmAlgorithm {}

pub fn aes_iv_generate(size: usize) -> Result<Vec<u8>> {
    utils::generate_key(size)
}

impl AesGcmAlgorithm {
    fn select_aes_cipher(&self, size: usize) -> Result<Cipher> {
        Ok(match size * 8 {
            128 => symm::Cipher::aes_128_gcm(),
            256 => symm::Cipher::aes_256_gcm(),
            _ => {
                return Err(ServiceError::BadRequest(format!(
                    "unsupported aes key length: {}",
                    size
                )))
            }
        })
    }
}

impl AesCbcAlgorithm {
    fn select_aes_cipher(&self, size: usize) -> Result<Cipher> {
        Ok(match size * 8 {
            128 => symm::Cipher::aes_128_cbc(),
            256 => symm::Cipher::aes_256_cbc(),
            _ => {
                return Err(ServiceError::BadRequest(format!(
                    "unsupported aes key length: {}",
                    size
                )))
            }
        })
    }
}

impl KeyAlgorithmFactory for AesGcmAlgorithm {
    type GenrateBasic = usize;

    fn encrypt<T: EncryptoAdaptor>(
        &self,
        key: &[u8],
        plaintext: &[u8],
        e: T,
    ) -> Result<Vec<u8>> {
        let ccipher = self.select_aes_cipher(key.len())?;
        let kits = e.kits().unwrap();
        Ok(symm::encrypt_aead(
            ccipher,
            key,
            Some(&kits[0]),
            &kits[1],
            plaintext,
            Some(&kits[2]),
        )
        .context(format!(
            "aead_aes_{} aead encrypt failed",
            ccipher.key_len() * 8
        ))?)
    }

    fn decrypt<T: EncryptoAdaptor>(
        &self,
        key: &[u8],
        cipher: &[u8],
        e: T,
    ) -> Result<Vec<u8>> {
        let ccipher = self.select_aes_cipher(key.len())?;
        let kits = e.kits().unwrap();

        Ok(symm::decrypt_aead(
            ccipher,
            key,
            Some(&kits[0]),
            &kits[1],
            cipher,
            Some(&kits[2]),
        )
        .context(format!(
            "aead_aes_{} aead decrypt failed",
            ccipher.key_len() * 8
        ))?)
    }

    fn generate(
        &self,
        basic: Self::GenrateBasic,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        utils::generate_key(basic)
    }

    fn derive(&self, private_key: &[u8]) -> Result<Vec<u8>> {
        Ok(private_key.to_vec())
    }

    fn sign<T: EncryptoAdaptor>(
        &self,
        pri_key: &[u8],
        plaintext: &[u8],
        e: T,
    ) -> Result<Vec<u8>> {
        Err(ServiceError::Unsupported(
            "aes gcm is unsupported sign action".to_owned(),
        ))
    }

    fn verify<T: EncryptoAdaptor>(
        &self,
        pub_key: &[u8],
        plaintext: &[u8],
        signature: &[u8],
        e: T,
    ) -> Result<bool> {
        Err(ServiceError::Unsupported(
            "aes gcm is unsupported verify action".to_owned(),
        ))
    }
}

impl KeyAlgorithmFactory for AesCbcAlgorithm {
    type GenrateBasic = usize;

    fn generate(&self, basic: Self::GenrateBasic) -> Result<Vec<u8>> {
        utils::generate_key(basic)
    }

    fn derive(&self, private_key: &[u8]) -> Result<Vec<u8>> {
        Ok(private_key.to_vec())
    }

    fn sign<T: EncryptoAdaptor>(
        &self,
        pri_key: &[u8],
        plaintext: &[u8],
        e: T,
    ) -> Result<Vec<u8>> {
        Err(ServiceError::Unsupported(
            "aes cbc is unsupported sign action".to_owned(),
        ))
    }

    fn verify<T: EncryptoAdaptor>(
        &self,
        pub_key: &[u8],
        plaintext: &[u8],
        signature: &[u8],
        e: T,
    ) -> Result<bool> {
        Err(ServiceError::Unsupported(
            "aes cbc is unsupported verify action".to_owned(),
        ))
    }

    fn encrypt<T: EncryptoAdaptor>(
        &self,
        key: &[u8],
        plaintext: &[u8],
        e: T,
    ) -> Result<Vec<u8>> {
        let ccipher = self.select_aes_cipher(key.len())?;
        Ok(
            symm::encrypt(ccipher, key, Some(&e.kits().unwrap()[0]), plaintext)
                .context(format!(
                    "aes_{} encrypt failed",
                    ccipher.key_len() * 8
                ))?,
        )
    }

    fn decrypt<T: EncryptoAdaptor>(
        &self,
        key: &[u8],
        cipher: &[u8],
        e: T,
    ) -> Result<Vec<u8>> {
        let ccipher = self.select_aes_cipher(key.len())?;
        Ok(
            symm::decrypt(ccipher, key, Some(&e.kits().unwrap()[0]), cipher)
                .context(format!(
                    "aes_{} encrypt failed",
                    ccipher.key_len() * 8
                ))?,
        )
    }
}
