use anyhow::Context;
use openssl::symm::{self, Cipher};

use super::algorithm::{EncryptoAdaptor, KeyAlgorithmFactory};
use crate::common::{
    errors::{Result, ServiceError},
    utils::{self},
};

pub struct AesCbcAlgorithmFactory {}

pub struct AesGcmAlgorithmFactory {}

pub fn aes_iv_generate(size: usize) -> Result<Vec<u8>> {
    utils::generate_key(size)
}

impl AesGcmAlgorithmFactory {
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

impl AesCbcAlgorithmFactory {
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

impl KeyAlgorithmFactory for AesGcmAlgorithmFactory {
    fn encrypt(
        &self,
        key: &[u8],
        plaintext: &[u8],
        e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        let ccipher = self.select_aes_cipher(key.len())?;
        let kits = e.kits.unwrap();
        Ok(symm::encrypt_aead(
            ccipher,
            key,
            Some(&kits[0]),
            &kits[1],
            plaintext,
            &mut kits[2].clone(),
        )
        .context(format!(
            "aead_aes_{} aead encrypt failed",
            ccipher.key_len() * 8
        ))?)
    }

    fn decrypt(
        &self,
        key: &[u8],
        cipher: &[u8],
        e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        let ccipher = self.select_aes_cipher(key.len())?;
        let kits = e.kits.unwrap();

        Ok(symm::decrypt_aead(
            ccipher,
            key,
            Some(&kits[0]),
            &kits[1],
            cipher,
            &kits[2].clone(),
        )
        .context(format!(
            "aead_aes_{} aead decrypt failed",
            ccipher.key_len() * 8
        ))?)
    }

    fn sign(
        &self,
        _pri_key: &[u8],
        _plaintext: &[u8],
        _e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        Err(ServiceError::Unsupported(
            "aes gcm is unsupported sign action".to_owned(),
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
            "aes gcm is unsupported verify action".to_owned(),
        ))
    }
}

impl KeyAlgorithmFactory for AesCbcAlgorithmFactory {
    fn sign(
        &self,
        _pri_key: &[u8],
        _plaintext: &[u8],
        _e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        Err(ServiceError::Unsupported(
            "aes cbc is unsupported sign action".to_owned(),
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
            "aes cbc is unsupported verify action".to_owned(),
        ))
    }

    fn encrypt(
        &self,
        key: &[u8],
        plaintext: &[u8],
        e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        let ccipher = self.select_aes_cipher(key.len())?;
        Ok(
            symm::encrypt(ccipher, key, Some(&e.kits.unwrap()[0]), plaintext)
                .context(format!(
                    "aes_{} encrypt failed",
                    ccipher.key_len() * 8
                ))?,
        )
    }

    fn decrypt(
        &self,
        key: &[u8],
        cipher: &[u8],
        e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        let ccipher = self.select_aes_cipher(key.len())?;
        Ok(
            symm::decrypt(ccipher, key, Some(&e.kits.unwrap()[0]), cipher)
                .context(format!(
                    "aes_{} encrypt failed",
                    ccipher.key_len() * 8
                ))?,
        )
    }
}
