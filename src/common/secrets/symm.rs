use anyhow::Context;
use openssl::{
    cipher,
    cipher_ctx::CipherCtx,
    symm::{self, Cipher},
};
use ring::rand::{SecureRandom, SystemRandom};

use super::algorithm::{AES_128, AES_256};
use crate::common::{
    errors::{Result, ServiceError},
    utils::{self, generate_b64},
};

pub struct SymmAlgorithm {}

impl SymmAlgorithm {
    fn select_aes_cipher(size: usize) -> Result<Cipher> {
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

    pub fn aes_generate(&self, size: usize) -> Result<Vec<u8>> {
        utils::generate_key(size)
    }

    pub fn aes_iv_generate(&self, size: usize) -> Result<Vec<u8>> {
        utils::generate_key(size)
    }

    pub fn aes_encrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let ccipher = Self::select_aes_cipher(key.len())?;
        Ok(symm::encrypt(ccipher, key, Some(iv), plaintext)
            .context(format!("aes_{} encrypt failed", ccipher.key_len() * 8))?)
    }

    pub fn aes_aead_encrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        tag: &mut [u8],
    ) -> Result<Vec<u8>> {
        let ccipher = Self::select_aes_cipher(key.len())?;
        Ok(
            symm::encrypt_aead(ccipher, key, Some(iv), aad, plaintext, tag)
                .context(format!(
                    "aead_aes_{} aead encrypt failed",
                    ccipher.key_len() * 8
                ))?,
        )
    }

    pub fn aes_decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        cipher: &[u8],
    ) -> Result<Vec<u8>> {
        let ccipher = Self::select_aes_cipher(key.len())?;
        Ok(symm::decrypt(ccipher, key, Some(iv), cipher)
            .context(format!("aes_{} encrypt failed", ccipher.key_len() * 8))?)
    }

    pub fn aes_aead_decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        cipher: &[u8],
        tag: &mut [u8],
    ) -> Result<Vec<u8>> {
        let ccipher = Self::select_aes_cipher(key.len())?;
        Ok(symm::decrypt_aead(ccipher, key, Some(iv), aad, cipher, tag)
            .context(format!(
                "aead_aes_{} aead decrypt failed",
                ccipher.key_len() * 8
            ))?)
    }
}
