use anyhow::Context;
use openssl::symm::{self, Cipher};

use super::{
    algorithm::{EncryptoAdaptor, KeyAlgorithmFactory},
    types::KeyAlgorithm,
};
use crate::common::{
    errors::{Result, ServiceError},
    utils::{self},
};

pub struct AesCBCAlgorithmFactory {}

pub struct AesGCMAlgorithmFactory {}

pub fn aes_iv_generate(size: usize) -> Result<Vec<u8>> {
    utils::generate_key(size)
}

fn select_cipher(size: usize, key_alg: KeyAlgorithm) -> Result<Cipher> {
    let cipher = match key_alg {
        KeyAlgorithm::AesCBC => match size * 8 {
            128 => symm::Cipher::aes_128_cbc(),
            256 => symm::Cipher::aes_256_cbc(),
        },
        KeyAlgorithm::AesGCM => match size * 8 {
            128 => symm::Cipher::aes_128_gcm(),
            256 => symm::Cipher::aes_256_gcm(),
        },
        KeyAlgorithm::Sm4CTR => symm::Cipher::sm4_ctr(),
        KeyAlgorithm::Sm4CBC => symm::Cipher::sm4_cbc(),
        _ => {
            return Err(ServiceError::Unsupported(format!(
                "unsupported aes key length: {}",
                size
            )))
        }
    };

    Ok(cipher)
}
impl KeyAlgorithmFactory for AesGCMAlgorithmFactory {
    fn encrypt(
        &self,
        key: &[u8],
        plaintext: &[u8],
        e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        let ccipher = select_cipher(key.len(), KeyAlgorithm::AesGCM)?;
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
        let ccipher = select_cipher(key.len(), KeyAlgorithm::AesGCM)?;
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

impl KeyAlgorithmFactory for AesCBCAlgorithmFactory {
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
        let ccipher = select_cipher(key.len(), KeyAlgorithm::AesCBC)?;
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
        let ccipher = select_cipher(key.len(), KeyAlgorithm::AesCBC)?;
        Ok(
            symm::decrypt(ccipher, key, Some(&e.kits.unwrap()[0]), cipher)
                .context(format!(
                    "aes_{} encrypt failed",
                    ccipher.key_len() * 8
                ))?,
        )
    }
}
pub struct SM4CTRAlgorithmFactory {}
impl KeyAlgorithmFactory for SM4CTRAlgorithmFactory {
    fn sign(
        &self,
        pri_key: &[u8],
        plaintext: &[u8],
        e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        Err(ServiceError::Unsupported(
            "aes cbc is unsupported verify action".to_owned(),
        ))
    }

    fn verify(
        &self,
        pub_key: &[u8],
        plaintext: &[u8],
        signature: &[u8],
        e: EncryptoAdaptor,
    ) -> Result<bool> {
        Err(ServiceError::Unsupported(
            "aes cbc is unsupported verify action".to_owned(),
        ))
    }

    fn encrypt(
        &self,
        pub_key: &[u8],
        plaintext: &[u8],
        e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        todo!()
    }

    fn decrypt(
        &self,
        private_key: &[u8],
        cipher: &[u8],
        e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        todo!()
    }
}

pub struct SM4CBCAlgorithmFactory {}
impl KeyAlgorithmFactory for SM4CBCAlgorithmFactory {
    fn sign(
        &self,
        pri_key: &[u8],
        plaintext: &[u8],
        e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        Err(ServiceError::Unsupported(
            "aes cbc is unsupported verify action".to_owned(),
        ))
    }

    fn verify(
        &self,
        pub_key: &[u8],
        plaintext: &[u8],
        signature: &[u8],
        e: EncryptoAdaptor,
    ) -> Result<bool> {
        Err(ServiceError::Unsupported(
            "aes cbc is unsupported verify action".to_owned(),
        ))
    }

    fn encrypt(
        &self,
        pub_key: &[u8],
        plaintext: &[u8],
        e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        todo!()
    }

    fn decrypt(
        &self,
        private_key: &[u8],
        cipher: &[u8],
        e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        todo!()
    }
}
