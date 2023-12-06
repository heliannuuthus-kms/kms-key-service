use anyhow::Context;
use openssl::symm::{self};

use super::{
    algorithm::{select_cipher, CryptoAdaptor, KeyAlgorithmFactory},
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

pub fn generate_iv(size: usize) -> Result<Vec<u8>> {
    utils::generate_key(size)
}

impl KeyAlgorithmFactory for AEADAlgorithmFactory {
    fn encrypt(
        &self,
        key: &[u8],
        plaintext: &[u8],
        e: CryptoAdaptor,
    ) -> Result<Vec<u8>> {
        let ccipher = select_cipher(key.len(), self.alg)?;
        let mut kits = e.kits.unwrap();
        Ok(symm::encrypt_aead(
            ccipher,
            key,
            Some(&kits.iv),
            &kits.aad,
            plaintext,
            &mut kits.tag,
        )
        .context(format!("{:?} aead encrypt failed", self.alg))?)
    }

    fn decrypt(
        &self,
        key: &[u8],
        cipher: &[u8],
        e: CryptoAdaptor,
    ) -> Result<Vec<u8>> {
        let ccipher = select_cipher(key.len(), self.alg)?;
        let kits = e.kits.unwrap();

        Ok(symm::decrypt_aead(
            ccipher,
            key,
            Some(&kits.iv),
            &kits.aad,
            cipher,
            &kits.tag,
        )
        .context(format!("{:?} aead decrypt failed", self.alg))?)
    }

    fn sign(
        &self,
        _pri_key: &[u8],
        _plaintext: &[u8],
        _e: CryptoAdaptor,
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
        _e: CryptoAdaptor,
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
        _e: CryptoAdaptor,
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
        _e: CryptoAdaptor,
    ) -> Result<bool> {
        Err(ServiceError::Unsupported(
            "cipher is unsupported verify action".to_owned(),
        ))
    }

    fn encrypt(
        &self,
        key: &[u8],
        plaintext: &[u8],
        e: CryptoAdaptor,
    ) -> Result<Vec<u8>> {
        let ccipher = select_cipher(key.len(), self.alg)?;
        Ok(
            symm::encrypt(ccipher, key, Some(&e.kits.unwrap().iv), plaintext)
                .context(format!("{:?} encrypt failed", self.alg))?,
        )
    }

    fn decrypt(
        &self,
        key: &[u8],
        cipher: &[u8],
        e: CryptoAdaptor,
    ) -> Result<Vec<u8>> {
        let ccipher = select_cipher(key.len(), self.alg)?;
        Ok(
            symm::decrypt(ccipher, key, Some(&e.kits.unwrap().iv), cipher)
                .context(format!("{:?} encrypt failed", self.alg))?,
        )
    }
}

#[cfg(test)]
mod tests {

    use super::{generate_iv, CipherAlgorithmFactory};
    use crate::{
        common::utils,
        crypto::{
            algorithm::{
                generate_key, CryptoAdaptor, EncryptKits, KeyAlgorithmFactory,
            },
            symm::AEADAlgorithmFactory,
            types::{KeyAlgorithm, KeySpec},
        },
    };

    #[test]
    fn test_aes_cipher() {
        for spec in [KeySpec::Aes128, KeySpec::Aes256, KeySpec::SM4] {
            let (_nid, size) = spec.into();
            let factory = if KeySpec::SM4.eq(&spec) {
                CipherAlgorithmFactory::new(KeyAlgorithm::Sm4CBC)
            } else {
                CipherAlgorithmFactory::new(KeyAlgorithm::AesCBC)
            };
            let (key, _nil) = generate_key(spec).unwrap();
            let iv = generate_iv(size).unwrap();

            let crypto = CryptoAdaptor {
                kits: Some(EncryptKits {
                    iv,
                    ..Default::default()
                }),
                ..Default::default()
            };
            let cipher =
                factory.encrypt(&key, b"plaintext", crypto.clone()).unwrap();
            println!("cipher: {}", utils::encode64(&cipher));
            assert_eq!(
                factory.decrypt(&key, &cipher, crypto).unwrap(),
                b"plaintext",
            );
        }
    }

    #[test]
    fn test_aead() {
        for spec in [KeySpec::Aes128, KeySpec::Aes256] {
            let (_nid, size) = spec.into();
            let factory = AEADAlgorithmFactory::new(KeyAlgorithm::AesGCM);
            let (key, _nil) = generate_key(spec).unwrap();
            let iv = generate_iv(size).unwrap();

            let crypto = CryptoAdaptor {
                kits: Some(EncryptKits {
                    iv,
                    ..Default::default()
                }),
                ..Default::default()
            };
            let cipher =
                factory.encrypt(&key, b"plaintext", crypto.clone()).unwrap();
            assert_eq!(
                factory.decrypt(&key, &cipher, crypto).unwrap(),
                b"plaintext",
            );
        }
    }
}
