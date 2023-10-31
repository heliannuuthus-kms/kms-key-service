use lazy_static::lazy_static;
use openssl::nid::Nid;
use ring::aead::{AES_128_GCM, AES_256_GCM};

use super::{
    ec::ECAlgorithm,
    rsa::RsaAlgorithm,
    symm::SymmAlgorithm,
    types::{KeySpec, KeyType, KeyUsage, WrappingKeySpec},
};
use crate::common::errors::{Result, ServiceError};

lazy_static! {
    static ref RSA_ALGORITHM: RsaAlgorithm = RsaAlgorithm::default();
    static ref EC_ALGORITHM: ECAlgorithm = ECAlgorithm::default();
    static ref SYMM_ALGORITHM: SymmAlgorithm = SymmAlgorithm::default();
}

pub struct KeyAlgorithmMeta {
    pub key_type: KeyType,
    pub key_size: usize,
    pub key_spec: KeySpec,
    pub key_usage: Vec<KeyUsage>,
}

pub enum KeyAlgorithmFactory {
    SYMM { factory: &'static SymmAlgorithm },
    RSA { factory: &'static RsaAlgorithm },
    EC { factory: &'static ECAlgorithm },
}

pub struct KeyAlgorithm {
    pub meta: KeyAlgorithmMeta,
    pub factory: KeyAlgorithmFactory,
}

impl KeyAlgorithmFactory {
    pub fn generate(
        &self,
        meta: &KeyAlgorithmMeta,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        Ok(match self {
            KeyAlgorithmFactory::SYMM { factory } => {
                let key = factory.aes_generate(meta.key_size)?;
                (key, vec![])
            }
            KeyAlgorithmFactory::RSA { factory } => {
                factory.generate(meta.key_size)?
            }
            KeyAlgorithmFactory::EC { factory } => match meta.key_spec {
                KeySpec::EcP256 => factory.genrate(Nid::X9_62_PRIME256V1)?,
                KeySpec::EcP256K => factory.genrate(Nid::SECP256K1)?,
                _ => {
                    return Err(ServiceError::Unsupported(format!(
                        "Unsupport ec key_spec: {:?}",
                        meta.key_spec,
                    )))
                }
            },
        })
    }
}

lazy_static! {
    pub static ref AES_128: KeyAlgorithm = KeyAlgorithm {
        meta: KeyAlgorithmMeta {
            key_type: KeyType::Symmetric,
            key_size: AES_128_GCM.key_len(),
            key_spec: KeySpec::Aes128,
            key_usage: vec![KeyUsage::EncryptAndDecrypt],
        },
        factory: KeyAlgorithmFactory::SYMM {
            factory: &SYMM_ALGORITHM
        }
    };
    pub static ref AES_256: KeyAlgorithm = KeyAlgorithm {
        meta: KeyAlgorithmMeta {
            key_type: KeyType::Symmetric,
            key_size: AES_256_GCM.key_len(),
            key_spec: KeySpec::Aes256,
            key_usage: vec![KeyUsage::EncryptAndDecrypt],
        },
        factory: KeyAlgorithmFactory::SYMM {
            factory: &SYMM_ALGORITHM
        }
    };
    pub static ref RSA_2048: KeyAlgorithm = KeyAlgorithm {
        meta: KeyAlgorithmMeta {
            key_type: KeyType::Asymmetric,
            key_size: 2048,
            key_spec: KeySpec::Rsa2048,
            key_usage: vec![
                KeyUsage::EncryptAndDecrypt,
                KeyUsage::SignAndVerify
            ],
        },
        factory: KeyAlgorithmFactory::RSA {
            factory: &RSA_ALGORITHM
        }
    };
    pub static ref RSA_3072: KeyAlgorithm = KeyAlgorithm {
        meta: KeyAlgorithmMeta {
            key_type: KeyType::Asymmetric,
            key_size: 3072,
            key_spec: KeySpec::Rsa3072,
            key_usage: vec![
                KeyUsage::EncryptAndDecrypt,
                KeyUsage::SignAndVerify
            ],
        },
        factory: KeyAlgorithmFactory::RSA {
            factory: &RSA_ALGORITHM
        }
    };
    pub static ref EC_P256: KeyAlgorithm = KeyAlgorithm {
        meta: KeyAlgorithmMeta {
            key_type: KeyType::Asymmetric,
            key_size: 256,
            key_spec: KeySpec::EcP256,
            key_usage: vec![KeyUsage::SignAndVerify],
        },
        factory: KeyAlgorithmFactory::EC {
            factory: &EC_ALGORITHM
        }
    };
    pub static ref EC_P256K: KeyAlgorithm = KeyAlgorithm {
        meta: KeyAlgorithmMeta {
            key_type: KeyType::Asymmetric,
            key_size: 256,
            key_spec: KeySpec::EcP256K,
            key_usage: vec![KeyUsage::SignAndVerify],
        },
        factory: KeyAlgorithmFactory::EC {
            factory: &EC_ALGORITHM
        }
    };
    pub static ref EC_SM2: KeyAlgorithm = KeyAlgorithm {
        meta: KeyAlgorithmMeta {
            key_type: KeyType::Asymmetric,
            key_size: 256,
            key_spec: KeySpec::EcP256K,
            key_usage: vec![
                KeyUsage::SignAndVerify,
                KeyUsage::EncryptAndDecrypt
            ],
        },
        factory: KeyAlgorithmFactory::EC {
            factory: &EC_ALGORITHM
        }
    };
}

pub fn select_key_alg<'a>(spec: KeySpec) -> &'a KeyAlgorithm {
    let key_alg: &KeyAlgorithm = match spec {
        KeySpec::Aes128 => &AES_128,
        KeySpec::Aes256 => &AES_256,
        KeySpec::Rsa2048 => &RSA_2048,
        KeySpec::Rsa3072 => &RSA_3072,
        KeySpec::EcP256 => &EC_P256,
        KeySpec::EcP256K => &EC_P256K,
    };
    key_alg
}

pub fn select_wrapping_key_alg<'a>(spec: WrappingKeySpec) -> &'a KeyAlgorithm {
    let key_alg: &KeyAlgorithm = match spec {
        WrappingKeySpec::Rsa2048 => &RSA_2048,
        WrappingKeySpec::EcSm2 => &EC_SM2,
    };
    key_alg
}
