use lazy_static::lazy_static;
use openssl::{cipher::Cipher, nid::Nid};
use ring::aead::{self};

use super::{
    aes::{AesCbcAlgorithm, AesGcmAlgorithm},
    ec::EcAlgorithm,
    rsa::RsaAlgorithm,
    types::{KeyAlgorithmFactory, KeySpec, KeyType, KeyUsage, WrappingKeySpec},
};

lazy_static! {
    static ref RSA_ALGORITHM: RsaAlgorithm = RsaAlgorithm::default();
    static ref EC_ALGORITHM: EcAlgorithm = EcAlgorithm::default();
    static ref AES_CBC_ALGORITHM: AesCbcAlgorithm = AesCbcAlgorithm::default();
    static ref AES_GCM_ALGORITHM: AesGcmAlgorithm = AesGcmAlgorithm::default();
}

pub struct KeyAlgorithmMeta {
    pub key_type: KeyType,
    pub key_size: usize,
    pub key_spec: KeySpec,
    pub key_usage: Vec<KeyUsage>,
}

pub enum KeyAlgorithmFactoryAdaptor {
    SYMM { factory: &'static AesCbcAlgorithm },
    RSA { factory: &'static RsaAlgorithm },
    EC { factory: &'static EcAlgorithm },
}

pub struct KeyAlgorithm<T: KeyAlgorithmFactory + 'static> {
    pub meta: KeyAlgorithmMeta,
    pub factory: &'static T,
}

lazy_static! {
    pub static ref AES_128_CBC: KeyAlgorithm<AesCbcAlgorithm> = KeyAlgorithm {
        meta: KeyAlgorithmMeta {
            key_type: KeyType::Symmetric,
            key_size: Cipher::aes_128_cbc().key_length(),
            key_spec: KeySpec::Aes128,
            key_usage: vec![KeyUsage::EncryptAndDecrypt],
        },
        factory: &AES_CBC_ALGORITHM
    };
    pub static ref AES_256_CBC: KeyAlgorithm<AesCbcAlgorithm> = KeyAlgorithm {
        meta: KeyAlgorithmMeta {
            key_type: KeyType::Symmetric,
            key_size: Cipher::aes_256_cbc().key_length(),
            key_spec: KeySpec::Aes256,
            key_usage: vec![KeyUsage::EncryptAndDecrypt],
        },
        factory: &AES_CBC_ALGORITHM
    };
    pub static ref AES_128_GCM: KeyAlgorithm<AesGcmAlgorithm> = KeyAlgorithm {
        meta: KeyAlgorithmMeta {
            key_type: KeyType::Symmetric,
            key_size: Cipher::aes_128_gcm().key_length(),

            key_spec: KeySpec::Aes128,
            key_usage: vec![KeyUsage::EncryptAndDecrypt],
        },
        factory: &AES_GCM_ALGORITHM
    };
    pub static ref AES_256_GCM: KeyAlgorithm<AesGcmAlgorithm> = KeyAlgorithm {
        meta: KeyAlgorithmMeta {
            key_type: KeyType::Symmetric,
            key_size: Cipher::aes_256_gcm().key_length(),
            key_spec: KeySpec::Aes256,
            key_usage: vec![KeyUsage::EncryptAndDecrypt],
        },
        factory: &AES_GCM_ALGORITHM
    };
    pub static ref RSA_2048: KeyAlgorithm<RsaAlgorithm> = KeyAlgorithm {
        meta: KeyAlgorithmMeta {
            key_type: KeyType::Asymmetric,
            key_size: 2048,
            key_spec: KeySpec::Rsa2048,
            key_usage: vec![
                KeyUsage::EncryptAndDecrypt,
                KeyUsage::SignAndVerify
            ],
        },
        factory: &RSA_ALGORITHM
    };
    pub static ref RSA_3072: KeyAlgorithm<RsaAlgorithm> = KeyAlgorithm {
        meta: KeyAlgorithmMeta {
            key_type: KeyType::Asymmetric,
            key_size: 3072,
            key_spec: KeySpec::Rsa3072,
            key_usage: vec![
                KeyUsage::EncryptAndDecrypt,
                KeyUsage::SignAndVerify
            ],
        },
        factory: &RSA_ALGORITHM
    };
    pub static ref EC_P256: KeyAlgorithm<EcAlgorithm> = KeyAlgorithm {
        meta: KeyAlgorithmMeta {
            key_type: KeyType::Asymmetric,
            key_size: 256,
            key_spec: KeySpec::EcP256,
            key_usage: vec![KeyUsage::SignAndVerify],
        },
        factory: &EC_ALGORITHM
    };
    pub static ref EC_P256K: KeyAlgorithm<EcAlgorithm> = KeyAlgorithm {
        meta: KeyAlgorithmMeta {
            key_type: KeyType::Asymmetric,
            key_size: 256,
            key_spec: KeySpec::EcP256K,
            key_usage: vec![KeyUsage::SignAndVerify],
        },
        factory: &EC_ALGORITHM
    };
    pub static ref EC_SM2: KeyAlgorithm<EcAlgorithm> = KeyAlgorithm {
        meta: KeyAlgorithmMeta {
            key_type: KeyType::Asymmetric,
            key_size: 256,
            key_spec: KeySpec::EcP256K,
            key_usage: vec![
                KeyUsage::SignAndVerify,
                KeyUsage::EncryptAndDecrypt
            ],
        },
        factory: &EC_ALGORITHM
    };
}

pub fn select_key_alg<'a, T: KeyAlgorithmFactory>(
    spec: KeySpec,
) -> &'a KeyAlgorithm<T> {
    let key_alg: &KeyAlgorithm<T> = match spec {
        KeySpec::Aes128 => &AES_128_GCM,
        KeySpec::Aes256 => &AES_256_GCM,
        KeySpec::Rsa2048 => &RSA_2048,
        KeySpec::Rsa3072 => &RSA_3072,
        KeySpec::EcP256 => &EC_P256,
        KeySpec::EcP256K => &EC_P256K,
    };
    key_alg
}

pub fn select_wrapping_key_alg<'a, T: KeyAlgorithmFactory>(
    spec: WrappingKeySpec,
) -> &'a KeyAlgorithm<T> {
    let key_alg: &KeyAlgorithm = match spec {
        WrappingKeySpec::Rsa2048 => &RSA_2048,
        WrappingKeySpec::EcSm2 => &EC_SM2,
    };
    key_alg
}
