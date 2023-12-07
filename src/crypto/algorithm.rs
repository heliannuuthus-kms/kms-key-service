use anyhow::Context;
use openssl::{ec, hash, nid::Nid, pkey, rsa, symm};

use super::{
    ec::EcAlgorithmFactory,
    rsa::RsaAlgorithmFactory,
    symm::{AEADAlgorithmFactory, CipherAlgorithmFactory},
    types::{
        KeyAlgorithm, KeySpec, KeyType, KeyUsage, WrappingKeyAlgorithm,
        WrappingKeySpec,
    },
};
use crate::common::{
    errors::{Result, ServiceError},
    utils,
};

pub const SUPPORTED_EXTERNAL_SPEC: &[KeySpec] =
    &[KeySpec::Aes128, KeySpec::Aes256];

pub trait KeyAlgorithmFactory {
    fn sign(
        &self,
        pri_key: &[u8],
        plaintext: &[u8],
        e: &CryptoAdaptor,
    ) -> Result<Vec<u8>>;
    fn verify(
        &self,
        pub_key: &[u8],
        plaintext: &[u8],
        signature: &[u8],
        e: &CryptoAdaptor,
    ) -> Result<bool>;
    fn encrypt(
        &self,
        pub_key: &[u8],
        plaintext: &[u8],
        e: &mut CryptoAdaptor,
    ) -> Result<Vec<u8>>;
    fn decrypt(
        &self,
        private_key: &[u8],
        cipher: &[u8],
        e: &CryptoAdaptor,
    ) -> Result<Vec<u8>>;
}

#[derive(Default, Clone)]
pub struct CryptoAdaptor {
    pub padding: Option<openssl::rsa::Padding>,
    pub kits: Option<EncryptKits>,
    pub md: Option<openssl::hash::MessageDigest>,
}
#[derive(Default, Clone)]

pub struct EncryptKits {
    pub iv: Vec<u8>,
    pub aad: Vec<u8>,
    pub tag: Vec<u8>,
}

pub struct KeyAlgorithmMeta {
    pub key_type: KeyType,
    pub key_size: usize,
    pub key_usage: Vec<KeyUsage>,
}

pub fn generate_key(spec: KeySpec) -> Result<(Vec<u8>, Vec<u8>)> {
    let (nid, size) = spec.into();
    match spec {
        KeySpec::Aes128 | KeySpec::Aes256 | KeySpec::SM4 => symm_generate(size),
        KeySpec::Rsa2048 | KeySpec::Rsa3072 => rsa_generate(size),
        KeySpec::EcP256 | KeySpec::EcP256K => ec_generate(nid),
    }
}

pub fn generate_wrapping_key(
    spec: WrappingKeySpec,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let (nid, size) = spec.into();
    match spec {
        WrappingKeySpec::Rsa2048 => rsa_generate(size),
        WrappingKeySpec::EcSm2 => ec_generate(nid),
    }
}

pub fn select_wrapping_meta(spec: WrappingKeySpec) -> KeyAlgorithmMeta {
    match spec {
        WrappingKeySpec::Rsa2048 => KeyAlgorithmMeta {
            key_type: KeyType::Asymmetric,
            key_size: 256,
            key_usage: vec![
                KeyUsage::EncryptAndDecrypt,
                KeyUsage::SignAndVerify,
            ],
        },
        WrappingKeySpec::EcSm2 => KeyAlgorithmMeta {
            key_type: KeyType::Asymmetric,
            key_size: 256,
            key_usage: vec![
                KeyUsage::SignAndVerify,
                KeyUsage::EncryptAndDecrypt,
            ],
        },
    }
}

pub fn select_meta(spec: KeySpec) -> KeyAlgorithmMeta {
    let (_nid, size) = spec.into();
    match spec {
        KeySpec::Aes128 | KeySpec::SM4 => KeyAlgorithmMeta {
            key_type: KeyType::Symmetric,
            key_size: size,
            key_usage: vec![KeyUsage::EncryptAndDecrypt],
        },

        KeySpec::Aes256 => KeyAlgorithmMeta {
            key_type: KeyType::Symmetric,
            key_size: size,
            key_usage: vec![KeyUsage::EncryptAndDecrypt],
        },
        KeySpec::Rsa2048 | KeySpec::Rsa3072 => KeyAlgorithmMeta {
            key_type: KeyType::Asymmetric,
            key_size: size,
            key_usage: vec![
                KeyUsage::EncryptAndDecrypt,
                KeyUsage::SignAndVerify,
            ],
        },

        KeySpec::EcP256 | KeySpec::EcP256K => KeyAlgorithmMeta {
            key_type: KeyType::Asymmetric,
            key_size: size,
            key_usage: vec![KeyUsage::SignAndVerify],
        },
    }
}

pub fn select_wrapping_factory(
    spec: WrappingKeySpec,
) -> Box<dyn KeyAlgorithmFactory + Send> {
    match spec {
        WrappingKeySpec::Rsa2048 => Box::new(RsaAlgorithmFactory {}),
        WrappingKeySpec::EcSm2 => Box::new(EcAlgorithmFactory {}),
    }
}

pub fn select_cipher(
    size: usize,
    key_alg: KeyAlgorithm,
) -> Result<symm::Cipher> {
    Ok(match key_alg {
        KeyAlgorithm::AesCBC => match size * 8 {
            128 => symm::Cipher::aes_128_cbc(),
            256 => symm::Cipher::aes_256_cbc(),
            _ => {
                return Err(ServiceError::Unsupported(format!(
                    "unsupported aes key length: {}",
                    size
                )))
            }
        },
        KeyAlgorithm::AesGCM => match size * 8 {
            128 => symm::Cipher::aes_128_gcm(),
            256 => symm::Cipher::aes_256_gcm(),
            _ => {
                return Err(ServiceError::Unsupported(format!(
                    "unsupported aes key length: {}",
                    size
                )))
            }
        },
        KeyAlgorithm::Sm4CTR => symm::Cipher::sm4_ctr(),
        KeyAlgorithm::Sm4CBC => symm::Cipher::sm4_cbc(),
        _ => {
            return Err(ServiceError::Unsupported(format!(
                "unsupported aes key length: {}",
                size
            )))
        }
    })
}

pub fn select_factory(
    alg: KeyAlgorithm,
) -> Result<Box<dyn KeyAlgorithmFactory>> {
    match alg {
        KeyAlgorithm::AesCBC
        | KeyAlgorithm::Sm4CBC
        | KeyAlgorithm::SM2DSA
        | KeyAlgorithm::SM2PKE => {
            Ok(Box::new(CipherAlgorithmFactory::new(alg)))
        }
        KeyAlgorithm::AesGCM => Ok(Box::new(AEADAlgorithmFactory::new(alg))),
        KeyAlgorithm::RsaOAEP
        | KeyAlgorithm::RsaPSS
        | KeyAlgorithm::RsaPKCS1 => Ok(Box::new(RsaAlgorithmFactory {})),
        KeyAlgorithm::Ecdsa | KeyAlgorithm::EciesSha1 => {
            Ok(Box::new(EcAlgorithmFactory {}))
        }
        _ => Err(ServiceError::Unsupported(format!(
            "unsupported alg {:?}",
            alg
        ))),
    }
}
fn symm_generate(size: usize) -> Result<(Vec<u8>, Vec<u8>)> {
    Ok((utils::generate_key(size)?, vec![]))
}

// currently rust-openssl cant be generate oid = sm2ecc algorithm  pkcs8 key
fn ec_generate(nid: Nid) -> Result<(Vec<u8>, Vec<u8>)> {
    let ec_group = ec::EcGroup::from_curve_name(nid)
        .context(format!("ec group create failed, curve_name: {:?}", nid))?;
    let key_pair = ec::EcKey::generate(&ec_group)
        .context(format!("generate ec key failed, nid: {:?}", nid))?;
    let pkey = pkey::PKey::from_ec_key(key_pair)
        .context("ec key transfer to pkey failed")?;
    Ok((
        pkey.private_key_to_pkcs8()
            .context(format!("export ec private key failed, nid: {:?}", nid))?,
        pkey.public_key_to_der()
            .context(format!("export ec public key failed, nid: {:?}", nid))?,
    ))
}

fn rsa_generate(size: usize) -> Result<(Vec<u8>, Vec<u8>)> {
    let rrg = rsa::Rsa::generate((size * 8) as u32)
        .context("rsa generate key failed")?;
    let pkey =
        pkey::PKey::from_rsa(rrg).context("ec key transfer to pkey failed")?;
    Ok((
        pkey.private_key_to_pkcs8()
            .context("export rsa public key failed")?,
        pkey.public_key_to_der()
            .context("export rsa private key failed")?,
    ))
}
pub fn derive_key(spec: KeySpec, key: &[u8]) -> Result<Vec<u8>> {
    match spec {
        KeySpec::Aes128 | KeySpec::Aes256 | KeySpec::SM4 => Ok(vec![]),
        KeySpec::Rsa2048 | KeySpec::Rsa3072 => rsa_derive(key),
        KeySpec::EcP256 | KeySpec::EcP256K => ec_derive(key),
    }
}

fn ec_derive(private_key: &[u8]) -> Result<Vec<u8>> {
    let pkey = pkey::PKey::private_key_from_pkcs8(private_key)
        .context("import ec private key failed")?;
    Ok(pkey
        .public_key_to_der()
        .context("export ec public key failed")?)
}

fn rsa_derive(private_key: &[u8]) -> Result<Vec<u8>> {
    let pkey_pair = pkey::PKey::private_key_from_pkcs8(private_key)
        .context("import rsa key failed")?;
    Ok(pkey_pair
        .public_key_to_der()
        .context("export public key failed")?)
}

impl From<WrappingKeyAlgorithm> for CryptoAdaptor {
    fn from(value: WrappingKeyAlgorithm) -> Self {
        match value {
            WrappingKeyAlgorithm::RsaesPkcs1V1_5 => CryptoAdaptor {
                padding: Some(rsa::Padding::PKCS1),
                ..Default::default()
            },
            WrappingKeyAlgorithm::RsaesOaepSha1 => CryptoAdaptor {
                padding: Some(rsa::Padding::PKCS1_OAEP),
                md: Some(hash::MessageDigest::sha1()),
                ..Default::default()
            },
            WrappingKeyAlgorithm::RsaesOaepSha256 => CryptoAdaptor {
                padding: Some(rsa::Padding::PKCS1_OAEP),
                md: Some(hash::MessageDigest::sha256()),
                ..Default::default()
            },
            WrappingKeyAlgorithm::SM2PKE => CryptoAdaptor {
                md: Some(hash::MessageDigest::sha256()),
                ..Default::default()
            },
        }
    }
}
