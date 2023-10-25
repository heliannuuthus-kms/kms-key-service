use anyhow::{anyhow, Context};
use lazy_static::lazy_static;
use openssl::{nid::Nid, rsa};
use ring::{
    aead::{AES_128_GCM, AES_256_GCM},
    rand::{SecureRandom, SystemRandom},
};

use super::types::{KeySpec, KeyType, KeyUsage};
use crate::common::{
    errors::{Result, ServiceError},
    utils::{self},
};

pub struct KeyAlgorithm {
    pub key_type: KeyType,
    pub key_size: usize,
    pub key_spec: KeySpec,
    pub key_usage: Vec<KeyUsage>,
    pub generator: fn() -> Result<(String, String)>,
    pub deriver: fn(&[u8]) -> Result<(String, String)>,
}

lazy_static! {
    pub static ref AES_128: KeyAlgorithm = KeyAlgorithm {
        key_type: KeyType::Symmetric,
        key_size: AES_128_GCM.key_len(),
        key_spec: KeySpec::Aes128,
        generator: gen_aes_128,
        deriver: aes_deriver,
        key_usage: vec![KeyUsage::EncryptAndDecrypt],
    };
    pub static ref AES_256: KeyAlgorithm = KeyAlgorithm {
        key_type: KeyType::Symmetric,
        key_size: AES_256_GCM.key_len(),
        key_spec: KeySpec::Aes256,
        generator: gen_aes_256,
        deriver: aes_deriver,
        key_usage: vec![KeyUsage::EncryptAndDecrypt],
    };
    pub static ref RSA_2048: KeyAlgorithm = KeyAlgorithm {
        key_type: KeyType::Asymmetric,
        key_size: 2048,
        key_spec: KeySpec::Rsa2048,
        generator: gen_rsa_2048,
        deriver: rsa_deriver,
        key_usage: vec![KeyUsage::EncryptAndDecrypt, KeyUsage::SignAndVerify],
    };
    pub static ref RSA_3072: KeyAlgorithm = KeyAlgorithm {
        key_type: KeyType::Asymmetric,
        key_size: 3072,
        key_spec: KeySpec::Rsa3072,
        generator: gen_rsa_3072,
        deriver: rsa_deriver,
        key_usage: vec![KeyUsage::EncryptAndDecrypt, KeyUsage::SignAndVerify],
    };
    pub static ref EC_P256: KeyAlgorithm = KeyAlgorithm {
        key_type: KeyType::Asymmetric,
        key_size: 256,
        key_spec: KeySpec::EcP256,
        generator: gen_ecp256,
        deriver: ecc_deriver,
        key_usage: vec![KeyUsage::SignAndVerify],
    };
    pub static ref EC_P256K: KeyAlgorithm = KeyAlgorithm {
        key_type: KeyType::Asymmetric,
        key_size: 256,
        key_spec: KeySpec::EcP256K,
        generator: gen_ecp256k,
        deriver: ecc_deriver,
        key_usage: vec![KeyUsage::SignAndVerify],
    };
    pub static ref EC_SM2: KeyAlgorithm = KeyAlgorithm {
        key_type: KeyType::Asymmetric,
        key_size: 256,
        key_spec: KeySpec::EcP256K,
        generator: gen_ec_sm2,
        deriver: ecc_deriver,
        key_usage: vec![KeyUsage::SignAndVerify, KeyUsage::EncryptAndDecrypt],
    };
}

fn gen_aes_128() -> Result<(String, String)> {
    gen_aes(AES_128_GCM.key_len())
}

fn gen_aes_256() -> Result<(String, String)> {
    gen_aes(AES_256_GCM.key_len())
}

fn gen_aes(size: usize) -> Result<(String, String)> {
    let rand = SystemRandom::new();
    let mut key_bytes = vec![0; size];
    rand.fill(&mut key_bytes).unwrap();
    let key_pair = &utils::encode64(&key_bytes);
    Ok((key_pair.to_string(), key_pair.to_string()))
}

fn gen_rsa_2048() -> Result<(String, String)> {
    gen_rsa(2048)
}

fn gen_rsa_3072() -> Result<(String, String)> {
    gen_rsa(3072)
}

fn gen_rsa(size: usize) -> Result<(String, String)> {
    let rsa = openssl::rsa::Rsa::generate(size as u32).unwrap();
    Ok((
        utils::encode64(&rsa.private_key_to_der().with_context(|| {
            tracing::error!("export rsa private key failed");
            "initial rsa private key failed"
        })?),
        utils::encode64(&rsa.public_key_to_der().with_context(|| {
            tracing::error!("export rsa public key failed");
            "initial rsa public key failed"
        })?),
    ))
}

fn gen_ecp256() -> Result<(String, String)> {
    gen_ec(Nid::X9_62_PRIME256V1, "ecp256")
}

fn gen_ecp256k() -> Result<(String, String)> {
    gen_ec(Nid::SECP256K1, "ecp256k")
}

fn gen_ec_sm2() -> Result<(String, String)> {
    gen_ec(Nid::SM2, "sm2")
}

fn gen_ec(nid: Nid, algorithm: &str) -> Result<(String, String)> {
    let ecg =
        openssl::ec::EcGroup::from_curve_name(nid).with_context(|| {
            let msg = format!("create {} group failed", algorithm);
            tracing::error!(msg);
            msg
        })?;
    let ec_key = openssl::ec::EcKey::generate(&ecg).with_context(|| {
        let msg = format!("generate {} key failed", algorithm);
        msg
    })?;
    Ok((
        utils::encode64(&ec_key.private_key_to_der().with_context(|| {
            let msg = format!("initial {} private key failed", algorithm);
            msg
        })?),
        utils::encode64(&ec_key.public_key_to_der().with_context(|| {
            let msg = format!("initial {} public key failed", algorithm);
            msg
        })?),
    ))
}

fn aes_deriver(import_key: &[u8]) -> Result<(String, String)> {
    let key = &utils::encode64(import_key);
    Ok((key.to_owned(), key.to_owned()))
}

fn rsa_deriver(import_key: &[u8]) -> Result<(String, String)> {
    let rsa_key_pair = rsa::Rsa::private_key_from_der(import_key)
        .context(ServiceError::BadRequest("invalid secret".to_owned()))?;

    Ok((
        utils::encode64(import_key),
        utils::encode64(&rsa_key_pair.public_key_to_der().context(
            ServiceError::InternalServer(anyhow!(
                "rsa derive public key failed"
            )),
        )?),
    ))
}

fn ecc_deriver(import_key: &[u8]) -> Result<(String, String)> {
    let ec = openssl::ec::EcKey::private_key_from_der(import_key)
        .context(ServiceError::BadRequest("invalid ec key".to_owned()))?;
    Ok((
        utils::encode64(import_key),
        utils::encode64(&ec.public_key_to_der().context(
            ServiceError::InternalServer(anyhow!(
                "ec derive public key failed"
            )),
        )?),
    ))
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
