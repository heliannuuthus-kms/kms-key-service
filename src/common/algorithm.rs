use anyhow::Context;
use lazy_static::lazy_static;
use openssl::nid::Nid;
use ring::{
    aead::{AES_128_GCM, AES_256_GCM},
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{errors::Result, utils::encode64};

#[derive(
    Deserialize,
    Serialize,
    Clone,
    PartialEq,
    Eq,
    Default,
    Copy,
    sqlx::Encode,
    sqlx::Decode,
    Hash,
    Debug,
    ToSchema,
)]
pub enum KeyUsage {
    #[default]
    #[serde(rename = "encrypt/decrypt")]
    #[sqlx(rename = "ENCRYPT/DECRYPT")]
    EncryptAndDecrypt,
    #[serde(rename = "sign/verify")]
    #[sqlx(rename = "SIGN/VERIFY")]
    SignAndVerify,
}

#[derive(
    Deserialize,
    Serialize,
    Clone,
    PartialEq,
    Eq,
    Default,
    sqlx::Decode,
    sqlx::Encode,
    Copy,
)]
pub enum KeyType {
    #[sqlx(rename = "SYMMETRIC")]
    Symmetric,
    #[sqlx(rename = "ASYMMETRIC")]
    Asymmetric,
    #[default]
    #[sqlx(rename = "UNKNOWN")]
    Unknown,
}

#[derive(
    Deserialize,
    Serialize,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    sqlx::Encode,
    sqlx::Decode,
    ToSchema,
)]
#[serde(rename = "snake_case")]
pub enum KeyOrigin {
    #[default]
    Kms,
    External,
}

#[derive(
    Deserialize,
    Serialize,
    Clone,
    PartialEq,
    Eq,
    Default,
    Copy,
    sqlx::Encode,
    sqlx::Decode,
    ToSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeySpec {
    #[default]
    Aes128,
    Aes256,
    Rsa2048,
    Rsa3072,
    EcP256,
    EcP256K,
}

impl From<KeySpec> for KeyType {
    fn from(value: KeySpec) -> Self {
        match value {
            KeySpec::Aes128 => KeyType::Symmetric,
            KeySpec::Aes256 => KeyType::Symmetric,
            KeySpec::Rsa2048 => KeyType::Asymmetric,
            KeySpec::Rsa3072 => KeyType::Asymmetric,
            KeySpec::EcP256 => KeyType::Asymmetric,
            KeySpec::EcP256K => KeyType::Asymmetric,
        }
    }
}

// 主密钥的状态
#[derive(
    Deserialize,
    Serialize,
    Clone,
    PartialEq,
    Eq,
    Default,
    sqlx::Encode,
    sqlx::Decode,
    Copy,
)]
pub enum KeyState {
    #[default]
    Enable, // 密钥默认处于 enable 状态
    Disable,         /* 处于 Disable
                      * 状态的密钥不可删除，不可使用（加解密，
                      * 签名验签等），可查询，可创建别名 */
    PendingDeletion, // 待删除的密钥，
    Pendingimport,   // 待导入的密钥
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Default)]
pub enum KeyStateStatus {
    #[default]
    Success, // 处理成功
    RejectedEnable,             //
    RejectedDisable,            // 由于 Disable 而失败
    PendingPendingDeletion,     // 由于 Pending Deletion 失败
    PendingPendingImport,       // 由于 Pending Import 失败
    PendingStateModifiedFailed, // 操作密钥信息导致前后状态不符合逻辑
}

#[derive(
    Deserialize,
    Serialize,
    Clone,
    PartialEq,
    Eq,
    Default,
    Copy,
    ToSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WrappingKeyAlgorithm {
    #[default]
    RsaesPkcs1V1_5,
    RsaesOaepSha1,
    RsaesOaepSha256,
    SM2PKE,
}

#[derive(
    Deserialize,
    Serialize,
    Clone,
    PartialEq,
    Eq,
    Default,
    Copy,
    ToSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WrappingKeySpec {
    #[default]
    Rsa2048,
    EcSm2,
}

pub struct KeyAlgorithm {
    pub key_type: KeyType,
    pub key_size: usize,
    pub key_spec: KeySpec,
    pub key_usage: Vec<KeyUsage>,
    pub generator: fn() -> Result<(String, String)>,
}

lazy_static! {
    pub static ref AES_128: KeyAlgorithm = KeyAlgorithm {
        key_type: KeyType::Symmetric,
        key_size: AES_128_GCM.key_len(),
        key_spec: KeySpec::Aes128,
        generator: gen_aes_128,
        key_usage: vec![KeyUsage::EncryptAndDecrypt],
    };
    pub static ref AES_256: KeyAlgorithm = KeyAlgorithm {
        key_type: KeyType::Symmetric,
        key_size: AES_256_GCM.key_len(),
        key_spec: KeySpec::Aes256,
        generator: gen_aes_256,
        key_usage: vec![KeyUsage::EncryptAndDecrypt],
    };
    pub static ref RSA_2048: KeyAlgorithm = KeyAlgorithm {
        key_type: KeyType::Asymmetric,
        key_size: 2048,
        key_spec: KeySpec::Rsa2048,
        generator: gen_rsa_2048,
        key_usage: vec![KeyUsage::EncryptAndDecrypt, KeyUsage::SignAndVerify],
    };
    pub static ref RSA_3072: KeyAlgorithm = KeyAlgorithm {
        key_type: KeyType::Asymmetric,
        key_size: 3072,
        key_spec: KeySpec::Rsa3072,
        generator: gen_rsa_3072,
        key_usage: vec![KeyUsage::EncryptAndDecrypt, KeyUsage::SignAndVerify],
    };
    pub static ref EC_P256: KeyAlgorithm = KeyAlgorithm {
        key_type: KeyType::Asymmetric,
        key_size: 256,
        key_spec: KeySpec::EcP256,
        generator: gen_ecp256,
        key_usage: vec![KeyUsage::SignAndVerify],
    };
    pub static ref EC_P256K: KeyAlgorithm = KeyAlgorithm {
        key_type: KeyType::Asymmetric,
        key_size: 256,
        key_spec: KeySpec::EcP256K,
        generator: gen_ecp256k,
        key_usage: vec![KeyUsage::SignAndVerify],
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
    let key_pair = &encode64(&key_bytes);
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
        encode64(&rsa.private_key_to_der().with_context(|| {
            tracing::error!("export rsa private key failed");
            "initial rsa private key failed"
        })?),
        encode64(&rsa.public_key_to_der().with_context(|| {
            tracing::error!("export rsa public key failed");
            "initial rsa public key failed"
        })?),
    ))
}

fn gen_ecp256() -> Result<(String, String)> {
    let ecg = openssl::ec::EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .with_context(|| {
            tracing::error!("create ec group failed");
            "create ec group failed"
        })?;

    let ec_key = openssl::ec::EcKey::generate(&ecg).with_context(|| {
        tracing::error!("generate ec key failed");
        "generate ecp256 key failed"
    })?;
    Ok((
        encode64(&ec_key.private_key_to_der().with_context(|| {
            tracing::error!("export ecp256 private key failed");
            "initial ecp256 private key failed"
        })?),
        encode64(&ec_key.public_key_to_der().with_context(|| {
            tracing::error!("export ecp256 public key failed");
            "initial ecp256 public key failed"
        })?),
    ))
}

fn gen_ecp256k() -> Result<(String, String)> {
    let ecg = openssl::ec::EcGroup::from_curve_name(Nid::SECP256K1)
        .with_context(|| {
            tracing::error!("create ecp256k group failed");
            "create ecp256k group failed"
        })?;
    let ec_key = openssl::ec::EcKey::generate(&ecg).with_context(|| {
        tracing::error!("generate ecp256k key failed");
        "generate ecp256k key failed"
    })?;
    Ok((
        encode64(&ec_key.private_key_to_der().with_context(|| {
            tracing::error!("export ecp256k private key failed");
            "initial ecp256k private key failed"
        })?),
        encode64(&ec_key.public_key_to_der().with_context(|| {
            tracing::error!("export ecp256k public key failed");
            "initial ecp256k public key failed"
        })?),
    ))
}
