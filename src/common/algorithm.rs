use anyhow::Context;
use lazy_static::lazy_static;
use openssl::nid::Nid;
use ring::{
    aead::{AES_128_GCM, AES_256_GCM},
    rand::{SecureRandom, SystemRandom},
};
use sea_orm::{DeriveActiveEnum, EnumIter};
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
    Hash,
    Debug,
    ToSchema,
    EnumIter,
    DeriveActiveEnum,
)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "usage")]
pub enum KeyUsage {
    #[default]
    #[sea_orm(string_value = "ENCRYPT/DECRYPT")]
    #[serde(rename = "encrypt/decrypt")]
    EncryptAndDecrypt,
    #[sea_orm(string_value = "SIGN/VERIFY")]
    #[serde(rename = "sign/verify")]
    SignAndVerify,
}

#[derive(
    DeriveActiveEnum,
    EnumIter,
    Serialize,
    Debug,
    Deserialize,
    Clone,
    PartialEq,
    Eq,
    Default,
    Copy,
)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "key_type")]
pub enum KeyType {
    #[sea_orm(string_value = "SYMMETRIC")]
    Symmetric,
    #[sea_orm(string_value = "ASYMMETRIC")]
    Asymmetric,
    #[default]
    #[sea_orm(string_value = "UNKNWON")]
    Unknown,
}

#[derive(
    Debug,
    Deserialize,
    Serialize,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    ToSchema,
    EnumIter,
    DeriveActiveEnum,
)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "usage")]
#[serde(rename = "snake_case")]
pub enum KeyOrigin {
    #[default]
    #[sea_orm(string_value = "KMS")]
    Kms,
    #[sea_orm(string_value = "EXTERNAL")]
    External,
}

#[derive(
    Deserialize,
    Serialize,
    Clone,
    PartialEq,
    DeriveActiveEnum,
    EnumIter,
    Eq,
    Default,
    Copy,
    ToSchema,
    Debug,
)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "sepc")]
pub enum KeySpec {
    #[default]
    #[sea_orm(string_value = "AES_128")]
    #[serde(rename = "AES_128")]
    Aes128,
    #[sea_orm(string_value = "AES_256")]
    #[serde(rename = "AES_256")]
    Aes256,
    #[sea_orm(string_value = "RSA_2048")]
    #[serde(rename = "RSA_2048")]
    Rsa2048,
    #[sea_orm(string_value = "RSA_3072")]
    #[serde(rename = "RSA_3072")]
    Rsa3072,
    #[sea_orm(string_value = "EC_P256")]
    #[serde(rename = "EC_P256")]
    EcP256,
    #[sea_orm(string_value = "EC_P256k")]
    #[serde(rename = "EC_P256K")]
    EcP256K,
}

// 主密钥的状态
#[derive(
    Deserialize,
    EnumIter,
    DeriveActiveEnum,
    Serialize,
    Clone,
    PartialEq,
    Eq,
    Default,
    Copy,
    Debug,
)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "state")]
pub enum KeyState {
    #[default]
    #[sea_orm(string_value = "ENABLE")]
    Enable, // 密钥默认处于 enable 状态
    #[sea_orm(string_value = "DISABLE")]
    Disable, /* 处于 Disable
              * 状态的密钥不可删除，不可使用（加解密，
              * 签名验签等），可查询，可创建别名 */
    #[sea_orm(string_value = "PENDING_DELETION")]
    PendingDeletion, // 待删除的密钥，
    #[sea_orm(string_value = "IMPORT_DELETION")]
    Pendingimport, // 待导入的密钥
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
    Deserialize, Serialize, Clone, PartialEq, Eq, Default, Copy, ToSchema,
)]
pub enum WrappingKeyAlgorithm {
    #[default]
    #[serde(rename = "RSAES_PKCS1_V1_5")]
    RsaesPkcs1V1_5,
    #[serde(rename = "RSAES_OAEP_SHA_1")]
    RsaesOaepSha1,
    #[serde(rename = "RSAES_OAEP_SHA_256")]
    RsaesOaepSha256,
    #[serde(rename = "SM2PKE")]
    SM2PKE,
}

#[derive(
    Deserialize, Serialize, Clone, PartialEq, Eq, Default, Copy, ToSchema,
)]
pub enum WrappingKeySpec {
    #[default]
    #[serde(rename = "RSA_2048")]
    Rsa2048,
    #[serde(rename = "EC_SM2")]
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
    pub static ref EC_SM2: KeyAlgorithm = KeyAlgorithm {
        key_type: KeyType::Asymmetric,
        key_size: 256,
        key_spec: KeySpec::EcP256K,
        generator: gen_ec_sm2,
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
        encode64(&ec_key.private_key_to_der().with_context(|| {
            let msg = format!("initial {} private key failed", algorithm);
            msg
        })?),
        encode64(&ec_key.public_key_to_der().with_context(|| {
            let msg = format!("initial {} public key failed", algorithm);
            msg
        })?),
    ))
}
