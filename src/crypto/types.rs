use std::{self, option::Option};

use openssl::{cipher::Cipher, nid::Nid};
use sea_orm::{DeriveActiveEnum, EnumIter};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Debug, Copy)]
pub enum KeyAlgorithm {
    #[serde(rename = "AES_128_CBC")]
    Aes128Cbc,
    #[serde(rename = "AES_256_CBC")]
    Aes256Cbc,
    #[serde(rename = "AES_128_GCM")]
    Aes128Gcm,
    #[serde(rename = "AES_128_GCM")]
    Aes256Gcm,
    #[serde(rename = "RSA_2048")]
    Rsa2048,
    #[serde(rename = "RSA_3072")]
    Rsa3072,
    #[serde(rename = "SM2")]
    SM2,
    #[serde(rename = "SM4")]
    SM4,
    #[serde(rename = "EC_P256K")]
    EcP256k,
    #[serde(rename = "EC_P256")]
    EcP256,
}

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
    ToSchema,
)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "key_type")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
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
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
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

impl From<KeySpec> for (Nid, usize) {
    fn from(value: KeySpec) -> Self {
        match value {
            KeySpec::Aes128 => {
                (Nid::AES_128_GCM, Cipher::aes_128_gcm().key_length())
            }
            KeySpec::Aes256 => {
                (Nid::AES_256_GCM, Cipher::aes_256_gcm().key_length())
            }
            KeySpec::Rsa2048 => (Nid::RSA, 256),
            KeySpec::Rsa3072 => (Nid::RSA, 384),
            KeySpec::EcP256 => (Nid::X9_62_PRIME256V1, 256),
            KeySpec::EcP256K => (Nid::SECP256K1, 256),
        }
    }
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
    ToSchema,
)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "state")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyState {
    // 密钥默认处于 enable 状态
    #[default]
    #[sea_orm(string_value = "ENABLE")]
    Enable = 0,
    // 处于 Disable
    // 状态的密钥不可删除，不可使用（加解密，
    // 签名验签等），可查询，可创建别名
    #[sea_orm(string_value = "DISABLE")]
    Disable = 1,
    // 待删除的密钥，
    #[sea_orm(string_value = "PENDING_DELETION")]
    PendingDeletion = 2,
    // 待导入的密钥
    #[sea_orm(string_value = "PENDING_IMPORT")]
    PendingImport,
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Default)]
pub enum KeyStateStatus {
    #[default]
    Success,
    // 处理成功
    RejectedEnable,
    //
    RejectedDisable,
    // 由于 Disable 而失败
    PendingPendingDeletion,
    // 由于 Pending Deletion 失败
    PendingPendingImport,
    // 由于 Pending Import 失败
    PendingStateModifiedFailed, // 操作密钥信息导致前后状态不符合逻辑
}

#[derive(
    Deserialize, Serialize, Clone, PartialEq, Eq, Default, Copy, ToSchema, Debug,
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
    Deserialize, Serialize, Clone, PartialEq, Eq, Default, Copy, ToSchema, Debug,
)]
pub enum WrappingKeySpec {
    #[default]
    #[serde(rename = "RSA_2048")]
    Rsa2048,
    #[serde(rename = "EC_SM2")]
    EcSm2,
}

impl From<WrappingKeySpec> for (Nid, usize) {
    fn from(value: WrappingKeySpec) -> Self {
        match value {
            WrappingKeySpec::Rsa2048 => (Nid::RSA, 256),
            WrappingKeySpec::EcSm2 => (Nid::SM2, 256),
        }
    }
}

// 0.enable 1.disable 2.pendingdeletion 3.archived
pub const KEY_STATE_MAP: [[bool; 3]; 3] =
    [[true, true, true], [true, true, true], [false, true, true]];
