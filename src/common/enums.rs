


use serde::{Deserialize, Serialize};

use super::{
    errors::{ServiceError},
};

#[derive(
    Deserialize,
    Serialize,
    Clone,
    PartialEq,
    Eq,
    Default,
    Copy,
    sqlx::Type,
    Hash,
    Debug,
)]
pub enum KeyUsage {
    #[default]
    #[serde(rename = "encrypt/decrypt")]
    EncryptAndDecrypt,
    #[serde(rename = "sign/verify")]
    SignAndVerify,
}

impl TryInto<KeyUsage> for KeySpec {
    type Error = ServiceError;

    fn try_into(self) -> std::result::Result<KeyUsage, Self::Error> {
        match self {
            KeySpec::Aes128
            | KeySpec::Aes256
            | KeySpec::Rsa2048
            | KeySpec::Rsa3072
            | KeySpec::EcP256
            | KeySpec::EcP256K => Ok(KeyUsage::EncryptAndDecrypt),
            KeySpec::Rsa2048
            | KeySpec::Rsa3072
            | KeySpec::EcP256
            | KeySpec::EcP256K => Ok(KeyUsage::SignAndVerify),
        }
    }
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Default, sqlx::Type)]
pub enum KeyType {
    Symmetric,
    Asymmetric,
    #[default]
    Unknown,
}

#[derive(
    Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Default, sqlx::Type,
)]
#[serde(rename = "snake_case")]
pub enum KeyOrigin {
    #[default]
    Kms,
    External,
}

#[derive(
    Deserialize, Serialize, Clone, PartialEq, Eq, Default, Copy, sqlx::Type,
)]
pub enum KeySpec {
    #[default]
    Aes128,
    Aes256,
    Rsa2048,
    Rsa3072,
    EcP256,
    EcP256K,
}

impl Into<KeyType> for KeySpec {
    fn into(self) -> KeyType {
        match self {
            KeySpec::Aes128 | KeySpec::Aes256 => KeyType::Symmetric,
            KeySpec::Rsa2048
            | KeySpec::Rsa3072
            | KeySpec::EcP256
            | KeySpec::EcP256K => KeyType::Asymmetric,
        }
    }
}

// 主密钥的状态
#[derive(
    Deserialize, Serialize, Clone, PartialEq, Eq, Default, sqlx::Type, Copy,
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
