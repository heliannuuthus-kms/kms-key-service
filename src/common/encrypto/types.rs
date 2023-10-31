use sea_orm::{DeriveActiveEnum, EnumIter};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
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
    Enable,
    // 密钥默认处于 enable 状态
    #[sea_orm(string_value = "DISABLE")]
    Disable,
    // 处于 Disable
    // 状态的密钥不可删除，不可使用（加解密，
    // 签名验签等），可查询，可创建别名
    #[sea_orm(string_value = "PENDING_DELETION")]
    PendingDeletion,
    // 待删除的密钥，
    #[sea_orm(string_value = "IMPORT_DELETION")]
    Pendingimport, // 待导入的密钥
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
