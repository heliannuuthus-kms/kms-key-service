use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
pub enum KeyUseage {
    #[serde(rename = "encrypt/decrypt")]
    EncryptAndDecrypt,
    #[serde(rename = "sign/verify")]
    SignAndVerify,
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename = "snake_case")]
pub enum KeyOrigin {
    Kms,
    External,
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Default)]
pub enum KeySpec {
    #[default]
    Aes128,
    Aes192,
    Aes256,
    Rsa2048,
    Rsa3072,
    EcP256,
    EcP256K,
}

// 主密钥的状态
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Default)]
pub enum KeyState {
    #[default]
    Enable, // 密钥默认处于 enable 状态
    Disable,         /* 处于 Disable
                      * 状态的密钥不可删除，不可使用（加解密，签名验签等），可查询，可创建别名 */
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
