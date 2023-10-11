use std::default;

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename = "snake_case")]
pub enum KeyUseage {
    EncryptAndDecrypt,
    SignAndVerify,
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename = "snake_case")]
pub enum KeyOrigin {
    Generator,
    External,
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Default)]
pub enum KeySpec {
    #[default]
    Aes256,
    Rsa2048,
    Rsa3072,
    EcP256,
    EcP256K,
}
