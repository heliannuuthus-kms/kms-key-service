use serde::{Deserialize, Serialize};

use crate::crypto::types::{KeyAlgorithm, Padding};

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptBody {
    pub key_id: String,

    pub plaintext: String,

    pub ciphertext: String,

    pub algorithm: KeyAlgorithm,

    pub iv: String,

    pub ada: String,

    pub padding: Padding
}
