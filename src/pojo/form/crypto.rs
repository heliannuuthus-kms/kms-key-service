use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::crypto::types::{KeyAlgorithm, Padding};

#[derive(Serialize, Deserialize)]
pub struct KeyEncryptBody {
    pub key_id: String,

    pub plaintext: String,

    pub ciphertext: String,

    pub algorithm: KeyAlgorithm,

    pub iv: String,

    pub ada: String,

    pub padding: Padding,
}

impl Debug for KeyEncryptBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyEncryptBody")
            .field("key_id", &self.key_id)
            .field("algorithm", &self.algorithm)
            .field("padding", &self.padding)
            .finish()
    }
}
