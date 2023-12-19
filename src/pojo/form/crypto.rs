use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::crypto::{
    algorithm::{CryptoAdaptor, EncryptKits},
    types::{KeyAlgorithm, Padding}, symm::generate_iv,
};

#[derive(Serialize, Deserialize)]
pub struct KeyCryptoBody {
    pub plaintext: Option<String>,

    pub ciphertext: Option<String>,

    pub algorithm: KeyAlgorithm,

    pub iv: Option<String>,

    pub ada: Option<String>,

    pub padding: bool,
}

impl Debug for KeyCryptoBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyEncryptBody")
            .field("algorithm", &self.algorithm)
            .field("padding", &self.padding)
            .finish()
    }
}

