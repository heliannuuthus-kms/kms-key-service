use anyhow::Context;
use openssl::{
    cipher_ctx::CipherCtx,
    symm::{self, Cipher},
};

use super::algorithm::{AES_128, AES_256};
use crate::common::errors::{Result, ServiceError};

pub struct SymmAlgorithm {}

impl SymmAlgorithm {
    pub fn aes_encrypt(
        key: &[u8],
        iv: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        ring::aead
    }
}
