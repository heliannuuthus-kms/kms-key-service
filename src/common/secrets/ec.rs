use anyhow::{anyhow, Context};
use openssl::{
    ec,
    encrypt::{self, Decrypter},
    hash, pkey, sign,
};
use serde::de;

use crate::common::{
    errors::{Result, ServiceError},
    utils::{self},
};

pub struct ECAlgorithm {}

impl ECAlgorithm {
    pub fn sign(
        pri_key: &[u8],
        plaintext: &[u8],
        message_digest: hash::MessageDigest,
    ) -> Result<Vec<u8>> {
        let ec_key_pair = ec::EcKey::private_key_from_der(pri_key)
            .context("import ec private key failed")?;
        let pkey = pkey::PKey::from_ec_key(ec_key_pair)
            .context("ec private key tansform to pkey failed")?;
        let mut signer = sign::Signer::new(message_digest, &pkey)
            .context("pkey tansform to signer failed")?;
        signer
            .update(plaintext)
            .context("ec update plaintext failed")?;

        Ok(signer.sign_to_vec().context("ec signer sign failed")?)
    }

    pub fn verifier(
        pub_key: &[u8],
        plaintext: &[u8],
        signature: &[u8],
        message_digest: hash::MessageDigest,
    ) -> Result<bool> {
        let ec_key_pair = ec::EcKey::public_key_from_der(pub_key)
            .context("import ec public key failed")?;
        let pkey = pkey::PKey::from_ec_key(ec_key_pair).context("import")?;
        let mut verifier = sign::Verifier::new(message_digest, &pkey)
            .context("pkey tansform to ec verifer failed")?;
        verifier
            .update(plaintext)
            .context("ec verifier update plaintext failed");
        Ok(verifier
            .verify(signature)
            .context("ec verifier veirify failed")?)
    }

    pub fn encrypter(
        pub_key: &[u8],
        plaintext: &[u8],
        message_digest: hash::MessageDigest,
    ) -> Result<Vec<u8>> {
        let ec_key_pair = ec::EcKey::public_key_from_der(pub_key)
            .context("import ec public key failed")?;
        let pkey_encrypter = pkey::PKey::from_ec_key(ec_key_pair.clone())
            .context("ec public key transform to pkey faield")?;
        let mut encrypter = encrypt::Encrypter::new(&pkey_encrypter)
            .context("pkey tansform to decrypter failed")?;
        let mut to = vec![
            0;
            encrypter
                .encrypt_len(plaintext)
                .context("compute ec encrpt size failed")?
        ];
        encrypter
            .encrypt(plaintext, &mut to)
            .context("ec encrypter encrypt failed");
        Ok(to)
    }

    pub fn decrypter(
        private_key: &[u8],
        plaintext: &[u8],
        message_digest: hash::MessageDigest,
    ) -> Result<Vec<u8>> {
        let ec_key_pair = ec::EcKey::private_key_from_der(private_key)
            .context("import ec private key failed")?;
        let pkey_decrypter = pkey::PKey::from_ec_key(ec_key_pair.clone())
            .context("ec key transform to pkey faield")?;
        let mut decrypter = encrypt::Decrypter::new(&pkey_decrypter)
            .context("pkey tansform to ec decrypter failed")?;
        let mut to = vec![
            0;
            decrypter
                .decrypt_len(plaintext)
                .context("compute ec decrypt size failed")?
        ];
        decrypter
            .decrypt(plaintext, &mut to)
            .context("ec decrypter decrypt failed")?;
        Ok(to)
    }
}
