use anyhow::Context;
use openssl::{
    encrypt::{self},
    pkey, sign,
};

use super::algorithm::{CryptoAdaptor, KeyAlgorithmFactory};
use crate::common::errors::Result;

pub struct RsaAlgorithmFactory {}

impl KeyAlgorithmFactory for RsaAlgorithmFactory {
    fn sign(
        &self,
        pri_key: &[u8],
        plaintext: &[u8],
        e: &CryptoAdaptor,
    ) -> Result<Vec<u8>> {
        let pkey = pkey::PKey::private_key_from_pkcs8(pri_key)
            .context("import rsa private key pkcs8 failed")?;
        let mut signer = sign::Signer::new(e.md.unwrap(), &pkey)
            .context("pkey tansform to rsa signer failed")?;

        if let Some(pad) = e.padding {
            signer
                .set_rsa_padding(pad)
                .context(format!("rsa signer set padding failed, {:?}", pad))?;
        }
        signer
            .update(plaintext)
            .context("rsa signer update plaintext failed")?;

        Ok(signer.sign_to_vec().context("rsa signer sign failed")?)
    }

    fn verify(
        &self,
        pub_key: &[u8],
        plaintext: &[u8],
        signature: &[u8],
        e: &CryptoAdaptor,
    ) -> Result<bool> {
        let pkey = pkey::PKey::public_key_from_der(pub_key)
            .context("import public key failed")?;
        let mut verifier = sign::Verifier::new(e.md.unwrap(), &pkey)
            .context("pkey tansform to verifer failed")?;

        verifier
            .update(plaintext)
            .context("rsa signer update plaintext failed")?;

        if let Some(pad) = e.padding {
            verifier.set_rsa_padding(pad).context(format!(
                "rsa verifier set padding failed, {:?}",
                pad
            ))?;
        }

        Ok(verifier
            .verify(signature)
            .context("rsa verifier verify failed")?)
    }

    fn encrypt(
        &self,
        pub_key: &[u8],
        plaintext: &[u8],
        e: &mut CryptoAdaptor,
    ) -> Result<Vec<u8>> {
        let pkey_encrypter = pkey::PKey::public_key_from_der(pub_key)
            .context("rsa public key transform to pkey faield")?;
        let mut encrypter = encrypt::Encrypter::new(&pkey_encrypter)
            .context("pkey tansform to decrypter failed")?;

        if let Some(pad) = e.padding {
            encrypter.set_rsa_padding(pad).context(format!(
                "rsa encrypter set padding failed, {:?}",
                pad
            ))?;
        }

        if let Some(md) = e.md {
            encrypter
                .set_rsa_mgf1_md(md)
                .context("rsa encrypter set mgf1 md failed")?;
            encrypter
                .set_rsa_oaep_md(md)
                .context("rsa encrypter set oaep md failed")?;
        }
        let mut to = vec![
            0;
            encrypter
                .encrypt_len(plaintext)
                .context("compute rsa encrpt size failed")?
        ];
        let encrypt_len = encrypter
            .encrypt(plaintext, &mut to)
            .context("rsa encrypter encrypt failed")?;
        to.truncate(encrypt_len);
        Ok(to)
    }

    fn decrypt(
        &self,
        private_key: &[u8],
        cipher: &[u8],
        e: &CryptoAdaptor,
    ) -> Result<Vec<u8>> {
        let pkey_decrypter = pkey::PKey::private_key_from_pkcs8(private_key)
            .context("rsa private key pkcs8 to pkey faield")?;
        let mut decrypter = encrypt::Decrypter::new(&pkey_decrypter)
            .context("pkey tansform to decrypter failed")?;

        if let Some(pad) = e.padding {
            decrypter.set_rsa_padding(pad).context(format!(
                "rsa decrypter set padding failed, {:?}",
                pad
            ))?;
        }

        if let Some(md) = e.md {
            decrypter
                .set_rsa_mgf1_md(md)
                .context("rsa decrypter set mgf1 md failed")?;
            decrypter
                .set_rsa_oaep_md(md)
                .context("rsa decrypter set oaep md failed")?;
        }
        let mut to = vec![
            0;
            decrypter
                .decrypt_len(cipher)
                .context("compute rsa decrypt size failed")?
        ];
        let decrypt_len = decrypter
            .decrypt(cipher, &mut to)
            .context("rsa decrypter decrypt failed")?;
        to.truncate(decrypt_len);
        Ok(to)
    }
}
