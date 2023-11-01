use anyhow::Context;
use openssl::{
    encrypt::{self},
    hash, pkey, rsa, sign,
};

use super::types::{EncryptoAdaptor, KeyAlgorithmFactory};
use crate::common::errors::Result;

#[derive(Default)]
pub struct RsaAlgorithm {}
impl KeyAlgorithmFactory for RsaAlgorithm {
    type GenrateBasic = usize;

    fn generate(
        &self,
        basic: Self::GenrateBasic,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let rrg = rsa::Rsa::generate(basic as u32)
            .context("rsa generate key failed")?;

        Ok((
            rrg.private_key_to_der()
                .context("export rsa public key failed")?,
            rrg.public_key_to_der()
                .context("export rsa private key failed")?,
        ))
    }

    fn derive(&self, private_key: &[u8]) -> Result<Vec<u8>> {
        let key_pair: rsa::Rsa<pkey::Private> =
            rsa::Rsa::private_key_from_der(private_key)
                .context("import rsa key failed")?;
        Ok(key_pair
            .public_key_to_der()
            .context("export public key failed")?)
    }

    fn sign<T: EncryptoAdaptor>(
        &self,
        pri_key: &[u8],
        plaintext: &[u8],
        e: T,
    ) -> Result<Vec<u8>> {
        let rsa_key_pair = rsa::Rsa::private_key_from_der(pri_key)
            .context("import rsa private key failed")?;
        let pkey = pkey::PKey::from_rsa(rsa_key_pair)
            .context("rsa private key tansform to pkey failed")?;
        let mut signer = sign::Signer::new(e.md().unwrap(), &pkey)
            .context("pkey tansform to rsa signer failed")?;

        if let Some(pad) = e.padding() {
            signer
                .set_rsa_padding(pad)
                .context(format!("rsa signer set padding failed, {:?}", pad))?;
        }
        signer
            .update(plaintext)
            .context("rsa signer update plaintext failed")?;

        Ok(signer.sign_to_vec().context("rsa signer sign failed")?)
    }

    fn verify<T: EncryptoAdaptor>(
        &self,
        pub_key: &[u8],
        plaintext: &[u8],
        signature: &[u8],
        e: T,
    ) -> Result<bool> {
        let rsa_key_pair = rsa::Rsa::public_key_from_der(pub_key)
            .context("import public key failed")?;
        let pkey = pkey::PKey::from_rsa(rsa_key_pair).context("import")?;
        let mut verifier = sign::Verifier::new(e.md().unwrap(), &pkey)
            .context("pkey tansform to verifer failed")?;

        verifier
            .update(plaintext)
            .context("rsa signer update plaintext failed")?;

        if let Some(pad) = e.padding() {
            verifier.set_rsa_padding(pad).context(format!(
                "rsa verifier set padding failed, {:?}",
                pad
            ))?;
        }

        Ok(verifier
            .verify(signature)
            .context("rsa verifier verify failed")?)
    }

    fn encrypt<T: EncryptoAdaptor>(
        &self,
        pub_key: &[u8],
        plaintext: &[u8],
        e: T,
    ) -> Result<Vec<u8>> {
        let rsa_key_pair = rsa::Rsa::public_key_from_der(pub_key)
            .context("import public key failed")?;
        let pkey_encrypter = pkey::PKey::from_rsa(rsa_key_pair.clone())
            .context("rsa public key transform to pkey faield")?;
        let mut encrypter = encrypt::Encrypter::new(&pkey_encrypter)
            .context("pkey tansform to decrypter failed")?;

        if let Some(pad) = e.padding() {
            encrypter.set_rsa_padding(pad).context(format!(
                "rsa encrypter set padding failed, {:?}",
                pad
            ))?;
        }

        if let Some(md) = e.md() {
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
        encrypter
            .encrypt(plaintext, &mut to)
            .context("rsa encrypter encrypt failed")?;
        Ok(to)
    }

    fn decrypt<T: EncryptoAdaptor>(
        &self,
        private_key: &[u8],
        cipher: &[u8],
        e: T,
    ) -> Result<Vec<u8>> {
        let rsa_key_pair = rsa::Rsa::private_key_from_der(private_key)
            .context("import rsa private key failed")?;
        let pkey_decrypter = pkey::PKey::from_rsa(rsa_key_pair.clone())
            .context("rsa key transform to pkey faield")?;
        let mut decrypter = encrypt::Decrypter::new(&pkey_decrypter)
            .context("pkey tansform to decrypter failed")?;

        if let Some(pad) = e.padding() {
            decrypter.set_rsa_padding(pad).context(format!(
                "rsa decrypter set padding failed, {:?}",
                pad
            ))?;
        }

        if let Some(md) = e.md() {
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
        decrypter
            .decrypt(cipher, &mut to)
            .context("rsa decrypter decrypt failed")?;
        Ok(to)
    }
}
