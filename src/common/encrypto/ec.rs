use anyhow::Context;
use openssl::{
    ec,
    encrypt::{self},
    hash,
    nid::Nid,
    pkey, sign,
};

use super::types::{EncryptoAdaptor, KeyAlgorithmFactory};
use crate::common::errors::Result;

#[derive(Default)]
pub struct EcAlgorithm {}

impl KeyAlgorithmFactory for EcAlgorithm {
    type GenrateBasic = Nid;

    fn generate(&self, nid: Nid) -> Result<(Vec<u8>, Vec<u8>)> {
        let ec_group = ec::EcGroup::from_curve_name(nid).context(format!(
            "ec group create failed, curve_name: {:?}",
            nid
        ))?;
        let key_pair = ec::EcKey::generate(&ec_group)
            .context(format!("generate ec key failed, nid: {:?}", nid))?;
        Ok((
            key_pair.private_key_to_der().context(format!(
                "export ec private key failed, nid: {:?}",
                nid
            ))?,
            key_pair.public_key_to_der().context(format!(
                "export ec public key failed, nid: {:?}",
                nid
            ))?,
        ))
    }

    fn derive(&self, private_key: &[u8]) -> Result<Vec<u8>> {
        let ec_key_pair = ec::EcKey::private_key_from_der(private_key)
            .context("import ec private key failed")?;

        Ok(ec_key_pair
            .public_key_to_der()
            .context("export ec public key failed")?)
    }

    fn sign<T: EncryptoAdaptor>(
        &self,
        pri_key: &[u8],
        plaintext: &[u8],
        e: T,
    ) -> Result<Vec<u8>> {
        let ec_key_pair = ec::EcKey::private_key_from_der(pri_key)
            .context("import ec private key failed")?;
        let pkey = pkey::PKey::from_ec_key(ec_key_pair)
            .context("ec private key tansform to pkey failed")?;
        let mut signer = sign::Signer::new(e.md().unwrap(), &pkey)
            .context("pkey tansform to signer failed")?;
        signer
            .update(plaintext)
            .context("ec update plaintext failed")?;

        Ok(signer.sign_to_vec().context("ec signer sign failed")?)
    }

    fn verify<T: EncryptoAdaptor>(
        &self,
        pub_key: &[u8],
        plaintext: &[u8],
        signature: &[u8],
        e: T,
    ) -> Result<bool> {
        let ec_key_pair = ec::EcKey::public_key_from_der(pub_key)
            .context("import ec public key failed")?;
        let pkey = pkey::PKey::from_ec_key(ec_key_pair).context("import")?;
        let mut verifier = sign::Verifier::new(e.md().unwrap(), &pkey)
            .context("pkey tansform to ec verifer failed")?;
        verifier
            .update(plaintext)
            .context("ec verifier update plaintext failed")?;
        Ok(verifier
            .verify(signature)
            .context("ec verifier veirify failed")?)
    }

    fn encrypt<T: EncryptoAdaptor>(
        &self,
        pub_key: &[u8],
        plaintext: &[u8],
        e: T,
    ) -> Result<Vec<u8>> {
        let ec_key_pair = ec::EcKey::public_key_from_der(pub_key)
            .context("import ec public key failed")?;
        let pkey_encrypter = pkey::PKey::from_ec_key(ec_key_pair.clone())
            .context("ec public key transform to pkey faield")?;
        let encrypter = encrypt::Encrypter::new(&pkey_encrypter)
            .context("pkey tansform to decrypter failed")?;
        let mut to = vec![
            0;
            encrypter
                .encrypt_len(plaintext)
                .context("compute ec encrpt size failed")?
        ];
        encrypter
            .encrypt(plaintext, &mut to)
            .context("ec encrypter encrypt failed")?;
        Ok(to)
    }

    fn decrypt<T: EncryptoAdaptor>(
        &self,
        private_key: &[u8],
        plaintext: &[u8],
        e: T,
    ) -> Result<Vec<u8>> {
        let ec_key_pair = ec::EcKey::private_key_from_der(private_key)
            .context("import ec private key failed")?;
        let pkey_decrypter = pkey::PKey::from_ec_key(ec_key_pair.clone())
            .context("ec key transform to pkey faield")?;
        let decrypter = encrypt::Decrypter::new(&pkey_decrypter)
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
