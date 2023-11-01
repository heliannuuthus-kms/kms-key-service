use anyhow::Context;
use openssl::{
    encrypt::{self},
    pkey, sign,
};

use super::algorithm::{EncryptoAdaptor, KeyAlgorithmFactory};
use crate::common::errors::Result;

pub struct EcAlgorithmFactory {}

impl EcAlgorithmFactory {}

impl KeyAlgorithmFactory for EcAlgorithmFactory {
    fn sign(
        &self,
        pri_key: &[u8],
        plaintext: &[u8],
        e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        let pkey = pkey::PKey::private_key_from_pkcs8(pri_key)
            .context("import ec private key pkcs8 to pkey failed")?;
        let mut signer = sign::Signer::new(e.md.unwrap(), &pkey)
            .context("pkey tansform to signer failed")?;
        signer
            .update(plaintext)
            .context("ec update plaintext failed")?;

        Ok(signer.sign_to_vec().context("ec signer sign failed")?)
    }

    fn verify(
        &self,
        pub_key: &[u8],
        plaintext: &[u8],
        signature: &[u8],
        e: EncryptoAdaptor,
    ) -> Result<bool> {
        let pkey =
            pkey::PKey::public_key_from_der(pub_key).context("import")?;
        let mut verifier = sign::Verifier::new(e.md.unwrap(), &pkey)
            .context("import public key to ec pkey failed")?;
        verifier
            .update(plaintext)
            .context("ec verifier update plaintext failed")?;
        Ok(verifier
            .verify(signature)
            .context("ec verifier veirify failed")?)
    }

    fn encrypt(
        &self,
        pub_key: &[u8],
        plaintext: &[u8],
        _e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        let pkey_encrypter = pkey::PKey::public_key_from_der(pub_key)
            .context("import ec public key transform to pkey faield")?;
        let encrypter = encrypt::Encrypter::new(&pkey_encrypter)
            .context("pkey tansform to decrypter failed")?;
        let mut to = vec![
            0;
            encrypter
                .encrypt_len(plaintext)
                .context("compute ec encrpt size failed")?
        ];
        let encrypt_len = encrypter
            .encrypt(plaintext, &mut to)
            .context("ec encrypter encrypt failed")?;
        to.truncate(encrypt_len);
        Ok(to)
    }

    fn decrypt(
        &self,
        private_key: &[u8],
        cipher: &[u8],
        _e: EncryptoAdaptor,
    ) -> Result<Vec<u8>> {
        let pkey_decrypter = pkey::PKey::private_key_from_pkcs8(private_key)
            .context("import ec key pkcs8 transform to pkey faield")?;
        let decrypter = encrypt::Decrypter::new(&pkey_decrypter)
            .context("pkey tansform to ec decrypter failed")?;
        let mut to = vec![
            0;
            decrypter.decrypt_len(cipher).context(
                "compute ec decrypt buffer size failed"
            )?
        ];
        let decrypt_len = decrypter
            .decrypt(cipher, &mut to)
            .context("ec decrypter decrypt failed")?;
        to.truncate(decrypt_len);
        Ok(to)
    }
}

#[cfg(test)]

mod tests {
    use super::EcAlgorithmFactory;
    use crate::common::{
        encrypto::{
            algorithm::{self, KeyAlgorithmFactory},
            types::{WrappingKeyAlgorithm, WrappingKeySpec},
        },
        utils,
    };

    #[test]
    fn test_encrypt_decrypt_sm2() {
        let ec_f = EcAlgorithmFactory {};

        let (private, public) =
            algorithm::generate_wrapping_key(WrappingKeySpec::EcSm2).unwrap();

        println!(
            "private: {}, public: {}",
            utils::encode64(&private),
            utils::encode64(&public)
        );

        let cipher = ec_f
            .encrypt(&public, b"plaintext", WrappingKeyAlgorithm::SM2PKE.into())
            .unwrap();

        println!("cipher: {}", utils::encode64(&cipher));
        assert_eq!(
            ec_f.decrypt(
                &private,
                &cipher,
                WrappingKeyAlgorithm::SM2PKE.into()
            )
            .unwrap(),
            b"plaintext"
        );
    }
}
