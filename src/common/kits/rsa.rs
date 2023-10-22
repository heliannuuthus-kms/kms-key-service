use anyhow::{anyhow, Context};
use openssl::{encrypt, hash, pkey, rsa, sign};

use crate::common::{
    errors::{Result, ServiceError},
    utils::{self},
};

pub fn sign(
    pri_key: &str,
    from: &[u8],
    message_digest: hash::MessageDigest,
) -> Result<Vec<u8>> {
    let pkey = pkey::PKey::private_key_from_der(&utils::decode64(pri_key)?)
        .context("rsa sign key `der` to pkey failed")?;
    let mut signer = sign::Signer::new(message_digest, &pkey)
        .with_context(|| "rsa signer create failed")?;
    let _buf: Vec<u8> = vec![0; pkey.size() as usize];
    signer
        .update(from)
        .context("rsa signer update sign content failed")?;
    Ok(signer.sign_to_vec().context("rsa signer sign failed")?)
}

pub fn verify(
    pub_key: &str,
    from: &[u8],
    signature: &[u8],
    message_digest: hash::MessageDigest,
) -> Result<bool> {
    let pkey = pkey::PKey::public_key_from_der(&utils::decode64(pub_key)?)
        .with_context(|| ServiceError::InternalServer(anyhow!("")))?;

    let mut verifier = sign::Verifier::new(message_digest, &pkey).context(
        ServiceError::InternalServer(anyhow!("pkey tansform verifer failed")),
    )?;
    let _buf: Vec<u8> = vec![0; pkey.size() as usize];
    verifier
        .update(from)
        .context(ServiceError::InternalServer(anyhow!(
            "rsa verifier update plaintext failed"
        )))?;
    Ok(verifier
        .verify(signature)
        .context(ServiceError::InternalServer(anyhow!("rsa verfier error")))?)
}

pub fn encrypt(
    pub_key: &str,
    from: &[u8],
    padding: rsa::Padding,
    message_digest: hash::MessageDigest,
) -> Result<Vec<u8>> {
    let rsa_key_pair =
        rsa::Rsa::public_key_from_der(&utils::decode64(pub_key)?)
            .with_context(|| {
                ServiceError::InternalServer(anyhow!("load key faield"))
            })?;
    let pkey_encryptor = pkey::PKey::from_rsa(rsa_key_pair.clone())
        .with_context(|| {
            ServiceError::InternalServer(anyhow!("key transform faield"))
        })?;
    let mut encryptor =
        encrypt::Encrypter::new(&pkey_encryptor).with_context(|| {
            ServiceError::InternalServer(anyhow!(
                "pkey tansform decrypter failed"
            ))
        })?;
    encryptor.set_rsa_padding(padding).with_context(|| {
        ServiceError::InternalServer(anyhow!(
            "decrypter set rsa padding failed"
        ))
    })?;
    match padding {
        rsa::Padding::PKCS1 => {}
        rsa::Padding::PKCS1_OAEP => {
            encryptor.set_rsa_oaep_md(message_digest).with_context(|| {
                ServiceError::InternalServer(anyhow!(
                    "decrypter set rsa md failed"
                ))
            })?;
        }
        rsa::Padding::PKCS1_PSS => {}
        _ => {}
    };
    let mut buf: Vec<u8> = vec![0; rsa_key_pair.size() as usize];
    encryptor.encrypt(from, &mut buf).with_context(|| {
        ServiceError::BadRequest("decrypt material failed".to_string())
    })?;

    Ok(buf.to_vec())
}

pub fn decrypt(
    private_key: &str,
    from: &[u8],
    padding: rsa::Padding,
    message_digest: hash::MessageDigest,
) -> Result<Vec<u8>> {
    let rsa_key_pair =
        rsa::Rsa::private_key_from_der(&utils::decode64(private_key)?)
            .with_context(|| {
                ServiceError::InternalServer(anyhow!("load key faield"))
            })?;
    let pkey_decryptor = pkey::PKey::from_rsa(rsa_key_pair.clone())
        .with_context(|| {
            ServiceError::InternalServer(anyhow!("key transform faield"))
        })?;
    let mut decryptor =
        encrypt::Decrypter::new(&pkey_decryptor).with_context(|| {
            ServiceError::InternalServer(anyhow!(
                "pkey tansform decrypter failed"
            ))
        })?;
    decryptor.set_rsa_padding(padding).with_context(|| {
        ServiceError::InternalServer(anyhow!(
            "decrypter set rsa padding failed"
        ))
    })?;
    match padding {
        rsa::Padding::PKCS1 => {}
        rsa::Padding::PKCS1_OAEP => {
            decryptor.set_rsa_oaep_md(message_digest).with_context(|| {
                ServiceError::InternalServer(anyhow!(
                    "decrypter set rsa md failed"
                ))
            })?;
        }
        rsa::Padding::PKCS1_PSS => {}
        _ => {}
    };
    let mut buf: Vec<u8> = vec![0; rsa_key_pair.size() as usize];
    decryptor.decrypt(from, &mut buf).with_context(|| {
        ServiceError::BadRequest("decrypt material failed".to_string())
    })?;
    Ok(buf.to_vec())
}
