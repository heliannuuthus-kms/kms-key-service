use anyhow::{anyhow, Context};
use openssl::{hash, rsa};

use crate::common::{
    errors::{Result, ServiceError},
    utils::{self},
};

pub fn sign(
    pri_key: &str,
    from: &[u8],
    padding: rsa::Padding,
    message_digest: hash::MessageDigest,
) -> Result<Vec<u8>> {
    let pkey =
        openssl::pkey::PKey::private_key_from_der(&utils::decode64(pri_key)?)
            .with_context(|| {
            ServiceError::Internal(anyhow!("key transform faield"))
        })?;

    let mut signer = openssl::sign::Signer::new(message_digest, &pkey)
        .context(ServiceError::Internal(anyhow!(
            "pkey tansform singer failed"
        )))?;
    signer
        .set_rsa_padding(padding)
        .context(ServiceError::Internal(anyhow!(
            "rsa signer set padding failed"
        )))?;
    let _buf: Vec<u8> = vec![0; pkey.size() as usize];
    signer.update(from).context(ServiceError::Internal(anyhow!(
        "rsa signer update plaintext failed"
    )))?;
    Ok(signer
        .sign_to_vec()
        .context(ServiceError::Internal(anyhow!("rsa sign error")))?)
}

pub fn verify(
    pub_key: &str,
    from: &[u8],
    signature: &[u8],
    padding: rsa::Padding,
    message_digest: hash::MessageDigest,
) -> Result<bool> {
    let pkey =
        openssl::pkey::PKey::public_key_from_der(&utils::decode64(pub_key)?)
            .with_context(|| {
                ServiceError::Internal(anyhow!("key transform faield"))
            })?;

    let mut verifier = openssl::sign::Verifier::new(message_digest, &pkey)
        .context(ServiceError::Internal(anyhow!(
            "pkey tansform verifer failed"
        )))?;
    verifier
        .set_rsa_padding(padding)
        .context(ServiceError::Internal(anyhow!(
            "rsa verfier set padding failed"
        )))?;
    let _buf: Vec<u8> = vec![0; pkey.size() as usize];
    verifier
        .update(from)
        .context(ServiceError::Internal(anyhow!(
            "rsa verifier update plaintext failed"
        )))?;
    Ok(verifier
        .verify(signature)
        .context(ServiceError::Internal(anyhow!("rsa verfier error")))?)
}

pub fn encrypt(
    pub_key: &str,
    from: &[u8],
    padding: rsa::Padding,
    message_digest: hash::MessageDigest,
) -> Result<Vec<u8>> {
    let rsa_key_pair =
        openssl::rsa::Rsa::public_key_from_der(&utils::decode64(pub_key)?)
            .with_context(|| {
                ServiceError::Internal(anyhow!("load key faield"))
            })?;
    let pkey_encryptor = openssl::pkey::PKey::from_rsa(rsa_key_pair.clone())
        .with_context(|| {
            ServiceError::Internal(anyhow!("key transform faield"))
        })?;
    let mut encryptor = openssl::encrypt::Encrypter::new(&pkey_encryptor)
        .with_context(|| {
            ServiceError::Internal(anyhow!("pkey tansform decrypter failed"))
        })?;
    encryptor.set_rsa_padding(padding).with_context(|| {
        ServiceError::Internal(anyhow!("decrypter set rsa padding failed"))
    })?;
    match padding {
        rsa::Padding::PKCS1 => {}
        rsa::Padding::PKCS1_OAEP => {
            encryptor.set_rsa_oaep_md(message_digest).with_context(|| {
                ServiceError::Internal(anyhow!("decrypter set rsa md failed"))
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
        openssl::rsa::Rsa::private_key_from_der(&utils::decode64(private_key)?)
            .with_context(|| {
                ServiceError::Internal(anyhow!("load key faield"))
            })?;
    let pkey_decryptor = openssl::pkey::PKey::from_rsa(rsa_key_pair.clone())
        .with_context(|| {
            ServiceError::Internal(anyhow!("key transform faield"))
        })?;
    let mut decryptor = openssl::encrypt::Decrypter::new(&pkey_decryptor)
        .with_context(|| {
            ServiceError::Internal(anyhow!("pkey tansform decrypter failed"))
        })?;
    decryptor.set_rsa_padding(padding).with_context(|| {
        ServiceError::Internal(anyhow!("decrypter set rsa padding failed"))
    })?;
    match padding {
        rsa::Padding::PKCS1 => {}
        rsa::Padding::PKCS1_OAEP => {
            decryptor.set_rsa_oaep_md(message_digest).with_context(|| {
                ServiceError::Internal(anyhow!("decrypter set rsa md failed"))
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
