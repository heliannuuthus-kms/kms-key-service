use actix_web::error::ErrorBadRequest;
use anyhow::Context;
use ring::{
    aead::AES_256_GCM,
    rand::{SecureRandom, SystemRandom},
};

use crate::{
    common::{
        datasource::{tx_begin, tx_commit},
        enums::KeyType,
        errors::{Result, ServiceError},
        utils::{encode64, gen_id},
    },
    pojo::po::secret::{Secret, SecretMeta},
    repository::secret_repository,
};

pub async fn create_secret(
    secret: &mut Secret,
    secret_meta: &mut SecretMeta,
) -> Result<()> {
    let mut tx = tx_begin("create secret").await?;
    match &secret.key_type {
        KeyType::Symmetric => {
            let rand = SystemRandom::new();
            let mut key_bytes = vec![0; AES_256_GCM.key_len()];
            rand.fill(&mut key_bytes).unwrap();
            let encoded = encode64(&key_bytes);
            secret.key_pair = encoded;
            secret_repository::insert_symmetric_secret(&mut tx, &secret)
                .await?;
        }
        KeyType::Asymmetric => {
          
        }
        _ => {
            return Err(ServiceError::Reponse(ErrorBadRequest(
                "unknown key type",
            )))
        }
    };
    secret_repository::insert_secret_meta(&mut tx, &secret_meta).await?;
    tx_commit(tx, "create secret").await?;
    Ok(())
}