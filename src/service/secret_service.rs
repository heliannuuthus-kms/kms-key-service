use std::{ops::DerefMut, sync::Arc};

use sea_orm::*;
use tokio::{sync::Mutex, try_join};

use crate::{
    common::{
        self,
        algorithm::KeyOrigin,
        datasource::{self},
        errors::{Result, ServiceError},
    },
    entity::{
        prelude::{Secret, SecretMeta},
        t_secret as TSecret, t_secret_meta as TSecretMeta,
    },
    pojo::form::secret,
    repository::secret_repository,
};

pub async fn create_secret(
    db: &DbConn,
    secret: &TSecret::Model,
    secret_meta: &TSecretMeta::Model,
) -> Result<String> {
    if KeyOrigin::Kms.eq(&secret_meta.origin) {
        secret_repository::insert_secret(db, secret).await?;
    };
    secret_repository::insert_secret_meta(db, secret_meta).await?;
    Ok(secret_meta.key_id.to_owned())
}

pub async fn import_secret_meta(db: &DbConn, key_id: &str) -> Result<()> {
    
}
