use sea_orm::*;

use crate::{
    common::{errors::Result, kits::algorithm::KeyOrigin},
    entity::{t_secret as TSecret, t_secret_meta as TSecretMeta},
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
