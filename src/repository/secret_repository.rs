use sea_orm::*;

use crate::{
    common::errors::Result,
    entity::{
        t_secret::{self as TSecret},
        t_secret_meta::{self as TSecretMeta},
    },
};

pub async fn insert_secret(db: &DbConn, model: &TSecret::Model) -> Result<()> {
    TSecret::Entity::insert(model.clone().into_active_model())
        .exec(db)
        .await?;
    Ok(())
}

pub async fn insert_secret_meta(
    db: &DbConn,
    model: &TSecretMeta::Model,
) -> Result<()> {
    TSecretMeta::Entity::insert(model.clone().into_active_model())
        .exec(db)
        .await?;
    Ok(())
}

pub async fn select_secret(
    db: &DbConn,
    key_id: &str,
) -> Result<Option<TSecret::Model>> {
    Ok(TSecret::Entity::find()
        .filter(TSecret::Column::KeyId.eq(key_id))
        .one(db)
        .await?)
}

pub async fn select_secret_meta(
    db: &DbConn,
    key_id: &str,
) -> Result<Option<TSecretMeta::Model>> {
    Ok(TSecretMeta::Entity::find()
        .filter(TSecretMeta::Column::KeyId.eq(key_id))
        .one(db)
        .await?)
}
