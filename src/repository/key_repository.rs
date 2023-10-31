use chrono::Duration;
use lazy_static::lazy_static;
use moka::future::Cache;
use sea_orm::*;

use crate::{
    common::errors::Result,
    entity::{self, kms, prelude::*},
};

pub async fn insert_key<C: ConnectionTrait>(
    db: &C,
    model: &entity::key::Model,
) -> Result<()> {
    Secret::insert(model.clone().into_active_model())
        .exec(db)
        .await?;
    Ok(())
}

pub async fn insert_key_meta<C: ConnectionTrait>(
    db: &C,
    model: &entity::key_meta::Model,
) -> Result<()> {
    SecretMeta::insert(model.clone().into_active_model())
        .exec(db)
        .await?;

    Ok(())
}

pub async fn select_key<C: ConnectionTrait>(
    db: &C,
    key_id: &str,
) -> Result<Option<entity::key::Model>> {
    Ok(Secret::find()
        .filter(entity::key::Column::KeyId.eq(key_id))
        .one(db)
        .await?)
}

pub async fn select_kms_keys<C: ConnectionTrait>(
    db: &C,
    kms_id: &str,
) -> Result<Vec<entity::key::Model>> {
    Ok(Secret::find()
        .filter(entity::key::Column::KmsId.eq(kms_id))
        .all(db)
        .await?)
}

pub async fn select_key_meta<C: ConnectionTrait>(
    db: &C,
    key_id: &str,
) -> Result<Option<entity::key_meta::Model>> {
    Ok(SecretMeta::find()
        .filter(entity::key_meta::Column::KeyId.eq(key_id))
        .one(db)
        .await?)
}
