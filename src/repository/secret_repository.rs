use chrono::Duration;
use lazy_static::lazy_static;
use moka::future::Cache;
use sea_orm::*;

use crate::{
    common::errors::Result,
    entity::{
        t_secret::{self as TSecret},
        t_secret_meta::{self as TSecretMeta},
    },
};

lazy_static! {
    static ref SECRET_META_CACHE: Cache<String, TSecretMeta::Model> =
        moka::future::CacheBuilder::new(64 * 1024 * 1024)
            .name("secret_meta_cache")
            .time_to_idle(Duration::minutes(30).to_std().unwrap())
            .time_to_live(Duration::days(1).to_std().unwrap())
            .build();
}

pub async fn insert_secret<C: ConnectionTrait>(
    db: &C,
    model: &TSecret::Model,
) -> Result<()> {
    TSecret::Entity::insert(model.clone().into_active_model())
        .exec(db)
        .await?;
    Ok(())
}

pub async fn insert_secret_meta<C: ConnectionTrait>(
    db: &C,
    model: &TSecretMeta::Model,
) -> Result<()> {
    TSecretMeta::Entity::insert(model.clone().into_active_model())
        .exec(db)
        .await?;

    SECRET_META_CACHE
        .insert(model.key_id.to_owned(), model.clone())
        .await;

    Ok(())
}

pub async fn select_secret<C: ConnectionTrait>(
    db: &C,
    key_id: &str,
) -> Result<Option<TSecret::Model>> {
    Ok(TSecret::Entity::find()
        .filter(TSecret::Column::KeyId.eq(key_id))
        .one(db)
        .await?)
}

pub async fn select_secret_meta<C: ConnectionTrait>(
    db: &C,
    key_id: &str,
) -> Result<Option<TSecretMeta::Model>> {
    Ok(match SECRET_META_CACHE.get(key_id).await {
        Some(secret_meta) => Some(secret_meta),
        None => {
            TSecretMeta::Entity::find()
                .filter(TSecretMeta::Column::KeyId.eq(key_id))
                .one(db)
                .await?
        }
    })
}
