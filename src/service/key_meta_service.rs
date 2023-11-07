use std::collections::HashMap;

use chrono::Duration;
use lazy_static::lazy_static;
use moka::future::Cache;
use sea_orm::DbConn;

use crate::{
    common::errors::{Result, ServiceError},
    entity::{self},
    repository::key_repository,
};

lazy_static! {
    pub static ref KEY_VERSION_META_CACHE: Cache<String, HashMap<String, entity::key_meta::Model>> =
        moka::future::CacheBuilder::new(64 * 1024 * 1024)
            .name("key_meta_version_cache")
            .time_to_idle(Duration::minutes(5).to_std().unwrap())
            .time_to_live(Duration::minutes(30).to_std().unwrap())
            .build();
}

pub async fn save_key_meta(
    db: &DbConn,
    model: &entity::key_meta::Model,
) -> Result<()> {
    key_repository::insert_key_meta(db, model).await?;
    KEY_VERSION_META_CACHE
        .remove(&format!("kms:keys:key_meta_version:{}", model.version))
        .await;

    Ok(())
}

pub async fn get_version_key_meta(
    db: &DbConn,
    key_id: &str,
    version: &str,
) -> Result<entity::key_meta::Model> {
    let version_metas = get_key_metas(db, key_id).await?;

    Ok(version_metas
        .get(version)
        .ok_or(ServiceError::NotFount(format!(
            "key_id is invalid, key_id: {}",
            key_id
        )))?
        .clone())
}

pub async fn get_key_metas(
    db: &DbConn,
    key_id: &str,
) -> Result<HashMap<String, entity::key_meta::Model>> {
    let version_metas_cache_id =
        format!("kms:keys:key_meta_version:{}", key_id);

    if let Some(version_metas) =
        KEY_VERSION_META_CACHE.get(&version_metas_cache_id).await
    {
        Ok(version_metas)
    } else {
        let version_metas = key_repository::select_key_metas(db, key_id)
            .await?
            .into_iter()
            .map(|model| (model.version.to_owned(), model))
            .collect::<HashMap<String, entity::key_meta::Model>>();
        KEY_VERSION_META_CACHE
            .insert(version_metas_cache_id, version_metas.clone())
            .await;
        Ok(version_metas)
    }
}
