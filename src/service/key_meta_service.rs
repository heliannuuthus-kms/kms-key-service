use std::collections::HashMap;

use chrono::Duration;
use lazy_static::lazy_static;
use moka::future::Cache;
use sea_orm::DbConn;

use crate::{
    common::errors::{Result, ServiceError},
    crypto::types::KEY_STATE_MAP,
    entity::prelude::*,
    pojo::form::key_extra::KeyChangeStateBody,
    repository::{key_meta_repository, key_repository},
};

lazy_static! {
    pub static ref KEY_VERSION_META_CACHE: Cache<String, HashMap<String, KeyMetaModel>> =
        moka::future::CacheBuilder::new(64 * 1024 * 1024)
            .name("key_meta_version_cache")
            .time_to_idle(Duration::minutes(5).to_std().unwrap())
            .time_to_live(Duration::minutes(30).to_std().unwrap())
            .build();
}

pub async fn change_state(
    db: &DbConn,
    body: &KeyChangeStateBody,
) -> Result<KeyMetaModel> {
    // 待加分布式锁 redis rslock
    let mut meta = get_main_key_meta(db, &body.key_id).await?;
    if !meta.state.eq(&body.from) {
        return Err(ServiceError::Unsupported(format!(
            "current key state is {:?}",
            meta.state
        )));
    }
    if !KEY_STATE_MAP[meta.state as usize][body.to as usize] {
        return Err(ServiceError::BadRequest(format!(
            "key state can`t change, from {:?} to {:?}",
            meta.state, body.to
        )));
    }
    meta.state = body.to;
    set_key_meta(db, meta.clone()).await?;
    Ok(meta)
}

pub async fn set_key_meta(db: &DbConn, model: KeyMetaModel) -> Result<()> {
    batch_set_key_meta(db, vec![model]).await?;
    Ok(())
}

pub async fn batch_set_key_meta(
    db: &DbConn,
    models: Vec<KeyMetaModel>,
) -> Result<()> {
    key_meta_repository::insert_or_update_key_metas(db, models.clone()).await?;
    for model in models {
        KEY_VERSION_META_CACHE
            .remove(&format!("kms:keys:key_meta_version:{}", model.version))
            .await;
    }
    Ok(())
}

pub async fn get_main_key_meta(
    db: &DbConn,
    key_id: &str,
) -> Result<KeyMetaModel> {
    get_key_metas(db, key_id)
        .await?
        .into_iter()
        .filter_map(|(version, meta)| {
            if version.eq(&meta.primary_version) {
                Some(meta)
            } else {
                None
            }
        })
        .next()
        .ok_or(ServiceError::NotFount(format!(
            "key_id is invalid, key_id: {}",
            key_id
        )))
}

pub async fn get_version_key_meta(
    db: &DbConn,
    key_id: &str,
    version: &str,
) -> Result<KeyMetaModel> {
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
) -> Result<HashMap<String, KeyMetaModel>> {
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
            .collect::<HashMap<String, KeyMetaModel>>();
        KEY_VERSION_META_CACHE
            .insert(version_metas_cache_id, version_metas.clone())
            .await;
        Ok(version_metas)
    }
}
