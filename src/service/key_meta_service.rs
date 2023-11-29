use chrono::Duration;
use itertools::Itertools;
use lazy_static::lazy_static;
use moka::future::Cache;
use sea_orm::DbConn;

use crate::{
    common::errors::{Result, ServiceError},
    crypto::types::KEY_STATE_MAP,
    encode_key,
    entity::prelude::*,
    pojo::form::key_extra::KeyChangeStateBody,
    repository::{key_meta_repository, key_repository},
};

pub const KEY_META_CACHE_KEY: &str = "key_meta_cache";

lazy_static! {
    pub static ref KEY_META_CACHE: Cache<String, Vec<KeyMetaModel>> =
        moka::future::CacheBuilder::new(64 * 1024 * 1024)
            .name(KEY_META_CACHE_KEY)
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
    for key_id in models.into_iter().map(|model| model.key_id).unique() {
        KEY_META_CACHE
            .remove(&encode_key!(KEY_META_CACHE_KEY, key_id))
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
        .filter_map(|meta| {
            if meta.version.eq(&meta.primary_version) {
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
    get_key_metas(db, key_id)
        .await?
        .into_iter()
        .find(|model| model.version.eq(version))
        .ok_or(ServiceError::NotFount(format!(
            "key_id is invalid, key_id: {}",
            key_id
        )))
}

pub async fn get_key_metas(
    db: &DbConn,
    key_id: &str,
) -> Result<Vec<KeyMetaModel>> {
    let cache_key = encode_key!(KEY_META_CACHE_KEY, key_id);
    if let Some(version_metas) = KEY_META_CACHE.get(&cache_key).await {
        Ok(version_metas)
    } else {
        let version_metas =
            key_repository::select_key_metas(db, key_id).await?;
        KEY_META_CACHE
            .insert(
                encode_key!(KEY_META_CACHE_KEY, key_id),
                version_metas.clone(),
            )
            .await;
        Ok(version_metas)
    }
}
