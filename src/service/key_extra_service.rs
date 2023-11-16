use std::collections::HashMap;

use chrono::Duration;
use lazy_static::lazy_static;
use moka::future::Cache;
use sea_orm::DbConn;

use super::key_service::{self, ALIAS_KEY_CACHE};
use crate::{
    common::{
        configs::env_var_default,
        datasource::{self, PaginatedResult, Paginator},
        errors::{Result, ServiceError},
    },
    entity::prelude::*,
    paginated_result,
    repository::{key_extra_repository, key_repository},
};

lazy_static! {
    pub static ref KEY_VERSION_META_CACHE: Cache<String, HashMap<String, KeyMetaModel>> =
        moka::future::CacheBuilder::new(64 * 1024 * 1024)
            .name("key_meta_version_cache")
            .time_to_idle(Duration::minutes(5).to_std().unwrap())
            .time_to_live(Duration::minutes(30).to_std().unwrap())
            .build();
    pub static ref KEY_ALIAS_CACHE: Cache<String, Vec<KeyAliasModel>> =
        moka::future::CacheBuilder::new(64 * 1024 * 1024)
            .name("key_alias_cache")
            .time_to_idle(Duration::minutes(5).to_std().unwrap())
            .time_to_live(Duration::minutes(30).to_std().unwrap())
            .build();
}

pub async fn set_key_meta(db: &DbConn, model: &KeyMetaModel) -> Result<()> {
    key_extra_repository::insert_or_update_key_meta(db, model).await?;
    KEY_VERSION_META_CACHE
        .remove(&format!("kms:keys:key_meta_version:{}", model.version))
        .await;
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

pub async fn get_aliases(
    db: &DbConn,
    key_id: &str,
) -> Result<Vec<KeyAliasModel>> {
    let key_alias_cache_key = format!("kms:keys:key_alias:{}", key_id);
    Ok(
        if let Some(r) = KEY_ALIAS_CACHE.get(&key_alias_cache_key).await {
            r
        } else {
            let aliaes =
                key_extra_repository::select_key_aliases(db, key_id).await?;
            KEY_ALIAS_CACHE
                .insert(key_alias_cache_key, aliaes.clone())
                .await;
            aliaes
        },
    )
}

pub async fn set_alias(db: &DbConn, key_id: &str, alias: &str) -> Result<()> {
    let _main_key = key_service::get_main_key(db, key_id).await?;
    let aliases = get_aliases(db, key_id).await?;
    let limit = env_var_default::<usize>("KEY_ALIAS_LIMIT", 5);
    if aliases.len() >= limit {
        Err(ServiceError::BadRequest(format!(
            "alias reached the upper limit, key_id: {}",
            key_id
        )))
    } else {
        key_extra_repository::set_key_alias(db, &KeyAliasModel {
            key_id: key_id.to_owned(),
            alias: alias.to_owned(),
            ..Default::default()
        })
        .await?;
        ALIAS_KEY_CACHE
            .remove(&format!("kms:keys:alias_key:{}", alias))
            .await;
        KEY_ALIAS_CACHE
            .remove(&format!("kms:keys:key_alias:{}", key_id))
            .await;
        Ok(())
    }
}

pub async fn remove_key_aliases(
    db: &DbConn,
    key_id: &str,
    aliases: Vec<String>,
) -> Result<()> {
    key_extra_repository::delete_key_aliases(db, key_id, aliases).await?;
    Ok(())
}

pub async fn list_key_aliases(
    db: &DbConn,
    key_id: &str,
    paginator: Paginator,
) -> Result<PaginatedResult<Vec<KeyAliasModel>>> {
    let mut result =
        key_extra_repository::pagin_key_alias(db, key_id, paginator.clone())
            .await?;

    paginated_result!(result, paginator.limit.unwrap_or(10))
}
