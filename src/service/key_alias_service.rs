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
    repository::key_alias_repository,
};

lazy_static! {
    pub static ref KEY_ALIAS_CACHE: Cache<String, Vec<KeyAliasModel>> =
        moka::future::CacheBuilder::new(64 * 1024 * 1024)
            .name("key_alias_cache")
            .time_to_idle(Duration::minutes(5).to_std().unwrap())
            .time_to_live(Duration::minutes(30).to_std().unwrap())
            .build();
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
                key_alias_repository::select_key_aliases(db, key_id).await?;
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
        key_alias_repository::set_key_alias(db, KeyAliasModel {
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
    key_alias_repository::delete_key_aliases(db, key_id, aliases).await?;
    Ok(())
}

pub async fn list_key_aliases(
    db: &DbConn,
    key_id: &str,
    paginator: Paginator,
) -> Result<PaginatedResult<Vec<KeyAliasModel>>> {
    let mut result =
        key_alias_repository::pagin_key_alias(db, key_id, paginator.clone())
            .await?;

    paginated_result!(result, paginator.limit.unwrap_or(10))
}
