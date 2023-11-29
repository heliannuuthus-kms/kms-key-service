use sea_orm::DbConn;

use super::key_service::{self};
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

pub async fn get_aliases(
    db: &DbConn,
    key_id: &str,
) -> Result<Vec<KeyAliasModel>> {
    key_alias_repository::select_key_aliases(db, key_id).await
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
