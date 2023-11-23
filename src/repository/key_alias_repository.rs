use anyhow::Context;
use itertools::Itertools;
use sea_orm::{
    sea_query::OnConflict, ActiveValue::NotSet, ColumnTrait, ConnectionTrait,
    EntityTrait, IntoActiveModel, QueryFilter, QuerySelect,
};

use crate::{
    common::{datasource, datasource::Paginator, errors::Result},
    entity::prelude::*,
    pagin,
};

pub async fn select_alias<C: ConnectionTrait>(
    db: &C,
    alias: &str,
) -> Result<Option<KeyAliasModel>> {
    Ok(KeyAliasEntity::find()
        .filter(KeyAliasColumn::Alias.eq(alias))
        .one(db)
        .await?)
}

pub async fn select_key_aliases<C: ConnectionTrait>(
    db: &C,
    key_id: &str,
) -> Result<Vec<KeyAliasModel>> {
    Ok(KeyAliasEntity::find()
        .filter(KeyAliasColumn::KeyId.eq(key_id))
        .all(db)
        .await?)
}

pub async fn set_key_alias<C: ConnectionTrait>(
    db: &C,
    model: KeyAliasModel,
) -> Result<()> {
    let mut active = model.into_active_model();
    active.created_at = NotSet;
    active.updated_at = NotSet;
    KeyAliasEntity::insert(active)
        .on_conflict(
            OnConflict::column(KeyAliasColumn::Alias)
                .update_column(KeyAliasColumn::KeyId)
                .to_owned(),
        )
        .exec(db)
        .await?;
    Ok(())
}

pub async fn delete_key_aliases<C: ConnectionTrait>(
    db: &C,
    key_id: &str,
    alias: Vec<String>,
) -> Result<()> {
    let mut se = KeyAliasColumn::KeyId.contains(key_id);

    if !alias.is_empty() {
        se = se.and(KeyAliasColumn::Alias.is_in(alias))
    };
    KeyAliasEntity::delete_many()
        .filter(se)
        .exec(db)
        .await
        .context(format!("delete key alias failed, key_id: {}", key_id))?;
    Ok(())
}

pub async fn pagin_key_alias<C: ConnectionTrait>(
    db: &C,
    key_id: &str,
    paginator: Paginator,
) -> Result<Vec<KeyAliasModel>> {
    pagin!(
        db,
        paginator,
        KeyAliasEntity::find().cursor_by(KeyMetaColumn::Id),
        format!("pagin key aliases failed, key_id: {}", key_id)
    )
}
