use anyhow::Context;
use sea_orm::{sea_query::OnConflict, *};

use crate::{
    common::{
        datasource::{self, Paginator},
        errors::Result,
    },
    entity::prelude::*,
};

pub async fn insert_key<C: ConnectionTrait>(
    db: &C,
    model: &KeyModel,
) -> Result<()> {
    KeyEntity::insert(model.clone().into_active_model())
        .exec(db)
        .await?;
    Ok(())
}

pub async fn update_key<C: ConnectionTrait>(
    db: &C,
    active_model: &KeyActiveModel,
) -> Result<()> {
    active_model.clone().update(db).await.context(format!(
        "update key failed, key_id: {}",
        active_model.key_id.as_ref()
    ))?;

    Ok(())
}

pub async fn insert_or_update_key_meta<C: ConnectionTrait>(
    db: &C,
    model: &KeyMetaModel,
) -> Result<()> {
    KeyMetaEntity::insert(model.clone().into_active_model())
        .on_conflict(
            OnConflict::columns([KeyMetaColumn::KeyId, KeyMetaColumn::Version])
                .update_column(KeyMetaColumn::Description)
                .to_owned(),
        )
        .exec(db)
        .await?;

    Ok(())
}

pub async fn select_kms_key_ids<C: ConnectionTrait>(
    db: &C,
    kms_id: &str,
) -> Result<Vec<KeyModel>> {
    Ok(KeyEntity::find()
        .filter(KeyColumn::KmsId.eq(kms_id))
        .select_only()
        .columns([KeyColumn::KmsId, KeyColumn::KeyId])
        .all(db)
        .await?)
}

pub async fn select_key<C: ConnectionTrait>(
    db: &C,
    key_id: &str,
) -> Result<Vec<KeyModel>> {
    Ok(KeyEntity::find()
        .filter(KeyColumn::KeyId.eq(key_id))
        .all(db)
        .await?)
}

pub async fn select_key_metas<C: ConnectionTrait>(
    db: &C,
    key_id: &str,
) -> Result<Vec<KeyMetaModel>> {
    Ok(KeyMetaEntity::find()
        .filter(KeyMetaColumn::KeyId.eq(key_id))
        .all(db)
        .await?)
}

pub async fn select_key_alias<C: ConnectionTrait>(
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
    model: &KeyAliasModel,
) -> Result<()> {
    KeyAliasEntity::insert(model.clone().into_active_model())
        .on_conflict(
            OnConflict::columns([KeyAliasColumn::Alias, KeyAliasColumn::KeyId])
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
    KeyAliasEntity::delete_many().filter(se).exec(db).await?;
    Ok(())
}

pub async fn pagin_key_alias<C: ConnectionTrait>(
    db: &C,
    paginator: Paginator,
) -> Result<Vec<KeyAliasModel>> {
    let mut cursor = KeyAliasEntity::find()
        .select_only()
        .columns([
            KeyAliasColumn::Id,
            KeyAliasColumn::KeyId,
            KeyAliasColumn::Alias,
            KeyAliasColumn::CreatedAt,
        ])
        .cursor_by(KeyAliasColumn::Id);

    if let Some(next) = paginator.next {
        let id = datasource::from_next(&next)?;
        cursor.after(id - 1);
    };

    Ok(cursor
        .first(paginator.limit.unwrap_or(10) + 1)
        .all(db)
        .await?)
}
