use anyhow::Context;
use sea_orm::*;

use crate::{common::errors::Result, entity::prelude::*};

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

pub async fn insert_key_meta<C: ConnectionTrait>(
    db: &C,
    model: &KeyMetaModel,
) -> Result<()> {
    KeyMetaEntity::insert(model.clone().into_active_model())
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