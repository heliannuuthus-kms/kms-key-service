use anyhow::Context;
use sea_orm::*;

use crate::{
    common::{
        datasource::{self, Paginator},
        errors::Result,
    },
    entity::prelude::*,
    pagin,
};

pub async fn batch_insert_key<C: ConnectionTrait>(
    db: &C,
    models: Vec<KeyModel>,
) -> Result<()> {
    tracing::debug!("print insert many: {:?}", models);
    KeyEntity::insert_many(models.into_iter().map(KeyModel::into_active_model))
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

pub async fn pagin_key_version<C: ConnectionTrait>(
    db: &C,
    key_id: &str,
    paginator: &Paginator,
) -> Result<Vec<KeyMetaModel>> {
    pagin!(
        db,
        paginator,
        KeyMetaEntity::find()
            .columns([
                KeyMetaColumn::Id,
                KeyMetaColumn::KeyId,
                KeyMetaColumn::Version,
                KeyMetaColumn::PrimaryVersion,
                KeyMetaColumn::CreatedAt,
            ])
            .cursor_by(KeyMetaColumn::Id),
        format!("pagin key version failed, key_id: {}", key_id)
    )
}

pub async fn pagin_kms_keys<C: ConnectionTrait>(
    db: &C,
    kms_id: &str,
    paginator: &Paginator,
) -> Result<Vec<KeyModel>> {
    pagin!(
        db,
        paginator,
        KeyEntity::find()
            .select_only()
            .columns([
                KeyColumn::Id,
                KeyColumn::KeyId,
                KeyColumn::KmsId,
                KeyColumn::Version,
                KeyColumn::UpdatedAt,
                KeyColumn::CreatedAt
            ])
            .filter(KeyColumn::KmsId.eq(kms_id))
            .cursor_by(KeyColumn::Id),
        format!("pagin kms keys failed, kms_id: {}", kms_id)
    )
}
