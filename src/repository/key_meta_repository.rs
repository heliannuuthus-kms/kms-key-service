use anyhow::Context;
use sea_orm::{
    sea_query::OnConflict, ColumnTrait, ConnectionTrait, EntityTrait,
    IntoActiveModel, QueryFilter,
};

use crate::{common::errors::Result, entity::prelude::*};

// batch insert metas
pub async fn insert_or_update_key_metas<C: ConnectionTrait>(
    db: &C,
    models: Vec<KeyMetaModel>,
) -> Result<()> {
    KeyMetaEntity::insert_many(
        models.into_iter().map(KeyMetaModel::into_active_model),
    )
    .on_conflict(
        OnConflict::columns([KeyMetaColumn::KeyId, KeyMetaColumn::Version])
            .update_columns([
                KeyMetaColumn::State,
                KeyMetaColumn::RotationInterval,
                KeyMetaColumn::Description,
                KeyMetaColumn::PrimaryVersion,
                KeyMetaColumn::LastRotationAt,
                KeyMetaColumn::MaterialExpireAt,
                KeyMetaColumn::DeletionAt,
            ])
            .to_owned(),
    )
    .exec(db)
    .await?;
    Ok(())
}

pub async fn select_key_meta<C: ConnectionTrait>(
    db: &C,
    key_id: &str,
) -> Result<Vec<KeyMetaModel>> {
    Ok(KeyMetaEntity::find()
        .filter(KeyMetaColumn::KeyId.eq(key_id))
        .all(db)
        .await
        .context(format!("select key meta failed, key_id: {}", key_id))?)
}

pub async fn select_key_meta_by_kms<C: ConnectionTrait>(
    db: &C,
    kms_id: &str,
) -> Result<Vec<KeyMetaModel>> {
    Ok(KeyMetaEntity::find()
        .filter(KeyMetaColumn::KmsId.eq(kms_id))
        .all(db)
        .await
        .context(format!(
            "select key meta by kms failed, kms_id: {}",
            kms_id
        ))?)
}
