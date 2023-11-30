use sea_orm::{
    sea_query::OnConflict, ConnectionTrait, EntityTrait, IntoActiveModel,
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
