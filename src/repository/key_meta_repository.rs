use sea_orm::{
    sea_query::OnConflict, ActiveValue::NotSet, ConnectionTrait, EntityTrait,
    IntoActiveModel, QuerySelect,
};

use crate::{common::errors::Result, entity::prelude::*};

// batch insert metas
pub async fn insert_or_update_key_metas<C: ConnectionTrait>(
    db: &C,
    models: Vec<KeyMetaModel>,
) -> Result<()> {
    tracing::debug!("insert or update: {:?}", models);
    KeyMetaEntity::insert_many(models.into_iter().map(|model| {
        let mut active = model.into_active_model();
        active.created_at = NotSet;
        active.updated_at = NotSet;
        active
    }))
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
