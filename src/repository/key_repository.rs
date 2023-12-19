use anyhow::Context;
use sea_orm::*;

use crate::{
    common::{
        errors::Result,
    },
    entity::prelude::*,
};

// batch insert key
pub async fn insert_keys<C: ConnectionTrait>(
    db: &C,
    models: Vec<KeyModel>,
) -> Result<()> {
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

pub async fn select_key<C: ConnectionTrait>(
    db: &C,
    key_id: &str,
) -> Result<Vec<KeyModel>> {
    Ok(KeyEntity::find()
        .filter(KeyColumn::KeyId.eq(key_id))
        .all(db)
        .await?)
}
