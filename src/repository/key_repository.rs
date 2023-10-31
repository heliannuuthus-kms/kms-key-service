use sea_orm::*;

use crate::{
    common::errors::Result,
    entity::{self, prelude::*},
};

pub async fn insert_key<C: ConnectionTrait>(
    db: &C,
    model: &entity::key::Model,
) -> Result<()> {
    Key::insert(model.clone().into_active_model())
        .exec(db)
        .await?;
    Ok(())
}

pub async fn insert_key_meta<C: ConnectionTrait>(
    db: &C,
    model: &entity::key_meta::Model,
) -> Result<()> {
    KeyMeta::insert(model.clone().into_active_model())
        .exec(db)
        .await?;

    Ok(())
}

pub async fn select_kms_keys<C: ConnectionTrait>(
    db: &C,
    kms_id: &str,
) -> Result<Vec<entity::key::Model>> {
    Ok(Key::find()
        .filter(entity::key::Column::KmsId.eq(kms_id))
        .all(db)
        .await?)
}

pub async fn select_kms_key_ids<C: ConnectionTrait>(
    db: &C,
    kms_id: &str,
) -> Result<Vec<entity::key::Model>> {
    Ok(Key::find()
        .filter(entity::key::Column::KmsId.eq(kms_id))
        .select_only()
        .columns([entity::key::Column::KmsId, entity::key::Column::KeyId])
        .all(db)
        .await?)
}

pub async fn select_key<C: ConnectionTrait>(
    db: &C,
    key_id: &str,
) -> Result<Vec<entity::key::Model>> {
    Ok(Key::find()
        .filter(entity::key::Column::KeyId.eq(key_id))
        .all(db)
        .await?)
}

pub async fn select_version_key<C: ConnectionTrait>(
    db: &C,
    key_id: &str,
    version: &str,
) -> Result<Option<entity::key::Model>> {
    Ok(Key::find()
        .filter(
            entity::key::Column::KeyId
                .eq(key_id)
                .and(entity::key::Column::Version.eq(version)),
        )
        .one(db)
        .await?)
}

pub async fn select_key_meta<C: ConnectionTrait>(
    db: &C,
    key_id: &str,
) -> Result<Option<entity::key_meta::Model>> {
    Ok(KeyMeta::find()
        .filter(entity::key_meta::Column::KeyId.eq(key_id))
        .one(db)
        .await?)
}
