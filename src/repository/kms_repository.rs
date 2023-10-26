use std::cmp;

use anyhow::Context;
use chrono::Duration;
use lazy_static::lazy_static;
use sea_orm::{
    entity::*, sea_query::OnConflict, ActiveModelTrait, ColumnTrait, DbConn,
    EntityTrait, IntoActiveModel, QueryFilter,
};

use crate::{
    common::errors::Result,
    entity::{self, prelude::*},
};

pub async fn select_kms(
    db: &DbConn,
    kms_id: &str,
) -> Result<Option<entity::kms::Model>> {
    Ok(Kms::find()
        .filter(entity::kms::Column::KmsId.eq(kms_id))
        .one(db)
        .await
        .context(format!("select kms instance failed, kms_id: {}", kms_id))?)
}

pub async fn insert_or_update_kms_instance(
    db: &DbConn,
    model: &entity::kms::Model,
) -> Result<()> {
    Kms::insert(model.clone().into_active_model())
        .on_conflict(
            OnConflict::column(entity::kms::Column::KmsId)
                .update_columns([
                    entity::kms::Column::Name,
                    entity::kms::Column::Description,
                ])
                .to_owned(),
        )
        .exec(db)
        .await
        .context(format!("insert or update failed kms: {:?}", model))?;
    Ok(())
}

pub async fn delete_kms_instance(db: &DbConn, kms_id: &str) -> Result<()> {
    Kms::delete(entity::kms::ActiveModel {
        kms_id: Set(kms_id.to_owned()),
        ..Default::default()
    })
    .exec(db)
    .await
    .context(format!("delete kms instance failed, kms_id: {}", kms_id))?;

    KmsAksk::delete(entity::kms_aksk::ActiveModel {
        kms_id: Set(kms_id.to_owned()),
        ..Default::default()
    })
    .exec(db)
    .await
    .context(format!("delete kms aksk failed, kms_id: {}", kms_id))?;

    Ok(())
}

pub async fn insert_kms_aksk(
    db: &DbConn,
    model: &entity::kms_aksk::Model,
) -> Result<()> {
    KmsAksk::insert(model.clone().into_active_model())
        .exec(db)
        .await
        .context(format!("insert kms aksk failed: {:?}", model))?;

    Ok(())
}

pub async fn select_kms_aksks_by_ak(
    db: &DbConn,
    access_key: &str,
) -> Result<Vec<entity::kms_aksk::Model>> {
    let mut models = KmsAksk::find()
        .filter(entity::kms_aksk::Column::AccessKey.eq(access_key))
        .all(db)
        .await
        .context(format!(
            "select kms aksk by access_key failed, access_key: {}",
            access_key,
        ))?;
    models.sort_by(|a, b| {
        if a.expired_at.is_none() {
            return cmp::Ordering::Less;
        }
        if b.expired_at.is_none() {
            return cmp::Ordering::Less;
        }
        a.expired_at.unwrap().cmp(&b.expired_at.unwrap())
    });
    Ok(models)
}
