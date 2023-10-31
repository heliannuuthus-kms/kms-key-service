use std::cmp;

use anyhow::Context;
use sea_orm::{
    sea_query::OnConflict, ActiveModelTrait, ColumnTrait, DbConn, EntityTrait,
    IntoActiveModel, QueryFilter,
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
    Kms::delete_many()
        .filter(entity::kms::Column::KmsId.eq(kms_id))
        .exec(db)
        .await
        .context(format!("delete kms instance failed, kms_id: {}", kms_id))?;

    KmsAksk::delete_many()
        .filter(entity::kms_aksk::Column::KmsId.eq(kms_id))
        .exec(db)
        .await
        .context(format!("delete kms aksk failed, kms_id: {}", kms_id))?;

    Ok(())
}

pub async fn insert_or_update_kms_aksk(
    db: &DbConn,
    model: &entity::kms_aksk::Model,
) -> Result<()> {
    KmsAksk::insert(model.clone().into_active_model())
        .on_conflict(
            OnConflict::column(entity::kms_aksk::Column::AccessKey)
                .update_column(entity::kms_aksk::Column::ExpiredAt)
                .to_owned(),
        )
        .exec(db)
        .await
        .context(format!("insert kms aksk failed: {:?}", model))?;

    Ok(())
}

pub async fn delete_kms_aksk_by_ak(
    db: &DbConn,
    access_keys: &[String],
) -> Result<()> {
    KmsAksk::delete_many()
        .filter(entity::kms_aksk::Column::AccessKey.is_in(access_keys))
        .exec(db)
        .await
        .context(format!(
            "delete kms aksk failed, access_keys: [{:?}]",
            access_keys
        ))?;
    Ok(())
}

pub async fn select_kms_aksks(
    db: &DbConn,
    kms_id: &str,
) -> Result<Vec<entity::kms_aksk::Model>> {
    let mut models = KmsAksk::find()
        .filter(entity::kms_aksk::Column::KmsId.eq(kms_id))
        .all(db)
        .await
        .context(format!(
            "select kms aksk by kms_id failed, kms_id: {}",
            kms_id,
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
