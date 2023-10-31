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
    Ok(())
}
