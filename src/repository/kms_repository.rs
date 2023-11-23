use anyhow::Context;
use sea_orm::{
    sea_query::OnConflict, ActiveValue::NotSet, ColumnTrait, DbConn,
    EntityTrait, IntoActiveModel, QueryFilter,
};

use crate::{common::errors::Result, entity::prelude::*};

pub async fn select_kms(db: &DbConn, kms_id: &str) -> Result<Option<KmsModel>> {
    Ok(KmsEntity::find()
        .filter(KmsColumn::KmsId.eq(kms_id))
        .one(db)
        .await
        .context(format!("select kms instance failed, kms_id: {}", kms_id))?)
}

pub async fn insert_or_update_kms_instance(
    db: &DbConn,
    model: &KmsModel,
) -> Result<()> {
    let kms_name = &model.name;
    let mut active = model.clone().into_active_model();
    active.created_at = NotSet;
    active.updated_at = NotSet;
    KmsEntity::insert(active)
        .on_conflict(
            OnConflict::column(KmsColumn::KmsId)
                .update_columns([KmsColumn::Name, KmsColumn::Description])
                .to_owned(),
        )
        .exec(db)
        .await
        .context(format!("insert or update failed name: {:?}", kms_name))?;
    Ok(())
}

pub async fn delete_kms_instance(db: &DbConn, kms_id: &str) -> Result<()> {
    KmsEntity::delete_many()
        .filter(KmsColumn::KmsId.eq(kms_id))
        .exec(db)
        .await
        .context(format!("delete kms instance failed, kms_id: {}", kms_id))?;
    Ok(())
}
