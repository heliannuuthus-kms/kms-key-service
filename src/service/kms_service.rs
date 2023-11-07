use chrono::Duration;
use lazy_static::lazy_static;
use sea_orm::DbConn;

use crate::{
    common::errors::{Result, ServiceError},
    entity::{self},
    pojo::result::kms::KmsResult,
    repository::kms_repository,
};

lazy_static! {
    static ref KMS_INSTANCE_CACHE: moka::future::Cache<String, entity::kms::Model> =
        moka::future::CacheBuilder::new(64 * 1024 * 1024)
            .name("kms_instance_cache")
            .time_to_idle(Duration::minutes(30).to_std().unwrap())
            .time_to_live(Duration::days(1).to_std().unwrap())
            .eviction_listener(|key, _, cause| {
                tracing::debug!("eviction {:?}, cause: {:?}", key, cause)
            })
            .build();
}

pub async fn create_kms(
    db: &DbConn,
    model: &entity::kms::Model,
) -> Result<KmsResult> {
    kms_repository::insert_or_update_kms_instance(db, model).await?;
    Ok(KmsResult {
        kms_id: model.kms_id.to_string(),
        name: model.name.to_string(),
        description: model.description.clone(),
    })
}

pub async fn delete_kms(db: &DbConn, kms_id: &str) -> Result<()> {
    kms_repository::delete_kms_instance(db, kms_id).await?;

    KMS_INSTANCE_CACHE
        .remove(&format!("kms:secrets:kms:instance:{}", kms_id))
        .await;

    Ok(())
}

pub async fn get_kms(db: &DbConn, kms_id: &str) -> Result<entity::kms::Model> {
    let cache_key = format!("kms:secrets:kms:instance:{}", kms_id);
    Ok(match KMS_INSTANCE_CACHE.get(&cache_key).await {
        Some(model) => model,
        None => match kms_repository::select_kms(db, kms_id).await? {
            Some(kms_model) => {
                KMS_INSTANCE_CACHE
                    .insert(cache_key, kms_model.clone())
                    .await;
                kms_model
            }
            None => {
                return Err(ServiceError::NotFount(format!(
                    "kms instant is nonexsitant, kms_id: {}",
                    kms_id
                )))
            }
        },
    })
}

pub async fn set_kms(db: &DbConn, model: entity::kms::Model) -> Result<()> {
    kms_repository::insert_or_update_kms_instance(db, &model).await?;

    KMS_INSTANCE_CACHE
        .remove(&format!("kms:secrets:kms:instance:{}", &model.kms_id))
        .await;

    Ok(())
}
