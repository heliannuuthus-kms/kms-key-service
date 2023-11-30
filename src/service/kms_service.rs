use chrono::Duration;
use lazy_static::lazy_static;
use sea_orm::DbConn;

use crate::{
    common::errors::{Result, ServiceError},
    encode_key,
    entity::prelude::KmsModel,
    pojo::result::kms::KmsResult,
    repository::kms_repository,
};

pub const KMS_CACHE_KEY: &str = "kms_cache";

lazy_static! {
    static ref KMS_CACHE: moka::future::Cache<String, KmsModel> =
        moka::future::CacheBuilder::new(64 * 1024 * 1024)
            .name(KMS_CACHE_KEY)
            .time_to_idle(Duration::minutes(30).to_std().unwrap())
            .time_to_live(Duration::days(1).to_std().unwrap())
            .build();
}

pub async fn create_kms(db: &DbConn, model: KmsModel) -> Result<KmsResult> {
    kms_repository::insert_or_update_kms_instance(db, &model).await?;
    Ok(KmsResult {
        kms_id: model.kms_id.to_owned(),
        name: model.name.to_owned(),
        description: model.description.to_owned(),
    })
}

pub async fn delete_kms(db: &DbConn, kms_id: &str) -> Result<()> {
    kms_repository::delete_kms_instance(db, kms_id).await?;

    KMS_CACHE.remove(&encode_key!(KMS_CACHE_KEY, kms_id)).await;

    Ok(())
}

pub async fn get_kms(db: &DbConn, kms_id: &str) -> Result<KmsModel> {
    let cache_key = encode_key!(KMS_CACHE_KEY, kms_id);
    Ok(match KMS_CACHE.get(&cache_key).await {
        Some(model) => model,
        None => match kms_repository::select_kms(db, kms_id).await? {
            Some(kms_model) => {
                KMS_CACHE.insert(cache_key, kms_model.clone()).await;
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

pub async fn set_kms(db: &DbConn, model: &KmsModel) -> Result<()> {
    kms_repository::insert_or_update_kms_instance(db, model).await?;

    KMS_CACHE
        .remove(&encode_key!(KMS_CACHE_KEY, model.kms_id.as_str()))
        .await;

    Ok(())
}
