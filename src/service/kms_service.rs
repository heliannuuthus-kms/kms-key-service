use chrono::Duration;
use lazy_static::lazy_static;
use sea_orm::DbConn;
use serde_json::json;

use crate::{
    common::{
        errors::{Result, ServiceError},
        secrets::rsa::RsaAlgorithm,
        utils,
    },
    entity,
    pojo::result::kms::{KmsAkskResult, KmsResult},
    repository::kms_repository,
};

lazy_static! {
    static ref KMS_INSTANCE_CACHE: moka::future::Cache<String, entity::kms::Model> =
        moka::future::CacheBuilder::new(64 * 1024 * 1024)
            .name("kms_instance_cache")
            .time_to_idle(Duration::minutes(30).to_std().unwrap())
            .time_to_live(Duration::days(1).to_std().unwrap())
            .build();
    static ref KMS_AKSK_CACHE: moka::future::Cache<String, Vec<entity::kms_aksk::Model>> =
        moka::future::CacheBuilder::new(64 * 1024 * 1024)
            .name("kms_aksk_cache")
            .time_to_idle(Duration::minutes(30).to_std().unwrap())
            .time_to_live(Duration::days(1).to_std().unwrap())
            .build();
}

pub async fn create_kms(
    db: &DbConn,
    model: &entity::kms::Model,
) -> Result<KmsResult> {
    kms_repository::insert_or_update_kms_instance(db, model).await?;
    let (left, right) = RsaAlgorithm::generate(2048)?;
    let private_key = utils::encode64(&left);
    let aksk_modle = entity::kms_aksk::Model {
        kms_id: model.kms_id.to_string(),
        access_key: utils::generate_b62(64)?,
        secret_key: json!({"pub": utils::encode64(&right), "pri": private_key}),
        ..Default::default()
    };
    kms_repository::insert_kms_aksk(db, &aksk_modle).await?;

    Ok(KmsResult {
        kms_id: model.kms_id.to_string(),
        name: model.name.to_string(),
        description: model.description.clone(),
        aksk: vec![KmsAkskResult {
            access_key: aksk_modle.access_key,
            secret_key: private_key,
        }],
    })
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
    let cache_key = format!("kms:secrets:kms:instance:{}", &model.kms_id);

    kms_repository::insert_or_update_kms_instance(db, &model).await?;

    KMS_INSTANCE_CACHE.remove(&cache_key).await;

    Ok(())
}

pub async fn get_main_aksk(
    db: &DbConn,
    access_key: &str,
) -> Result<entity::kms_aksk::Model> {
    match get_all_of_aksk(db, access_key).await?.get(0) {
        Some(model) => Ok(model.clone()),
        None => Err(ServiceError::NotFount(format!("aksk is not found"))),
    }
}

pub async fn get_all_of_aksk(
    db: &DbConn,
    aksk: &str,
) -> Result<Vec<entity::kms_aksk::Model>> {
    let cache_key = format!("kms:secrets:kms:aksk:{}", aksk);
    Ok(match KMS_AKSK_CACHE.get(&cache_key).await {
        Some(model) => model,
        None => {
            let models =
                kms_repository::select_kms_aksks_by_ak(db, aksk).await?;
            KMS_AKSK_CACHE.insert(cache_key, models.clone()).await;
            models
        }
    })
}
