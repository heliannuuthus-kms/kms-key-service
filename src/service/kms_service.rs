use chrono::{Duration, Local};
use lazy_static::lazy_static;
use sea_orm::DbConn;
use serde_json::json;

use crate::{
    common::{
        errors::{Result, ServiceError},
        secrets::rsa::RsaAlgorithm,
        utils,
    },
    entity::{self},
    pojo::result::kms::{KmsAkskResult, KmsResult},
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
    static ref KMS_AKSK_CACHE: moka::future::Cache<String, Vec<entity::kms_aksk::Model>> =
        moka::future::CacheBuilder::new(64 * 1024 * 1024)
            .name("kms_aksk_cache")
            .time_to_idle(Duration::minutes(30).to_std().unwrap())
            .time_to_live(Duration::days(1).to_std().unwrap())
            .eviction_listener(|key, _, cause| {
                tracing::debug!("eviction {:?}, cause: {:?}", key, cause)
            })
            .build();
}

fn generate_aksk(_kms_id: &str) -> Result<(String, String)> {
    let (left, right) = RsaAlgorithm::generate(2048)?;
    Ok((utils::encode64(&left), utils::encode64(&right)))
}

pub async fn create_kms(
    db: &DbConn,
    model: &entity::kms::Model,
) -> Result<KmsResult> {
    let (left, right) = generate_aksk(&model.kms_id)?;

    let aksk_model = entity::kms_aksk::Model {
        kms_id: model.kms_id.to_string(),
        access_key: utils::generate_b62(64)?,
        secret_key: json!({"pub": right, "pri": left}),
        ..Default::default()
    };
    kms_repository::insert_or_update_kms_instance(db, model).await?;
    kms_repository::insert_or_update_kms_aksk(db, &aksk_model).await?;

    Ok(KmsResult {
        kms_id: model.kms_id.to_string(),
        name: model.name.to_string(),
        description: model.description.clone(),
        aksk: vec![KmsAkskResult {
            access_key: aksk_model.access_key,
            secret_key: left,
        }],
    })
}

pub async fn delete_kms(db: &DbConn, kms_id: &str) -> Result<()> {
    kms_repository::delete_kms_instance(db, kms_id).await?;

    KMS_INSTANCE_CACHE
        .remove(&format!("kms:secrets:kms:instance:{}", kms_id))
        .await;

    KMS_AKSK_CACHE
        .remove(&format!("kms:secrets:kms:aksk:{}", kms_id))
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

pub async fn set_kms_aksk(
    db: &DbConn,
    model: &mut entity::kms_aksk::Model,
) -> Result<KmsResult> {
    let kms_id = &model.kms_id;
    let kms_instance = get_kms(db, kms_id).await?;
    let main_key = get_main_aksk(db, kms_id).await?;
    model.access_key = main_key.access_key.to_owned();
    let aksk_ckey = format!("kms:secrets:kms:aksk:{}", &kms_id);
    let expired_keys = get_all_of_aksk(db, kms_id)
        .await?
        .into_iter()
        .filter_map(|model| {
            if let Some(exp) = model.expired_at {
                if exp <= Local::now() {
                    Some(model.access_key.to_string())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect::<Vec<String>>();

    let (left, right) = generate_aksk(kms_id)?;
    let aksk_model = entity::kms_aksk::Model {
        kms_id: kms_id.to_string(),
        access_key: utils::generate_b62(64)?,
        secret_key: json!({"pub": right, "pri": left}),
        ..Default::default()
    };
    let result = KmsResult {
        kms_id: kms_id.to_string(),
        name: kms_instance.name.to_string(),
        description: kms_instance.description.clone(),
        aksk: vec![KmsAkskResult {
            access_key: aksk_model.access_key.to_string(),
            secret_key: left,
        }],
    };

    tracing::info!("delete expired keys: {:?}", expired_keys);
    kms_repository::insert_or_update_kms_aksk(db, model).await?;
    kms_repository::insert_or_update_kms_aksk(db, &aksk_model).await?;
    kms_repository::delete_kms_aksk_by_ak(db, &expired_keys).await?;
    KMS_AKSK_CACHE.remove(&aksk_ckey).await;

    Ok(result)
}

pub async fn get_main_aksk(
    db: &DbConn,
    kms_id: &str,
) -> Result<entity::kms_aksk::Model> {
    match get_all_of_aksk(db, kms_id).await?.get(0) {
        Some(model) => Ok(model.clone()),
        None => Err(ServiceError::NotFount(format!(
            "aksk is not found, kms_id: {}",
            kms_id
        ))),
    }
}

pub async fn get_all_of_aksk(
    db: &DbConn,
    kms_id: &str,
) -> Result<Vec<entity::kms_aksk::Model>> {
    tracing::info!("get aksk list, kms_id: {}", kms_id);

    let cache_key = format!("kms:secrets:kms:aksk:{}", kms_id);

    if let Some(models) = KMS_AKSK_CACHE.get(&cache_key).await {
        if !models.is_empty() {
            return Ok(models);
        }
    };
    let models = kms_repository::select_kms_aksks(db, kms_id).await?;
    KMS_AKSK_CACHE.insert(cache_key, models.clone()).await;
    Ok(models)
}
