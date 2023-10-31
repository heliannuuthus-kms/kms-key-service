use std::collections::HashMap;

use chrono::{Duration, Local};
use itertools::Itertools;
use lazy_static::lazy_static;
use moka::future::Cache;
use sea_orm::*;
use serde_json::json;

use super::kms_service;
use crate::{
    common::{
        encrypto::{
            self,
            types::{KeyOrigin, KeyState, KeyType},
        },
        errors::{Result, ServiceError},
        utils,
    },
    entity::{self, kms},
    pojo::{
        form::key::{KeyCreateForm, KeyImportParamsQuery},
        result::key::{KeyCreateResult, KeyMaterialImportParamsResult},
    },
    repository::key_repository,
};

lazy_static! {
    static ref KEY_CACHE: Cache<String, HashMap<String, entity::key::Model>> =
        moka::future::CacheBuilder::new(64 * 1024 * 1024)
            .name("key_cache")
            .time_to_idle(Duration::hours(1).to_std().unwrap())
            .time_to_live(Duration::days(1).to_std().unwrap())
            .build();
    static ref KET_META_CACHE: Cache<String, entity::key_meta::Model> =
        moka::future::CacheBuilder::new(64 * 1024 * 1024)
            .name("key_meta_cache")
            .time_to_idle(Duration::minutes(30).to_std().unwrap())
            .time_to_live(Duration::days(1).to_std().unwrap())
            .build();
}

pub async fn create_key(
    db: &DbConn,
    data: &KeyCreateForm,
) -> Result<KeyCreateResult> {
    let kms_id = &data.kms_id;
    let _kms_instance = kms_service::get_kms(db, kms_id).await?;

    let key_id = &utils::generate_b62(32)?;

    let key_alg = encrypto::algorithm::select_key_alg(data.spec);
    if !key_alg.meta.key_usage.contains(&data.usage) {
        return Err(ServiceError::BadRequest(format!(
            "unsupported key usage({:?})",
            data.usage
        )));
    }

    let mut key = entity::key::Model {
        key_id: key_id.to_owned(),
        key_type: key_alg.meta.key_type,
        kms_id: kms_id.to_owned(),
        ..Default::default()
    };

    let mut key_meta = entity::key_meta::Model {
        key_id: key_id.to_owned(),
        origin: data.origin,
        spec: data.spec,
        usage: data.usage,
        ..Default::default()
    };
    let mut result = KeyCreateResult {
        kms_id: kms_id.to_owned(),
        key_id: key_id.to_owned(),
        key_type: key.key_type,
        key_spec: key_meta.spec,
        key_usage: key_meta.usage,
        key_origin: key_meta.origin,
        ..Default::default()
    };
    // fill key rotation interval
    if let Some(ri) = data.rotation_interval {
        if data.enable_automatic_rotation {
            key_meta.rotation_interval = ri.num_seconds();
            result.expired_at = Some(Local::now().fixed_offset() + ri);
        } else {
            return Err(ServiceError::BadRequest(
                "enable `enable_automatic_rotation`, if set \
                 `roration_interval`"
                    .to_owned(),
            ));
        }
    }

    if KeyOrigin::Kms.eq(&key_meta.origin) {
       let s = match key_alg.factory {
        encrypto::algorithm::KeyAlgorithmFactory::SYMM { factory } => todo!(),
        encrypto::algorithm::KeyAlgorithmFactory::RSA { factory } => todo!(),
        encrypto::algorithm::KeyAlgorithmFactory::EC { factory } => todo!(),
    };
        let (pri_key, pub_key) = (key_alg.factory )()?;
        key.key_pair = Some(if KeyType::Symmetric.eq(&key_alg.key_type) {
            json!(entity::key::SymmtricKeyPair { key_pair: pri_key })
        } else {
            json!(entity::key::AsymmtricKeyPair {
                private_key: pri_key,
                public_key: pub_key,
            })
        });
    } else {
        key_meta.state = KeyState::Pendingimport;
        result.key_state = key_meta.state
        // 存入缓存
    }
    key_repository::insert_key(db, &key).await?;
    key_repository::insert_key_meta(db, &key_meta).await?;

    Ok(result)
}

pub async fn generate_key_import_params(
    db: &DbConn,
    form: &KeyImportParamsQuery,
) -> Result<KeyMaterialImportParamsResult> {
    let key_alg =
        encrypto::algorithm::select_wrapping_key_alg(form.wrapping_key_spec);

        key_alg.generator

    Ok(KeyMaterialImportParamsResult {
        key_id:"",
        token: "",
        pub_key: todo!(),
        key_spec: todo!(),
        expires_in: todo!(),
    })
}

pub async fn get_keys(
    db: &DbConn,
    kms_id: &str,
) -> Result<HashMap<String, entity::key::Model>> {
    let _kms_instance = kms_service::get_kms(db, kms_id).await?;

    let key_cache_id = format!("kms:keys:key:{}", kms_id);

    if let Some(cached_keys) = KEY_CACHE.get(&key_cache_id).await {
        if !cached_keys.is_empty() {
            return Ok(cached_keys);
        }
    };

    let presistent_keys: HashMap<String, entity::key::Model> =
        key_repository::select_kms_keys(db, kms_id)
            .await?
            .into_iter()
            .map(|model| (model.kms_id.to_owned(), model))
            .collect();

    if presistent_keys.is_empty() {
        Err(ServiceError::NotFount(format!(
            "kms keys is empty, kms_id: {}",
            kms_id
        )))
    } else {
        KEY_CACHE
            .insert(key_cache_id, presistent_keys.clone())
            .await;
        Ok(presistent_keys)
    }
}
