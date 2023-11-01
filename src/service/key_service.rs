use std::collections::{HashMap, HashSet};

use chrono::{Duration, Local};
use lazy_static::lazy_static;
use moka::future::Cache;
use sea_orm::*;
use serde_json::json;

use super::{
    key_meta_service::{self, get_key_metas},
    kms_service,
};
use crate::{
    common::{
        cache::{redis_get, redis_setex, RdConn},
        encrypto::{
            algorithm::{self},
            types::{KeyOrigin, KeyState, KeyType},
        },
        errors::{Result, ServiceError},
        utils,
    },
    entity::{
        self,
        key::{AsymmtricKeyPair, SymmtricKeyPair},
        prelude::*,
    },
    pojo::{
        form::key::{KeyCreateForm, KeyImportForm, KeyImportParamsQuery},
        result::key::{
            KeyCreateResult, KeyMaterialImportParams,
            KeyMaterialImportParamsResult,
        },
    },
    repository::key_repository,
};

lazy_static! {
    static ref KEY_INDEX_CACHE: Cache<String, HashSet<String>> =
        moka::future::CacheBuilder::new(64 * 1024 * 1024)
            .name("key_index_cache")
            .time_to_idle(Duration::minutes(5).to_std().unwrap())
            .time_to_live(Duration::minutes(30).to_std().unwrap())
            .build();
    static ref KEY_VERSION_CACHE: Cache<String, HashMap<String, KeyModel>> =
        moka::future::CacheBuilder::new(64 * 1024 * 1024)
            .name("key_version_cache")
            .time_to_idle(Duration::minutes(5).to_std().unwrap())
            .time_to_live(Duration::minutes(30).to_std().unwrap())
            .build();
    static ref KET_KMS_META_CACHE: Cache<String, HashMap<String, entity::key_meta::Model>> =
        moka::future::CacheBuilder::new(64 * 1024 * 1024)
            .name("key_version_meta_cache")
            .time_to_idle(Duration::minutes(30).to_std().unwrap())
            .time_to_live(Duration::days(1).to_std().unwrap())
            .build();
}

pub async fn create_key(
    db: &DbConn,
    data: &KeyCreateForm,
) -> Result<KeyCreateResult> {
    let key_alg_meta = algorithm::select_meta(data.spec);

    if !key_alg_meta.key_usage.contains(&data.usage) {
        return Err(ServiceError::BadRequest(format!(
            "unsupported key usage({:?})",
            data.usage
        )));
    }

    let kms_id = &data.kms_id;

    kms_service::get_kms(db, kms_id).await?;

    let key_id = &utils::generate_b62(32)?;

    let mut key = KeyModel {
        key_id: key_id.to_owned(),
        key_type: key_alg_meta.key_type,
        kms_id: kms_id.to_owned(),
        version: utils::uuid(),
        ..Default::default()
    };

    let mut key_meta = KeyMetaModel {
        key_id: key_id.to_owned(),
        description: data.description.to_owned(),
        origin: data.origin,
        spec: data.spec,
        usage: data.usage,
        version: key.version.clone(),
        primary_version: key.version.clone(),
        ..Default::default()
    };
    let mut result = KeyCreateResult {
        kms_id: kms_id.to_owned(),
        key_id: key_id.to_owned(),
        key_type: key_alg_meta.key_type,
        key_spec: key_meta.spec,
        key_usage: key_meta.usage,
        key_origin: key_meta.origin,
        primary_key_version: key_meta.primary_version.to_owned(),
        ..Default::default()
    };
    // fill key rotation interval
    if data.enable_automatic_rotation {
        if let Some(ri) = data.rotation_interval {
            key_meta.rotation_interval = ri.num_seconds();
            result.rotate_interval = Some(ri);
            result.next_rotated_at = Some(Local::now().fixed_offset() + ri);
        } else {
            return Err(ServiceError::BadRequest(
                "please set `rotation_interval`, if enable \
                 `enable_automatic_rotation`"
                    .to_owned(),
            ));
        }
    }

    if KeyOrigin::Kms.eq(&key_meta.origin) {
        let (left, right) = algorithm::generate_key(data.spec)?;
        let pri_key = utils::encode64(&left);
        key.key_pair = Some(if KeyType::Symmetric.eq(&key_alg_meta.key_type) {
            json!(entity::key::SymmtricKeyPair { key_pair: pri_key })
        } else {
            json!(entity::key::AsymmtricKeyPair {
                private_key: pri_key,
                public_key: utils::encode64(&right)
            })
        });
    } else {
        key_meta.state = KeyState::PendingImport;
        result.key_state = key_meta.state
    };

    tracing::info!(
        "presist key, kms_id: {}, key_id: {}, version: {}",
        key.kms_id,
        key.key_id,
        key.version
    );
    save_key(db, &key).await?;
    key_meta_service::save_key_meta(db, &key_meta).await?;

    Ok(result)
}

pub async fn generate_key_import_params(
    db: &DbConn,
    rd: &RdConn,
    form: &KeyImportParamsQuery,
) -> Result<KeyMaterialImportParamsResult> {
    let key_id = &form.key_id;
    let key_metas = get_key_metas(db, key_id).await?;

    if key_metas.is_empty() {
        return Err(ServiceError::NotFount(format!(
            "key is nonexistent, key_id: {}",
            key_id
        )));
    }

    let cmk_meta = key_metas
        .iter()
        .filter_map(|(version, key_meta)| {
            if version.to_owned().eq(&key_meta.primary_version.to_owned()) {
                Some(key_meta.clone())
            } else {
                None
            }
        })
        .next()
        .ok_or(ServiceError::NotFount(format!(
            "cmk key is nonexistent, key_id: {}",
            key_id
        )))?;
    if !cmk_meta.state.eq(&KeyState::PendingImport) {
        return Err(ServiceError::BadRequest(format!(
            "key is imported: {}",
            key_id
        )));
    }

    let (left, right) =
        algorithm::generate_wrapping_key(form.wrapping_key_spec)?;

    let expires_in = Duration::days(1);

    let import_token = utils::generate_b64(128)?;
    redis_setex(
        rd,
        &format!("kms:keys:import_material:{}", key_id),
        KeyMaterialImportParams {
            token: import_token.to_owned(),
            private_key: utils::encode64(&left),
            wrapping_spec: form.wrapping_key_spec,
            wrapping_algorithm: form.wrapping_algorithm,
        },
        expires_in,
    )
    .await?;
    Ok(KeyMaterialImportParamsResult {
        key_id: key_id.to_owned(),
        token: import_token,
        pub_key: utils::encode64(&right),
        expires_in,
    })
}

pub async fn import_key_material(
    db: &DbConn,
    rd: &RdConn,
    data: &KeyImportForm,
) -> Result<()> {
    let key_id = &data.key_id;

    let material_data = match redis_get::<KeyMaterialImportParams>(
        rd,
        &format!("kms:keys:import_material:{}", key_id),
    )
    .await?
    {
        Some(import_material_data) => {
            if !import_material_data.token.eq(&data.import_token) {
                return Err(ServiceError::BadRequest(
                    "token is unmatched".to_owned(),
                ));
            }
            import_material_data
        }
        None => {
            return Err(ServiceError::NotFount(format!(
                "material is not created or token is expired, key_id: {}",
                key_id,
            )))
        }
    };

    let f = algorithm::select_wrapping_factory(material_data.wrapping_spec);

    let private_key = f.decrypt(
        &utils::decode64(&material_data.private_key)?,
        &utils::decode64(&data.encrypted_key_material)?,
        material_data.wrapping_algorithm.into(),
    )?;

    let key_pair =
        String::from_utf8(private_key.to_owned()).map_err(|err| {
            ServiceError::BadRequest(format!(
                "imported key is invalid string, err: {}",
                err
            ))
        })?;

    let key_model: KeyModel = get_main_key(db, key_id).await?;

    let key_meta_model =
        key_meta_service::get_version_key_meta(db, key_id, &key_model.version)
            .await?;

    let mut key_active_model = key_model.clone().into_active_model();

    key_active_model.key_pair =
        Set(Some(if KeyType::Symmetric.eq(&key_model.key_type) {
            json!(SymmtricKeyPair { key_pair })
        } else {
            let public_key =
                algorithm::derive_key(key_meta_model.spec, &private_key)?;
            json!(AsymmtricKeyPair {
                public_key: utils::encode64(&public_key),
                private_key: key_pair.to_owned()
            })
        }));
    key_repository::update_key(db, &key_active_model).await?;

    Ok(())
}

async fn save_key(db: &DbConn, model: &KeyModel) -> Result<()> {
    key_repository::insert_key(db, model).await?;

    KEY_INDEX_CACHE
        .remove(&format!("kms:keys:key_index:{}", model.kms_id))
        .await;
    KEY_VERSION_CACHE
        .remove(&format!("kms:keys:key_version:{}", model.key_id))
        .await;

    Ok(())
}

pub async fn get_main_key(db: &DbConn, key_id: &str) -> Result<KeyModel> {
    let key_version_keys = get_keys(db, key_id).await?;

    key_version_keys
        .into_iter()
        .filter_map(|(version, model)| {
            if model.version.eq(&version) {
                Some(model)
            } else {
                None
            }
        })
        .next()
        .ok_or(ServiceError::NotFount(format!(
            "key_id is invalid, key_id: {}",
            key_id
        )))
}

pub async fn get_version_key(
    db: &DbConn,
    key_id: &str,
    version: &str,
) -> Result<KeyModel> {
    let key_version_keys = get_keys(db, key_id).await?;
    Ok(key_version_keys
        .get(version)
        .ok_or(ServiceError::NotFount(format!(
            "key_id is invalid, key_id: {}",
            key_id
        )))?
        .clone())
}

pub async fn get_keys(
    db: &DbConn,
    key_id: &str,
) -> Result<HashMap<String, KeyModel>> {
    let key_version_cache_id = format!("kms:keys:key_version:{}", key_id);
    if let Some(version_keys) =
        KEY_VERSION_CACHE.get(&key_version_cache_id).await
    {
        tracing::debug!("print version keys: {:?}", version_keys);
        Ok(version_keys)
    } else {
        let ks = key_repository::select_key(db, key_id)
            .await?
            .into_iter()
            .map(|model| (model.version.to_owned(), model.clone()))
            .collect::<HashMap<String, KeyModel>>();

        KEY_VERSION_CACHE
            .insert(key_version_cache_id, ks.clone())
            .await;

        Ok(ks.clone())
    }
}

pub async fn get_kms_keys(
    db: &DbConn,
    kms_id: &str,
) -> Result<HashMap<String, Vec<KeyModel>>> {
    let key_index_cache_id = format!("kms:keys:key_index:{}", kms_id);

    let cached_keys = if let Some(cached_keys) =
        KEY_INDEX_CACHE.get(&key_index_cache_id).await
    {
        cached_keys
    } else {
        let _kms_instance = kms_service::get_kms(db, kms_id).await?;
        key_repository::select_kms_key_ids(db, kms_id)
            .await?
            .into_iter()
            .map(|model| model.key_id)
            .collect::<HashSet<String>>()
    };

    let mut kms_keys: HashMap<String, Vec<KeyModel>> = HashMap::new();
    for key_id in cached_keys.iter() {
        let keys = get_keys(db, key_id).await?;
        kms_keys.insert(
            key_id.to_owned(),
            keys.into_values().collect::<Vec<KeyModel>>(),
        );
    }

    KEY_INDEX_CACHE
        .insert(key_index_cache_id, cached_keys)
        .await;

    Ok(kms_keys)
}