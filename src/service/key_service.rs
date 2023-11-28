use std::collections::{HashMap, HashSet};

use anyhow::Context;
use chrono::{Duration, NaiveDateTime, Utc};
use itertools::Itertools;
use lazy_static::lazy_static;
use moka::future::Cache;
use redis::AsyncCommands;
use sea_orm::*;
use serde_json::json;

use super::{
    key_meta_service::{self, get_key_metas, get_main_key_meta},
    kms_service,
};
use crate::{
    common::{
        cache::{self, redis_get, RdConn},
        datasource::{self, PaginatedResult, Paginator},
        errors::{Result, ServiceError},
        utils,
    },
    crypto::{
        algorithm::{self},
        types::{self, KeyOrigin, KeyState, KeyType},
    },
    entity::{
        key::{AsymmtricKeyPair, SymmtricKeyPair},
        prelude::*,
    },
    paginated_result,
    pojo::{
        form::key::{KeyCreateForm, KeyImportForm, KeyImportParamsQuery},
        result::key::{
            KeyCreateResult, KeyMaterialImportParams,
            KeyMaterialImportParamsResult, KeyVersionResult,
        },
    },
    repository::{key_alias_repository, key_repository},
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
    pub static ref ALIAS_KEY_CACHE: Cache<String, KeyModel> =
        moka::future::CacheBuilder::new(64 * 1024 * 1024)
            .name("alias_key_cache")
            .time_to_idle(Duration::minutes(5).to_std().unwrap())
            .time_to_live(Duration::minutes(30).to_std().unwrap())
            .build();
}

#[derive(Clone)]
pub struct RotateExecutor {
    db: DbConn,
    rd: RdConn,
}

impl RotateExecutor {
    pub async fn new(db: DbConn, rd: RdConn) -> Self {
        RotateExecutor { db, rd }
    }

    fn inner_key(&self, timestamp: i64) -> String {
        format!("kms:keys:rotation:{}", timestamp)
    }

    pub async fn submit(&self, key_id: &str, interval: Duration) -> Result<()> {
        let mut conn = cache::borrow(&self.rd).await?;
        let current_timestamp = (Utc::now() + interval).timestamp();
        conn.sadd(&self.inner_key(current_timestamp), key_id)
            .await?;
        Ok(())
    }

    pub async fn remove(
        &self,
        key_id: &str,
        timestamp: NaiveDateTime,
    ) -> Result<()> {
        let mut conn = cache::borrow(&self.rd).await?;
        conn.srem(self.inner_key(timestamp.timestamp()), key_id)
            .await?;
        Ok(())
    }

    pub async fn poll_purge(&self) -> Result<()> {
        let mut delay =
            tokio::time::interval(Duration::seconds(1).to_std().unwrap());
        loop {
            delay.tick().await;
            let mut conn = cache::borrow(&self.rd).await?;
            let key = self.inner_key(Utc::now().timestamp());
            let key_ids: HashSet<String> =
                conn.smembers(key.to_owned()).await?;
            conn.del(key).await?;
            futures::future::join_all(
                key_ids
                    .iter()
                    .map(|key_id| async {
                        create_key_version(&self.db, self, key_id).await
                    })
                    .collect_vec(),
            )
            .await;
        }
    }
}

pub async fn create_key(
    db: &DbConn,
    re: RotateExecutor,
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
        kms_id: kms_id.to_owned(),
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
        version: key_meta.primary_version.to_owned(),
        primary_key_version: key_meta.primary_version.to_owned(),
        ..Default::default()
    };

    if KeyOrigin::Kms.eq(&key_meta.origin) {
        key.generate_key(data.spec)?;
    } else {
        if !algorithm::SUPPORTED_EXTERNAL_SPEC.contains(&data.spec) {
            return Err(ServiceError::Unsupported(format!(
                "external marterial spec is not supported: {:?}",
                data.spec,
            )));
        }
        key_meta.state = KeyState::PendingImport;
        result.key_state = key_meta.state
    };

    tracing::info!(
        "presist key, kms_id: {}, key_id: {}, version: {}",
        key.kms_id,
        key.key_id,
        key.version
    );

    // fill key rotation interval
    if data.enable_automatic_rotation {
        if let Some(ri) = data.rotation_interval {
            key_meta.rotation_interval = ri.num_seconds();
            result.rotate_interval = Some(ri);
            result.next_rotated_at = Some(key_meta.created_at + ri);
            re.submit(key_id, ri).await?;
        } else {
            return Err(ServiceError::BadRequest(
                "please set `rotation_interval`, if enable \
                 `enable_automatic_rotation`"
                    .to_owned(),
            ));
        }
    }

    save_key(db, &key).await?;
    key_meta_service::set_key_meta(db, key_meta).await?;

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
    let mut conn = cache::borrow(rd).await?;
    conn.set_ex(
        format!("kms:keys:import_material:{}", key_id),
        serde_json::to_string(&KeyMaterialImportParams {
            token: import_token.to_owned(),
            private_key: utils::encode64(&left),
            wrapping_spec: form.wrapping_key_spec,
            wrapping_algorithm: form.wrapping_algorithm,
        })
        .context("serilize key material failed")?,
        expires_in.num_seconds() as usize,
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

    let key_model: KeyModel = get_main_key(db, key_id).await?;

    let key_meta_model =
        key_meta_service::get_version_key_meta(db, key_id, &key_model.version)
            .await?;

    let meta = algorithm::select_meta(key_meta_model.spec);

    let key_pair = utils::encode64(&private_key);

    if meta.key_size != private_key.len() {
        return Err(ServiceError::BadRequest(format!(
            "key length is invalid, expect: {}, actul: {}",
            meta.key_size,
            private_key.len()
        )));
    }

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

pub async fn create_key_version(
    db: &DbConn,
    re: &RotateExecutor,
    key_id: &str,
) -> Result<KeyVersionResult> {
    let mut key_meta: KeyMetaModel = get_main_key_meta(db, key_id).await?;

    // judge origin
    if KeyOrigin::External.eq(&key_meta.origin) {
        return Err(ServiceError::Unsupported(
            "external key is unsuppoted to create new version".to_owned(),
        ));
    }

    // judge state
    types::assert_state(KeyState::Enable, key_meta.state)?;

    let key_alg_meta = algorithm::select_meta(key_meta.spec);

    let mut key = KeyModel {
        kms_id: key_meta.kms_id.to_owned(),
        key_id: key_meta.key_id.to_owned(),
        key_type: key_alg_meta.key_type,
        version: utils::uuid(),
        ..Default::default()
    };

    key.generate_key(key_meta.spec)?;

    save_key(db, &key).await?;
    // 缺少时间判断
    key_meta.version = utils::uuid();

    let key_meta_new = key_meta.renew(&key);

    let mut key_metas = get_key_metas(db, key_id)
        .await?
        .into_iter()
        .map(|(version, mut meta)| {
            if version.eq(&meta.primary_version) {
                // old key version
                meta.last_rotation_at = Some(Utc::now().naive_utc());
            };
            meta.primary_version = key.version.to_owned();
            meta
        })
        .collect_vec();

    key_metas.push(key_meta_new.clone());

    key_meta_service::batch_set_key_meta(db, key_metas).await?;

    if key_meta.rotation_interval >= 0 {
        let last_rotation_at =
            key_meta.last_rotation_at.unwrap_or(key_meta.created_at);
        let interval = Duration::seconds(key_meta.rotation_interval);
        re.remove(key_id, last_rotation_at + interval).await?;
        re.submit(key_id, interval).await?;
    }

    Ok(KeyVersionResult::from(key_meta_new))
}

async fn save_key(db: &DbConn, model: &KeyModel) -> Result<()> {
    batch_save_key(db, vec![model.clone()]).await
}

async fn batch_save_key(db: &DbConn, models: Vec<KeyModel>) -> Result<()> {
    key_repository::insert_keys(db, models.clone()).await?;
    for model in models {
        KEY_INDEX_CACHE
            .remove(&format!("kms:keys:key_index:{}", model.kms_id))
            .await;
        KEY_VERSION_CACHE
            .remove(&format!("kms:keys:key_version:{}", model.key_id))
            .await;
    }
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

pub async fn list_kms_keys(
    db: &DbConn,
    kms_id: &str,
    paginator: &Paginator,
) -> Result<PaginatedResult<Vec<KeyModel>>> {
    paginated_result!(
        key_repository::pagin_kms_keys(db, kms_id, paginator).await?,
        paginator.limit.unwrap_or(10)
    )
}

pub async fn list_key_versions(
    db: &DbConn,
    key_id: &str,
    paginator: &Paginator,
) -> Result<PaginatedResult<Vec<KeyVersionResult>>> {
    let mut result = key_repository::pagin_key_version(db, key_id, paginator)
        .await?
        .into_iter()
        .map(|model| model.into())
        .collect::<Vec<KeyVersionResult>>();
    paginated_result!(result, paginator.limit.unwrap_or(10))
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

pub async fn get_key_by_alias(db: &DbConn, alias: &str) -> Result<KeyModel> {
    let alias_key_cache_key = format!("kms:keys:alias_key:{}", alias);
    match ALIAS_KEY_CACHE.get(&alias_key_cache_key).await {
        Some(key) => Ok(key),
        None => {
            if let Some(key_alias) =
                key_alias_repository::select_alias(db, alias).await?
            {
                let key = get_main_key(db, &key_alias.key_id).await?;
                ALIAS_KEY_CACHE
                    .insert(alias_key_cache_key, key.clone())
                    .await;

                Ok(key)
            } else {
                Err(ServiceError::NotFount(format!(
                    "key is nonexistent, alias: {}",
                    alias
                )))
            }
        }
    }
}

#[cfg(test)]
mod test {

    use std::{
        sync::{Arc, Mutex},
        task::Poll,
        thread,
    };

    use chrono::{Duration, Utc};
    use futures::ready;
    use tokio::time::Instant;

    use crate::common::utils;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_delay_queue() {
        let queue = Arc::new(Mutex::new(tokio_util::time::DelayQueue::new()));
        let rotation = |key_id: String| {
            println!(
                "thread_id: {:?}, rotate_key, key_id: {}, timestamp: {:?}",
                thread::current().id(),
                key_id,
                Utc::now().naive_local()
            )
        };

        let tasks = (0 .. 10).map(|i| {
            let queue2 = queue.clone();
            tokio::spawn(async move {
                let mut q1 = queue2.lock().unwrap();
                println!("thread_id: {:?}", thread::current().id(),);
                let _key = q1.insert_at(
                    rotation,
                    Instant::now() + Duration::seconds(i).to_std().unwrap(),
                );
            })
        });

        futures::future::join_all(tasks).await;

        futures::future::poll_fn(|cx| {
            let mut q1 = queue.lock().unwrap();
            while let Some(entry) = ready!(q1.poll_expired(cx)) {
                entry.get_ref()(utils::uuid());
            }
            Poll::Ready(())
        })
        .await
    }
}
