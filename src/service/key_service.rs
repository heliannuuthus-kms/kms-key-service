use anyhow::Context;
use chrono::{Duration, NaiveDateTime, Utc};
use itertools::Itertools;
use redis::AsyncCommands;
use sea_orm::*;
use serde_json::json;

use super::{
    key_meta_service::{self, get_main_key_meta},
    kms_service,
};
use crate::{
    cache::{
        self,
        prelude::{rdconn, redis_get, RdConn},
    },
    common::{
        configs,
        errors::{Result, ServiceError},
        utils,
    },
    crypto::{
        algorithm::{self},
        types::{self, KeyOrigin, KeyState, KeyType},
    },
    encode_key,
    entity::{
        key::{AsymmtricKeyPair, SymmtricKeyPair},
        prelude::*,
    },
    pojo::{
        form::key::{KeyImportBody, KeyImportParamsQuery},
        result::key::{
            KeyCreateResult, KeyMaterialImportParams,
            KeyMaterialImportParamsResult, KeyVersionResult,
        },
    },
    repository::key_repository,
};

#[derive(Clone)]
pub struct RotateExecutor {
    db: DbConn,
    rd: RdConn,
}

impl RotateExecutor {
    pub async fn new(db: DbConn, rd: RdConn) -> Self {
        RotateExecutor { db, rd }
    }

    fn key(&self) -> String {
        "kms:keys:rotation".to_owned()
    }

    pub async fn submit(&self, key_id: &str, interval: Duration) -> Result<()> {
        let mut conn = rdconn(&self.rd).await?;
        let current_timestamp =
            (Utc::now().naive_local() + interval).timestamp();
        conn.zadd(&self.key(), key_id, current_timestamp).await?;
        Ok(())
    }

    pub async fn remove(&self, key_id: &str) -> Result<()> {
        let mut conn = rdconn(&self.rd).await?;
        conn.zrem(self.key(), key_id).await?;
        Ok(())
    }

    pub async fn poll_purge(&self) -> Result<()> {
        let default_interval =
            configs::env_var_default::<i64>("DEFAULT_ROTATION_INTERVAL", 5);
        let mut delay = tokio::time::interval(
            Duration::seconds(default_interval).to_std().unwrap(),
        );
        loop {
            let mut conn = rdconn(&self.rd).await?;

            let mut lowest_key: Vec<(String, i64)> = conn
                .zrangebyscore_limit_withscores(
                    self.key(),
                    Utc::now().naive_local().timestamp(),
                    "+inf",
                    0,
                    1,
                )
                .await?;

            let interval = lowest_key
                .pop()
                .map(|(_key_id, timestamp)| {
                    std::cmp::min(
                        NaiveDateTime::from_timestamp_opt(timestamp, 0)
                            .unwrap()
                            .signed_duration_since(Utc::now().naive_local())
                            .num_seconds(),
                        default_interval,
                    )
                })
                .unwrap_or(default_interval);

            delay.reset_after(Duration::seconds(interval).to_std().unwrap());
            delay.tick().await;

            let end = (Utc::now() + Duration::minutes(1))
                .naive_local()
                .timestamp();

            let key_ids: Option<Vec<String>> =
                conn.zrange(self.key(), 0, end.try_into().unwrap()).await?;
            if let Some(key_ids) = key_ids {
                conn.zrembyscore(self.key(), 0, end).await?;
                futures::future::join_all(
                    key_ids
                        .iter()
                        .map(|key_id| async {
                            create_key_version(&self.rd, &self.db, self, key_id)
                                .await
                        })
                        .collect_vec(),
                )
                .await;
            }
        }
    }
}

pub async fn create_key(
    rd: &RdConn,
    db: &DbConn,
    re: RotateExecutor,
    key_meta: &mut KeyMetaModel,
) -> Result<KeyCreateResult> {
    let key_alg_meta = algorithm::select_algorithm_meta(key_meta.spec);

    let kms_id = &key_meta.kms_id;

    kms_service::get_kms(rd, db, kms_id).await?;

    let key_id = &utils::generate_b62(32)?;

    let mut key = KeyModel {
        key_id: key_id.to_owned(),
        key_type: key_alg_meta.key_type,
        kms_id: kms_id.to_owned(),
        version: utils::uuid(),
        ..Default::default()
    };

    key_meta.key_id = key_id.to_owned();
    key_meta.version = key.version.to_owned();
    key_meta.primary_version = key.version.to_owned();

    if KeyOrigin::Kms.eq(&key_meta.origin) {
        key.generate_key(key_meta.spec)?;
    } else {
        key_meta.state = KeyState::PendingImport;
    };

    // fill key rotation interval
    if key_meta.rotation_interval > 0 {
        re.submit(key_id, Duration::seconds(key_meta.rotation_interval))
            .await?;
    }

    save_key(db, &key).await?;
    key_meta_service::set_key_meta(rd, db, key_meta.clone()).await?;

    let mut result: KeyCreateResult = key_meta.clone().into();
    result.key_type = key_alg_meta.key_type;
    Ok(result)
}

pub async fn generate_key_import_params(
    rd: &RdConn,
    db: &DbConn,
    form: &KeyImportParamsQuery,
) -> Result<KeyMaterialImportParamsResult> {
    let key_id = &form.key_id;
    let cmk_meta = get_main_key_meta(rd, db, key_id).await?;
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
    let mut conn = rdconn(rd).await?;
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
    rd: &RdConn,
    db: &DbConn,
    data: &KeyImportBody,
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
        &material_data.wrapping_algorithm.into(),
    )?;

    let key_model: KeyModel = get_main_key(rd, db, key_id).await?;

    let key_meta_model = key_meta_service::get_version_key_meta(
        rd,
        db,
        key_id,
        &key_model.version,
    )
    .await?;

    let meta = algorithm::select_algorithm_meta(key_meta_model.spec);

    if meta.key_size != private_key.len() {
        return Err(ServiceError::BadRequest(format!(
            "key length is invalid, expect: {}, actul: {}",
            meta.key_size,
            private_key.len()
        )));
    }

    let mut key_active_model = key_model.clone().into_active_model();
    let public_key = algorithm::derive_key(key_meta_model.spec, &private_key)?;
    key_active_model.pri_key = Set(Some(utils::encode64(&private_key)));
    key_active_model.pub_key = Set(Some(utils::encode64(&public_key)));
    key_repository::update_key(db, &key_active_model).await?;

    Ok(())
}

pub async fn create_key_version(
    rd: &RdConn,
    db: &DbConn,
    re: &RotateExecutor,
    key_id: &str,
) -> Result<KeyVersionResult> {
    let mut key_meta: KeyMetaModel = get_main_key_meta(rd, db, key_id).await?;

    // judge origin
    if KeyOrigin::External.eq(&key_meta.origin) {
        return Err(ServiceError::Unsupported(
            "external key is unsuppoted to create new version".to_owned(),
        ));
    }

    // judge state
    types::assert_state(KeyState::Enabled, key_meta.state)?;

    let key_alg_meta = algorithm::select_algorithm_meta(key_meta.spec);

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

    let mut key_metas = cache::key_meta::get_key_metas(rd, db, key_id)
        .await?
        .into_iter()
        .map(|mut meta| {
            if meta.version.eq(&meta.primary_version) {
                // old key version
                meta.last_rotation_at = Some(Utc::now().naive_utc());
            };
            meta.primary_version = key.version.to_owned();
            meta
        })
        .collect_vec();

    key_metas.push(key_meta_new.clone());

    key_meta_service::batch_set_key_meta(rd, db, key_metas).await?;

    if key_meta.rotation_interval >= 0 {
        let interval = Duration::seconds(key_meta.rotation_interval);
        re.remove(key_id).await?;
        re.submit(key_id, interval).await?;
    }

    Ok(KeyVersionResult::from(key_meta_new))
}

async fn save_key(db: &DbConn, model: &KeyModel) -> Result<()> {
    batch_save_key(db, vec![model.clone()]).await
}

async fn batch_save_key(db: &DbConn, models: Vec<KeyModel>) -> Result<()> {
    key_repository::insert_keys(db, models.clone()).await?;

    for key_id in models.into_iter().map(|model| model.key_id).unique() {
        cache::key::remove_keys(&key_id).await?
    }
    Ok(())
}

pub async fn get_keys(db: &DbConn, key_id: &str) -> Result<Vec<KeyModel>> {
    let keys = cache::key::get_keys(db, key_id).await?;
    if !keys.is_empty() {
        Ok(keys)
    } else {
        Err(ServiceError::NotFount(format!("key is nonexistent")))
    }
}

pub async fn get_main_key(
    rd: &RdConn,
    db: &DbConn,
    key_id: &str,
) -> Result<KeyModel> {
    let meta = get_main_key_meta(rd, db, key_id).await?;
    get_version_key(db, key_id, &meta.version).await
}

pub async fn get_version_key(
    db: &DbConn,
    key_id: &str,
    version: &str,
) -> Result<KeyModel> {
    cache::key::get_keys(db, key_id)
        .await?
        .into_iter()
        .find(|key| key.version.eq(version))
        .ok_or(ServiceError::NotFount(format!(
            "key_id is invalid, key_id: {}",
            key_id
        )))
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
