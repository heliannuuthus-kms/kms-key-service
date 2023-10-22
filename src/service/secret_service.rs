use sea_orm::*;

use crate::{
    common::{
        errors::{Result, ServiceError},
        kits::{
            self,
            algorithm::{KeyOrigin, KeyState, KeyType},
        },
        utils,
    },
    entity::{t_secret as TSecret, t_secret_meta as TSecretMeta},
    pojo::form::secret::SecretCreateForm,
    repository::secret_repository,
};

pub async fn create_secret(
    db: &DbConn,
    data: &SecretCreateForm,
) -> Result<String> {
    let key_id = &utils::gen_b62_id(32);

    let key_alg = kits::algorithm::select_key_alg(data.spec);
    if !key_alg.key_usage.contains(&data.usage) {
        return Err(ServiceError::BadRequest(format!(
            "unsupported key usage({:?})",
            data.usage
        )));
    }

    let mut secret = TSecret::Model {
        key_id: key_id.to_string(),
        key_type: key_alg.key_type,
        primary_key_id: "#".to_string(),
        ..Default::default()
    };

    let mut secret_meta = TSecretMeta::Model {
        key_id: key_id.to_string(),
        origin: data.origin,
        spec: data.spec,
        usage: data.usage,
        rotation_interval: data.rotation_interval.num_seconds(),
        ..Default::default()
    };

    // fill secret rotation interval
    if data.enable_automatic_rotation {
        secret_meta.rotation_interval = data.rotation_interval.num_seconds();
        // 往某个队列里投放密钥轮换的任务
    }

    if KeyOrigin::Kms.eq(&secret_meta.origin) {
        let (pri_key, pub_key) = (key_alg.generator)()?;

        if KeyType::Symmetric.eq(&key_alg.key_type) {
            secret.key_pair = Some(pri_key);
        } else {
            secret.pub_key = Some(pub_key);
            secret.pri_key = Some(pri_key);
        }
        secret_repository::insert_secret(db, &secret).await?;
    } else {
        secret_meta.state = KeyState::Pendingimport;
        // 存入缓存
        
    }
    secret_repository::insert_secret_meta(db, &secret_meta).await?;
    Ok(secret_meta.key_id.to_owned())
}
