use redis::AsyncCommands;
use sea_orm::DbConn;

use super::prelude::{rdconn, redis_get, RdConn};
use crate::{
    common::{configs::env_var_default, errors::Result},
    entity::prelude::KmsModel,
    repository::kms_repository,
};

const KMS_KEY: &str = "KMS_EXPIRES";

fn encode_key(kms_id: &str) -> String {
    format!("kms:keys:kms:{}", kms_id)
}

pub async fn get_kms(
    rd: &RdConn,
    db: &DbConn,
    kms_id: &str,
) -> Result<Option<KmsModel>> {
    let cache_key = &encode_key(kms_id);
    Ok(match redis_get::<KmsModel>(rd, cache_key).await? {
        Some(model) => Some(model),
        None => {
            if let Some(model) = kms_repository::select_kms(db, kms_id).await? {
                let mut conn = rdconn(rd).await?;
                conn.set_ex(
                    cache_key,
                    serde_json::to_string(&model).unwrap(),
                    env_var_default(KMS_KEY, 60 * 30),
                )
                .await?;
                Some(model)
            } else {
                None
            }
        }
    })
}

pub async fn remove_kms(rd: &RdConn, kms_id: &str) -> Result<()> {
    let mut conn = rdconn(rd).await?;
    conn.del(encode_key(kms_id)).await?;
    Ok(())
}
