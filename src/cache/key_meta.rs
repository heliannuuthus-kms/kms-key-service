use redis::AsyncCommands;
use sea_orm::DbConn;

use super::prelude::{rdconn, redis_get, RdConn};
use crate::{
    common::{configs::env_var_default, errors::Result},
    entity::prelude::*,
    repository::key_meta_repository,
};

const META_KEY: &str = "META_KEY_EXPIRES";

pub fn encode_key(key_id: &str) -> String {
    format!("kms:key:meta:{}", key_id)
}

pub async fn get_key_metas(
    rd: &RdConn,
    db: &DbConn,
    key_id: &str,
) -> Result<Vec<KeyMetaModel>> {
    Ok(match redis_get::<Vec<KeyMetaModel>>(rd, key_id).await? {
        Some(data) => data,
        None => {
            let key_metas =
                key_meta_repository::select_key_meta(db, key_id).await?;
            let mut conn = rdconn(rd).await?;
            conn.set_ex(
                &encode_key(key_id),
                serde_json::to_string(&key_metas).unwrap(),
                env_var_default(META_KEY, 60 * 30),
            )
            .await?;
            key_metas
        }
    })
}

pub async fn remove_key_meta(rd: &RdConn, key_id: &str) -> Result<()> {
    let mut conn = rdconn(rd).await?;
    conn.del(encode_key(key_id)).await?;
    Ok(())
}
