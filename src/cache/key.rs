use chrono::Duration;
use lazy_static::lazy_static;
use moka::future::Cache;
use sea_orm::DbConn;

use crate::{
    common::errors::Result, entity::prelude::KeyModel,
    repository::key_repository,
};
pub const KEY_CACHE_KEY: &str = "key_cache";

lazy_static! {
    static ref KEY_CACHE: Cache<String, Vec<KeyModel>> =
        moka::future::CacheBuilder::new(64 * 1024 * 1024)
            .name(KEY_CACHE_KEY)
            .time_to_idle(Duration::minutes(5).to_std().unwrap())
            .time_to_live(Duration::minutes(30).to_std().unwrap())
            .build();
}

fn encode_key(key_id: &str) -> String {
    format!("mokaKeyCache:{}", key_id)
}

pub async fn get_keys(db: &DbConn, key_id: &str) -> Result<Vec<KeyModel>> {
    let cache_key = encode_key(key_id);
    Ok(match KEY_CACHE.get(&cache_key).await {
        Some(model) => model,
        None => {
            let models = key_repository::select_key(db, key_id).await?;
            if !models.is_empty() {
                KEY_CACHE.insert(cache_key, models.clone()).await;
            }
            models
        }
    })
}

pub async fn remove_keys(key_id: &str) -> Result<()> {
    KEY_CACHE.remove(&encode_key(key_id)).await;
    Ok(())
}
