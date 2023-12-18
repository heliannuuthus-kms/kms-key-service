use anyhow::Context;
use redis::{aio::Connection, AsyncCommands, Client};

use crate::common::{configs::env_var, errors::Result};

pub type RdConn = redis::Client;

pub async fn init() -> Result<RdConn> {
    Ok(Client::open(format!(
        "redis://{}:{}",
        env_var::<String>("REDIS_HOST"),
        env_var::<u16>("REDIS_PORT")
    ))
    .with_context(|| {
        tracing::error!("init redis failed");
        "init redis failed"
    })?)
}

pub async fn rdconn(rd: &Client) -> Result<Connection> {
    Ok(rd.get_async_connection().await.with_context(|| {
        tracing::error!("borrow redis connection failed");
        "borrow redis connection failed"
    })?)
}

pub async fn redis_get<T>(rd: &Client, key: &str) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    let mut conn = rdconn(rd).await?;
    let value: Option<String> = conn.get(key).await?;
    match value {
        Some(v) => Ok(Some(
            serde_json::from_str::<T>(&v)
                .context(format!("redis GET serlialize failed: {}", key))?,
        )),
        None => Ok(None),
    }
}

#[macro_export]
macro_rules! encode_key {
    ($prefix:expr, $($param:expr),*) => {
        format!("{}:{}", $prefix, vec![$($param),*].join("_"))
    };
}
