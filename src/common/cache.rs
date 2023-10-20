use anyhow::Context;
use chrono::Duration;
use redis::{aio::Connection, Client, FromRedisValue, ToRedisArgs};

use super::{configs::env_var, errors::Result};

pub async fn init() -> Result<Client> {
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

pub async fn borrow(client: &Client) -> Result<Connection> {
    Ok(client.get_async_connection().await.with_context(|| {
        tracing::error!("borrow redis connection failed");
        "borrow redis connection failed"
    })?)
}

pub async fn redis_set<T>(client: &Client, key: &str, value: T) -> Result<()>
where
    T: serde::Serialize,
{
    let mut conn = borrow(client).await?;

    redis::cmd("SET")
        .arg(key)
        .arg(serde_json::to_string(&value).context(format!(
            "redis execute SET serialized failed: {} ",
            key
        ))?)
        .query_async(&mut conn)
        .await
        .context(format!("redis SET value failed: {}", key))?;

    Ok(())
}

pub async fn redis_get<T>(client: &Client, key: &str) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    let mut conn = borrow(client).await?;
    let value: Option<String> = redis::cmd("GET")
        .arg(key)
        .query_async(&mut conn)
        .await
        .context(format!("redis execute GET faild: {}", key))?;
    match value {
        Some(v) => Ok(Some(
            serde_json::from_str::<T>(&v)
                .context(format!("redis GET serlialize failed: {}", key))?,
        )),
        None => Ok(None),
    }
}

pub async fn redis_setex<T>(
    client: &Client,
    key: &str,
    value: T,
    expires_in: Duration,
) -> Result<()>
where
    T: serde::Serialize,
{
    let mut conn = borrow(client).await?;
    redis::cmd("SETEX")
        .arg(key)
        .arg(expires_in.num_seconds())
        .arg(
            serde_json::to_string(&value)
                .context(format!("redis SETEX serialize failed {}", key))?,
        )
        .query_async(&mut conn)
        .await
        .context(format!("redis SETEX failed {}", key))?;
    Ok(())
}

pub async fn redis_hgetall<T: FromRedisValue>(
    client: &Client,
    key: &str,
) -> Result<T> {
    let mut conn = borrow(client).await?;
    Ok(redis::cmd("HGETALL")
        .arg(key)
        .query_async(&mut conn)
        .await
        .context(format!("redis HSET failed {}", key))?)
}

pub async fn redis_hsetex<K, V>(
    client: &Client,
    key: &str,
    value: Vec<(K, V)>,
    expires_in: Option<Duration>,
) -> Result<()>
where
    K: ToRedisArgs,
    V: ToRedisArgs,
{
    let mut conn = borrow(client).await?;

    redis::cmd("HSET")
        .arg(key)
        .arg(&value)
        .query_async(&mut conn)
        .await
        .context(format!("redis HSET failed {}", key))?;
    if let Some(exp) = expires_in {
        redis::cmd("EXPIRE")
            .arg(key)
            .arg(exp.num_seconds())
            .query_async(&mut conn)
            .await
            .context(format!("redis EXPIRE failed {}", key))?;
    }

    Ok(())
}
