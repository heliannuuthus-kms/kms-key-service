use std::string::String;

use anyhow::Context;
use chrono::Duration;
use sea_orm::{ConnectOptions, Database, DatabaseBackend, DatabaseConnection};
use serde::{ser::SerializeSeq, Deserialize};

use super::{
    algorithm::{KeyOrigin, KeySpec, KeyState, KeyType, KeyUsage},
    errors::{Result, ServiceError},
};
use crate::common::configs::env_var;

pub async fn init() -> Result<DatabaseConnection> {
    let mut opt = ConnectOptions::new(env_var::<String>("DATABASE_URL"));
    opt.max_connections(5)
        .acquire_timeout(Duration::seconds(2).to_std().unwrap())
        .idle_timeout(Duration::seconds(60).to_std().unwrap())
        .sqlx_logging(true)
        .sqlx_logging_level(tracing::log::LevelFilter::Debug);
    Ok(Database::connect(opt).await.with_context(|| {
        tracing::error!("init datasource failed");
        "init datasource failed"
    })?)
}

pub fn to_vec<S>(
    v: &Option<String>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let str_splitor = match v {
        Some(vv) => vv.split(',').map(|s| s.to_string()).collect(),
        None => vec![],
    };
    let mut seq_serializer: <S as serde::Serializer>::SerializeSeq =
        serializer.serialize_seq(Some(str_splitor.len()))?;
    for strs in str_splitor {
        seq_serializer.serialize_element(&strs)?;
    }
    seq_serializer.end()
}

pub fn from_vec<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let str_sequence = Vec::<String>::deserialize(deserializer)?;
    if str_sequence.is_empty() {
        Ok(None)
    } else {
        Ok(Some(str_sequence.join(",")))
    }
}
