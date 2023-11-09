use std::string::String;

use anyhow::Context;
use chrono::Duration;
use num::ToPrimitive;
use num_bigint::BigInt;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use utoipa::{IntoParams, ToSchema};

use super::{errors::Result, utils};
use crate::{common::configs::env_var, entity::prelude::*};

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

pub fn to_next(id: i64) -> String {
    let bigint = BigInt::from(id);
    let bytes = bigint.to_signed_bytes_le();
    utils::encode64_no_padding(&bytes)
}

pub fn from_next(next: &str) -> Result<i64> {
    let bytes = utils::decode64_no_padding(next)?;
    let bigint: BigInt = BigInt::from_signed_bytes_be(&bytes);
    Ok(bigint.to_i64().context("next convert i64 failed")?)
}
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, IntoParams)]
pub struct Paginator {
    pub next: Option<String>,
    pub limit: Option<u64>,
    pub params: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
#[aliases(PaginatedKeyAliasModels = PaginatedResult<Vec<KeyAliasModel>>)]
pub struct PaginatedResult<T: Serialize> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    pub data: T,
}
