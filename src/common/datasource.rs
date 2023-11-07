use std::string::String;

use anyhow::Context;
use chrono::Duration;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};

use super::errors::Result;
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
