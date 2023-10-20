//! `SeaORM` Entity. Generated by sea-orm-codegen 0.12.3

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

use crate::common::kits::algorithm::KeyType;

#[derive(
    Clone,
    Debug,
    PartialEq,
    DeriveEntityModel,
    Eq,
    Serialize,
    Deserialize,
    Default,
)]
#[sea_orm(table_name = "t_secret")]
pub struct Model {
    #[sea_orm(primary_key)]
    #[serde(skip_deserializing)]
    pub id: i64,
    #[sea_orm(unique)]
    pub key_id: String,
    pub primary_key_id: String,
    pub key_type: KeyType,
    pub key_pair: Option<String>,
    pub pub_key: Option<String>,
    pub pri_key: Option<String>,
    #[serde(skip_deserializing)]
    pub updated_at: DateTimeUtc,
    #[serde(skip_deserializing)]
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
