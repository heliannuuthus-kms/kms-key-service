//! `SeaORM` Entity. Generated by sea-orm-codegen 0.12.3

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

use crate::common::secrets::types::KeyType;

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
    #[sea_orm(column_name = "_id", primary_key)]
    #[serde(skip)]
    pub id: i64,
    #[sea_orm(unique)]
    pub key_id: String,
    pub kms_id: String,
    pub key_type: KeyType,
    #[sea_orm(column_type = "Text")]
    pub key_pair: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub pub_key: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub pri_key: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
