use chrono::{DateTime};
use serde::{Deserialize, Serialize};
use sqlx::types::chrono::Utc;

use crate::common::enums::{KeyOrigin, KeySpec, KeyState, KeyType, KeyUsage};

#[derive(Serialize, Deserialize, Clone, sqlx::FromRow, Default)]
pub struct Secret {
    pub key_id: String,
    pub primary_key_id: String,
    pub key_type: KeyType,
    pub key_pair: String,
    pub pub_key: String,
    pub pri_key: String,
}

#[derive(Serialize, Deserialize, Clone, sqlx::FromRow, Default)]
pub struct SecretMeta {
    pub key_id: String,
    #[serde(rename = "key_spec")]
    pub spec: KeySpec,
    #[serde(rename = "key_origin")]
    pub origin: KeyOrigin,
    pub description: String,
    #[serde(rename = "key_state")]
    pub state: KeyState,
    #[serde(rename = "key_usage")]
    pub usage: KeyUsage,
    pub rotation_interval: u64,
    pub creator: String,
    pub material_expire_at: Option<DateTime<Utc>>,
    pub last_rotation_at: Option<DateTime<Utc>>,
    pub deletion_at: Option<DateTime<Utc>>,
}
