use chrono::{DateTime, Duration, FixedOffset};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DurationSeconds};
use utoipa::ToSchema;

use crate::common::encrypto::types::{
    KeyOrigin, KeySpec, KeyState, KeyType, KeyUsage,
};

#[serde_as]
#[derive(Serialize, Deserialize, Clone, ToSchema, Default)]
pub struct KeyCreateResult {
    pub kms_id: String,
    pub key_id: String,
    #[serde(rename = "type")]
    pub key_type: KeyType,
    #[serde(rename = "origin")]
    pub key_origin: KeyOrigin,
    #[serde(rename = "spec")]
    pub key_spec: KeySpec,
    #[serde(rename = "usage")]
    pub key_usage: KeyUsage,
    #[serde(rename = "state")]
    pub key_state: KeyState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expired_at: Option<DateTime<FixedOffset>>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, ToSchema)]
pub struct KeyMaterialImportParamsResult {
    pub key_id: String,
    pub token: String,
    #[serde(rename = "public_key")]
    pub pub_key: String,
    #[serde(rename = "private_key", skip_serializing_if = "String::is_empty")]
    pub pri_key: String,
    #[serde_as(as = "DurationSeconds<String>")]
    pub expires_in: Duration,
}
