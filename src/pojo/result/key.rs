use chrono::{DateTime, Duration, FixedOffset};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DurationSeconds};
use utoipa::ToSchema;

use crate::common::encrypto::types::{
    KeyOrigin, KeySpec, KeyState, KeyType, KeyUsage, WrappingKeyAlgorithm,
    WrappingKeySpec,
};

#[serde_as]
#[derive(Serialize, Deserialize, Clone, ToSchema, Default)]
pub struct KeyCreateResult {
    pub kms_id: String,
    pub key_id: String,
    pub key_type: KeyType,
    pub key_origin: KeyOrigin,
    pub key_spec: KeySpec,
    pub key_usage: KeyUsage,
    pub key_state: KeyState,
    pub primary_key_version: String,
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotate_interval: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_rotated_at: Option<DateTime<FixedOffset>>,
}

#[derive(Serialize, Deserialize, Clone, ToSchema)]

pub struct KeyMaterialImportParams {
    pub token: String,
    pub private_key: String,
    pub wrapping_spec: WrappingKeySpec,
    pub wrapping_algorithm: WrappingKeyAlgorithm,
}
#[serde_as]
#[derive(Serialize, Deserialize, Clone, ToSchema)]
pub struct KeyMaterialImportParamsResult {
    pub key_id: String,
    pub token: String,
    #[serde(rename = "public_key")]
    pub pub_key: String,
    #[serde_as(as = "DurationSeconds<String>")]
    pub expires_in: Duration,
}
