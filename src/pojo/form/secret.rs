use chrono::Duration;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DurationSeconds};
use utoipa::ToSchema;

use crate::common::algorithm::{
    KeyOrigin, KeySpec, KeyUsage, WrappingKeyAlgorithm, WrappingKeySpec,
};
#[serde_as]
#[derive(Serialize, Deserialize, ToSchema, Clone)]
pub struct SecretCreateForm {
    #[serde(rename = "key_usage")]
    pub usage: KeyUsage,
    pub origin: KeyOrigin,
    #[serde(rename = "key_spec")]
    pub spec: KeySpec,
    pub enable_automatic_rotation: bool,
    #[serde_as(as = "DurationSeconds<String>")]
    pub rotation_interval: Duration,
}

#[derive(Serialize, Deserialize, ToSchema, Clone)]
pub struct SecretImportForm {
    pub key_id: String,
    pub wrapping_algorithm: WrappingKeyAlgorithm,
    pub wrapping_ey_spec: WrappingKeySpec,
}

#[serde_as]
#[derive(Serialize, Deserialize, ToSchema, Clone)]
pub struct SecretImportResult {
    pub key_id: String,
    pub token: String,
    #[serde_as(as = "DurationSeconds<String>")]
    pub expires_in: Duration,
    #[serde(rename = "public_key")]
    pub pub_key: String,
}
