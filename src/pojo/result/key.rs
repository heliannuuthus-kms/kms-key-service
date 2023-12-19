use chrono::{Duration, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DurationSeconds};
use utoipa::ToSchema;

use crate::{
    crypto::types::{
        KeyOrigin, KeySpec, KeyState, KeyType, KeyUsage, WrappingKeyAlgorithm,
        WrappingKeySpec,
    },
    entity::prelude::*,
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
    pub version: String,
    pub primary_key_version: String,
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotate_interval: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_rotated_at: Option<NaiveDateTime>,
}

impl Into<KeyCreateResult> for KeyMetaModel {
    fn into(self) -> KeyCreateResult {
        KeyCreateResult {
            kms_id: self.kms_id.to_owned(),
            key_id: self.key_id.to_owned(),
            key_origin: self.origin,
            key_spec: self.spec,
            key_usage: self.usage,
            key_state: self.state,
            version: self.version.to_owned(),
            primary_key_version: self.primary_version.to_owned(),
            rotate_interval: Some(self.rotation_interval)
                .filter(|ri| ri == &0)
                .map(Duration::seconds),
            next_rotated_at: Some(self.rotation_interval)
                .filter(|ri| ri == &0)
                .map(|ri| {
                    let rotation = Duration::seconds(ri);
                    (Utc::now() + rotation).naive_local()
                }),
            ..Default::default()
        }
    }
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

#[derive(Serialize, Deserialize, Clone, ToSchema)]

pub struct KeyVersionResult {
    #[serde(skip)]
    pub id: i64,
    pub key_id: String,
    pub version: String,
    pub primary_version: String,
    pub created_at: NaiveDateTime,
}

impl From<KeyMetaModel> for KeyVersionResult {
    fn from(value: KeyMetaModel) -> Self {
        KeyVersionResult {
            id: value.id,
            key_id: value.key_id,
            version: value.version,
            primary_version: value.primary_version,
            created_at: value.created_at,
        }
    }
}
