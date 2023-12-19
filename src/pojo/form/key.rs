use std::fmt::Debug;

use chrono::Duration;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DurationSeconds};
use utoipa::{IntoParams, ToSchema};

use crate::{
    crypto::types::{
        KeyOrigin, KeySpec, KeyUsage, WrappingKeyAlgorithm, WrappingKeySpec,
    },
    entity::prelude::KeyMetaModel,
};
#[serde_as]
#[derive(Serialize, Deserialize, ToSchema, Clone, Debug)]
pub struct KeyCreateBody {
    pub kms_id: String,
    pub description: Option<String>,
    #[serde(rename = "key_usage")]
    pub usage: KeyUsage,
    #[serde(rename = "key_origin")]
    pub origin: KeyOrigin,
    #[serde(rename = "key_spec")]
    pub spec: KeySpec,
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub rotation_interval: Option<Duration>,
}

impl From<KeyCreateBody> for KeyMetaModel {
    fn from(val: KeyCreateBody) -> Self {
        KeyMetaModel {
            kms_id: val.kms_id.to_owned(),
            spec: val.spec,
            origin: val.origin,
            description: val.description,
            state: crate::crypto::types::KeyState::Enabled,
            usage: val.usage,
            rotation_interval: val
                .rotation_interval
                .map(|ri| ri.num_seconds())
                .unwrap_or_default(),
            ..Default::default()
        }
    }
}

#[derive(Serialize, Deserialize, ToSchema, Clone, Debug, IntoParams)]
pub struct KeyImportParamsQuery {
    pub key_id: String,
    pub wrapping_algorithm: WrappingKeyAlgorithm,
    pub wrapping_key_spec: WrappingKeySpec,
}

#[serde_as]
#[derive(Serialize, Deserialize, ToSchema, Clone)]
pub struct KeyImportBody {
    pub key_id: String,
    pub encrypted_key_material: String,
    pub import_token: String,
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub key_material_expire_in: Option<Duration>,
}

impl Debug for KeyImportBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyImportForm")
            .field("key_id", &self.key_id)
            .field("import_token", &self.import_token)
            .field("key_material_expire_in", &self.key_material_expire_in)
            .finish()
    }
}
