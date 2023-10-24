use chrono::Duration;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DurationSeconds};
use utoipa::ToSchema;

use crate::common::secrets::algorithm::{
    KeySpec, WrappingKeyAlgorithm, WrappingKeySpec,
};

#[serde_as]
#[derive(Serialize, Deserialize, Clone, ToSchema)]
pub struct SecretMaterialImportParamsResult {
    pub key_id: String,
    pub token: String,
    #[serde(rename = "public_key")]
    pub pub_key: String,
    pub key_spec: WrappingKeySpec,
    #[serde_as(as = "DurationSeconds<String>")]
    pub expires_in: Duration,
}
