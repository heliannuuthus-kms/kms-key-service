use std::time::Duration;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::common::enums::{KeyOrigin, KeySpec, KeyUseage};
#[derive(Serialize, Deserialize, ToSchema, Clone)]
pub struct SecretCreateForm {
    key_useage: KeyUseage,
    origin: KeyOrigin,
    enable_automatic_rotation: bool,
    rotation_interval: Duration,
    key_spec: KeySpec,
}

