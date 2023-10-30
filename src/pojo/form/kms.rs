use chrono::{Duration, Local};
use sea_orm::entity::*;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DurationSeconds};
use utoipa::ToSchema;

use crate::{
    common::{errors::ServiceError, utils::generate_b62},
    entity::{kms, kms_aksk},
};

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct KmsCreateForm {
    name: String,
    description: Option<String>,
}

impl TryFrom<KmsCreateForm> for kms::Model {
    type Error = ServiceError;

    fn try_from(value: KmsCreateForm) -> Result<Self, Self::Error> {
        Ok(kms::Model {
            kms_id: generate_b62(32)?,
            name: value.name,
            description: value.description,
            ..Default::default()
        })
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct KmsUpdateForm {
    pub kms_id: String,
    pub name: String,
    pub description: Option<String>,
}

impl TryFrom<KmsUpdateForm> for kms::Model {
    type Error = ServiceError;

    fn try_from(value: KmsUpdateForm) -> Result<Self, Self::Error> {
        Ok(kms::Model {
            kms_id: value.kms_id,
            name: value.name,
            description: value.description,
            ..Default::default()
        })
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct KmsAkskUpdateForm {
    kms_id: String,
    #[serde_as(as = "Option<DurationSeconds<String>>")]
    window: Option<Duration>,
}

impl TryFrom<KmsAkskUpdateForm> for kms_aksk::Model {
    type Error = ServiceError;

    fn try_from(value: KmsAkskUpdateForm) -> Result<Self, Self::Error> {
        let mut model = kms_aksk::Model {
            kms_id: value.kms_id,
            ..Default::default()
        };
        if let Some(win) = value.window {
            model.expired_at = Some((Local::now() + win).fixed_offset())
        }
        Ok(model)
    }
}
