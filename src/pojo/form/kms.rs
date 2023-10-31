use sea_orm::entity::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use utoipa::ToSchema;

use crate::{
    common::{errors::ServiceError, utils::generate_b62},
    entity::kms,
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
