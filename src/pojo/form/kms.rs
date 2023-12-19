use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use utoipa::ToSchema;

use crate::{
    common::{configs::Patch, errors::ServiceError, utils::generate_b62},
    entity::{kms, prelude::KmsModel},
};

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct KmsCreateBody {
    name: String,
    description: Option<String>,
}

impl TryFrom<KmsCreateBody> for KmsModel {
    type Error = ServiceError;

    fn try_from(value: KmsCreateBody) -> Result<Self, Self::Error> {
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
pub struct KmsPatchForm {
    pub name: Option<String>,
    pub description: Option<String>,
}

impl Patch<KmsPatchForm> for KmsModel {
    fn patched(&mut self, patched: KmsPatchForm) -> &mut Self {
        if let Some(name) = patched.name {
            self.name = name;
        };
        if let Some(description) = patched.description {
            self.description = Some(description);
        };
        self
    }
}
