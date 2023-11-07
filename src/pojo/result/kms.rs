use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema)]
pub struct KmsResult {
    pub kms_id: String,
    pub name: String,
    pub description: Option<String>,
}
