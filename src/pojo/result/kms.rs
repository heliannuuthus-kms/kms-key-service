use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema)]
pub struct KmsResult {
    pub kms_id: String,
    pub name: String,
    pub description: Option<String>,
    pub aksk: Vec<KmsAkskResult>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct KmsAkskResult {
    #[serde(rename = "ak")]
    pub access_key: String,
    #[serde(rename = "sk")]
    pub secret_key: String,
}
