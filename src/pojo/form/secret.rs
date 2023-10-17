use actix_web::error::ErrorBadRequest;
use chrono::Duration;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DurationSeconds};
use utoipa::ToSchema;

use crate::{
    common::{
        algorithm::{
            KeyAlgorithm, KeyOrigin, KeySpec, KeyType, KeyUsage,
            WrappingKeyAlgorithm, WrappingKeySpec, AES_128, AES_256, EC_P256,
            EC_P256K, RSA_2048, RSA_3072,
        },
        errors::ServiceError,
        utils::gen_id,
    },
    pojo::po::secret::{Secret, SecretMeta},
};
#[serde_as]
#[derive(Serialize, Deserialize, ToSchema, Clone)]
pub struct SecretCreateForm {
    #[serde(rename = "key_usage")]
    usage: KeyUsage,
    origin: KeyOrigin,
    #[serde(rename = "key_spec")]
    spec: KeySpec,
    enable_automatic_rotation: bool,
    #[serde_as(as = "DurationSeconds<String>")]
    rotation_interval: Duration,
}

impl TryInto<(Secret, SecretMeta)> for SecretCreateForm {
    type Error = ServiceError;

    fn try_into(self) -> Result<(Secret, SecretMeta), Self::Error> {
        let key_id = &gen_id(32);

        let key_alg: &KeyAlgorithm = match self.spec {
            KeySpec::Aes128 => &AES_128,
            KeySpec::Aes256 => &AES_256,
            KeySpec::Rsa2048 => &RSA_2048,
            KeySpec::Rsa3072 => &RSA_3072,
            KeySpec::EcP256 => &EC_P256,
            KeySpec::EcP256K => &EC_P256K,
        };

        if !key_alg.key_usage.contains(&self.usage) {
            return Err(ServiceError::Reponse(ErrorBadRequest(format!(
                "unsupported key usage({:?})",
                self.usage
            ))));
        }

        let mut secret = Secret {
            key_id: key_id.to_string(),
            key_type: key_alg.key_type,
            primary_key_id: "#".to_string(),
            ..Default::default()
        };

        let mut secret_meta = SecretMeta {
            key_id: key_id.to_string(),
            origin: self.origin,
            spec: self.spec,
            usage: self.usage,
            rotation_interval: self.rotation_interval.num_seconds(),
            ..Default::default()
        };

        // fill secret rotation interval
        if self.enable_automatic_rotation {
            secret_meta.rotation_interval =
                self.rotation_interval.num_seconds();
        }

        if KeyOrigin::Kms.eq(&secret_meta.origin) {
            let (pri_key, pub_key) = (key_alg.generator)()?;

            if KeyType::Symmetric.eq(&key_alg.key_type) {
                secret.key_pair = pri_key;
            } else {
                secret.pub_key = pri_key;
                secret.pri_key = pub_key;
            }
        }

        Ok((secret, secret_meta))
    }
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
