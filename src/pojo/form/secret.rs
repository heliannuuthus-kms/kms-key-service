use std::time::Duration;

use actix_web::error::ErrorBadRequest;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    common::{
        algorithm::{
            KeyAlgorithm, AES_128, AES_256, EC_P256, EC_P256K, RSA_2048,
            RSA_3072,
        },
        configs::env_var_default,
        enums::{KeyOrigin, KeySpec, KeyType, KeyUsage},
        errors::ServiceError,
        utils::gen_id,
    },
    pojo::po::secret::{Secret, SecretMeta},
};
#[derive(Serialize, Deserialize, ToSchema, Clone)]
pub struct SecretCreateForm {
    #[serde(rename = "key_usage")]
    usage: KeyUsage,
    origin: KeyOrigin,
    #[serde(rename = "key_spec")]
    spec: KeySpec,
    enable_automatic_rotation: bool,
    rotation_interval: Duration,
}

impl TryInto<(Secret, SecretMeta)> for SecretCreateForm {
    type Error = ServiceError;

    fn try_into(self) -> Result<(Secret, SecretMeta), Self::Error> {
        let key_id = &gen_id(128);

        let key_usage: KeyUsage = self.spec.try_into()?;
        let key_type: KeyType = self.spec.into();

        let key_alg: &KeyAlgorithm = match self.spec {
            KeySpec::Aes128 => &AES_128,
            KeySpec::Aes256 => &AES_256,
            KeySpec::Rsa2048 => &RSA_2048,
            KeySpec::Rsa3072 => &RSA_3072,
            KeySpec::EcP256 => &EC_P256,
            KeySpec::EcP256K => &EC_P256K,
        };

        if !key_alg.key_usage.contains(&key_usage) {
            return Err(ServiceError::Reponse(ErrorBadRequest(format!(
                "unsupported key usage({:?})",
                key_usage
            ))));
        }

        let (pri_key, pub_key) = (key_alg.generator)()?;

        let mut secret = Secret {
            key_id: key_id.to_string(),
            key_type,
            primary_key_id: "#".to_string(),
            ..Default::default()
        };

        let mut secret_meta = SecretMeta {
            key_id: key_id.to_string(),
            origin: self.origin,
            spec: self.spec,
            usage: key_usage,
            rotation_interval: self.rotation_interval.as_secs(),
            ..Default::default()
        };

        // fill secret rotation interval
        if self.enable_automatic_rotation {
            secret_meta.rotation_interval = env_var_default::<u64>(
                "secrets_rotation_interval",
                60 * 60 * 24 * 30,
            );
        }

        if KeyType::Symmetric.eq(&key_alg.key_type) {
            secret.key_pair = pri_key;
        } else {
            secret.pub_key = pri_key;
            secret.pri_key = pub_key;
        }

        Ok((secret, secret_meta))
    }
}
