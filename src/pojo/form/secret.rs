use std::time::Duration;

use actix_web::error::ErrorBadRequest;
use ring::{aead::{quic::AES_128, AES_128_GCM, AES_256_GCM}, rand::SystemRandom, signature::RSA_PKCS1_2048_8192_SHA256};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    common::{
        configs::env_var_default,
        enums::{KeyOrigin, KeySpec, KeyType, KeyUseage},
        errors::ServiceError,
        utils::gen_id,
    },
    pojo::po::secret::{Secret, SecretMeta},
};
#[derive(Serialize, Deserialize, ToSchema, Clone)]
pub struct SecretCreateForm {
    #[serde(rename = "key_usage")]
    usage: KeyUseage,
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

        let key_usage: KeyUseage = self.spec.try_into()?;
        let key_type: KeyType = self.spec.into();

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

        // fill secret key content
        if self.enable_automatic_rotation {
            secret_meta.rotation_interval = env_var_default::<u64>(
                "secrets_rotation_interval",
                60 * 60 * 24 * 30,
            );
        }

       let key_size =  match self.spec {
            KeySpec::Aes128 => {
                AES_128_GCM.key_len()        
            }
            KeySpec::Aes256 => {
                AES_256_GCM.key_len()            
            },
            KeySpec::Rsa2048 => {
                
            },
            KeySpec::Rsa3072 => {
                
            },
            KeySpec::EcP256 => todo!(),
            KeySpec::EcP256K => todo!(),
        }

        match key_type {
            KeyType::Symmetric => {}
            KeyType::Asymmetric => {}
            KeyType::Unknown => {
                return Err(ServiceError::Reponse(ErrorBadRequest(
                    "unknown key type",
                )))
            }
        }

        Ok((secret, secret_meta))
    }
}

impl SecretCreateForm {
    pub fn replenish_symmetric(&mut self) {}

    pub fn replenish_asymmetric(&mut self) {}
}
