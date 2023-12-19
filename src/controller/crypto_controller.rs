use axum::{
    body,
    extract::{Path, State},
    response::IntoResponse,
};
use pojo::form::crypto::KeyCryptoBody;

use crate::{
    common::{
        axum::Json,
        errors::{Result, ServiceError},
        utils::{decode64, encode64},
    },
    crypto::{
        algorithm::{self, CryptoAdaptor, EncryptKits},
        symm::generate_iv,
    },
    pojo,
    service::{key_meta_service, key_service},
    States,
};

#[utoipa::path(
  post,
  path="/encrypt/{}",
  operation_id = "",
  context_path= "/keys/{key_id}",
  params(
    ("key_id" = String, Path, description="kms 标识"),
  ),
  responses(
      (status = 200, description = "密文信息", body = String, content_type="application/json"),
      (status = 400, description = "illegal params")
  ),
)]
pub async fn encrypt(
    Path(key_id): Path<String>,
    version: Option<Path<String>>,
    State(States { db, rd, .. }): State<States>,
    Json(body): Json<KeyCryptoBody>,
) -> Result<impl IntoResponse> {
    tracing::info!(
        "encrypt data, key_id: {}, version: {:?}, body {:?}",
        key_id,
        version,
        body
    );
    if body.plaintext.is_none() {
        return Err(ServiceError::BadRequest(format!("required plaintext")));
    }

    let (key, key_meta) = match version {
        Some(v) => {
            futures::join!(
                key_service::get_version_key(&db, &key_id, v.as_str()),
                key_meta_service::get_version_key_meta(
                    &rd,
                    &db,
                    &key_id,
                    v.as_str()
                )
            )
        }
        None => futures::join!(
            key_service::get_main_key(&rd, &db, &key_id),
            key_meta_service::get_main_key_meta(&rd, &db, &key_id)
        ),
    };
    let k = key?;
    let km = key_meta?;

    match body.algorithm {
        crate::crypto::types::KeyAlgorithm::AesCBC => todo!(),
        crate::crypto::types::KeyAlgorithm::AesGCM => todo!(),
        crate::crypto::types::KeyAlgorithm::RsaOAEP => todo!(),
        crate::crypto::types::KeyAlgorithm::SM2PKE => todo!(),
        crate::crypto::types::KeyAlgorithm::Sm4CTR => todo!(),
        crate::crypto::types::KeyAlgorithm::Sm4CBC => todo!(),
        crate::crypto::types::KeyAlgorithm::EciesSha1 => todo!(),
        crate::crypto::types::KeyAlgorithm::RsaPSS => todo!(),
        crate::crypto::types::KeyAlgorithm::RsaPKCS1 => todo!(),
        crate::crypto::types::KeyAlgorithm::Ecdsa => todo!(),
        crate::crypto::types::KeyAlgorithm::SM2DSA => todo!(),
    };

    let (_id, size) = km.spec.into();

    let factory = algorithm::select_factory(body.algorithm)?;

    let iv = body.iv.map_or(generate_iv(size), |iv| decode64(&iv))?;

    let kits = EncryptKits {
        iv,
        aad: todo!(),
        tag: todo!(),
    };

    factory.encrypt(&key.pub_key.unwrap(), body.plaintext, &mut ca);

    Ok("")
}

#[utoipa::path(
  post,
  path="/encrypt",
  operation_id = "增强加密，即仅用主密钥主版本",
  context_path= "/keys/{key_id}",
  params(
    ("key_id" = String, Path, description="kms 标识"),
  ),
  responses(
      (status = 200, description = "密文信息", body = String, content_type="application/json"),
      (status = 400, description = "illegal params")
  ),
)]
pub async fn advance_encrypt() -> Result<impl IntoResponse> {
    Ok("")
}

#[utoipa::path(
  post,
  path="/decrypt",
  operation_id = "使用默认密钥解密",
  context_path= "/keys/{key_id}",
  params(
    ("key_id" = String, Path, description="kms 标识"),
  ),
  responses(
      (status = 200, description = "密文信息", body = String, content_type="application/json"),
      (status = 400, description = "illegal params")
  ),
)]
pub async fn decrypt() -> Result<impl IntoResponse> {
    Ok("")
}

#[utoipa::path(
  post,
  path="/sign",
  operation_id = "增强签名，用主密钥的主版本",
  context_path= "/keys/{key_id}",
  params(
    ("key_id" = String, Path, description="kms 标识"),
  ),
  responses(
      (status = 200, description = "密文信息", body = String, content_type="application/json"),
      (status = 400, description = "illegal params")
  ),
)]
pub async fn advance_sign() -> Result<impl IntoResponse> {
    Ok("")
}

#[utoipa::path(
  post,
  path="/sign/{version}",
  operation_id = "签名",
  context_path= "/keys/{key_id}",
  params(
    ("key_id" = String, Path, description="kms 标识"),
  ),
  responses(
      (status = 200, description = "密文信息", body = String, content_type="application/json"),
      (status = 400, description = "illegal params")
  ),
)]
pub async fn sign() -> Result<impl IntoResponse> {
    Ok("")
}

#[utoipa::path(
  post,
  path="/verify",
  operation_id = "验签",
  context_path= "/keys/{key_id}",
  params(
    ("key_id" = String, Path, description="kms 标识"),
  ),
  responses(
      (status = 200, description = "密文信息", body = String, content_type="application/json"),
      (status = 400, description = "illegal params")
  ),
)]
pub async fn verify() -> Result<impl IntoResponse> {
    Ok("")
}
