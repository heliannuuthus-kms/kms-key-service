use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use openssl::hash::MessageDigest;
use pojo::form::crypto::EncryptBody;

use crate::{
    common::{axum::Json, errors::Result},
    crypto, pojo,
    service::{key_meta_service, key_service},
    States,
};

#[utoipa::path(
  post,
  path="/encrypt",
  operation_id = "加密",
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
    State(States { db, .. }): State<States>,
    Json(body): Json<EncryptBody>,
) -> Result<impl IntoResponse> {
    tracing::info!("encrypt data: body {:?}", body);
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
  operation_id = "解密",
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
