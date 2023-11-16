use axum::response::IntoResponse;

use crate::common::errors::Result;

#[utoipa::path(
  post,
  path="/encrypt/{:version}",
  operation_id = "加密",
  context_path= "/keys/{key_id}",
  responses(
      (status = 200, description = "密文信息", body = String, content_type="application/json"),
      (status = 400, description = "illegal params")
  ),
)]
pub async fn encrypt() -> Result<impl IntoResponse> {
    Ok("")
}

#[utoipa::path(
  post,
  path="/encrypt",
  operation_id = "增强加密，即仅用主密钥主版本",
  context_path= "/keys/{key_id}",
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
  responses(
      (status = 200, description = "密文信息", body = String, content_type="application/json"),
      (status = 400, description = "illegal params")
  ),
)]
pub async fn verify() -> Result<impl IntoResponse> {
    Ok("")
}
