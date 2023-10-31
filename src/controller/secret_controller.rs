use axum::{extract::State, response::IntoResponse};
use http::StatusCode;
use serde_json::json;

use crate::{
    common::{
        axum::{Form, Json},
        errors::Result,
    },
    pojo::form::secret::{
        SecretCreateForm, SecretImportForm, SecretImportParamsQuery,
    },
    States,
};

#[utoipa::path(
    post,
    path="",
    operation_id = "创建密钥",
    context_path= "/secrets",
    responses(
        (status = 200, description = "密钥标识",example = json!({"key_id": "key_id"}),body = String, content_type="application/json"),
        (status = 400, description = "illegal params")
    ),
    request_body = SecretCreateForm
)]
pub async fn create_secret(
    _state: State<States>,
    Form(_form): Form<SecretCreateForm>,
) -> Result<impl IntoResponse> {
    Ok((StatusCode::OK, axum::Json(json!({"key_id": ""}))).into_response())
}

#[utoipa::path(
    get,
    path="/import/params",
    operation_id = "导入密钥材料所需的参数",
    context_path= "/secrets",
    responses(
        (status = 200, description = "", body = SecretMaterialImportParamsResult),
        (status = 400, description = "illegal params")
    ),
    request_body = SecretImportParamsQuery
)]
pub async fn import_secret_params(
    State(_state): State<States>,
    Json(_form): Json<SecretImportParamsQuery>,
) -> Result<impl IntoResponse> {
    Ok((StatusCode::OK, axum::Json(json!({"key_id": ""}))).into_response())
}

#[utoipa::path(
    post,
    path="/import",
    operation_id = "导入密钥材料",
    context_path= "/secrets",
    request_body = SecretImportForm,
    responses(
        (status = 200, description = "", body = String),
        (status = 400, description = "illegal params")
    ),
)]
pub async fn import_secret(
    State(_state): State<States>,
    Json(_form): Json<SecretImportForm>,
) -> Result<impl IntoResponse> {
    Ok((StatusCode::OK, axum::Json(json!({"key_id": ""}))).into_response())
}

#[utoipa::path(
    patch,
    path="/meta",
    operation_id = "更新密钥元数据信息",
    context_path= "/secrets",
    responses(
        (status = 200, description = "", body = String),
        (status = 400, description = "illegal params")
    ),
    request_body = SecretCreateForm
)]
pub async fn set_secret_meta(
    Json(_form): Json<SecretCreateForm>,
) -> Result<impl IntoResponse> {
    Ok("")
}
