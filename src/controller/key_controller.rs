use axum::{extract::State, response::IntoResponse};
use http::StatusCode;
use serde_json::json;

use crate::{
    common::{
        axum::{Json, Query},
        encrypto,
        errors::{Result, ServiceError},
    },
    pojo::form::{
        self,
        key::{KeyCreateForm, KeyImportForm, KeyImportParamsQuery},
    },
    service::key_service,
    States,
};

#[utoipa::path(
    post,
    path="",
    operation_id = "创建密钥",
    context_path= "/keys",
    responses(
        (status = 200, description = "密钥标识",example = json!({"key_id": "key_id"}),body = String, content_type="application/json"),
        (status = 400, description = "illegal params")
    ),
    request_body = KeyCreateForm
)]
pub async fn create_key(
    State(States { db, .. }): State<States>,
    Json(form): Json<KeyCreateForm>,
) -> Result<impl IntoResponse> {
    tracing::info!("create master key, data: {:?}", form);

   

    key_service::create_key(&db, key_alg, &form)
        .await
        .map(axum::Json)
}

#[utoipa::path(
    get,
    path="/import/params",
    operation_id = "导入密钥材料所需的参数",
    context_path= "/keys",
    params(KeyImportParamsQuery),
    responses(
        (status = 200, description = "", body = KeyMaterialImportParamsResult),
        (status = 400, description = "illegal params")
    ),
)]
pub async fn import_key_params(
    State(States { db, rd }): State<States>,
    Query(form): Query<KeyImportParamsQuery>,
) -> Result<impl IntoResponse> {
    tracing::info!("create import key material, data: {:?}", form);
    key_service::generate_key_import_params(&db, &rd, &form)
        .await
        .map(axum::Json)
}

#[utoipa::path(
    post,
    path="/import",
    operation_id = "导入密钥材料",
    context_path= "/keys",
    request_body = KeyImportForm,
    responses(
        (status = 200, description = "", body = String),
        (status = 400, description = "illegal params")
    ),
)]
pub async fn import_key(
    State(_state): State<States>,
    Json(form): Json<KeyImportForm>,
) -> Result<impl IntoResponse> {
    Ok((StatusCode::OK, axum::Json(json!({"key_id": ""}))).into_response())
}

#[utoipa::path(
    patch,
    path="/meta",
    operation_id = "更新密钥元数据信息",
    context_path= "/keys",
    responses(
        (status = 200, description = "", body = String),
        (status = 400, description = "illegal params")
    ),
    request_body = KeyCreateForm
)]
pub async fn set_key_meta(
    Json(_form): Json<KeyCreateForm>,
) -> Result<impl IntoResponse> {
    Ok("")
}
