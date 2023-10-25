use std::collections::HashMap;

use anyhow::{bail, Context};
use axum::{extract::State, response::IntoResponse, Json};
use chrono::Duration;
use http::StatusCode;
use openssl::{hash, rsa};
use serde_json::json;

use crate::{
    common::{
        self, cache,
        errors::{Result, ServiceError},
        secrets::{
            self,
            types::{KeyState, WrappingKeySpec},
        },
        utils::{self, decode64, generate_b64},
    },
    entity::{t_secret, t_secret_meta},
    pojo::{
        form::secret::{
            SecretCreateForm, SecretImportForm, SecretImportParamsForm,
        },
        result::secret::SecretMaterialImportParamsResult,
    },
    repository::secret_repository,
    service::secret_service,
    States,
};

#[utoipa::path(
    post,
    path="/secrets",
    operation_id = "创建密钥",
    responses(
        (status = 200, description = "密钥标识",example = json!({"key_id": "key_id"}),body = String, content_type="application/json"),
        (status = 400, description = "illegal params")
    ),
    request_body = SecretCreateForm
)]
pub async fn create_secret(
    state: State<States>,
    Json(form): Json<SecretCreateForm>,
) -> Result<impl IntoResponse> {
    Ok((StatusCode::OK, axum::Json(json!({"key_id": ""}))).into_response())
}

#[utoipa::path(
    get,
    path="/secrets/import/params",
    operation_id = "导入密钥材料所需的参数",
    responses(
        (status = 200, description = "", body = String),
        (status = 400, description = "illegal params")
    ),
    request_body = SecretImportParamsForm
)]
pub async fn import_secret_params(
    State(state): State<States>,
    Json(form): Json<SecretImportParamsForm>,
) -> Result<impl IntoResponse> {
    Ok((StatusCode::OK, axum::Json(json!({"key_id": ""}))).into_response())
}

#[utoipa::path(
    post,
    path="/secrets/import",
    operation_id = "导入密钥材料",
    responses(
        (status = 200, description = "", body = String),
        (status = 400, description = "illegal params")
    ),
    request_body = SecretImportForm
)]
pub async fn import_secret(
    State(States { db, cache }): State<States>,
    Json(form): Json<SecretImportForm>,
) -> Result<impl IntoResponse> {
    Ok((StatusCode::OK, axum::Json(json!({"key_id": ""}))).into_response())
}

#[utoipa::path(
    patch,
    path="/secrets/meta",
    operation_id = "更新密钥元数据信息",
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
