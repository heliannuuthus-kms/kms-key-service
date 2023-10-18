use axum::{extract::State, response::IntoResponse, Json};
use http::StatusCode;
use serde_json::json;

use crate::{
    common::{
        self,
        errors::{Result, ServiceError},
    },
    entity::{t_secret, t_secret_meta},
    pojo::form::secret::{SecretCreateForm, SecretImportForm},
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
    let key_id = &common::utils::gen_id(32);

    let key_alg: &common::algorithm::KeyAlgorithm = match form.spec {
        common::algorithm::KeySpec::Aes128 => &common::algorithm::AES_128,
        common::algorithm::KeySpec::Aes256 => &common::algorithm::AES_256,
        common::algorithm::KeySpec::Rsa2048 => &common::algorithm::RSA_2048,
        common::algorithm::KeySpec::Rsa3072 => &common::algorithm::RSA_3072,
        common::algorithm::KeySpec::EcP256 => &common::algorithm::EC_P256,
        common::algorithm::KeySpec::EcP256K => &common::algorithm::EC_P256K,
    };

    if !key_alg.key_usage.contains(&form.usage) {
        return Err(ServiceError::BadRequest(format!(
            "unsupported key usage({:?})",
            form.usage
        )));
    }

    let mut secret = t_secret::Model {
        key_id: key_id.to_string(),
        key_type: key_alg.key_type,
        primary_key_id: "#".to_string(),
        ..Default::default()
    };

    let mut secret_meta = t_secret_meta::Model {
        key_id: key_id.to_string(),
        origin: form.origin,
        spec: form.spec,
        usage: form.usage,
        rotation_interval: form.rotation_interval.num_seconds(),
        ..Default::default()
    };

    // fill secret rotation interval
    if form.enable_automatic_rotation {
        secret_meta.rotation_interval = form.rotation_interval.num_seconds();
        // 往某个队列里投放密钥轮换的任务
    }

    if common::algorithm::KeyOrigin::Kms.eq(&secret_meta.origin) {
        let (pri_key, pub_key) = (key_alg.generator)()?;

        if common::algorithm::KeyType::Symmetric.eq(&key_alg.key_type) {
            secret.key_pair = Some(pri_key);
        } else {
            secret.pub_key = Some(pub_key);
            secret.pri_key = Some(pri_key);
        }
    }
    let key_id: String =
        secret_service::create_secret(&state.db, &secret, &secret_meta).await?;
    Ok((StatusCode::OK, axum::Json(json!({"key_id": key_id}))).into_response())
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
    state: State<States>,
    Json(form): Json<SecretImportForm>,
) -> Result<impl IntoResponse> {
    match secret_service::import_secret_meta(&state.db, &form.key_id).await? {}
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
