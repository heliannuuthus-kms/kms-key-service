use std::collections::HashMap;

use anyhow::Context;
use axum::{extract::State, response::IntoResponse, Json};
use chrono::Duration;
use http::StatusCode;
use openssl::{hash, rsa};
use serde_json::json;

use crate::{
    common::{
        self, cache,
        errors::{Result, ServiceError},
        kits::{
            self,
            algorithm::{WrappingKeySpec, EC_SM2, RSA_2048},
        },
        utils::{self, decode64, gen_b64_id},
    },
    entity::{t_secret, t_secret_meta},
    pojo::form::secret::{
        SecretCreateForm, SecretImportForm, SecretImportParamsForm,
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
    let key_id = &common::utils::gen_b62_id(32);
    let key_alg = kits::algorithm::select_key_alg(form.spec);
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

    if common::kits::algorithm::KeyOrigin::Kms.eq(&secret_meta.origin) {
        let (pri_key, pub_key) = (key_alg.generator)()?;

        if common::kits::algorithm::KeyType::Symmetric.eq(&key_alg.key_type) {
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
    let key_id = &form.key_id;
    let States { db: _, ref cache } = state;

    let key_alg: &common::kits::algorithm::KeyAlgorithm =
        match form.wrapping_ey_spec {
            WrappingKeySpec::Rsa2048 => &RSA_2048,
            WrappingKeySpec::EcSm2 => &EC_SM2,
        };
    let (encrypt_pri_key, encrypt_pub_key) = (key_alg.generator)()?;
    let token = gen_b64_id(256);

    let values =
        vec![("import_token", &token), ("private_key", &encrypt_pri_key)];
    let exp = Duration::days(1);
    let import_signature = kits::rsa::sign(
        &encrypt_pri_key,
        &decode64(&token)?,
        hash::MessageDigest::sha256(),
    )?;
    cache::redis_hsetex(
        cache,
        format!("kms:secrets:import:params:{}", key_id).as_str(),
        values,
        Some(exp),
    )
    .await?;
    let resp = json!({"key_id":key_id, "import_token": utils::encode64(&import_signature), "public_key": encrypt_pub_key, "expires_in": exp.num_seconds()});
    Ok((StatusCode::OK, axum::Json(resp)).into_response())
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
    let key_id = &form.key_id;

    let secret_import_params = cache::redis_hgetall::<HashMap<String, String>>(
        &cache,
        format!("kms:secrets:import:params:{}", key_id).as_str(),
    )
    .await?;

    if secret_import_params.is_empty() {
        return Err(ServiceError::BadRequest(format!(
            "missing import params, key_id: {}",
            key_id
        )));
    }

    let import_token = secret_import_params.get("import_token").unwrap();
    let enctypt_pri_key = secret_import_params.get("private_key").unwrap();
    let enctypt_pub_key = secret_import_params.get("pub_key").unwrap();

    if !kits::rsa::verify(
        enctypt_pub_key,
        &decode64(import_token)?,
        &decode64(&form.import_token)?,
        hash::MessageDigest::sha256(),
    )? {
        return Err(ServiceError::VerifyFailed(format!(
            "verify import token failed, key_id: {}",
            key_id
        )));
    }

    let key_pair = kits::rsa::decrypt(
        enctypt_pri_key,
        &utils::decode64(&form.encrypted_key_material)?,
        rsa::Padding::PKCS1_OAEP,
        hash::MessageDigest::sha256(),
    )?;

    match secret_repository::select_secret_meta(&db, key_id).await? {
        Some(secret_meta) => {
            match secret_repository::select_secret(&db, key_id).await? {
                Some(_secret) => {
                    let key_alg =
                        kits::algorithm::select_key_alg(secret_meta.spec);
                    let (pri_key, pub_key) = (key_alg.deriver)(&key_pair)?;
                    let mut secret = t_secret::Model::default();
                    match key_alg.key_type {
                        kits::algorithm::KeyType::Symmetric => {
                            secret.key_type =
                                kits::algorithm::KeyType::Symmetric;
                            secret.key_pair = Some(pub_key);
                        }
                        kits::algorithm::KeyType::Asymmetric => {
                            secret.key_type =
                                kits::algorithm::KeyType::Asymmetric;
                            secret.pub_key = Some(pub_key);
                            secret.pri_key = Some(pri_key);
                        }
                        kits::algorithm::KeyType::Unknown => {
                            return Err(ServiceError::BadRequest(
                                "known secret type".to_string(),
                            ))
                        }
                    }
                    secret_repository::insert_secret(&db, &secret).await?;
                }
                None => {
                    return Err(ServiceError::BadRequest(
                        "secret was set".to_owned(),
                    ))
                }
            }
        }
        None => {
            return Err(ServiceError::BadRequest(
                "secret is need to create".to_owned(),
            ))
        }
    };

    Ok((StatusCode::OK).into_response())
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
