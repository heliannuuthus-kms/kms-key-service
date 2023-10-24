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
            algorithm::{KeyState, WrappingKeySpec, EC_SM2, RSA_2048},
        },
        utils::{self, decode64, gen_b64_id},
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
    let key_id: String =
        secret_service::create_secret(&state.db, &form).await?;
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

    let (key_alg, signer_creator): (
        &common::secrets::algorithm::KeyAlgorithm,
        for<'a, 'b> fn(
            &'a [u8],
            hash::MessageDigest,
        ) -> Result<openssl::sign::Signer<'a>>,
    ) = match form.wrapping_key_spec {
        WrappingKeySpec::Rsa2048 => (&RSA_2048, secrets::rsa::signer),
        WrappingKeySpec::EcSm2 => (&EC_SM2, secrets::ec::signer),
    };
    let (encrypt_pri_key, encrypt_pub_key) = (key_alg.generator)()?;
    let token = gen_b64_id(256);

    let exp = Duration::days(1);
    let pri_key = &utils::decode64(&encrypt_pri_key)?;
    let mut signer = signer_creator(pri_key, hash::MessageDigest::sha256())?;
    signer
        .update(&utils::decode64(&token)?)
        .context("signer update failed")?;
    let imported_signature =
        utils::encode64(&signer.sign_to_vec().context("signer sign failed")?);
    let result = SecretMaterialImportParamsResult {
        key_id: key_id.to_owned(),
        token: imported_signature.to_owned(),
        pub_key: encrypt_pub_key,
        expires_in: exp,
        key_spec: form.wrapping_key_spec,
    };
    cache::redis_setex(
        cache,
        format!("kms:secrets:import:params:{}", key_id).as_str(),
        serde_json::to_string(&result).context(format!(
            "save import params failed, serialize result failed, key_id:{}",
            key_id
        ))?,
        exp,
    )
    .await?;
    Ok((StatusCode::OK, axum::Json(result)).into_response())
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

    let secret_meta =
        match secret_repository::select_secret_meta(&db, key_id).await? {
            Some(secret_meta) => secret_meta,
            None => {
                return Err(ServiceError::NotFount(format!(
                    "secret meta is nonexitent, key_id: {}",
                    key_id
                )))
            }
        };
    let secret_import_params =
        match cache::redis_get::<SecretMaterialImportParamsResult>(
            &cache,
            format!("kms:secrets:import:params:{}", key_id).as_str(),
        )
        .await?
        {
            Some(params) => params,
            None => {
                return Err(ServiceError::BadRequest(format!(
                    "missing import params, key_id: {}",
                    key_id
                )))
            }
        };

    let (verifier_creator, decrypter_creator): (
        for<'a, 'b> fn(
            &'a [u8],
            hash::MessageDigest,
        ) -> Result<openssl::encrypt::Decrypter<'a>>,
        for<'a, 'b> fn(
            &'a [u8],
            hash::MessageDigest,
        ) -> Result<openssl::sign::Verifier<'a>>,
    ) = match secret_import_params.key_spec {
        WrappingKeySpec::Rsa2048 => (secrets::rsa::decrypter, secrets::rsa::verifier),
        WrappingKeySpec::EcSm2 => (secrets::ec::decrypter, secrets::ec::verifier),
    };

    
    verifier_creator()

    let key_pair = secrets::rsa::decrypter(
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
                        secrets::algorithm::select_key_alg(secret_meta.spec);
                    let (pri_key, pub_key) = (key_alg.deriver)(&key_pair)?;
                    let mut secret = t_secret::Model::default();
                    match key_alg.key_type {
                        secrets::algorithm::KeyType::Symmetric => {
                            secret.key_type =
                                secrets::algorithm::KeyType::Symmetric;
                            secret.key_pair = Some(pub_key);
                        }
                        secrets::algorithm::KeyType::Asymmetric => {
                            secret.key_type =
                                secrets::algorithm::KeyType::Asymmetric;
                            secret.pub_key = Some(pub_key);
                            secret.pri_key = Some(pri_key);
                        }
                        secrets::algorithm::KeyType::Unknown => {
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
