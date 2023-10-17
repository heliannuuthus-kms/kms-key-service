use actix_web::{patch, post, web::Json, HttpResponse, Responder};
use serde_json::json;

use crate::{
    common::errors::Result,
    pojo::{
        form::secret::{SecretCreateForm, SecretImportForm},
        po::secret::{Secret, SecretMeta},
    },
    service::secret_service,
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
#[post("")]
pub async fn create_secret(
    Json(form): Json<SecretCreateForm>,
) -> Result<impl Responder> {
    let (mut secret, mut secret_meta): (Secret, SecretMeta) =
        form.try_into()?;
    let key_id: String =
        secret_service::create_secret(&mut secret, &mut secret_meta).await?;
    Ok(HttpResponse::Ok().json(json!({"key_id": key_id})))
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
#[post("/import")]
pub async fn import_secret(
    Json(_form): Json<SecretImportForm>,
) -> Result<impl Responder> {
    


    Ok("")
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
#[patch("/meta")]
pub async fn set_secret_meta(
    Json(_form): Json<SecretCreateForm>,
) -> Result<impl Responder> {
    Ok("")
}
