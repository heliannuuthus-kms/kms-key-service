use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use http::StatusCode;

use crate::{
    common::errors::{Result, ServiceError},
    pojo::{
        form::kms::{KmsCreateForm, KmsUpdateForm},
        result::kms::KmsAkskResult,
    },
    repository::kms_repository,
    service::kms_service,
    States,
};

#[utoipa::path(
  get,
  path="/kms/{kms_id}",
  operation_id = "获取 kms 实例信息",
  responses(
      (status = 200, description = "kms 标识",example = json!({"kms_id": "kms_id"}),body = String, content_type="application/json"),
      (status = 400, description = "illegal params")
  ),
  request_body = KmsCreateForm
)]
pub async fn get_kms(
    State(States { db, .. }): State<States>,
    Path(kms_id): Path<String>,
) -> Result<impl IntoResponse> {
    tracing::info!("获取 kms 实例信息 {:?}", kms_id);
    let kms = match kms_repository::select_kms(&db, &kms_id).await? {
        Some(model) => model,
        None => {
            return Err(ServiceError::NotFount(format!(
                "kms is nonexistant, kms_id: {kms_id}"
            )))
        }
    };
    Ok((StatusCode::OK, Json(kms).into_response()))
}

#[utoipa::path(
  post,
  path="/kms",
  operation_id = "创建 kms 实例",
  request_body = KmsCreateForm,
  responses(
      (status = 200, description = "kms ak/sk 数据对象", body = KmsAkskResult, content_type="application/json"),
      (status = 400, description = "illegal params")
  ),
)]
pub async fn create_kms(
    State(States { db, .. }): State<States>,
    Json(form): Json<KmsCreateForm>,
) -> Result<impl IntoResponse> {
    tracing::info!("创建 kms 实例 {:?}", form);

    Ok(kms_service::create_kms(&db, &form.try_into()?)
        .await
        .map(Json)?
        .into_response())
}

#[utoipa::path(
  put,
  path="/kms",
  operation_id = "更新 kms 信息",
  responses(
      (status = 200, description = "密钥标识",example = json!({"kms_id": "kms_id"}),body = String, content_type="application/json"),
      (status = 400, description = "illegal params")
  ),
  request_body = KmsUpdateForm
)]
pub async fn set_kms(
    State(States { db, .. }): State<States>,
    Json(form): Json<KmsUpdateForm>,
) -> Result<impl IntoResponse> {
    kms_service::set_kms(&db, form.try_into()?).await?;
    Ok(StatusCode::OK.into_response())
}

#[utoipa::path(
  delete,
  path="/kms/{kms_id}",
  operation_id = "销毁 kms 实例",
  responses(
      (status = 200, description = "密钥标识",example = json!({"kms_id": "kms_id"}),body = String, content_type="application/json"),
      (status = 400, description = "illegal params")
  ),
  request_body = KmsUpdateForm
)]
pub async fn destroy_kms(
    State(_state): State<States>,
    Path(kms_id): Path<String>,
) -> Result<impl IntoResponse> {
    tracing::info!("销毁 kms 实例 {:?}", kms_id);
    Ok("".into_response())
}


#[utoipa::path(
    post,
    path="/kms/aksk/{access_key}/rotate",
    operation_id = "轮转 kms_aksk",
    responses(
        (status = 200, description = "kms ak/sk 数据对象", body = KmsAkskResult, content_type="application/json"),
        (status = 400, description = "illegal params")
    ),
    request_body = KmsUpdateForm
  )]
pub async fn rotate_kms_aksk(
    State(States { db, .. }): State<States>,
    Json(form): Json<KmsUpdateForm>,
) -> Result<impl IntoResponse> {
    
}
