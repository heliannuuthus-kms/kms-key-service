use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use http::StatusCode;

use crate::{
    common::{
        axum::Json,
        configs::Patch,
        errors::{Result, ServiceError},
    },
    pojo::form::kms::{KmsCreateForm, KmsPatchForm},
    repository::kms_repository,
    service::kms_service,
    States,
};

#[utoipa::path(
  get,
  path="/{kms_id}",
  operation_id = "获取 kms 实例信息",
  context_path= "/kms",
  responses(
      (status = 200, description = "kms 实例信息", body = KmsModel, content_type="application/json"),
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
  path="",
  operation_id = "创建 kms 实例",
  request_body = KmsCreateForm,
  context_path= "/kms",
  responses(
      (status = 200, description = "kms 数据对象", body = KmsResult, content_type="application/json"),
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
  patch,
  path="",
  operation_id = "更新 kms 信息",
  context_path= "/kms/{kms_id}",
  params(
    ("kms_id" = String, Path, description="kms 标识"),
  ),
  request_body = KmsPatchForm,
  responses(
      (status = 200, description = "密钥标识", body = KmsModel, content_type="application/json"),
      (status = 400, description = "illegal params")
  ),
)]
pub async fn set_kms(
    State(States { db, .. }): State<States>,
    Path(kms_id): Path<String>,
    Json(form): Json<KmsPatchForm>,
) -> Result<impl IntoResponse> {
    let mut model = kms_service::get_kms(&db, &kms_id).await?;
    kms_service::set_kms(&db, model.patched(form)).await?;
    Ok(StatusCode::OK.into_response())
}

#[utoipa::path(
  delete,
  path="/{kms_id}",
  operation_id = "销毁 kms 实例",
  context_path= "/kms",
  params(
    ("kms_id" = String, Path, description="kms 标识"),
  ),
  responses(
      (status = 200, description = "密钥标识",example = json!({"kms_id": "kms_id"}),body = String, content_type="application/json"),
      (status = 400, description = "illegal params")
  )
)]
pub async fn destroy_kms(
    State(States { db, .. }): State<States>,
    Path(kms_id): Path<String>,
) -> Result<impl IntoResponse> {
    tracing::info!("销毁 kms 实例 {:?}", kms_id);

    kms_service::delete_kms(&db, &kms_id).await?;

    Ok(().into_response())
}
