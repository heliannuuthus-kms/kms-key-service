use crate::{
    common::{axum::Json, configs::Patch, errors::Result},
    pojo::form::{
        key::KeyCreateForm,
        key_meta::{KeyAliasPatchForm, KeyMetaPatchForm},
    },
    service::key_meta_service,
    States,
};
use axum::extract::State;
use axum::response::IntoResponse;

#[utoipa::path(
  put,
  path="/",
  operation_id = "设置密钥元数据信息",
  context_path= "/keys/{key_id}/meta",
  responses(
      (status = 200, description = "", body = String),
      (status = 400, description = "illegal params")
  ),
  request_body = KeyMetaPatchForm
)]
pub async fn set_key_meta(
    State(States { db, .. }): State<States>,
    Json(form): Json<KeyMetaPatchForm>,
) -> Result<impl IntoResponse> {
    tracing::info!("set key meta: {:?}", form);
    let mut model =
        key_meta_service::get_main_key_meta(&db, &form.key_id).await?;
    form.merge(&mut model);
    key_meta_service::set_key_meta(&db, &model)
        .await
        .map(|_| axum::Json(model))
}

#[utoipa::path(
  patch,
  path="/alias",
  operation_id = "设置密钥别名",
  context_path= "/keys/{key_id}/meta",
  responses(
      (status = 200, description = "", body = String),
      (status = 400, description = "illegal params")
  ),
  request_body = KeyAliasPatchForm
)]
pub async fn set_key_alias(
    State(States { db, .. }): State<States>,
    Json(form): Json<KeyAliasPatchForm>,
) -> Result<impl IntoResponse> {
    tracing::info!("set key alias: {:?}", form);
    key_meta_service::set_alias(&db, &form).await?;
    Ok(())
}

#[utoipa::path(
  delete,
  path="/alias",
  operation_id = "删除密钥别名",
  context_path= "/keys/{key_id}/meta",
  responses(
      (status = 200, description = "", body = String),
      (status = 400, description = "illegal params")
  ),
  request_body = KeyAliasPatchForm
)]
pub async fn remove_key_alias(
    State(States { db, .. }): State<States>,
    Json(form): Json<KeyAliasPatchForm>,
) -> Result<impl IntoResponse> {
    tracing::info!("set key alias: {:?}", form);
    key_meta_service::set_alias(&db, &form).await?;
    Ok(())
}

#[utoipa::path(
  delete,
  path="/alias",
  operation_id = "批量删除密钥别名",
  context_path= "/keys/{key_id}/meta",
  request_body = KeyAliasPatchForm,
  responses(
      (status = 200, description = "", body = String),
      (status = 400, description = "illegal params")
  ),
)]
pub async fn batch_remove_key_alias(
    State(States { db, .. }): State<States>,
    Json(form): Json<KeyAliasPatchForm>,
) -> Result<impl IntoResponse> {
    tracing::info!("set key alias: {:?}", form);
    key_meta_service::set_alias(&db, &form).await?;
    Ok(())
}
