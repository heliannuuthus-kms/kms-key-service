use axum::{
    extract::{Path, State},
    response::IntoResponse,
};

use crate::{
    common::{axum::Json, configs::Patch, errors::Result},
    pojo::form::key_extra::{KeyChangeStateBody, KeyMetaPatchForm},
    service::key_meta_service::{self},
    States,
};

#[utoipa::path(
  patch,
  path="",
  operation_id = "设置密钥元数据信息",
  context_path= "/keys/{key_id}/metas",
  params(
    ("key_id" = String, Path, description="kms 标识"),
  ),
  request_body = KeyMetaPatchForm,
  responses(
      (status = 200, description = "", body = ()),
      (status = 400, description = "illegal params")
  ),
)]
pub async fn set_key_meta(
    State(States { db, rd, .. }): State<States>,
    Path(key_id): Path<String>,
    Json(form): Json<KeyMetaPatchForm>,
) -> Result<impl IntoResponse> {
    tracing::info!("set key meta, key_id: {}, meta: {:?}", key_id, form);
    let mut model =
        key_meta_service::get_main_key_meta(&rd, &db, &key_id).await?;

    model.patched(form);
    key_meta_service::set_key_meta(&rd, &db, model.clone())
        .await
        .map(|_| axum::Json(model))
}

#[utoipa::path(
    get,
    path="",
    operation_id = "获取主密钥元数据信息",
    context_path= "/keys/{key_id}/metas",
    params(
      ("key_id" = String, Path, description="密钥标识"),
    ),
    request_body = KeyMetaPatchForm,
    responses(
        (status = 200, description = "", body = KeyMetaModel),
        (status = 400, description = "illegal params")
    ),
  )]
pub async fn get_key_meta(
    State(States { db, rd, .. }): State<States>,
    Path(key_id): Path<String>,
) -> Result<impl IntoResponse> {
    tracing::info!("get key meta, key_id: {}", key_id);
    key_meta_service::get_main_key_meta(&rd, &db, &key_id)
        .await
        .map(axum::Json)
}

#[utoipa::path(
    post,
    path="/state",
    operation_id = "切换密钥状态",
    context_path= "/keys/{key_id}",
    responses(
        (status = 200, description = "密钥元数据信息", body = KeyMetaModel, content_type="application/json"),
        (status = 400, description = "illegal params")
    ),
    request_body = KeyChangeStateBody
)]
pub async fn change_key_state(
    State(States { db, rd, .. }): State<States>,
    Path(key_id): Path<String>,
    Json(mut body): Json<KeyChangeStateBody>,
) -> Result<impl IntoResponse> {
    tracing::info!("change key state, key_id: {}, body: {:?}", key_id, body);
    body.key_id = key_id;
    key_meta_service::change_state(&rd, &db, &body)
        .await
        .map(axum::Json)
}
