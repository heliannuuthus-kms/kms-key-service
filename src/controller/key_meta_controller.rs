use axum::{
    extract::{Path, State},
    response::IntoResponse,
};

use crate::{
    common::{
        axum::{Json, Query},
        configs::Patch,
        datasource::Paginator,
        errors::Result,
    },
    pojo::form::key_meta::{
        KeyAliasDeleteForm, KeyAliasPatchForm, KeyMetaPatchForm,
    },
    service::key_meta_service,
    States,
};

#[utoipa::path(
  patch,
  path="/",
  operation_id = "设置密钥元数据信息",
  context_path= "/keys/{key_id}/metas",
  responses(
      (status = 200, description = "", body = ()),
      (status = 400, description = "illegal params")
  ),
  request_body = KeyMetaPatchForm
)]
pub async fn set_key_meta(
    State(States { db, .. }): State<States>,
    Path(key_id): Path<String>,
    Json(form): Json<KeyMetaPatchForm>,
) -> Result<impl IntoResponse> {
    tracing::info!("set key meta, key_id: {}, meta: {:?}", key_id, form);
    let mut model = key_meta_service::get_main_key_meta(&db, &key_id).await?;
    form.merge(&mut model);
    key_meta_service::set_key_meta(&db, &model)
        .await
        .map(|_| axum::Json(model))
}

#[utoipa::path(
  patch,
  path="",
  operation_id = "设置密钥别名",
  context_path= "/keys/{key_id}/aliases",
  responses(
      (status = 200, description = "", body = ()),
      (status = 400, description = "illegal params")
  ),
  request_body = KeyAliasPatchForm
)]
pub async fn set_key_alias(
    State(States { db, .. }): State<States>,
    Path(key_id): Path<String>,
    Json(form): Json<KeyAliasPatchForm>,
) -> Result<impl IntoResponse> {
    tracing::info!("set key alias, key_id: {}, alias: {:?}", key_id, form);
    key_meta_service::set_alias(&db, &key_id, &form.alias).await?;
    Ok(())
}

#[utoipa::path(
  delete,
  path="",
  operation_id = "批量删除密钥别名",
  context_path= "/keys/{key_id}/aliases",
  request_body = KeyAliasDeleteForm,
  responses(
      (status = 200, description = "", body = ()),
      (status = 400, description = "illegal params")
  ),
)]
pub async fn remove_key_alias(
    State(States { db, .. }): State<States>,
    Path(key_id): Path<String>,
    Json(form): Json<KeyAliasDeleteForm>,
) -> Result<impl IntoResponse> {
    tracing::info!("remove key alias, key_id: {}, form: {:?}", key_id, form);
    key_meta_service::remove_key_aliases(&db, &key_id, form.aliases).await?;
    Ok(())
}

#[utoipa::path(
    get,
    path="",
    operation_id = "密钥元数据信息的分页查询",
    context_path= "/keys/{key_id}/aliases",
    params(Paginator),
    responses(
        (status = 200, description = "", body = PaginatedKeyAliasModels),
        (status = 400, description = "illegal params")
    ),
  )]
pub async fn list_key_alias(
    State(States { db, .. }): State<States>,
    Query(paginator): Query<Paginator>,
) -> Result<impl IntoResponse> {
    tracing::info!("paging alias: {:?}", paginator);
    key_meta_service::list_key_aliases(&db, paginator)
        .await
        .map(axum::Json)
}
