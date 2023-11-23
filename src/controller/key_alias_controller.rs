use axum::{
    extract::{Path, State},
    response::IntoResponse,
};

use crate::{
    common::{
        axum::{Json, Query},
        datasource::Paginator,
        errors::Result,
    },
    pojo::form::key_extra::{KeyAliasCreateOrUpdateForm, KeyAliasDeleteForm},
    service::key_alias_service,
    States,
};

#[utoipa::path(
  patch,
  path="",
  operation_id = "设置密钥别名",
  context_path= "/keys/{key_id}/aliases",
  params(
    ("key_id" = String, Path, description="kms 标识"),
  ),
  request_body = KeyAliasCreateOrUpdateForm,
  responses(
      (status = 200, description = "", body = ()),
      (status = 400, description = "illegal params")
  ),
)]
pub async fn set_key_alias(
    State(States { db, .. }): State<States>,
    Path(key_id): Path<String>,
    Json(form): Json<KeyAliasCreateOrUpdateForm>,
) -> Result<impl IntoResponse> {
    tracing::info!("set key alias, key_id: {}, alias: {:?}", key_id, form);
    key_alias_service::set_alias(&db, &key_id, &form.alias).await?;
    Ok(())
}

#[utoipa::path(
  delete,
  path="",
  operation_id = "批量删除密钥别名",
  context_path= "/keys/{key_id}/aliases",
  params(
    ("key_id" = String, Path, description="kms 标识"),
  ),
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
    key_alias_service::remove_key_aliases(&db, &key_id, form.aliases).await?;
    Ok(())
}

#[utoipa::path(
    get,
    path="",
    operation_id = "密钥别名信息的分页查询",
    context_path= "/keys/{key_id}/aliases",
    params(
        ("kms_id" = String, Path, description="kms 标识"),
        Paginator
    ),
    responses(
        (status = 200, description = "", body = PaginatedKeyAliasModels),
        (status = 400, description = "illegal params")
    ),
  )]
pub async fn list_key_alias(
    State(States { db, .. }): State<States>,
    Path(key_id): Path<String>,
    Query(paginator): Query<Paginator>,
) -> Result<impl IntoResponse> {
    tracing::info!("paging alias: {:?}", paginator);
    key_alias_service::list_key_aliases(&db, &key_id, paginator)
        .await
        .map(axum::Json)
}
