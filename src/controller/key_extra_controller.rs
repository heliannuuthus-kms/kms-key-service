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
    pojo::form::key_extra::{
        KeyAliasCreateOrUpdateForm, KeyAliasDeleteForm, KeyMetaPatchForm,
    },
    service::{key_extra_service, key_service},
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
    State(States { db, .. }): State<States>,
    Path(key_id): Path<String>,
    Json(form): Json<KeyMetaPatchForm>,
) -> Result<impl IntoResponse> {
    tracing::info!("set key meta, key_id: {}, meta: {:?}", key_id, form);
    let mut model = key_extra_service::get_main_key_meta(&db, &key_id).await?;
    model.patched(form);
    key_extra_service::set_key_meta(&db, &model)
        .await
        .map(|_| axum::Json(model))
}

#[utoipa::path(
    get,
    path="",
    operation_id = "获取主密钥元数据信息",
    context_path= "/keys/{key_id}/metas",
    params(
      ("key_id" = String, Path, description="kms 标识"),
    ),
    request_body = KeyMetaPatchForm,
    responses(
        (status = 200, description = "", body = KeyMetaModel),
        (status = 400, description = "illegal params")
    ),
  )]
pub async fn get_key_meta(
    State(States { db, .. }): State<States>,
    Path(key_id): Path<String>,
) -> Result<impl IntoResponse> {
    tracing::info!("get key meta, key_id: {}", key_id);
    key_extra_service::get_main_key_meta(&db, &key_id)
        .await
        .map(axum::Json)
}

#[utoipa::path(
    get,
    path="",
    operation_id = "分页查询主密钥版本信息",
    context_path= "/keys/{key_id}/versions",
    params(
        ("key_id" = String, Path, description="kms 标识"),
        Paginator
      ),
    responses(
        (status = 200, description = "", body = ()),
        (status = 400, description = "illegal params")
    ),
  )]
pub async fn list_key_version(
    State(States { db, .. }): State<States>,
    Path(key_id): Path<String>,
    Query(paginator): Query<Paginator>,
) -> Result<impl IntoResponse> {
    tracing::info!(
        "pagin key meta, key_id: {}, paginator: {:?}",
        key_id,
        paginator
    );

    key_service::list_key_versions(&db, &key_id, &paginator)
        .await
        .map(axum::Json)
}

#[utoipa::path(
  patch,
  path="",
  operation_id = "设置密钥别名",
  context_path= "/keys/{key_id}/aliases",
  params(
    ("key_id" = String, Path, description="kms 标识"),
  ),request_body = KeyAliasCreateOrUpdateForm,
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
    key_extra_service::set_alias(&db, &key_id, &form.alias).await?;
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
    key_extra_service::remove_key_aliases(&db, &key_id, form.aliases).await?;
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
    key_extra_service::list_key_aliases(&db, &key_id, paginator)
        .await
        .map(axum::Json)
}
