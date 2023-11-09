use axum::{
    response::Html,
    routing::{delete, get, patch, post, put},
    Router,
};
use common::{cache::RdConn, configs::env_var};
use controller::{
    key_controller::{create_key, import_key, import_key_params},
    key_extra_controller::{
        list_key_alias, remove_key_alias, set_key_alias, set_key_meta,
    },
    kms_controller::{create_kms, destroy_kms, get_kms, set_kms},
    ApiDoc,
};
use dotenvy::dotenv;
use sea_orm::DbConn;
use utoipa::OpenApi;
use utoipa_redoc::Redoc;

mod common;
mod controller;
mod entity;
mod pojo;
mod repository;
mod service;

#[derive(Clone)]
pub struct States {
    pub db: DbConn,
    pub rd: RdConn,
}

#[tokio::main]
async fn main() {
    let openapi = ApiDoc::openapi();
    let api_doc = openapi.to_pretty_json().unwrap();
    dotenv().expect(".env file not found");
    common::log::init();
    let state = States {
        db: common::datasource::init().await.unwrap(),
        rd: common::cache::init().await.unwrap(),
    };

    let key_router = Router::new()
        .route("/", post(create_key))
        .route("/import", post(import_key))
        .route("/import/params", get(import_key_params));
    let key_meta_router = Router::new().route("/", post(set_key_meta));
    let key_alias_router = Router::new()
        .route("/", get(list_key_alias))
        .route("/", patch(set_key_alias))
        .route("/", delete(remove_key_alias));
    let kms_router = Router::new()
        .route("/", post(create_kms))
        .route("/", put(set_kms))
        .route("/:kms_id", get(get_kms))
        .route("/:kms_id", delete(destroy_kms));
    let app = Router::new()
        .nest("/kms", kms_router)
        .nest("/keys", key_router)
        .nest("/keys/:key_id/metas", key_meta_router)
        .nest("/keys/:key_id/aliases", key_alias_router)
        .route(
            "/openapi",
            get(move || async { Html::from(Redoc::new(openapi).to_html()) }),
        )
        .route("/openapi/doc", get(move || async { api_doc }))
        .with_state(state);
    axum::serve(
        tokio::net::TcpListener::bind(format!(
            "{}:{}",
            env_var::<String>("SERVER_HOST"),
            env_var::<u16>("SERVER_PORT")
        ))
        .await
        .unwrap(),
        app,
    )
    .await
    .unwrap();
}
