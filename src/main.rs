use axum::{
    routing::{delete, get, patch, post, put},
    Router,
};
use common::configs::env_var;
use controller::{
    kms_controller::{
        create_kms, destroy_kms, get_kms, rotate_kms_aksk, set_kms,
    },
    secret_controller::{
        create_secret, import_secret, import_secret_params, set_secret_meta,
    },
    ApiDoc,
};
use dotenvy::dotenv;
use sea_orm::DbConn;
use utoipa::OpenApi;

mod common;
mod controller;
mod entity;
mod pojo;
mod repository;
mod service;

#[derive(Clone)]
struct States {
    db: DbConn,
    cache: redis::Client,
}

#[tokio::main]
async fn main() {
    let api = ApiDoc::openapi();
    let api_doc = api.to_pretty_json().unwrap();
    dotenv().expect(".env file not found");
    common::log::init();
    let db = common::datasource::init().await.unwrap();
    let cache = common::cache::init().await.unwrap();
    let state = States { db, cache };
    let secret_router = Router::new()
        .route("/", post(create_secret))
        .route("/import", post(import_secret))
        .route("/import/params", get(import_secret_params))
        .route("/meta", patch(set_secret_meta));
    let kms_router = Router::new()
        .route("/", post(create_kms))
        .route("/", put(set_kms))
        .route("/:kms_id", get(get_kms))
        .route("/:kms_id", delete(destroy_kms))
        .route("/:kms_id/rotate", post(rotate_kms_aksk));
    let app = Router::new()
        .nest("/kms", kms_router)
        .nest("/secrets", secret_router)
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
