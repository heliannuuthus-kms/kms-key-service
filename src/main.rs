use axum::{
    response::Html,
    routing::{delete, get, patch, post},
    Router,
};
use common::{cache::RdConn, configs::env_var};
use controller::{
    crypto_controller::{
        advance_encrypt, advance_sign, decrypt, encrypt, sign, verify,
    },
    key_alias_controller::{list_key_alias, remove_key_alias, set_key_alias},
    key_controller::{
        create_key, create_key_version, import_key, import_key_params,
        list_key_version, list_kms_keys,
    },
    key_meta_controller::{change_key_state, get_key_meta, set_key_meta},
    kms_controller::{create_kms, destroy_kms, get_kms, set_kms},
    ApiDoc,
};
use dotenvy::dotenv;
use sea_orm::DbConn;
use service::key_service::RotateExecutor;
use utoipa::OpenApi;
use utoipa_redoc::Redoc;

mod common;
mod controller;
mod crypto;
mod entity;
mod pojo;
mod repository;
mod service;

#[derive(Clone)]
pub struct States {
    pub db: DbConn,
    pub rd: RdConn,
    pub extra: ExtraStates,
}

#[derive(Clone)]
pub struct ExtraStates {
    re: RotateExecutor,
}

#[tokio::main]
async fn main() {
    let openapi = ApiDoc::openapi();
    let api_doc = openapi.to_pretty_json().unwrap();
    dotenv().expect(".env file not found");
    common::log::init();
    let db = common::datasource::init().await.unwrap();
    let rd = common::cache::init().await.unwrap();
    let executor = RotateExecutor::new(db.clone(), rd.clone()).await;
    let state = States {
        db,
        rd,
        extra: ExtraStates {
            re: executor.clone(),
        },
    };
    tokio::spawn(async move {
        executor.poll_purge().await.unwrap();
    });
    let key_router = Router::new()
        .route("/", post(create_key))
        .route("/import", post(import_key))
        .route("/import/params", get(import_key_params));
    let key_extra_router = Router::new()
        .route("/state", post(change_key_state))
        .route("/metas", post(set_key_meta))
        .route("/metas", get(get_key_meta))
        .route("/versions", post(create_key_version))
        .route("/versions", get(list_key_version))
        .route("/aliases", patch(set_key_alias))
        .route("/aliases", delete(remove_key_alias))
        .route("/aliases", get(list_key_alias));
    let crypto_router = Router::new()
        .route("/encrypt", post(advance_encrypt))
        .route("/decrypt", post(decrypt))
        .route("/encrypt/:version", post(encrypt))
        .route("/sign", post(advance_sign))
        .route("/sign/:version", post(sign))
        .route("/verify", post(verify));
    let kms_router = Router::new()
        .route("/", post(create_kms))
        .route("/:kms_id", patch(set_kms))
        .route("/:kms_id", get(get_kms))
        .route("/:kms_id", delete(destroy_kms))
        .route("/:kms_id/keys", get(list_kms_keys));
    let app = Router::new()
        .nest("/kms", kms_router)
        .nest("/keys", key_router)
        .nest("/keys/:key_id/", key_extra_router)
        .nest("/keys/:key_id/", crypto_router)
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
