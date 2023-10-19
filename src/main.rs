use std::net::SocketAddr;

use axum::{
    routing::{get, patch, post},
    Router,
};
use common::configs::env_var;
use controller::{
    secret_controller::{create_secret, import_secret_params, set_secret_meta},
    ApiDoc,
};
use dotenvy::dotenv;
use sea_orm::DatabaseConnection;
use utoipa::OpenApi;
use utoipa_redoc::{Redoc, Servable};
mod common;
mod controller;
mod entity;
mod pojo;
mod repository;
mod service;

#[derive(Clone)]
struct States {
    db: DatabaseConnection,
    cache: redis::Client,
}

#[tokio::main]
async fn main() {
    dotenv().expect(".env file not found");
    common::logger::init();
    let db = common::datasource::init().await.unwrap();
    let cache = common::cache::init().await.unwrap();
    let state = States { db, cache };
    let secret_router = Router::new()
        .route("/", post(create_secret))
        .route("/import", post(import_secret_params))
        .route("/import/params", get(import_secret_params))
        .route("/meta", patch(set_secret_meta));
    let app = Router::new()
        .nest("/secrets", secret_router)
        .merge(Redoc::with_url("/openapi", ApiDoc::openapi()))
        .with_state(state);

    let addr = format!(
        "{}:{}",
        env_var::<String>("SERVER_HOST"),
        env_var::<u16>("SERVER_PORT")
    );
    axum::Server::bind(&addr.parse::<SocketAddr>().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
