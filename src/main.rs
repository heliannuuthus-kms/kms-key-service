use std::{net::SocketAddr, time::Duration};

use axum::{
    routing::{get, patch, post},
    Router,
};
use common::configs::{env_var, env_var_default};
use controller::{
    secret_controller::{self, create_secret, import_secret, set_secret_meta},
    ApiDoc,
};
use dotenvy::dotenv;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use tracing_actix_web::TracingLogger;
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
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
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv().expect(".env file not found");

    common::logger::init();
    let db = common::datasource::init().await.unwrap();
    let state = States { db };

    let app = Router::new()
        .route_service(
            "/secrets",
            Router::new()
                .route("", post(create_secret))
                .route("/import", post(import_secret))
                .route("/meta", patch(set_secret_meta)),
        )
        .merge(Redoc::with_url("/openapi", ApiDoc::openapi()))
        .with_state(state);

    let addr = format!(
        "{}:{}",
        env_var::<String>("SERVER_HOST"),
        env_var::<u16>("SERVER_PORT")
    );
    axum::Server::bind(&addr.parse::<SocketAddr>().unwrap())
        .serve(app.into_make_service());
    Ok(())
}
