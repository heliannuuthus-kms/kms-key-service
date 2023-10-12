use actix_web::{App, HttpServer};
use common::configs::{env_var, env_var_default};
use controller::ApiDoc;
use dotenvy::dotenv;
use tracing_actix_web::TracingLogger;
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use utoipa::OpenApi;
use utoipa_redoc::{Redoc, Servable};
mod common;
mod controller;
mod pojo;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().expect(".env file not found");
    let file_appender = tracing_appender::rolling::hourly(
        env_var_default::<String>("LOG", "./log".to_string()),
        format!("{}.log", env!("CARGO_PKG_NAME")),
    );
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    let _ = tracing::subscriber::set_global_default(
        tracing_subscriber::fmt::Subscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish()
            .with(
                tracing_subscriber::fmt::Layer::default()
                    .with_writer(non_blocking),
            ),
    );
    let api_doc = ApiDoc::openapi();

    HttpServer::new(move || {
        App::new()
            .wrap(TracingLogger::default())
            .service(Redoc::with_url("/openapi", api_doc.clone()))
    })
    .bind((
        env_var::<String>("SERVER_HOST"),
        env_var::<u16>("SERVER_PORT"),
    ))?
    .run()
    .await
}
