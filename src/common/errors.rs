use axum::{response::IntoResponse, Json};
use chrono::offset;
use http::StatusCode;
use sea_orm::DbErr;
use serde_json::json;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, ServiceError>;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("{0}")]
    BadRequest(String),
    #[error("illegal secret format {0}")]
    ChaoticSecret(String),
    #[error("sign failed {0}")]
    SignFailed(String),
    #[error("signature verify failed {0}")]
    VerifyFailed(String),
    #[error("{0}")]
    NotFount(String),
    #[error("internal server error {0}")]
    InternalServer(#[from] anyhow::Error),
    #[error("datasource error")]
    Datasource(#[from] DbErr),
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("{:?}", self);
        let resp = match self {
            ServiceError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ServiceError::SignFailed(msg) => (StatusCode::BAD_REQUEST, msg),
            ServiceError::VerifyFailed(msg) => (StatusCode::BAD_REQUEST, msg),
            ServiceError::NotFount(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, msg)
            }
            ServiceError::InternalServer(e) => {
                tracing::debug!("error backtrace: {}", e.backtrace());
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
            ServiceError::Datasource(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
            ServiceError::ChaoticSecret(msg) => (StatusCode::BAD_REQUEST, msg),
        };

        (
            resp.0,
            Json(json!({
                "code": resp.0.as_u16(),
                "msg": resp.1,
                "timestamp": offset::Local::now()
            })),
        )
            .into_response()
    }
}
