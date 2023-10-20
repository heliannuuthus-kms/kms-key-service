use axum::response::IntoResponse;
use http::StatusCode;
use sea_orm::DbErr;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, ServiceError>;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("{0}")]
    BadRequest(String),
    #[error("sign failed {0}")]
    SignFailed(String),
    #[error("signature verify failed {0}")]
    VerifyFailed(String),
    #[error("{0}")]
    NotFount(String),
    #[error("an unspecified internal error occurred {0}")]
    Internal(#[from] anyhow::Error),
    #[error("datasource error")]
    Datasource(#[from] DbErr),
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> axum::response::Response {
        match self {
            ServiceError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ServiceError::SignFailed(msg) => (StatusCode::BAD_REQUEST, msg),
            ServiceError::VerifyFailed(msg) => (StatusCode::BAD_REQUEST, msg),
            ServiceError::NotFount(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, msg)
            }
            ServiceError::Internal(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
            ServiceError::Datasource(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
        }
        .into_response()
    }
}
