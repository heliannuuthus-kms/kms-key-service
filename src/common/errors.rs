use actix_web::{
    http::{header::ContentType, StatusCode},
    HttpResponse, ResponseError,
};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, ServiceError>;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("{0}")]
    Reponse(#[from] actix_web::Error),
    #[error("an unspecified internal error occurred {0}")]
    Internal(#[from] anyhow::Error),
}

impl ResponseError for ServiceError {
    fn status_code(&self) -> http::StatusCode {
        match self {
            ServiceError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ServiceError::Reponse(e) => e.as_response_error().status_code(),
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::json())
            .body(format!(
                r#"{{
              "code": {},
              "msg": "{}"
          }}"#,
                self.status_code().as_str(),
                self
            ))
    }
}
