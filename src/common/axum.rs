use axum::{
    extract::{
        rejection::{FormRejection, JsonRejection, QueryRejection},
        FromRequest, FromRequestParts,
    },
    response::IntoResponse,
};
use chrono::{DateTime, FixedOffset, Local};
use http::StatusCode;
use serde::Serialize;
use serde_json::json;

#[derive(FromRequest)]
#[from_request(via(axum::Json), rejection(ErrorResponse))]
pub struct Json<T>(pub T);

#[derive(FromRequest)]
#[from_request(via(axum::Form), rejection(ErrorResponse))]
pub struct Form<T>(pub T);

#[derive(FromRequestParts)]
#[from_request(via(axum::extract::Query), rejection(ErrorResponse))]
pub struct Query<T>(pub T);

impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> axum::response::Response {
        let Self(value) = self;
        axum::Json(value).into_response()
    }
}

impl<T: Serialize> IntoResponse for Form<T> {
    fn into_response(self) -> axum::response::Response {
        let Self(value) = self;
        axum::Json(value).into_response()
    }
}

#[derive(Debug)]
pub struct ErrorResponse {
    code: StatusCode,
    msg: String,
    timestamp: DateTime<FixedOffset>,
}

impl From<JsonRejection> for ErrorResponse {
    fn from(rejection: JsonRejection) -> Self {
        Self {
            code: StatusCode::BAD_REQUEST,
            msg: rejection.body_text(),
            timestamp: Local::now().fixed_offset(),
        }
    }
}

impl From<FormRejection> for ErrorResponse {
    fn from(rejection: FormRejection) -> Self {
        Self {
            code: StatusCode::BAD_REQUEST,
            msg: rejection.body_text(),
            timestamp: Local::now().fixed_offset(),
        }
    }
}

impl From<QueryRejection> for ErrorResponse {
    fn from(rejection: QueryRejection) -> Self {
        Self {
            code: StatusCode::BAD_REQUEST,
            msg: rejection.body_text(),
            timestamp: Local::now().fixed_offset(),
        }
    }
}

impl<T: Serialize> IntoResponse for Query<T> {
    fn into_response(self) -> axum::response::Response {
        let Self(value) = self;
        axum::Json(value).into_response()
    }
}
// We implement `IntoResponse` so `ApiError` can be used as a response
impl IntoResponse for ErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (
            self.code,
            axum::Json(json!({
                "code": self.code.as_u16(),
                "msg": self.msg,
                "timestamp": self.timestamp
            })),
        )
            .into_response()
    }
}
