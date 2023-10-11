use utoipa::OpenApi;

pub mod secret_controller;

#[derive(OpenApi)]
#[openapi()]
pub struct ApiDoc;
