use utoipa::OpenApi;

use crate::{
    common::algorithm::{KeyOrigin, KeySpec, KeyUsage},
    pojo::form::secret::SecretCreateForm,
};

pub mod secret_controller;

#[derive(OpenApi)]
#[openapi(
    components(schemas(SecretCreateForm, KeyUsage, KeyOrigin, KeySpec)),
    paths(
        secret_controller::create_secret,
        secret_controller::import_secret_params,
        secret_controller::set_secret_meta,
    )
)]
pub struct ApiDoc {}
