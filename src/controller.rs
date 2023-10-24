use utoipa::OpenApi;

use crate::{
    common::secrets::algorithm::{
        KeyOrigin, KeySpec, KeyUsage, WrappingKeyAlgorithm, WrappingKeySpec,
    },
    pojo::form::secret::{
        SecretCreateForm, SecretImportForm, SecretImportParamsForm,
    },
};

pub mod secret_controller;

#[derive(OpenApi)]
#[openapi(
    components(schemas(
        SecretCreateForm,
        SecretImportParamsForm,
        SecretImportForm,
        KeyUsage,
        KeyOrigin,
        KeySpec,
        WrappingKeyAlgorithm,
        WrappingKeySpec
    )),
    paths(
        secret_controller::create_secret,
        secret_controller::import_secret,
        secret_controller::import_secret_params,
        secret_controller::set_secret_meta,
    )
)]
pub struct ApiDoc {}
