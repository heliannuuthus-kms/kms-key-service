use utoipa::OpenApi;

use crate::{
    common::secrets::types::{
        KeyOrigin, KeySpec, KeyUsage, WrappingKeyAlgorithm, WrappingKeySpec,
    },
    pojo::{
        form::{
            kms::{KmsCreateForm, KmsUpdateForm},
            secret::{
                SecretCreateForm, SecretImportForm, SecretImportParamsQuery,
            },
        },
        result::secret::SecretMaterialImportParamsResult,
    },
};

pub mod kms_controller;
pub mod secret_controller;

#[derive(OpenApi)]
#[openapi(
    components(schemas(
        SecretCreateForm,
        SecretImportParamsQuery,
        SecretImportForm,
        SecretMaterialImportParamsResult,
        KmsCreateForm,
        KmsUpdateForm,
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
        kms_controller::create_kms,
        kms_controller::set_kms,
        kms_controller::get_kms,
        kms_controller::destroy_kms,
    )
)]
pub struct ApiDoc {}
