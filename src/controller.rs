use utoipa::OpenApi;

use crate::{
    common::encrypto::types::{
        KeyOrigin, KeySpec, KeyState, KeyType, KeyUsage, WrappingKeyAlgorithm,
        WrappingKeySpec,
    },
    entity::{self},
    pojo::{
        form::{
            key::{KeyCreateForm, KeyImportForm, KeyImportParamsQuery},
            kms::{KmsCreateForm, KmsUpdateForm},
        },
        result::{
            key::{KeyCreateResult, KeyMaterialImportParamsResult},
            kms::KmsResult,
        },
    },
};

pub mod key_controller;
pub mod kms_controller;

#[derive(OpenApi)]
#[openapi(
    components(schemas(
        entity::kms::Model,
        KmsResult,
        KmsCreateForm,
        KmsUpdateForm,
        KeyCreateForm,
        KeyImportParamsQuery,
        KeyImportForm,
        KeyCreateResult,
        KeyMaterialImportParamsResult,
        KeyUsage,
        KeyOrigin,
        KeySpec,
        KeyState,
        KeyType,
        WrappingKeyAlgorithm,
        WrappingKeySpec
    )),
    paths(
        key_controller::create_key,
        key_controller::import_key,
        key_controller::import_key_params,
        key_controller::set_key_meta,
        kms_controller::create_kms,
        kms_controller::set_kms,
        kms_controller::get_kms,
        kms_controller::destroy_kms,
    )
)]
pub struct ApiDoc {}
