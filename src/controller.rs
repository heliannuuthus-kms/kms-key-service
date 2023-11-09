use utoipa::OpenApi;

use crate::{
    common::{
        datasource::{PaginatedKeyAliasModels, Paginator},
        encrypto::types::{
            KeyOrigin, KeySpec, KeyState, KeyType, KeyUsage,
            WrappingKeyAlgorithm, WrappingKeySpec,
        },
    },
    entity::prelude::*,
    pojo::{
        form::{
            key::{KeyCreateForm, KeyImportForm, KeyImportParamsQuery},
            key_meta::{
                KeyAliasDeleteForm, KeyAliasPatchForm, KeyMetaPatchForm,
            },
            kms::{KmsCreateForm, KmsUpdateForm},
        },
        result::{
            key::{KeyCreateResult, KeyMaterialImportParamsResult},
            kms::KmsResult,
        },
    },
};

pub mod key_controller;
pub mod key_meta_controller;
pub mod kms_controller;

#[derive(OpenApi)]
#[openapi(
    components(schemas(
        KmsModel,
        KeyAliasModel,
        KeyMetaModel,
        KmsResult,
        KmsCreateForm,
        KmsUpdateForm,
        KeyCreateForm,
        KeyImportParamsQuery,
        KeyImportForm,
        KeyCreateResult,
        KeyMaterialImportParamsResult,
        KeyAliasDeleteForm,
        KeyAliasPatchForm,
        KeyMetaPatchForm,
        KeyUsage,
        KeyOrigin,
        KeySpec,
        KeyState,
        KeyType,
        WrappingKeyAlgorithm,
        WrappingKeySpec,
        Paginator,
        PaginatedKeyAliasModels,
    )),
    paths(
        key_controller::create_key,
        key_controller::import_key,
        key_controller::import_key_params,
        kms_controller::create_kms,
        kms_controller::set_kms,
        kms_controller::get_kms,
        kms_controller::destroy_kms,
        key_meta_controller::set_key_meta,
        key_meta_controller::set_key_alias,
        key_meta_controller::remove_key_alias,
        key_meta_controller::list_key_alias,
    )
)]
pub struct ApiDoc {}
