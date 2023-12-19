use utoipa::OpenApi;

use crate::{
    common::datasource::{PaginatedKeyAliasModels, Paginator},
    crypto::types::{
        KeyOrigin, KeySpec, KeyState, KeyType, KeyUsage, WrappingKeyAlgorithm,
        WrappingKeySpec,
    },
    entity::prelude::*,
    pojo::{
        form::{
            key::{KeyCreateForm, KeyImportForm, KeyImportParamsQuery},
            key_extra::{
                KeyAliasCreateOrUpdateForm, KeyAliasDeleteForm,
                KeyChangeStateBody, KeyMetaPatchForm,
            },
            kms::{KmsCreateForm, KmsPatchForm},
        },
        result::{
            key::{
                KeyCreateResult, KeyMaterialImportParamsResult,
                KeyVersionResult,
            },
            kms::KmsResult,
        },
    },
};

pub mod crypto_controller;
pub mod key_alias_controller;
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
        KmsPatchForm,
        KeyCreateForm,
        KeyChangeStateBody,
        KeyImportParamsQuery,
        KeyImportForm,
        KeyCreateResult,
        KeyMaterialImportParamsResult,
        KeyAliasDeleteForm,
        KeyAliasCreateOrUpdateForm,
        KeyVersionResult,
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
        kms_controller::create_kms,
        kms_controller::destroy_kms,
        kms_controller::set_kms,
        kms_controller::get_kms,
        key_controller::create_key,
        key_controller::import_key,
        key_controller::import_key_params,
        key_controller::create_key_version,
        key_meta_controller::list_kms_keys,
        key_meta_controller::list_key_version,
        key_meta_controller::set_key_meta,
        key_meta_controller::get_key_meta,
        key_meta_controller::change_key_state,
        key_alias_controller::set_key_alias,
        key_alias_controller::remove_key_alias,
        key_alias_controller::list_key_alias,
        crypto_controller::encrypt,
        crypto_controller::advance_encrypt,
        crypto_controller::decrypt,
        crypto_controller::advance_sign,
        crypto_controller::sign,
        crypto_controller::verify,
    )
)]
pub struct ApiDoc {}
