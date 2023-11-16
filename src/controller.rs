use utoipa::OpenApi;

use crate::{
    common::{
        crypto::types::{
            KeyOrigin, KeySpec, KeyState, KeyType, KeyUsage,
            WrappingKeyAlgorithm, WrappingKeySpec,
        },
        datasource::{PaginatedKeyAliasModels, Paginator},
    },
    entity::prelude::*,
    pojo::{
        form::{
            key::{KeyCreateForm, KeyImportForm, KeyImportParamsQuery},
            key_extra::{
                KeyAliasCreateOrUpdateForm, KeyAliasDeleteForm,
                KeyMetaPatchForm,
            },
            kms::{KmsCreateForm, KmsPatchForm},
        },
        result::{
            key::{KeyCreateResult, KeyMaterialImportParamsResult},
            kms::KmsResult,
        },
    },
};

pub mod crypto_controller;
pub mod key_controller;
pub mod key_extra_controller;
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
        KeyImportParamsQuery,
        KeyImportForm,
        KeyCreateResult,
        KeyMaterialImportParamsResult,
        KeyAliasDeleteForm,
        KeyAliasCreateOrUpdateForm,
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
        key_controller::list_kms_keys,
        kms_controller::create_kms,
        kms_controller::set_kms,
        kms_controller::get_kms,
        kms_controller::destroy_kms,
        key_extra_controller::set_key_meta,
        key_extra_controller::set_key_alias,
        key_extra_controller::remove_key_alias,
        key_extra_controller::list_key_alias,
        key_extra_controller::list_key_version,
        
    )
)]
pub struct ApiDoc {}
