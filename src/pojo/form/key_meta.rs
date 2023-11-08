use axum::extract::{FromRequest, Path};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    common::{axum::Json, configs::Patch},
    entity::prelude::*,
};
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct KeyMetaPatchForm {
    pub key_id: String,
    pub description: Option<String>,
}

impl Patch for KeyMetaPatchForm {
    type Into = KeyMetaModel;

    fn merge(&self, into: &mut Self::Into) {
        into.key_id = self.key_id.to_owned();
        into.description = self.description.clone();
    }
}

#[derive(Serialize, Deserialize, ToSchema, Debug, FromRequest)]
pub struct KeyAliasPatchForm {
    #[from_request(via(Path))]
    pub key_id: String,
    #[from_request(via(Json))]
    pub alias: KeyAliasPatchFormAliases,
}

#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct KeyAliasPatchFormAliases {
    alias: String,
}

impl Patch for KeyAliasPatchForm {
    type Into = KeyAliasModel;

    fn merge(&self, into: &mut Self::Into) {
        into.key_id = self.key_id.to_owned();
        into.alias = self.alias.alias.to_owned()
    }
}

#[derive(Serialize, Deserialize, ToSchema, Debug, FromRequest)]
pub struct KeyAliasDeleteForm {
    #[from_request(via(Path))]
    pub key_id: String,
    #[from_request(via(Json))]
    pub aliases: KeyAliasDeleteFormAliases,
}

#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct KeyAliasDeleteFormAliases {
    pub aliases: Vec<String>,
}
