use crate::common::configs::Patch;
use crate::entity::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

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

#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct KeyAliasPatchForm {
    pub key_id: String,
    pub alias: String,
}

impl Patch for KeyAliasPatchForm {
    type Into = KeyAliasModel;

    fn merge(&self, into: &mut Self::Into) {
        into.key_id = self.key_id.to_owned();
        into.alias = self.alias.to_owned();
    }
}
