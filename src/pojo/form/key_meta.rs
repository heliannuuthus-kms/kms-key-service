use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{common::configs::Patch, entity::prelude::*};
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct KeyMetaPatchForm {
    pub description: Option<String>,
}

impl Patch for KeyMetaPatchForm {
    type Into = KeyMetaModel;

    fn merge(&self, into: &mut Self::Into) {
        into.description = self.description.clone();
    }
}

#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct KeyAliasPatchForm {
    pub alias: String,
}

impl Patch for KeyAliasPatchForm {
    type Into = KeyAliasModel;

    fn merge(&self, into: &mut Self::Into) {
        into.alias = self.alias.to_owned()
    }
}

#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct KeyAliasDeleteForm {
    pub aliases: Vec<String>,
}
