use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    common::configs::Patch, crypto::types::KeyState, entity::prelude::*,
};
#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct KeyMetaPatchForm {
    pub description: Option<String>,
}

impl Patch<KeyMetaPatchForm> for KeyMetaModel {
    fn patched(&mut self, patched: KeyMetaPatchForm) -> &mut Self {
        if let Some(description) = patched.description {
            self.description = Some(description)
        }
        self
    }
    // fn patched(&mut self, patcher: KeyMetaPatchForm) -> &mut Self {
    //     patcher.description.map(|patched| {
    //         match patched {
    //             Some(description) =>  {
    //                 match stringify!(self.description) {
    //                     "Option" => {
    //                         self.description = Some(description);
    //                     },
    //                     _ => {
    //                         self.description = description;
    //                     }
    //                 }
    //             },
    //             None => {}
    //         }
    //     });
    //     self
    // }
}

#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct KeyAliasCreateOrUpdateForm {
    pub alias: String,
}

#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct KeyAliasDeleteForm {
    pub aliases: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, ToSchema, Clone)]
pub struct KeyChangeStateBody {
    pub key_id: String,
    pub from: KeyState,
    pub to: KeyState,
}
