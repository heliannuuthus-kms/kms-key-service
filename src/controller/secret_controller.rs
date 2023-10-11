use actix_web::{post, web::Json, Responder};

use crate::{common::errors::Result, pojo::form::secret::SymmetricSecretCreateForm};

#[post("/symmetric")]
pub async fn generate_secret(
    Json(form): Json<SymmetricSecretCreateForm>,
) -> Result<impl Responder> {
    
  Ok("")
}
