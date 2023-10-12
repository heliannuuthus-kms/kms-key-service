use actix_web::{post, web::Json, Responder};

use crate::{common::errors::Result, pojo::form::secret::SecretCreateForm};

#[post("")]
pub async fn create_secret(Json(_form): Json<SecretCreateForm>) -> Result<impl Responder> {
    Ok("")
}
