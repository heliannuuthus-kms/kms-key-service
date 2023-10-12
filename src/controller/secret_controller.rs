use actix_web::{post, web::Json, Responder, put, patch};

use crate::{common::errors::Result, pojo::form::secret::SecretCreateForm};

#[post("")]
pub async fn create_secret(
    Json(_form): Json<SecretCreateForm>,
) -> Result<impl Responder> {
    Ok("")
}


#[post("/import")]
pub async fn import_secret(
    Json(_form): Json<SecretCreateForm>,
) -> Result<impl Responder> {
    Ok("")
}


#[patch("")]
pub async fn set_secret_meta(
    Json(_form): Json<SecretCreateForm>,
) -> Result<impl Responder> {
    Ok("")
}
