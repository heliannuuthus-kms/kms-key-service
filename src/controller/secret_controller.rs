use actix_web::{patch, post, web::Json, HttpResponse, Responder};

use crate::{
    common::errors::Result,
    pojo::{
        form::secret::SecretCreateForm,
        po::secret::{Secret, SecretMeta},
    },
    service::secret_service,
};

#[post("")]
pub async fn create_secret(
    Json(form): Json<SecretCreateForm>,
) -> Result<impl Responder> {
    let (mut secret, mut secret_meta): (Secret, SecretMeta) =
        form.try_into()?;
    let key_id: String =
        secret_service::create_secret(&mut secret, &mut secret_meta).await?;
    Ok(HttpResponse::Ok().json(format!(r#"{{"key_id": {}}}"#, key_id)))
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
