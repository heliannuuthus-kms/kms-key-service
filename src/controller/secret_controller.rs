use actix_web::{patch, post, put, web::Json, Responder};

use crate::{
    common::{
        datasource::{tx_begin, CONN, tx_commit},
        errors::Result,
    },
    pojo::{
        form::secret::SecretCreateForm,
        po::secret::{Secret, SecretMeta},
    },
    repository::secret_repository, service::secret_service,
};

#[post("")]
pub async fn create_secret(
    Json(form): Json<SecretCreateForm>,
) -> Result<impl Responder> {
    let (secret, secret_meta): (Secret, SecretMeta) = form.try_into()?;
    secret_service::create_secret(&mut secret, &mut secret_meta).await?;
    
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
