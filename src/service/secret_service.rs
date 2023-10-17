use crate::{
    common::{
        algorithm::KeyOrigin,
        datasource::{tx_begin, tx_commit},
        errors::Result,
    },
    pojo::po::secret::{Secret, SecretMeta},
    repository::secret_repository,
};

pub async fn create_secret(
    secret: &mut Secret,
    secret_meta: &mut SecretMeta,
) -> Result<String> {
    let mut tx = tx_begin("create secret").await?;
    // 插入数据
    secret_repository::insert_secret(&mut tx, secret).await?;
    secret_repository::insert_secret_meta(&mut tx, secret_meta).await?;
    tx_commit(tx, "create secret").await?;
    Ok(secret.key_id.clone())
}
