use actix_web::error::ErrorBadRequest;
use anyhow::Context;
use sqlx::MySql;

use crate::{
    common::errors::{Result, ServiceError},
    pojo::po::secret::{Secret, SecretMeta},
};
pub async fn insert_secret(
    tx: &mut sqlx::Transaction<'_, MySql>,
    sec: &Secret,
) -> Result<()> {
    match sec.key_type {
        crate::common::enums::KeyType::Symmetric => {
            sqlx::query_as!(
                Secret,
                "INSERT INTO t_secret(key_id, primary_key_id, key_type, \
                 key_pair) VALUES(?, ?, ? ,?)",
                sec.key_id,
                sec.primary_key_id,
                sec.key_type,
                sec.key_pair
            )
            .execute(tx.as_mut())
            .await
            .with_context(|| {
                tracing::error!(
                    "create symmetric secret faield, key_id: {}",
                    sec.key_id
                );
                "create secret failed"
            })?;
        }
        crate::common::enums::KeyType::Asymmetric => {
            sqlx::query_as!(
                Secret,
                "INSERT INTO t_secret(key_id, primary_key_id, key_type, \
                 pub_key, pri_key) VALUES(?, ?, ? ,?, ?)",
                sec.key_id,
                sec.primary_key_id,
                sec.key_type,
                sec.pub_key,
                sec.pri_key,
            )
            .execute(tx.as_mut())
            .await
            .with_context(|| {
                tracing::error!(
                    "create asynmmtric secret faield, key_id: {}",
                    sec.key_id
                );
                "create secret failed"
            })?;
        }
        crate::common::enums::KeyType::Unknown => {
            return Err(ServiceError::Reponse(ErrorBadRequest(
                "unknown key type",
            )))
        }
    }

    Ok(())
}

pub async fn insert_secret_meta(
    tx: &mut sqlx::Transaction<'_, MySql>,
    meta: &SecretMeta,
) -> Result<()> {
    sqlx::query!(
        "INSERT INTO t_secret_meta(key_id, sepc, origin, description, state, \
         `usage`, rotation_interval, creator, material_expire_at, \
         last_rotation_at, deletion_at) VALUE(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        meta.key_id,
        meta.spec,
        meta.origin,
        meta.description,
        meta.state,
        meta.usage,
        meta.rotation_interval,
        meta.creator,
        meta.material_expire_at,
        meta.last_rotation_at,
        meta.deletion_at,
    )
    .execute(tx.as_mut())
    .await
    .with_context(|| {
        tracing::error!("create secret meta failed, key_id: {}", meta.key_id,);
        "create secret meta failed"
    })?;
    Ok(())
}
