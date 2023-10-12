use sqlx::MySql;

use crate::common::errors::Result;

pub async fn insert_sysmtric_secret(tx: &mut sqlx::Transaction<'_, MySql>) -> Result<()> {
  
  let row = sqlx::query("INSERT INTO t_secret(key_id, )").fetch_one(&mut *tx).await?;

    sqlx::query("...").execute(&mut *tx).await?;
}
