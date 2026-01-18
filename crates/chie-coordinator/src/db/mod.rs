//! Database models and queries.

pub mod models;
pub mod repository;

pub use models::*;
pub use repository::*;

use sqlx::PgPool;

/// Database connection pool.
pub type DbPool = PgPool;

/// Initialize the database connection pool.
pub async fn init_pool(database_url: &str) -> anyhow::Result<DbPool> {
    let pool = PgPool::connect(database_url).await?;

    // Run migrations
    sqlx::migrate!("./migrations").run(&pool).await?;

    Ok(pool)
}
