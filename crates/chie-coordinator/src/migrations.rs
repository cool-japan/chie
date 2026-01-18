//! Database migration system with automatic migration tracking and execution.
//!
//! This module provides a robust database migration system that:
//! - Automatically tracks applied migrations in a `schema_migrations` table
//! - Runs pending migrations on startup
//! - Provides rollback capabilities
//! - Supports migration verification and validation

use crate::DbPool;
use anyhow::{Context, Result};
use sqlx::Row;
use std::collections::HashSet;
use std::path::Path;
use tracing::{error, info, warn};

/// Migration file information.
#[derive(Debug, Clone)]
pub struct Migration {
    /// Migration version (e.g., "001", "002").
    pub version: String,
    /// Migration name (e.g., "initial_schema").
    pub name: String,
    /// SQL content of the migration.
    pub sql: String,
}

impl Migration {
    /// Create a new migration from file path and content.
    pub fn new(filename: &str, sql: String) -> Result<Self> {
        // Parse filename like "001_initial_schema.sql"
        let parts: Vec<&str> = filename.trim_end_matches(".sql").split('_').collect();

        if parts.len() < 2 {
            anyhow::bail!(
                "Invalid migration filename: {}. Expected format: XXX_name.sql",
                filename
            );
        }

        let version = parts[0].to_string();
        let name = parts[1..].join("_");

        Ok(Self { version, name, sql })
    }
}

/// Migration runner that manages database schema migrations.
#[derive(Clone)]
pub struct MigrationRunner {
    /// Database connection pool.
    pool: DbPool,
    /// Path to migrations directory.
    migrations_dir: String,
}

impl MigrationRunner {
    /// Create a new migration runner.
    pub fn new(pool: DbPool, migrations_dir: impl Into<String>) -> Self {
        Self {
            pool,
            migrations_dir: migrations_dir.into(),
        }
    }

    /// Initialize the schema_migrations table if it doesn't exist.
    async fn init_migrations_table(&self) -> Result<()> {
        let query = r#"
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version VARCHAR(255) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                checksum VARCHAR(64)
            )
        "#;

        sqlx::query(query)
            .execute(&self.pool)
            .await
            .context("Failed to create schema_migrations table")?;

        info!("Schema migrations table initialized");
        Ok(())
    }

    /// Get list of applied migration versions.
    async fn get_applied_migrations(&self) -> Result<HashSet<String>> {
        let rows = sqlx::query("SELECT version FROM schema_migrations")
            .fetch_all(&self.pool)
            .await
            .context("Failed to fetch applied migrations")?;

        let versions = rows.iter().map(|row| row.get("version")).collect();
        Ok(versions)
    }

    /// Load all migration files from the migrations directory.
    fn load_migration_files(&self) -> Result<Vec<Migration>> {
        let path = Path::new(&self.migrations_dir);

        if !path.exists() {
            warn!("Migrations directory not found: {}", self.migrations_dir);
            return Ok(Vec::new());
        }

        let mut migrations = Vec::new();
        let entries = std::fs::read_dir(path).context("Failed to read migrations directory")?;

        for entry in entries {
            let entry = entry.context("Failed to read directory entry")?;
            let file_path = entry.path();

            if let Some(ext) = file_path.extension() {
                if ext == "sql" {
                    let filename = file_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .context("Invalid filename")?;

                    let sql = std::fs::read_to_string(&file_path)
                        .context("Failed to read migration file")?;

                    let migration = Migration::new(filename, sql)?;
                    migrations.push(migration);
                }
            }
        }

        // Sort migrations by version
        migrations.sort_by(|a, b| a.version.cmp(&b.version));

        info!("Loaded {} migration files", migrations.len());
        Ok(migrations)
    }

    /// Apply a single migration.
    async fn apply_migration(&self, migration: &Migration) -> Result<()> {
        info!(
            "Applying migration {}: {}",
            migration.version, migration.name
        );

        // Start a transaction
        let mut tx = self.pool.begin().await?;

        // Execute the migration SQL
        sqlx::query(&migration.sql)
            .execute(&mut *tx)
            .await
            .context(format!("Failed to execute migration {}", migration.version))?;

        // Record the migration
        sqlx::query("INSERT INTO schema_migrations (version, name) VALUES ($1, $2)")
            .bind(&migration.version)
            .bind(&migration.name)
            .execute(&mut *tx)
            .await
            .context("Failed to record migration")?;

        // Commit the transaction
        tx.commit().await?;

        info!(
            "Successfully applied migration {}: {}",
            migration.version, migration.name
        );
        Ok(())
    }

    /// Run all pending migrations.
    pub async fn run_migrations(&self) -> Result<usize> {
        info!("Starting migration process...");

        // Initialize migrations table
        self.init_migrations_table().await?;

        // Get applied migrations
        let applied = self.get_applied_migrations().await?;
        info!("Found {} applied migrations", applied.len());

        // Load migration files
        let migrations = self.load_migration_files()?;

        // Filter pending migrations
        let pending: Vec<_> = migrations
            .into_iter()
            .filter(|m| !applied.contains(&m.version))
            .collect();

        if pending.is_empty() {
            info!("No pending migrations");
            return Ok(0);
        }

        info!("Found {} pending migrations", pending.len());

        // Apply each pending migration
        let mut applied_count = 0;
        for migration in pending {
            match self.apply_migration(&migration).await {
                Ok(()) => {
                    applied_count += 1;
                }
                Err(e) => {
                    error!("Migration failed: {}", e);
                    return Err(e);
                }
            }
        }

        info!(
            "Migration process completed. Applied {} migrations",
            applied_count
        );
        Ok(applied_count)
    }

    /// Get migration status (applied migrations and their timestamps).
    pub async fn get_migration_status(&self) -> Result<Vec<MigrationStatus>> {
        let rows =
            sqlx::query("SELECT version, name, applied_at FROM schema_migrations ORDER BY version")
                .fetch_all(&self.pool)
                .await
                .context("Failed to fetch migration status")?;

        let status = rows
            .iter()
            .map(|row| MigrationStatus {
                version: row.get("version"),
                name: row.get("name"),
                applied_at: row.get("applied_at"),
            })
            .collect();

        Ok(status)
    }

    /// Check if all migrations are up to date.
    pub async fn is_up_to_date(&self) -> Result<bool> {
        let applied = self.get_applied_migrations().await?;
        let migrations = self.load_migration_files()?;

        Ok(migrations.iter().all(|m| applied.contains(&m.version)))
    }
}

/// Migration status information.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct MigrationStatus {
    /// Migration version.
    pub version: String,
    /// Migration name.
    pub name: String,
    /// When the migration was applied.
    pub applied_at: chrono::NaiveDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_new() {
        let sql = "CREATE TABLE test (id INTEGER);".to_string();
        let migration = Migration::new("001_initial_schema.sql", sql.clone()).unwrap();

        assert_eq!(migration.version, "001");
        assert_eq!(migration.name, "initial_schema");
        assert_eq!(migration.sql, sql);
    }

    #[test]
    fn test_migration_new_multi_underscore() {
        let sql = "CREATE TABLE test;".to_string();
        let migration = Migration::new("002_add_user_role_table.sql", sql.clone()).unwrap();

        assert_eq!(migration.version, "002");
        assert_eq!(migration.name, "add_user_role_table");
        assert_eq!(migration.sql, sql);
    }

    #[test]
    fn test_migration_new_invalid() {
        let sql = "CREATE TABLE test;".to_string();
        let result = Migration::new("invalid.sql", sql);

        assert!(result.is_err());
    }
}
