//! Database connection pool management

use crate::errors::DbError;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::time::Duration;
use tracing::{info, instrument};

/// Create a PostgreSQL connection pool with default settings
///
/// # Arguments
/// * `database_url` - PostgreSQL connection URL (e.g., "postgres://user:pass@host/db")
///
/// # Errors
/// Returns `DbError::ConnectionFailed` if the connection cannot be established.
#[instrument(skip(database_url))]
pub async fn create_pool(database_url: &str) -> Result<PgPool, DbError> {
    info!("Creating PostgreSQL connection pool");

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await
        .map_err(|source| DbError::ConnectionFailed { source })?;

    info!("PostgreSQL connection pool created successfully");
    Ok(pool)
}

/// Create a PostgreSQL connection pool with custom options
///
/// # Arguments
/// * `database_url` - PostgreSQL connection URL
/// * `max_connections` - Maximum number of connections in the pool
/// * `timeout` - Connection acquisition timeout in seconds
///
/// # Errors
/// Returns `DbError::ConnectionFailed` if the connection cannot be established.
#[instrument(skip(database_url))]
pub async fn create_pool_with_options(
    database_url: &str,
    max_connections: u32,
    timeout: u64,
) -> Result<PgPool, DbError> {
    info!(
        max_connections = max_connections,
        timeout_secs = timeout,
        "Creating PostgreSQL connection pool with custom options"
    );

    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(timeout))
        .connect(database_url)
        .await
        .map_err(|source| DbError::ConnectionFailed { source })?;

    info!("PostgreSQL connection pool created successfully");
    Ok(pool)
}

/// Create a PostgreSQL connection pool from parsed options
///
/// This allows for more fine-grained control over connection parameters.
///
/// # Errors
/// Returns `DbError::ConnectionFailed` if the connection cannot be established.
#[instrument]
pub async fn create_pool_from_options(
    options: PgConnectOptions,
    max_connections: u32,
) -> Result<PgPool, DbError> {
    info!(
        max_connections = max_connections,
        "Creating PostgreSQL connection pool from options"
    );

    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options)
        .await
        .map_err(|source| DbError::ConnectionFailed { source })?;

    info!("PostgreSQL connection pool created successfully");
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_pool_requires_valid_url() {
        let result = create_pool("invalid://url").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_pool_with_options() {
        let result = create_pool_with_options("invalid://url", 5, 3).await;
        assert!(result.is_err());
    }
}
