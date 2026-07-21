//! entity_types registry repository.
//!
//! The `entity_types` table (migration 054) is the single source of truth for
//! which entity types edges may reference and which backing table/id_column
//! each resolves to. This repo reads that table with RUNTIME sqlx queries (no
//! `query!`/`query_as!` macros, so no `.sqlx` prepare is required) and folds a
//! `to_regclass` table-presence probe into each returned entry.
//!
//! NOTE: the NER `entities` table + [`crate::EntityRepository`] are unrelated;
//! this registry is deliberately named `entity_types` / `EntityTypeRepository`
//! to avoid the collision.

use crate::errors::DbError;
use sqlx::PgPool;
use tracing::instrument;

/// One resolved entity-type registry entry.
///
/// `table_present` is computed at load time via `to_regclass(schema.table)`,
/// NOT stored — it reflects whether the backing table currently exists in the
/// connected database, so the hot path (`entity_exists`) needs zero per-call
/// `to_regclass` probes.
#[derive(Debug, Clone)]
pub struct EntityTypeEntry {
    /// schema_name (defaults to `public`).
    pub schema: String,
    /// table_name; `None` for table-less types (e.g. `node`).
    pub table: Option<String>,
    /// id_column (defaults to `id`).
    pub id_column: String,
    /// true = foreign/absent-tolerant (missing table -> Ok(false));
    /// false = owned/fail-loud (missing table -> InternalError).
    pub is_optional: bool,
    /// true = epigraph-owned core type; API-immutable (hijack guard).
    pub is_core: bool,
    /// Whether the backing table currently resolves via `to_regclass` at load
    /// time. Always `false` when `table` is `None`.
    pub table_present: bool,
}

/// Raw registry row as stored (pre-`to_regclass` fold).
#[derive(Debug, Clone, sqlx::FromRow)]
struct EntityTypeRow {
    type_name: String,
    schema_name: String,
    table_name: Option<String>,
    id_column: String,
    is_optional: bool,
    is_core: bool,
}

/// Repository for the `entity_types` registry.
pub struct EntityTypeRepository;

impl EntityTypeRepository {
    /// Load every registered entity type, folding a `to_regclass` presence
    /// probe into each entry's `table_present`.
    ///
    /// Runs one `SELECT *` plus one `to_regclass($1)` per row with a table.
    /// Used at startup to prime the API cache. Table-less rows (`node`) get
    /// `table_present = false` without a probe.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any query fails.
    #[instrument(skip(pool))]
    pub async fn list_all(pool: &PgPool) -> Result<Vec<(String, EntityTypeEntry)>, DbError> {
        let rows: Vec<EntityTypeRow> = sqlx::query_as::<_, EntityTypeRow>(
            "SELECT type_name, schema_name, table_name, id_column, is_optional, is_core \
             FROM entity_types",
        )
        .fetch_all(pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let entry = Self::resolve_row(pool, row).await?;
            out.push(entry);
        }
        Ok(out)
    }

    /// Look up a single entity type by name, folding its `to_regclass` probe.
    /// Returns `None` if the type is not registered.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_name(
        pool: &PgPool,
        type_name: &str,
    ) -> Result<Option<(String, EntityTypeEntry)>, DbError> {
        let row: Option<EntityTypeRow> = sqlx::query_as::<_, EntityTypeRow>(
            "SELECT type_name, schema_name, table_name, id_column, is_optional, is_core \
             FROM entity_types WHERE type_name = $1",
        )
        .bind(type_name)
        .fetch_optional(pool)
        .await?;

        match row {
            Some(row) => Ok(Some(Self::resolve_row(pool, row).await?)),
            None => Ok(None),
        }
    }

    /// Return `Some(is_core)` for a registered type, or `None` if unregistered.
    /// Used by the admin endpoint's hijack guard before an upsert.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool))]
    pub async fn core_status(pool: &PgPool, type_name: &str) -> Result<Option<bool>, DbError> {
        let is_core: Option<bool> =
            sqlx::query_scalar("SELECT is_core FROM entity_types WHERE type_name = $1")
                .bind(type_name)
                .fetch_optional(pool)
                .await?;
        Ok(is_core)
    }

    /// Upsert a NON-core entity type (API registration path).
    ///
    /// Inserts a new row, or updates an existing NON-core row's target
    /// table/schema/id_column/optionality. The `WHERE entity_types.is_core =
    /// false` guard on the conflict arm makes a remap of a core type a no-op at
    /// the SQL layer (belt-and-suspenders behind the handler's 403 hijack
    /// guard). `is_core` is forced `false` and `registered_by` records the
    /// caller's oauth client_id.
    ///
    /// Returns the resolved [`EntityTypeEntry`] (with `table_present` folded via
    /// `to_regclass`) for write-through into the API cache.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(pool))]
    pub async fn upsert_non_core(
        pool: &PgPool,
        type_name: &str,
        schema_name: &str,
        table_name: Option<&str>,
        id_column: &str,
        is_optional: bool,
        registered_by: uuid::Uuid,
    ) -> Result<(String, EntityTypeEntry), DbError> {
        let row: EntityTypeRow = sqlx::query_as::<_, EntityTypeRow>(
            "INSERT INTO entity_types \
                 (type_name, schema_name, table_name, id_column, is_optional, is_core, registered_by) \
             VALUES ($1, $2, $3, $4, $5, false, $6) \
             ON CONFLICT (type_name) DO UPDATE SET \
                 schema_name = EXCLUDED.schema_name, \
                 table_name = EXCLUDED.table_name, \
                 id_column = EXCLUDED.id_column, \
                 is_optional = EXCLUDED.is_optional, \
                 registered_by = EXCLUDED.registered_by, \
                 updated_at = now() \
             WHERE entity_types.is_core = false \
             RETURNING type_name, schema_name, table_name, id_column, is_optional, is_core",
        )
        .bind(type_name)
        .bind(schema_name)
        .bind(table_name)
        .bind(id_column)
        .bind(is_optional)
        .bind(registered_by)
        .fetch_one(pool)
        .await?;

        Self::resolve_row(pool, row).await
    }

    /// Fold a raw row into `(type_name, EntityTypeEntry)`, probing table
    /// presence via `to_regclass`. The `schema.table` value is bound as a TEXT
    /// param to `to_regclass($1)` (a value, never interpolated) — the registry
    /// CHECK regexes already constrain the identifier shape at rest.
    async fn resolve_row(
        pool: &PgPool,
        row: EntityTypeRow,
    ) -> Result<(String, EntityTypeEntry), DbError> {
        let table_present = match row.table_name.as_deref() {
            Some(table) => {
                let qualified = format!("{}.{}", row.schema_name, table);
                let regclass: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
                    .bind(&qualified)
                    .fetch_one(pool)
                    .await?;
                regclass.is_some()
            }
            None => false,
        };

        let entry = EntityTypeEntry {
            schema: row.schema_name,
            table: row.table_name,
            id_column: row.id_column,
            is_optional: row.is_optional,
            is_core: row.is_core,
            table_present,
        };
        Ok((row.type_name, entry))
    }
}
