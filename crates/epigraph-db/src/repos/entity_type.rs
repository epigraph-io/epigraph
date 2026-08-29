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
    /// How this type carries tenancy (migration 069). One of `columns`,
    /// `derived`, `identity`. `unclassified` is forbidden by the
    /// `entity_types_no_unclassified` CHECK, and the column has no DEFAULT —
    /// a registration that omits it is a 23502, not a silent `public`.
    pub tenancy_tier: String,
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
    tenancy_tier: String,
}

/// What migration 077/079 will need to be true of a table before an entity type
/// may claim the `columns` tenancy tier (plan §2.5).
///
/// Reported as data, not as a boolean: the handler turns each individual
/// shortfall into a 400 that NAMES the missing item, so a registrar is told
/// which of the four things to fix rather than "rejected".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenancyPrecondition {
    /// `visibility` exists and is `NOT NULL`.
    pub visibility_not_null: bool,
    /// `owner_group_id` exists and is `NOT NULL`.
    pub owner_group_not_null: bool,
    /// Distinct `pg_policy.polcmd` values on the table. `*` is the
    /// all-commands policy and covers `r`/`a`/`w`/`d` on its own.
    pub policy_cmds: Vec<String>,
    /// `pg_class.relrowsecurity` — RLS is ENABLED, i.e. policies apply at all.
    ///
    /// Independent of [`Self::force_rls`]: `ALTER TABLE … FORCE ROW LEVEL
    /// SECURITY` can be set on a table where RLS was never ENABLEd, and in that
    /// state Postgres applies **no policy whatsoever**. Reading only
    /// `relforcerowsecurity` would report such a table as satisfied while its
    /// tenancy is inert — the one thing the `columns` tier exists to rule out.
    pub rls_enabled: bool,
    /// `pg_class.relforcerowsecurity` — RLS applies to the table OWNER too.
    pub force_rls: bool,
}

impl TenancyPrecondition {
    /// The four commands a `columns`-tier table must have a policy for.
    pub const REQUIRED_CMDS: [&'static str; 4] = ["r", "a", "w", "d"];

    /// Every required command is covered, either by a `*` policy or by its own.
    #[must_use]
    pub fn policies_complete(&self) -> bool {
        self.missing_policy_cmds().is_empty()
    }

    /// The required commands with no covering policy, in `REQUIRED_CMDS` order.
    #[must_use]
    pub fn missing_policy_cmds(&self) -> Vec<&'static str> {
        if self.policy_cmds.iter().any(|c| c == "*") {
            return Vec::new();
        }
        Self::REQUIRED_CMDS
            .iter()
            .copied()
            .filter(|want| !self.policy_cmds.iter().any(|have| have == want))
            .collect()
    }

    /// All five conditions hold.
    #[must_use]
    pub fn is_satisfied(&self) -> bool {
        self.visibility_not_null
            && self.owner_group_not_null
            && self.rls_enabled
            && self.force_rls
            && self.policies_complete()
    }
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
            "SELECT type_name, schema_name, table_name, id_column, is_optional, is_core, \
                    tenancy_tier \
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
            "SELECT type_name, schema_name, table_name, id_column, is_optional, is_core, \
                    tenancy_tier \
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
    /// `tenancy_tier` is REQUIRED, not defaulted: migration 069 drops the
    /// column's DEFAULT, so an INSERT that omits it raises 23502. The handler
    /// validates the vocabulary and (for the `columns` tier) the §2.5
    /// precondition via [`EntityTypeRepository::tenancy_precondition`] before
    /// calling this.
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
        tenancy_tier: &str,
    ) -> Result<(String, EntityTypeEntry), DbError> {
        let row: EntityTypeRow = sqlx::query_as::<_, EntityTypeRow>(
            "INSERT INTO entity_types \
                 (type_name, schema_name, table_name, id_column, is_optional, is_core, \
                  registered_by, tenancy_tier) \
             VALUES ($1, $2, $3, $4, $5, false, $6, $7) \
             ON CONFLICT (type_name) DO UPDATE SET \
                 schema_name = EXCLUDED.schema_name, \
                 table_name = EXCLUDED.table_name, \
                 id_column = EXCLUDED.id_column, \
                 is_optional = EXCLUDED.is_optional, \
                 registered_by = EXCLUDED.registered_by, \
                 tenancy_tier = EXCLUDED.tenancy_tier, \
                 updated_at = now() \
             WHERE entity_types.is_core = false \
             RETURNING type_name, schema_name, table_name, id_column, is_optional, is_core, \
                       tenancy_tier",
        )
        .bind(type_name)
        .bind(schema_name)
        .bind(table_name)
        .bind(id_column)
        .bind(is_optional)
        .bind(registered_by)
        .bind(tenancy_tier)
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
            tenancy_tier: row.tenancy_tier,
        };
        Ok((row.type_name, entry))
    }

    /// Read the §2.5 precondition for a would-be `columns`-tier table.
    ///
    /// **Why this lives in the repo and not the handler.** Plan §2.5 rule 1 says
    /// the check must run *in the handler*, "not in a test" — i.e. at runtime,
    /// on the real database, on every registration. CLAUDE.md says all SQL lives
    /// in `crates/epigraph-db/src/repos/`. Both hold: the three queries are
    /// here, the 400 decision is in `routes/admin.rs::register_entity_type`.
    ///
    /// `schema` / `table` are bound as VALUES, never interpolated. The caller
    /// has already run `is_pg_ident` on both; binding keeps this layer safe
    /// independently of that.
    ///
    /// NOTE ON WHAT THIS RETURNS TODAY: at migration head 069 NO table in the
    /// schema has `relrowsecurity`, `relforcerowsecurity` or a single
    /// `pg_policy` row — RLS is PR-17's migrations 077/079. Every call
    /// therefore reports both RLS flags `false` and an empty `policy_cmds`, and
    /// the `columns` tier is unregisterable through the API for the whole
    /// PR-05 → PR-17 window. That is intended: the six seeded `columns` types
    /// are `is_core = true` and the handler's hijack guard 403s them BEFORE
    /// this function is reached (`routes/admin.rs` runs the guard above the
    /// tier gate, so a core type never reaches these catalog probes).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any of the three catalog queries fails.
    #[instrument(skip(pool))]
    pub async fn tenancy_precondition(
        pool: &PgPool,
        schema: &str,
        table: &str,
    ) -> Result<TenancyPrecondition, DbError> {
        let column_not_null = |column: &'static str| async move {
            let present: Option<bool> = sqlx::query_scalar(
                "SELECT (is_nullable = 'NO') FROM information_schema.columns \
                 WHERE table_schema = $1 AND table_name = $2 AND column_name = $3",
            )
            .bind(schema)
            .bind(table)
            .bind(column)
            .fetch_optional(pool)
            .await?;
            // Absent column -> `None` -> not satisfied. An absent TABLE is the
            // same answer, and the handler already refuses a table-less
            // `columns` registration before it gets here.
            Ok::<bool, DbError>(present.unwrap_or(false))
        };

        let visibility_not_null = column_not_null("visibility").await?;
        let owner_group_not_null = column_not_null("owner_group_id").await?;

        // BOTH flags, in one probe. `relrowsecurity` is what makes policies
        // apply; `relforcerowsecurity` is what stops the table owner being
        // exempt from them. FORCE without ENABLE applies nothing at all, so
        // reading only the second flag would pass a table whose tenancy is
        // decorative.
        let rls: Option<(bool, bool)> = sqlx::query_as(
            "SELECT c.relrowsecurity, c.relforcerowsecurity FROM pg_class c \
               JOIN pg_namespace n ON n.oid = c.relnamespace \
              WHERE n.nspname = $1 AND c.relname = $2",
        )
        .bind(schema)
        .bind(table)
        .fetch_optional(pool)
        .await?;

        // `polcmd` is a "char"; cast to text so sqlx decodes it as a String.
        let policy_cmds: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT p.polcmd::text FROM pg_policy p \
               JOIN pg_class c ON c.oid = p.polrelid \
               JOIN pg_namespace n ON n.oid = c.relnamespace \
              WHERE n.nspname = $1 AND c.relname = $2",
        )
        .bind(schema)
        .bind(table)
        .fetch_all(pool)
        .await?;

        let (rls_enabled, force_rls) = rls.unwrap_or((false, false));
        Ok(TenancyPrecondition {
            visibility_not_null,
            owner_group_not_null,
            policy_cmds,
            rls_enabled,
            force_rls,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::TenancyPrecondition;

    fn precond(cmds: &[&str]) -> TenancyPrecondition {
        TenancyPrecondition {
            visibility_not_null: true,
            owner_group_not_null: true,
            policy_cmds: cmds.iter().map(|c| (*c).to_string()).collect(),
            rls_enabled: true,
            force_rls: true,
        }
    }

    #[test]
    fn all_four_commands_is_complete() {
        assert!(precond(&["r", "a", "w", "d"]).policies_complete());
        assert!(precond(&["r", "a", "w", "d"]).is_satisfied());
    }

    /// A single `FOR ALL` policy has `polcmd = '*'` and covers all four.
    #[test]
    fn star_policy_covers_everything() {
        assert!(precond(&["*"]).policies_complete());
    }

    #[test]
    fn missing_commands_are_named_in_order() {
        assert_eq!(precond(&["r"]).missing_policy_cmds(), vec!["a", "w", "d"]);
        assert_eq!(
            precond(&[]).missing_policy_cmds(),
            vec!["r", "a", "w", "d"],
            "no policies at all is the state of EVERY table at migration head 069"
        );
    }

    #[test]
    fn any_single_shortfall_fails_the_whole_precondition() {
        let mut p = precond(&["*"]);
        assert!(p.is_satisfied());
        p.force_rls = false;
        assert!(!p.is_satisfied(), "FORCE ROW LEVEL SECURITY is required");
        p.force_rls = true;
        p.visibility_not_null = false;
        assert!(!p.is_satisfied(), "visibility NOT NULL is required");
        p.visibility_not_null = true;
        p.owner_group_not_null = false;
        assert!(!p.is_satisfied(), "owner_group_id NOT NULL is required");
    }

    /// The reachable-in-practice trap: `ALTER TABLE … FORCE ROW LEVEL SECURITY`
    /// WITHOUT `ENABLE ROW LEVEL SECURITY`. Postgres accepts both flags
    /// independently, and with `relrowsecurity = false` it applies NO policy at
    /// all — so a precondition that read only `relforcerowsecurity` reported
    /// "satisfied" for a table whose tenancy was entirely inert. Verified
    /// against a live catalog: `CREATE TABLE t(...); ALTER TABLE t FORCE ROW
    /// LEVEL SECURITY; CREATE POLICY p ON t FOR ALL USING (true);` yields
    /// `relrowsecurity = f, relforcerowsecurity = t`.
    #[test]
    fn force_without_enable_is_not_satisfied() {
        let mut p = precond(&["*"]);
        p.rls_enabled = false;
        assert!(
            !p.is_satisfied(),
            "FORCE without ENABLE applies no policy; the columns tier must not \
             accept a table in that state"
        );
    }
}
