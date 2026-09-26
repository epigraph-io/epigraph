//! Reads for `epigraph-operator`'s repair subcommands (batch R2):
//! `reown-seed` (backlog 0512ca33).
//!
//! # Who may call these
//!
//! The operator CLI, on a MAINTENANCE connection (`epigraph_cli::operator::connect`
//! refuses any other session). None of these takes a `Viewer`: they read
//! corpus-wide by construction, and the caller is not a request. They are
//! registered in `visibility_lint.rs::CONN_WITHOUT_VIEWER` with that reason.

use crate::errors::DbError;
use sqlx::PgConnection;
use uuid::Uuid;

/// The tier-A tables that carry `owner_group_id`: migration 062's `tier_a`
/// array, verbatim, which is also migration 074's section-5 array.
pub const TIER_A_TABLES: &[&str] = &[
    "claims",
    "evidence",
    "edges",
    "triples",
    "entity_mentions",
    "claim_versions",
    "mass_functions",
    "ds_combined_beliefs",
    "ds_bayesian_divergence",
    "claim_frames",
    "harvester_claim_provenance",
    "challenges",
    "reasoning_traces",
    "experiment_triples",
    "experiment_entity_mentions",
    "claim_clusters",
    "claim_cluster_membership",
    "claim_neighborhood_membership",
    "claim_signature_revocations",
    "harvester_fragments",
    "frames",
    "contexts",
    "perspectives",
    "communities",
    "recall_events",
];

/// Operator repair reads. See the module doc.
pub struct OperatorRepairRepository;

impl OperatorRepairRepository {
    /// Every claim owned by `group`, oldest first.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails.
    pub async fn claim_ids_owned_by_conn(
        conn: &mut PgConnection,
        group: Uuid,
    ) -> Result<Vec<Uuid>, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT id FROM claims WHERE owner_group_id = $1 ORDER BY created_at, id",
        )
        .bind(group)
        .fetch_all(&mut *conn)
        .await?)
    }

    /// Rows owned by `group`, per tier-A table that exists on this database
    /// ([`TIER_A_TABLES`]; a table this schema lacks is skipped). Tables with
    /// no such row are omitted.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if a read fails.
    pub async fn count_owned_by_per_table_conn(
        conn: &mut PgConnection,
        group: Uuid,
    ) -> Result<Vec<(String, i64)>, DbError> {
        let present: Vec<String> = sqlx::query_scalar(
            "SELECT c.relname::text FROM pg_class c \
               JOIN pg_namespace n ON n.oid = c.relnamespace \
              WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname = ANY($1) \
              ORDER BY 1",
        )
        .bind(TIER_A_TABLES)
        .fetch_all(&mut *conn)
        .await?;
        let mut out = Vec::new();
        for t in present {
            // `t` came from pg_class AND is a member of the literal list
            // above, so it is an identifier this function spelled, not caller
            // data; quote_ident-equivalent quoting is still applied.
            let sql = format!(
                "SELECT count(*)::bigint FROM public.\"{}\" WHERE owner_group_id = $1",
                t.replace('"', "\"\"")
            );
            let n: i64 = sqlx::query_scalar(&sql)
                .bind(group)
                .fetch_one(&mut *conn)
                .await?;
            if n > 0 {
                out.push((t, n));
            }
        }
        Ok(out)
    }
}
