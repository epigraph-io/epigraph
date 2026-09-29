//! Reads and writes for `epigraph-operator`'s repair subcommands (batch R2):
//! `reown-seed` (backlog 0512ca33) and `strip-label` / `strip-label-reverse`
//! (backlog f6310444).
//!
//! # Who may call these
//!
//! The operator CLI, on a MAINTENANCE connection (`epigraph_cli::operator::connect`
//! refuses any other session), inside the transaction it opened. None of these
//! takes a `Viewer`: they read and write corpus-wide by construction, and the
//! caller is not a request. They are registered in
//! `write_gate_lint.rs::UNGATED_REPO_WRITES` under "maintenance / corpus-wide,
//! unreachable from a request" so that a request-reachable caller is a visible
//! diff there.
//!
//! # Why the label writes are exact, not `update_labels_conn`
//!
//! `ClaimRepository::update_labels_conn` rewrites the array as
//! `array_agg(DISTINCT … ORDER BY …)`: it de-duplicates and SORTS every label,
//! not only the one removed. A repair must change exactly one element and a
//! reversal must restore the array byte for byte, so [`Self::strip_label_conn`]
//! uses `array_remove` (every other element keeps its position) and
//! [`Self::restore_labels_conn`] is a compare-and-swap on the whole array.

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

/// One claim carrying a label, as the label repair reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabelledClaim {
    pub id: Uuid,
    pub labels: Vec<String>,
    pub is_current: bool,
}

/// Operator repair reads and writes. See the module doc.
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

    /// Every claim whose labels contain `label` exactly, oldest first. With
    /// `for_update`, the rows are locked `FOR UPDATE`.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails (including a lock timeout).
    pub async fn claims_with_label_conn(
        conn: &mut PgConnection,
        label: &str,
        for_update: bool,
    ) -> Result<Vec<LabelledClaim>, DbError> {
        let sql = if for_update {
            "SELECT id, labels, is_current FROM claims WHERE $1 = ANY(labels) \
              ORDER BY created_at, id FOR UPDATE"
        } else {
            "SELECT id, labels, is_current FROM claims WHERE $1 = ANY(labels) \
              ORDER BY created_at, id"
        };
        let rows: Vec<(Uuid, Vec<String>, bool)> = sqlx::query_as(sql)
            .bind(label)
            .fetch_all(&mut *conn)
            .await?;
        Ok(rows
            .into_iter()
            .map(|(id, labels, is_current)| LabelledClaim {
                id,
                labels,
                is_current,
            })
            .collect())
    }

    /// The labels of the listed claims, locked `FOR UPDATE`. A claim that no
    /// longer exists is absent from the result.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails (including a lock timeout).
    pub async fn labels_for_update_conn(
        conn: &mut PgConnection,
        ids: &[Uuid],
    ) -> Result<Vec<LabelledClaim>, DbError> {
        let rows: Vec<(Uuid, Vec<String>, bool)> = sqlx::query_as(
            "SELECT id, labels, is_current FROM claims WHERE id = ANY($1) ORDER BY id FOR UPDATE",
        )
        .bind(ids)
        .fetch_all(&mut *conn)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, labels, is_current)| LabelledClaim {
                id,
                labels,
                is_current,
            })
            .collect())
    }

    /// Remove every occurrence of `label` from each listed claim's labels,
    /// leaving every other element where it was (`array_remove`). A claim not
    /// carrying the label is not written. Returns `(id, labels after)` for
    /// every row written.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the write fails.
    pub async fn strip_label_conn(
        conn: &mut PgConnection,
        ids: &[Uuid],
        label: &str,
    ) -> Result<Vec<(Uuid, Vec<String>)>, DbError> {
        Ok(sqlx::query_as(
            "UPDATE claims SET labels = array_remove(labels, $2) \
              WHERE id = ANY($1) AND $2 = ANY(labels) \
              RETURNING id, labels",
        )
        .bind(ids)
        .bind(label)
        .fetch_all(&mut *conn)
        .await?)
    }

    /// Set one claim's labels to `before` IF they are exactly `after` now (a
    /// compare-and-swap over the whole array, order included). Returns whether
    /// the row was written.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the write fails.
    pub async fn restore_labels_conn(
        conn: &mut PgConnection,
        id: Uuid,
        after: &[String],
        before: &[String],
    ) -> Result<bool, DbError> {
        let n = sqlx::query("UPDATE claims SET labels = $3 WHERE id = $1 AND labels = $2::text[]")
            .bind(id)
            .bind(after)
            .bind(before)
            .execute(&mut *conn)
            .await?
            .rows_affected();
        Ok(n == 1)
    }
}
