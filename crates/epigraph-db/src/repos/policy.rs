//! Repository for policy claims.
//!
//! Network-access policies and their challenges are ordinary claims labelled
//! `policy:*`, with `host` / `port` / `protocol` / `decay_exempt` / `status`
//! carried in `properties` (see `epigraph-api/src/routes/policies.rs`). The
//! reads here are the ones the `/api/v1/policies/*` and
//! `/api/v1/policy-challenges/*` handlers used to run inline on the raw pool
//! with no `Viewer` (`F-inline-claim-content-reads`). Each carries a
//! `/* {VISIBILITY:c} */` marker, so a policy claim private to a group is served
//! only to that group's members.

use crate::errors::DbError;
use tracing::instrument;
use uuid::Uuid;

/// One active network-access policy claim.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct NetworkPolicyRow {
    pub id: Uuid,
    pub truth_value: f64,
    pub properties: serde_json::Value,
}

/// Reads over policy claims. All viewer-filtered.
pub struct PolicyRepository;

impl PolicyRepository {
    /// Active network-access policies (`policy:active` AND `policy:network`)
    /// at or above `min_truth`, strongest first, that the viewer can read.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn list_active_network<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        min_truth: f64,
    ) -> Result<Vec<NetworkPolicyRow>, DbError> {
        let sql = viewer.splice(
            "SELECT c.id, c.truth_value, c.properties \
             FROM claims c \
             WHERE 'policy:active' = ANY(c.labels) \
               AND 'policy:network' = ANY(c.labels) \
               AND c.truth_value >= $1 \
               /* {VISIBILITY:c} */ \
             ORDER BY c.truth_value DESC",
            2,
        );
        let mut q = sqlx::query_as::<_, NetworkPolicyRow>(&sql).bind(min_truth);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// The `properties` of policy challenge `id`, when it exists, is labelled
    /// `policy:challenge`, and the viewer can read it. `None` in all three
    /// other cases, which are deliberately indistinguishable: the route answers
    /// 404 for each, so it is not an existence oracle for private challenges.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_challenge<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        id: Uuid,
    ) -> Result<Option<serde_json::Value>, DbError> {
        let sql = viewer.splice(
            "SELECT c.properties FROM claims c \
             WHERE c.id = $1 AND 'policy:challenge' = ANY(c.labels) \
               /* {VISIBILITY:c} */",
            2,
        );
        let mut q = sqlx::query_scalar::<_, serde_json::Value>(&sql).bind(id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_optional(executor).await?)
    }
}
