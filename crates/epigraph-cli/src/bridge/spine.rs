//! Spine-destination report: for a candidate-pair table, aggregate the
//! target-side claim-theme labels weighted by candidate count, returning
//! the top N umbrellas. Used as a graph-health diagnostic on dry-runs.
//!
//! Schema note: this codebase stores themes as `claim_themes(id, label, ...)`
//! and references them via a single FK column `claims.theme_id`. There is no
//! separate `themes` table and no claim↔theme join table. Targets with
//! `theme_id IS NULL` are dropped from the aggregation (they don't contribute
//! to spine-destination weight).

use serde::Serialize;
use sqlx::PgPool;

use crate::bridge::candidates::is_safe_table_name;

#[derive(Debug, Clone, Serialize)]
pub struct SpineUmbrella {
    /// `claim_themes.label` for the umbrella.
    pub umbrella: String,
    /// Candidate count for this label divided by total candidates whose
    /// target has any theme assignment.
    pub weight: f64,
    /// Raw candidate count for this label.
    pub count: i64,
}

/// Compute spine-destination per spec §3. For each candidate row in
/// `<candidates_table>`, look up the target_id's theme via `claims.theme_id`,
/// aggregate counts by `claim_themes.label`, divide by total to produce
/// weights, return the top `top_n` by weight descending.
///
/// Targets without a theme assignment (`claims.theme_id IS NULL`) are dropped
/// — they don't contribute to spine-destination weight. If no targets have
/// themes, returns an empty Vec.
pub async fn compute_spine_destination(
    pool: &PgPool,
    candidates_table: &str,
    top_n: usize,
) -> Result<Vec<SpineUmbrella>, sqlx::Error> {
    if !is_safe_table_name(candidates_table) {
        return Err(sqlx::Error::Protocol(format!(
            "candidate table name must be [a-zA-Z0-9_]+: {candidates_table}"
        )));
    }

    let total_sql = format!(
        "SELECT COUNT(*) FROM {candidates_table} ct \
         JOIN claims c ON c.id = ct.target_id \
         JOIN claim_themes ct_th ON ct_th.id = c.theme_id"
    );
    let total: i64 = sqlx::query_scalar(&total_sql).fetch_one(pool).await?;
    if total == 0 {
        return Ok(Vec::new());
    }

    let agg_sql = format!(
        r#"
        SELECT ct_th.label AS umbrella, COUNT(*)::bigint AS cnt
        FROM {candidates_table} ct
        JOIN claims c ON c.id = ct.target_id
        JOIN claim_themes ct_th ON ct_th.id = c.theme_id
        GROUP BY ct_th.label
        ORDER BY cnt DESC, ct_th.label ASC
        LIMIT $1
        "#
    );
    let rows: Vec<(String, i64)> = sqlx::query_as(&agg_sql)
        .bind(top_n as i64)
        .fetch_all(pool)
        .await?;

    let total_f = total as f64;
    Ok(rows
        .into_iter()
        .map(|(label, count)| SpineUmbrella {
            umbrella: label,
            weight: count as f64 / total_f,
            count,
        })
        .collect())
}
