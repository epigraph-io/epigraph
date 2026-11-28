//! The claim load behind the `analyze_graph` report (backlog fe1cdcdf).
//!
//! The report runs the Datalog reasoning engine over every claim and prints a
//! claim's cached `truth_value` beside it in its samples and rankings. A
//! compound's cached value is a fold of its own BBAs, not a belief derived
//! from its leaves, so the report must not present it as one: a compound is
//! loaded with no belief (`belief: None`) and printed as such, and the
//! belief-ordered load ranks the non-compounds by `truth_value` and puts the
//! compounds after them. The compound stays in the claim set: the engine reads
//! claims for membership (connected components, unsupported claims), and a
//! compound is a node of the graph's structure like any other.

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_db::repos::claim_role::is_compound_sql;

/// One claim of the report's corpus.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphClaim {
    pub id: Uuid,
    pub content: String,
    /// The cached `truth_value` of a non-compound; `None` for a compound,
    /// whose cache is not a belief to report.
    pub belief: Option<f64>,
}

/// Every claim, non-compounds first by `truth_value` DESC, then compounds,
/// with `id` as the tiebreaker.
///
/// Corpus-wide: run it on the maintenance connection (the caller's
/// `MaintenancePool`), or row security narrows it to the public subgraph.
///
/// # Errors
/// Returns the database error when the query fails.
pub async fn load_claims(pool: &PgPool) -> Result<Vec<GraphClaim>, sqlx::Error> {
    let sql = format!(
        "SELECT g.id, g.content, CASE WHEN g.is_compound THEN NULL ELSE g.truth_value END \
           FROM (SELECT c.id, c.content, c.truth_value, {is_compound} AS is_compound \
                   FROM claims c) g \
          ORDER BY g.is_compound, g.truth_value DESC, g.id",
        is_compound = is_compound_sql("c"),
    );
    let rows: Vec<(Uuid, String, Option<f64>)> = sqlx::query_as(&sql).fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|(id, content, belief)| GraphClaim {
            id,
            content,
            belief,
        })
        .collect())
}

/// How the report prints a claim's belief: two decimals for a non-compound,
/// `cmpd` for a compound.
#[must_use]
pub fn belief_label(belief: Option<f64>) -> String {
    belief.map_or_else(|| "cmpd".to_string(), |b| format!("{b:.2}"))
}

#[cfg(test)]
mod tests {
    use super::belief_label;

    #[test]
    fn a_compound_prints_no_number() {
        assert_eq!(belief_label(Some(0.456)), "0.46");
        assert_eq!(belief_label(None), "cmpd");
    }
}
