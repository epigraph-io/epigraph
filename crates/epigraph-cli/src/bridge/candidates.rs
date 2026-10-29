//! Per-source-atom kNN candidate-pair table builder for bridge sweeps.

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

/// Validate that a string is safe to interpolate into SQL as an identifier.
/// Restricts to `[a-zA-Z0-9_]+` to block injection. The bridge bins generate
/// names from UUIDs so this is the realistic shape.
pub(crate) fn is_safe_table_name(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Column list shared by both [`CandidateTableLifetime`]s.
const CANDIDATE_COLUMNS: &str = "(\
    source_id uuid NOT NULL, \
    target_id uuid NOT NULL, \
    similarity double precision NOT NULL, \
    PRIMARY KEY (source_id, target_id)\
 )";

/// How long a candidate table built by [`build_candidate_table`] lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateTableLifetime {
    /// `CREATE TEMP TABLE … ON COMMIT DROP`: the table exists only inside the
    /// transaction that built it and is removed when that transaction commits
    /// or rolls back, on every exit path. Needs only TEMPORARY on the database,
    /// which the maintenance login has; it holds no CREATE on any schema, by
    /// design. Every read of the table must run on that same transaction.
    Transaction,
    /// A regular table in the first schema of `search_path`, which survives
    /// the transaction and the process (`--keep-tables`, for inspection or a
    /// later `rerank_bridges --candidates-table`). Needs CREATE on that schema,
    /// which neither the application role nor the maintenance login holds;
    /// only a role granted it can use this. Drop it with
    /// [`drop_candidate_table`].
    Persistent,
}

/// Build a candidate-pair table containing per-source-atom top-K matches in
/// the target atom set, filtered by cosine similarity ≥ `min_similarity`.
///
/// The table has columns `(source_id uuid, target_id uuid, similarity float8)`.
/// It is built inside `tx`, and its `lifetime` decides whether it outlives
/// that transaction (see [`CandidateTableLifetime`]). Taking a transaction,
/// not a pool, is what makes the TEMP table usable: it is visible only in the
/// session that created it, so the reads that follow
/// (`bridge::spine::compute_spine_destination`,
/// `rerank::find_candidates_from_table`) must be given `&mut *tx` too.
///
/// Returns the row count.
pub async fn build_candidate_table(
    tx: &mut Transaction<'_, Postgres>,
    table_name: &str,
    lifetime: CandidateTableLifetime,
    source_atom_ids: &[Uuid],
    target_atom_ids: &[Uuid],
    min_similarity: f64,
    top_k: u32,
) -> Result<usize, sqlx::Error> {
    if !is_safe_table_name(table_name) {
        return Err(sqlx::Error::Protocol(format!(
            "candidate table name must be [a-zA-Z0-9_]+: {table_name}"
        )));
    }

    let create_sql = match lifetime {
        // No leading DROP: an unqualified `DROP TABLE IF EXISTS` falls
        // through `search_path` to `public` when no temp table of that name
        // exists. Names are UUID-suffixed, so a clash is an error worth seeing.
        CandidateTableLifetime::Transaction => {
            format!("CREATE TEMP TABLE {table_name} {CANDIDATE_COLUMNS} ON COMMIT DROP")
        }
        CandidateTableLifetime::Persistent => {
            sqlx::query(&format!("DROP TABLE IF EXISTS {table_name}"))
                .execute(&mut **tx)
                .await?;
            format!("CREATE TABLE {table_name} {CANDIDATE_COLUMNS}")
        }
    };
    sqlx::query(&create_sql).execute(&mut **tx).await?;

    // Per-source-atom top-K insert. The lateral join uses HNSW (migration 030)
    // to bound cost. Cosine similarity = 1 - distance.
    let insert_sql = format!(
        r#"
        INSERT INTO {table_name} (source_id, target_id, similarity)
        SELECT s.id, k.target_id, k.similarity
        FROM (SELECT id, embedding FROM claims WHERE id = ANY($1) AND embedding IS NOT NULL) s
        CROSS JOIN LATERAL (
            SELECT t.id AS target_id, 1 - (t.embedding <=> s.embedding) AS similarity
            FROM claims t
            WHERE t.id = ANY($2)
              AND t.embedding IS NOT NULL
              AND (1 - (t.embedding <=> s.embedding)) >= $3
            ORDER BY t.embedding <=> s.embedding
            LIMIT $4
        ) k
        ON CONFLICT (source_id, target_id) DO NOTHING
        "#
    );

    let rows_inserted = sqlx::query(&insert_sql)
        .bind(source_atom_ids)
        .bind(target_atom_ids)
        .bind(min_similarity)
        .bind(top_k as i64)
        .execute(&mut **tx)
        .await?
        .rows_affected();

    Ok(rows_inserted as usize)
}

/// Drop a [`CandidateTableLifetime::Persistent`] candidate table. A
/// [`CandidateTableLifetime::Transaction`] one needs no call: it is gone once
/// its transaction ends.
pub async fn drop_candidate_table(pool: &PgPool, table_name: &str) -> Result<(), sqlx::Error> {
    if !is_safe_table_name(table_name) {
        return Err(sqlx::Error::Protocol(format!(
            "candidate table name must be [a-zA-Z0-9_]+: {table_name}"
        )));
    }
    let drop_sql = format!("DROP TABLE IF EXISTS {table_name}");
    sqlx::query(&drop_sql).execute(pool).await?;
    Ok(())
}
