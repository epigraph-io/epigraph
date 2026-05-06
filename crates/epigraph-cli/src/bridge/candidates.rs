//! Per-source-atom kNN candidate-pair table builder for bridge sweeps.

use sqlx::PgPool;
use uuid::Uuid;

/// Validate that a string is safe to interpolate into SQL as an identifier.
/// Restricts to `[a-zA-Z0-9_]+` to block injection. The bridge bins generate
/// names from UUIDs so this is the realistic shape.
pub(crate) fn is_safe_table_name(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Build a temporary candidate-pair table containing per-source-atom top-K
/// matches in the target atom set, filtered by cosine similarity ≥ min_similarity.
///
/// The table has columns `(source_id uuid, target_id uuid, similarity float8)`
/// and is created with `CREATE TABLE` (NOT temp — `rerank_candidates_table`
/// reads it from a separate connection in the pool, and TEMP tables are
/// session-local).
///
/// Returns the row count.
///
/// Caller is responsible for dropping the table when done (or pass --keep-tables).
pub async fn build_candidate_table(
    pool: &PgPool,
    table_name: &str,
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

    // Build the table.
    let drop_sql = format!("DROP TABLE IF EXISTS {table_name}");
    sqlx::query(&drop_sql).execute(pool).await?;

    let create_sql = format!(
        "CREATE TABLE {table_name} (\
            source_id uuid NOT NULL, \
            target_id uuid NOT NULL, \
            similarity double precision NOT NULL, \
            PRIMARY KEY (source_id, target_id)\
         )"
    );
    sqlx::query(&create_sql).execute(pool).await?;

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
        .execute(pool)
        .await?
        .rows_affected();

    Ok(rows_inserted as usize)
}

/// Drop the candidate table.
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
