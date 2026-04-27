//! Orchestrates a single clustering run: load edges + claims, run Louvain,
//! compute supernode metadata, persist results, GC old runs.

use std::collections::HashMap;
use sqlx::PgPool;
use uuid::Uuid;

use super::louvain::{louvain, LouvainInput};

/// Edge relationship strings considered "epistemic" for clustering. Governance
/// edges (OCCUPIES, GOVERNED_BY, HAS_ROLE) are excluded by NOT being listed.
pub const EPISTEMIC_RELATIONSHIPS: &[&str] = &["SUPPORTS", "CONTRADICTS"];

#[derive(Debug)]
pub struct RunConfig {
    pub resolution: f64,
    pub retain_runs: u32,
}

#[derive(Debug)]
pub struct RunSummary {
    pub run_id: Uuid,
    pub cluster_count: usize,
    pub degraded: bool,
}

#[derive(Debug, sqlx::FromRow)]
struct ClaimRow {
    id: Uuid,
    pignistic_prob: Option<f64>,
    frame_id: Option<Uuid>,
}

#[derive(Debug, sqlx::FromRow)]
struct EdgeRow {
    source: Uuid,   // aliased from edges.source_id in SELECT
    target: Uuid,   // aliased from edges.target_id in SELECT
}

pub async fn run_clustering(pool: &PgPool, cfg: &RunConfig) -> Result<RunSummary, sqlx::Error> {
    // Schema reality (verified against migrations/001_initial_schema.sql, 2026-04-27):
    //   - `claims` has NO `frame_id` column; frame association is via the `claim_frames`
    //     join table (PK: claim_id, frame_id). A claim can belong to multiple frames; for
    //     clustering "dominant frame" we pick any one — use a LATERAL pick or LEFT JOIN with
    //     DISTINCT ON. v1 uses LEFT JOIN + DISTINCT ON for determinism.
    //   - `edges` columns are `source_id` and `target_id` (not `source` / `target`). The
    //     EdgeRow struct keeps the shorter field names by aliasing in the SELECT.
    let claims: Vec<ClaimRow> = sqlx::query_as::<_, ClaimRow>(
        "SELECT DISTINCT ON (c.id)
                c.id, c.pignistic_prob, cf.frame_id
         FROM claims c
         LEFT JOIN claim_frames cf ON cf.claim_id = c.id
         ORDER BY c.id, cf.frame_id",
    )
    .fetch_all(pool)
    .await?;

    let allow_array: Vec<&str> = EPISTEMIC_RELATIONSHIPS.to_vec();
    let edges: Vec<EdgeRow> = sqlx::query_as::<_, EdgeRow>(
        "SELECT source_id AS source, target_id AS target
         FROM edges
         WHERE relationship = ANY($1)",
    )
    .bind(&allow_array)
    .fetch_all(pool)
    .await?;

    // Map claim UUIDs to dense u32 ids.
    let mut id_to_idx: HashMap<Uuid, u32> = HashMap::with_capacity(claims.len());
    for (i, c) in claims.iter().enumerate() {
        id_to_idx.insert(c.id, i as u32);
    }
    let mut edge_pairs: Vec<(u32, u32, f64)> = Vec::with_capacity(edges.len());
    for e in &edges {
        let (Some(&a), Some(&b)) = (id_to_idx.get(&e.source), id_to_idx.get(&e.target)) else {
            continue;
        };
        if a == b { continue; }
        edge_pairs.push((a, b, 1.0));
    }

    let input = LouvainInput {
        node_count: claims.len(),
        edges: edge_pairs,
        resolution: cfg.resolution,
    };
    let result = louvain(&input).map_err(|e| sqlx::Error::Protocol(format!("louvain: {e}")))?;

    let run_id = Uuid::new_v4();
    let degraded = unique_count(&result.assignments) < 2;

    if degraded {
        write_degraded_by_frame(pool, &claims, run_id).await?;
    } else {
        write_clusters(pool, &claims, &result.assignments, run_id).await?;
    }

    let cluster_count = unique_count_after_write(pool, run_id).await?;
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded)
         VALUES ($1, $2, $3)",
    )
    .bind(run_id)
    .bind(cluster_count as i32)
    .bind(degraded)
    .execute(pool)
    .await?;

    gc_old_runs(pool, cfg.retain_runs).await?;

    Ok(RunSummary { run_id, cluster_count, degraded })
}

fn unique_count(assignments: &[u32]) -> usize {
    let mut seen: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    for a in assignments { seen.insert(*a); }
    seen.len()
}

async fn unique_count_after_write(pool: &PgPool, run_id: Uuid) -> Result<usize, sqlx::Error> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM graph_clusters WHERE run_id = $1",
    )
    .bind(run_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0 as usize)
}

async fn write_clusters(
    pool: &PgPool,
    claims: &[ClaimRow],
    assignments: &[u32],
    run_id: Uuid,
) -> Result<(), sqlx::Error> {
    // Build per-community aggregates: members, mean_betp, dominant_frame_id.
    use std::collections::HashMap;
    let mut groups: HashMap<u32, Vec<usize>> = HashMap::new();
    for (idx, comm) in assignments.iter().enumerate() {
        groups.entry(*comm).or_default().push(idx);
    }

    let mut tx = pool.begin().await?;
    let mut cluster_ids: HashMap<u32, Uuid> = HashMap::new();
    for (comm, members) in &groups {
        let cluster_id = Uuid::new_v4();
        cluster_ids.insert(*comm, cluster_id);

        let size = members.len() as i32;
        let mut sum_betp = 0.0_f64;
        let mut count_betp = 0i32;
        let mut frame_counts: HashMap<Uuid, i32> = HashMap::new();
        for &m in members {
            if let Some(b) = claims[m].pignistic_prob {
                sum_betp += b;
                count_betp += 1;
            }
            if let Some(f) = claims[m].frame_id {
                *frame_counts.entry(f).or_insert(0) += 1;
            }
        }
        let mean_betp = if count_betp > 0 { Some(sum_betp / count_betp as f64) } else { None };
        let dominant_frame_id = frame_counts.iter().max_by_key(|(_, c)| **c).map(|(k, _)| *k);
        let label = dominant_frame_id
            .map(|f| f.to_string())
            .unwrap_or_else(|| format!("cluster-{comm}"));

        sqlx::query(
            "INSERT INTO graph_clusters
             (id, run_id, label, size, mean_betp, dominant_type, dominant_frame_id, degraded)
             VALUES ($1, $2, $3, $4, $5, 'claim', $6, FALSE)",
        )
        .bind(cluster_id)
        .bind(run_id)
        .bind(label)
        .bind(size)
        .bind(mean_betp)
        .bind(dominant_frame_id)
        .execute(&mut *tx)
        .await?;
    }

    // Write membership rows in batches of 1000.
    let chunk = 1000;
    let mut batch: Vec<(Uuid, Uuid)> = Vec::with_capacity(chunk);
    for (idx, comm) in assignments.iter().enumerate() {
        let cluster_id = cluster_ids[comm];
        batch.push((claims[idx].id, cluster_id));
        if batch.len() == chunk {
            flush_membership(&mut tx, &batch, run_id).await?;
            batch.clear();
        }
    }
    if !batch.is_empty() {
        flush_membership(&mut tx, &batch, run_id).await?;
    }

    // Inter-cluster edge counts: re-scan edges within transaction.
    sqlx::query(
        r#"
        INSERT INTO cluster_edges (run_id, cluster_a, cluster_b, weight)
        SELECT $1::uuid AS run_id,
               LEAST(ma.cluster_id, mb.cluster_id) AS cluster_a,
               GREATEST(ma.cluster_id, mb.cluster_id) AS cluster_b,
               COUNT(*)::int AS weight
        FROM edges e
        JOIN claim_cluster_membership ma ON ma.claim_id = e.source_id AND ma.run_id = $1
        JOIN claim_cluster_membership mb ON mb.claim_id = e.target_id AND mb.run_id = $1
        WHERE e.relationship = ANY($2)
          AND ma.cluster_id <> mb.cluster_id
        GROUP BY 1, 2, 3
        "#,
    )
    .bind(run_id)
    .bind(EPISTEMIC_RELATIONSHIPS)
    .execute(&mut *tx)
    .await?;

    tx.commit().await
}

async fn flush_membership(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    batch: &[(Uuid, Uuid)],
    run_id: Uuid,
) -> Result<(), sqlx::Error> {
    let mut q = String::from(
        "INSERT INTO claim_cluster_membership (claim_id, cluster_id, run_id) VALUES ",
    );
    let mut params: Vec<String> = Vec::with_capacity(batch.len());
    for i in 0..batch.len() {
        let base = i * 3;
        params.push(format!("(${}, ${}, ${})", base + 1, base + 2, base + 3));
    }
    q.push_str(&params.join(", "));
    let mut query = sqlx::query(&q);
    for (claim_id, cluster_id) in batch {
        query = query.bind(claim_id).bind(cluster_id).bind(run_id);
    }
    query.execute(&mut **tx).await?;
    Ok(())
}

async fn write_degraded_by_frame(
    pool: &PgPool,
    claims: &[ClaimRow],
    run_id: Uuid,
) -> Result<(), sqlx::Error> {
    use std::collections::HashMap;
    let mut by_frame: HashMap<Uuid, Vec<usize>> = HashMap::new();
    let mut orphans: Vec<usize> = Vec::new();
    for (i, c) in claims.iter().enumerate() {
        match c.frame_id {
            Some(f) => by_frame.entry(f).or_default().push(i),
            None => orphans.push(i),
        }
    }
    let mut tx = pool.begin().await?;
    for (frame, members) in &by_frame {
        let cluster_id = Uuid::new_v4();
        let mean_betp = mean_betp_of(claims, members);
        sqlx::query(
            "INSERT INTO graph_clusters
             (id, run_id, label, size, mean_betp, dominant_type, dominant_frame_id, degraded)
             VALUES ($1, $2, $3, $4, $5, 'claim', $6, TRUE)",
        )
        .bind(cluster_id)
        .bind(run_id)
        .bind(frame.to_string())
        .bind(members.len() as i32)
        .bind(mean_betp)
        .bind(*frame)
        .execute(&mut *tx)
        .await?;
        for &m in members {
            sqlx::query(
                "INSERT INTO claim_cluster_membership (claim_id, cluster_id, run_id) VALUES ($1, $2, $3)",
            )
            .bind(claims[m].id)
            .bind(cluster_id)
            .bind(run_id)
            .execute(&mut *tx)
            .await?;
        }
    }
    if !orphans.is_empty() {
        let cluster_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO graph_clusters
             (id, run_id, label, size, mean_betp, dominant_type, dominant_frame_id, degraded)
             VALUES ($1, $2, 'unframed', $3, $4, 'claim', NULL, TRUE)",
        )
        .bind(cluster_id)
        .bind(run_id)
        .bind(orphans.len() as i32)
        .bind(mean_betp_of(claims, &orphans))
        .execute(&mut *tx)
        .await?;
        for &m in &orphans {
            sqlx::query(
                "INSERT INTO claim_cluster_membership (claim_id, cluster_id, run_id) VALUES ($1, $2, $3)",
            )
            .bind(claims[m].id)
            .bind(cluster_id)
            .bind(run_id)
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await
}

fn mean_betp_of(claims: &[ClaimRow], idxs: &[usize]) -> Option<f64> {
    let mut sum = 0.0_f64;
    let mut n = 0i32;
    for &i in idxs {
        if let Some(b) = claims[i].pignistic_prob { sum += b; n += 1; }
    }
    if n == 0 { None } else { Some(sum / n as f64) }
}

async fn gc_old_runs(pool: &PgPool, retain: u32) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        WITH old AS (
            SELECT run_id FROM graph_cluster_runs
            ORDER BY completed_at DESC
            OFFSET $1
        )
        DELETE FROM graph_cluster_runs WHERE run_id IN (SELECT run_id FROM old);
        "#,
    )
    .bind(retain as i64)
    .execute(pool)
    .await?;
    sqlx::query(
        "DELETE FROM cluster_edges WHERE run_id NOT IN (SELECT run_id FROM graph_cluster_runs)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "DELETE FROM claim_cluster_membership WHERE run_id NOT IN (SELECT run_id FROM graph_cluster_runs)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "DELETE FROM graph_clusters WHERE run_id NOT IN (SELECT run_id FROM graph_cluster_runs)",
    )
    .execute(pool)
    .await?;
    Ok(())
}
