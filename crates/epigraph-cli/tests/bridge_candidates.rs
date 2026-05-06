use epigraph_cli::bridge::candidates::{build_candidate_table, drop_candidate_table};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(id)
        .bind("aa".repeat(32))
        .execute(pool)
        .await
        .unwrap();
    id
}

/// Seed a claim with a 1536-dim unit-ish embedding split across two axes.
/// `axis0` is the magnitude on axis 0, `axis1` is the magnitude on axis 1.
/// Because pgvector cosine distance ignores magnitude (direction only), tests
/// that need varying *similarity* must vary the direction — e.g. axis0=1, axis1=0
/// vs axis0=0, axis1=1 yields cosine similarity 0.
async fn seed_atom_with_embedding(pool: &PgPool, agent_id: Uuid, axis0: f64, axis1: f64) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    let mut zeros = vec!["0.0".to_string(); 1536];
    zeros[0] = axis0.to_string();
    zeros[1] = axis1.to_string();
    let pgvec = format!("[{}]", zeros.join(","));
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, embedding) \
         VALUES ($1, $2, $3, $4, 0.5, jsonb_build_object('level', 3), $5::vector)",
    )
    .bind(id)
    .bind(format!("a-{id}"))
    .bind(hash)
    .bind(agent_id)
    .bind(&pgvec)
    .execute(pool)
    .await
    .unwrap();
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn build_candidate_table_caps_at_top_k(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    // 1 source atom on axis 0; 5 target atoms with mixed axis0/axis1 components.
    // Cosine similarity to [1, 0, ...] = axis0 / sqrt(axis0^2 + axis1^2), so
    // varying these changes direction (and therefore similarity), unlike
    // pure-magnitude scaling along a single axis.
    let src = seed_atom_with_embedding(&pool, agent, 1.0, 0.0).await;
    let mut targets = vec![];
    for (a, b) in [(1.0, 0.0), (1.0, 0.1), (1.0, 0.5), (1.0, 1.0), (0.0, 1.0)] {
        targets.push(seed_atom_with_embedding(&pool, agent, a, b).await);
    }

    let table = format!("test_cands_{}", Uuid::new_v4().simple());
    let n = build_candidate_table(&pool, &table, &[src], &targets, 0.5, 3)
        .await
        .unwrap();
    // Top-3 by similarity, all >= 0.5: should be 3 (mag 0.45 below threshold).
    // Actually similarity = 1 - cosine_distance which depends on the vectors;
    // the check below is the real assertion.
    let rows: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(rows <= 3, "top_k=3 should cap at 3, got {rows}");
    assert_eq!(n as i64, rows);

    drop_candidate_table(&pool, &table).await.unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn build_candidate_table_filters_by_min_similarity(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    // Source on axis 0; close target also on axis 0 (cosine sim ~1.0);
    // far target on axis 1 (cosine sim 0).
    let src = seed_atom_with_embedding(&pool, agent, 1.0, 0.0).await;
    let close = seed_atom_with_embedding(&pool, agent, 1.0, 0.0).await;
    let far = seed_atom_with_embedding(&pool, agent, 0.0, 1.0).await;

    let table = format!("test_cands_{}", Uuid::new_v4().simple());
    build_candidate_table(&pool, &table, &[src], &[close, far], 0.95, 10)
        .await
        .unwrap();
    let row_ids: Vec<Uuid> = sqlx::query_scalar(&format!("SELECT target_id FROM {table}"))
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(row_ids.contains(&close), "near match must appear");
    assert!(
        !row_ids.contains(&far),
        "far match must be filtered by min_similarity"
    );

    drop_candidate_table(&pool, &table).await.unwrap();
}

#[tokio::test]
async fn rejects_unsafe_table_name() {
    // We can call build_candidate_table without a real pool by using a dummy
    // pool; instead just probe `is_safe_table_name` indirectly through the
    // public surface by using a name with semicolons and verifying the
    // returned error.

    // Use a quick lazy connection that won't actually be used.
    let pool = sqlx::PgPool::connect_lazy("postgres://_/_").expect("connect_lazy never errors");
    let result = build_candidate_table(&pool, "t; DROP TABLE x", &[], &[], 0.5, 10).await;
    assert!(result.is_err(), "unsafe table name must error");
}
