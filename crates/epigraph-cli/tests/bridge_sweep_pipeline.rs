//! End-to-end test of the bridge_sweep pipeline through library code.
//! Two small components + a giant; assert each small produces a candidate
//! and the spine populates only when themes exist.

#![cfg(feature = "genai")]

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_cli::bridge::candidates::{build_candidate_table, drop_candidate_table};
use epigraph_cli::bridge::components::{compute_components, ComponentSummary};
use epigraph_cli::bridge::spine::compute_spine_destination;
use epigraph_cli::rerank::{rerank_candidates_table, RerankConfig};

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

async fn seed_atom(pool: &PgPool, agent: Uuid, mag: f64) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    let mut zeros = vec!["0.0".to_string(); 1536];
    zeros[0] = mag.to_string();
    let pgvec = format!("[{}]", zeros.join(","));
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, embedding) \
         VALUES ($1, $2, $3, $4, 0.5, jsonb_build_object('level', 3), $5::vector)",
    )
    .bind(id)
    .bind(format!("a-{id}"))
    .bind(hash)
    .bind(agent)
    .bind(&pgvec)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn seed_corroborates(pool: &PgPool, source: Uuid, target: Uuid) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'CORROBORATES')",
    )
    .bind(source)
    .bind(target)
    .execute(pool)
    .await
    .unwrap();
}

async fn seed_theme(pool: &PgPool, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO claim_themes (id, label) VALUES ($1, $2)")
        .bind(id)
        .bind(label)
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn assign_theme(pool: &PgPool, claim_id: Uuid, theme_id: Uuid) {
    sqlx::query("UPDATE claims SET theme_id = $1 WHERE id = $2")
        .bind(theme_id)
        .bind(claim_id)
        .execute(pool)
        .await
        .unwrap();
}

/// Locate the component containing `claim`.
fn find_component_by_member<'a>(
    components: &'a [ComponentSummary],
    claim: &Uuid,
) -> &'a ComponentSummary {
    components
        .iter()
        .find(|c| c.claim_ids.contains(claim))
        .expect("component for claim")
}

#[sqlx::test(migrations = "../../migrations")]
async fn sweep_dry_run_with_two_small_components(pool: PgPool) {
    let agent = seed_agent(&pool).await;

    // Giant: 5 atoms unified by CORROBORATES (chain).
    let g0 = seed_atom(&pool, agent, 0.99).await;
    let g1 = seed_atom(&pool, agent, 0.98).await;
    let g2 = seed_atom(&pool, agent, 0.97).await;
    let g3 = seed_atom(&pool, agent, 0.96).await;
    let g4 = seed_atom(&pool, agent, 0.95).await;
    seed_corroborates(&pool, g0, g1).await;
    seed_corroborates(&pool, g1, g2).await;
    seed_corroborates(&pool, g2, g3).await;
    seed_corroborates(&pool, g3, g4).await;

    // Small A: 2 atoms unified by CORROBORATES.
    let a0 = seed_atom(&pool, agent, 0.94).await;
    let a1 = seed_atom(&pool, agent, 0.93).await;
    seed_corroborates(&pool, a0, a1).await;

    // Small B: 2 atoms unified by CORROBORATES.
    let b0 = seed_atom(&pool, agent, 0.92).await;
    let b1 = seed_atom(&pool, agent, 0.91).await;
    seed_corroborates(&pool, b0, b1).await;

    // Theme assignment so spine has something to aggregate (only on the
    // giant — small_b will have an unthemed-target spine result, which is
    // fine for the spine assertion).
    let theme_x = seed_theme(&pool, "X").await;
    for tgt in [g0, g1, g2, g3, g4] {
        assign_theme(&pool, tgt, theme_x).await;
    }

    // Compute components — expect 3.
    let components = compute_components(&pool).await.unwrap();
    assert_eq!(components.len(), 3, "expected 3 components total");

    // Largest is the giant.
    let target = &components[0];
    assert_eq!(target.size, 5, "giant should have 5 claims");

    let small_a = find_component_by_member(&components, &a0);
    let small_b = find_component_by_member(&components, &b0);
    assert_eq!(small_a.size, 2);
    assert_eq!(small_b.size, 2);
    assert_ne!(small_a.component_id, target.component_id);
    assert_ne!(small_b.component_id, target.component_id);

    // Drive the sweep manually for both small components.
    // (Mirrors what bridge_sweep::run_sweep does when --components is given.)
    let target_atoms = vec![g0, g1, g2, g3, g4];

    let mut total_processed = 0;
    let mut total_edges_created = 0;
    let mut spine_seen = false;

    for (small, source_atoms) in [(small_a, vec![a0, a1]), (small_b, vec![b0, b1])] {
        assert_ne!(small.component_id, target.component_id, "must skip target");

        let table = format!("test_sweep_{}", Uuid::new_v4().simple());
        let count = build_candidate_table(&pool, &table, &source_atoms, &target_atoms, 0.5, 10)
            .await
            .unwrap();
        assert!(count > 0, "expected at least one candidate pair");

        let spine = compute_spine_destination(&pool, &table, 5).await.unwrap();
        if !spine.is_empty() {
            spine_seen = true;
            // Targets are all under theme "X".
            assert_eq!(spine[0].umbrella, "X");
        }

        let config = RerankConfig {
            min_similarity: 0.5,
            batch_size: 10,
            provider: "mock".to_string(),
            model: None,
            dry_run: true, // dry-run
            limit: None,
            verbose: false,
        };
        let summary = rerank_candidates_table(&pool, &table, &config)
            .await
            .unwrap();
        assert_eq!(summary.edges_created, 0, "dry-run must not create edges");
        total_edges_created += summary.edges_created;
        total_processed += 1;

        drop_candidate_table(&pool, &table).await.unwrap();
    }

    assert_eq!(total_processed, 2, "expected 2 small components processed");
    assert_eq!(total_edges_created, 0, "dry-run must create no edges");
    assert!(spine_seen, "spine should populate when target themes exist");
}
