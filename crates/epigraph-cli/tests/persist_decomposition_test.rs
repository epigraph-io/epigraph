//! Integration test for `epigraph_cli::decompose::persist_decomposition`
//! (item 46aee550). Uses an INJECTED submit closure that direct-inserts a
//! minimal claim row, so we verify the parent->child decomposes_to wiring +
//! generality property + single-atom skip WITHOUT an LLM or an embedder.
//! Requires the `db` feature: run with `--features db`.
#![cfg(feature = "db")]

use epigraph_cli::decompose::{persist_decomposition, Decomposition};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2,'hex'))")
        .bind(id)
        .bind("bb".repeat(32))
        .execute(pool)
        .await
        .unwrap();
    id
}
async fn insert_min_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    sqlx::query("INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current) VALUES ($1,$2,$3,0.5,$4,true)")
        .bind(id).bind(content).bind(hash).bind(agent).execute(pool).await.unwrap();
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn persists_atoms_and_wires_parent_to_child_edges(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent = insert_min_claim(
        &pool,
        agent,
        "compound: gravity bends light and time dilates near mass",
    )
    .await;

    let decomp = Decomposition {
        atoms: vec![
            "Gravity bends light".to_string(),
            "Time dilates near mass".to_string(),
        ],
        generality: vec![0, 1],
    };
    let pool_c = pool.clone();
    let outcome = persist_decomposition(&pool, parent, &decomp, None, move |atom_text, _gen| {
        let pool_c = pool_c.clone();
        let agent = agent;
        async move { Ok(insert_min_claim(&pool_c, agent, &atom_text).await) }
    })
    .await
    .unwrap();

    assert_eq!(outcome.atom_claim_ids.len(), 2);
    assert_eq!(outcome.edges_created, 2);
    assert_eq!(outcome.skipped_singletons, 0);

    // Direction: parent is SOURCE, atom is TARGET. Assert via SQL on edges.
    // Also assert generality per-target (NOT positionally via `ORDER BY id`,
    // which is gen_random_uuid -> random): atom ids come back in atom order,
    // so zip each with its expected generality and check that specific edge.
    for (atom_id, expected_gen) in outcome.atom_claim_ids.iter().zip([0i64, 1]) {
        let cnt: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND target_id = $2 AND relationship = 'decomposes_to'")
            .bind(parent).bind(atom_id).fetch_one(&pool).await.unwrap();
        assert_eq!(
            cnt, 1,
            "parent must be the SOURCE of decomposes_to and atom the TARGET"
        );
        // No reversed edge.
        let rev: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND target_id = $2 AND relationship = 'decomposes_to'")
            .bind(atom_id).bind(parent).fetch_one(&pool).await.unwrap();
        assert_eq!(
            rev, 0,
            "edge direction must be parent->child, never child->parent"
        );
        // Generality recorded on the edge property — checked per-target so the
        // assertion is independent of edges.id ordering.
        let gen: serde_json::Value = sqlx::query_scalar(
            "SELECT properties->'generality' FROM edges WHERE source_id = $1 AND target_id = $2 AND relationship = 'decomposes_to'")
            .bind(parent).bind(atom_id).fetch_one(&pool).await.unwrap();
        assert_eq!(
            gen,
            serde_json::json!(expected_gen),
            "generality tier must be recorded on the matching edge"
        );
    }
}

/// When the same decomposition is run a second time — as happens when
/// decompose_claims re-processes a claim that was partially decomposed, or
/// when if_not_exists=true causes the API to return the existing atom ID —
/// persist_decomposition must not error and must leave edges intact
/// (create_if_not_exists is idempotent; was_created=false on the second call).
#[sqlx::test(migrations = "../../migrations")]
async fn resubmit_with_existing_atom_id_is_idempotent(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent = insert_min_claim(
        &pool,
        agent,
        "compound: water is H2O and oxygen is diatomic in air",
    )
    .await;
    // Pre-seed both atoms (simulate: a prior run already created them, and the
    // API returns their IDs via if_not_exists=true on the second call).
    let atom_a = insert_min_claim(&pool, agent, "Water is H2O").await;
    let atom_b = insert_min_claim(&pool, agent, "Oxygen is diatomic in air").await;

    let decomp = Decomposition {
        atoms: vec![
            "Water is H2O".to_string(),
            "Oxygen is diatomic in air".to_string(),
        ],
        generality: vec![0, 1],
    };
    let ids = [atom_a, atom_b];
    let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let call_count_c = call_count.clone();
    // submit_via returns pre-existing IDs — mirrors if_not_exists=true returning
    // existing claim IDs from the API rather than creating new ones.
    let outcome = persist_decomposition(&pool, parent, &decomp, None, move |_text, _gen| {
        let idx = call_count_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let id = ids[idx];
        async move { Ok(id) }
    })
    .await
    .unwrap();

    assert_eq!(outcome.atom_claim_ids, vec![atom_a, atom_b]);
    // Edges are NEW because the parent->atom edge didn't exist yet.
    assert_eq!(outcome.edges_created, 2);
    assert_eq!(outcome.skipped_singletons, 0);

    // Run again with the same atoms: edges already exist, was_created=false.
    let call_count2 = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let call_count2_c = call_count2.clone();
    let ids2 = [atom_a, atom_b];
    let outcome2 = persist_decomposition(&pool, parent, &decomp, None, move |_text, _gen| {
        let idx = call_count2_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let id = ids2[idx];
        async move { Ok(id) }
    })
    .await
    .unwrap();

    assert_eq!(outcome2.atom_claim_ids, vec![atom_a, atom_b]);
    // No new edges created — create_if_not_exists found the existing triple.
    assert_eq!(outcome2.edges_created, 0);
    assert_eq!(outcome2.skipped_singletons, 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn single_atom_decomposition_is_skipped(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent = insert_min_claim(&pool, agent, "already atomic single proposition here").await;
    let decomp = Decomposition {
        atoms: vec!["already atomic single proposition here".to_string()],
        generality: vec![0],
    };
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls_c = calls.clone();
    let outcome = persist_decomposition(&pool, parent, &decomp, None, move |_t, _g| {
        calls_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        async move { Ok(Uuid::new_v4()) }
    })
    .await
    .unwrap();
    assert_eq!(outcome.skipped_singletons, 1);
    assert_eq!(outcome.edges_created, 0);
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "single-atom decomposition must not submit or wire anything"
    );
    let cnt: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND relationship='decomposes_to'",
    )
    .bind(parent)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(cnt, 0);
}
