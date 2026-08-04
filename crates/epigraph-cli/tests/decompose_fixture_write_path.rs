//! End-to-end cover for the `decompose_claims` atom/edge WRITE path, driven by
//! the deterministic `fixture` provider instead of a live LLM.
//!
//! These tests call `run_decomposition_batches` — the batch loop
//! `decompose_claims`'s `main` runs — so they cover the whole chain
//! (build_batch_prompt -> LlmProvider::complete_json -> parse_batch_response ->
//! chunk.get(local_idx) parent lookup -> persist_decomposition), not a
//! re-implementation of it. Only the submit closure is a stand-in: it
//! direct-inserts a minimal claim row where the binary POSTs to
//! `/api/v1/claims`.
//!
//! Before this change there was no way to reach `persist_decomposition` from a
//! test at all: `mock` returns an empty batch and `epigraph` needs a live
//! CLAUDE_CODE_OAUTH_TOKEN. `mock_provider_writes_nothing` pins that `mock`'s
//! inert behavior is unchanged.
//!
//! Requires the `db` feature: run with `--features db` (in `default`).
#![cfg(feature = "db")]

use epigraph_cli::decompose::{run_decomposition_batches, BatchClaim};
use epigraph_cli::enrichment::llm_client::{FixtureLlmClient, MockLlmClient};
use sqlx::PgPool;
use uuid::Uuid;

const COMPOUND_A: &str = "gravity bends light and time dilates near mass";
const COMPOUND_B: &str = "water is H2O and oxygen is diatomic in air";

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2,'hex'))")
        .bind(id)
        .bind("cc".repeat(32))
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

/// The fixture both provider tests load — two compound claims, each with two
/// atoms, keyed by claim text exactly as the provider expects.
fn fixture_json() -> serde_json::Value {
    serde_json::json!({
        COMPOUND_A: {
            "atoms": ["Gravity bends light", "Time dilates near mass"],
            "generality": [0, 1],
        },
        COMPOUND_B: {
            "atoms": ["Water is H2O", "Oxygen is diatomic in air"],
            "generality": [2, 1],
        },
    })
}

/// Atom texts wired to `parent`, read back from the graph via the
/// `decomposes_to` edges. Sorted so assertions are order-independent.
async fn atoms_of(pool: &PgPool, parent: Uuid) -> Vec<String> {
    let mut rows: Vec<String> = sqlx::query_scalar(
        "SELECT c.content FROM edges e JOIN claims c ON c.id = e.target_id \
         WHERE e.source_id = $1 AND e.relationship = 'decomposes_to'",
    )
    .bind(parent)
    .fetch_all(pool)
    .await
    .unwrap();
    rows.sort();
    rows
}

/// The core claim of this change: with `--provider fixture` the write path
/// actually runs — atoms are created and `decomposes_to` edges are wired —
/// with no LLM call and no OAuth token.
#[sqlx::test(migrations = "../../migrations")]
async fn fixture_provider_writes_atoms_and_decomposes_to_edges(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent_a = insert_min_claim(&pool, agent, COMPOUND_A).await;
    let parent_b = insert_min_claim(&pool, agent, COMPOUND_B).await;

    let llm = FixtureLlmClient::from_json(&fixture_json()).unwrap();
    let claims = vec![
        BatchClaim {
            claim_id: parent_a,
            agent_id: agent,
            content: COMPOUND_A.to_string(),
        },
        BatchClaim {
            claim_id: parent_b,
            agent_id: agent,
            content: COMPOUND_B.to_string(),
        },
    ];

    let pool_c = pool.clone();
    let totals = run_decomposition_batches(
        &pool,
        &claims,
        &llm,
        10,
        None,
        move |atom_text, _generality, parent_agent_id| {
            let pool_c = pool_c.clone();
            async move { Ok(insert_min_claim(&pool_c, parent_agent_id, &atom_text).await) }
        },
    )
    .await
    .unwrap();

    assert_eq!(totals.atoms, 4, "two compounds x two atoms each");
    assert_eq!(totals.edges, 4, "one decomposes_to edge per atom");

    // Atoms must land under the RIGHT parent — the failure mode a
    // position-keyed fixture would hide.
    assert_eq!(
        atoms_of(&pool, parent_a).await,
        vec!["Gravity bends light", "Time dilates near mass"]
    );
    assert_eq!(
        atoms_of(&pool, parent_b).await,
        vec!["Oxygen is diatomic in air", "Water is H2O"]
    );

    // Generality rides on the edge, per atom, as the binary records it.
    let gen: serde_json::Value = sqlx::query_scalar(
        "SELECT e.properties->'generality' FROM edges e JOIN claims c ON c.id = e.target_id \
         WHERE e.source_id = $1 AND c.content = 'Time dilates near mass'",
    )
    .bind(parent_a)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(gen, serde_json::json!(1));
}

/// The fixture is keyed by claim text and positions are resolved from the
/// prompt actually built, so the parent->atom mapping is independent of the
/// order `list_undecomposed` happens to return. Same fixture, reversed input:
/// identical graph. A position-keyed `{"0": …}` fixture would swap the atoms
/// between parents here while still reporting "4 atoms, 4 edges".
#[sqlx::test(migrations = "../../migrations")]
async fn atoms_follow_claim_text_not_batch_position(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent_a = insert_min_claim(&pool, agent, COMPOUND_A).await;
    let parent_b = insert_min_claim(&pool, agent, COMPOUND_B).await;

    let llm = FixtureLlmClient::from_json(&fixture_json()).unwrap();
    // B first, A second — the reverse of the other test.
    let claims = vec![
        BatchClaim {
            claim_id: parent_b,
            agent_id: agent,
            content: COMPOUND_B.to_string(),
        },
        BatchClaim {
            claim_id: parent_a,
            agent_id: agent,
            content: COMPOUND_A.to_string(),
        },
    ];

    let pool_c = pool.clone();
    let totals = run_decomposition_batches(
        &pool,
        &claims,
        &llm,
        10,
        None,
        move |atom_text, _generality, parent_agent_id| {
            let pool_c = pool_c.clone();
            async move { Ok(insert_min_claim(&pool_c, parent_agent_id, &atom_text).await) }
        },
    )
    .await
    .unwrap();

    assert_eq!(totals.atoms, 4);
    assert_eq!(totals.edges, 4);
    assert_eq!(
        atoms_of(&pool, parent_a).await,
        vec!["Gravity bends light", "Time dilates near mass"],
        "atoms must follow claim TEXT, not the claim's position in the batch"
    );
    assert_eq!(
        atoms_of(&pool, parent_b).await,
        vec!["Oxygen is diatomic in air", "Water is H2O"]
    );
}

/// A claim absent from the fixture yields no decomposition and no writes —
/// the fixture never fabricates atoms for claims it was not given.
#[sqlx::test(migrations = "../../migrations")]
async fn claims_missing_from_the_fixture_are_left_untouched(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent_a = insert_min_claim(&pool, agent, COMPOUND_A).await;
    let unknown =
        insert_min_claim(&pool, agent, "a compound claim the fixture never mentions").await;

    let llm = FixtureLlmClient::from_json(&fixture_json()).unwrap();
    let claims = vec![
        BatchClaim {
            claim_id: parent_a,
            agent_id: agent,
            content: COMPOUND_A.to_string(),
        },
        BatchClaim {
            claim_id: unknown,
            agent_id: agent,
            content: "a compound claim the fixture never mentions".to_string(),
        },
    ];

    let pool_c = pool.clone();
    let totals = run_decomposition_batches(
        &pool,
        &claims,
        &llm,
        10,
        None,
        move |atom_text, _generality, parent_agent_id| {
            let pool_c = pool_c.clone();
            async move { Ok(insert_min_claim(&pool_c, parent_agent_id, &atom_text).await) }
        },
    )
    .await
    .unwrap();

    assert_eq!(totals.atoms, 2, "only the fixture-covered claim decomposes");
    assert_eq!(totals.edges, 2);
    assert!(
        atoms_of(&pool, unknown).await.is_empty(),
        "a claim absent from the fixture must get no atoms and no edges"
    );
}

/// Regression guard on the constraint that adding `fixture` must not change
/// `mock`: `mock` still returns an empty batch, so the same runner writes
/// nothing at all. This is the state that made the write path untestable, and
/// it must stay exactly as it was.
#[sqlx::test(migrations = "../../migrations")]
async fn mock_provider_writes_nothing(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent = insert_min_claim(&pool, agent, COMPOUND_A).await;

    let llm = MockLlmClient::new();
    let claims = vec![BatchClaim {
        claim_id: parent,
        agent_id: agent,
        content: COMPOUND_A.to_string(),
    }];

    let submitted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let submitted_c = submitted.clone();
    let totals = run_decomposition_batches(&pool, &claims, &llm, 10, None, move |_t, _g, _a| {
        submitted_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        async move { Ok(Uuid::new_v4()) }
    })
    .await
    .unwrap();

    assert_eq!(totals.atoms, 0, "mock must remain inert");
    assert_eq!(totals.edges, 0, "mock must remain inert");
    assert_eq!(
        submitted.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "mock must not submit any claim"
    );
    assert!(atoms_of(&pool, parent).await.is_empty());
}
