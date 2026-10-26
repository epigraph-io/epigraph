//! Engine twin of the MCP recall partition fix (see
//! `epigraph-mcp/tests/recall_partition_reads_gated_score.rs`).
//!
//! `epigraph_engine::recall::recall` (the library path other crates seed
//! from) has no epistemic partition, so the property it must hold is the one
//! the partition now depends on: the gate admits or drops a claim on its gated
//! belief, never on its authored `truth_value`, and reports that gated score
//! as `belief_score`. In each test the two claims are identical to retrieval
//! and differ only in which side of the gate their authored value and their DS
//! value fall on.
//!
//! `recall` has two legs that gate separately: the semantic leg, and
//! `text_search_fallback` (the ILIKE leg that serves a seed whenever the
//! embedder errs). Each leg gets its own case, so a regression in either one
//! is caught on its own.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_embeddings::{config::EmbeddingConfig, providers::MockProvider, EmbeddingService};
use epigraph_engine::recall::recall;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(id)
        .bind("cc".repeat(32))
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

/// `pgvec: None` seeds a claim with no embedding, which only the ILIKE
/// fallback leg can return.
async fn seed_claim(
    pool: &PgPool,
    agent: Uuid,
    content: &str,
    truth: f64,
    pgvec: Option<&str>,
) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    hash[..16].copy_from_slice(id.as_bytes());
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, embedding, is_current) \
         VALUES ($1, $2, $3, $4, $5, $6::vector, true)",
    )
    .bind(id)
    .bind(content)
    .bind(hash)
    .bind(agent)
    .bind(truth)
    .bind(pgvec)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// A coherent DS cache (Bel <= BetP <= Pl); `truth_value` stays authored.
async fn set_ds_cache(pool: &PgPool, claim: Uuid, belief: f64, plausibility: f64, betp: f64) {
    assert!(belief <= betp && betp <= plausibility);
    sqlx::query(
        "UPDATE claims SET belief = $2, plausibility = $3, pignistic_prob = $4 WHERE id = $1",
    )
    .bind(claim)
    .bind(belief)
    .bind(plausibility)
    .bind(betp)
    .execute(pool)
    .await
    .expect("seed DS cache");
}

#[sqlx::test(migrations = "../../migrations")]
async fn engine_recall_gates_on_the_gated_score_not_truth_value(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let mock = MockProvider::new(EmbeddingConfig::openai(1536));
    let query = "brelltide sorption isotherm";
    let qvec = mock.generate_query(query).await.expect("mock embed");
    let pgvec = format!(
        "[{}]",
        qvec.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );

    let agent = seed_agent(&pool).await;
    let inflated = seed_claim(
        &pool,
        agent,
        "brelltide sorption inflated",
        0.9,
        Some(&pgvec),
    )
    .await;
    let understated = seed_claim(
        &pool,
        agent,
        "brelltide sorption understated",
        0.4,
        Some(&pgvec),
    )
    .await;
    set_ds_cache(&pool, inflated, 0.3, 0.5, 0.4).await;
    set_ds_cache(&pool, understated, 0.85, 0.95, 0.9).await;

    // Control: with the gate wide open both claims are reachable, so an absence
    // below is the gate deciding, not the fixture being unretrievable.
    let open = recall(&pool, &viewer, &mock, query, 10, 0.0)
        .await
        .expect("recall");
    let open_ids: Vec<&str> = open.iter().map(|r| r.claim_id.as_str()).collect();
    assert!(
        open_ids.contains(&inflated.to_string().as_str())
            && open_ids.contains(&understated.to_string().as_str()),
        "control: both claims must be retrievable at min_truth 0.0, got {open_ids:?}"
    );

    let gated = recall(&pool, &viewer, &mock, query, 10, 0.5)
        .await
        .expect("recall");
    assert!(
        !gated.iter().any(|r| r.claim_id == inflated.to_string()),
        "a claim with truth_value 0.9 and BetP 0.4 passed a 0.5 gate: the engine gate is \
         reading truth_value"
    );
    let kept = gated
        .iter()
        .find(|r| r.claim_id == understated.to_string())
        .expect("a claim with BetP 0.9 must pass a 0.5 gate whatever its truth_value (0.4)");
    assert!(
        (kept.belief_score - 0.9).abs() < 1e-9 && (kept.truth_value - 0.4).abs() < 1e-9,
        "the engine must report the gated score as belief_score (0.9) and the authored \
         truth_value (0.4) unchanged; got belief_score={} truth_value={}",
        kept.belief_score,
        kept.truth_value
    );
}

/// The ILIKE fallback leg: the embedder errs on every call, and the fixture
/// claims carry no embedding, so only `text_search_fallback` can return them.
#[sqlx::test(migrations = "../../migrations")]
async fn engine_recall_fallback_leg_gates_on_the_gated_score_not_truth_value(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // failure_rate 1.0: every generate_query errs, so `recall` takes the
    // text-search fallback on every call below.
    let failing = MockProvider::new(EmbeddingConfig::openai(1536)).with_failures(1.0);
    assert!(
        failing.generate_query("probe").await.is_err(),
        "fixture: the provider must refuse to embed, or the semantic leg runs instead"
    );
    // ILIKE is `%query%`: every fixture's content contains the whole query.
    let query = "vexmorrow lattice strain";

    let agent = seed_agent(&pool).await;
    let inflated = seed_claim(&pool, agent, "vexmorrow lattice strain inflated", 0.9, None).await;
    let understated = seed_claim(
        &pool,
        agent,
        "vexmorrow lattice strain understated",
        0.4,
        None,
    )
    .await;
    set_ds_cache(&pool, inflated, 0.3, 0.5, 0.4).await;
    set_ds_cache(&pool, understated, 0.85, 0.95, 0.9).await;

    // Control: with the gate wide open the fallback leg returns both claims, so
    // an absence below is the gate deciding.
    let open = recall(&pool, &viewer, &failing, query, 10, 0.0)
        .await
        .expect("recall");
    let open_ids: Vec<&str> = open.iter().map(|r| r.claim_id.as_str()).collect();
    assert!(
        open_ids.contains(&inflated.to_string().as_str())
            && open_ids.contains(&understated.to_string().as_str()),
        "control: both claims must be returned by the fallback leg at min_truth 0.0, \
         got {open_ids:?}"
    );

    let gated = recall(&pool, &viewer, &failing, query, 10, 0.5)
        .await
        .expect("recall");
    assert!(
        !gated.iter().any(|r| r.claim_id == inflated.to_string()),
        "a claim with truth_value 0.9 and BetP 0.4 passed a 0.5 gate on the fallback leg: \
         text_search_fallback is reading truth_value"
    );
    let kept = gated
        .iter()
        .find(|r| r.claim_id == understated.to_string())
        .expect(
            "a claim with BetP 0.9 must pass a 0.5 gate on the fallback leg whatever its \
             truth_value (0.4)",
        );
    assert!(
        (kept.belief_score - 0.9).abs() < 1e-9 && (kept.truth_value - 0.4).abs() < 1e-9,
        "the fallback leg must report the gated score as belief_score (0.9) and the authored \
         truth_value (0.4) unchanged; got belief_score={} truth_value={}",
        kept.belief_score,
        kept.truth_value
    );
}
