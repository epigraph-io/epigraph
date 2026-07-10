//! Write-side semantic novelty gate for `submit_claim` / `memorize`
//! (backlog `1bcaed94`, Task 6.4).
//!
//! Runs AFTER the existing content-hash dedup (`create_claim_idempotent` /
//! `ClaimRepository::create_or_get`) short-circuits an EXACT-content
//! resubmit, and only on genuinely new content: the incoming claim's
//! embedding is generated up front, the nearest `is_current` claims are
//! looked up via [`epigraph_db::ClaimRepository::nearest_by_embedding`]
//! (cosine distance, `<=>` — see that function's doc comment for why not
//! the backlog plan's literal `<->`), and the closest neighbor's distance
//! decides:
//!
//! - `dist < novelty_threshold` (default `0.05`) — semantic duplicate.
//!   Suppress the insert; return the existing claim's id.
//! - `dist < 0.15` — near-duplicate. Insert normally, but flag it with a
//!   `near-duplicate` label so it is discoverable/reviewable. The 0.15 band
//!   is fixed, NOT the tunable `novelty_threshold`.
//! - otherwise — insert normally, no flag.
//!
//! `novelty_threshold = 0.0` is the escape hatch: a distance is never `< 0.0`,
//! so the semantic-duplicate branch never fires and every submission inserts
//! (still subject to the fixed 0.15 near-duplicate soft-flag).

use epigraph_db::{ClaimRepository, NearestClaimHit};
use sqlx::PgPool;
use uuid::Uuid;

/// Number of ANN neighbors fetched per the backlog plan's SQL sketch
/// (`... ORDER BY dist LIMIT 5`). Only the closest is used for the gate
/// decision; the rest is headroom for future soft-dup review tooling.
pub const NEAREST_K: i64 = 5;

/// Fixed near-duplicate soft-flag band. NOT the tunable `novelty_threshold`
/// — see module docs.
pub const NEAR_DUPLICATE_BAND: f64 = 0.15;

/// Default `novelty_threshold` when the caller omits it — backward
/// compatible: existing callers that don't know about this param get this
/// value, not 0.0 (which would disable the gate entirely).
pub const DEFAULT_NOVELTY_THRESHOLD: f64 = 0.05;

/// Outcome of the gate decision, independent of I/O — see [`classify`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GateDecision {
    /// `dist < novelty_threshold`: suppress the insert, return the existing
    /// claim's id unchanged.
    ReturnExisting(Uuid),
    /// `novelty_threshold <= dist < NEAR_DUPLICATE_BAND`: insert normally,
    /// but append the `near-duplicate` label.
    InsertFlagged,
    /// `dist >= NEAR_DUPLICATE_BAND` (or no neighbors at all): insert
    /// normally, no flag.
    Insert,
}

/// Pure decision function — no I/O, directly testable.
///
/// `nearest` is the ANN result ordered closest-first (as returned by
/// `ClaimRepository::nearest_by_embedding`); only `nearest.first()` is
/// consulted since Step 2 of the backlog task is defined purely in terms of
/// the single nearest neighbor's distance.
#[must_use]
pub fn classify(nearest: &[NearestClaimHit], novelty_threshold: f64) -> GateDecision {
    match nearest.first() {
        Some(hit) if hit.distance < novelty_threshold => GateDecision::ReturnExisting(hit.claim_id),
        Some(hit) if hit.distance < NEAR_DUPLICATE_BAND => GateDecision::InsertFlagged,
        _ => GateDecision::Insert,
    }
}

/// I/O wrapper: embed `content`, look up its nearest `is_current` claims,
/// and classify. Returns `None` (never gates) if embedding generation
/// fails — the gate is best-effort and must never block a write the way
/// post-insert embedding is best-effort today (see CLAUDE.md embedding
/// policy). Callers that get `None` should fall back to the pre-gate
/// embed-after-insert behavior (there is no vector to reuse).
///
/// On `Some`, the returned `String` is the ALREADY-GENERATED embedding,
/// pgvector-formatted, so the caller can store it directly
/// (`ClaimRepository::store_embedding`) instead of calling `embed_and_store`
/// again and paying for a second embedding call. (Only the formatted string
/// is returned, not the raw `Vec<f32>` — no caller needs the unformatted
/// vector, and carrying a dead 1536-element `Vec<f32>` through every
/// caller's match arm would be pure waste.)
///
/// Takes `&dyn EmbeddingService` (not the concrete `McpEmbedder`) purely so
/// this function is unit-testable against `epigraph_embeddings::MockProvider`
/// — `EpiGraphMcpFull` itself still only ever constructs this with its one
/// concrete `McpEmbedder` (hardcoded to the OpenAI endpoint); this is not a
/// server-wide trait-object refactor.
pub async fn decide(
    pool: &PgPool,
    embedder: &dyn epigraph_embeddings::EmbeddingService,
    content: &str,
    novelty_threshold: f64,
) -> Option<(GateDecision, String)> {
    let vector = embedder.generate(content).await.ok()?;
    let pgvec = crate::embed::format_pgvector(&vector);
    let nearest = match ClaimRepository::nearest_by_embedding(pool, &pgvec, NEAREST_K).await {
        Ok(hits) => hits,
        Err(e) => {
            tracing::warn!("novelty gate: nearest_by_embedding failed: {e}");
            return None;
        }
    };
    Some((classify(&nearest, novelty_threshold), pgvec))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(distance: f64) -> NearestClaimHit {
        NearestClaimHit {
            claim_id: Uuid::new_v4(),
            distance,
        }
    }

    #[test]
    fn empty_neighbors_inserts_unflagged() {
        assert_eq!(
            classify(&[], DEFAULT_NOVELTY_THRESHOLD),
            GateDecision::Insert
        );
    }

    #[test]
    fn distance_below_default_threshold_returns_existing() {
        let h = hit(0.01);
        let expected_id = h.claim_id;
        let nearest = [h];
        assert_eq!(
            classify(&nearest, DEFAULT_NOVELTY_THRESHOLD),
            GateDecision::ReturnExisting(expected_id)
        );
    }

    #[test]
    fn distance_in_near_duplicate_band_inserts_flagged() {
        let nearest = [hit(0.10)];
        assert_eq!(
            classify(&nearest, DEFAULT_NOVELTY_THRESHOLD),
            GateDecision::InsertFlagged
        );
    }

    #[test]
    fn distance_at_near_duplicate_band_boundary_is_exclusive() {
        // dist == 0.15 is NOT < 0.15, so it must NOT be flagged.
        let nearest = [hit(NEAR_DUPLICATE_BAND)];
        assert_eq!(
            classify(&nearest, DEFAULT_NOVELTY_THRESHOLD),
            GateDecision::Insert
        );
    }

    #[test]
    fn distance_at_novelty_threshold_boundary_is_exclusive() {
        // dist == threshold is NOT < threshold, so it must NOT be suppressed;
        // it falls through to the near-duplicate band check instead.
        let nearest = [hit(DEFAULT_NOVELTY_THRESHOLD)];
        assert_eq!(
            classify(&nearest, DEFAULT_NOVELTY_THRESHOLD),
            GateDecision::InsertFlagged
        );
    }

    #[test]
    fn distance_far_above_band_inserts_unflagged() {
        let nearest = [hit(0.9)];
        assert_eq!(
            classify(&nearest, DEFAULT_NOVELTY_THRESHOLD),
            GateDecision::Insert
        );
    }

    /// `novelty_threshold = 0.0` is the escape hatch: distance is never
    /// negative, so `dist < 0.0` never holds and ReturnExisting can never
    /// fire, even for a near-identical (dist ~ 0) neighbor. The fixed 0.15
    /// near-duplicate band still applies — the escape hatch disables
    /// suppression, not the soft flag.
    #[test]
    fn zero_threshold_never_suppresses_even_near_zero_distance() {
        let nearest = [hit(0.0001)];
        assert_eq!(classify(&nearest, 0.0), GateDecision::InsertFlagged);
    }

    #[test]
    fn zero_threshold_still_flags_within_near_duplicate_band() {
        let nearest = [hit(0.12)];
        assert_eq!(classify(&nearest, 0.0), GateDecision::InsertFlagged);
    }

    #[test]
    fn zero_threshold_still_inserts_unflagged_beyond_band() {
        let nearest = [hit(0.5)];
        assert_eq!(classify(&nearest, 0.0), GateDecision::Insert);
    }

    /// Only the closest neighbor matters — a very-close second neighbor
    /// behind a not-close first neighbor must not affect the decision.
    #[test]
    fn only_nearest_neighbor_is_consulted() {
        let nearest = [hit(0.5), hit(0.001)];
        assert_eq!(
            classify(&nearest, DEFAULT_NOVELTY_THRESHOLD),
            GateDecision::Insert
        );
    }

    // ── decide() end-to-end: real embed -> ANN -> classify, real DB ──
    //
    // `EpiGraphMcpFull` only ever constructs `decide()`'s caller with a
    // concrete `McpEmbedder` pointed at the (hardcoded) OpenAI endpoint, so
    // there is no live-embedder path through submit_claim/memorize in this
    // test process (see novelty_gate_test.rs in tests/ for that documented
    // boundary). But `decide()` itself takes `&dyn EmbeddingService`
    // specifically so ITS embed -> nearest_by_embedding -> classify pipeline
    // can be exercised here with `epigraph_embeddings::MockProvider`, which
    // generates a REAL (deterministic, hash-derived, non-mocked-away)
    // 1536-dim vector from text — no network call, but not a stub of
    // `classify` either: distances are computed genuinely by Postgres/pgvector.

    use epigraph_embeddings::{config::EmbeddingConfig, EmbeddingService, MockProvider};

    async fn seed_agent(pool: &sqlx::PgPool) -> Uuid {
        let agent = epigraph_core::Agent::new([0x42u8; 32], Some("novelty-gate-test".to_string()));
        epigraph_db::AgentRepository::create(pool, &agent)
            .await
            .expect("create agent")
            .id
            .into()
    }

    fn distinct_hash(tag: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = tag;
        h
    }

    /// A neighbor claim seeded with the vector for the EXACT SAME text as
    /// the query must be returned as a semantic duplicate (distance ~0 <
    /// default 0.05 threshold) — `decide` must classify it `ReturnExisting`.
    #[sqlx::test(migrations = "../../migrations")]
    async fn decide_returns_existing_for_identical_text_embedding(pool: sqlx::PgPool) {
        let agent = seed_agent(&pool).await;
        let embedder = MockProvider::new(EmbeddingConfig::openai(1536));

        let text = "The mitochondria is the powerhouse of the cell";
        let vector = EmbeddingService::generate(&embedder, text)
            .await
            .expect("mock generate");
        let pgvec = crate::embed::format_pgvector(&vector);

        let neighbor_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, embedding, is_current) \
             VALUES ($1, $2, $3, $4, 0.5, $5::vector, true)",
        )
        .bind(neighbor_id)
        .bind("existing neighbor claim")
        .bind(distinct_hash(1).as_slice())
        .bind(agent)
        .bind(&pgvec)
        .execute(&pool)
        .await
        .expect("seed neighbor claim");

        let (decision, _pgvec) = decide(&pool, &embedder, text, DEFAULT_NOVELTY_THRESHOLD)
            .await
            .expect("decide must succeed with a working mock embedder");

        assert_eq!(
            decision,
            GateDecision::ReturnExisting(neighbor_id),
            "identical-text embedding must be classified as a semantic duplicate of the seeded neighbor"
        );
    }

    /// Same fixture as above, but `novelty_threshold = 0.0` (the escape
    /// hatch): even though the embedding is identical (distance ~0), the
    /// decision must NOT be `ReturnExisting` — it must insert (flagged,
    /// since ~0 is still within the fixed 0.15 near-duplicate band).
    #[sqlx::test(migrations = "../../migrations")]
    async fn decide_zero_threshold_never_returns_existing_even_for_identical_text(
        pool: sqlx::PgPool,
    ) {
        let agent = seed_agent(&pool).await;
        let embedder = MockProvider::new(EmbeddingConfig::openai(1536));

        let text = "Water boils at 100C at standard atmospheric pressure";
        let vector = EmbeddingService::generate(&embedder, text)
            .await
            .expect("mock generate");
        let pgvec = crate::embed::format_pgvector(&vector);

        let neighbor_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, embedding, is_current) \
             VALUES ($1, $2, $3, $4, 0.5, $5::vector, true)",
        )
        .bind(neighbor_id)
        .bind("existing neighbor claim 2")
        .bind(distinct_hash(2).as_slice())
        .bind(agent)
        .bind(&pgvec)
        .execute(&pool)
        .await
        .expect("seed neighbor claim");

        let (decision, _pgvec) = decide(&pool, &embedder, text, 0.0)
            .await
            .expect("decide must succeed with a working mock embedder");

        assert_eq!(
            decision,
            GateDecision::InsertFlagged,
            "novelty_threshold=0.0 must never suppress an insert, even for an identical-text embedding; \
             the fixed 0.15 near-duplicate band still applies"
        );
    }

    /// Unrelated text (no seeded neighbor at all) must classify `Insert`
    /// (no flag) — proves `decide` doesn't spuriously suppress/flag when
    /// the corpus has nothing close.
    #[sqlx::test(migrations = "../../migrations")]
    async fn decide_inserts_unflagged_when_no_neighbors_exist(pool: sqlx::PgPool) {
        let embedder = MockProvider::new(EmbeddingConfig::openai(1536));

        let (decision, _pgvec) = decide(
            &pool,
            &embedder,
            "an utterly unrelated claim with no corpus neighbors",
            DEFAULT_NOVELTY_THRESHOLD,
        )
        .await
        .expect("decide must succeed with a working mock embedder");

        assert_eq!(decision, GateDecision::Insert);
    }
}
