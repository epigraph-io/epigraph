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
//! # Two escape hatches
//!
//! 1. **`novelty_threshold = 0.0`**: a distance is never `< 0.0`, so the
//!    semantic-duplicate branch never fires and every submission inserts
//!    (still subject to the fixed 0.15 near-duplicate soft-flag). This is a
//!    per-CALL opt-out: the caller has to remember it on every submission.
//!
//! 2. **Status labels** ([`STATUS_CLAIM_LABELS`]): a STRUCTURAL opt-out that
//!    travels with the claim's own labels rather than with the caller's
//!    argument list (operator ruling R-35). A recurring report ("run
//!    2026-07-12: 41 sources, 4 new" then "run 2026-07-19: 42 sources, 7 new")
//!    is templated by construction: only numbers and dates change, so its
//!    embedding sits well inside the 0.05 band and each run silently collapsed
//!    into the PRIOR run's claim, destroying the time series the report exists
//!    to build (backlog `a3e63a12` weekly backfill report, `0a97ba24`
//!    norcal-rfp generator status). Hatch 1 was the documented workaround and
//!    it did not hold: it has to be re-asserted at every call site.
//!
//!    A labelled status claim gets the SAME semantics as
//!    `novelty_threshold = 0.0`: suppression off, 0.15 soft-flag still on.
//!    Suppression is what loses data; the flag is only discoverability.
//!
//! The bypass sits in [`decide`], the one function every gated write path
//! (`submit_claim`, `batch_submit_claims` through it, `memorize`) calls, and
//! `labels` is a required argument there. No HTTP claim-write route runs this
//! gate, so there is nothing to bypass on that transport.

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

/// Labels that mark a claim as a templated per-run status or telemetry report,
/// exempt from novelty suppression (see the module docs' escape hatch 2).
///
/// These are the labels recurring reporters already attach to their own
/// summaries, not a new taxonomy:
///
/// * `telemetry`: the marker this repo's embedding policy already keys on;
///   scheduled agents also put it on per-run observations (url-discovery
///   results, filter-drop lists, fetch outages).
/// * The per-run summary labels the scheduled writers in epiclaw-host's
///   `deploy/` prompts write today: the norcal-rfp generators, reviewers,
///   revisers and cross-generator dedup (`norcal-rfp-*-status`), and the
///   grant-monitor generators, dedup and run summary (`grant-*-status`). Those
///   writers rebuild their roster of completed cycles from these labels, so a
///   collapsed run reads as a cycle that never ran.
/// * The bare forms the same reporters used before their labels were prefixed
///   (`gen-status`, `generator-summary`, `review-status`, `revise-status`,
///   `research-scan`).
///
/// Matching is EXACT (no prefix, suffix or case folding). Deliberately excluded
/// although they co-occur with status claims: TOPIC labels such as
/// `graph-integrity`, `maintenance` or `rfp`. They say what a claim is about,
/// not that it is a periodic report, and exempting one would silently disable
/// dedup for genuine content on that topic. A new recurring reporter adds its
/// summary label here.
pub const STATUS_CLAIM_LABELS: [&str; 13] = [
    "telemetry",
    "gen-status",
    "generator-summary",
    "review-status",
    "revise-status",
    "research-scan",
    "norcal-rfp-gen-status",
    "norcal-rfp-review-status",
    "norcal-rfp-revise-status",
    "norcal-rfp-dedup-status",
    "grant-gen-status",
    "grant-run-status",
    "grant-dedup-status",
];

/// `true` when any of `labels` is in [`STATUS_CLAIM_LABELS`].
#[must_use]
pub fn is_status_claim(labels: &[String]) -> bool {
    labels
        .iter()
        .any(|l| STATUS_CLAIM_LABELS.contains(&l.as_str()))
}

/// The threshold actually applied to a submission: `0.0` (never suppress) for
/// a status claim, otherwise the caller's `novelty_threshold`.
#[must_use]
pub fn effective_threshold(novelty_threshold: f64, labels: &[String]) -> f64 {
    if is_status_claim(labels) {
        0.0
    } else {
        novelty_threshold
    }
}

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
/// pgvector-formatted, so the caller can hand it straight to
/// `claim_helper::embed_claim_author_stamped`'s `pending_embedding` parameter
/// instead of paying for a second embedding call. (Storing it "directly" through
/// `ClaimRepository::store_embedding` — which this sentence used to recommend —
/// is the unstamped write that `claims_tenancy` refuses; the stamped store is the
/// only one that lands.) (Only the formatted string
/// is returned, not the raw `Vec<f32>` — no caller needs the unformatted
/// vector, and carrying a dead 1536-element `Vec<f32>` through every
/// caller's match arm would be pure waste.)
///
/// Takes `&dyn EmbeddingService` (not the concrete `McpEmbedder`) purely so
/// this function is unit-testable against `epigraph_embeddings::MockProvider`
/// — `EpiGraphMcpFull` itself still only ever constructs this with its one
/// concrete `McpEmbedder` (hardcoded to the OpenAI endpoint); this is not a
/// server-wide trait-object refactor.
///
/// `labels` are the labels the CALLER attaches to this submission
/// (`submit_claim`'s `labels`, `memorize`'s `tags`); a status label lifts
/// suppression ([`effective_threshold`]). They are a required argument so that
/// a new gated write path has to pass its real labels: never `&[]` as a
/// placeholder.
pub async fn decide(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    embedder: &dyn epigraph_embeddings::EmbeddingService,
    content: &str,
    novelty_threshold: f64,
    labels: &[String],
) -> Option<(GateDecision, String)> {
    let vector = embedder.generate(content).await.ok()?;
    let pgvec = crate::embed::format_pgvector(&vector);
    let nearest = match ClaimRepository::nearest_by_embedding(pool, viewer, &pgvec, NEAREST_K).await
    {
        Ok(hits) => hits,
        Err(e) => {
            tracing::warn!("novelty gate: nearest_by_embedding failed: {e}");
            return None;
        }
    };
    let threshold = effective_threshold(novelty_threshold, labels);
    Some((classify(&nearest, threshold), pgvec))
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

        let (decision, _pgvec) = decide(
            &pool,
            &epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
                .await
                .expect("resolve viewer"),
            &embedder,
            text,
            DEFAULT_NOVELTY_THRESHOLD,
            &[],
        )
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

        let (decision, _pgvec) = decide(
            &pool,
            &epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
                .await
                .expect("resolve viewer"),
            &embedder,
            text,
            0.0,
            &[],
        )
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
            &epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
                .await
                .expect("resolve viewer"),
            &embedder,
            "an utterly unrelated claim with no corpus neighbors",
            DEFAULT_NOVELTY_THRESHOLD,
            &[],
        )
        .await
        .expect("decide must succeed with a working mock embedder");

        assert_eq!(decision, GateDecision::Insert);
    }

    // ── status-claim bypass (ruling R-35) ────────────────────────────────

    #[test]
    fn is_status_claim_matches_only_the_listed_labels_exactly() {
        for label in STATUS_CLAIM_LABELS {
            assert!(
                is_status_claim(&["2026-07-19".to_string(), label.to_string()]),
                "`{label}` is in STATUS_CLAIM_LABELS and must be recognized"
            );
        }
        assert!(!is_status_claim(&[]));
        assert!(!is_status_claim(&[
            "graph-integrity".to_string(),
            "maintenance".to_string(),
            "rfp".to_string(),
            "backlog".to_string(),
        ]));
        // Exact, not substring / prefix / suffix / case-insensitive: a claim
        // ABOUT telemetry, or a lookalike, is not a status report.
        for lookalike in [
            "telemetry-design",
            "Telemetry",
            "norcal-rfp-gen-status-v2",
            "rfp-gen-status",
            "per-exit-status",
        ] {
            assert!(
                !is_status_claim(&[lookalike.to_string()]),
                "`{lookalike}` must not bypass the gate"
            );
        }
    }

    /// A status label pins the effective threshold to 0.0 whatever the caller
    /// passed, including a deliberately raised one; any other label set passes
    /// the caller's value through untouched.
    #[test]
    fn status_label_overrides_any_caller_supplied_threshold() {
        let status = vec!["grant-gen-status".to_string()];
        assert!(effective_threshold(DEFAULT_NOVELTY_THRESHOLD, &status).abs() < f64::EPSILON);
        assert!(effective_threshold(0.9, &status).abs() < f64::EPSILON);
        let plain = vec!["backlog".to_string()];
        assert!((effective_threshold(0.9, &plain) - 0.9).abs() < f64::EPSILON);
        assert!(
            (effective_threshold(DEFAULT_NOVELTY_THRESHOLD, &plain) - DEFAULT_NOVELTY_THRESHOLD)
                .abs()
                < f64::EPSILON
        );
    }
}
