//! Behavioural suite for the library-level `epigraph_engine::recall::recall`.
//!
//! `recall.rs` promised this file in Phase 0 and deferred it on a seeding
//! helper (`ingest_claim_via_api`) that was never written. The blocker went
//! away when `#[sqlx::test]` fixtures began seeding claims directly — the two
//! neighbouring binaries (`recall_audit_test.rs`,
//! `recall_claims_embedding_test.rs`) already do — but the suite itself was
//! never written, so nothing pinned WHERE recall applies its filters.
//!
//! That turned out to matter. The semantic leg fetched exactly `limit` ANN
//! candidates and only then dropped rows below `min_truth` in Rust, so a page
//! whose nearest `limit` candidates were low-truth came back short, or empty,
//! while qualifying claims sat just past the cut. That is the "seed recall
//! returned no claims" starvation episcience synthesis has hit before.
//!
//! # What each test pins
//!
//! * `min_truth` excludes, on both legs.
//! * `min_truth` narrows the semantic candidate pool BEFORE `LIMIT` —
//!   `semantic_leg_min_truth_does_not_starve_limit`. It carries a calibration
//!   assertion (the same query at `min_truth = 0.0`) proving the low-truth
//!   decoys really are the top-`limit` candidates, so the test cannot pass
//!   vacuously on a fixture where the qualifying claims happened to rank
//!   first anyway.
//! * The `min_truth` bind composes with the viewer's group bind — a group
//!   member sees their own private claim through the semantic leg, a stranger
//!   does not. A mis-numbered bind makes the ANN statement ERROR, and recall
//!   swallows that error into the text fallback; every semantic-leg test
//!   therefore also asserts `similarity > 0`, which the fallback never
//!   produces.
//! * Dispute annotation on both legs.
//!
//! # A limit of the starvation test
//!
//! On these tiny throwaway databases the ANN statement sees every row, so
//! "filter before LIMIT" is exact. On a large corpus served by
//! `idx_claims_embedding_hnsw` the predicate is a filter over the index's
//! `ef_search` candidate set, and a highly selective `min_truth` can still
//! under-fill without `hnsw.iterative_scan` — the same limitation the
//! visibility predicate carries (`docs/tenancy/FINAL-PLAN.md` §10.1 R1).
//! This test pins placement, not that.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_embeddings::{config::EmbeddingConfig, providers::MockProvider, EmbeddingService};
use epigraph_engine::recall::{recall, RecallResult};
use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

/// A deterministic 1536-d embedder: the same query text always yields the same
/// vector, so a claim seeded with that vector is an exact (cosine 1.0) match.
fn embedder() -> MockProvider {
    MockProvider::new(EmbeddingConfig::openai(1536))
}

/// An embedder whose every call fails, which is what routes `recall` into its
/// text fallback. Seeding no embeddings does NOT do that: an empty ANN result
/// is `Ok(vec![])`, and only an `Err` falls back.
fn failing_embedder() -> MockProvider {
    embedder().with_failures(1.0)
}

fn pgvec(v: &[f32]) -> String {
    format!(
        "[{}]",
        v.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn cosine(a: &[f32], b: &[f32]) -> f64 {
    let dot: f64 = a
        .iter()
        .zip(b)
        .map(|(x, y)| f64::from(*x) * f64::from(*y))
        .sum();
    let na: f64 = a.iter().map(|x| f64::from(*x).powi(2)).sum::<f64>().sqrt();
    let nb: f64 = b.iter().map(|x| f64::from(*x).powi(2)).sum::<f64>().sqrt();
    dot / (na * nb)
}

/// `q` pushed off-axis along basis vector `axis`: strictly less similar to `q`
/// than `q` itself, and still well inside the neighbourhood.
fn perturbed(q: &[f32], axis: usize) -> Vec<f32> {
    let mut v = q.to_vec();
    v[axis] += 0.6;
    v
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'test-recall-suite', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

/// How a seeded claim should look. Tenancy is declared explicitly — public and
/// world-owned unless `group` is set — rather than left to a trigger, so the
/// viewer each test uses provably can (or cannot) see it.
struct Seed<'a> {
    content: &'a str,
    truth: f64,
    embedding: Option<&'a str>,
    group: Option<Uuid>,
}

impl<'a> Seed<'a> {
    fn new(content: &'a str, truth: f64) -> Self {
        Self {
            content,
            truth,
            embedding: None,
            group: None,
        }
    }
    fn embedded(mut self, v: &'a str) -> Self {
        self.embedding = Some(v);
        self
    }
    fn private_to(mut self, group: Uuid) -> Self {
        self.group = Some(group);
        self
    }
}

async fn seed(pool: &PgPool, agent: Uuid, s: Seed<'_>) -> Uuid {
    let (visibility, owner) = match s.group {
        Some(g) => ("group", g),
        None => ("public", fixture::world_group(pool).await),
    };
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, embedding, \
                             is_current, visibility, owner_group_id) \
         VALUES ($1, $2, sha256($1::text::bytea), $3, $4, $5::vector, true, $6, $7)",
    )
    .bind(id)
    .bind(s.content)
    .bind(agent)
    .bind(s.truth)
    .bind(s.embedding)
    .bind(visibility)
    .bind(owner)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn seed_contradicts(pool: &PgPool, source: Uuid, target: Uuid) {
    sqlx::query(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship) \
         VALUES ($1, $2, 'claim', 'claim', 'contradicts')",
    )
    .bind(source)
    .bind(target)
    .execute(pool)
    .await
    .expect("seed contradicts edge");
}

fn ids(results: &[RecallResult]) -> HashSet<Uuid> {
    results
        .iter()
        .map(|r| Uuid::parse_str(&r.claim_id).expect("claim_id is a uuid"))
        .collect()
}

fn assert_semantic(results: &[RecallResult]) {
    for r in results {
        assert!(
            r.similarity > 0.0,
            "result {} carries similarity {} — the text fallback's constant. The \
             semantic leg errored and recall silently fell back, which is what a \
             mis-numbered bind in the ANN statement looks like",
            r.claim_id,
            r.similarity
        );
    }
}

// ── semantic leg ──────────────────────────────────────────────────────────────

/// A claim below `min_truth` is excluded even when it is the best match.
#[sqlx::test(migrations = "../../migrations")]
async fn semantic_leg_drops_claims_below_min_truth(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let mock = embedder();
    let query = "quillfeather lattice resonance";
    let q = pgvec(&mock.generate_query(query).await.expect("embed"));
    let agent = seed_agent(&pool).await;

    let high = seed(
        &pool,
        agent,
        Seed::new("quillfeather high", 0.9).embedded(&q),
    )
    .await;
    let low = seed(
        &pool,
        agent,
        Seed::new("quillfeather low", 0.2).embedded(&q),
    )
    .await;

    let results = recall(&pool, &viewer, &mock, query, 10, 0.5)
        .await
        .expect("recall");

    assert_semantic(&results);
    let got = ids(&results);
    assert!(got.contains(&high), "the 0.9 claim clears min_truth 0.5");
    assert!(!got.contains(&low), "the 0.2 claim is below min_truth 0.5");
    assert!(
        results.iter().all(|r| r.truth_value >= 0.5),
        "every result must honour min_truth"
    );
}

/// `min_truth` must narrow the candidate pool BEFORE `LIMIT`, not trim an
/// already-truncated top-`limit`.
///
/// Three low-truth decoys sit exactly on the query vector; two qualifying
/// claims sit slightly off it. Filtering after a `limit = 2` fetch sees only
/// decoys and returns nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn semantic_leg_min_truth_does_not_starve_limit(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let mock = embedder();
    let query = "brindlewort catalysis pathway";
    let qv = mock.generate_query(query).await.expect("embed");
    let q = pgvec(&qv);
    let far_a = perturbed(&qv, 0);
    let far_b = perturbed(&qv, 1);
    for far in [&far_a, &far_b] {
        let c = cosine(&qv, far);
        assert!(
            c < 0.99 && c > 0.5,
            "fixture geometry: a qualifying claim must be strictly further from \
             the query than the decoys, yet still a neighbour; cosine was {c}"
        );
    }
    let (far_a, far_b) = (pgvec(&far_a), pgvec(&far_b));
    let agent = seed_agent(&pool).await;

    let mut decoys = HashSet::new();
    for i in 0..3 {
        let content = format!("brindlewort decoy {i}");
        decoys.insert(seed(&pool, agent, Seed::new(&content, 0.1).embedded(&q)).await);
    }
    let a = seed(
        &pool,
        agent,
        Seed::new("brindlewort a", 0.9).embedded(&far_a),
    )
    .await;
    let b = seed(
        &pool,
        agent,
        Seed::new("brindlewort b", 0.9).embedded(&far_b),
    )
    .await;

    // Calibration: with no truth floor, the top 2 are decoys. Without this the
    // assertion below could pass on a fixture that never exercised placement.
    let unfiltered = recall(&pool, &viewer, &mock, query, 2, 0.0)
        .await
        .expect("recall");
    assert_semantic(&unfiltered);
    assert!(
        ids(&unfiltered).is_subset(&decoys) && unfiltered.len() == 2,
        "calibration: the nearest 2 candidates must be decoys"
    );

    let results = recall(&pool, &viewer, &mock, query, 2, 0.5)
        .await
        .expect("recall");
    assert_semantic(&results);
    assert_eq!(
        ids(&results),
        HashSet::from([a, b]),
        "min_truth must be applied before LIMIT: both qualifying claims exist \
         within the neighbourhood, so a limit-2 page must hold both"
    );
}

/// The `min_truth` bind must not displace the viewer's group bind: a member
/// reads their own group-private claim through the semantic leg, filtered by
/// `min_truth`, and a stranger reads neither.
#[sqlx::test(migrations = "../../migrations")]
async fn semantic_leg_min_truth_composes_with_group_visibility(pool: PgPool) {
    let mock = embedder();
    let query = "tessellate moraine bedrock";
    let q = pgvec(&mock.generate_query(query).await.expect("embed"));
    let (member, group) = fixture::seed_agent_with_group(&pool, "recall-suite").await;
    let member_viewer = epigraph_db::visibility::Viewer::resolve(&pool, member)
        .await
        .expect("resolve member");
    let stranger = fixture::public_viewer(&pool).await;

    let high = seed(
        &pool,
        member,
        Seed::new("tessellate high", 0.9)
            .embedded(&q)
            .private_to(group),
    )
    .await;
    let low = seed(
        &pool,
        member,
        Seed::new("tessellate low", 0.2)
            .embedded(&q)
            .private_to(group),
    )
    .await;

    let mine = recall(&pool, &member_viewer, &mock, query, 10, 0.5)
        .await
        .expect("recall as member");
    assert_semantic(&mine);
    assert_eq!(
        ids(&mine),
        HashSet::from([high]),
        "the member sees their own private claim above min_truth, and not the \
         one below it"
    );

    let theirs = recall(&pool, &stranger, &mock, query, 10, 0.0)
        .await
        .expect("recall as stranger");
    let got = ids(&theirs);
    assert!(
        !got.contains(&high) && !got.contains(&low),
        "a non-member must not read a group-private claim"
    );
}

// ── text fallback ─────────────────────────────────────────────────────────────

/// The fallback applies `min_truth`, and reports similarity 0.0.
#[sqlx::test(migrations = "../../migrations")]
async fn text_fallback_drops_claims_below_min_truth(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let high = seed(&pool, agent, Seed::new("the zorblax fixture holds", 0.9)).await;
    let low = seed(&pool, agent, Seed::new("the zorblax fixture fails", 0.2)).await;

    // The fallback ILIKEs the whole query as one substring, so the query must
    // be a literal substring of the seeded content or it proves nothing.
    let results = recall(&pool, &viewer, &failing_embedder(), "zorblax", 10, 0.5)
        .await
        .expect("recall");

    let got = ids(&results);
    assert!(got.contains(&high), "the 0.9 claim clears min_truth 0.5");
    assert!(!got.contains(&low), "the 0.2 claim is below min_truth 0.5");
    assert!(
        results.iter().all(|r| r.similarity == 0.0),
        "every result came through the text fallback"
    );
}

// ── dispute annotation ────────────────────────────────────────────────────────

/// Both legs annotate a live `contradicts` against a returned claim, and leave
/// an uncontested one at its defaults.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_annotates_live_disputes_on_both_legs(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let mock = embedder();
    let query = "wobblecrest dispute";
    let q = pgvec(&mock.generate_query(query).await.expect("embed"));
    let agent = seed_agent(&pool).await;

    let contested = seed(
        &pool,
        agent,
        Seed::new("wobblecrest dispute contested", 0.9).embedded(&q),
    )
    .await;
    let calm = seed(
        &pool,
        agent,
        Seed::new("wobblecrest dispute calm", 0.9).embedded(&q),
    )
    .await;
    // The contester's content does not match the query and it has no vector,
    // so it is never itself a result — it only marks its target.
    let contester = seed(&pool, agent, Seed::new("an unrelated rebuttal", 0.7)).await;
    seed_contradicts(&pool, contester, contested).await;

    for (leg, results) in [
        (
            "semantic",
            recall(&pool, &viewer, &mock, query, 10, 0.0)
                .await
                .expect("recall"),
        ),
        (
            "fallback",
            recall(&pool, &viewer, &failing_embedder(), query, 10, 0.0)
                .await
                .expect("recall"),
        ),
    ] {
        let find = |id: Uuid| {
            results
                .iter()
                .find(|r| r.claim_id == id.to_string())
                .unwrap_or_else(|| panic!("{leg}: claim {id} must be returned"))
        };
        let c = find(contested);
        assert_eq!(c.dispute_count, 1, "{leg}: one live contradicts edge");
        assert!(c.is_contested, "{leg}: dispute_count > 0 means contested");
        assert_eq!(
            c.contesting_claim_ids,
            vec![contester],
            "{leg}: names the contester"
        );
        let k = find(calm);
        assert_eq!(k.dispute_count, 0, "{leg}: uncontested");
        assert!(!k.is_contested, "{leg}: uncontested");
        assert!(k.contesting_claim_ids.is_empty(), "{leg}: uncontested");
    }
}
