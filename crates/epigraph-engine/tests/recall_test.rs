//! Behavioural suite for the library-level `epigraph_engine::recall::recall`.
//!
//! `recall.rs` promised this file in Phase 0 and deferred it on a seeding
//! helper (`ingest_claim_via_api`) that was never written. The blocker went
//! away when `#[sqlx::test]` fixtures began seeding claims directly — the two
//! neighbouring binaries (`recall_audit_test.rs`,
//! `recall_claims_embedding_test.rs`) already do — but the suite itself was
//! never written, so nothing pinned WHERE recall applies its filters.
//!
//! # What each test pins
//!
//! * `min_truth` excludes, on both legs.
//! * The viewer's group bind reaches the semantic leg — a group member sees
//!   their own private claim, a stranger does not. recall swallows an ANN
//!   statement error into the text fallback, so a broken semantic statement
//!   looks like a working recall; every semantic-leg test therefore also
//!   asserts `similarity > 0`, which the fallback never produces.
//! * Dispute annotation on both legs.

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

/// The viewer's group bind reaches the semantic leg alongside `min_truth`: a
/// member reads their own group-private claim, filtered by `min_truth`, and a
/// stranger reads neither.
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
