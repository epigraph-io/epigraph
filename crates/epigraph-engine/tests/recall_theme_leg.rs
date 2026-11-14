//! The library `recall`'s System-2 theme-traversal leg (backlog a47df8ed).
//!
//! Geometry used by every test. Vectors live in 1536-d, split into 1536/16 = 96
//! wide buckets; a vector is "bucket `b` at magnitude `m`" plus optionally a
//! component in bucket 0, the query bucket. Cosine similarity to the query
//! (pure bucket 0) is then controlled exactly by the bucket-0 share:
//!
//! - `ann_a` / `ann_b`: bucket 0 share 0.36 / 0.35 against a far bucket at 1.0, cosine
//!   ~0.339 / ~0.330. These are the claims nearest the query, but below the 0.4 sparse
//!   threshold, so `RecallRoute::Auto` must trigger the theme leg.
//! - the theme member: bucket 0 share 0.2 against a far bucket at 1.0, cosine
//!   ~0.20: strictly FARTHER from the query than both ANN hits, so a pure ANN
//!   page of 2 can never contain it. It sits in a theme whose CENTROID is the
//!   query bucket itself (cosine 1.0), which is exactly the System-2 signal:
//!   the theme is about the query even though no single member is close.
//!
//! The member therefore appears on a `limit = 2` page if, and only if, the
//! theme leg ran and was RRF-merged. Plain `recall` is the similarity route,
//! so the theme leg is reached only through `recall_routed`. Its private sibling (same theme, closer
//! to the query than the public member) must never appear for a viewer
//! outside its group: the leg is viewer-scoped.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_embeddings::{
    config::EmbeddingConfig, providers::MockProvider, EmbeddingError, EmbeddingService,
    SimilarClaim, TokenUsage,
};
use epigraph_engine::recall::{recall, recall_routed, RecallRoute};
use sqlx::PgPool;
use uuid::Uuid;

const DIM: usize = 1536;
const STRIDE: usize = DIM / 16;

fn vec_to_pgvec(v: &[f32]) -> String {
    format!(
        "[{}]",
        v.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// Bucket 0 at `query_share` plus `far_bucket` at 1.0.
fn mixed(far_bucket: usize, query_share: f32) -> String {
    let mut v = vec![0.0f32; DIM];
    for slot in v.iter_mut().take(STRIDE) {
        *slot = query_share;
    }
    for slot in v.iter_mut().skip(far_bucket * STRIDE).take(STRIDE) {
        *slot = 1.0;
    }
    vec_to_pgvec(&v)
}

/// Pure bucket 0: the query, and the theme centroid.
fn query_bucket() -> String {
    let mut v = vec![0.0f32; DIM];
    for slot in v.iter_mut().take(STRIDE) {
        *slot = 1.0;
    }
    vec_to_pgvec(&v)
}

/// An embedder whose every query embeds to the query bucket, so the test owns
/// the geometry instead of the mock's hash. Everything but the two generate
/// calls delegates to a `MockProvider`; `recall` calls only `generate_query`.
struct FixedEmbedder(Vec<f32>, MockProvider);

#[async_trait::async_trait]
impl EmbeddingService for FixedEmbedder {
    async fn generate(&self, _text: &str) -> Result<Vec<f32>, EmbeddingError> {
        Ok(self.0.clone())
    }
    async fn generate_query(&self, _text: &str) -> Result<Vec<f32>, EmbeddingError> {
        Ok(self.0.clone())
    }
    async fn batch_generate(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        Ok(texts.iter().map(|_| self.0.clone()).collect())
    }
    async fn store(&self, claim_id: Uuid, embedding: &[f32]) -> Result<(), EmbeddingError> {
        self.1.store(claim_id, embedding).await
    }
    async fn get(&self, claim_id: Uuid) -> Result<Vec<f32>, EmbeddingError> {
        self.1.get(claim_id).await
    }
    async fn similar(
        &self,
        embedding: &[f32],
        k: usize,
        min_similarity: f32,
    ) -> Result<Vec<SimilarClaim>, EmbeddingError> {
        self.1.similar(embedding, k, min_similarity).await
    }
    fn dimension(&self) -> usize {
        self.0.len()
    }
    fn token_usage(&self) -> TokenUsage {
        self.1.token_usage()
    }
    fn reset_token_usage(&self) {
        self.1.reset_token_usage()
    }
    async fn health_check(&self) -> Result<(), EmbeddingError> {
        Ok(())
    }
}

fn embedder() -> FixedEmbedder {
    let mut v = vec![0.0f32; DIM];
    for slot in v.iter_mut().take(STRIDE) {
        *slot = 1.0;
    }
    FixedEmbedder(v, MockProvider::new(EmbeddingConfig::openai(DIM)))
}

async fn seed_theme(pool: &PgPool, label: &str, centroid: &str) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description) VALUES ($1, 'recall theme leg test') \
         RETURNING id",
    )
    .bind(label)
    .fetch_one(pool)
    .await
    .expect("insert theme");
    sqlx::query("UPDATE claim_themes SET centroid = $2::vector WHERE id = $1")
        .bind(id)
        .bind(centroid)
        .execute(pool)
        .await
        .expect("set centroid");
    id
}

async fn embed_and_theme(pool: &PgPool, claim: Uuid, vec: &str, theme: Option<Uuid>) {
    fixture::set_claim_embedding(pool, claim, vec).await;
    sqlx::query("UPDATE claims SET truth_value = 0.8, theme_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(theme)
        .execute(pool)
        .await
        .expect("set theme");
}

struct Corpus {
    ann_a: Uuid,
    ann_b: Uuid,
    member: Uuid,
    private_member: Uuid,
    outsider: Uuid,
}

/// Two public ANN-nearest claims outside any theme, one public theme member
/// farther than both, and one group-private theme member that the `outsider`
/// agent (a member of a different group) must never see.
async fn seed(pool: &PgPool) -> Corpus {
    let (author, group) = fixture::seed_agent_with_group(pool, "a47df8ed-author").await;
    let (outsider, _) = fixture::seed_agent_with_group(pool, "a47df8ed-outsider").await;
    let theme = seed_theme(pool, "a47df8ed-theme", &query_bucket()).await;

    let ann_a = fixture::seed_public_claim(pool, author, "near claim a").await;
    embed_and_theme(pool, ann_a, &mixed(3, 0.36), None).await;
    let ann_b = fixture::seed_public_claim(pool, author, "near claim b").await;
    embed_and_theme(pool, ann_b, &mixed(4, 0.35), None).await;

    let member = fixture::seed_public_claim(pool, author, "theme member").await;
    embed_and_theme(pool, member, &mixed(5, 0.2), Some(theme)).await;

    // Closer to the query than the public member, so a leg that forgot the
    // viewer would rank it FIRST in the theme list, not bury it.
    let private_member =
        fixture::seed_group_claim(pool, author, group, "private theme member").await;
    embed_and_theme(pool, private_member, &mixed(6, 0.3), Some(theme)).await;

    Corpus {
        ann_a,
        ann_b,
        member,
        private_member,
        outsider,
    }
}

fn ids(results: &[epigraph_engine::RecallResult]) -> Vec<String> {
    results.iter().map(|r| r.claim_id.clone()).collect()
}

/// The pre-change behaviour, kept reachable AND kept as plain `recall`'s: on the
/// weak fixture, where Auto would traverse, a page of 2 is the two ANN-nearest
/// claims and never the farther theme member. Plain `recall` must serve the
/// same page, so existing callers (episcience synthesis seeding) are not moved
/// onto the uncalibrated Auto thresholds; delegating `recall` to Auto fails it.
#[sqlx::test(migrations = "../../migrations")]
async fn similarity_route_is_ann_only(pool: PgPool) {
    let c = seed(&pool).await;
    let scoped = fixture::scoped_pool(&pool).await;
    let viewer = epigraph_db::Viewer::resolve(&pool, c.outsider)
        .await
        .expect("viewer");
    let routed = recall_routed(
        &pool,
        &scoped,
        &viewer,
        &embedder(),
        "q",
        2,
        0.0,
        RecallRoute::Similarity,
    )
    .await
    .expect("recall");
    let plain = recall(&pool, &scoped, &viewer, &embedder(), "q", 2, 0.0)
        .await
        .expect("recall");
    for (name, page) in [("Similarity", &routed), ("plain recall", &plain)] {
        let got = ids(page);
        assert_eq!(got.len(), 2, "{name}: both ANN hits: {got:?}");
        assert!(got.contains(&c.ann_a.to_string()), "{name}: {got:?}");
        assert!(got.contains(&c.ann_b.to_string()), "{name}: {got:?}");
        assert!(!got.contains(&c.member.to_string()), "{name}: {got:?}");
        assert!(
            page.iter().all(|r| !r.via_theme_traversal),
            "{name} must not run the theme leg: {got:?}"
        );
    }
}

/// Route Auto: the ANN page is weak (max cosine ~0.33 < 0.4), so the theme leg
/// runs and its top member is RRF-merged onto the page, displacing the weaker
/// ANN hit. Fails on the pre-change code, which had no theme leg.
#[sqlx::test(migrations = "../../migrations")]
async fn auto_route_merges_theme_member_when_ann_is_weak(pool: PgPool) {
    let c = seed(&pool).await;
    let scoped = fixture::scoped_pool(&pool).await;
    let viewer = epigraph_db::Viewer::resolve(&pool, c.outsider)
        .await
        .expect("viewer");
    let got = recall_routed(
        &pool,
        &scoped,
        &viewer,
        &embedder(),
        "q",
        2,
        0.0,
        RecallRoute::Auto,
    )
    .await
    .expect("recall");
    let member = got
        .iter()
        .find(|r| r.claim_id == c.member.to_string())
        .unwrap_or_else(|| panic!("theme member missing from auto page: {:?}", ids(&got)));
    assert!(
        member.via_theme_traversal,
        "member must be tagged as theme-leg"
    );
    assert!(
        (member.similarity - 0.196).abs() < 0.02,
        "a theme-leg hit reports its real cosine, got {}",
        member.similarity
    );
    assert_eq!(got.len(), 2, "limit holds after the merge: {:?}", ids(&got));
    assert!(
        got.iter()
            .any(|r| r.claim_id == c.ann_a.to_string() && !r.via_theme_traversal),
        "the top ANN hit survives the merge: {:?}",
        ids(&got)
    );
}

/// The merge is viewer-scoped: the private sibling sits CLOSER to the query
/// than the public member, so an unscoped theme leg ranks it first. An outsider
/// must never receive it, on either the auto or the hierarchical route.
///
/// Result-level absence alone is not the property: the per-claim `get_by_id`
/// re-applies the viewer, so an unscoped theme read would still never RETURN
/// the private row. What it would do is spend a page slot on it and then drop
/// it, so a `limit = 1` hierarchical page comes back EMPTY, and how short the
/// page runs tells the outsider how many hidden rows sit near its query (the
/// ranking side channel backlog a507966d closed on the ANN leg). The
/// `limit = 1` case pins that the slot goes to the visible member.
///
/// This pins the MEMBER level only. The theme shortlist itself
/// (`find_similar_themes_at_dim`, 3 nearest centroids) is not viewer-scoped:
/// themes made up only of claims an outsider cannot read can still take the
/// shortlist slots, so whether a page carries theme-leg hits says something
/// about which themes sit near the query. Theme rows carry no tenancy, and
/// `recall_with_context` and the REST diverse route share that posture.
#[sqlx::test(migrations = "../../migrations")]
async fn theme_leg_never_returns_a_claim_the_viewer_cannot_read(pool: PgPool) {
    let c = seed(&pool).await;
    let scoped = fixture::scoped_pool(&pool).await;
    let viewer = epigraph_db::Viewer::resolve(&pool, c.outsider)
        .await
        .expect("viewer");
    for route in [RecallRoute::Auto, RecallRoute::Hierarchical] {
        let got = recall_routed(&pool, &scoped, &viewer, &embedder(), "q", 10, 0.0, route)
            .await
            .expect("recall");
        let got = ids(&got);
        assert!(
            !got.contains(&c.private_member.to_string()),
            "{route:?} leaked a group-private theme member to an outsider: {got:?}"
        );
        assert!(
            got.contains(&c.member.to_string()),
            "{route:?} must still serve the public member: {got:?}"
        );
    }
    let one = recall_routed(
        &pool,
        &scoped,
        &viewer,
        &embedder(),
        "q",
        1,
        0.0,
        RecallRoute::Hierarchical,
    )
    .await
    .expect("recall");
    assert_eq!(
        ids(&one),
        vec![c.member.to_string()],
        "the one theme slot must go to the visible member, not be spent on a hidden row"
    );
}

/// The hierarchical route is the theme leg ALONE: the ANN-nearest claims carry
/// no theme, so they cannot appear.
#[sqlx::test(migrations = "../../migrations")]
async fn hierarchical_route_serves_only_theme_members(pool: PgPool) {
    let c = seed(&pool).await;
    let scoped = fixture::scoped_pool(&pool).await;
    let viewer = epigraph_db::Viewer::resolve(&pool, c.outsider)
        .await
        .expect("viewer");
    let got = recall_routed(
        &pool,
        &scoped,
        &viewer,
        &embedder(),
        "q",
        10,
        0.0,
        RecallRoute::Hierarchical,
    )
    .await
    .expect("recall");
    assert_eq!(ids(&got), vec![c.member.to_string()]);
    assert!(got[0].via_theme_traversal);
}

/// Auto does NOT traverse when the ANN page is dense and strong: with a claim
/// at cosine 1.0 and a full page of 5, the theme member stays off the page.
#[sqlx::test(migrations = "../../migrations")]
async fn auto_route_skips_theme_leg_when_ann_is_strong(pool: PgPool) {
    let c = seed(&pool).await;
    let (author, _) = fixture::seed_agent_with_group(&pool, "a47df8ed-strong").await;
    let strong = fixture::seed_public_claim(&pool, author, "exact hit").await;
    embed_and_theme(&pool, strong, &query_bucket(), None).await;
    // Pad the visible corpus past the min-hits floor (5) with near-query claims
    // so the page of `limit` is full and its best cosine is 1.0.
    for b in 7..11 {
        let pad = fixture::seed_public_claim(&pool, author, &format!("pad {b}")).await;
        embed_and_theme(&pool, pad, &mixed(b, 0.9), None).await;
    }
    let scoped = fixture::scoped_pool(&pool).await;
    let viewer = epigraph_db::Viewer::resolve(&pool, c.outsider)
        .await
        .expect("viewer");
    let got = recall_routed(
        &pool,
        &scoped,
        &viewer,
        &embedder(),
        "q",
        5,
        0.0,
        RecallRoute::Auto,
    )
    .await
    .expect("recall");
    assert!(
        got.iter().all(|r| !r.via_theme_traversal),
        "a strong, full ANN page must not trigger the theme leg: {:?}",
        ids(&got)
    );
    assert!(!ids(&got).contains(&c.member.to_string()));
}

/// Break the theme read alone: every theme-leg query reads
/// `claim_themes.centroid`, and nothing on the ANN, text, belief, dispute or
/// audit paths does.
async fn break_theme_read(pool: &PgPool) {
    sqlx::query("ALTER TABLE claim_themes RENAME COLUMN centroid TO centroid_broken")
        .execute(pool)
        .await
        .expect("rename centroid");
}

/// A failed theme leg degrades instead of erroring, and differently per route.
///
/// - Auto still holds a valid ANN page and must serve it. The query text
///   "theme member" would make the text fallback return the theme member, so
///   an Auto that dropped to text search instead serves the wrong page.
/// - Hierarchical has no ANN page and must fall back to text search: "near
///   claim a" matches exactly one visible claim. A Hierarchical that served
///   the empty theme page instead returns nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn failed_theme_leg_degrades_per_route(pool: PgPool) {
    let c = seed(&pool).await;
    let scoped = fixture::scoped_pool(&pool).await;
    let viewer = epigraph_db::Viewer::resolve(&pool, c.outsider)
        .await
        .expect("viewer");
    break_theme_read(&pool).await;

    let auto = recall_routed(
        &pool,
        &scoped,
        &viewer,
        &embedder(),
        "theme member",
        2,
        0.0,
        RecallRoute::Auto,
    )
    .await
    .expect("Auto must degrade, not error");
    let got = ids(&auto);
    assert_eq!(got.len(), 2, "Auto serves the ANN page: {got:?}");
    assert!(got.contains(&c.ann_a.to_string()), "{got:?}");
    assert!(got.contains(&c.ann_b.to_string()), "{got:?}");
    assert!(auto.iter().all(|r| !r.via_theme_traversal), "{got:?}");

    let hier = recall_routed(
        &pool,
        &scoped,
        &viewer,
        &embedder(),
        "near claim a",
        10,
        0.0,
        RecallRoute::Hierarchical,
    )
    .await
    .expect("Hierarchical must degrade, not error");
    assert_eq!(
        ids(&hier),
        vec![c.ann_a.to_string()],
        "Hierarchical falls back to the text search"
    );
}

/// A query vector at a dimension the theme read does not support (768, not
/// 1536 or 3072) is `InvalidData` from the theme read; Hierarchical, which
/// skips the ANN leg, must degrade to the text search rather than error or
/// serve an empty page. (On Auto and Similarity the 1536-d ANN read rejects
/// the vector first, which is the pre-existing text-fallback path.)
#[sqlx::test(migrations = "../../migrations")]
async fn hierarchical_unsupported_dimension_falls_back_to_text(pool: PgPool) {
    let c = seed(&pool).await;
    let scoped = fixture::scoped_pool(&pool).await;
    let viewer = epigraph_db::Viewer::resolve(&pool, c.outsider)
        .await
        .expect("viewer");
    let narrow = FixedEmbedder(
        vec![0.5f32; 768],
        MockProvider::new(EmbeddingConfig::openai(768)),
    );
    let got = recall_routed(
        &pool,
        &scoped,
        &viewer,
        &narrow,
        "near claim a",
        10,
        0.0,
        RecallRoute::Hierarchical,
    )
    .await
    .expect("an unsupported dimension must degrade, not error");
    assert_eq!(ids(&got), vec![c.ann_a.to_string()]);
    assert!(got.iter().all(|r| !r.via_theme_traversal));
}
