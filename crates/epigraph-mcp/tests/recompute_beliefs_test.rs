//! Behavioral tests for the `recompute_beliefs` CDST-maintenance tool.
//!
//! Setup mirrors `source_strength_tests.rs`: `auto_wire_ds_update` writes a
//! real BBA on the canonical `binary_truth` frame and seeds the cached
//! `claims.pignistic_prob`. We then corrupt the cache and assert the tool
//! restores it (the 50ea636e ingest-initial-asymmetry use case), plus check
//! the target-selection, truncation, and no-BBA-skip reporting.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::types::RecomputeBeliefsParams;
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use rmcp::model::ContentBlock;
use sqlx::PgPool;
use uuid::Uuid;

fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x2bu8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

fn result_json(out: rmcp::model::CallToolResult) -> serde_json::Value {
    let first = out.content.first().cloned().expect("first content");
    let text = match first {
        ContentBlock::Text(t) => t.text,
        other => panic!("expected text content, got {other:?}"),
    };
    serde_json::from_str(&text).expect("result is JSON")
}

async fn insert_agent(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), $1, 'system', ARRAY['test'])
         RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn insert_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, sha256($1::bytea), 0.5, $2, true) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn insert_claim_with_label(pool: &PgPool, agent: Uuid, content: &str, label: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, labels)
         VALUES ($1, sha256($1::bytea), 0.5, $2, true, ARRAY[$3]) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .bind(label)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Give `claim_id` a real binary-frame BBA + cached belief.
async fn wire_bba(pool: &PgPool, claim_id: Uuid, agent_id: Uuid) {
    let viewer = fixture::public_viewer(pool).await;
    tools::ds_auto::auto_wire_ds_update(
        &mut pool.acquire().await.expect("acquire"),
        &viewer,
        claim_id,
        agent_id,
        0.9,  // confidence
        1.0,  // weight
        true, // supports
        Some("empirical"),
        None,  // evidence_id
        false, // seed_truth_prior: direct calls exercise the combine alone
    )
    .await
    .expect("auto_wire_ds_update");
}

async fn pignistic(pool: &PgPool, claim_id: Uuid) -> f64 {
    sqlx::query_scalar::<_, f64>("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Targeting by `claim_ids` restores a deliberately-corrupted cache to the
/// correct combine result and reports accurate counts.
#[sqlx::test(migrations = "../../migrations")]
async fn recompute_claim_ids_restores_stale_cache(pool: PgPool) {
    // recompute_beliefs enumerates via `MassFunctionRepository::list_claim_ids`,
    // whose debug_assert requires a Bypass viewer: a Scoped one would leave every
    // other tenant's cached beliefs stale. Hold the ScopedPool.
    // The tool now takes a MaintenanceSession (batch H1), minted at the call
    // below over this test database: its bypass viewer is what the old
    // `fixture::bypass` supplied here.
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "recompute-stale").await;
    let claim = insert_claim(&pool, agent, &format!("recompute-stale-{}", Uuid::new_v4())).await;
    wire_bba(&pool, claim, agent).await;

    let correct = pignistic(&pool, claim).await;
    // Corrupt the cache to a value the combine path would never produce here.
    sqlx::query("UPDATE claims SET pignistic_prob = 0.123 WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .unwrap();
    assert!((pignistic(&pool, claim).await - 0.123).abs() < 1e-9);

    let out = tools::cdst_maintenance::recompute_beliefs(
        &server,
        &mut fixture::scoped_pool(&pool)
            .await
            .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
            .await
            .expect("a maintenance session over the test database"),
        RecomputeBeliefsParams {
            claim_ids: Some(vec![claim.to_string()]),
            labels: None,
            limit: None,
            offset: None,
        },
    )
    .await
    .expect("recompute_beliefs");

    let j = result_json(out);
    assert_eq!(j["target"], "claim_ids");
    assert_eq!(j["claims_considered"], 1);
    assert_eq!(j["claims_recomputed"], 1);
    assert_eq!(j["claims_skipped_no_bba"], 0);
    assert!(j["frame_writes"].as_u64().unwrap() >= 1);
    assert_eq!(j["truncated"], false);
    assert!(j["errors"].as_array().unwrap().is_empty());

    // Cache is back to the correct combine result, not the corrupted value.
    let restored = pignistic(&pool, claim).await;
    assert!(
        (restored - correct).abs() < 1e-9,
        "expected restored {correct}, got {restored}"
    );
    assert!((restored - 0.123).abs() > 1e-6, "still corrupted");
}

/// A claim with no BBAs is counted as skipped, not recomputed, and is not an error.
#[sqlx::test(migrations = "../../migrations")]
async fn recompute_skips_claim_without_bbas(pool: PgPool) {
    // recompute_beliefs enumerates via `MassFunctionRepository::list_claim_ids`,
    // whose debug_assert requires a Bypass viewer: a Scoped one would leave every
    // other tenant's cached beliefs stale. Hold the ScopedPool.
    // The tool now takes a MaintenanceSession (batch H1), minted at the call
    // below over this test database: its bypass viewer is what the old
    // `fixture::bypass` supplied here.
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "recompute-nobba").await;
    let bare = insert_claim(&pool, agent, &format!("recompute-nobba-{}", Uuid::new_v4())).await;

    let out = tools::cdst_maintenance::recompute_beliefs(
        &server,
        &mut fixture::scoped_pool(&pool)
            .await
            .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
            .await
            .expect("a maintenance session over the test database"),
        RecomputeBeliefsParams {
            claim_ids: Some(vec![bare.to_string()]),
            labels: None,
            limit: None,
            offset: None,
        },
    )
    .await
    .expect("recompute_beliefs");

    let j = result_json(out);
    assert_eq!(j["claims_considered"], 1);
    assert_eq!(j["claims_recomputed"], 0);
    assert_eq!(j["claims_skipped_no_bba"], 1);
    assert_eq!(j["frame_writes"], 0);
    assert!(j["errors"].as_array().unwrap().is_empty());
}

/// The bulk path (no claim_ids/labels) enumerates claims-with-BBAs and sets
/// `truncated=true` when `limit` is smaller than the population.
#[sqlx::test(migrations = "../../migrations")]
async fn recompute_bulk_truncates_at_limit(pool: PgPool) {
    // recompute_beliefs enumerates via `MassFunctionRepository::list_claim_ids`,
    // whose debug_assert requires a Bypass viewer: a Scoped one would leave every
    // other tenant's cached beliefs stale. Hold the ScopedPool.
    // The tool now takes a MaintenanceSession (batch H1), minted at the call
    // below over this test database: its bypass viewer is what the old
    // `fixture::bypass` supplied here.
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "recompute-bulk").await;
    // Two claims with BBAs; ephemeral DB so the bulk population is exactly 2.
    for i in 0..2 {
        let c = insert_claim(
            &pool,
            agent,
            &format!("recompute-bulk-{i}-{}", Uuid::new_v4()),
        )
        .await;
        wire_bba(&pool, c, agent).await;
    }

    let out = tools::cdst_maintenance::recompute_beliefs(
        &server,
        &mut fixture::scoped_pool(&pool)
            .await
            .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
            .await
            .expect("a maintenance session over the test database"),
        RecomputeBeliefsParams {
            claim_ids: None,
            labels: None,
            limit: Some(1),
            offset: None,
        },
    )
    .await
    .expect("recompute_beliefs");

    let j = result_json(out);
    assert_eq!(j["target"], "all_with_bbas");
    assert_eq!(j["claims_considered"], 1, "limit=1 caps the batch");
    assert_eq!(j["truncated"], true, "more claims remain past limit");

    // Page 2 picks up the remaining claim and is not truncated.
    let out2 = tools::cdst_maintenance::recompute_beliefs(
        &server,
        &mut fixture::scoped_pool(&pool)
            .await
            .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
            .await
            .expect("a maintenance session over the test database"),
        RecomputeBeliefsParams {
            claim_ids: None,
            labels: None,
            limit: Some(1),
            offset: Some(1),
        },
    )
    .await
    .expect("recompute_beliefs page 2");
    let j2 = result_json(out2);
    assert_eq!(j2["claims_considered"], 1);
    assert_eq!(j2["truncated"], false, "no claims remain after offset 1");
}

/// The labels path must report `truncated` honestly: true when more labeled
/// claims remain past `limit`, and — critically — false when exactly `limit`
/// claims exist and none remain (the bug the limit+1 fetch fixes).
#[sqlx::test(migrations = "../../migrations")]
async fn recompute_labels_truncation_is_exact(pool: PgPool) {
    // recompute_beliefs enumerates via `MassFunctionRepository::list_claim_ids`,
    // whose debug_assert requires a Bypass viewer: a Scoped one would leave every
    // other tenant's cached beliefs stale. Hold the ScopedPool.
    // The tool now takes a MaintenanceSession (batch H1), minted at the call
    // below over this test database: its bypass viewer is what the old
    // `fixture::bypass` supplied here.
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "recompute-lbl").await;
    let label = format!("rb-lbl-{}", Uuid::new_v4());
    for i in 0..2 {
        let c = insert_claim_with_label(
            &pool,
            agent,
            &format!("recompute-lbl-{i}-{}", Uuid::new_v4()),
            &label,
        )
        .await;
        wire_bba(&pool, c, agent).await;
    }

    // limit=1 over 2 labeled claims → one remains → truncated.
    let out = tools::cdst_maintenance::recompute_beliefs(
        &server,
        &mut fixture::scoped_pool(&pool)
            .await
            .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
            .await
            .expect("a maintenance session over the test database"),
        RecomputeBeliefsParams {
            claim_ids: None,
            labels: Some(vec![label.clone()]),
            limit: Some(1),
            offset: None,
        },
    )
    .await
    .expect("recompute_beliefs labels limit=1");
    let j = result_json(out);
    assert_eq!(j["target"], "labels");
    assert_eq!(j["claims_considered"], 1);
    assert_eq!(j["truncated"], true);

    // limit=2 over exactly 2 labeled claims → none remain → NOT truncated.
    let out2 = tools::cdst_maintenance::recompute_beliefs(
        &server,
        &mut fixture::scoped_pool(&pool)
            .await
            .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
            .await
            .expect("a maintenance session over the test database"),
        RecomputeBeliefsParams {
            claim_ids: None,
            labels: Some(vec![label]),
            limit: Some(2),
            offset: None,
        },
    )
    .await
    .expect("recompute_beliefs labels limit=2");
    let j2 = result_json(out2);
    assert_eq!(j2["claims_considered"], 2);
    assert_eq!(
        j2["truncated"], false,
        "exactly limit claims, none remain — must not false-positive"
    );
}

/// Backlog 696d3a1c: `recompute_beliefs` reverted edge-derived belief.
///
/// The claim hypothesised the edge mass was never persisted, or persisted in a
/// form the enumeration could not read. Neither: it IS persisted on
/// `binary_truth` and it IS read. It is then OVERWRITTEN.
///
/// `recompute_claim_belief_on_frame` persists nothing per-frame — it writes only
/// the five SHARED `claims.{belief, plausibility, mass_on_empty, pignistic_prob,
/// mass_on_missing}` columns. `recompute_beliefs` calls it once per frame the
/// claim has BBAs on, over `list_frames_for_claim`'s `ORDER BY f.name`. So with
/// N frames the cache ends up holding the ALPHABETICALLY LAST frame's numbers.
///
/// `binary_truth` sorts first (b < c < f < p < t), so the edge-derived values it
/// owns are written first and clobbered by every other frame — typically a
/// `paper_validity_*` or `textbook_veracity_*` frame carrying the PRE-EDGE
/// intrinsic assessment. That is exactly the reported symptom: ee862955 reset to
/// "exactly the claim's pre-edge intrinsic BBA", with `errors=[]`.
///
/// Deterministic rather than racy, which makes it worse: it reverts the same way
/// every run.
#[sqlx::test(migrations = "../../migrations")]
async fn recompute_preserves_canonical_frame_belief_across_multiple_frames(pool: PgPool) {
    // Same reason as the sibling tests: recompute_beliefs enumerates via
    // `list_claim_ids`, whose debug_assert requires a Bypass viewer. Hold the
    // ScopedPool for the duration.
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "696d3a1c-multiframe").await;
    let claim = insert_claim(&pool, agent, &format!("696d3a1c-{}", Uuid::new_v4())).await;

    // Canonical binary_truth BBA — this is what the link_epistemic wiring path
    // writes, and what unframed get_belief is documented to serve.
    wire_bba(&pool, claim, agent).await;
    let canonical = pignistic(&pool, claim).await;

    // A second frame whose name sorts AFTER "binary_truth", carrying a clearly
    // different opinion. "zz_" makes the ordering explicit rather than relying on
    // a realistic name that happens to sort later.
    let other_frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, description, hypotheses)
         VALUES ($1, 'sorts after binary_truth', ARRAY['TRUE','FALSE'])
         RETURNING id",
    )
    .bind(format!("zz_other_frame_{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("insert second frame");

    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index)
         VALUES ($1, $2, 0) ON CONFLICT DO NOTHING",
    )
    .bind(claim)
    .bind(other_frame)
    .execute(&pool)
    .await
    .expect("assign claim to second frame");

    let other_agent = insert_agent(&pool, "696d3a1c-other").await;
    sqlx::query(
        "INSERT INTO mass_functions
           (id, claim_id, frame_id, source_agent_id, masses, conflict_k,
            combination_method, source_strength, evidence_type, locality_tag)
         VALUES (gen_random_uuid(), $1, $2, $3, '{\"1\":0.85,\"0,1\":0.15}'::jsonb,
                 0.0, 'auto_wire', 0.9, 'empirical', 'intra_self_cite')",
    )
    .bind(claim)
    .bind(other_frame)
    .bind(other_agent)
    .execute(&pool)
    .await
    .expect("insert second-frame BBA");

    let out = tools::cdst_maintenance::recompute_beliefs(
        &server,
        &mut fixture::scoped_pool(&pool)
            .await
            .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
            .await
            .expect("a maintenance session over the test database"),
        RecomputeBeliefsParams {
            claim_ids: Some(vec![claim.to_string()]),
            labels: None,
            limit: None,
            offset: None,
        },
    )
    .await
    .expect("recompute_beliefs");
    let json = result_json(out);

    assert_eq!(
        json["errors"].as_array().map(Vec::len),
        Some(0),
        "the clobber is the happy path — it must not be masked by an error: {json}"
    );

    let after = pignistic(&pool, claim).await;
    assert!(
        (after - canonical).abs() < 1e-9,
        "recompute_beliefs must leave the canonical binary_truth belief intact, \
         not overwrite it with a non-canonical frame's opinion. \
         canonical(binary_truth)={canonical}, after recompute={after}. \
         The second frame sorts after 'binary_truth' and won the shared \
         claims.pignistic_prob cache — this is backlog 696d3a1c, and it is what \
         silently reverts every contradicts/refutes edge written since the last \
         recompute."
    );

    // The cache must also SAY which frame it summarizes. `claims` carries six
    // belief columns and, before migration 092, no frame reference — so the number
    // looked authoritative while silently describing one of N contexts. Multi-frame
    // claims are intended (claim_frames is PK (claim_id, frame_id)), which is
    // exactly why the cache has to be self-describing.
    let cached_frame: Option<Uuid> =
        sqlx::query_scalar("SELECT belief_frame_id FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("belief_frame_id");
    let binary = epigraph_engine::edge_factor::ensure_binary_frame(
        &mut pool.acquire().await.expect("acquire"),
        &viewer,
    )
    .await
    .expect("ensure_binary_frame");
    assert_eq!(
        cached_frame,
        Some(binary),
        "claims.belief_frame_id must name the frame the cached scalars summarize, \
         so a reader can tell which context the number describes"
    );
}

// ---------------------------------------------------------------------------
// Cache-owner selection.
//
// `claims.{belief, plausibility, pignistic_prob, ...}` summarize exactly ONE
// frame's combination, recorded in `claims.belief_frame_id`. Among the frames
// holding the claim's combine inputs (cached combination rows excluded):
//
//   1. `binary_truth`, when the claim has an input on it;
//   2. else `claim_validity`, when the claim has an input on it;
//   3. else the recorded owner (`claims.belief_frame_id`), while it still holds
//      an input;
//   4. else the first-writer frame: the frame holding the claim's earliest
//      input (`mass_functions.created_at`), ties broken by frame id.
//
// Frame names play no other part. Wherever name order could stand in for the
// rule, the tests use three frames and give the expected owner the MIDDLE name,
// so neither ascending nor descending name order picks it. Resolving the owner
// is a read: the recompute must not create frames.
// ---------------------------------------------------------------------------

/// A support-leaning BBA (mass on TRUE).
const SUPPORTS: &str = r#"{"0":0.9,"0,1":0.1}"#;
/// A refute-leaning BBA (mass on FALSE), so the two opinions are far apart.
const REFUTES: &str = r#"{"1":0.85,"0,1":0.15}"#;

/// Insert a two-hypothesis frame, with an explicit id when one is given.
///
/// `claim_validity` is never inserted: migration 154 seeds the canonical row
/// (`8a594393`, `frames.name` is UNIQUE) on every database, so the helper
/// returns that row, as assess itself resolves it.
async fn insert_frame(pool: &PgPool, id: Option<Uuid>, name: &str) -> Uuid {
    if name == "claim_validity" {
        assert!(id.is_none(), "claim_validity is the seeded canonical row");
        return sqlx::query_scalar("SELECT id FROM frames WHERE name = 'claim_validity'")
            .fetch_one(pool)
            .await
            .expect("migration 154's canonical claim_validity row");
    }
    sqlx::query_scalar(
        "INSERT INTO frames (id, name, description, hypotheses)
         VALUES (COALESCE($1, gen_random_uuid()), $2, 'cache-owner test frame',
                 ARRAY['TRUE','FALSE'])
         RETURNING id",
    )
    .bind(id)
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("insert frame")
}

async fn assign_claim_to_frame(pool: &PgPool, claim: Uuid, frame: Uuid) {
    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index)
         VALUES ($1, $2, 0) ON CONFLICT DO NOTHING",
    )
    .bind(claim)
    .bind(frame)
    .execute(pool)
    .await
    .expect("assign claim to frame");
}

/// Assign `claim` to `frame` (hypothesis 0) and store one input BBA there with
/// an explicit `created_at`, so which input is the claim's earliest is fixed by
/// the test rather than by statement timing. Returns the row id.
async fn insert_bba_at(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    source: Uuid,
    masses: &str,
    created_at: &str,
) -> Uuid {
    assign_claim_to_frame(pool, claim, frame).await;
    sqlx::query_scalar(
        "INSERT INTO mass_functions
           (id, claim_id, frame_id, source_agent_id, masses, conflict_k,
            combination_method, source_strength, evidence_type, locality_tag, created_at)
         VALUES (gen_random_uuid(), $1, $2, $3, $4::jsonb, 0.0, 'auto_wire', 0.9,
                 'empirical', 'unknown', $5::timestamptz)
         RETURNING id",
    )
    .bind(claim)
    .bind(frame)
    .bind(source)
    .bind(masses)
    .bind(created_at)
    .fetch_one(pool)
    .await
    .expect("insert BBA")
}

/// Store a cached combination row (no source agent, no perspective, a
/// combination label: the shape `assess` / REST `submit_evidence` store after
/// folding). It is derived from the inputs beside it, not an input.
async fn insert_cached_row_at(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    masses: &str,
    created_at: &str,
) {
    assign_claim_to_frame(pool, claim, frame).await;
    sqlx::query(
        "INSERT INTO mass_functions
           (id, claim_id, frame_id, source_agent_id, perspective_id, masses, conflict_k,
            combination_method, locality_tag, created_at)
         VALUES (gen_random_uuid(), $1, $2, NULL, NULL, $3::jsonb, 0.0, 'Dempster',
                 'unknown', $4::timestamptz)",
    )
    .bind(claim)
    .bind(frame)
    .bind(masses)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("insert cached combination row");
}

async fn row_created_at(pool: &PgPool, row: Uuid) -> chrono::DateTime<chrono::Utc> {
    sqlx::query_scalar("SELECT created_at FROM mass_functions WHERE id = $1")
        .bind(row)
        .fetch_one(pool)
        .await
        .expect("mass_functions.created_at")
}

/// Run `recompute_beliefs` on one claim through a maintenance session, and
/// require that it reported no errors and wrote the claim's cache.
async fn recompute_one(pool: &PgPool, claim: Uuid) -> serde_json::Value {
    let server = make_server(pool.clone());
    let out = tools::cdst_maintenance::recompute_beliefs(
        &server,
        &mut fixture::scoped_pool(pool)
            .await
            .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
            .await
            .expect("a maintenance session over the test database"),
        RecomputeBeliefsParams {
            claim_ids: Some(vec![claim.to_string()]),
            labels: None,
            limit: None,
            offset: None,
        },
    )
    .await
    .expect("recompute_beliefs");
    let json = result_json(out);
    assert_eq!(
        json["errors"].as_array().map(Vec::len),
        Some(0),
        "recompute_beliefs must not report errors: {json}"
    );
    assert_eq!(json["claims_recomputed"], 1, "{json}");
    json
}

async fn cache_owner(pool: &PgPool, claim: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT belief_frame_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("belief_frame_id")
}

async fn frame_named(pool: &PgPool, name: &str) -> Option<Uuid> {
    sqlx::query_scalar("SELECT id FROM frames WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
        .expect("frame by name")
}

async fn frame_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM frames")
        .fetch_one(pool)
        .await
        .expect("frame count")
}

/// The pignistic probability the combine pipeline produces on `frame` alone,
/// computed without writing: what the cache must hold when `frame` owns it.
async fn pignistic_on_frame(pool: &PgPool, claim: Uuid, frame: Uuid) -> f64 {
    let (_scoped, viewer) = fixture::bypass(pool).await;
    epigraph_engine::edge_factor::preview_claim_belief_on_frame(
        &mut pool.acquire().await.expect("acquire"),
        &viewer,
        claim,
        frame,
    )
    .await
    .expect("preview")
    .expect("the claim has inputs on the frame")
    .pignistic_prob
}

/// Assert `frame` owns the claim's cache: `belief_frame_id` names it and the
/// cached pignistic probability is its combination.
async fn assert_owner(pool: &PgPool, claim: Uuid, frame: Uuid, what: &str) {
    let owner = cache_owner(pool, claim).await;
    assert_eq!(
        owner,
        Some(frame),
        "{what}: expected owner {frame}, got {owner:?}"
    );
    let expected = pignistic_on_frame(pool, claim, frame).await;
    let cached = pignistic(pool, claim).await;
    assert!(
        (cached - expected).abs() < 1e-9,
        "{what}: the cached belief must be the owner's combination: \
         expected {expected}, cached {cached}"
    );
}

/// Write `frame`'s combination into the claim's cache the way the direct
/// write paths do (`submit_ds_evidence` recomputes on the frame it just wrote),
/// which records `frame` as the cache owner.
async fn record_owner_via_direct_write(pool: &PgPool, claim: Uuid, frame: Uuid) {
    let (_scoped, viewer) = fixture::bypass(pool).await;
    let wrote = epigraph_engine::edge_factor::recompute_claim_belief_on_frame(
        &mut pool.acquire().await.expect("acquire"),
        &viewer,
        claim,
        frame,
    )
    .await
    .expect("direct write");
    assert!(wrote, "the claim has inputs on {frame}");
    assert_eq!(cache_owner(pool, claim).await, Some(frame));
}

/// With no canonical frame and no recorded owner, the frame holding the claim's
/// earliest input owns the cache. Expected owner `mmm_first` (earliest input) has
/// the middle name: `aaa_later` and `zzz_later` hold later inputs.
#[sqlx::test(migrations = "../../migrations")]
async fn cache_owner_is_the_first_writer_frame(pool: PgPool) {
    let agent = insert_agent(&pool, "cache-owner-first-writer").await;
    let source = insert_agent(&pool, "cache-owner-first-writer-source").await;
    let claim = insert_claim(&pool, agent, &format!("cache-owner-fw-{}", Uuid::new_v4())).await;

    let first = insert_frame(&pool, None, "mmm_first").await;
    let aaa = insert_frame(&pool, None, "aaa_later").await;
    let zzz = insert_frame(&pool, None, "zzz_later").await;
    insert_bba_at(
        &pool,
        claim,
        first,
        source,
        SUPPORTS,
        "2026-01-01T00:00:00Z",
    )
    .await;
    insert_bba_at(&pool, claim, aaa, source, REFUTES, "2026-01-02T00:00:00Z").await;
    insert_bba_at(&pool, claim, zzz, source, REFUTES, "2026-01-03T00:00:00Z").await;

    recompute_one(&pool, claim).await;
    assert_owner(
        &pool,
        claim,
        first,
        &format!("first-writer mmm_first (aaa_later {aaa}, zzz_later {zzz})"),
    )
    .await;
}

/// A `binary_truth` input makes `binary_truth` the owner whatever other frames
/// the claim carries and whenever their inputs were written.
#[sqlx::test(migrations = "../../migrations")]
async fn cache_owner_is_binary_truth_when_the_claim_has_a_binary_truth_bba(pool: PgPool) {
    let agent = insert_agent(&pool, "cache-owner-binary").await;
    let source = insert_agent(&pool, "cache-owner-binary-source").await;
    let claim = insert_claim(&pool, agent, &format!("cache-owner-bt-{}", Uuid::new_v4())).await;

    // Earlier inputs on an ordinary frame and on claim_validity ...
    let ordinary = insert_frame(&pool, None, "aaa_ordinary").await;
    insert_bba_at(
        &pool,
        claim,
        ordinary,
        source,
        REFUTES,
        "2026-01-01T00:00:00Z",
    )
    .await;
    let validity = insert_frame(&pool, None, "claim_validity").await;
    insert_bba_at(
        &pool,
        claim,
        validity,
        source,
        REFUTES,
        "2026-01-01T01:00:00Z",
    )
    .await;
    // ... the binary_truth input (written now) ...
    wire_bba(&pool, claim, agent).await;
    let binary = frame_named(&pool, "binary_truth")
        .await
        .expect("wire_bba materializes binary_truth");
    // ... and a later one on a frame whose name sorts last.
    let later = insert_frame(&pool, None, "zzz_later").await;
    insert_bba_at(&pool, claim, later, source, REFUTES, "2100-01-01T00:00:00Z").await;

    recompute_one(&pool, claim).await;
    assert_owner(
        &pool,
        claim,
        binary,
        &format!("binary_truth (ordinary {ordinary}, claim_validity {validity}, later {later})"),
    )
    .await;
}

/// Without a `binary_truth` input, `claim_validity` owns the cache even though an
/// ordinary frame wrote the claim's earliest input. `aaa_early` (earliest,
/// sorts before `claim_validity`) and `zzz_late` (written last, sorts after it)
/// make ascending name order, descending name order and first-writer each pick
/// a different, wrong frame.
#[sqlx::test(migrations = "../../migrations")]
async fn cache_owner_prefers_claim_validity_over_an_earlier_ordinary_frame(pool: PgPool) {
    let agent = insert_agent(&pool, "cache-owner-validity").await;
    let source = insert_agent(&pool, "cache-owner-validity-source").await;
    let claim = insert_claim(&pool, agent, &format!("cache-owner-cv-{}", Uuid::new_v4())).await;

    let early = insert_frame(&pool, None, "aaa_early").await;
    let validity = insert_frame(&pool, None, "claim_validity").await;
    let late = insert_frame(&pool, None, "zzz_late").await;
    insert_bba_at(&pool, claim, early, source, REFUTES, "2026-01-01T00:00:00Z").await;
    insert_bba_at(
        &pool,
        claim,
        validity,
        source,
        SUPPORTS,
        "2026-01-02T00:00:00Z",
    )
    .await;
    insert_bba_at(&pool, claim, late, source, REFUTES, "2026-01-03T00:00:00Z").await;

    recompute_one(&pool, claim).await;
    assert_owner(
        &pool,
        claim,
        validity,
        &format!("claim_validity (aaa_early {early}, zzz_late {late})"),
    )
    .await;
}

/// Three frames whose inputs share one timestamp: the lowest frame id owns the
/// cache. Ids `…a1` / `…b2` / `…c3` are named `mm_` / `aa_` / `zz_`, so only
/// ascending id order picks `…a1`; ascending name order picks `…b2` and
/// descending name order picks `…c3`.
#[sqlx::test(migrations = "../../migrations")]
async fn cache_owner_tie_breaks_on_frame_id(pool: PgPool) {
    let agent = insert_agent(&pool, "cache-owner-tie").await;
    let source = insert_agent(&pool, "cache-owner-tie-source").await;
    let claim = insert_claim(&pool, agent, &format!("cache-owner-tie-{}", Uuid::new_v4())).await;

    let id = |s: &str| Uuid::parse_str(s).unwrap();
    let a1 = insert_frame(
        &pool,
        Some(id("00000000-0000-4000-8000-0000000000a1")),
        "mm_tie",
    )
    .await;
    let b2 = insert_frame(
        &pool,
        Some(id("00000000-0000-4000-8000-0000000000b2")),
        "aa_tie",
    )
    .await;
    let c3 = insert_frame(
        &pool,
        Some(id("00000000-0000-4000-8000-0000000000c3")),
        "zz_tie",
    )
    .await;
    for (frame, masses) in [(c3, REFUTES), (b2, REFUTES), (a1, SUPPORTS)] {
        insert_bba_at(&pool, claim, frame, source, masses, "2026-01-01T00:00:00Z").await;
    }

    recompute_one(&pool, claim).await;
    assert_owner(
        &pool,
        claim,
        a1,
        &format!("lowest frame id on an equal timestamp (b2 {b2}, c3 {c3})"),
    )
    .await;
}

/// Resolving the owner is a read. A recompute over a claim whose inputs are all
/// on an ordinary frame must leave the frames table exactly as it found it; in
/// particular it must not create `binary_truth`.
#[sqlx::test(migrations = "../../migrations")]
async fn cache_owner_recompute_creates_no_frames(pool: PgPool) {
    let agent = insert_agent(&pool, "cache-owner-readonly").await;
    let source = insert_agent(&pool, "cache-owner-readonly-source").await;
    let claim = insert_claim(&pool, agent, &format!("cache-owner-ro-{}", Uuid::new_v4())).await;

    let ordinary = insert_frame(&pool, None, "aaa_ordinary").await;
    insert_bba_at(
        &pool,
        claim,
        ordinary,
        source,
        SUPPORTS,
        "2026-01-01T00:00:00Z",
    )
    .await;
    assert_eq!(
        frame_named(&pool, "binary_truth").await,
        None,
        "precondition: no binary_truth frame exists"
    );
    let frames_before = frame_count(&pool).await;

    recompute_one(&pool, claim).await;

    assert_eq!(
        frame_named(&pool, "binary_truth").await,
        None,
        "the recompute must not create a binary_truth frame"
    );
    assert_eq!(
        frame_count(&pool).await,
        frames_before,
        "the recompute must not create any frame"
    );
    assert_eq!(cache_owner(&pool, claim).await, Some(ordinary));
}

/// A cached combination row is not an input, so it cannot make its frame the
/// owner. The claim's earliest row is a cached row on `zzz_cached_only`, which
/// holds no input; the owner is `aaa_input`, and the cache is written from it.
#[sqlx::test(migrations = "../../migrations")]
async fn cache_owner_ignores_cached_combination_rows(pool: PgPool) {
    let agent = insert_agent(&pool, "cache-owner-cached-row").await;
    let source = insert_agent(&pool, "cache-owner-cached-row-source").await;
    let claim = insert_claim(&pool, agent, &format!("cache-owner-cc-{}", Uuid::new_v4())).await;

    let cached_only = insert_frame(&pool, None, "zzz_cached_only").await;
    insert_cached_row_at(&pool, claim, cached_only, REFUTES, "2026-01-01T00:00:00Z").await;
    let input = insert_frame(&pool, None, "aaa_input").await;
    insert_bba_at(
        &pool,
        claim,
        input,
        source,
        SUPPORTS,
        "2026-01-02T00:00:00Z",
    )
    .await;

    recompute_one(&pool, claim).await;
    assert_owner(
        &pool,
        claim,
        input,
        &format!("the frame holding the only input (cached-only frame {cached_only})"),
    )
    .await;
}

/// A frame's position is set by its earliest INPUT, not by an earlier cached row.
/// `zzz_cached_then_input` has a cached row first and its input third;
/// `mmm_input` (middle name) has its input second; `aaa_late` last.
#[sqlx::test(migrations = "../../migrations")]
async fn cache_owner_orders_frames_by_their_earliest_input(pool: PgPool) {
    let agent = insert_agent(&pool, "cache-owner-earliest-input").await;
    let source = insert_agent(&pool, "cache-owner-earliest-input-source").await;
    let claim = insert_claim(&pool, agent, &format!("cache-owner-ei-{}", Uuid::new_v4())).await;

    let cached_first = insert_frame(&pool, None, "zzz_cached_then_input").await;
    let middle = insert_frame(&pool, None, "mmm_input").await;
    let late = insert_frame(&pool, None, "aaa_late").await;
    insert_cached_row_at(&pool, claim, cached_first, REFUTES, "2026-01-01T00:00:00Z").await;
    insert_bba_at(
        &pool,
        claim,
        middle,
        source,
        SUPPORTS,
        "2026-01-02T00:00:00Z",
    )
    .await;
    insert_bba_at(
        &pool,
        claim,
        cached_first,
        source,
        REFUTES,
        "2026-01-03T00:00:00Z",
    )
    .await;
    insert_bba_at(&pool, claim, late, source, REFUTES, "2026-01-04T00:00:00Z").await;

    recompute_one(&pool, claim).await;
    assert_owner(
        &pool,
        claim,
        middle,
        &format!("earliest input mmm_input (cached-then-input {cached_first}, aaa_late {late})"),
    )
    .await;
}

/// `binary_truth` outranks the other frames only when the claim has an INPUT on
/// it. Here it holds only a cached row, so `claim_validity` owns the cache.
#[sqlx::test(migrations = "../../migrations")]
async fn cache_owner_skips_binary_truth_holding_only_a_cached_row(pool: PgPool) {
    let agent = insert_agent(&pool, "cache-owner-bt-cached").await;
    let source = insert_agent(&pool, "cache-owner-bt-cached-source").await;
    let claim = insert_claim(&pool, agent, &format!("cache-owner-btc-{}", Uuid::new_v4())).await;

    let binary = insert_frame(&pool, None, "binary_truth").await;
    insert_cached_row_at(&pool, claim, binary, REFUTES, "2026-01-01T00:00:00Z").await;
    let validity = insert_frame(&pool, None, "claim_validity").await;
    insert_bba_at(
        &pool,
        claim,
        validity,
        source,
        SUPPORTS,
        "2026-01-02T00:00:00Z",
    )
    .await;
    let late = insert_frame(&pool, None, "zzz_late").await;
    insert_bba_at(&pool, claim, late, source, REFUTES, "2026-01-03T00:00:00Z").await;

    recompute_one(&pool, claim).await;
    assert_owner(
        &pool,
        claim,
        validity,
        &format!("claim_validity (binary_truth {binary} holds only a cached row)"),
    )
    .await;
}

/// Replacing a BBA resets its `created_at` (the
/// `MassFunctionRepository::store_with_perspective` upsert), which moves its
/// frame behind the others in write order. The recorded owner keeps the cache
/// anyway while it still holds an input.
#[sqlx::test(migrations = "../../migrations")]
async fn cache_owner_recorded_owner_survives_a_replaced_bba(pool: PgPool) {
    let agent = insert_agent(&pool, "cache-owner-replace").await;
    let writer_x = insert_agent(&pool, "cache-owner-replace-x").await;
    let writer_y = insert_agent(&pool, "cache-owner-replace-y").await;
    let claim = insert_claim(&pool, agent, &format!("cache-owner-rp-{}", Uuid::new_v4())).await;

    let a = insert_frame(&pool, None, "mmm_recorded").await;
    let b = insert_frame(&pool, None, "zzz_other").await;
    let c = insert_frame(&pool, None, "aaa_other").await;
    let a_row = insert_bba_at(&pool, claim, a, writer_x, SUPPORTS, "2026-01-01T00:00:00Z").await;
    let b_row = insert_bba_at(&pool, claim, b, writer_y, REFUTES, "2026-01-02T00:00:00Z").await;
    insert_bba_at(&pool, claim, c, writer_y, REFUTES, "2026-01-03T00:00:00Z").await;

    recompute_one(&pool, claim).await;
    assert_owner(
        &pool,
        claim,
        a,
        "first recompute: first-writer mmm_recorded",
    )
    .await;

    // X replaces its own BBA on A through the real store path.
    let replaced = epigraph_db::MassFunctionRepository::store_with_perspective(
        &pool,
        claim,
        a,
        Some(writer_x),
        None,
        &serde_json::from_str::<serde_json::Value>(r#"{"0":0.6,"0,1":0.4}"#).unwrap(),
        None,
        None,
        Some(0.9),
        Some("empirical"),
        "unknown",
        None,
    )
    .await
    .expect("store_with_perspective");
    assert_eq!(
        replaced, a_row,
        "the store must REPLACE X's row on A, not add one"
    );
    assert!(
        row_created_at(&pool, a_row).await > row_created_at(&pool, b_row).await,
        "precondition: the replace moved A's input after B's in write order"
    );

    recompute_one(&pool, claim).await;
    assert_owner(
        &pool,
        claim,
        a,
        &format!("recorded owner mmm_recorded after the replace (zzz_other {b}, aaa_other {c})"),
    )
    .await;
}

/// A recorded owner that no longer holds an input (its only input was deleted)
/// does not keep the cache: ownership falls through to the first-writer frame
/// among the rest, `mmm_next` (middle name among the remaining frames).
#[sqlx::test(migrations = "../../migrations")]
async fn cache_owner_unbacked_recorded_owner_falls_through_to_first_writer(pool: PgPool) {
    let agent = insert_agent(&pool, "cache-owner-unbacked").await;
    let source = insert_agent(&pool, "cache-owner-unbacked-source").await;
    let claim = insert_claim(&pool, agent, &format!("cache-owner-ub-{}", Uuid::new_v4())).await;

    let recorded = insert_frame(&pool, None, "ccc_recorded").await;
    let next = insert_frame(&pool, None, "mmm_next").await;
    let aaa = insert_frame(&pool, None, "aaa_last").await;
    let zzz = insert_frame(&pool, None, "zzz_late").await;
    let recorded_row = insert_bba_at(
        &pool,
        claim,
        recorded,
        source,
        REFUTES,
        "2026-01-01T00:00:00Z",
    )
    .await;
    insert_bba_at(&pool, claim, next, source, SUPPORTS, "2026-01-02T00:00:00Z").await;
    insert_bba_at(&pool, claim, aaa, source, REFUTES, "2026-01-03T00:00:00Z").await;
    insert_bba_at(&pool, claim, zzz, source, REFUTES, "2026-01-04T00:00:00Z").await;

    recompute_one(&pool, claim).await;
    assert_owner(
        &pool,
        claim,
        recorded,
        "first recompute: first-writer ccc_recorded",
    )
    .await;

    sqlx::query("DELETE FROM mass_functions WHERE id = $1")
        .bind(recorded_row)
        .execute(&pool)
        .await
        .expect("delete the recorded owner's only input");

    recompute_one(&pool, claim).await;
    assert_owner(
        &pool,
        claim,
        next,
        &format!("first-writer mmm_next once ccc_recorded {recorded} holds no input (aaa {aaa}, zzz {zzz})"),
    )
    .await;
}

/// A recorded owner that is NOT the first writer (a direct write path recorded
/// it) keeps the cache when another agent later writes the claim's first BBA on
/// a new frame. `mmm_recorded` has the middle name; `aaa_first` holds the
/// earliest input and `zzz_new` the newest.
#[sqlx::test(migrations = "../../migrations")]
async fn cache_owner_recorded_owner_survives_another_agents_new_frame(pool: PgPool) {
    let agent = insert_agent(&pool, "cache-owner-recorded").await;
    let source = insert_agent(&pool, "cache-owner-recorded-source").await;
    let other = insert_agent(&pool, "cache-owner-recorded-other").await;
    let claim = insert_claim(&pool, agent, &format!("cache-owner-rc-{}", Uuid::new_v4())).await;

    let first = insert_frame(&pool, None, "aaa_first").await;
    let recorded = insert_frame(&pool, None, "mmm_recorded").await;
    insert_bba_at(&pool, claim, first, source, REFUTES, "2026-01-01T00:00:00Z").await;
    insert_bba_at(
        &pool,
        claim,
        recorded,
        source,
        SUPPORTS,
        "2026-01-02T00:00:00Z",
    )
    .await;
    record_owner_via_direct_write(&pool, claim, recorded).await;

    // Another agent writes a BBA on a newly created frame.
    let new = insert_frame(&pool, None, "zzz_new").await;
    assign_claim_to_frame(&pool, claim, new).await;
    epigraph_db::MassFunctionRepository::store_with_perspective(
        &pool,
        claim,
        new,
        Some(other),
        None,
        &serde_json::from_str::<serde_json::Value>(REFUTES).unwrap(),
        None,
        None,
        Some(0.9),
        Some("empirical"),
        "unknown",
        None,
    )
    .await
    .expect("store_with_perspective");

    recompute_one(&pool, claim).await;
    assert_owner(
        &pool,
        claim,
        recorded,
        &format!("recorded owner mmm_recorded (aaa_first {first}, zzz_new {new})"),
    )
    .await;
}

/// The canonical frames outrank a recorded owner: a claim whose cache is owned by
/// an ordinary frame moves to `claim_validity` once it has an input there.
#[sqlx::test(migrations = "../../migrations")]
async fn cache_owner_canonical_frame_outranks_the_recorded_owner(pool: PgPool) {
    let agent = insert_agent(&pool, "cache-owner-canonical").await;
    let source = insert_agent(&pool, "cache-owner-canonical-source").await;
    let claim = insert_claim(&pool, agent, &format!("cache-owner-co-{}", Uuid::new_v4())).await;

    let recorded = insert_frame(&pool, None, "mmm_recorded").await;
    let aaa = insert_frame(&pool, None, "aaa_other").await;
    let zzz = insert_frame(&pool, None, "zzz_other").await;
    insert_bba_at(
        &pool,
        claim,
        recorded,
        source,
        REFUTES,
        "2026-01-01T00:00:00Z",
    )
    .await;
    insert_bba_at(&pool, claim, aaa, source, REFUTES, "2026-01-02T00:00:00Z").await;
    insert_bba_at(&pool, claim, zzz, source, REFUTES, "2026-01-03T00:00:00Z").await;
    recompute_one(&pool, claim).await;
    assert_owner(
        &pool,
        claim,
        recorded,
        "first recompute: first-writer mmm_recorded",
    )
    .await;

    let validity = insert_frame(&pool, None, "claim_validity").await;
    insert_bba_at(
        &pool,
        claim,
        validity,
        source,
        SUPPORTS,
        "2026-01-04T00:00:00Z",
    )
    .await;
    recompute_one(&pool, claim).await;
    assert_owner(
        &pool,
        claim,
        validity,
        &format!("claim_validity over the recorded owner {recorded}"),
    )
    .await;
}
