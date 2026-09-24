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
use rmcp::model::RawContent;
use sqlx::PgPool;
use uuid::Uuid;

fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x2bu8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

fn result_json(out: rmcp::model::CallToolResult) -> serde_json::Value {
    let first = out.content.first().cloned().expect("first content");
    let text = match first.raw {
        RawContent::Text(t) => t.text,
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
        None, // evidence_id
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
    let (_scoped, viewer) = fixture::bypass(&pool).await;
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
        &viewer,
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
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "recompute-nobba").await;
    let bare = insert_claim(&pool, agent, &format!("recompute-nobba-{}", Uuid::new_v4())).await;

    let out = tools::cdst_maintenance::recompute_beliefs(
        &server,
        &viewer,
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
    let (_scoped, viewer) = fixture::bypass(&pool).await;
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
        &viewer,
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
        &viewer,
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
    let (_scoped, viewer) = fixture::bypass(&pool).await;
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
        &viewer,
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
        &viewer,
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
        &viewer,
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
