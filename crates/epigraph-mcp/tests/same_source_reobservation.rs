//! Backlog 4c42c0bf: a re-worded re-observation of the SAME source by the SAME
//! agent must not count as independent corroboration.
//!
//! `update_with_evidence` refuses only a byte-identical `evidence_data`
//! (`evidence_content_hash_claim_unique`), so a weekly "still listed, nothing
//! changed" re-sighting of one web page adds a fresh BBA. Before this fix both
//! the write path (`ds_auto::auto_wire_ds_update`) and the recompute path
//! (`edge_factor::compute_combined_belief`) Dempster-folded every BBA as an
//! independent source, so each repeat raised BetP (0.672 -> 0.768 on claim
//! fc5e6a60). The fix folds BBAs that share (source agent, evidence
//! `source_url`) with the cautious rule first, which is idempotent: N copies of
//! one source's verdict carry exactly the weight of one.
//!
//! The controls pin what must NOT change: a different `source_url` is a
//! different source and still corroborates, and evidence with no `source_url`
//! (the shape `report_workflow_outcome`'s repeated execution reports take) still
//! accumulates as before.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_mcp::types::UpdateWithEvidenceParams;
use sqlx::PgPool;
use uuid::Uuid;

const PAGE: &str = "https://example.org/rfp/sierra-vista-es";

async fn observe(
    server: &epigraph_mcp::EpiGraphMcpFull,
    pool: &PgPool,
    claim_id: Uuid,
    data: &str,
    source_url: Option<&str>,
) -> f64 {
    observe_verdict(server, pool, claim_id, data, source_url, true).await
}

async fn observe_verdict(
    server: &epigraph_mcp::EpiGraphMcpFull,
    pool: &PgPool,
    claim_id: Uuid,
    data: &str,
    source_url: Option<&str>,
    supports: bool,
) -> f64 {
    let viewer = fixture::public_viewer(pool).await;
    epigraph_mcp::tools::claims::update_with_evidence(
        server,
        &viewer,
        UpdateWithEvidenceParams {
            canonical_name: None,
            step_index: None,
            claim_id: claim_id.to_string(),
            evidence_type: "empirical".into(),
            evidence_data: data.into(),
            source_url: source_url.map(String::from),
            supports,
            strength: 0.8,
            labels: vec![],
        },
        None,
    )
    .await
    .expect("update_with_evidence");
    pignistic(pool, claim_id).await
}

async fn pignistic(pool: &PgPool, claim_id: Uuid) -> f64 {
    sqlx::query_scalar::<_, Option<f64>>("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("read pignistic_prob")
        .expect("pignistic_prob written by the DS wiring")
}

async fn setup(pool: &PgPool, tag: &str) -> (epigraph_mcp::EpiGraphMcpFull, Uuid) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(pool).await);
    let claim = seed_claim(pool, &format!("X09 {tag} {}", Uuid::new_v4()), 0.5).await;
    (server, claim)
}

/// The defect. Four re-worded "still listed, unchanged" observations of one
/// page by one agent leave BetP where the first observation put it.
#[sqlx::test(migrations = "../../migrations")]
async fn same_source_reobservations_do_not_raise_betp(pool: PgPool) {
    let (server, claim) = setup(&pool, "same-source").await;

    let first = observe(
        &server,
        &pool,
        claim,
        "Listed; 3 addenda; no due date.",
        Some(PAGE),
    )
    .await;
    assert!(
        first > 0.5,
        "precondition: one supporting observation must move BetP above 0.5, got {first}"
    );

    let mut last = first;
    for (i, data) in [
        "Still listed, due date still not shown.",
        "Re-checked: listing unchanged, three addenda.",
        "Weekly re-sighting: no change on the page.",
    ]
    .iter()
    .enumerate()
    {
        last = observe(&server, &pool, claim, data, Some(PAGE)).await;
        assert!(
            last <= first + 1e-9,
            "re-observation #{} of the SAME source raised BetP {first} -> {last}: \
             a repeat of one source was combined as independent corroboration",
            i + 2
        );
    }
    assert!(
        (last - first).abs() < 1e-9,
        "N copies of one source must carry exactly one copy's weight: {first} vs {last}"
    );
}

/// Positive control: the same agent reading a DIFFERENT page is a second
/// source and must still corroborate. Without this, a fix that stopped all
/// accumulation would pass the test above.
#[sqlx::test(migrations = "../../migrations")]
async fn distinct_sources_still_corroborate(pool: PgPool) {
    let (server, claim) = setup(&pool, "distinct-sources").await;

    let first = observe(
        &server,
        &pool,
        claim,
        "Listed on the district page.",
        Some(PAGE),
    )
    .await;
    let second = observe(
        &server,
        &pool,
        claim,
        "Also listed on the county aggregator.",
        Some("https://aggregator.example.net/listing/42"),
    )
    .await;
    assert!(
        second > first + 1e-6,
        "an observation of a DIFFERENT source must still raise BetP: {first} -> {second}"
    );
}

/// Regression guard for evidence with no `source_url` — the shape every
/// `report_workflow_outcome` execution report takes through the same
/// `auto_wire_ds_update`. Repeated reports are distinct trials and must keep
/// accumulating; the source key is the URL, never the agent alone.
#[sqlx::test(migrations = "../../migrations")]
async fn evidence_without_source_url_still_accumulates(pool: PgPool) {
    let (server, claim) = setup(&pool, "no-url").await;

    let first = observe(&server, &pool, claim, "Execution 1 succeeded.", None).await;
    let second = observe(&server, &pool, claim, "Execution 2 succeeded.", None).await;
    assert!(
        second > first + 1e-6,
        "two URL-less observations by one agent must still accumulate: {first} -> {second}"
    );
}

/// The recompute path must agree with the write path. Otherwise the next
/// `recompute_beliefs` (or any edge-triggered recompute) folds the repeats as
/// independent again and re-inflates the cache the write path left honest.
#[sqlx::test(migrations = "../../migrations")]
async fn recompute_does_not_reinflate_same_source_repeats(pool: PgPool) {
    let (server, claim) = setup(&pool, "recompute").await;

    let first = observe(&server, &pool, claim, "Listed, no due date.", Some(PAGE)).await;
    observe(
        &server,
        &pool,
        claim,
        "Still listed, unchanged.",
        Some(PAGE),
    )
    .await;
    observe(&server, &pool, claim, "Unchanged again.", Some(PAGE)).await;

    // Clear the cache so the monotonicity clamp in the write path cannot be
    // what holds the value: only the recompute's own combine is measured.
    sqlx::query("UPDATE claims SET pignistic_prob = NULL WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .expect("clear cache");

    let viewer = fixture::public_viewer(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let wrote =
        epigraph_engine::edge_factor::recompute_claim_belief_binary(&mut conn, &viewer, claim)
            .await
            .expect("recompute");
    assert!(wrote, "the claim has BBAs on the binary frame");
    drop(conn);

    let recomputed = pignistic(&pool, claim).await;
    assert!(
        (recomputed - first).abs() < 1e-9,
        "recompute folded same-source repeats as independent: single-observation BetP \
         {first}, recomputed {recomputed}"
    );
}

/// The cache's binary frame, as the DS wiring recorded it.
async fn belief_frame(pool: &PgPool, claim_id: Uuid) -> Uuid {
    sqlx::query_scalar::<_, Option<Uuid>>("SELECT belief_frame_id FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("read belief_frame_id")
        .expect("belief_frame_id written by the DS wiring")
}

/// The compute-on-read readers must agree with the cache. Framed `get_belief`
/// (MCP `get_belief` with a frame), `get_perspective_belief` (`scoped_belief`,
/// `get_claim`, the REST perspective routes) and `get_perspective_belief_batch`
/// (lensed `recall` / `memory`) recombine the stored BBAs on every read. If
/// they still folded same-source repeats as independent, the defect would stay
/// visible through every one of them while `claims.pignistic_prob` looked
/// honest.
#[sqlx::test(migrations = "../../migrations")]
async fn compute_on_read_readers_agree_with_the_cache_after_same_source_repeats(pool: PgPool) {
    let (server, claim) = setup(&pool, "readers").await;

    let first = observe(&server, &pool, claim, "Listed, no due date.", Some(PAGE)).await;
    observe(
        &server,
        &pool,
        claim,
        "Still listed, unchanged.",
        Some(PAGE),
    )
    .await;
    let cached = observe(&server, &pool, claim, "Unchanged again.", Some(PAGE)).await;
    assert!(
        (cached - first).abs() < 1e-9,
        "precondition: the write path keeps the cache at the single-observation value \
         ({first} vs {cached})"
    );

    let viewer = fixture::public_viewer(&pool).await;
    let frame = belief_frame(&pool, claim).await;

    let framed = epigraph_engine::belief_query::get_belief(&pool, &viewer, claim, Some(frame))
        .await
        .expect("framed get_belief");
    assert!(
        (framed.pignistic_prob - cached).abs() < 1e-9,
        "framed get_belief folded same-source repeats as independent: cache {cached}, \
         framed read {}",
        framed.pignistic_prob
    );

    // A perspective with no reliability overrides expresses no opinion, so the
    // lensed read must reduce to the same value.
    let lens = Uuid::new_v4();
    let lensed =
        epigraph_engine::belief_query::get_perspective_belief(&pool, &viewer, claim, frame, lens)
            .await
            .expect("get_perspective_belief");
    assert!(
        (lensed.pignistic_prob - cached).abs() < 1e-9,
        "get_perspective_belief folded same-source repeats as independent: cache {cached}, \
         lensed read {}",
        lensed.pignistic_prob
    );

    let batch = epigraph_engine::belief_query::get_perspective_belief_batch(
        &pool,
        &viewer,
        &[claim],
        frame,
        lens,
    )
    .await
    .expect("get_perspective_belief_batch");
    let batched = batch[0].1.as_ref().expect("batch item").pignistic_prob;
    assert!(
        (batched - cached).abs() < 1e-9,
        "get_perspective_belief_batch folded same-source repeats as independent: cache \
         {cached}, batch read {batched}"
    );
}

/// The production shape of the filed case (claim fc5e6a60): `submit_claim`
/// records the listing on first sighting, then weekly `update_with_evidence`
/// re-sightings of the SAME page follow. The creation BBA must carry the same
/// source identity as the re-sightings; otherwise the FIRST re-sighting is
/// still folded as independent corroboration (the filed 0.672 -> 0.768 step)
/// and only later repeats are idempotent.
///
/// The re-sightings use the creation's strength and evidence type, so each is
/// the same reading of the same page. (A STRONGER reading of one source may
/// legitimately raise BetP to that reading: the cautious fold keeps the
/// strongest, it does not freeze the first.)
#[sqlx::test(migrations = "../../migrations")]
async fn submit_then_same_source_updates_do_not_raise_betp(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let body = first_text(
        &epigraph_mcp::tools::claims::submit_claim(
            &server,
            &viewer,
            epigraph_mcp::types::SubmitClaimParams {
                content: format!("X09 submit-then-update {}", Uuid::new_v4()),
                methodology: "direct_observation".into(),
                evidence_data: "Listed; 3 addenda; no due date.".into(),
                evidence_type: "empirical".into(),
                confidence: 0.8,
                source_url: Some(PAGE.into()),
                reasoning: None,
                labels: vec![],
                novelty_threshold: None,
            },
            None,
        )
        .await
        .expect("submit_claim"),
    );
    let claim = parse_uuid_field(&body, "claim_id");
    let after_submit = pignistic(&pool, claim).await;
    assert!(
        after_submit > 0.5,
        "precondition: the creation BBA supports the claim, got {after_submit}"
    );

    for (i, data) in [
        "Still listed, due date still not shown.",
        "Re-checked: listing unchanged, three addenda.",
    ]
    .iter()
    .enumerate()
    {
        let now = observe(&server, &pool, claim, data, Some(PAGE)).await;
        assert!(
            (now - after_submit).abs() < 1e-9,
            "re-sighting #{} of the page submit_claim recorded moved BetP {after_submit} -> \
             {now}: the creation BBA and the re-sighting were combined as independent sources",
            i + 1
        );
    }

    // The recompute and the framed reader must agree, without the write
    // path's monotonicity clamp in play.
    sqlx::query("UPDATE claims SET pignistic_prob = NULL WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .expect("clear cache");
    let mut conn = pool.acquire().await.expect("acquire");
    let wrote =
        epigraph_engine::edge_factor::recompute_claim_belief_binary(&mut conn, &viewer, claim)
            .await
            .expect("recompute");
    assert!(wrote, "the claim has BBAs on the binary frame");
    drop(conn);
    let recomputed = pignistic(&pool, claim).await;
    assert!(
        (recomputed - after_submit).abs() < 1e-9,
        "recompute folded the creation BBA and same-source re-sightings as independent: \
         post-submit BetP {after_submit}, recomputed {recomputed}"
    );

    let frame = belief_frame(&pool, claim).await;
    let framed = epigraph_engine::belief_query::get_belief(&pool, &viewer, claim, Some(frame))
        .await
        .expect("framed get_belief");
    assert!(
        (framed.pignistic_prob - after_submit).abs() < 1e-9,
        "framed get_belief disagrees with the post-submit value: {after_submit} vs {}",
        framed.pignistic_prob
    );
}

/// Same-source REFUTING repeats. The write path's monotonicity clamp applies
/// only to supporting evidence (`betp = prior.min(pl)` when `supports`), so in
/// the supporting tests a fold that wrongly LOWERED BetP could be lifted back to
/// the first value by the clamp. No clamp applies here: this measures the
/// write-path combine itself. Re-worded refutations of one page by one agent
/// must leave BetP where the first refutation put it.
#[sqlx::test(migrations = "../../migrations")]
async fn same_source_refutations_do_not_compound(pool: PgPool) {
    let (server, claim) = setup(&pool, "refute").await;

    let first = observe_verdict(
        &server,
        &pool,
        claim,
        "Listing withdrawn from the page.",
        Some(PAGE),
        false,
    )
    .await;
    assert!(
        first < 0.5,
        "precondition: one refuting observation must move BetP below 0.5, got {first}"
    );
    for (i, data) in [
        "Still withdrawn, nothing posted.",
        "Re-checked: listing remains withdrawn.",
    ]
    .iter()
    .enumerate()
    {
        let now = observe_verdict(&server, &pool, claim, data, Some(PAGE), false).await;
        assert!(
            (now - first).abs() < 1e-9,
            "refutation #{} of the SAME source moved BetP {first} -> {now}: a repeat \
             of one source was combined as independent evidence",
            i + 2
        );
    }
}
