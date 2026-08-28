//! REPRODUCTION for backlog 696d3a1c — `recompute_beliefs` discards belief
//! contributed by epistemic edges.
//!
//! Scenario, mirroring the field report on claim ee862955:
//!   * a claim carries an intrinsic BBA on the canonical `binary_truth` frame,
//!   * N `contradicts` edges are wired through the real `link_epistemic` path,
//!     each materializing a `perspective_id = edge_id` BBA on `binary_truth`
//!     and driving the cached BetP down,
//!   * a subsequent `recompute_beliefs` reports `errors=[]` and resets the
//!     cached scalars back to the pre-edge intrinsic value.
//!
//! Four fixtures. Status as recorded against the BROKEN tree (fd95ec9); (2) is
//! now GREEN under the fix, and (1) and (3) still pass, which is what pins the
//! mechanism against a future refactor:
//!   1. `recompute_beliefs_preserves_edge_belief_single_frame` — GREEN.
//!      Control: all BBAs on `binary_truth` only; the recompute is a stable
//!      no-op. Rules out the combine pipeline / `get_for_claim_frame` / the
//!      edge BBAs themselves.
//!   2. `recompute_beliefs_preserves_edge_belief_multi_frame` — was **RED**.
//!      The reproduction. The same claim ALSO carries one BBA on a frame whose
//!      NAME sorts after `binary_truth`, so that frame's per-frame recompute
//!      lands LAST and overwrites the frame-agnostic `claims.{belief,
//!      plausibility, pignistic_prob}` scalars that the seven `contradicts`
//!      edges had driven down. Fixed by ordering `binary_truth` last in
//!      `MassFunctionRepository::list_frames_for_claim`.
//!   3. `recompute_beliefs_survives_when_binary_frame_sorts_last` — GREEN.
//!      Mechanism witness: identical to (2) but the second frame's name sorts
//!      BEFORE `binary_truth`, so `binary_truth` is written last and the edge
//!      belief survives. (2)+(3) isolated the defect to frame-NAME ordering in
//!      the recompute cascade's per-frame loop.
//!   4. `unframed_get_belief_reports_truth_value_not_the_ds_cache` — was
//!      **RED** and `#[ignore]`d, now GREEN and live. A SECOND, INDEPENDENT
//!      defect (backlog `152d9af6`), and the one that produced the field
//!      report's exact numbers: `belief_query::get_belief` with no `frame_id`
//!      returned `BeliefInterval::cached_from_truth(claim.truth_value)` —
//!      belief=truth_value, plausibility=1.0, BetP=truth_value — while
//!      labelling the result `source: "cached"` and while the tool schema said
//!      "If omitted, returns cached DS columns". For a claim seeded at
//!      truth_value 0.6 that read out as belief=0.600 / ignorance=0.400 /
//!      pignistic=0.600 both BEFORE and AFTER any recompute. Fixed by having
//!      the unframed branch read `claims.{belief, plausibility,
//!      pignistic_prob, mass_on_empty, mass_on_missing}` via
//!      `ClaimRepository::get_belief_columns`, falling back to `truth_value`
//!      (and saying so in `source`) only when the cache is NULL.

mod common;

use common::{build_test_server, seed_claim, seed_claim_with_belief};
use epigraph_db::{FrameRepository, MassFunctionRepository};
use epigraph_mcp::tools;
use epigraph_mcp::tools::link_epistemic::do_link_epistemic;
use epigraph_mcp::types::{LinkEpistemicParams, RecomputeBeliefsParams};
use epigraph_mcp::EpiGraphMcpFull;
use rmcp::model::RawContent;
use sqlx::PgPool;
use uuid::Uuid;

/// `(belief, plausibility, pignistic_prob, classification)` as cached on `claims`.
type Cached = (Option<f64>, Option<f64>, Option<f64>, Option<String>);

async fn cached(pool: &PgPool, claim_id: Uuid) -> Cached {
    sqlx::query_as(
        "SELECT belief, plausibility, pignistic_prob, classification FROM claims WHERE id = $1",
    )
    .bind(claim_id)
    .fetch_one(pool)
    .await
    .expect("read cached DS scalars")
}

fn result_json(out: rmcp::model::CallToolResult) -> serde_json::Value {
    let first = out.content.first().cloned().expect("first content");
    let text = match first.raw {
        RawContent::Text(t) => t.text,
        other => panic!("expected text content, got {other:?}"),
    };
    serde_json::from_str(&text).expect("result is JSON")
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) \
         VALUES ($1, $2, 'system') ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed agent");
    id
}

/// Build the claim under test: intrinsic BBA `m({TRUE})=0.6, m({TRUE,FALSE})=0.4`
/// on `binary_truth`, cache seeded through the canonical combine cascade, then
/// seven `contradicts` edges wired through the real `link_epistemic` tool.
///
/// Returns `(target_claim_id, binary_frame_id, post_edge_cached_scalars)`.
async fn build_contradicted_claim(pool: &PgPool, server: &EpiGraphMcpFull) -> (Uuid, Uuid, Cached) {
    let binary = epigraph_engine::edge_factor::ensure_binary_frame(pool)
        .await
        .expect("binary frame");

    let target = seed_claim(pool, &format!("696d3a1c target {}", Uuid::new_v4()), 0.6).await;
    let author = seed_agent(pool).await;

    // Intrinsic BBA on binary_truth — the "pre-edge" state the field report
    // says the recompute reverts to.
    FrameRepository::assign_claim(pool, target, binary, Some(0))
        .await
        .expect("assign target to binary frame");
    MassFunctionRepository::store_with_perspective(
        pool,
        target,
        binary,
        Some(author),
        None, // no perspective => intrinsic, not edge-derived
        &serde_json::json!({ "0": 0.6, "0,1": 0.4 }),
        None,
        Some("intrinsic"),
        Some(1.0),
        None, // evidence_type NULL => effective_source_strength honours the 1.0
        "cross",
        None,
    )
    .await
    .expect("store intrinsic BBA");

    epigraph_engine::edge_factor::recompute_claim_belief_on_frame(pool, target, binary)
        .await
        .expect("seed cache from intrinsic BBA");
    let pre_edge = cached(pool, target).await;

    // Seven contradicting sources, each wired via the real MCP edge path.
    for i in 0..7 {
        let source = seed_claim_with_belief(pool, 0.9, 1.0, Some(0.9)).await;
        let out = do_link_epistemic(
            server,
            LinkEpistemicParams {
                source_claim_id: source.to_string(),
                target_claim_id: target.to_string(),
                relationship: "contradicts".to_string(),
                properties: None,
            },
        )
        .await
        .expect("link_epistemic contradicts");
        let j = result_json(out);
        assert_eq!(
            j["belief_wired"],
            serde_json::Value::Bool(true),
            "fixture precondition: contradicts edge #{i} must materialize a BBA; raw={j}"
        );
    }

    let post_edge = cached(pool, target).await;
    assert!(
        post_edge.2.expect("post-edge betp") < pre_edge.2.expect("pre-edge betp") - 0.05,
        "fixture precondition: seven contradicts edges must drive BetP down; \
         pre={pre_edge:?} post={post_edge:?}"
    );

    (target, binary, post_edge)
}

async fn run_recompute(server: &EpiGraphMcpFull, target: Uuid) -> serde_json::Value {
    let out = tools::cdst_maintenance::recompute_beliefs(
        server,
        RecomputeBeliefsParams {
            claim_ids: Some(vec![target.to_string()]),
            labels: None,
            limit: None,
            offset: None,
        },
    )
    .await
    .expect("recompute_beliefs");
    result_json(out)
}

/// CONTROL: every BBA on `binary_truth` only. `recompute_beliefs` must be a
/// stable no-op over the edge-contributed belief.
#[sqlx::test(migrations = "../../migrations")]
async fn recompute_beliefs_preserves_edge_belief_single_frame(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let (target, _binary, post_edge) = build_contradicted_claim(&pool, &server).await;

    let report = run_recompute(&server, target).await;
    assert!(
        report["errors"]
            .as_array()
            .expect("errors array")
            .is_empty(),
        "recompute reported errors: {report}"
    );

    let after = cached(&pool, target).await;
    assert!(
        (after.2.expect("betp") - post_edge.2.expect("betp")).abs() < 1e-9,
        "single-frame recompute changed the cached BetP: post_edge={post_edge:?} after={after:?} \
         report={report}"
    );
}

/// Give `target` one extra BBA on a brand-new frame named `frame_name`.
async fn add_second_frame_bba(pool: &PgPool, target: Uuid, frame_name: String) -> Uuid {
    let author = seed_agent(pool).await;
    let other = FrameRepository::create(
        pool,
        &frame_name,
        Some("second frame for backlog 696d3a1c reproduction"),
        &["supported".to_string(), "refuted".to_string()],
    )
    .await
    .expect("create second frame");
    FrameRepository::assign_claim(pool, target, other.id, Some(0))
        .await
        .expect("assign target to second frame");
    MassFunctionRepository::store_with_perspective(
        pool,
        target,
        other.id,
        Some(author),
        None,
        &serde_json::json!({ "0": 0.6, "0,1": 0.4 }),
        None,
        Some("intrinsic"),
        Some(1.0),
        None,
        "cross",
        None,
    )
    .await
    .expect("store second-frame BBA");
    other.id
}

/// REPRODUCTION: the same claim also carries ONE BBA on a frame whose name
/// sorts after `binary_truth`. `recompute_beliefs` walks the claim's frames in
/// frame-NAME order and writes the frame-agnostic `claims.{belief,
/// plausibility, pignistic_prob}` scalars once per frame — so the last frame
/// wins and the binary-frame result (which is the only one the seven
/// `contradicts` edges contributed to) is discarded.
#[sqlx::test(migrations = "../../migrations")]
async fn recompute_beliefs_preserves_edge_belief_multi_frame(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let (target, _binary, post_edge) = build_contradicted_claim(&pool, &server).await;

    // A second frame, named so it sorts AFTER "binary_truth" — exactly what a
    // workflow's `claim_validity` / `paper_validity_*` / `textbook_veracity_*`
    // BBA does in production.
    let name = format!("claim_validity_696d3a1c_{}", Uuid::new_v4());
    assert!(
        "binary_truth" < name.as_str(),
        "fixture precondition: the second frame must sort after binary_truth"
    );
    add_second_frame_bba(&pool, target, name).await;

    // The second-frame BBA alone must not disturb the cache — no recompute ran.
    let before = cached(&pool, target).await;
    assert!(
        (before.2.expect("betp") - post_edge.2.expect("betp")).abs() < 1e-9,
        "fixture precondition: storing a BBA does not itself rewrite the cache"
    );

    let report = run_recompute(&server, target).await;
    assert!(
        report["errors"]
            .as_array()
            .expect("errors array")
            .is_empty(),
        "recompute reported errors: {report}"
    );
    assert_eq!(report["claims_recomputed"], 1);
    assert_eq!(report["claims_skipped_no_bba"], 0);
    assert_eq!(report["frame_writes"], 2);

    let after = cached(&pool, target).await;
    assert!(
        (after.2.expect("betp") - post_edge.2.expect("betp")).abs() < 1e-9,
        "recompute_beliefs discarded the belief contributed by seven contradicts edges.\n\
         post_edge (belief, plausibility, betp, classification) = {post_edge:?}\n\
         after    (belief, plausibility, betp, classification) = {after:?}\n\
         recompute report = {report}"
    );
}

/// MECHANISM WITNESS: identical to `..._multi_frame` except the second frame's
/// NAME sorts BEFORE `binary_truth`, so `binary_truth` is written last and the
/// edge-contributed belief survives. Green at HEAD.
///
/// Pairing this with the red `..._multi_frame` fixture isolates the defect to
/// frame-NAME ordering in `cdst_maintenance::recompute_beliefs`' per-frame
/// loop — nothing in the combine pipeline, the edge BBAs, or
/// `get_for_claim_frame`.
#[sqlx::test(migrations = "../../migrations")]
async fn recompute_beliefs_survives_when_binary_frame_sorts_last(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let (target, _binary, post_edge) = build_contradicted_claim(&pool, &server).await;

    let name = format!("aaa_696d3a1c_{}", Uuid::new_v4());
    assert!(
        name.as_str() < "binary_truth",
        "fixture precondition: the second frame must sort before binary_truth"
    );
    add_second_frame_bba(&pool, target, name).await;

    let report = run_recompute(&server, target).await;
    assert_eq!(report["frame_writes"], 2);

    let after = cached(&pool, target).await;
    assert!(
        (after.2.expect("betp") - post_edge.2.expect("betp")).abs() < 1e-9,
        "with binary_truth written LAST the edge belief must survive: \
         post_edge={post_edge:?} after={after:?} report={report}"
    );
}

/// Regression guard for the SECOND (independent) defect the field report's
/// exact numbers pointed at — backlog `152d9af6`: `get_belief` WITHOUT a
/// `frame_id` did not read the cached DS columns at all. Its unframed branch
/// returned `BeliefInterval::cached_from_truth(claim.truth_value)` — belief =
/// truth_value, plausibility = 1.0, BetP = truth_value — while labelling the
/// result `source: "cached"`, so an unframed `get_belief` reported
/// belief=0.600 / ignorance=0.400 / pignistic=0.600 for a claim seeded at
/// truth_value 0.6 no matter what the seven contradicts edges did.
///
/// This is the END-TO-END witness for that fix, and the reason it is here
/// rather than only beside the fix site: the cached scalars it compares against
/// are produced by the REAL pipeline — seven `contradicts` edges wired through
/// `do_link_epistemic` and then `recompute_beliefs` — not by a hand-seeded row.
/// The narrow column-mapping fixtures live in `belief_query::tests`.
///
/// Was `#[ignore]`d as a known-RED reproduction while 696d3a1c was fixed; the
/// attribute came off with the `152d9af6` fix.
#[sqlx::test(migrations = "../../migrations")]
async fn unframed_get_belief_reports_truth_value_not_the_ds_cache(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let (target, _binary, post_edge) = build_contradicted_claim(&pool, &server).await;

    let interval = epigraph_engine::belief_query::get_belief(&pool, target, None)
        .await
        .expect("unframed get_belief");

    println!(
        "cached DS columns  = {post_edge:?}\n\
         unframed get_belief = belief={} plausibility={} ignorance={} betp={} source={}",
        interval.belief,
        interval.plausibility,
        interval.plausibility - interval.belief,
        interval.pignistic_prob,
        interval.source,
    );

    assert!(
        (interval.pignistic_prob - post_edge.2.expect("cached betp")).abs() < 1e-9,
        "unframed get_belief must reflect the cached DS scalars, not truth_value"
    );
}
