//! The retraction cascade is *observable* — PREREGISTRATION.md criteria
//! C1 (backward compatibility + the resource that answers the new race) and
//! C4 (enumeration survives the in-transaction edge migration).
//!
//! A fire-and-forget repair would make a post-`supersede_claim` read of a
//! downstream claim racy with nothing the caller could do about it but sleep.
//! The answer chosen here is a resource rather than a prohibition: the
//! response reports which claims were repaired and how, so the caller can act
//! on it. These tests pin that contract, and pin that nothing was taken away
//! to get it.
//!
//! C4 is the interesting half. `ClaimRepository::supersede` re-points every
//! non-`supersedes` outgoing edge onto the replacement claim *inside* its
//! transaction, so the obvious post-commit enumeration
//! (`WHERE source_id = <retracted id>`) matches **zero rows** and a naive
//! implementation logs "0 downstream claims, cascade complete" while being
//! completely wrong. `targets` being non-empty is what falsifies that.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{admin_auth, build_test_server, seed_claim, seed_claim_with_belief};
use epigraph_mcp::tools::link_epistemic::do_link_epistemic;
use epigraph_mcp::tools::supersede::{mark_duplicate, supersede_claim};
use epigraph_mcp::types::{LinkEpistemicParams, MarkDuplicateParams, SupersedeClaimParams};
use sqlx::PgPool;
use uuid::Uuid;

fn body(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .first()
        .expect("content")
        .as_text()
        .expect("text")
        .text
        .clone();
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("response JSON: {e}; raw={text}"))
}

async fn wire_supports(
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    s: Uuid,
    t: Uuid,
) {
    let r = do_link_epistemic(
        server,
        viewer,
        LinkEpistemicParams {
            source_claim_id: s.to_string(),
            target_claim_id: t.to_string(),
            relationship: "supports".to_string(),
            properties: None,
        },
    )
    .await
    .expect("link_epistemic supports");
    assert_eq!(
        body(&r)["belief_wired"],
        serde_json::Value::Bool(true),
        "fixture precondition: {s} --supports--> {t} must materialize a BBA"
    );
}

/// C4 + C1(b) for `supersede_claim`.
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_reports_the_downstream_target_it_repaired(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_test_server(pool.clone());

    let a = seed_claim_with_belief(&pool, 0.9, 0.9, Some(0.9)).await;
    let c = seed_claim_with_belief(&pool, 0.6, 0.7, Some(0.65)).await;
    let b = seed_claim(&pool, "downstream claim B", 0.5).await;
    wire_supports(&server, &viewer, a, b).await;
    wire_supports(&server, &viewer, c, b).await;

    // The enumeration the proposal sketched, run here to prove it is a trap:
    // after the commit, nothing outgoing is still sourced at the retracted id.
    let result = supersede_claim(
        &server,
        &viewer,
        SupersedeClaimParams {
            claim_id: a.to_string(),
            content: format!("replacement for {a}"),
            truth_value: 0.5,
            reason: "observability fixture".to_string(),
        },
        Some(&admin_auth()),
    )
    .await
    .expect("supersede_claim succeeds");
    let json = body(&result);

    let naive_enumeration: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT target_id) FROM edges \
         WHERE source_id = $1 AND relationship IN ('supports','corroborates','elaborates')",
    )
    .bind(a)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(
        naive_enumeration, 0,
        "sanity: enumerating from the RETRACTED id finds nothing, because \
         supersede re-points outgoing edges onto the replacement inside its \
         transaction — an implementation that queries it reports an empty \
         cascade and is silently wrong"
    );

    // C1(a): every pre-existing key survives.
    assert!(json["new_claim_id"].as_str().is_some());
    assert_eq!(
        json["superseded_claim_id"].as_str(),
        Some(a.to_string()).as_deref()
    );
    assert_eq!(json["reason"].as_str(), Some("observability fixture"));

    // C1(b) + C4: the cascade is reported, and it found B.
    let cascade = &json["belief_cascade"];
    let targets: Vec<String> = cascade["targets"]
        .as_array()
        .expect("belief_cascade.targets must be an array")
        .iter()
        .map(|v| v.as_str().expect("uuid string").to_string())
        .collect();
    assert_eq!(
        targets,
        vec![b.to_string()],
        "the cascade must report the downstream claim it repaired; got {cascade}"
    );
    assert_eq!(
        cascade["invalidated_bbas"].as_u64(),
        Some(1),
        "exactly the A->B edge factor was invalidated; got {cascade}"
    );
    assert_eq!(
        cascade["recomputed"].as_array().map(Vec::len),
        Some(1),
        "B still had the C supporter, so it was recomputed rather than unbacked"
    );
    assert!(
        cascade["unbacked"]
            .as_array()
            .expect("unbacked array")
            .is_empty(),
        "B still has a supporter; got {cascade}"
    );
    assert!(
        cascade["errors"]
            .as_array()
            .expect("errors array")
            .is_empty(),
        "healthy cascade must report no errors; got {cascade}"
    );
}

/// C6's observable half: "the cascade's reported outcome distinguishes this
/// case from 'nothing to do'". A claim left with no evidence at all must show
/// up in `unbacked`, not vanish into an empty report.
#[sqlx::test(migrations = "../../migrations")]
async fn sole_supporter_retraction_is_reported_as_unbacked_not_as_nothing_to_do(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_test_server(pool.clone());

    let a = seed_claim_with_belief(&pool, 0.9, 0.9, Some(0.9)).await;
    let b = seed_claim(&pool, "sole-supported claim B", 0.5).await;
    wire_supports(&server, &viewer, a, b).await;

    let result = supersede_claim(
        &server,
        &viewer,
        SupersedeClaimParams {
            claim_id: a.to_string(),
            content: format!("replacement for {a}"),
            truth_value: 0.5,
            reason: "unbacked reporting fixture".to_string(),
        },
        Some(&admin_auth()),
    )
    .await
    .expect("supersede_claim succeeds");
    let cascade = body(&result)["belief_cascade"].clone();

    let unbacked: Vec<String> = cascade["unbacked"]
        .as_array()
        .expect("unbacked array")
        .iter()
        .map(|v| v.as_str().expect("uuid string").to_string())
        .collect();
    assert_eq!(
        unbacked,
        vec![b.to_string()],
        "B lost its only supporter; the report must say its cache was cleared \
         for lack of evidence, not stay silent. `recompute_beliefs` returns \
         'frame_writes: 0, errors: []' here, which is indistinguishable from \
         a healthy no-op. Got {cascade}"
    );
    assert!(
        cascade["recomputed"]
            .as_array()
            .expect("recomputed array")
            .is_empty(),
        "there was nothing left to combine, so nothing was recomputed"
    );
}

/// C7.3: a cascade failure is surfaced in the report, not in the `Result`.
/// The corruption is real (an unparseable stored BBA), so the combine pipeline
/// genuinely errors.
#[sqlx::test(migrations = "../../migrations")]
async fn cascade_errors_are_reported_not_propagated(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_test_server(pool.clone());

    let a = seed_claim_with_belief(&pool, 0.9, 0.9, Some(0.9)).await;
    let c = seed_claim_with_belief(&pool, 0.6, 0.7, Some(0.65)).await;
    let b = seed_claim(&pool, "downstream claim B", 0.5).await;
    wire_supports(&server, &viewer, a, b).await;
    wire_supports(&server, &viewer, c, b).await;

    sqlx::query(
        "UPDATE mass_functions SET masses = '{\"0\": \"not-a-number\"}'::jsonb \
         WHERE perspective_id = (SELECT id FROM edges WHERE source_id = $1 AND target_id = $2)",
    )
    .bind(c)
    .bind(b)
    .execute(&pool)
    .await
    .expect("corrupt surviving BBA");

    let result = supersede_claim(
        &server,
        &viewer,
        SupersedeClaimParams {
            claim_id: a.to_string(),
            content: format!("replacement for {a}"),
            truth_value: 0.5,
            reason: "error reporting fixture".to_string(),
        },
        Some(&admin_auth()),
    )
    .await
    .expect("a cascade failure must NOT fail the already-committed supersede");

    let cascade = body(&result)["belief_cascade"].clone();
    let errors = cascade["errors"].as_array().expect("errors array");
    assert!(
        !errors.is_empty(),
        "swallowing the failure silently is as bad as propagating it — the \
         caller must be able to see that B was left stale; got {cascade}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.as_str().unwrap_or_default().contains(&b.to_string())),
        "the error must name the claim it could not repair; got {cascade}"
    );
}

/// C1 for `mark_duplicate`: pre-existing keys intact, cascade reported.
#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_keeps_its_keys_and_reports_the_cascade(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_test_server(pool.clone());

    let canonical = seed_claim(&pool, "canonical claim", 0.5).await;
    let dup = seed_claim(&pool, "duplicate claim", 0.5).await;
    let u = seed_claim_with_belief(&pool, 0.6, 0.7, Some(0.65)).await;
    wire_supports(&server, &viewer, u, dup).await;

    let result = mark_duplicate(
        &server,
        &viewer,
        MarkDuplicateParams {
            claim_id: dup.to_string(),
            canonical_id: canonical.to_string(),
            reason: None,
        },
        Some(&admin_auth()),
    )
    .await
    .expect("mark_duplicate succeeds");
    let json = body(&result);

    assert_eq!(
        json["duplicate_id"].as_str(),
        Some(dup.to_string()).as_deref()
    );
    assert_eq!(
        json["canonical_id"].as_str(),
        Some(canonical.to_string()).as_deref()
    );
    assert_eq!(json["mode"].as_str(), Some("mark_duplicate"));

    let cascade = &json["belief_cascade"];
    let targets: Vec<String> = cascade["targets"]
        .as_array()
        .expect("targets array")
        .iter()
        .map(|v| v.as_str().expect("uuid string").to_string())
        .collect();
    assert!(
        targets.contains(&canonical.to_string()),
        "the canonical claim inherited the duplicate's supporter, so its \
         belief was rebuilt and the report must say so; got {cascade}"
    );
    assert!(
        targets.contains(&dup.to_string()),
        "the duplicate lost every supporter it had; its cache is a derived \
         record that must be repaired too; got {cascade}"
    );
    assert!(
        cascade["errors"]
            .as_array()
            .expect("errors array")
            .is_empty(),
        "healthy cascade must report no errors; got {cascade}"
    );
}
