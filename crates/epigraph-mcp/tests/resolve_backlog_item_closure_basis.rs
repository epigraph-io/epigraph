//! Integration test for `resolve_backlog_item`'s CLOSURE BASIS (backlog
//! d4f1e8fa).
//!
//! Before this, backlog closure was one-way and therefore not defeasible: the
//! tool filed a resolution claim and patched the original with
//! `add=["resolved"]`, but recorded no link to the claims that justified the
//! closure. Nothing could flag a reopen candidate when later evidence
//! contradicted the basis, because there was nothing to traverse from.
//!
//! `basis_claim_ids` now writes a `resolution -justifies-> basis` edge per id,
//! which puts the closure on the graph that `supersede_claim`,
//! `retraction_cascade` and `recompute_beliefs` already walk.
//!
//! The tests that carry weight here are the two REFUSALS, not the happy path:
//! a basis the caller cannot see, and a basis that is the item itself. Both are
//! cases where silently skipping would leave a closure whose recorded basis is
//! quietly smaller than the one the caller asked for — indistinguishable, after
//! the fact, from a closure filed with no basis at all.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::ClaimId;
use epigraph_db::ClaimRepository;
use epigraph_mcp::tools::claims::{resolve_backlog_item, JUSTIFIES_RELATIONSHIP};
use epigraph_mcp::types::ResolveBacklogItemParams;
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::build_scoped_test_server;

#[sqlx::test(migrations = "../../migrations")]
async fn closure_basis_is_recorded_as_justifies_edges(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let server_agent = bootstrap_server_agent(&server, &pool).await;

    let original = seed_backlog_claim(&pool, server_agent).await;
    let basis_a =
        fixture::seed_public_claim(&pool, server_agent, "the measurement that closed it").await;
    let basis_b =
        fixture::seed_public_claim(&pool, server_agent, "the second corroborating run").await;

    let body = parse_json(
        &resolve_backlog_item(
            &server,
            &viewer,
            ResolveBacklogItemParams {
                original_id: original.as_uuid().to_string(),
                resolution_content: "Closed: both runs agree.".to_string(),
                methodology: None,
                // Deliberately repeats basis_a: a caller listing the same
                // justification twice must not produce two edges.
                basis_claim_ids: vec![
                    basis_a.to_string(),
                    basis_b.to_string(),
                    basis_a.to_string(),
                ],
            },
            None,
        )
        .await
        .expect("resolve_backlog_item with a basis must succeed"),
    );

    // The RESPONSE must also report the basis exactly once. `create_if_not_exists`
    // keys on (source, target, relationship) and so collapses the repeat at the
    // edge table regardless; this assertion is what makes the handler's own
    // de-duplication load-bearing, by pinning the set it reports back.
    let reported: Vec<String> = body["basis_claim_ids"]
        .as_array()
        .expect("basis_claim_ids array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        reported,
        vec![basis_a.to_string(), basis_b.to_string()],
        "the reported basis must list each claim once, in the order given"
    );

    let resolution_id: Uuid = body["resolution_claim_id"]
        .as_str()
        .expect("resolution_claim_id")
        .parse()
        .expect("uuid");

    // THE POINT OF THE FEATURE: the closure is now traversable. Read the edges
    // back out of the database rather than trusting the response body — the
    // response is what the tool says it did; the edge table is what it did.
    let targets: Vec<Uuid> = sqlx::query_scalar(
        "SELECT source_id FROM edges \
         WHERE target_id = $1 AND relationship = $2 ORDER BY source_id",
    )
    .bind(resolution_id)
    .bind(JUSTIFIES_RELATIONSHIP)
    .fetch_all(&pool)
    .await
    .expect("read justifies edges");

    let mut expected = vec![basis_a, basis_b];
    expected.sort();
    assert_eq!(
        targets, expected,
        "the resolution must justify exactly its two distinct basis claims; \
         a repeated id must not become a second edge"
    );

    // The basis is on the SOURCE side, which is the side
    // `EdgeRepository::list_current_claim_targets` walks (`WHERE e.source_id = $1`).
    // So a retracted basis can reach the closure resting on it — a precondition
    // for a future automatic reopen, not a mechanism that fires today (see the
    // `basis_claim_ids` doc: `justifies` is Neutral and carries no BBA).
    let back: Vec<Uuid> = sqlx::query_scalar(
        "SELECT target_id FROM edges WHERE source_id = $1 AND relationship = $2",
    )
    .bind(basis_a)
    .bind(JUSTIFIES_RELATIONSHIP)
    .fetch_all(&pool)
    .await
    .expect("reverse traversal");
    assert_eq!(back, vec![resolution_id]);

    // The pre-existing contract is untouched: retirement is still label-side.
    let original_after = ClaimRepository::get_by_id(&pool, &viewer, original)
        .await
        .expect("get original")
        .expect("original exists");
    assert!(original_after.is_current);
    assert!(original_after.supersedes.is_none());
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_basis_the_caller_cannot_see_is_refused_not_skipped(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let server_agent = bootstrap_server_agent(&server, &pool).await;

    let original = seed_backlog_claim(&pool, server_agent).await;
    let visible = fixture::seed_public_claim(&pool, server_agent, "a basis anyone may read").await;

    // A group-private claim belonging to somebody else's group: it exists, so
    // a naive existence check keyed on the pool would find it, but the public
    // viewer must not be able to point a closure at it.
    let (other_agent, other_group) = fixture::seed_agent_with_group(&pool, "closure-basis").await;
    let invisible =
        fixture::seed_group_claim(&pool, other_agent, other_group, "a private measurement").await;

    // Precondition, so a later visibility change turns this test red rather
    // than making it vacuous: the viewer genuinely cannot read it.
    assert!(
        ClaimRepository::get_by_id(&pool, &viewer, ClaimId::from_uuid(invisible))
            .await
            .expect("scoped read")
            .is_none(),
        "fixture precondition: the public viewer must not see the group-private claim"
    );

    let err = resolve_backlog_item(
        &server,
        &viewer,
        ResolveBacklogItemParams {
            original_id: original.as_uuid().to_string(),
            resolution_content: "Closed on a basis I cannot read.".to_string(),
            methodology: None,
            basis_claim_ids: vec![visible.to_string(), invisible.to_string()],
        },
        None,
    )
    .await
    .expect_err("an unreadable basis claim must be refused");
    assert!(
        err.message.contains(&invisible.to_string()),
        "the refusal must name the offending basis id, got: {}",
        err.message
    );

    // AND NOTHING WAS WRITTEN. The refusal happens before `submit_claim`, so
    // there is no orphan resolution claim and the item is still open. This is
    // the half that a "skip the invisible one" implementation would also fail,
    // and the half a response-body assertion cannot see.
    let labels = ClaimRepository::get_labels(&pool, &viewer, original)
        .await
        .expect("labels");
    assert!(
        !labels.contains(&"resolved".to_string()),
        "a refused closure must leave the item OPEN, got {labels:?}"
    );
    let edge_count: i64 = sqlx::query_scalar("SELECT count(*) FROM edges WHERE relationship = $1")
        .bind(JUSTIFIES_RELATIONSHIP)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(
        edge_count, 0,
        "a refused closure must not have written a partial basis for the readable id"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_item_cannot_be_its_own_closure_basis(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let server_agent = bootstrap_server_agent(&server, &pool).await;
    let original = seed_backlog_claim(&pool, server_agent).await;

    let err = resolve_backlog_item(
        &server,
        &viewer,
        ResolveBacklogItemParams {
            original_id: original.as_uuid().to_string(),
            resolution_content: "Closed because it says so.".to_string(),
            methodology: None,
            basis_claim_ids: vec![original.as_uuid().to_string()],
        },
        None,
    )
    .await
    .expect_err("an item must not be able to justify its own closure");
    assert!(
        err.message.contains("own justification"),
        "unexpected message: {}",
        err.message
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn omitting_the_basis_stays_wire_compatible(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let server_agent = bootstrap_server_agent(&server, &pool).await;
    let original = seed_backlog_claim(&pool, server_agent).await;

    // `basis_claim_ids` is `#[serde(default)]`, so a caller that predates it
    // still deserializes. Prove it at the wire level, not by constructing the
    // struct in Rust — the struct literal cannot omit a field.
    let params: ResolveBacklogItemParams = serde_json::from_value(serde_json::json!({
        "original_id": original.as_uuid().to_string(),
        "resolution_content": "Closed the old way.",
    }))
    .expect("a payload with no basis_claim_ids must still deserialize");
    assert!(params.basis_claim_ids.is_empty());

    let body = parse_json(
        &resolve_backlog_item(&server, &viewer, params, None)
            .await
            .expect("a basis-less closure must still be accepted"),
    );
    assert!(body["basis_claim_ids"]
        .as_array()
        .expect("basis_claim_ids array")
        .is_empty());
}

// ── helpers ──

fn parse_json(result: &CallToolResult) -> Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content block");
    serde_json::from_str(&text).expect("response is JSON")
}

/// Submit a throwaway claim so the server's signer agent is registered, then
/// return that agent's UUID — `resolve_backlog_item` enforces caller-owns-claim.
async fn bootstrap_server_agent(server: &epigraph_mcp::EpiGraphMcpFull, pool: &PgPool) -> Uuid {
    let viewer = fixture::public_viewer(pool).await;
    let result = epigraph_mcp::tools::claims::submit_claim(
        server,
        &viewer,
        epigraph_mcp::types::SubmitClaimParams {
            content: "bootstrap claim for closure-basis test".into(),
            methodology: "deductive_logic".into(),
            evidence_data: "ev".into(),
            evidence_type: "logical".into(),
            confidence: 0.5,
            source_url: None,
            reasoning: None,
            labels: vec![],
            novelty_threshold: None,
        },
        None,
    )
    .await
    .expect("bootstrap submit_claim");
    let claim_id: Uuid = parse_json(&result)["claim_id"]
        .as_str()
        .expect("claim_id")
        .parse()
        .expect("uuid");
    sqlx::query_scalar::<_, Uuid>("SELECT agent_id FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("fetch agent_id")
}

async fn seed_backlog_claim(pool: &PgPool, agent_id: Uuid) -> ClaimId {
    let id = fixture::seed_public_claim(pool, agent_id, "an open backlog item").await;
    sqlx::query("UPDATE claims SET labels = ARRAY['backlog']::text[] WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("label as backlog");
    ClaimId::from_uuid(id)
}
