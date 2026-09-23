//! Acceptance item 21 (plan §8.5) for the three MCP edge writers that dedup:
//! `link_epistemic`, `link_hierarchical` and `link_alternative`.
//!
//! Each used to answer a re-assertion of an edge the caller could not read
//! with that edge's id — `link_epistemic` / `link_hierarchical` through
//! `EdgeRepository::create_if_not_exists`'s unfiltered probe,
//! `link_alternative` through `create_symmetric_if_absent_returning`'s
//! unfiltered dedup-hit read. Every fixture here is two PUBLIC claims (so the
//! stranger can see and name both endpoints) joined by an edge forced private
//! to the owner's group, so the edge's own tenancy is the only thing between
//! the stranger and it.
//!
//! * `link_epistemic` / `link_hierarchical` now treat the invisible edge as
//!   absent: the stranger's own edge is created, exactly as with no edge.
//! * `link_alternative` cannot, because `edges_alternative_of_symmetric_uniq`
//!   refuses a second in-force row whoever owns the first. It answers a fixed
//!   literal as invalid params and never the id. That residual is
//!   `D-N21-unique-keys-omit-owner-group`.
//!
//! Every test runs the owner first as a CLASS P arm: a reader still gets the
//! existing edge back, so the dedup was narrowed, not disabled.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_db::visibility::Viewer;
use epigraph_db::EdgeRepository;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::link_alternative::do_link_alternative;
use epigraph_mcp::tools::link_epistemic::do_link_epistemic;
use epigraph_mcp::tools::link_hierarchical::do_link_hierarchical;
use epigraph_mcp::types::{LinkAlternativeParams, LinkEpistemicParams, LinkHierarchicalParams};
use sqlx::PgPool;
use uuid::Uuid;

fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

fn body(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = &result
        .content
        .first()
        .expect("a content block")
        .as_text()
        .expect("text content")
        .text;
    serde_json::from_str(text).expect("JSON response")
}

/// `(owner viewer, stranger viewer, source, target, hidden edge)`: two public
/// claims and a `relationship` edge between them forced private to the owner's
/// group.
async fn public_pair_with_private_edge(
    pool: &PgPool,
    label: &str,
    relationship: &str,
) -> (Viewer, Viewer, Uuid, Uuid, Uuid) {
    let (owner, group) = fixture::seed_agent_with_group(pool, &format!("{label}-owner")).await;
    let (stranger, _) = fixture::seed_agent_with_group(pool, &format!("{label}-stranger")).await;
    let source = fixture::seed_public_claim(pool, owner, &format!("{label} src")).await;
    let target = fixture::seed_public_claim(pool, owner, &format!("{label} tgt")).await;
    let edge = fixture::seed_edge_owned_by(pool, source, target, "group", group).await;
    sqlx::query("UPDATE edges SET relationship = $2 WHERE id = $1")
        .bind(edge)
        .bind(relationship)
        .execute(pool)
        .await
        .expect("set relationship");

    let owner_viewer = Viewer::resolve(pool, owner).await.expect("resolve owner");
    let stranger_viewer = Viewer::resolve(pool, stranger)
        .await
        .expect("resolve stranger");

    // PREMISE: the edge is readable by the owner and not by the stranger.
    let reads = |rows: Vec<epigraph_db::EdgeRow>| rows.iter().any(|r| r.id == edge);
    assert!(reads(
        EdgeRepository::get_by_source(pool, &owner_viewer, source, "claim")
            .await
            .expect("get_by_source")
    ));
    assert!(!reads(
        EdgeRepository::get_by_source(pool, &stranger_viewer, source, "claim")
            .await
            .expect("get_by_source")
    ));

    (owner_viewer, stranger_viewer, source, target, edge)
}

#[sqlx::test(migrations = "../../migrations")]
async fn link_epistemic_treats_an_invisible_edge_as_absent(pool: PgPool) {
    let server = make_server(pool.clone());
    let (owner, stranger, source, target, hidden) =
        public_pair_with_private_edge(&pool, "n21-epi", "supports").await;
    let params = || LinkEpistemicParams {
        source_claim_id: source.to_string(),
        target_claim_id: target.to_string(),
        relationship: "supports".to_string(),
        properties: None,
    };

    let owners = body(
        &do_link_epistemic(&server, &owner, params())
            .await
            .expect("owner link"),
    );
    assert_eq!(owners["edge_id"], hidden.to_string(), "CLASS P: {owners}");
    assert_eq!(owners["was_created"], false);

    let strangers = body(
        &do_link_epistemic(&server, &stranger, params())
            .await
            .expect("stranger link"),
    );
    assert_ne!(
        strangers["edge_id"],
        hidden.to_string(),
        "link_epistemic handed a stranger the id of an edge it cannot read: {strangers}"
    );
    assert_eq!(
        strangers["was_created"], true,
        "an invisible edge must be treated as absent: {strangers}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn link_hierarchical_treats_an_invisible_edge_as_absent(pool: PgPool) {
    let server = make_server(pool.clone());
    let (owner, stranger, source, target, hidden) =
        public_pair_with_private_edge(&pool, "n21-hier", "decomposes_to").await;
    let params = || LinkHierarchicalParams {
        source_claim_id: source.to_string(),
        target_claim_id: target.to_string(),
        relationship: "decomposes_to".to_string(),
        properties: None,
    };

    let owners = body(
        &do_link_hierarchical(&server, &owner, params())
            .await
            .expect("owner link"),
    );
    assert_eq!(owners["edge_id"], hidden.to_string(), "CLASS P: {owners}");
    assert_eq!(owners["created"], false);

    let strangers = body(
        &do_link_hierarchical(&server, &stranger, params())
            .await
            .expect("stranger link"),
    );
    assert_ne!(
        strangers["edge_id"],
        hidden.to_string(),
        "link_hierarchical handed a stranger the id of an edge it cannot read: {strangers}"
    );
    assert_eq!(
        strangers["created"], true,
        "an invisible edge must be treated as absent: {strangers}"
    );
}

/// The first test over `link_alternative` / `create_symmetric_if_absent_returning`
/// at all, so it also pins the two ordinary paths the invisible case is
/// compared against.
#[sqlx::test(migrations = "../../migrations")]
async fn link_alternative_never_returns_an_invisible_edge(pool: PgPool) {
    let server = make_server(pool.clone());
    let (owner, stranger, a, b, hidden) =
        public_pair_with_private_edge(&pool, "n21-alt", "alternative_of").await;
    let params = |x: Uuid, y: Uuid| LinkAlternativeParams {
        claim_a: x.to_string(),
        claim_b: y.to_string(),
        target_claim_id: None,
        rationale: None,
    };

    // Absent, then visible: a fresh pair is created, and re-linking it in the
    // REVERSED order is a dedup hit on the same edge.
    let (author, _) = fixture::seed_agent_with_group(&pool, "n21-alt-fresh").await;
    let x = fixture::seed_public_claim(&pool, author, "n21 alt fresh x").await;
    let y = fixture::seed_public_claim(&pool, author, "n21 alt fresh y").await;
    let created = body(
        &do_link_alternative(&server, &stranger, params(x, y))
            .await
            .expect("absent pair links"),
    );
    assert_eq!(created["created"], true, "{created}");
    let again = body(
        &do_link_alternative(&server, &stranger, params(y, x))
            .await
            .expect("visible pair dedups"),
    );
    assert_eq!(
        (again["created"].clone(), again["edge_id"].clone()),
        (serde_json::json!(false), created["edge_id"].clone()),
        "a readable symmetric edge is returned on a re-link in either order"
    );

    // CLASS P over the private edge: its owner still gets it back.
    let owners = body(
        &do_link_alternative(&server, &owner, params(b, a))
            .await
            .expect("owner re-link"),
    );
    assert_eq!(owners["edge_id"], hidden.to_string(), "{owners}");

    // The stranger never gets it.
    let err = do_link_alternative(&server, &stranger, params(a, b))
        .await
        .expect_err("the symmetric index refuses a second alternative_of edge");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");
    assert_eq!(err.message, EdgeRepository::SYMMETRIC_COLLISION_REASON);
    assert!(
        !err.message.contains(&hidden.to_string()),
        "the refusal names the invisible edge: {err:?}"
    );
}
