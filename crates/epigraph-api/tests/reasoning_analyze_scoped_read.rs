#![cfg(feature = "db")]
//! `POST /api/v1/reasoning/analyze` answers from the caller's own view of the
//! graph, and only for a caller holding `analysis:reasoning`.
//!
//! # What the handler exposes
//!
//! With `edges` empty the handler loads claim-to-claim edges itself, then runs
//! the reasoning engine over them. Every derived row — a transitive support, a
//! contradiction, a component — names the two endpoint claim ids of the edges
//! it was derived from, and `stats.edges_loaded` counts them. So the edge read
//! decides which claim ids and which graph structure a response can carry, and
//! it has to be the caller's read, not an unfiltered one.
//!
//! # The corpus, and why each edge is shaped the way it is
//!
//! Three PUBLIC claims `p1 -> p2 -> p3`, chained by two `supports` edges:
//!
//! * `p1 -> p2` is FORCED to `('group', owner_group)` with
//!   `viewer_fixture::seed_edge_owned_by`. Both endpoints are public, so no
//!   claim predicate can be what withholds it from a stranger: only the EDGE
//!   predicate can. An edge left to migration 070's trigger would inherit its
//!   endpoints' visibility, and a stranger assertion over it would stay green
//!   with the edge predicate deleted.
//! * `p2 -> p3` is left to the trigger, so it is public. It is the non-vacuity
//!   control: the stranger's request must still return it, or an empty answer
//!   could be a broken endpoint rather than a working filter.
//!
//! Each arm asserts an EXACT `edges_loaded` and names every derived pair in
//! both directions, so a fail-open regression (stranger sees 2) and a
//! fail-closed one (owner sees 1) are both visible.
//!
//! # Why `#[sqlx::test]` plus `spawn_app`
//!
//! The arms go through the real router — bearer middleware, scope check,
//! `ViewerExtractor`, handler — on a private database
//! (`viewer_fixture::database_url_for`), as `graph_routes_test.rs` does. The
//! private database is what makes the `claim_ids`-less arm meaningful: it reads
//! every claim-to-claim edge in the database, which on a shared database could
//! page the seeded edges out of its row cap and pass for the wrong reason.

use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

mod viewer_fixture;

mod common;

/// The three-claim chain described in the module doc, plus tokens.
struct Corpus {
    p1: Uuid,
    p2: Uuid,
    p3: Uuid,
    owner_agent: Uuid,
    stranger_agent: Uuid,
}

async fn corpus(pool: &PgPool) -> Corpus {
    let (owner_agent, owner_group) =
        viewer_fixture::seed_agent_with_group(pool, "reasoning-owner").await;
    let (stranger_agent, _stranger_group) =
        viewer_fixture::seed_agent_with_group(pool, "reasoning-stranger").await;

    let p1 = viewer_fixture::seed_public_claim(pool, owner_agent, "reasoning chain p1").await;
    let p2 = viewer_fixture::seed_public_claim(pool, owner_agent, "reasoning chain p2").await;
    let p3 = viewer_fixture::seed_public_claim(pool, owner_agent, "reasoning chain p3").await;

    viewer_fixture::seed_edge_owned_by(pool, p1, p2, "group", owner_group).await;
    viewer_fixture::seed_edge(pool, p2, p3).await;

    // CALIBRATION: the corpus has exactly the tenancy shape the arms rely on.
    let shapes: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT source_id, target_id, visibility::text FROM edges \
         WHERE source_id = ANY($1) AND target_id = ANY($1) ORDER BY visibility",
    )
    .bind(vec![p1, p2, p3])
    .fetch_all(pool)
    .await
    .expect("read back seeded edges");
    assert_eq!(
        shapes,
        vec![
            (p1, p2, "group".to_string()),
            (p2, p3, "public".to_string()),
        ],
        "CALIBRATION: p1->p2 must be group-private and p2->p3 public, or the \
         stranger arms below cannot tell the edge predicate from anything else"
    );

    Corpus {
        p1,
        p2,
        p3,
        owner_agent,
        stranger_agent,
    }
}

/// POST the analysis request; return `(status, body)`.
async fn analyze(addr: std::net::SocketAddr, token: &str, body: Value) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/reasoning/analyze"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("POST /api/v1/reasoning/analyze");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("response body");
    let json = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (status, json)
}

/// The `(source_id, target_id)` pairs of `transitive_supports`.
fn support_pairs(body: &Value) -> Vec<(Uuid, Uuid)> {
    let mut pairs: Vec<(Uuid, Uuid)> = body["transitive_supports"]
        .as_array()
        .unwrap_or_else(|| panic!("response has no transitive_supports array: {body}"))
        .iter()
        .map(|ts| {
            let id = |k: &str| {
                Uuid::parse_str(ts[k].as_str().expect("id is a string")).expect("id is a uuid")
            };
            (id("source_id"), id("target_id"))
        })
        .collect();
    pairs.sort();
    pairs
}

fn edges_loaded(body: &Value) -> u64 {
    body["stats"]["edges_loaded"]
        .as_u64()
        .unwrap_or_else(|| panic!("response has no stats.edges_loaded: {body}"))
}

fn sorted(mut v: Vec<(Uuid, Uuid)>) -> Vec<(Uuid, Uuid)> {
    v.sort();
    v
}

/// The scoped arm (`claim_ids` given): the owner gets its own group-private edge
/// and everything derived through it; a stranger gets the public edge only.
#[sqlx::test(migrations = "../../migrations")]
async fn analyze_withholds_a_group_private_edge_from_a_stranger(pool: PgPool) {
    let c = corpus(&pool).await;
    let url = viewer_fixture::database_url_for(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let request = json!({ "claim_ids": [c.p1, c.p2, c.p3] });

    let owner_token = common::mint_token_with_agent(&["analysis:reasoning"], c.owner_agent);
    let (status, owner) = analyze(addr, &owner_token, request.clone()).await;
    assert_eq!(status, 200, "owner analyze must succeed: {owner}");
    assert_eq!(
        edges_loaded(&owner),
        2,
        "the owner must load both edges, including its own group-private one: {owner}"
    );
    assert_eq!(
        support_pairs(&owner),
        sorted(vec![(c.p1, c.p2), (c.p2, c.p3), (c.p1, c.p3)]),
        "the owner's analysis must derive through its own private edge"
    );

    let stranger_token = common::mint_token_with_agent(&["analysis:reasoning"], c.stranger_agent);
    let (status, stranger) = analyze(addr, &stranger_token, request).await;
    assert_eq!(status, 200, "stranger analyze must succeed: {stranger}");
    assert_eq!(
        edges_loaded(&stranger),
        1,
        "a stranger must load only the public edge, not another group's: {stranger}"
    );
    assert_eq!(
        support_pairs(&stranger),
        vec![(c.p2, c.p3)],
        "a stranger must see the public support and nothing derived from \
         another group's private edge ({} -> {})",
        c.p1,
        c.p2
    );
}

/// The unscoped arm (no `claim_ids`): every claim-to-claim edge the CALLER can
/// read, which for a stranger excludes another group's private edge.
#[sqlx::test(migrations = "../../migrations")]
async fn analyze_without_claim_ids_withholds_a_group_private_edge_from_a_stranger(pool: PgPool) {
    let c = corpus(&pool).await;
    let url = viewer_fixture::database_url_for(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let owner_token = common::mint_token_with_agent(&["analysis:reasoning"], c.owner_agent);
    let (status, owner) = analyze(addr, &owner_token, json!({})).await;
    assert_eq!(status, 200, "owner analyze must succeed: {owner}");
    let owner_pairs = support_pairs(&owner);
    for pair in [(c.p1, c.p2), (c.p2, c.p3), (c.p1, c.p3)] {
        assert!(
            owner_pairs.contains(&pair),
            "the owner's unscoped analysis must include {pair:?}; got {owner_pairs:?}"
        );
    }

    let stranger_token = common::mint_token_with_agent(&["analysis:reasoning"], c.stranger_agent);
    let (status, stranger) = analyze(addr, &stranger_token, json!({})).await;
    assert_eq!(status, 200, "stranger analyze must succeed: {stranger}");
    let stranger_pairs = support_pairs(&stranger);
    assert!(
        stranger_pairs.contains(&(c.p2, c.p3)),
        "non-vacuity: the stranger must still see the public support; got {stranger_pairs:?}"
    );
    for pair in [(c.p1, c.p2), (c.p1, c.p3)] {
        assert!(
            !stranger_pairs.contains(&pair),
            "a stranger must not see {pair:?}, derived from another group's \
             private edge; got {stranger_pairs:?}"
        );
    }
}

/// A token without `analysis:reasoning` is refused, even for the owner of the
/// data — and the refusal carries no analysis.
#[sqlx::test(migrations = "../../migrations")]
async fn analyze_requires_the_analysis_reasoning_scope(pool: PgPool) {
    let c = corpus(&pool).await;
    let url = viewer_fixture::database_url_for(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let request = json!({ "claim_ids": [c.p1, c.p2, c.p3] });

    let unscoped = common::mint_token_with_agent(&["claims:read", "edges:read"], c.owner_agent);
    let (status, body) = analyze(addr, &unscoped, request.clone()).await;
    assert_eq!(
        status, 403,
        "a token without analysis:reasoning must be refused: {body}"
    );
    assert!(
        body.get("transitive_supports").is_none(),
        "a refused request must carry no analysis: {body}"
    );

    // CALIBRATION: the same agent with the scope is served, so the 403 above is
    // the scope and not the principal.
    let scoped = common::mint_token_with_agent(&["analysis:reasoning"], c.owner_agent);
    let (status, body) = analyze(addr, &scoped, request).await;
    assert_eq!(status, 200, "the scoped token must be served: {body}");
}
