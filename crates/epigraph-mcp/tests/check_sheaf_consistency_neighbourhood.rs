//! `check_sheaf_consistency` reads every claim's WHOLE in-force epistemic
//! neighbourhood and scores it with `build_cdst_sections` (drain U030 PR 2;
//! backlog d74bd078 / 4d7f1557).
//!
//! Each test pins one way the pre-U030 consumer misread the graph, through the
//! MCP tool itself (its signature does not change, so every test compiles on
//! the old code and fails there on an assertion):
//! - the SOURCE of a `supports` edge was scored against a floor taken from its
//!   own target (live example 04b7055e);
//! - `ORDER BY c.id LIMIT limit*10` cut a claim's neighbour list mid-claim;
//! - retracted edges (`valid_to` in the past) still contributed neighbours;
//! - `relationship IN ('supports', …)` was case-sensitive, so the UPPER-case
//!   spellings that most prod edges carry (premeasure U030-q5: 4,409 rows
//!   lowercase vs 21,717 case-insensitive) were invisible;
//! - `params.profile` was documented but ignored.
//!
//! Numbers: a supporter at Bel 0.9 transmits a one-sided Bel floor of
//! f·0.9 (f = 0.8 scientific, 0.95 regulatory), so a target at Bel 0.1 has
//! radius 0.72 - 0.1 = 0.62 (scientific) or 0.855 - 0.1 = 0.755 (regulatory).

mod common;
#[path = "viewer_fixture.rs"]
mod fixture;

use common::{build_test_server, seed_agent};
use epigraph_mcp::tools::sheaf::check_sheaf_consistency;
use epigraph_mcp::types::CheckSheafConsistencyParams;
use epigraph_mcp::EpiGraphMcpFull;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// A public, current claim with an explicit belief interval and
/// BetP = (bel + pl) / 2, under `id` when one is given.
async fn claim(pool: &PgPool, id: Option<Uuid>, bel: f64, pl: f64) -> Uuid {
    let agent = seed_agent(pool).await;
    let id = id.unwrap_or_else(Uuid::new_v4);
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, \
                             belief, plausibility, pignistic_prob, is_current, labels) \
         VALUES ($1, $2, $3, $4, 0.5, $5, $6, $7, true, ARRAY[]::text[])",
    )
    .bind(id)
    .bind(format!("u030 sheaf neighbourhood probe {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(bel)
    .bind(pl)
    .bind((bel + pl) / 2.0)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', $3, '{}'::jsonb) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .expect("insert edge")
}

async fn sections(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    limit: i64,
    profile: Option<&str>,
) -> Vec<Value> {
    let out = check_sheaf_consistency(
        server,
        &fixture::public_viewer(pool).await,
        CheckSheafConsistencyParams {
            min_radius: Some(0.0),
            limit: Some(limit),
            profile: profile.map(str::to_string),
        },
    )
    .await
    .expect("check_sheaf_consistency");
    let body = common::first_text(&out);
    body["sections"].as_array().expect("sections array").clone()
}

fn section_of(sections: &[Value], id: Uuid) -> Option<&Value> {
    sections.iter().find(|s| s["node_id"] == id.to_string())
}

fn radius(s: &Value) -> f64 {
    s["consistency_radius"].as_f64().expect("radius")
}

/// 04b7055e's shape: a weak claim whose only epistemic edge is an OUTGOING
/// `supports` to a strong claim. `src -[supports]-> dst` constrains dst only,
/// so the supporter must not inherit a floor from its target.
#[sqlx::test(migrations = "../../migrations")]
async fn a_weak_supporter_is_not_flagged_by_its_strong_target(pool: PgPool) {
    let weak = claim(&pool, None, 0.1, 0.2).await;
    let strong = claim(&pool, None, 0.9, 0.9).await;
    edge(&pool, weak, strong, "supports").await;

    let server = build_test_server(pool.clone());
    let all = sections(&server, &pool, 200, None).await;

    let s = section_of(&all, weak)
        .expect("the supporter is still examined (it has an edge), so it gets a section");
    assert!(
        radius(s) < 1e-9,
        "a supporter is not constrained by its target: radius must be 0, got {} \
         (0.62 = the target's floor 0.8*0.9 - 0.1 applied to the WRONG end)",
        radius(s)
    );
    assert_eq!(
        s["neighbor_count"], 0,
        "the outgoing supports row is skipped"
    );
}

/// The old SQL ended `ORDER BY c.id LIMIT limit*10`, so `limit = 1` read 10
/// rows: a hub whose id sorts first and has 12 supporters lost 2 of them.
#[sqlx::test(migrations = "../../migrations")]
async fn a_hub_keeps_its_whole_neighbourhood_past_the_old_row_cap(pool: PgPool) {
    let hub = claim(
        &pool,
        Some(Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap()),
        0.1,
        0.2,
    )
    .await;
    for _ in 0..12 {
        let supporter = claim(&pool, None, 0.9, 0.9).await;
        edge(&pool, supporter, hub, "supports").await;
    }

    let server = build_test_server(pool.clone());
    let top = sections(&server, &pool, 1, None).await;

    assert_eq!(
        top.len(),
        1,
        "limit truncates the OUTPUT to the worst section"
    );
    assert_eq!(
        top[0]["node_id"],
        hub.to_string(),
        "the under-supported hub (radius 0.62) is the worst node; its supporters \
         score 0 because outgoing supports rows are skipped"
    );
    assert_eq!(
        top[0]["neighbor_count"], 12,
        "every one of the hub's 12 supporters must reach its section"
    );
}

/// A retracted edge (`valid_to` in the past) is no longer asserted by anyone,
/// so it must not manufacture an inconsistency (as `get_epistemic_edge_pairs`
/// already guarantees for the cohomology scan).
#[sqlx::test(migrations = "../../migrations")]
async fn a_retracted_edge_contributes_no_neighbour(pool: PgPool) {
    let weak = claim(&pool, None, 0.1, 0.2).await;
    let strong = claim(&pool, None, 0.9, 0.9).await;
    let e = edge(&pool, strong, weak, "supports").await;

    let server = build_test_server(pool.clone());
    let before = sections(&server, &pool, 200, None).await;
    let s = section_of(&before, weak).expect("PREMISE: the in-force edge flags the weak target");
    assert!(
        (radius(s) - 0.62).abs() < 1e-9,
        "PREMISE: under-support shortfall 0.72 - 0.1 = 0.62, got {}",
        radius(s)
    );

    let closed = epigraph_db::EdgeRepository::retract(&pool, &[e])
        .await
        .expect("retract");
    assert_eq!(closed, vec![e], "PREMISE: retract closed the edge");

    let after = sections(&server, &pool, 200, None).await;
    assert!(
        section_of(&after, weak).is_none(),
        "with its only edge retracted the claim has no neighbourhood, so no section; \
         got {:?}",
        section_of(&after, weak)
    );
}

/// Most prod edges are UPPER-case (premeasure U030-q5). The consumer must read
/// them: an under-supported claim whose supporter is linked by `SUPPORTS` is
/// flagged exactly as one linked by `supports`.
#[sqlx::test(migrations = "../../migrations")]
async fn upper_case_relationships_are_read(pool: PgPool) {
    let weak = claim(&pool, None, 0.1, 0.2).await;
    let strong = claim(&pool, None, 0.9, 0.9).await;
    edge(&pool, strong, weak, "SUPPORTS").await;

    let stored: String = sqlx::query_scalar(
        "SELECT relationship FROM edges WHERE source_id = $1 AND target_id = $2",
    )
    .bind(strong)
    .bind(weak)
    .fetch_one(&pool)
    .await
    .expect("read back");
    assert_eq!(
        stored, "SUPPORTS",
        "PREMISE: the spelling is stored as written"
    );

    let server = build_test_server(pool.clone());
    let all = sections(&server, &pool, 200, None).await;
    let s = section_of(&all, weak).expect("the SUPPORTS edge must reach the scan");
    assert!(
        (radius(s) - 0.62).abs() < 1e-9,
        "SUPPORTS restricts like supports (Positive 0.8): 0.62, got {}",
        radius(s)
    );
    let source = section_of(&all, strong).expect("the source has a section too");
    assert_eq!(
        source["neighbor_count"], 0,
        "the direction rule is case-insensitive too: the SUPPORTS source is skipped"
    );
}

/// `profile` is documented on the tool ("'scientific' (default) or
/// 'regulatory'") and must change the transmission factor.
#[sqlx::test(migrations = "../../migrations")]
async fn the_regulatory_profile_tightens_the_floor(pool: PgPool) {
    let weak = claim(&pool, None, 0.1, 0.2).await;
    let strong = claim(&pool, None, 0.9, 0.9).await;
    edge(&pool, strong, weak, "supports").await;

    let server = build_test_server(pool.clone());
    let scientific = sections(&server, &pool, 200, None).await;
    let regulatory = sections(&server, &pool, 200, Some("regulatory")).await;

    let sci = radius(section_of(&scientific, weak).expect("scientific section"));
    let reg = radius(section_of(&regulatory, weak).expect("regulatory section"));
    assert!(
        (sci - 0.62).abs() < 1e-9,
        "scientific: 0.8*0.9 - 0.1 = 0.62, got {sci}"
    );
    assert!(
        (reg - 0.755).abs() < 1e-9,
        "regulatory: 0.95*0.9 - 0.1 = 0.755, got {reg}"
    );
}

/// The neighbour's Bel (not its BetP) sets a Positive floor, as in U029's
/// edge arm: a supporter at [0.7, 1.0] (BetP 0.85) floors its target at
/// 0.8*0.7 = 0.56, not 0.8*0.85 = 0.68. The old query returned no neighbour
/// Bel/Pl, so the consumer used the point interval at BetP.
#[sqlx::test(migrations = "../../migrations")]
async fn the_floor_uses_the_neighbours_belief_not_its_betp(pool: PgPool) {
    let weak = claim(&pool, None, 0.1, 0.2).await;
    let wide = claim(&pool, None, 0.7, 1.0).await;
    edge(&pool, wide, weak, "supports").await;

    let server = build_test_server(pool.clone());
    let all = sections(&server, &pool, 200, None).await;
    let r = radius(section_of(&all, weak).expect("the weak target is flagged"));
    assert!(
        (r - 0.46).abs() < 1e-9,
        "floor 0.8*Bel 0.7 = 0.56, minus Bel 0.1 = 0.46; 0.58 means BetP was used. Got {r}"
    );
}
