//! MCP `sheaf_cohomology` and `reconcile_sheaf` must score upper-case
//! epistemic edges exactly like their lower-case spelling.
//!
//! Writers store the same relationship in more than one spelling (MCP
//! `link_epistemic` writes `supports`; the HTTP edge route, the DS evidence
//! writers and the cross-source matcher write `SUPPORTS`). Two links must hold
//! for an upper-case edge to reach H1:
//! - `SheafRepository::get_epistemic_edge_pairs` must return it (it matches
//!   the relationship list case-insensitively), and
//! - `compute_cdst_edge_inconsistency` must restrict it as Positive /
//!   Negative, not Neutral (`restriction_kind_with_profile` folds case).
//!
//! The DB tests pin the first link only. These tests pin both, through the
//! tools themselves, as `check_sheaf_consistency_neighbourhood.rs::
//! upper_case_relationships_are_read` does for consistency.
//!
//! Numbers (scientific profile: supports 0.8, contradicts 0.9):
//! - a supporter at Bel 0.9 sets a Bel floor of 0.8 * 0.9 = 0.72 on its
//!   target, so a target at Bel 0.1 falls 0.62 short;
//! - a contradictor at Bel 0.9 sets a Pl ceiling of 1 - 0.9 * 0.9 = 0.19 on its
//!   target, so a target at Bel 0.8 exceeds it by 0.61.
//!
//! A `Neutral` restriction (expected = target) would score both edges 0.

mod common;
#[path = "viewer_fixture.rs"]
mod fixture;

use common::{build_test_server, seed_agent};
use epigraph_mcp::tools::sheaf::{reconcile_sheaf, sheaf_cohomology};
use epigraph_mcp::types::{ReconcileSheafParams, SheafCohomologyParams};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// A public, current claim with an explicit belief interval and
/// BetP = (bel + pl) / 2.
async fn claim(pool: &PgPool, bel: f64, pl: f64) -> Uuid {
    let agent = seed_agent(pool).await;
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, \
                             belief, plausibility, pignistic_prob, is_current, labels) \
         VALUES ($1, $2, $3, $4, 0.5, $5, $6, $7, true, ARRAY[]::text[])",
    )
    .bind(id)
    .bind(format!("sheaf cohomology case probe {id}"))
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

async fn edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', $3, '{}'::jsonb)",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("insert edge");
}

/// The obstruction on the edge `source -> target`, if the tool reported one.
fn obstruction(obstructions: &[Value], source: Uuid, target: Uuid) -> Option<&Value> {
    obstructions
        .iter()
        .find(|o| o["source_id"] == source.to_string() && o["target_id"] == target.to_string())
}

fn inconsistency(o: &Value) -> f64 {
    o["edge_inconsistency"]
        .as_f64()
        .expect("edge_inconsistency")
}

/// A lower-case control, an upper-case `SUPPORTS` under-support and an
/// upper-case `CONTRADICTS` ceiling breach, each on its own pair: all three are
/// obstructions with the magnitude their restriction kind implies, and the
/// relationship is reported as stored.
#[sqlx::test(migrations = "../../migrations")]
async fn cohomology_scores_upper_case_edges_like_lower_case(pool: PgPool) {
    // Control: today's lower-case spelling.
    let lower_src = claim(&pool, 0.9, 0.9).await;
    let lower_tgt = claim(&pool, 0.1, 0.2).await;
    edge(&pool, lower_src, lower_tgt, "supports").await;

    let sup_src = claim(&pool, 0.9, 0.9).await;
    let sup_tgt = claim(&pool, 0.1, 0.2).await;
    edge(&pool, sup_src, sup_tgt, "SUPPORTS").await;

    let con_src = claim(&pool, 0.9, 0.9).await;
    let con_tgt = claim(&pool, 0.8, 0.9).await;
    edge(&pool, con_src, con_tgt, "CONTRADICTS").await;

    let server = build_test_server(pool.clone());
    let out = sheaf_cohomology(
        &server,
        &fixture::public_viewer(&pool).await,
        SheafCohomologyParams {
            threshold: Some(0.05),
        },
    )
    .await
    .expect("sheaf_cohomology");
    let body = common::first_text(&out);
    let obstructions = body["obstructions"].as_array().expect("obstructions array");

    let control = obstruction(obstructions, lower_src, lower_tgt).expect(
        "control: the lower-case `supports` under-support must be an obstruction, \
         otherwise this test cannot tell a case defect from a dead scan",
    );
    assert!(
        (inconsistency(control) - 0.62).abs() < 1e-9,
        "control: supports floor shortfall 0.8*0.9 - 0.1 = 0.62, got {}",
        inconsistency(control)
    );

    let sup = obstruction(obstructions, sup_src, sup_tgt)
        .expect("the SUPPORTS under-support must reach H1 as an obstruction");
    assert!(
        (inconsistency(sup) - 0.62).abs() < 1e-9,
        "SUPPORTS restricts like supports (Positive 0.8): 0.62, got {}",
        inconsistency(sup)
    );
    assert_eq!(
        sup["relationship"], "SUPPORTS",
        "the relationship is reported as stored"
    );

    let con = obstruction(obstructions, con_src, con_tgt)
        .expect("the CONTRADICTS ceiling breach must reach H1 as an obstruction");
    assert!(
        (inconsistency(con) - 0.61).abs() < 1e-9,
        "CONTRADICTS restricts like contradicts (Negative 0.9): ceiling 0.19, \
         excess 0.8 - 0.19 = 0.61, got {}",
        inconsistency(con)
    );
    assert_eq!(con["relationship"], "CONTRADICTS");
}

/// `reconcile_sheaf` builds its clusters from the same obstructions, so an
/// upper-case edge the scan dropped would leave its endpoints out of every
/// cluster and out of `updated_intervals`.
#[sqlx::test(migrations = "../../migrations")]
async fn reconcile_takes_upper_case_edges_as_constraints(pool: PgPool) {
    let lower_src = claim(&pool, 0.9, 0.9).await;
    let lower_tgt = claim(&pool, 0.1, 0.2).await;
    edge(&pool, lower_src, lower_tgt, "supports").await;

    let sup_src = claim(&pool, 0.9, 0.9).await;
    let sup_tgt = claim(&pool, 0.1, 0.2).await;
    edge(&pool, sup_src, sup_tgt, "SUPPORTS").await;

    let server = build_test_server(pool.clone());
    let out = reconcile_sheaf(
        &server,
        &fixture::public_viewer(&pool).await,
        ReconcileSheafParams {
            min_inconsistency: Some(0.15),
            max_depth: None,
            profile: None,
        },
    )
    .await
    .expect("reconcile_sheaf");
    let body = common::first_text(&out);
    let updated: Vec<&str> = body["updated_intervals"]
        .as_array()
        .expect("updated_intervals array")
        .iter()
        .map(|u| u["node_id"].as_str().expect("node_id"))
        .collect();

    // Both edges are 0.62 floor shortfalls, above min_inconsistency 0.15, so
    // each puts its pair into a reconciled cluster.
    assert!(
        updated.contains(&lower_tgt.to_string().as_str()),
        "control: the lower-case `supports` target must be reconciled, otherwise \
         this test cannot tell a case defect from a dead scan; got {updated:?}"
    );
    assert!(
        updated.contains(&sup_tgt.to_string().as_str()),
        "the SUPPORTS target must be reconciled like the supports one; got {updated:?}"
    );
}
