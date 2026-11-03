//! MCP `sheaf_cohomology`, `reconcile_sheaf` and `check_sheaf_consistency`
//! must stop reporting an edge once one of its endpoints is retired
//! (`is_current = false`), per DD-20 (backlog 174ffd23).
//!
//! Observed: `463f1056 -contradicts-> a6821df8` stayed the #2 obstruction of
//! the whole graph after its author superseded a6821df8. Supersession leaves
//! `contradicts` / `refutes` on the retired claim by design (issue #398), so
//! the reads have to exclude it.
//!
//! Each test seeds a current-current control pair and a contested pair, reads
//! once with everything current (both pairs must be reported: proves the
//! scan is live and the contested pair is an obstruction in its own right),
//! then retires the contested TARGET and reads again.
//!
//! Numbers (scientific profile, contradicts 0.9): a contradictor at Bel 0.9
//! caps its target's Pl at 1 - 0.9 * 0.9 = 0.19, so a target at Bel 0.8
//! exceeds it by 0.61.

mod common;
#[path = "viewer_fixture.rs"]
mod fixture;

use common::{build_test_server, seed_agent};
use epigraph_mcp::tools::sheaf::{check_sheaf_consistency, reconcile_sheaf, sheaf_cohomology};
use epigraph_mcp::types::{
    CheckSheafConsistencyParams, ReconcileSheafParams, SheafCohomologyParams,
};
use epigraph_mcp::EpiGraphMcpFull;
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
    .bind(format!("sheaf retired-endpoint probe {id}"))
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

/// Retire a claim the way supersede / mark_duplicate leave it: not current,
/// no embedding (the fixture claims have none), edges untouched.
async fn retire(pool: &PgPool, id: Uuid) {
    let n = sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("retire")
        .rows_affected();
    assert_eq!(n, 1, "retired exactly the seeded claim");
}

struct Seed {
    ctl_src: Uuid,
    ctl_tgt: Uuid,
    contester: Uuid,
    retired: Uuid,
}

async fn seed(pool: &PgPool) -> Seed {
    let ctl_src = claim(pool, 0.9, 0.9).await;
    let ctl_tgt = claim(pool, 0.8, 0.9).await;
    edge(pool, ctl_src, ctl_tgt, "contradicts").await;
    let contester = claim(pool, 0.9, 0.9).await;
    let retired = claim(pool, 0.8, 0.9).await;
    edge(pool, contester, retired, "contradicts").await;
    Seed {
        ctl_src,
        ctl_tgt,
        contester,
        retired,
    }
}

async fn cohomology(server: &EpiGraphMcpFull, pool: &PgPool) -> Value {
    let out = sheaf_cohomology(
        server,
        &fixture::public_viewer(pool).await,
        SheafCohomologyParams {
            threshold: Some(0.05),
        },
    )
    .await
    .expect("sheaf_cohomology");
    common::first_text(&out)
}

fn has_obstruction(body: &Value, source: Uuid, target: Uuid) -> bool {
    body["obstructions"]
        .as_array()
        .expect("obstructions array")
        .iter()
        .any(|o| o["source_id"] == source.to_string() && o["target_id"] == target.to_string())
}

fn count(body: &Value) -> u64 {
    body["obstruction_count"]
        .as_u64()
        .expect("obstruction_count")
}

#[sqlx::test(migrations = "../../migrations")]
async fn cohomology_drops_the_obstruction_of_a_retired_endpoint(pool: PgPool) {
    let s = seed(&pool).await;
    let server = build_test_server(pool.clone());

    let before = cohomology(&server, &pool).await;
    assert!(
        has_obstruction(&before, s.ctl_src, s.ctl_tgt)
            && has_obstruction(&before, s.contester, s.retired),
        "precondition: both contradicts pairs are obstructions while current; got {before}"
    );

    retire(&pool, s.retired).await;
    let after = cohomology(&server, &pool).await;
    assert!(
        has_obstruction(&after, s.ctl_src, s.ctl_tgt),
        "control: the current pair is still an obstruction; got {after}"
    );
    assert!(
        !has_obstruction(&after, s.contester, s.retired),
        "an edge to a retired claim must not be reported as an obstruction"
    );
    assert_eq!(
        count(&after),
        count(&before) - 1,
        "obstruction_count must drop by exactly the retired pair"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn reconcile_does_not_reconcile_a_retired_endpoint(pool: PgPool) {
    let s = seed(&pool).await;
    retire(&pool, s.retired).await;

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
    let updated: Vec<String> = body["updated_intervals"]
        .as_array()
        .expect("updated_intervals array")
        .iter()
        .map(|u| u["node_id"].as_str().expect("node_id").to_string())
        .collect();

    assert!(
        updated.contains(&s.ctl_tgt.to_string()) || updated.contains(&s.ctl_src.to_string()),
        "control: the current contradicts pair is reconciled; got {updated:?}"
    );
    for id in [s.retired, s.contester] {
        assert!(
            !updated.contains(&id.to_string()),
            "{id} is constrained only by an edge to a retired claim and must not be \
             reconciled; got {updated:?}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn consistency_has_no_section_for_a_retired_endpoint(pool: PgPool) {
    let s = seed(&pool).await;
    retire(&pool, s.retired).await;

    let server = build_test_server(pool.clone());
    let out = check_sheaf_consistency(
        &server,
        &fixture::public_viewer(&pool).await,
        CheckSheafConsistencyParams {
            min_radius: Some(0.0),
            limit: Some(200),
            profile: None,
        },
    )
    .await
    .expect("check_sheaf_consistency");
    let body = common::first_text(&out);
    let nodes: Vec<String> = body["sections"]
        .as_array()
        .expect("sections array")
        .iter()
        .map(|sec| sec["node_id"].as_str().expect("node_id").to_string())
        .collect();

    assert!(
        nodes.contains(&s.ctl_tgt.to_string()),
        "control: the current pair has a section; got {nodes:?}"
    );
    assert!(
        !nodes.contains(&s.retired.to_string()),
        "a retired claim must not get a consistency section; got {nodes:?}"
    );
    assert!(
        !nodes.contains(&s.contester.to_string()),
        "a current claim whose only neighbour is retired has no neighbourhood; got {nodes:?}"
    );
}
