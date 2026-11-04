//! Ruling R-22 (generalised to every claim, R-71): a claim's cached belief
//! folds only BBAs whose every source is at least as widely readable as the
//! claim, decided by `DerivationScopeRepository::cache_admissible`, which is
//! written INCLUSIVELY ("include iff the source is visible") so that a
//! maintenance connection and an application session give the same answer.
//!
//! # What this pins
//!
//! Every other cache test recomputes on the superuser harness pool, where row
//! security is bypassed. Here one recompute of a GROUP claim (group A, with
//! one BBA from group A's own source and one from group B's) runs on the
//! harness pool and again on an `epigraph_app` session stamped as each of two
//! members (one of A and B, one of A only), where row security applies; the
//! cached interval must be the same every time. If admissibility were judged
//! on what the session can see, a group claim's cache would differ by who
//! recomputed it (or stop updating with no error).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_engine::edge_factor::{
    auto_wire_ds_for_edge, ensure_binary_frame, recompute_claim_cached_belief, EdgeFactorOutcome,
};
use sqlx::PgPool;
use uuid::Uuid;

async fn with_interval(pool: &PgPool, claim: Uuid, bel: f64, pl: f64) {
    sqlx::query("UPDATE claims SET belief = $2, plausibility = $3 WHERE id = $1")
        .bind(claim)
        .bind(bel)
        .bind(pl)
        .execute(pool)
        .await
        .expect("set the source interval");
}

async fn wire(pool: &PgPool, viewer: &Viewer, signer: Uuid, edge: Uuid, from: Uuid, to: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = auto_wire_ds_for_edge(&mut conn, viewer, edge, signer, from, to, "supports")
        .await
        .expect("wire the edge factor");
    assert_eq!(out, EdgeFactorOutcome::Wired, "PREMISE: the edge wires");
}

async fn team_group(pool: &PgPool, label: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind) \
         VALUES ($1, 'did:test:r22adm:' || gen_random_uuid(), decode(repeat('ab', 32), 'hex'), \
                 'team') RETURNING id",
    )
    .bind(label)
    .fetch_one(pool)
    .await
    .expect("team group")
}

async fn join(pool: &PgPool, group: Uuid, agent: Uuid) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'admin')",
    )
    .bind(group)
    .bind(agent)
    .execute(pool)
    .await
    .expect("membership");
}

async fn cached(pool: &PgPool, claim: Uuid) -> (Option<f64>, Option<f64>, Option<f64>) {
    sqlx::query_as("SELECT pignistic_prob, belief, plausibility FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("cache")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_group_claims_recompute_agrees_on_the_app_role_and_on_maintenance(pool: PgPool) {
    let public = fixture::public_viewer(&pool).await;
    let group_a = team_group(&pool, "r22 adm A").await;
    let group_b = team_group(&pool, "r22 adm B").await;
    let (both, _) = fixture::seed_agent_with_group(&pool, "r22-adm-both").await;
    let (only_a, _) = fixture::seed_agent_with_group(&pool, "r22-adm-only-a").await;
    join(&pool, group_a, both).await;
    join(&pool, group_b, both).await;
    join(&pool, group_a, only_a).await;
    let both_viewer = Viewer::resolve(&pool, both).await.expect("viewer");
    let a_viewer = Viewer::resolve(&pool, only_a).await.expect("viewer");
    ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &public)
        .await
        .expect("binary_truth");

    let target = fixture::seed_group_claim(&pool, both, group_a, "r22 adm A target").await;
    let a_source = fixture::seed_group_claim(&pool, both, group_a, "r22 adm A source").await;
    let b_source = fixture::seed_group_claim(&pool, both, group_b, "r22 adm B source").await;
    with_interval(&pool, a_source, 0.6, 0.8).await;
    with_interval(&pool, b_source, 0.9, 0.95).await;
    let a_edge = fixture::seed_edge(&pool, a_source, target).await;
    wire(&pool, &both_viewer, both, a_edge, a_source, target).await;
    let b_edge = fixture::seed_edge(&pool, b_source, target).await;
    wire(&pool, &both_viewer, both, b_edge, b_source, target).await;

    // Maintenance (the harness superuser, row security bypassed).
    let mut conn = pool.acquire().await.expect("acquire");
    recompute_claim_cached_belief(&mut conn, &both_viewer, target)
        .await
        .expect("recompute on maintenance");
    drop(conn);
    let maintenance = cached(&pool, target).await;
    assert!(maintenance.0.is_some(), "PREMISE: the cache is filled");

    // The application role, stamped as each member in turn, after clearing
    // the cache so the value is this session's own.
    let url = fixture::database_url_for(&pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    for viewer in [&both_viewer, &a_viewer] {
        sqlx::query(
            "UPDATE claims SET pignistic_prob = NULL, belief = NULL, plausibility = NULL \
              WHERE id = $1",
        )
        .bind(target)
        .execute(&pool)
        .await
        .expect("clear the cache");
        let mut tx = scoped.begin_as(viewer).await.expect("stamped app session");
        recompute_claim_cached_belief(&mut tx, viewer, target)
            .await
            .expect("recompute on the application role");
        tx.commit().await.expect("commit");
        let app = cached(&pool, target).await;
        let close = |x: Option<f64>, y: Option<f64>| match (x, y) {
            (Some(x), Some(y)) => (x - y).abs() < 1e-9,
            _ => false,
        };
        assert!(
            close(app.0, maintenance.0)
                && close(app.1, maintenance.1)
                && close(app.2, maintenance.2),
            "a member's recompute on the application role cached {app:?}, maintenance cached \
             {maintenance:?}: the inclusive rule must give one answer whoever recomputes"
        );
    }
}
