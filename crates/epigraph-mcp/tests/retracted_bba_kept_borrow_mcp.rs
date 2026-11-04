//! SPEC §11 phase 1, S-1 (migration 194; H10) under SPEC §12's
//! "App session and borrow" rule: a `claims:admin` caller that supersedes a
//! claim in a group it does not write BORROWS this server's own agent's stamp
//! (`tools::supersede::begin_claim_act` ->
//! `EpiGraphMcpFull::admin_borrowed_server_identity`). With 194 applied, that
//! act and its belief cascade complete over a RETRACTED edge-keyed BBA: no
//! SR09 (H10) and no RT07 (184) anywhere, the retracted row is kept, and no
//! `cascade.admin_failed` row is written.
//!
//! REGRESSION PIN, not a red test (SPEC §12's exception): after K4a no MCP
//! tool deletes a retracted BBA, so this cannot fail on the K4a base. It pins
//! that the borrow path stays that way once H10 refuses such a delete.
//!
//! The borrow is proved, not assumed: the same token is first refused ADM02
//! (its client record grants no live `claims:admin`, so it may not borrow) with
//! nothing written, then succeeds once the grant is seeded.
//!
//! The act runs on the harness pool, as `supersede_claim_test.rs`'s borrow
//! tests do. On `epigraph_app` pools the borrowed act itself is refused before
//! any cascade, an `internal_error` from the act's own write (measured while
//! building this file). That refusal touches no `mass_functions` row and is
//! coded-denial work for SPEC §11 K5, not H10's. The CASCADE is H10's surface:
//! the inline cascade and the deferred replay run on a NOSUPERUSER
//! `epigraph_maintenance` login, the privileged deleter SPEC §10.1 orders the
//! 194 deploy behind. The retracted row is made by migration 184's definer on
//! the application role.

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "../../epigraph-db/tests/support/retracted_bba_fixture.rs"]
mod retracted;

mod common;
use common::*;

use epigraph_db::{MassFunctionRepository, ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::supersede::supersede_claim;
use epigraph_mcp::types::SupersedeClaimParams;
use retracted::{retract_through_definer, row_state};
use sqlx::PgPool;
use uuid::Uuid;

/// The harness `ScopedPool` the borrowed act runs on; with `inline`, its
/// maintenance pool is a NOSUPERUSER `epigraph_maintenance` login, so the
/// cascade runs in the call on that login.
async fn server(pool: &PgPool, inline: bool) -> EpiGraphMcpFull {
    let mut scoped = fixture::scoped_pool(pool).await;
    if inline {
        let m = fixture::downgraded_pool(pool, "epigraph_maintenance").await;
        let (superuser, privileged): (bool, bool) = sqlx::query_as(
            "SELECT r.rolsuper, public.epigraph_bypass() FROM pg_roles r \
              WHERE r.rolname = current_user",
        )
        .fetch_one(&m)
        .await
        .expect("read the maintenance login");
        assert!(
            !superuser && privileged,
            "fixture: a NOSUPERUSER maintenance login"
        );
        scoped = scoped.with_maintenance_pool(m);
    }
    build_scoped_test_server(pool.clone(), scoped)
}

async fn claim_of(pool: &PgPool, agent: Uuid, group: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("{content} {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// A claim-to-claim edge written on the harness, and its edge-factor
/// perspective.
async fn edge(pool: &PgPool, source: Uuid, target: Uuid) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports') RETURNING id",
    )
    .bind(source)
    .bind(target)
    .fetch_one(pool)
    .await
    .expect("seed edge");
    sqlx::query(
        "INSERT INTO perspectives (id, name, perspective_type) VALUES ($1, 'edge_factor', 'edge')",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("seed the edge's perspective");
    id
}

async fn frame(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("h10-borrow-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed frame")
}

/// The supersede fixture: `author`'s claim `old` supports another writer's
/// claim `b`; the edge-keyed BBA on `b` was retracted by `b`'s group writer.
/// Neither group is the server agent's, so a `claims:admin` caller borrows.
struct World {
    old: Uuid,
    old_group: Uuid,
    b: Uuid,
    b_group: Uuid,
    retracted: Uuid,
}

async fn world(pool: &PgPool) -> World {
    let (author, ag) = fixture::seed_agent_with_group(pool, "h10-borrow-author").await;
    let (x, xg) = fixture::seed_agent_with_group(pool, "h10-borrow-x").await;
    let old = claim_of(pool, author, ag, "h10 borrow supporter").await;
    let b = claim_of(pool, x, xg, "h10 borrow downstream").await;
    let e = edge(pool, old, b).await;
    let f = frame(pool).await;
    let retracted = MassFunctionRepository::store_with_perspective(
        pool,
        b,
        f,
        Some(author),
        Some(e),
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        Some("edge_factor"),
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("store a BBA");
    retract_through_definer(pool, retracted).await;
    World {
        old,
        old_group: ag,
        b,
        b_group: xg,
        retracted,
    }
}

fn params(claim: Uuid) -> SupersedeClaimParams {
    SupersedeClaimParams {
        claim_id: claim.to_string(),
        content: format!("an admin correction of {claim}"),
        truth_value: 0.6,
        reason: "h10 borrow".to_string(),
    }
}

async fn is_current(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT COALESCE(is_current, true) FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read is_current")
}

/// Every `cascade.admin_failed` row, and every security event whose details
/// carry H10's or 184's refusal code.
async fn failures(pool: &PgPool) -> (i64, i64) {
    sqlx::query_as(
        "SELECT count(*) FILTER (WHERE event_type = 'cascade.admin_failed'), \
                count(*) FILTER (WHERE details::text LIKE '%SR09%' OR details::text LIKE '%RT07%') \
           FROM security_events",
    )
    .fetch_one(pool)
    .await
    .expect("read security events")
}

#[sqlx::test(migrations = "../../migrations")]
async fn supersede_claim_under_the_claims_admin_borrow_keeps_a_retracted_edge_bba_with_194(
    pool: PgPool,
) {
    let h10: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_trigger \
                         WHERE tgrelid = 'public.mass_functions'::regclass \
                           AND tgname = 'mass_functions_retracted_delete_guard')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(h10, "fixture: migration 194's H10 trigger is installed");

    let server = server(&pool, true).await;
    let w = world(&pool).await;
    let (auth, admin_viewer) = server_admin(&server).await;
    for g in [w.old_group, w.b_group] {
        assert!(
            !admin_viewer.writable_groups().contains(&g),
            "fixture: the server agent does not write group {g}, so the admin act borrows"
        );
    }

    // 1. No live grant on the token's client record: the borrow is refused
    //    ADM02 and nothing is written. This proves the act below takes the
    //    borrow arm (a caller writing the group would not reach the re-check).
    let err = supersede_claim(&server, &admin_viewer, params(w.old), Some(&auth))
        .await
        .expect_err("a claims:admin token without a live grant may not borrow");
    assert!(err.message.contains("ADM02"), "{}", err.message);
    assert!(
        is_current(&pool, w.old).await,
        "the refused act wrote nothing"
    );

    // 2. The same token with its live grant: the act borrows the server's stamp.
    seed_admin_grant(&pool, &auth).await;
    let r = supersede_claim(&server, &admin_viewer, params(w.old), Some(&auth))
        .await
        .expect("the borrowed supersede completes with a retracted BBA on the re-pointed edge");
    let body = first_text(&r);
    assert!(!is_current(&pool, w.old).await, "the act retired the claim");
    assert_eq!(body["cascade"]["status"], "applied", "{body}");
    let cascade = &body["belief_cascade"];
    assert_eq!(
        cascade["errors"],
        serde_json::json!([]),
        "the cascade completes with no error: {cascade}"
    );
    assert_eq!(
        cascade["retracted_key_kept"], 1,
        "the cascade counts the kept retracted key: {cascade}"
    );
    assert_eq!(
        row_state(&pool, w.retracted).await,
        Some((w.b, true)),
        "the retracted edge BBA is kept for audit"
    );
    assert_eq!(
        failures(&pool).await,
        (0, 0),
        "no cascade.admin_failed row, and no SR09 / RT07 anywhere in security_events"
    );
}

async fn replay_now(pool: &PgPool) -> epigraph_engine::admin_cascade::ReplayReport {
    let url = fixture::database_url_for(pool).await;
    let maintenance = fixture::downgraded_pool(pool, "epigraph_maintenance").await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("ScopedPool")
            .with_maintenance_pool(maintenance);
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance session");
    session
        .assert_privileged()
        .await
        .expect("the replay's connection is privileged");
    let (conn, admin_viewer) = session.split();
    epigraph_engine::admin_cascade::replay_deferred(
        conn,
        admin_viewer,
        "h10-borrow",
        50,
        epigraph_engine::admin_cascade::DEFAULT_MAX_FAILURES,
    )
    .await
    .expect("replay")
}

/// The same borrowed act with no maintenance connection: the cascade is
/// deferred under the borrowed stamp, and the maintenance replay keeps the
/// retracted edge BBA and applies without a failure row.
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_claim_under_the_claims_admin_borrow_deferred_replay_keeps_a_retracted_edge_bba_with_194(
    pool: PgPool,
) {
    let server = server(&pool, false).await;
    let w = world(&pool).await;
    let (auth, admin_viewer) = granted_server_admin(&server, &pool).await;
    for g in [w.old_group, w.b_group] {
        assert!(
            !admin_viewer.writable_groups().contains(&g),
            "fixture: the server agent does not write group {g}, so the admin act borrows"
        );
    }
    let r = supersede_claim(&server, &admin_viewer, params(w.old), Some(&auth))
        .await
        .expect("the borrowed supersede");
    let body = first_text(&r);
    assert_eq!(body["cascade"]["status"], "deferred", "{body}");

    let report = replay_now(&pool).await;
    assert_eq!((report.applied, report.failed), (1, 0), "{report:?}");
    assert_eq!(
        row_state(&pool, w.retracted).await,
        Some((w.b, true)),
        "the replay keeps the retracted edge BBA"
    );
    assert_eq!(
        failures(&pool).await,
        (0, 0),
        "no cascade.admin_failed row, and no SR09 / RT07 anywhere in security_events"
    );
}
