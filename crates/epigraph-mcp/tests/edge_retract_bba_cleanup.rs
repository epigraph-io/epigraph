//! Migration 120: an edge's owner withdrawing it cleans up the BBAs keyed on
//! it, and the cross-owner half is administrative (D1).
//!
//! * (a) the owner's retract (`delete_edge`) deletes its OWN edge-keyed BBA in
//!   the act (`bba_cleanup.deleted`);
//! * (b) another writer's BBA on the same edge survives the act, is deferred as
//!   `cause = 'edge_retract'` naming the owner, and the maintenance replay
//!   removes it with a `cascade.admin_applied` row naming the owner;
//! * the owner cannot write the belief cache of a claim it does not own, so
//!   the deferral carries the claims its own deleted BBAs lived on and the
//!   replay re-derives them: the cache after the replay is exactly what a
//!   fresh recompute from the surviving rows writes, per claim;
//! * a replay of an `edge_retract` whose edge is back in force removes nothing
//!   and writes `admin_applied` with zero counts and a reason, never
//!   `admin_failed`;
//! * a future-dated `valid_to` records no deferral and removes nothing;
//! * the one-shot legacy sweep removes the BBAs of an edge withdrawn before
//!   any deferral existed, audited as `edge_retract` naming the acting
//!   operator, and never touches a genuine (non-edge) perspective's BBA, even
//!   one whose id equals a withdrawn edge's;
//! * the claims a deferral asks the replay to re-derive are STATE (the claims
//!   of the session's own edge-keyed rows, derived by the definer): a caller
//!   naming another writer's claims is refused, and their caches are untouched;
//! * two acts on one edge before a replay both reach it: the replay re-derives
//!   the claims of every open deferral of the edge, not only the oldest one's.
//!
//! Both MCP servers and every BBA write run on the application role
//! (`epigraph_app`); the replay and the sweep on a non-superuser
//! `epigraph_maintenance` connection.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::visibility::Viewer;
use epigraph_db::{FrameRepository, MassFunctionRepository, ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::edge_mutation::{do_delete_edge, do_patch_edge};
use epigraph_mcp::types::{DeleteEdgeParams, PatchEdgeParams};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

struct Side {
    server: EpiGraphMcpFull,
    agent: Uuid,
    group: Uuid,
    viewer: Viewer,
}

async fn app_role_pools(pool: &PgPool) -> (PgPool, ScopedPool) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(!bypassrls, "epigraph_app holds BYPASSRLS: vacuous");
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    (plain, scoped)
}

async fn side(pool: &PgPool, server: EpiGraphMcpFull) -> Side {
    let agent = server.server_agent_id().await.expect("server agent");
    let group = personal_group_of(pool, agent).await;
    let viewer = Viewer::resolve(pool, agent).await.expect("viewer");
    Side {
        server,
        agent,
        group,
        viewer,
    }
}

fn csv(ids: &[Uuid]) -> String {
    ids.iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

async fn stamp(conn: &mut PgConnection, pool: &PgPool, agent: Uuid) {
    let v = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(csv(v.group_bind().expect("scoped viewer")))
    .bind(csv(v.writable_groups()))
    .bind(agent.to_string())
    .execute(&mut *conn)
    .await
    .expect("stamp");
}

/// An edge `agent` writes on the application role, and its edge-factor
/// perspective (what `ensure_edge_perspective` creates when a BBA is wired).
async fn owned_edge(pool: &PgPool, agent: Uuid, a: Uuid, b: Uuid) -> Uuid {
    let p = pool.clone();
    let edge = fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, agent).await;
        let e: Uuid = sqlx::query_scalar(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
             VALUES ($1, 'claim', $2, 'claim', 'supports') RETURNING id",
        )
        .bind(a)
        .bind(b)
        .fetch_one(&mut *conn)
        .await
        .expect("the writer's edge");
        (conn, e)
    })
    .await;
    perspective(pool, edge, "edge").await;
    edge
}

async fn perspective(pool: &PgPool, id: Uuid, kind: &str) {
    sqlx::query("INSERT INTO perspectives (id, name, perspective_type) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(format!("w12b {kind} {id}"))
        .bind(kind)
        .execute(pool)
        .await
        .expect("seed perspective");
}

/// `agent`'s BBA on `claim`, keyed on `perspective`, written on the
/// application role (114 makes it the writer's row on a public claim).
async fn bba(pool: &PgPool, agent: Uuid, claim: Uuid, frame: Uuid, perspective: Uuid) -> Uuid {
    let p = pool.clone();
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, agent).await;
        let id = MassFunctionRepository::store_with_perspective(
            &mut *conn,
            claim,
            frame,
            Some(agent),
            Some(perspective),
            &serde_json::json!({"0": 0.6, "0,1": 0.4}),
            None,
            Some("test"),
            None,
            None,
            "unknown",
            None,
        )
        .await
        .expect("store the BBA");
        (conn, id)
    })
    .await
}

async fn bba_exists(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mass_functions WHERE id = $1)")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("bba exists")
}

/// `(event_type, agent_id, details)` of every `edge_retract` cascade row for
/// `edge`, oldest first.
async fn cascade_rows(pool: &PgPool, edge: Uuid) -> Vec<(String, Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT event_type, agent_id, details FROM security_events \
          WHERE event_type LIKE 'cascade.%' \
            AND details->>'cause' = 'edge_retract' \
            AND details->'trigger'->>'subject_id' = $1::text \
          ORDER BY created_at, id",
    )
    .bind(edge)
    .fetch_all(pool)
    .await
    .expect("cascade rows")
}

/// A `ScopedPool` whose maintenance pool runs as `epigraph_maintenance` (not a
/// superuser), as `epigraph-cascade-replay.timer`'s login does.
async fn maintenance_scoped(pool: &PgPool) -> ScopedPool {
    let url = fixture::database_url_for(pool).await;
    let maintenance = fixture::downgraded_pool(pool, "epigraph_maintenance").await;
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("ScopedPool")
        .with_maintenance_pool(maintenance)
}

async fn replay_now(pool: &PgPool) -> epigraph_engine::admin_cascade::ReplayReport {
    let scoped = maintenance_scoped(pool).await;
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
        "w12b-test",
        50,
        epigraph_engine::admin_cascade::DEFAULT_MAX_FAILURES,
    )
    .await
    .expect("replay")
}

fn text(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let raw = result
        .content
        .first()
        .expect("content")
        .as_text()
        .expect("text")
        .text
        .clone();
    serde_json::from_str(&raw).expect("json")
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_owners_retract_cleans_its_own_bba_now_and_defers_every_other_writers(pool: PgPool) {
    let (plain, scoped) = app_role_pools(&pool).await;
    let w1 = side(
        &pool,
        build_scoped_test_server(plain.clone(), scoped.clone()),
    )
    .await;
    let w2 = side(
        &pool,
        build_scoped_test_server_generated_signer(plain, scoped),
    )
    .await;
    let author = fixture::seed_agent_with_group(&pool, "author").await.0;
    let a = fixture::seed_public_claim(&pool, author, "w12b bba source").await;
    let b = fixture::seed_public_claim(&pool, author, "w12b bba target").await;
    let frame = FrameRepository::create(
        &pool,
        "binary_truth",
        Some("w12b"),
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("frame")
    .id;

    let edge = owned_edge(&pool, w1.agent, a, b).await;
    let own = bba(&pool, w1.agent, b, frame, edge).await;
    let foreign = bba(&pool, w2.agent, b, frame, edge).await;
    let owners: Vec<Uuid> =
        sqlx::query_scalar("SELECT owner_group_id FROM mass_functions WHERE id = ANY($1) ORDER BY array_position($1, id)")
            .bind(vec![own, foreign])
            .fetch_all(&pool)
            .await
            .expect("owners");
    assert_eq!(
        owners,
        vec![w1.group, w2.group],
        "fixture shape: one BBA each"
    );

    // The owner retracts.
    let out = do_delete_edge(
        &w1.server,
        &w1.viewer,
        DeleteEdgeParams {
            edge_id: edge.to_string(),
        },
        None,
    )
    .await
    .expect("the owner retracts its edge");
    let out = text(&out);
    assert_eq!(out["bba_cleanup"]["deleted"], 1, "{out}");
    assert!(out["bba_cleanup"]["deferral_event_id"].is_string(), "{out}");
    assert!(
        !bba_exists(&pool, own).await,
        "(a) the owner's own BBA went in the act"
    );
    assert!(
        bba_exists(&pool, foreign).await,
        "(b) another writer's survives the act"
    );
    let rows = cascade_rows(&pool, edge).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, "cascade.deferred");
    assert_eq!(rows[0].1, Some(w1.agent), "the deferral names the owner");
    assert_eq!(
        rows[0].2["recorded_by"], "epigraph_record_cascade_deferral",
        "written by the definer"
    );

    // The replay removes the other writer's BBA and names the owner.
    let report = replay_now(&pool).await;
    assert_eq!((report.applied, report.failed), (1, 0), "{report:?}");
    assert!(!bba_exists(&pool, foreign).await, "the replay removed it");
    let rows = cascade_rows(&pool, edge).await;
    let applied: Vec<_> = rows
        .iter()
        .filter(|r| r.0 == "cascade.admin_applied")
        .collect();
    assert_eq!(applied.len(), 1, "{rows:?}");
    assert_eq!(
        applied[0].1,
        Some(w1.agent),
        "the applied row names the owner"
    );
    let touched = &applied[0].2["touched"];
    assert_eq!(touched["edge_withdrawn"], true, "{touched}");
    assert_eq!(touched["bbas_deleted"], 1, "{touched}");
    assert!(
        !touched.to_string().contains(&foreign.to_string())
            && !touched.to_string().contains(&w2.agent.to_string()),
        "counts only: no other writer's BBA or agent id in the owner-readable row: {touched}"
    );
    assert!(rows.iter().all(|r| r.0 != "cascade.admin_failed"));
    // A second replay finds nothing pending.
    assert_eq!(replay_now(&pool).await.pending, 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_replay_over_an_edge_back_in_force_removes_nothing_and_does_not_fail(pool: PgPool) {
    let (plain, scoped) = app_role_pools(&pool).await;
    let w1 = side(
        &pool,
        build_scoped_test_server(plain.clone(), scoped.clone()),
    )
    .await;
    let w2 = side(
        &pool,
        build_scoped_test_server_generated_signer(plain, scoped),
    )
    .await;
    let author = fixture::seed_agent_with_group(&pool, "author").await.0;
    let a = fixture::seed_public_claim(&pool, author, "w12b bba source").await;
    let b = fixture::seed_public_claim(&pool, author, "w12b bba target").await;
    let frame = FrameRepository::create(
        &pool,
        "binary_truth",
        Some("w12b"),
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("frame")
    .id;

    // Back in force before the replay.
    let edge = owned_edge(&pool, w1.agent, a, b).await;
    let foreign = bba(&pool, w2.agent, b, frame, edge).await;
    do_delete_edge(
        &w1.server,
        &w1.viewer,
        DeleteEdgeParams {
            edge_id: edge.to_string(),
        },
        None,
    )
    .await
    .expect("retract");
    sqlx::query("UPDATE edges SET valid_to = NULL WHERE id = $1")
        .bind(edge)
        .execute(&pool)
        .await
        .expect("un-retract (privileged)");

    // A future-dated retraction records nothing.
    let later = owned_edge(&pool, w1.agent, b, a).await;
    let later_own = bba(&pool, w1.agent, a, frame, later).await;
    let out = do_patch_edge(
        &w1.server,
        &w1.viewer,
        PatchEdgeParams {
            edge_id: later.to_string(),
            valid_to: Some((chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339()),
            properties: None,
        },
        None,
    )
    .await
    .expect("future-dated patch");
    let out = text(&out);
    assert!(out.get("bba_cleanup").is_none(), "{out}");
    assert!(cascade_rows(&pool, later).await.is_empty(), "no deferral");
    assert!(bba_exists(&pool, later_own).await, "nothing removed yet");

    let report = replay_now(&pool).await;
    assert_eq!((report.applied, report.failed), (1, 0), "{report:?}");
    assert!(
        bba_exists(&pool, foreign).await,
        "state-derived: nothing removed"
    );
    let rows = cascade_rows(&pool, edge).await;
    let applied: Vec<_> = rows
        .iter()
        .filter(|r| r.0 == "cascade.admin_applied")
        .collect();
    assert_eq!(applied.len(), 1, "{rows:?}");
    let touched = &applied[0].2["touched"];
    assert_eq!(touched["edge_withdrawn"], false, "{touched}");
    assert_eq!(touched["bbas_deleted"], 0, "{touched}");
    assert!(touched["reason"].is_string(), "{touched}");
    assert!(
        rows.iter().all(|r| r.0 != "cascade.admin_failed"),
        "a legitimate state is never a failure: {rows:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_one_shot_sweep_is_audited_and_spares_a_genuine_perspective(pool: PgPool) {
    let (operator, _) = fixture::seed_agent_with_group(&pool, "operator").await;
    let (writer, _) = fixture::seed_agent_with_group(&pool, "legacy-writer").await;
    let a = fixture::seed_public_claim(&pool, operator, "w12b sweep a").await;
    let b = fixture::seed_public_claim(&pool, operator, "w12b sweep b").await;
    let frame = FrameRepository::create(
        &pool,
        "binary_truth",
        Some("w12b"),
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("frame")
    .id;

    // A legacy edge retracted before withdrawals recorded deferrals.
    let legacy = fixture::seed_edge(&pool, a, b).await;
    perspective(&pool, legacy, "edge").await;
    let legacy_bba = bba(&pool, writer, b, frame, legacy).await;
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 day' WHERE id = $1")
        .bind(legacy)
        .execute(&pool)
        .await
        .expect("retract (privileged)");
    // A retracted edge whose id is ALSO a genuine perspective's id: the
    // perspective is not an edge factor, and its BBA must survive.
    let twin = fixture::seed_edge(&pool, b, a).await;
    perspective(&pool, twin, "analytical").await;
    let genuine_bba = bba(&pool, writer, a, frame, twin).await;
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 day' WHERE id = $1")
        .bind(twin)
        .execute(&pool)
        .await
        .expect("retract (privileged)");

    let scoped = maintenance_scoped(&pool).await;
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance session");
    session
        .assert_privileged()
        .await
        .expect("the sweep's connection is privileged");
    let (conn, admin_viewer) = session.split();
    let items = epigraph_engine::admin_cascade::sweep_withdrawn_edge_bbas(
        conn,
        admin_viewer,
        operator,
        "w12b legacy sweep",
        100,
    )
    .await
    .expect("sweep");
    assert_eq!(
        items.iter().map(|i| i.edge_id).collect::<Vec<_>>(),
        vec![legacy],
        "exactly the edge-factor perspective is a candidate"
    );
    // Even named directly (a forged deferral), the genuine perspective's BBA
    // is not an edge factor and is not removed.
    let forged = epigraph_engine::admin_cascade::CascadeTrigger::new(
        epigraph_engine::admin_cascade::CascadeCause::EdgeRetract,
        Some(operator),
        None,
        twin,
        None,
    );
    let status =
        epigraph_engine::admin_cascade::apply_after_edge_retract(conn, admin_viewer, &forged, None)
            .await;
    assert_eq!(
        status.touched.expect("touched")["bbas_deleted"],
        0,
        "keyed on perspective_type = 'edge'"
    );

    assert!(
        !bba_exists(&pool, legacy_bba).await,
        "the legacy BBA is gone"
    );
    assert!(
        bba_exists(&pool, genuine_bba).await,
        "the genuine perspective's BBA survives"
    );
    let rows = cascade_rows(&pool, legacy).await;
    let applied: Vec<_> = rows
        .iter()
        .filter(|r| r.0 == "cascade.admin_applied")
        .collect();
    assert_eq!(applied.len(), 1, "{rows:?}");
    assert!(
        rows.iter()
            .all(|r| r.0 == "cascade.admin_applied" || r.0 == "cascade.belief_rederived"),
        "no deferral and no failure for a one-shot sweep: {rows:?}"
    );
    assert_eq!(
        applied[0].1,
        Some(operator),
        "audited under the acting operator"
    );
    assert_eq!(applied[0].2["touched"]["sweep_reason"], "w12b legacy sweep");
    assert_eq!(applied[0].2["touched"]["bbas_deleted"], 1);
}

// ---------------------------------------------------------------------------
// The owner's own BBAs: their claims' belief is re-derived by the replay.
//
// The owner deletes its own edge-keyed BBAs in the act, but it cannot write
// the belief cache of a claim it does not own, so the deferral carries those
// claims (`trigger.sources`) and the replay re-derives them. Without that, a
// claim on which only the owner held the edge-keyed BBA keeps a cache the
// retracted edge still moves.
// ---------------------------------------------------------------------------

/// `agent`'s plain BBA on `claim` (no perspective: not keyed on any edge), with
/// masses unlike the edge-keyed ones, so the cache with and without the
/// edge-keyed row differs.
async fn plain_bba(pool: &PgPool, agent: Uuid, claim: Uuid, frame: Uuid) -> Uuid {
    let p = pool.clone();
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, agent).await;
        let id = MassFunctionRepository::store_with_perspective(
            &mut *conn,
            claim,
            frame,
            Some(agent),
            None,
            &serde_json::json!({"1": 0.5, "0,1": 0.5}),
            None,
            Some("test"),
            None,
            None,
            "unknown",
            None,
        )
        .await
        .expect("store the plain BBA");
        (conn, id)
    })
    .await
}

/// Recompute `claim`'s cached belief on `frame` from the rows it has, on the
/// maintenance connection (what a fresh administrative recompute writes).
async fn recompute(pool: &PgPool, claim: Uuid, frame: Uuid) -> bool {
    let scoped = maintenance_scoped(pool).await;
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance session");
    let (conn, admin_viewer) = session.split();
    epigraph_engine::edge_factor::recompute_claim_belief_on_frame(conn, admin_viewer, claim, frame)
        .await
        .expect("recompute")
}

type Cache = (Option<f64>, Option<f64>);

async fn cached(pool: &PgPool, claim: Uuid) -> Cache {
    sqlx::query_as("SELECT belief, pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("cached belief")
}

async fn binary_frame(pool: &PgPool) -> Uuid {
    FrameRepository::create(
        pool,
        "binary_truth",
        Some("w12b"),
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("frame")
    .id
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_owners_retract_rederives_the_belief_its_own_bba_moved(pool: PgPool) {
    let (plain, scoped) = app_role_pools(&pool).await;
    let w1 = side(
        &pool,
        build_scoped_test_server(plain.clone(), scoped.clone()),
    )
    .await;
    let w2 = side(
        &pool,
        build_scoped_test_server_generated_signer(plain, scoped),
    )
    .await;
    let author = fixture::seed_agent_with_group(&pool, "author").await.0;
    let a = fixture::seed_public_claim(&pool, author, "w12b rederive source").await;
    let b = fixture::seed_public_claim(&pool, author, "w12b rederive target").await;
    let frame = binary_frame(&pool).await;

    // The owner is the ONLY writer with a BBA keyed on its edge; the target
    // also carries another writer's plain BBA, which survives everything.
    let edge = owned_edge(&pool, w1.agent, a, b).await;
    let own = bba(&pool, w1.agent, b, frame, edge).await;
    let survivor = plain_bba(&pool, w2.agent, b, frame).await;
    assert!(recompute(&pool, b, frame).await, "fixture: cache populated");
    let before = cached(&pool, b).await;
    assert!(before.1.is_some(), "fixture: a cached belief {before:?}");

    let out = do_delete_edge(
        &w1.server,
        &w1.viewer,
        DeleteEdgeParams {
            edge_id: edge.to_string(),
        },
        None,
    )
    .await
    .expect("the owner retracts its edge");
    let out = text(&out);
    assert_eq!(out["bba_cleanup"]["deleted"], 1, "{out}");
    assert!(!bba_exists(&pool, own).await, "(a) went in the act");
    let rows = cascade_rows(&pool, edge).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        rows[0].2["trigger"]["sources"],
        serde_json::json!([b]),
        "the deferral carries the claim the owner's own BBA lived on"
    );

    let report = replay_now(&pool).await;
    assert_eq!((report.applied, report.failed), (1, 0), "{report:?}");
    let rows = cascade_rows(&pool, edge).await;
    let applied: Vec<_> = rows
        .iter()
        .filter(|r| r.0 == "cascade.admin_applied")
        .collect();
    assert_eq!(applied.len(), 1, "{rows:?}");
    let touched = &applied[0].2["touched"];
    assert_eq!(
        touched["bbas_deleted"], 0,
        "nothing foreign to remove: {touched}"
    );
    assert_eq!(touched["owner_claims_rederived"], 1, "{touched}");

    assert!(
        bba_exists(&pool, survivor).await,
        "the plain BBA is untouched"
    );
    let after = cached(&pool, b).await;
    assert_ne!(
        after, before,
        "the cache no longer carries the retracted edge's BBA"
    );
    assert!(
        after.1.is_some(),
        "b is still backed by the plain BBA: {after:?}"
    );
    assert!(recompute(&pool, b, frame).await);
    assert_eq!(
        cached(&pool, b).await,
        after,
        "the replay left exactly what a fresh recompute from the surviving rows writes"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_owners_claim_and_another_writers_claim_are_both_rederived(pool: PgPool) {
    let (plain, scoped) = app_role_pools(&pool).await;
    let w1 = side(
        &pool,
        build_scoped_test_server(plain.clone(), scoped.clone()),
    )
    .await;
    let w2 = side(
        &pool,
        build_scoped_test_server_generated_signer(plain, scoped),
    )
    .await;
    let author = fixture::seed_agent_with_group(&pool, "author").await.0;
    let a = fixture::seed_public_claim(&pool, author, "w12b per-claim a").await;
    let b = fixture::seed_public_claim(&pool, author, "w12b per-claim b").await;
    let frame = binary_frame(&pool).await;

    // The owner's edge-keyed BBA is on a, another writer's on b: the replay
    // removes (and so re-derives) b, and must re-derive a too.
    let edge = owned_edge(&pool, w1.agent, a, b).await;
    bba(&pool, w1.agent, a, frame, edge).await;
    let foreign = bba(&pool, w2.agent, b, frame, edge).await;
    assert!(recompute(&pool, a, frame).await);
    assert!(recompute(&pool, b, frame).await);
    let (a0, b0) = (cached(&pool, a).await, cached(&pool, b).await);
    assert!(a0.1.is_some() && b0.1.is_some(), "fixture: {a0:?} {b0:?}");

    do_delete_edge(
        &w1.server,
        &w1.viewer,
        DeleteEdgeParams {
            edge_id: edge.to_string(),
        },
        None,
    )
    .await
    .expect("the owner retracts its edge");
    let report = replay_now(&pool).await;
    assert_eq!((report.applied, report.failed), (1, 0), "{report:?}");
    assert!(!bba_exists(&pool, foreign).await, "the replay removed b's");

    let none: Cache = (None, None);
    assert_eq!(
        cached(&pool, a).await,
        none,
        "a has no BBA left, so no cache"
    );
    assert_eq!(
        cached(&pool, b).await,
        none,
        "b has no BBA left, so no cache"
    );
}

// ---------------------------------------------------------------------------
// The re-derivation set is the database's, never the caller's. The deferral
// definer derives an `edge_retract`'s sources itself (the claims of the
// session's OWN BBA rows keyed on the edge, read before the act deletes them)
// and refuses caller-named ones: a caller naming another writer's claims must
// not make the privileged replay rewrite or clear their belief caches. And two
// acts on one edge before a replay both reach it: the replay re-derives the
// union of every pending deferral's sources, not only the oldest one's.
// ---------------------------------------------------------------------------

type Cache3 = (Option<f64>, Option<f64>, Option<f64>);

async fn cache3(pool: &PgPool, claim: Uuid) -> Cache3 {
    sqlx::query_as("SELECT belief, plausibility, pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("cache")
}

fn sqlstate(e: &sqlx::Error) -> String {
    e.as_database_error()
        .and_then(|d| d.code().map(|c| c.to_string()))
        .unwrap_or_else(|| e.to_string())
}

/// `agent`'s own direct call of the deferral definer on the application role
/// (what a session with raw SQL can do), with `sources` as given.
async fn direct_deferral(
    pool: &PgPool,
    agent: Uuid,
    edge: Uuid,
    sources: Option<Vec<Uuid>>,
) -> Result<Uuid, String> {
    let p = pool.clone();
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, agent).await;
        let r = sqlx::query_scalar::<_, Uuid>(
            "SELECT public.epigraph_record_cascade_deferral(\
             'edge_retract', $1, $2, NULL, $3, NULL, 'w12b direct')",
        )
        .bind(agent)
        .bind(edge)
        .bind(sources)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| sqlstate(&e));
        (conn, r)
    })
    .await
}

/// `agent`'s BBA keyed on `perspective` onto `claim`, on the application role,
/// or the refusal's SQLSTATE.
async fn try_bba(
    pool: &PgPool,
    agent: Uuid,
    claim: Uuid,
    frame: Uuid,
    perspective: Uuid,
) -> Result<Uuid, String> {
    let p = pool.clone();
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, agent).await;
        let r = MassFunctionRepository::store_with_perspective(
            &mut *conn,
            claim,
            frame,
            Some(agent),
            Some(perspective),
            &serde_json::json!({"0": 0.6, "0,1": 0.4}),
            None,
            Some("test"),
            None,
            None,
            "unknown",
            None,
        )
        .await
        .map_err(|e| e.to_string());
        (conn, r)
    })
    .await
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_caller_cannot_name_the_claims_an_edge_retract_rederives(pool: PgPool) {
    let (plain, scoped) = app_role_pools(&pool).await;
    let w1 = side(&pool, build_scoped_test_server(plain, scoped)).await;
    let author = fixture::seed_agent_with_group(&pool, "author").await.0;
    let a = fixture::seed_public_claim(&pool, author, "w12b forged a").await;
    let b = fixture::seed_public_claim(&pool, author, "w12b forged b").await;
    let (z, zg) = fixture::seed_agent_with_group(&pool, "bystander-z").await;
    let v_pub = fixture::seed_public_claim(&pool, z, "w12b bystander public").await;
    let v_priv = fixture::seed_group_claim(&pool, z, zg, "w12b bystander private").await;
    let frame = binary_frame(&pool).await;
    // A cache with no BBA rows behind it (what a belief-propagation apply
    // writes directly): a re-derivation would clear it.
    sqlx::query(
        "UPDATE claims SET belief = 0.7, plausibility = 0.9, pignistic_prob = 0.8 \
          WHERE id = ANY($1)",
    )
    .bind(vec![v_pub, v_priv])
    .execute(&pool)
    .await
    .expect("seed caches");
    let before = (cache3(&pool, v_pub).await, cache3(&pool, v_priv).await);

    // W1 owns a withdrawn edge factor, and the honest cascade has drained.
    let edge = owned_edge(&pool, w1.agent, a, b).await;
    do_delete_edge(
        &w1.server,
        &w1.viewer,
        DeleteEdgeParams {
            edge_id: edge.to_string(),
        },
        None,
    )
    .await
    .expect("the owner retracts its edge");
    let drained = replay_now(&pool).await;
    assert_eq!((drained.applied, drained.failed), (1, 0), "{drained:?}");

    // (a) Caller-named sources are refused, the bystander's claims first.
    for named in [vec![v_pub, v_priv], vec![v_pub], vec![a]] {
        assert_eq!(
            direct_deferral(&pool, w1.agent, edge, Some(named.clone())).await,
            Err("22023".to_string()),
            "an edge_retract deferral takes no caller-named sources: {named:?}"
        );
    }
    // (c) The sources the database derives are the claims of the session's
    // own edge-keyed rows, and a writer cannot plant a row on a claim it
    // cannot see: the same write onto a public claim is admitted (control).
    try_bba(&pool, w1.agent, a, frame, edge)
        .await
        .expect("control: W1 keys a BBA on its edge onto a public claim");
    let planted = try_bba(&pool, w1.agent, v_priv, frame, edge).await;
    assert!(
        planted
            .as_ref()
            .is_err_and(|e| e.contains("row-level security")),
        "a writer cannot key a BBA on another group's private claim: {planted:?}"
    );
    // (b) With no sources named, the definer records the ones state gives:
    // exactly the claim of W1's own row, never a bystander's.
    let id = direct_deferral(&pool, w1.agent, edge, None)
        .await
        .expect("the owner may record its own withdrawn edge factor again");
    let trigger: serde_json::Value =
        sqlx::query_scalar("SELECT details->'trigger' FROM security_events WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("the deferral");
    assert_eq!(
        trigger["sources"],
        serde_json::json!([a]),
        "the sources are the session's own rows' claims: {trigger}"
    );
    let report = replay_now(&pool).await;
    assert_eq!((report.applied, report.failed), (1, 0), "{report:?}");

    assert_eq!(
        (cache3(&pool, v_pub).await, cache3(&pool, v_priv).await),
        before,
        "no deferral may rewrite a claim the caller held no BBA on"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn two_acts_on_one_edge_before_a_replay_both_reach_it(pool: PgPool) {
    let (plain, scoped) = app_role_pools(&pool).await;
    let w1 = side(&pool, build_scoped_test_server(plain, scoped)).await;
    let author = fixture::seed_agent_with_group(&pool, "author").await.0;
    let a = fixture::seed_public_claim(&pool, author, "w12b union a").await;
    let b = fixture::seed_public_claim(&pool, author, "w12b union b").await;
    let c = fixture::seed_public_claim(&pool, author, "w12b union c").await;
    let frame = binary_frame(&pool).await;

    // Act 1: the owner's BBA on a goes with its retract.
    let edge = owned_edge(&pool, w1.agent, a, b).await;
    bba(&pool, w1.agent, a, frame, edge).await;
    assert!(recompute(&pool, a, frame).await, "fixture: a's cache");
    assert!(cached(&pool, a).await.1.is_some());
    do_delete_edge(
        &w1.server,
        &w1.viewer,
        DeleteEdgeParams {
            edge_id: edge.to_string(),
        },
        None,
    )
    .await
    .expect("act 1: the owner retracts its edge");
    // Act 2, before any replay: a BBA keyed on the edge onto c, then a patch
    // that sets the window again; the act deletes it and defers c.
    bba(&pool, w1.agent, c, frame, edge).await;
    assert!(recompute(&pool, c, frame).await, "fixture: c's cache");
    assert!(cached(&pool, c).await.1.is_some());
    let out = do_patch_edge(
        &w1.server,
        &w1.viewer,
        PatchEdgeParams {
            edge_id: edge.to_string(),
            valid_to: Some("now".to_string()),
            properties: None,
        },
        None,
    )
    .await
    .expect("act 2: the owner patches its retracted edge");
    assert_eq!(
        text(&out)["bba_cleanup"]["deleted"],
        1,
        "act 2 deleted c's row"
    );
    let deferred: Vec<serde_json::Value> = cascade_rows(&pool, edge)
        .await
        .into_iter()
        .filter(|r| r.0 == "cascade.deferred")
        .map(|r| r.2["trigger"]["sources"].clone())
        .collect();
    assert_eq!(
        deferred,
        vec![serde_json::json!([a]), serde_json::json!([c])],
        "two deferrals, one per act"
    );

    let report = replay_now(&pool).await;
    assert_eq!((report.applied, report.failed), (1, 0), "{report:?}");
    let none: Cache = (None, None);
    assert_eq!(cached(&pool, a).await, none, "act 1's claim is re-derived");
    assert_eq!(
        cached(&pool, c).await,
        none,
        "act 2's claim is re-derived too, though its deferral collapsed into act 1's"
    );
}
