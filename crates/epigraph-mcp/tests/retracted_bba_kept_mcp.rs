//! SPEC §11 phase 1, K4a, through the MCP tools: a RETRACTED mass function
//! (migration 184, rulings R-79 / R-103) survives `supersede_claim` (inline
//! and deferred-then-replayed), `mark_duplicate` and `delete_edge` with its
//! maintenance replay; each act completes, and the cascades count what they
//! kept.
//!
//! The server's pools are the application role (`epigraph_app`); the inline
//! cascade and the replay run on a NOSUPERUSER `epigraph_maintenance`
//! connection (SPEC §12). Every retracted row is made by migration 184's
//! definer on the application role. Seeding runs on the superuser harness.

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "../../epigraph-db/tests/support/retracted_bba_fixture.rs"]
mod retracted;

mod common;
use common::*;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::visibility::Viewer;
use epigraph_db::{MassFunctionRepository, ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::edge_mutation::do_delete_edge;
use epigraph_mcp::tools::supersede::{mark_duplicate, supersede_claim};
use epigraph_mcp::types::{DeleteEdgeParams, MarkDuplicateParams, SupersedeClaimParams};
use retracted::{retract_through_definer, row_state};
use sqlx::PgPool;
use uuid::Uuid;

/// The application-role `ScopedPool`; with `inline`, its maintenance pool is a
/// NOSUPERUSER `epigraph_maintenance` login, so the cascade runs in the call.
async fn app_role_server(pool: &PgPool, inline: bool) -> EpiGraphMcpFull {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(!bypassrls, "epigraph_app holds BYPASSRLS: vacuous");
    let url = fixture::database_url_for(pool).await;
    let mut scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    if inline {
        scoped = scoped
            .with_maintenance_pool(fixture::downgraded_pool(pool, "epigraph_maintenance").await);
    }
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    build_scoped_test_server(plain, scoped)
}

fn human(agent: Uuid) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Human,
        scopes: vec!["claims:read".to_string(), "claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

async fn viewer(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("resolve")
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
    perspective(pool, id).await;
    id
}

async fn perspective(pool: &PgPool, id: Uuid) {
    sqlx::query(
        "INSERT INTO perspectives (id, name, perspective_type) VALUES ($1, 'edge_factor', 'edge')",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("seed the edge's perspective");
}

async fn frame(pool: &PgPool, tag: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("k4a-mcp-{tag}-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed frame")
}

async fn harness_bba(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    agent: Uuid,
    perspective: Uuid,
) -> Uuid {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        Some(perspective),
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        Some("edge_factor"),
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("store a BBA")
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
        "k4a-mcp",
        50,
        epigraph_engine::admin_cascade::DEFAULT_MAX_FAILURES,
    )
    .await
    .expect("replay")
}

/// The belief audit rows (`cascade.belief_rederived`) of the cascade whose
/// subject is `subject`, their `belief` counts, oldest first.
async fn belief_counts(pool: &PgPool, subject: Uuid) -> Vec<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT details->'belief' FROM security_events \
          WHERE event_type = 'cascade.belief_rederived' \
            AND details->'trigger'->>'subject_id' = $1::text \
          ORDER BY created_at, id",
    )
    .bind(subject)
    .fetch_all(pool)
    .await
    .expect("belief audit rows")
}

/// A supersede fixture: the author's claim `old` supports another writer's
/// claim `b`; the edge-keyed BBA on `b` was retracted by `b`'s group writer.
struct SupersedeWorld {
    author: Uuid,
    old: Uuid,
    b: Uuid,
    retracted: Uuid,
}

async fn supersede_world(pool: &PgPool) -> SupersedeWorld {
    let (author, ag) = fixture::seed_agent_with_group(pool, "k4a-mcp-author").await;
    let (x, xg) = fixture::seed_agent_with_group(pool, "k4a-mcp-x").await;
    let old = claim_of(pool, author, ag, "k4a mcp supporter").await;
    let b = claim_of(pool, x, xg, "k4a mcp downstream").await;
    let e = edge(pool, old, b).await;
    let f = frame(pool, "supersede").await;
    let retracted = harness_bba(pool, b, f, author, e).await;
    retract_through_definer(pool, retracted).await;
    SupersedeWorld {
        author,
        old,
        b,
        retracted,
    }
}

fn supersede_params(claim: Uuid) -> SupersedeClaimParams {
    SupersedeClaimParams {
        claim_id: claim.to_string(),
        content: format!("a correction of {claim}"),
        truth_value: 0.6,
        reason: "k4a mcp".to_string(),
    }
}

/// Sites 1 and 8 through `supersede_claim` with the cascade inline: the
/// retracted edge BBA on the re-pointed edge is kept, the cascade applies with
/// no error, and both the caller's copy of the report and the belief audit
/// row count the kept retracted key.
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_claim_inline_keeps_a_retracted_edge_bba_and_counts_it(pool: PgPool) {
    let server = app_role_server(&pool, true).await;
    let w = supersede_world(&pool).await;
    let r = supersede_claim(
        &server,
        &viewer(&pool, w.author).await,
        supersede_params(w.old),
        Some(&human(w.author)),
    )
    .await
    .expect("the author's supersede");
    let body = first_text(&r);
    assert_eq!(body["cascade"]["status"], "applied", "{body}");
    assert_eq!(
        row_state(&pool, w.retracted).await,
        Some((w.b, true)),
        "the retracted edge BBA is kept for audit"
    );
    let cascade = &body["belief_cascade"];
    assert_eq!(
        cascade["errors"],
        serde_json::json!([]),
        "the cascade completes with no error: {cascade}"
    );
    assert_eq!(
        cascade["retracted_key_kept"], 1,
        "the caller's copy counts the kept retracted key: {cascade}"
    );
    let rows = belief_counts(&pool, w.old).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["retracted_key_kept"], 1, "{rows:?}");
}

/// The same act with no maintenance connection: the cascade is deferred, and
/// the replay (on the maintenance login) keeps the retracted edge BBA, applies
/// without failing, and its belief audit row counts the kept key.
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_claim_deferred_replay_keeps_a_retracted_edge_bba(pool: PgPool) {
    let server = app_role_server(&pool, false).await;
    let w = supersede_world(&pool).await;
    let r = supersede_claim(
        &server,
        &viewer(&pool, w.author).await,
        supersede_params(w.old),
        Some(&human(w.author)),
    )
    .await
    .expect("the author's supersede");
    let body = first_text(&r);
    assert_eq!(body["cascade"]["status"], "deferred", "{body}");

    let report = replay_now(&pool).await;
    assert_eq!((report.applied, report.failed), (1, 0), "{report:?}");
    assert_eq!(
        row_state(&pool, w.retracted).await,
        Some((w.b, true)),
        "the replay keeps the retracted edge BBA"
    );
    let rows = belief_counts(&pool, w.old).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["errors"], 0, "{rows:?}");
    assert_eq!(rows[0]["retracted_key_kept"], 1, "{rows:?}");
}

/// Site 2 through `mark_duplicate` with the cascade inline: another writer's
/// edge onto the duplicate carries two edge-keyed BBAs that collide with rows
/// the canonical holds under the same key. The duplicate's LIVE copy, whose
/// canonical holder is retracted, stays on the duplicate and is counted; its
/// RETRACTED copy, whose canonical holder is live, stays too. The repair
/// applies (it has no savepoint, so a raise would fail it).
#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_inline_keeps_retracted_rows_and_the_live_copy_they_block(pool: PgPool) {
    let server = app_role_server(&pool, true).await;
    let (h, hg) = fixture::seed_agent_with_group(&pool, "k4a-mcp-h").await;
    let (x, xg) = fixture::seed_agent_with_group(&pool, "k4a-mcp-citer").await;
    let dup = claim_of(&pool, h, hg, "k4a mcp duplicate").await;
    let canonical = claim_of(&pool, h, hg, "k4a mcp canonical").await;
    let xc = claim_of(&pool, x, xg, "k4a mcp citer").await;
    let e = edge(&pool, xc, dup).await;
    let (f1, f2) = (frame(&pool, "d1").await, frame(&pool, "d2").await);
    let live_copy = harness_bba(&pool, dup, f1, x, e).await;
    let retracted_holder = harness_bba(&pool, canonical, f1, x, e).await;
    let retracted_copy = harness_bba(&pool, dup, f2, x, e).await;
    let live_holder = harness_bba(&pool, canonical, f2, x, e).await;
    retract_through_definer(&pool, retracted_holder).await;
    retract_through_definer(&pool, retracted_copy).await;

    let r = mark_duplicate(
        &server,
        &viewer(&pool, h).await,
        MarkDuplicateParams {
            claim_id: dup.to_string(),
            canonical_id: canonical.to_string(),
            reason: None,
        },
        Some(&human(h)),
    )
    .await
    .expect("the author's dedup");
    let body = first_text(&r);
    assert_eq!(
        body["cascade"]["status"], "applied",
        "the repair completes: {body}"
    );
    assert_eq!(
        row_state(&pool, live_copy).await,
        Some((dup, false)),
        "the live copy a retracted holder blocks stays on the duplicate"
    );
    assert_eq!(
        row_state(&pool, retracted_copy).await,
        Some((dup, true)),
        "the retracted copy is kept where it is"
    );
    assert_eq!(
        row_state(&pool, retracted_holder).await,
        Some((canonical, true))
    );
    assert_eq!(
        row_state(&pool, live_holder).await,
        Some((canonical, false))
    );
    let touched = &body["cascade"]["touched"];
    assert_eq!(
        touched["bbas_kept_on_duplicate_by_retracted_holder"], 1,
        "the caller's counts report the kept live copy: {touched}"
    );
    assert_eq!(touched["duplicate_copies_dropped"], 0, "{touched}");
}

/// A server agent, its personal group and viewer.
struct Side {
    server: EpiGraphMcpFull,
    agent: Uuid,
    viewer: Viewer,
}

async fn side(pool: &PgPool, server: EpiGraphMcpFull) -> Side {
    let agent = server.server_agent_id().await.expect("server agent");
    let viewer = Viewer::resolve(pool, agent).await.expect("viewer");
    Side {
        server,
        agent,
        viewer,
    }
}

/// `agent`'s BBA on `claim`, keyed on `perspective`, written on the
/// application role stamped for `agent` (114 makes it the writer's row).
async fn app_bba(pool: &PgPool, agent: Uuid, claim: Uuid, frame: Uuid, perspective: Uuid) -> Uuid {
    let v = Viewer::resolve(pool, agent).await.expect("resolve");
    let csv = |ids: &[Uuid]| {
        ids.iter()
            .map(Uuid::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    let groups = csv(v.group_bind().expect("scoped"));
    let writable = csv(v.writable_groups());
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.group_ids', $1, false), \
                    set_config('epigraph.writable_group_ids', $2, false), \
                    set_config('epigraph.principal_id', $3, false)",
        )
        .bind(groups)
        .bind(writable)
        .bind(agent.to_string())
        .execute(&mut *conn)
        .await
        .expect("stamp");
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

/// Sites 4 and 5 through `delete_edge` and its replay: the edge's owner
/// retracts it. In the act (the application-session caller arm) the owner's
/// live edge BBA goes and its retracted one stays; the maintenance replay
/// removes the other writer's live one and keeps its retracted one. Neither
/// half fails.
#[sqlx::test(migrations = "../../migrations")]
async fn delete_edge_and_its_replay_keep_retracted_edge_bbas(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(&pool, "epigraph_app").await;
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
    let author = fixture::seed_agent_with_group(&pool, "k4a-mcp-edge-author")
        .await
        .0;
    let a = fixture::seed_public_claim(&pool, author, "k4a edge source").await;
    let b = fixture::seed_public_claim(&pool, author, "k4a edge target").await;
    let (f1, f2) = (frame(&pool, "e1").await, frame(&pool, "e2").await);

    let p = pool.clone();
    let w1_agent = w1.agent;
    let e: Uuid = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let v = Viewer::resolve(&p, w1_agent).await.expect("resolve");
        let csv = |ids: &[Uuid]| {
            ids.iter()
                .map(Uuid::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        sqlx::query(
            "SELECT set_config('epigraph.group_ids', $1, false), \
                    set_config('epigraph.writable_group_ids', $2, false), \
                    set_config('epigraph.principal_id', $3, false)",
        )
        .bind(csv(v.group_bind().expect("scoped")))
        .bind(csv(v.writable_groups()))
        .bind(w1_agent.to_string())
        .execute(&mut *conn)
        .await
        .expect("stamp");
        let e: Uuid = sqlx::query_scalar(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
             VALUES ($1, 'claim', $2, 'claim', 'supports') RETURNING id",
        )
        .bind(a)
        .bind(b)
        .fetch_one(&mut *conn)
        .await
        .expect("the owner's edge");
        (conn, e)
    })
    .await;
    perspective(&pool, e).await;
    let own_live = app_bba(&pool, w1.agent, b, f1, e).await;
    let own_retracted = app_bba(&pool, w1.agent, b, f2, e).await;
    let foreign_live = app_bba(&pool, w2.agent, b, f1, e).await;
    let foreign_retracted = app_bba(&pool, w2.agent, b, f2, e).await;
    retract_through_definer(&pool, own_retracted).await;
    retract_through_definer(&pool, foreign_retracted).await;

    let out = do_delete_edge(
        &w1.server,
        &w1.viewer,
        DeleteEdgeParams {
            edge_id: e.to_string(),
        },
        None,
    )
    .await
    .expect("the owner retracts its edge");
    let out = first_text(&out);
    assert_eq!(
        row_state(&pool, own_retracted).await,
        Some((b, true)),
        "the act keeps the owner's retracted edge BBA"
    );
    assert_eq!(
        row_state(&pool, own_live).await,
        None,
        "and deletes its live one"
    );
    assert_eq!(out["bba_cleanup"]["deleted"], 1, "{out}");

    let report = replay_now(&pool).await;
    assert_eq!((report.applied, report.failed), (1, 0), "{report:?}");
    assert_eq!(
        row_state(&pool, foreign_retracted).await,
        Some((b, true)),
        "the replay keeps another writer's retracted edge BBA"
    );
    assert_eq!(
        row_state(&pool, foreign_live).await,
        None,
        "and removes its live one"
    );
}
