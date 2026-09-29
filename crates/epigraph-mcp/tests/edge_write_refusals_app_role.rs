//! `patch_edge` and `delete_edge` on the APPLICATION ROLE: an edge the caller
//! can read but the server's agent may not update is REFUSED as such, not
//! reported as missing and never reported as changed.
//!
//! Migration 117 made UPDATE on `edges` owner-scoped with a RESTRICTIVE USING
//! clause. Under row security a USING clause that refuses a row does not raise:
//! the UPDATE matches zero rows and reports success. Before this change both
//! tools turned that into "edge not found", indistinguishable from a typo; the
//! repository now compares what the statement could see with what it changed
//! (`DbError::WriteRefused`).
//!
//! Both pools of the server are downgraded to `epigraph_app` (see
//! `writer_owned_attach_app_role.rs` for why a superuser pool proves nothing
//! here); the fixture is seeded on the superuser pool.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::edge_mutation::{do_delete_edge, do_patch_edge};
use epigraph_mcp::types::{DeleteEdgeParams, PatchEdgeParams};
use sqlx::PgPool;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> (EpiGraphMcpFull, Uuid, Viewer) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let server = build_scoped_test_server(plain, scoped);
    let agent = server.server_agent_id().await.expect("server agent");
    let viewer = Viewer::resolve(pool, agent).await.expect("viewer");
    (server, agent, viewer)
}

/// An edge exactly as `edges_tenancy` stamps it from its endpoints.
async fn edge(pool: &PgPool, source: Uuid, target: Uuid) -> Uuid {
    fixture::seed_edge(pool, source, target).await
}

async fn edge_state(pool: &PgPool, e: Uuid) -> (bool, serde_json::Value, Uuid) {
    sqlx::query_as("SELECT valid_to IS NULL, properties, owner_group_id FROM edges WHERE id = $1")
        .bind(e)
        .fetch_one(pool)
        .await
        .expect("edge")
}

fn patch(e: Uuid) -> PatchEdgeParams {
    PatchEdgeParams {
        edge_id: e.to_string(),
        valid_to: None,
        properties: Some(serde_json::json!({"note": "patched"})),
    }
}

/// A world-owned edge between two public claims: readable by everyone,
/// updatable by no application session. Both tools refuse it, by name, and
/// change nothing. The server agent's own edge (it touches the agent's
/// group-private claim) is patched and retracted normally, and an edge that
/// does not exist is still "not found".
#[sqlx::test(migrations = "../../migrations")]
async fn a_readable_edge_the_agent_may_not_update_is_refused_not_missing(pool: PgPool) {
    let (server, agent, viewer) = app_role_server(&pool).await;
    let world = fixture::world_group(&pool).await;
    let own_group = personal_group_of(&pool, agent).await;

    let a = fixture::seed_public_claim(&pool, agent, "edge-refusal public a").await;
    let b = fixture::seed_public_claim(&pool, agent, "edge-refusal public b").await;
    let world_edge = edge(&pool, a, b).await;
    assert_eq!(
        edge_state(&pool, world_edge).await.2,
        world,
        "fixture shape: an edge between two public claims is world-owned"
    );
    let mine = fixture::seed_group_claim(&pool, agent, own_group, "edge-refusal mine").await;
    let own_edge = edge(&pool, mine, a).await;
    assert_eq!(
        edge_state(&pool, own_edge).await.2,
        own_group,
        "fixture shape: an edge touching the agent's private claim is its group's"
    );

    // patch_edge: refused, named (migration 120: the explicit `not_owner`
    // refusal naming the administrative rule), nothing written.
    let e = do_patch_edge(&server, &viewer, patch(world_edge), None)
        .await
        .expect_err("a world edge is not the agent's to patch");
    assert!(
        e.message
            .contains("administrative (world-owned) edge; admin-only")
            && !e.message.contains("not found"),
        "the refusal is named, not reported as a missing edge: {e:?}"
    );
    assert_eq!(e.code, rmcp::model::ErrorCode::INVALID_REQUEST, "{e:?}");
    let data = e.data.clone().expect("the refusal carries data");
    assert_eq!(data["error"], "not_owner", "{data}");
    assert_eq!(data["rule"], "administrative_edge", "{data}");
    assert_eq!(
        edge_state(&pool, world_edge).await.1,
        serde_json::json!({}),
        "nothing was merged"
    );

    // delete_edge: refused, named, still in force.
    let e = do_delete_edge(
        &server,
        &viewer,
        DeleteEdgeParams {
            edge_id: world_edge.to_string(),
        },
        None,
    )
    .await
    .expect_err("a world edge is not the agent's to retract");
    assert!(
        e.message.contains("admin-only") && !e.message.contains("not found"),
        "{e:?}"
    );
    assert_eq!(e.data.clone().expect("data")["error"], "not_owner");
    assert!(edge_state(&pool, world_edge).await.0, "still in force");

    // The agent's own edge: both work.
    do_patch_edge(&server, &viewer, patch(own_edge), None)
        .await
        .expect("the agent patches its own edge");
    assert_eq!(
        edge_state(&pool, own_edge).await.1["note"],
        "patched",
        "the patch landed"
    );
    do_delete_edge(
        &server,
        &viewer,
        DeleteEdgeParams {
            edge_id: own_edge.to_string(),
        },
        None,
    )
    .await
    .expect("the agent retracts its own edge");
    assert!(!edge_state(&pool, own_edge).await.0, "retracted");

    // A missing edge is still "not found".
    let e = do_delete_edge(
        &server,
        &viewer,
        DeleteEdgeParams {
            edge_id: Uuid::new_v4().to_string(),
        },
        None,
    )
    .await
    .expect_err("missing");
    assert!(e.message.contains("not found"), "{e:?}");
}

/// Batch H-b review (authority-attack, medium), measured on config A: an
/// unrelated `claims:write` caller retired another agent's edge with
/// `patch_edge {valid_to: 2020-01-01}`. H-b closed it with a tool-level check
/// keyed on the edge's SOURCE claim's author; batches W10 and W12b (migrations
/// 117 and 120, operator decision D8) moved that authority into the database:
/// the edge's WRITER owns it, and an UPDATE is owner-scoped. Merged, the MCP
/// write runs on the caller's own stamp (batch H-b, D1), so the database decides
/// with the caller's authority. Measured here on the APPLICATION role, over
/// authenticated HTTP: the stranger's retire is refused as `not_owner` and
/// writes nothing; the edge's writer retires its own edge. (Moved from
/// `edge_mutation_smoke.rs` at the staging merge: a superuser pool bypasses the
/// policy that now carries the property, so only an app-role server measures it.)
#[sqlx::test(migrations = "../../migrations")]
async fn a_stranger_cannot_retire_another_writers_edge_over_http(pool: PgPool) {
    let (server, _agent, _viewer) = app_role_server(&pool).await;
    let (author, author_token, author_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (_stranger, stranger_token, stranger_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let author_group = personal_group_of(&pool, author).await;
    let source = fixture::seed_public_claim(&pool, author, "the author's public source").await;
    let target = fixture::seed_public_claim(&pool, author, "the author's public target").await;
    // D8: an edge between two public claims is owned by its writer's group and
    // stays public.
    let edge = fixture::seed_edge_owned_by(&pool, source, target, "public", author_group).await;
    let retire = |id: Uuid| PatchEdgeParams {
        edge_id: id.to_string(),
        valid_to: Some("2020-01-01T00:00:00Z".to_string()),
        properties: None,
    };

    let e = do_patch_edge(
        &server,
        &stranger_viewer,
        retire(edge),
        Some(&stranger_token),
    )
    .await
    .expect_err("a stranger must not retire another writer's edge over HTTP");
    assert!(
        !e.message.contains("not found"),
        "named, not missing: {e:?}"
    );
    assert_eq!(
        e.data.clone().expect("the refusal carries data")["error"],
        "not_owner",
        "{e:?}"
    );
    assert!(
        edge_state(&pool, edge).await.0,
        "nothing written: still in force"
    );

    do_patch_edge(&server, &author_viewer, retire(edge), Some(&author_token))
        .await
        .expect("the edge's writer retires its own edge");
    assert!(!edge_state(&pool, edge).await.0, "retracted");
}
