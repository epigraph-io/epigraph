//! Migration 120 (operator decision D8) through the MCP edge tools, on the
//! APPLICATION ROLE: an edge between two public claims is its writer's.
//!
//! Two MCP servers with DIFFERENT signing agents share one database, both
//! downgraded to `epigraph_app` (a superuser pool bypasses every policy, see
//! `writer_owned_attach_app_role.rs`):
//!
//! * W's server links two public claims with `link_epistemic`: the edge is W's
//!   group's (`owned_by_caller = true`);
//! * Z's server can read it, and its `patch_edge` / `delete_edge` answer the
//!   explicit `not_owner` refusal naming "owned by another writer", with
//!   nothing written; on a world edge they name the administrative rule; on an
//!   edge Z cannot read they keep "not found";
//! * W patches and retracts its own edge; W then links the same triple again
//!   and gets a NEW in-force edge (never a silent `was_created = false` onto the
//!   retracted row); Z re-asserting the triple gets W's edge back with
//!   `owned_by_caller = false`;
//! * the same holds for the SYMMETRIC link tools (`link_epistemic` with
//!   `contradicts`, in either direction, and `link_alternative`): their probe
//!   matches rows in force only, so a retracted symmetric link asserted again
//!   is a new edge. (The matcher's own promotion probe still matches any
//!   state; it is not a caller link.)

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::edge_mutation::{do_delete_edge, do_patch_edge};
use epigraph_mcp::tools::link_alternative::do_link_alternative;
use epigraph_mcp::tools::link_epistemic::do_link_epistemic;
use epigraph_mcp::types::{
    DeleteEdgeParams, LinkAlternativeParams, LinkEpistemicParams, PatchEdgeParams,
};
use rmcp::model::ErrorCode;
use sqlx::PgPool;
use uuid::Uuid;

struct Side {
    server: EpiGraphMcpFull,
    group: Uuid,
    viewer: Viewer,
}

async fn app_role_pools(pool: &PgPool) -> (PgPool, ScopedPool) {
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
    (plain, scoped)
}

async fn side(pool: &PgPool, server: EpiGraphMcpFull) -> Side {
    let agent = server.server_agent_id().await.expect("server agent");
    let group = personal_group_of(pool, agent).await;
    let viewer = Viewer::resolve(pool, agent).await.expect("viewer");
    Side {
        server,
        group,
        viewer,
    }
}

#[derive(serde::Deserialize)]
struct Linked {
    edge_id: Uuid,
    was_created: bool,
    owned_by_caller: bool,
}

fn text(result: &rmcp::model::CallToolResult) -> String {
    result
        .content
        .first()
        .expect("a content block")
        .as_text()
        .expect("text")
        .text
        .clone()
}

async fn link(s: &Side, a: Uuid, b: Uuid) -> Linked {
    link_as(s, a, b, "supports").await
}

async fn link_as(s: &Side, a: Uuid, b: Uuid, relationship: &str) -> Linked {
    let r = do_link_epistemic(
        &s.server,
        &s.viewer,
        LinkEpistemicParams {
            source_claim_id: a.to_string(),
            target_claim_id: b.to_string(),
            relationship: relationship.to_string(),
            properties: None,
        },
    )
    .await
    .expect("link_epistemic");
    let raw = text(&r);
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{e}: {raw}"))
}

fn patch(e: Uuid) -> PatchEdgeParams {
    PatchEdgeParams {
        edge_id: e.to_string(),
        valid_to: None,
        properties: Some(serde_json::json!({"note": "patched"})),
    }
}

fn delete(e: Uuid) -> DeleteEdgeParams {
    DeleteEdgeParams {
        edge_id: e.to_string(),
    }
}

/// `(owner, visibility, valid_to IS NULL, properties)`.
async fn state(pool: &PgPool, e: Uuid) -> (Uuid, String, bool, serde_json::Value) {
    sqlx::query_as(
        "SELECT owner_group_id, visibility::text, valid_to IS NULL, properties \
           FROM edges WHERE id = $1",
    )
    .bind(e)
    .fetch_one(pool)
    .await
    .expect("edge state")
}

fn assert_not_owner(e: &rmcp::model::ErrorData, rule: &str, phrase: &str) {
    assert_eq!(e.code, ErrorCode::INVALID_REQUEST, "{e:?}");
    assert!(
        e.message.contains(phrase) && !e.message.contains("not found"),
        "the refusal names the rule, never absence: {e:?}"
    );
    let data = e.data.clone().expect("the refusal carries data");
    assert_eq!(data["error"], "not_owner", "{data}");
    assert_eq!(data["rule"], rule, "{data}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_bystander_is_refused_by_name_and_the_writer_owns_its_edge(pool: PgPool) {
    let (plain, scoped) = app_role_pools(&pool).await;
    let w = side(
        &pool,
        build_scoped_test_server(plain.clone(), scoped.clone()),
    )
    .await;
    let z = side(
        &pool,
        build_scoped_test_server_generated_signer(plain, scoped),
    )
    .await;
    assert_ne!(w.group, z.group, "two writers, two groups");

    let author = fixture::seed_agent_with_group(&pool, "author").await.0;
    let a = fixture::seed_public_claim(&pool, author, "w12b mcp public a").await;
    let b = fixture::seed_public_claim(&pool, author, "w12b mcp public b").await;
    let c = fixture::seed_public_claim(&pool, author, "w12b mcp public c").await;
    let world_edge = fixture::seed_edge(&pool, b, c).await;
    let w_private = fixture::seed_group_claim(&pool, author, w.group, "w12b W-private").await;
    let hidden = fixture::seed_edge(&pool, w_private, a).await;

    // W links: its own edge.
    let first = link(&w, a, b).await;
    assert!(first.was_created && first.owned_by_caller);
    let (owner, vis, live, _) = state(&pool, first.edge_id).await;
    assert_eq!((owner, vis.as_str(), live), (w.group, "public", true));

    // Z: refused by name, nothing written.
    let e = do_patch_edge(&z.server, &z.viewer, patch(first.edge_id))
        .await
        .expect_err("not Z's to patch");
    assert_not_owner(&e, "owned_by_another_writer", "owned by another writer");
    let e = do_delete_edge(&z.server, &z.viewer, delete(first.edge_id))
        .await
        .expect_err("not Z's to delete");
    assert_not_owner(&e, "owned_by_another_writer", "owned by another writer");
    let (_, _, live, props) = state(&pool, first.edge_id).await;
    assert!(live, "still in force");
    assert_eq!(props, serde_json::json!({}), "nothing merged");

    // A world edge: the administrative rule.
    let e = do_delete_edge(&z.server, &z.viewer, delete(world_edge))
        .await
        .expect_err("admin-only");
    assert_not_owner(
        &e,
        "administrative_edge",
        "administrative (world-owned) edge",
    );

    // An edge Z cannot read: still "not found", no oracle.
    let e = do_delete_edge(&z.server, &z.viewer, delete(hidden))
        .await
        .expect_err("invisible to Z");
    assert!(e.message.contains("not found"), "{e:?}");
    assert!(e.data.is_none(), "no not_owner data for an invisible edge");

    // W patches and retracts its own.
    do_patch_edge(&w.server, &w.viewer, patch(first.edge_id))
        .await
        .expect("W patches its edge");
    do_delete_edge(&w.server, &w.viewer, delete(first.edge_id))
        .await
        .expect("W retracts its edge");
    let (_, _, live, props) = state(&pool, first.edge_id).await;
    assert!(!live, "retracted");
    assert_eq!(props["note"], "patched");

    // Retract, then link again: a NEW edge.
    let again = link(&w, a, b).await;
    assert!(
        again.was_created,
        "not a silent no-op onto the retracted row"
    );
    assert!(again.owned_by_caller);
    assert_ne!(again.edge_id, first.edge_id);
    assert!(state(&pool, again.edge_id).await.2, "in force");

    // Z re-asserts the same triple: W's edge, not Z's.
    let by_z = link(&z, a, b).await;
    assert_eq!(
        (by_z.edge_id, by_z.was_created, by_z.owned_by_caller),
        (again.edge_id, false, false)
    );
}

#[derive(serde::Deserialize)]
struct Alternative {
    edge_id: Uuid,
    created: bool,
}

async fn alternative(s: &Side, a: Uuid, b: Uuid) -> Alternative {
    let r = do_link_alternative(
        &s.server,
        &s.viewer,
        LinkAlternativeParams {
            claim_a: a.to_string(),
            claim_b: b.to_string(),
            target_claim_id: None,
            rationale: None,
        },
    )
    .await
    .expect("link_alternative");
    let raw = text(&r);
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{e}: {raw}"))
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_retracted_symmetric_link_asserted_again_is_a_new_edge(pool: PgPool) {
    let (plain, scoped) = app_role_pools(&pool).await;
    let w = side(&pool, build_scoped_test_server(plain, scoped)).await;
    let author = fixture::seed_agent_with_group(&pool, "author").await.0;
    let a = fixture::seed_public_claim(&pool, author, "w12b symmetric a").await;
    let b = fixture::seed_public_claim(&pool, author, "w12b symmetric b").await;

    // link_epistemic, `contradicts` (symmetric): W links a -> b, re-asserts it
    // (a dedup hit while in force), retracts it, then asserts it in the
    // REVERSE direction.
    let first = link_as(&w, a, b, "contradicts").await;
    assert!(first.was_created && first.owned_by_caller);
    let hit = link_as(&w, b, a, "contradicts").await;
    assert_eq!(
        (hit.edge_id, hit.was_created),
        (first.edge_id, false),
        "in force, either direction is the same symmetric edge"
    );
    do_delete_edge(&w.server, &w.viewer, delete(first.edge_id))
        .await
        .expect("W retracts its contradicts link");
    assert!(!state(&pool, first.edge_id).await.2, "retracted");
    let again = link_as(&w, b, a, "contradicts").await;
    assert!(
        again.was_created,
        "a retracted symmetric link asserted again is a new edge, not a silent no-op"
    );
    assert_ne!(again.edge_id, first.edge_id);
    let (owner, vis, live, _) = state(&pool, again.edge_id).await;
    assert_eq!((owner, vis.as_str(), live), (w.group, "public", true));
    assert!(again.owned_by_caller);
    // And a further re-assert finds the NEW edge, never the retracted twin.
    let hit = link_as(&w, a, b, "contradicts").await;
    assert_eq!((hit.edge_id, hit.was_created), (again.edge_id, false));

    // link_alternative (`alternative_of`, symmetric): the same.
    let alt = alternative(&w, a, b).await;
    assert!(alt.created);
    do_delete_edge(&w.server, &w.viewer, delete(alt.edge_id))
        .await
        .expect("W retracts its alternative_of link");
    let alt2 = alternative(&w, b, a).await;
    assert!(
        alt2.created,
        "a retracted alternative_of asserted again is a new edge"
    );
    assert_ne!(alt2.edge_id, alt.edge_id);
    assert!(state(&pool, alt2.edge_id).await.2, "in force");
    let alt3 = alternative(&w, a, b).await;
    assert_eq!((alt3.edge_id, alt3.created), (alt2.edge_id, false));
}
