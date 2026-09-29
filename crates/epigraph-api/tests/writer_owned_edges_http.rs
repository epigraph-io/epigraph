//! Migration 120 (operator decision D8) through the HTTP edge write routes, on
//! the APPLICATION ROLE.
//!
//! Before batch W12b the five edge write handlers ran on the unstamped raw
//! pool: every HTTP-created edge between two public claims landed world-owned
//! (administrative from birth), and on the application role the owner's own
//! patch and retract matched zero rows. They now run on a transaction stamped
//! with the caller's viewer (`AppState::write_as`).
//!
//! # The instrument
//!
//! BOTH pools of the `AppState` are downgraded to `epigraph_app`: the stamped
//! `ScopedPool` (`connect_downgraded_for_tests`) that the converted handlers
//! write through, and the raw `db_pool` their post-commit side effects use. A
//! superuser pool bypasses every policy, so on one "the patch changed 0 rows"
//! and "the patch changed 1 row" would be indistinguishable. Handlers are
//! invoked directly, with the caller's `ViewerExtractor`.

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Extension;
use axum::Json;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::AuthContext;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::conventions::{forget_convention, share_skill, ShareSkillRequest};
use epigraph_api::routes::edges::{
    create_edge, create_hierarchical_edge, delete_edge, patch_edge, relate_claims,
    CreateEdgeRequest, LinkHierarchicalRequest, PatchEdgeRequest, RelateClaimsRequest,
};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    database_url_for, downgraded_pool, seed_agent_with_group, seed_edge, seed_group_claim,
    seed_public_claim, world_group,
};

async fn app_role_state(pool: &PgPool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

/// The shape of a deployment still serving on a privileged DSN (before the
/// application-role move): the raw `db_pool` is the harness superuser, so a
/// handler's unstamped statements land; the stamped `ScopedPool` is the
/// application role, so an edge written through `AppState::write_as` is held
/// to the caller's own writable groups and proves the stamp.
async fn privileged_raw_state(pool: &PgPool) -> AppState {
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let mut state = AppState::with_db(pool.clone(), ApiConfig::default());
    state.scoped = Some(scoped);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

async fn viewer(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("resolve")
}

/// The `AuthContext` `bearer_auth_middleware` attaches for `agent`'s token with
/// `scopes`. The converted handlers take `ViewerExtractor`, which refuses a
/// request without one, so they check the scope unconditionally.
fn auth_with(agent: Uuid, scopes: &[&str]) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: agent,
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: ClientType::Service,
        scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        jti: Uuid::new_v4(),
    }))
}

fn auth(agent: Uuid) -> Option<Extension<AuthContext>> {
    auth_with(agent, &["edges:write"])
}

/// `(owner, visibility, co_owner, writer_group_id, valid_to IS NULL, properties)`.
type Row = (
    Uuid,
    String,
    Option<Uuid>,
    Option<Uuid>,
    bool,
    serde_json::Value,
);

async fn row(pool: &PgPool, e: Uuid) -> Row {
    sqlx::query_as(
        "SELECT owner_group_id, visibility::text, co_owner_group_id, writer_group_id, \
                valid_to IS NULL, properties FROM edges WHERE id = $1",
    )
    .bind(e)
    .fetch_one(pool)
    .await
    .expect("edge row")
}

fn create_body(source: Uuid, target: Uuid) -> CreateEdgeRequest {
    CreateEdgeRequest {
        source_id: source,
        target_id: target,
        source_type: "claim".to_string(),
        target_type: "claim".to_string(),
        relationship: "supports".to_string(),
        properties: None,
        labels: None,
        valid_from: None,
        valid_to: None,
        if_not_exists: false,
    }
}

fn note(n: &str) -> PatchEdgeRequest {
    PatchEdgeRequest {
        valid_to: None,
        properties: Some(serde_json::json!({ "note": n })),
    }
}

/// The status and JSON body an `ApiError` renders.
async fn rendered(e: ApiError) -> (u16, serde_json::Value) {
    let resp = e.into_response();
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn assert_not_owner(e: ApiError, rule: &str) {
    let (status, body) = rendered(e).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"], "not_owner", "{body}");
    assert_eq!(body["rule"], rule, "{body}");
    assert_eq!(body["retryable"], false, "{body}");
}

/// Test 12: the owner creates, patches and retracts over HTTP on the
/// application role, one row each, and the edge is its writer group's. A
/// bystander who can read it gets `403 not_owner` naming the rule, with nothing
/// written; a world edge names the administrative rule; an edge the bystander
/// cannot read is still a 404.
#[sqlx::test(migrations = "../../migrations")]
async fn the_owner_writes_its_edge_over_http_and_a_bystander_is_refused_by_name(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (author, _) = seed_agent_with_group(&pool, "author").await;
    let (w, w_g) = seed_agent_with_group(&pool, "http-writer-w").await;
    let (z, _) = seed_agent_with_group(&pool, "http-bystander-z").await;
    let a = seed_public_claim(&pool, author, "w12b http public a").await;
    let b = seed_public_claim(&pool, author, "w12b http public b").await;
    let c = seed_public_claim(&pool, author, "w12b http public c").await;
    let world_edge = seed_edge(&pool, b, c).await;
    assert_eq!(row(&pool, world_edge).await.0, world_group(&pool).await);
    let w_private = seed_group_claim(&pool, w, w_g, "w12b http W-private").await;
    let hidden = seed_edge(&pool, w_private, a).await;

    // A token without `edges:write` cannot create (403), and nothing is
    // written. The other handlers are checked on W's OWN edge below.
    let edges_before: i64 = sqlx::query_scalar("SELECT count(*) FROM edges")
        .fetch_one(&pool)
        .await
        .expect("count");
    let no_scope = create_edge(
        ViewerExtractor(viewer(&pool, w).await),
        State(state.clone()),
        auth_with(w, &["claims:read"]),
        Json(create_body(a, b)),
    )
    .await
    .expect_err("no edges:write scope");
    assert!(
        matches!(no_scope, ApiError::Forbidden { .. }),
        "{no_scope:?}"
    );
    let edges_after: i64 = sqlx::query_scalar("SELECT count(*) FROM edges")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(edges_after, edges_before, "nothing written");

    // W creates: 201, its own, the author record set.
    let (status, Json(created)) = create_edge(
        ViewerExtractor(viewer(&pool, w).await),
        State(state.clone()),
        auth(w),
        Json(create_body(a, b)),
    )
    .await
    .expect("the owner creates its edge over HTTP on the application role");
    assert_eq!(status.as_u16(), 201);
    assert!(created.owned_by_caller);
    let edge = created.edge.id;
    let r = row(&pool, edge).await;
    assert_eq!(
        (r.0, r.1.as_str(), r.2, r.3, r.4),
        (w_g, "public", None, Some(w_g), true)
    );

    // The scope check is unconditional in every converted handler: W, whose
    // edge this is and who may otherwise patch, retract and relate, is
    // refused 403 by each without `edges:write`, and nothing is written.
    let no_scope = || auth_with(w, &["claims:read"]);
    let edges_before: i64 = sqlx::query_scalar("SELECT count(*) FROM edges")
        .fetch_one(&pool)
        .await
        .expect("count");
    let refused = patch_edge(
        ViewerExtractor(viewer(&pool, w).await),
        State(state.clone()),
        no_scope(),
        Path(edge),
        Json(note("without the scope")),
    )
    .await
    .expect_err("patch without edges:write");
    assert!(matches!(refused, ApiError::Forbidden { .. }), "{refused:?}");
    let refused = delete_edge(
        ViewerExtractor(viewer(&pool, w).await),
        State(state.clone()),
        no_scope(),
        Path(edge),
    )
    .await
    .expect_err("delete without edges:write");
    assert!(matches!(refused, ApiError::Forbidden { .. }), "{refused:?}");
    let refused = relate_claims(
        ViewerExtractor(viewer(&pool, w).await),
        State(state.clone()),
        no_scope(),
        Path(a),
        Json(RelateClaimsRequest {
            target_claim_id: b,
            properties: None,
        }),
    )
    .await
    .expect_err("relate without edges:write");
    assert!(matches!(refused, ApiError::Forbidden { .. }), "{refused:?}");
    let r = row(&pool, edge).await;
    assert!(
        r.4 && r.5 == serde_json::json!({}),
        "W's edge is untouched: {r:?}"
    );
    let edges_after: i64 = sqlx::query_scalar("SELECT count(*) FROM edges")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(edges_after, edges_before, "relate wrote no edge");

    // Z: refused by name, nothing written.
    let refused = patch_edge(
        ViewerExtractor(viewer(&pool, z).await),
        State(state.clone()),
        auth(z),
        Path(edge),
        Json(note("by z")),
    )
    .await
    .expect_err("not Z's to patch");
    assert_not_owner(refused, "owned_by_another_writer").await;
    let refused = delete_edge(
        ViewerExtractor(viewer(&pool, z).await),
        State(state.clone()),
        auth(z),
        Path(edge),
    )
    .await
    .expect_err("not Z's to delete");
    assert_not_owner(refused, "owned_by_another_writer").await;
    let r = row(&pool, edge).await;
    assert!(
        r.4 && r.5 == serde_json::json!({}),
        "nothing written: {r:?}"
    );

    // A world edge: administrative. An invisible edge: 404.
    let refused = delete_edge(
        ViewerExtractor(viewer(&pool, z).await),
        State(state.clone()),
        auth(z),
        Path(world_edge),
    )
    .await
    .expect_err("admin-only");
    assert_not_owner(refused, "administrative_edge").await;
    let missing = delete_edge(
        ViewerExtractor(viewer(&pool, z).await),
        State(state.clone()),
        auth(z),
        Path(hidden),
    )
    .await
    .expect_err("invisible to Z");
    assert_eq!(rendered(missing).await.0, 404);

    // W patches and retracts its own: one row each.
    let Json(patched) = patch_edge(
        ViewerExtractor(viewer(&pool, w).await),
        State(state.clone()),
        auth(w),
        Path(edge),
        Json(note("by w")),
    )
    .await
    .expect("the owner patches its edge");
    assert_eq!(patched.properties["note"], "by w");
    let status = delete_edge(
        ViewerExtractor(viewer(&pool, w).await),
        State(state.clone()),
        auth(w),
        Path(edge),
    )
    .await
    .expect("the owner retracts its edge");
    assert_eq!(status.as_u16(), 204);
    let r = row(&pool, edge).await;
    assert!(!r.4, "retracted");
    assert_eq!(r.5["note"], "by w");
}

/// The other two converted write routes own their edges by the caller too, and
/// a caller that may not write the meet of a mixed edge is refused (403) with
/// nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn hierarchical_and_relate_are_the_callers_and_a_mixed_edge_is_decided_by_its_group(
    pool: PgPool,
) {
    let state = app_role_state(&pool).await;
    let (author, _) = seed_agent_with_group(&pool, "author").await;
    let (w, w_g) = seed_agent_with_group(&pool, "http-writer-w").await;
    let (owner, g) = seed_agent_with_group(&pool, "group-owner").await;
    let (reader, _) = seed_agent_with_group(&pool, "reader-of-g").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(g)
    .bind(reader)
    .execute(&pool)
    .await
    .expect("reader membership");
    let a = seed_public_claim(&pool, author, "w12b http public a").await;
    let b = seed_public_claim(&pool, author, "w12b http public b").await;
    let private = seed_group_claim(&pool, owner, g, "w12b http G-private").await;

    let (_, Json(h)) = create_hierarchical_edge(
        ViewerExtractor(viewer(&pool, w).await),
        State(state.clone()),
        auth(w),
        Json(LinkHierarchicalRequest {
            source_claim_id: a,
            target_claim_id: b,
            relationship: "decomposes_to".to_string(),
            properties: None,
        }),
    )
    .await
    .expect("hierarchical link");
    assert!(h.created && h.owned_by_caller);
    assert_eq!(row(&pool, h.edge_id).await.0, w_g);

    let (_, Json(rel)) = relate_claims(
        ViewerExtractor(viewer(&pool, w).await),
        State(state.clone()),
        auth(w),
        Path(a),
        Json(RelateClaimsRequest {
            target_claim_id: b,
            properties: None,
        }),
    )
    .await
    .expect("relate");
    let ids: Vec<Uuid> = serde_json::from_value(rel["edge_ids"].clone()).expect("edge ids");
    assert_eq!(ids.len(), 2);
    for id in ids {
        let r = row(&pool, id).await;
        assert_eq!(
            (r.0, r.3),
            (w_g, Some(w_g)),
            "both RELATES_TO edges are W's"
        );
    }

    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM edges")
        .fetch_one(&pool)
        .await
        .expect("count");
    let refused = create_edge(
        ViewerExtractor(viewer(&pool, reader).await),
        State(state.clone()),
        auth(reader),
        Json(create_body(a, private)),
    )
    .await
    .expect_err("a reader of G may not write an edge the meet gives to G");
    assert_eq!(rendered(refused).await.0, 403);
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM edges")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(after, before, "nothing written");
}

/// Brief 4.4: a registered handler that already holds a viewer writes its
/// in-scope edge on a transaction stamped with the caller's viewer.
/// `share_skill` (claim -> claim SHARED_BY) and `forget_convention`
/// (evidence -> claim REFUTES) write every other statement on the raw pool
/// (autocommit, no transaction to split), so their edge statement alone moved
/// to `AppState::write_as`. The edge is the caller's, and the caller (not a
/// bystander) can retract it on the application role.
#[sqlx::test(migrations = "../../migrations")]
async fn a_viewer_holding_handlers_edge_is_the_callers(pool: PgPool) {
    let state = privileged_raw_state(&pool).await;
    let app = app_role_state(&pool).await;
    let (author, _) = seed_agent_with_group(&pool, "author").await;
    let (w, w_g) = seed_agent_with_group(&pool, "http-sharer-w").await;
    let (z, _) = seed_agent_with_group(&pool, "http-bystander-z").await;
    let workflow = seed_public_claim(&pool, author, "w12b http shared workflow").await;
    let convention = seed_public_claim(&pool, author, "w12b http convention").await;

    // share_skill: the SHARED_BY edge is W's.
    let (status, Json(shared)) = share_skill(
        ViewerExtractor(viewer(&pool, w).await),
        State(state.clone()),
        Json(ShareSkillRequest {
            workflow_id: workflow,
        }),
    )
    .await
    .expect("W shares the workflow");
    assert_eq!(status.as_u16(), 201);
    let r = row(&pool, shared.edge_id).await;
    assert_eq!(
        (r.0, r.1.as_str(), r.2, r.3, r.4),
        (w_g, "public", None, Some(w_g), true),
        "the caller's SHARED_BY edge, not an administrative one"
    );
    let refused = delete_edge(
        ViewerExtractor(viewer(&pool, z).await),
        State(app.clone()),
        auth(z),
        Path(shared.edge_id),
    )
    .await
    .expect_err("not Z's to retract");
    assert_not_owner(refused, "owned_by_another_writer").await;
    assert!(row(&pool, shared.edge_id).await.4, "still in force");
    let status = delete_edge(
        ViewerExtractor(viewer(&pool, w).await),
        State(app.clone()),
        auth(w),
        Path(shared.edge_id),
    )
    .await
    .expect("W retracts the edge it wrote");
    assert_eq!(status.as_u16(), 204);
    assert!(!row(&pool, shared.edge_id).await.4, "retracted");

    // forget_convention: the REFUTES edge is W's.
    let Json(forgotten) = forget_convention(
        ViewerExtractor(viewer(&pool, w).await),
        State(state.clone()),
        auth_with(w, &["claims:admin"]),
        Path(convention),
    )
    .await
    .expect("W forgets the convention");
    assert_eq!(forgotten.claim_id, convention);
    let refutes: Vec<(Uuid, String, Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
        "SELECT owner_group_id, visibility::text, co_owner_group_id, writer_group_id \
           FROM edges WHERE target_id = $1 AND relationship = 'REFUTES'",
    )
    .bind(convention)
    .fetch_all(&pool)
    .await
    .expect("REFUTES edges");
    assert_eq!(
        refutes,
        vec![(w_g, "public".to_string(), None, Some(w_g))],
        "exactly one REFUTES edge, the caller's"
    );
}
