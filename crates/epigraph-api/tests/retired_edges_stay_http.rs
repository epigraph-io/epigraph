#![cfg(feature = "db")]
//! Supersede SPEC §11 phase 1, K1 and K2, through the HTTP routes: the edges
//! `POST /api/v1/claims/:id/supersede` and `POST /api/v1/claims/:id/dedup`
//! leave on the claim they retire.
//!
//! K1 (ruling R-133, which generalises R-113(2)): an agent's `AUTHORED` /
//! `asserts` edge, and a supersession act edge, stay on the retired claim.
//! K2: a retracted edge stays on the retired claim.
//!
//! Handlers are invoked directly with the caller's `ViewerExtractor`, as
//! `own_claim_authority_http.rs` does. The `AppState`'s pools are the
//! application role; the inline cascade and the deferred replay run on a
//! NOSUPERUSER `epigraph_maintenance` login (SPEC §12). There is no
//! consolidate HTTP route; its twin is MCP `consolidate_claims`
//! (`crates/epigraph-mcp/tests/retired_edges_stay_mcp.rs`).

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::Extension;
use axum::Json;
use epigraph_api::middleware::bearer::AuthContext;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::versioning::{
    mark_duplicate, supersede_claim, DedupRequest, SupersedeRequest,
};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool, seed_agent_with_group};

/// `(source_id, target_id, still in force)` of one edge.
type Ends = (Uuid, Uuid, bool);

/// Both pools on the application role; with `inline`, the `ScopedPool`'s
/// maintenance pool is a NOSUPERUSER `epigraph_maintenance` login, so the
/// routes run the cascade in the request.
async fn app_role_state(pool: &PgPool, inline: bool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(!bypassrls, "epigraph_app holds BYPASSRLS: vacuous");
    let url = database_url_for(pool).await;
    let mut scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    if inline {
        scoped = scoped.with_maintenance_pool(downgraded_pool(pool, "epigraph_maintenance").await);
    }
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state.admin_cascade = inline;
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

async fn viewer(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("resolve")
}

fn human(agent: Uuid) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Human,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }))
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

/// An edge written on the harness, with `properties` (`{}` when `None`).
async fn edge(
    pool: &PgPool,
    (source, source_type): (Uuid, &str),
    (target, target_type): (Uuid, &str),
    relationship: &str,
    properties: Option<serde_json::Value>,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(source)
    .bind(source_type)
    .bind(target)
    .bind(target_type)
    .bind(relationship)
    .bind(properties.unwrap_or_else(|| serde_json::json!({})))
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {relationship} edge: {e}"))
}

async fn ends(pool: &PgPool, ids: &[Uuid]) -> Vec<Ends> {
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        out.push(
            sqlx::query_as(
                "SELECT source_id, target_id, valid_to IS NULL FROM edges WHERE id = $1",
            )
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("edge"),
        );
    }
    out
}

/// `author` supersedes `old` through the route; returns the successor and
/// asserts the cascade status.
async fn supersede_via_http(
    state: &AppState,
    pool: &PgPool,
    author: Uuid,
    old: Uuid,
    status: &str,
) -> Uuid {
    let (code, Json(resp)) = supersede_claim(
        ViewerExtractor(viewer(pool, author).await),
        State(state.clone()),
        human(author),
        Path(old),
        Json(SupersedeRequest {
            content: format!("a correction of {old}"),
            truth_value: 0.6,
            reason: "retired-edges http".to_string(),
        }),
    )
    .await
    .expect("the author's supersede");
    assert_eq!(code.as_u16(), 201);
    let cascade = serde_json::to_value(&resp.cascade).expect("cascade");
    assert_eq!(cascade["status"], status, "{cascade}");
    resp.new_claim_id
}

/// The `properties` a supersession act edge carries.
fn act_marker() -> serde_json::Value {
    serde_json::json!({
        "tool": "supersede_claim",
        "was_created": true,
        epigraph_db::SUPERSEDE_ACT_PROPERTY: "supersede_claim",
    })
}

// ── K1: agent authorship and act edges ──────────────────────────────────────

struct Authorship {
    authored: Uuid,
    asserts: Uuid,
    control: Uuid,
}

/// Another agent's `AUTHORED` and a third agent's `asserts` into `x`, and a
/// third claim's `supports` (the control every act moves).
async fn seed_authorship(pool: &PgPool, author: Uuid, group: Uuid, x: Uuid) -> Authorship {
    let (w1, _) = seed_agent_with_group(pool, "k1-http-authored-by").await;
    let (w2, _) = seed_agent_with_group(pool, "k1-http-asserted-by").await;
    let y = claim_of(pool, author, group, "k1 http third claim").await;
    Authorship {
        authored: edge(pool, (w1, "agent"), (x, "claim"), "AUTHORED", None).await,
        asserts: edge(pool, (w2, "agent"), (x, "claim"), "asserts", None).await,
        control: edge(pool, (y, "claim"), (x, "claim"), "supports", None).await,
    }
}

/// The supersede route twice, cascade inline: the second act retires a
/// successor carrying the first act's REAL act edge. R-133 (SPEC SF-23).
#[sqlx::test(migrations = "../../migrations")]
async fn http_supersede_leaves_agent_authorship_and_act_edges_on_the_retired_claim(pool: PgPool) {
    let state = app_role_state(&pool, true).await;
    let (author, group) = seed_agent_with_group(&pool, "k1-http-supersede").await;
    let first = claim_of(&pool, author, group, "k1 http first version").await;
    let x = supersede_via_http(&state, &pool, author, first, "applied").await;
    let act_edge: Uuid = sqlx::query_scalar(
        "SELECT id FROM edges WHERE source_id = $1 AND target_id = $2 \
           AND relationship = 'AUTHORED' AND properties ? $3",
    )
    .bind(author)
    .bind(x)
    .bind(epigraph_db::SUPERSEDE_ACT_PROPERTY)
    .fetch_one(&pool)
    .await
    .expect("the first act's act edge on its successor");
    let a = seed_authorship(&pool, author, group, x).await;
    let kept = [a.authored, a.asserts, act_edge];
    let before = ends(&pool, &kept).await;

    let n = supersede_via_http(&state, &pool, author, x, "applied").await;

    assert_eq!(
        ends(&pool, &[a.control]).await[0].1,
        n,
        "the control supports edge followed the successor: the cascade ran"
    );
    assert_eq!(
        ends(&pool, &kept).await,
        before,
        "agent AUTHORED, agent asserts and the act edge stay on the retired claim"
    );
}

/// The dedup route, cascade inline. A supersession successor cannot be marked
/// (its `supersedes` is set), so the act edge is harness-written in the act's
/// shape. R-133 (SPEC SF-23).
#[sqlx::test(migrations = "../../migrations")]
async fn http_dedup_leaves_agent_authorship_and_act_edges_on_the_duplicate(pool: PgPool) {
    let state = app_role_state(&pool, true).await;
    let (author, group) = seed_agent_with_group(&pool, "k1-http-dedup").await;
    let dup = claim_of(&pool, author, group, "k1 http duplicate").await;
    let canonical = claim_of(&pool, author, group, "k1 http canonical").await;
    let a = seed_authorship(&pool, author, group, dup).await;
    let act_edge = edge(
        &pool,
        (author, "agent"),
        (dup, "claim"),
        "AUTHORED",
        Some(act_marker()),
    )
    .await;
    let kept = [a.authored, a.asserts, act_edge];
    let before = ends(&pool, &kept).await;

    let Json(resp) = mark_duplicate(
        ViewerExtractor(viewer(&pool, author).await),
        State(state),
        human(author),
        Path(dup),
        Json(DedupRequest {
            canonical_id: canonical,
            reason: None,
        }),
    )
    .await
    .expect("the author's dedup");
    let cascade = serde_json::to_value(&resp.cascade).expect("cascade");
    assert_eq!(cascade["status"], "applied", "{cascade}");

    let control = ends(&pool, &[a.control]).await[0];
    assert_eq!(
        (control.1, control.2),
        (canonical, true),
        "the control supports edge followed the canonical: the repair ran"
    );
    assert_eq!(
        ends(&pool, &kept).await,
        before,
        "agent AUTHORED, agent asserts and the act edge stay on the duplicate"
    );
}
