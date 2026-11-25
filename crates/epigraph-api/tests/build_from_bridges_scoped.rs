#![cfg(feature = "db")]
//! `POST /api/v1/clusters/build-from-bridges` clusters only what the CALLER
//! may read, and writes the run on the caller's stamped transaction
//! (backlog 67c905a3).
//!
//! # The defect
//!
//! The handler read its two `edges ⨝ claims` statements (the bridge edges and
//! the paragraph nodes) inline on `state.db_pool` with no `Viewer`, then wrote
//! `graph_cluster_runs` / `graph_clusters` / `claim_cluster_membership` from
//! them on the same raw pool. On a login that bypasses row security every
//! paragraph in the database was clustered for any `claims:admin` bearer,
//! whatever groups it belongs to; on the application role the unstamped
//! session read public rows only and wrote with an empty writable set.
//!
//! # The two instruments
//!
//! * **Superuser arm** ([`superuser_router`]): both `AppState.db_pool` and
//!   `AppState.scoped` are the test's superuser login, so row security filters
//!   nothing and only the in-query predicate the repo splices can remove a
//!   row. The OLD code reads everything here, which is the failure this arm
//!   proves. It carries three kinds of paragraph pair besides the calibrations:
//!   - a foreign group's private pair whose `decomposes_to` edges are left as
//!     the edge trigger stamps them (private to that group);
//!   - a foreign group's private pair whose edges are FORCED public, so only
//!     the CLAIM marker (`{VISIBILITY:p}`) can drop it
//!     (`viewer_fixture::seed_edge_owned_by` explains why an edge that tracks
//!     its endpoints would let the claim marker be deleted unnoticed);
//!   - a PUBLIC pair whose shared atom is a foreign group's private claim, so
//!     its edges are private to that group and only the EDGE marker
//!     (`{EDGE_VISIBILITY:e}`) can drop it.
//!
//!   Calibrations: the caller's own private pair and a public pair ARE
//!   clustered, so an empty answer cannot pass.
//! * **Application-role arm** ([`app_role_router`]): both pools are
//!   `epigraph_app` (no BYPASSRLS, row security FORCEd), as in production.
//!   The caller's own private pair is clustered and a foreign private pair is
//!   not. A PUBLIC paragraph is a separate arm: its membership row inherits the
//!   claim's `('public', world)` tenancy, the world group is in nobody's
//!   writable set, so row security refuses the write (`42501`); the handler
//!   answers 403 and commits nothing.
//!
//! `#[sqlx::test]` hands every test a fresh database migrated from empty.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::BTreeSet;
use tower::ServiceExt;
use uuid::Uuid;

mod viewer_fixture;

// ── Instruments ──

/// Both pools are the superuser login: only the spliced predicate filters.
async fn superuser_router(pool: &PgPool) -> axum::Router {
    let scoped = viewer_fixture::scoped_pool(pool).await;
    create_router(AppState::with_scoped_pool(scoped, ApiConfig::default()))
}

/// Both pools are `epigraph_app`, as in production.
async fn app_role_router(pool: &PgPool) -> axum::Router {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = viewer_fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = viewer_fixture::downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    create_router(state)
}

/// A `claims:admin` token bound to `agent`.
fn admin_token(agent: Uuid) -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (t, _jti) = cfg
        .issue_access_token(
            agent,
            vec!["claims:admin".to_string()],
            "service",
            Some(agent),
            Some(agent),
            chrono::Duration::minutes(60),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("test JWT issued");
    t
}

async fn build(app: axum::Router, caller: Uuid) -> (StatusCode, String) {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/clusters/build-from-bridges")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", admin_token(caller)),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"min_shared_atoms": 1, "resolution": 1.0, "retain_runs": 5}).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

// ── Seeding (all on the superuser harness pool) ──

async fn set_level(pool: &PgPool, claim: Uuid, level: i32) {
    sqlx::query(
        "UPDATE claims SET properties = jsonb_build_object('level', $2::int) WHERE id = $1",
    )
    .bind(claim)
    .bind(level)
    .execute(pool)
    .await
    .expect("set level");
}

async fn public_claim(pool: &PgPool, agent: Uuid, level: i32) -> Uuid {
    let id = viewer_fixture::seed_public_claim(
        pool,
        agent,
        &format!("67c905a3 public L{level} {}", Uuid::new_v4()),
    )
    .await;
    set_level(pool, id, level).await;
    id
}

async fn group_claim(pool: &PgPool, agent: Uuid, group: Uuid, level: i32) -> Uuid {
    let id = viewer_fixture::seed_group_claim(
        pool,
        agent,
        group,
        &format!("67c905a3 private L{level} {}", Uuid::new_v4()),
    )
    .await;
    set_level(pool, id, level).await;
    id
}

/// A `decomposes_to` edge, tenancy as the edge trigger stamps it from its
/// endpoints.
async fn decomposes(pool: &PgPool, parent: Uuid, child: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship) \
         VALUES ($1, $2, 'claim', 'claim', 'decomposes_to') RETURNING id",
    )
    .bind(parent)
    .bind(child)
    .fetch_one(pool)
    .await
    .expect("seed decomposes_to edge")
}

/// A `decomposes_to` edge FORCED to `('public', world)`, single-owner. Same
/// shape as `viewer_fixture::seed_edge_owned_by` (which seeds `supports`).
async fn decomposes_forced_public(pool: &PgPool, parent: Uuid, child: Uuid) {
    let id = decomposes(pool, parent, child).await;
    let world = viewer_fixture::world_group(pool).await;
    sqlx::query(
        "UPDATE edges SET visibility = 'public', owner_group_id = $2, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .bind(world)
    .execute(pool)
    .await
    .expect("force edge tenancy");
}

/// Two paragraphs sharing one atom, plus one atom each of their own.
struct Pair {
    a: Uuid,
    b: Uuid,
}

async fn wire_pair(pool: &PgPool, a: Uuid, b: Uuid, shared: Uuid, own_a: Uuid, own_b: Uuid) {
    decomposes(pool, a, shared).await;
    decomposes(pool, b, shared).await;
    decomposes(pool, a, own_a).await;
    decomposes(pool, b, own_b).await;
}

async fn own_private_pair(pool: &PgPool, agent: Uuid, group: Uuid) -> Pair {
    let a = group_claim(pool, agent, group, 2).await;
    let b = group_claim(pool, agent, group, 2).await;
    let shared = group_claim(pool, agent, group, 3).await;
    let own_a = group_claim(pool, agent, group, 3).await;
    let own_b = group_claim(pool, agent, group, 3).await;
    wire_pair(pool, a, b, shared, own_a, own_b).await;
    Pair { a, b }
}

async fn public_pair(pool: &PgPool, agent: Uuid) -> Pair {
    let a = public_claim(pool, agent, 2).await;
    let b = public_claim(pool, agent, 2).await;
    let shared = public_claim(pool, agent, 3).await;
    let own_a = public_claim(pool, agent, 3).await;
    let own_b = public_claim(pool, agent, 3).await;
    wire_pair(pool, a, b, shared, own_a, own_b).await;
    Pair { a, b }
}

/// Fetch the run's membership as a set of claim ids.
async fn members(pool: &PgPool, run_id: Uuid) -> BTreeSet<Uuid> {
    sqlx::query_scalar::<_, Uuid>("SELECT claim_id FROM claim_cluster_membership WHERE run_id = $1")
        .bind(run_id)
        .fetch_all(pool)
        .await
        .expect("read membership")
        .into_iter()
        .collect()
}

async fn cluster_of(pool: &PgPool, run_id: Uuid, claim: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT cluster_id FROM claim_cluster_membership WHERE run_id = $1 AND claim_id = $2",
    )
    .bind(run_id)
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("clustered")
}

fn run_id_of(body: &str) -> Uuid {
    let v: Value = serde_json::from_str(body).expect("JSON body");
    Uuid::parse_str(v["run_id"].as_str().expect("run_id")).expect("uuid")
}

// ── Superuser arm: only the spliced predicates filter ──

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_paragraph_outside_the_callers_groups_is_not_clustered(pool: PgPool) {
    let (caller, caller_group) = viewer_fixture::seed_agent_with_group(&pool, "67c9-caller").await;
    let (foreign, foreign_group) =
        viewer_fixture::seed_agent_with_group(&pool, "67c9-foreign").await;

    // Calibrations: these MUST be clustered.
    let own = own_private_pair(&pool, caller, caller_group).await;
    let public = public_pair(&pool, foreign).await;

    // 1. Foreign private pair, edges as the trigger stamps them.
    let hidden = own_private_pair(&pool, foreign, foreign_group).await;

    // 2. Foreign private pair whose edges are FORCED public: only the claim
    //    marker on `p` can drop it.
    let forced = {
        let a = group_claim(&pool, foreign, foreign_group, 2).await;
        let b = group_claim(&pool, foreign, foreign_group, 2).await;
        let shared = public_claim(&pool, foreign, 3).await;
        decomposes_forced_public(&pool, a, shared).await;
        decomposes_forced_public(&pool, b, shared).await;
        Pair { a, b }
    };

    // 3. PUBLIC paragraphs whose only atom is a foreign PRIVATE claim: their
    //    `decomposes_to` edges are private to the foreign group, so only the
    //    edge marker on `e` can drop them (the paragraphs themselves are
    //    readable).
    let edge_hidden = {
        let a = public_claim(&pool, foreign, 2).await;
        let b = public_claim(&pool, foreign, 2).await;
        let shared = group_claim(&pool, foreign, foreign_group, 3).await;
        decomposes(&pool, a, shared).await;
        decomposes(&pool, b, shared).await;
        Pair { a, b }
    };

    let (status, body) = build(superuser_router(&pool).await, caller).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    let run_id = run_id_of(&body);

    let got = members(&pool, run_id).await;
    let want: BTreeSet<Uuid> = [own.a, own.b, public.a, public.b].into_iter().collect();
    for (what, p) in [
        ("foreign private (trigger-stamped edges)", &hidden),
        (
            "foreign private (edges forced public: claim marker)",
            &forced,
        ),
        (
            "public over a foreign private atom (edge marker)",
            &edge_hidden,
        ),
    ] {
        assert!(
            !got.contains(&p.a) && !got.contains(&p.b),
            "{what} paragraph was clustered for a caller outside its group: {body}"
        );
    }
    assert_eq!(
        got, want,
        "exactly the caller's own and the public pair: {body}"
    );
    assert_eq!(v["paragraph_count"], 4, "{body}");
    assert_eq!(v["bridge_edge_count"], 2, "{body}");
    assert_eq!(v["cluster_count"], 2, "{body}");
    assert_eq!(
        cluster_of(&pool, run_id, own.a).await,
        cluster_of(&pool, run_id, own.b).await,
        "the caller's own pair shares a cluster"
    );

    // The owner of the foreign group, by contrast, DOES get its pairs: the
    // filter is the viewer's, not a blanket exclusion of private rows.
    let (status, body) = build(superuser_router(&pool).await, foreign).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let got = members(&pool, run_id_of(&body)).await;
    for p in [&hidden, &forced, &edge_hidden, &public] {
        assert!(
            got.contains(&p.a) && got.contains(&p.b),
            "the foreign group's owner sees its own pairs: {body}"
        );
    }
    assert!(
        !got.contains(&own.a) && !got.contains(&own.b),
        "and not the first caller's private pair: {body}"
    );
}

// ── Application-role arm: row security on both the reads and the writes ──

#[sqlx::test(migrations = "../../migrations")]
async fn on_the_app_role_the_caller_clusters_its_own_groups_paragraphs_only(pool: PgPool) {
    let (caller, caller_group) = viewer_fixture::seed_agent_with_group(&pool, "67c9-caller").await;
    let (foreign, foreign_group) =
        viewer_fixture::seed_agent_with_group(&pool, "67c9-foreign").await;
    let own = own_private_pair(&pool, caller, caller_group).await;
    let hidden = own_private_pair(&pool, foreign, foreign_group).await;

    let (status, body) = build(app_role_router(&pool).await, caller).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    let run_id = run_id_of(&body);

    let got = members(&pool, run_id).await;
    let want: BTreeSet<Uuid> = [own.a, own.b].into_iter().collect();
    assert_eq!(
        got, want,
        "the caller's own pair, and not the foreign one: {body}"
    );
    assert!(!got.contains(&hidden.a) && !got.contains(&hidden.b));
    assert_eq!(v["paragraph_count"], 2, "{body}");
    assert_eq!(v["bridge_edge_count"], 1, "{body}");

    // The membership rows carry the claims' tenancy, not a widened one.
    let owners: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT visibility, owner_group_id FROM claim_cluster_membership WHERE run_id = $1",
    )
    .bind(run_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(owners.len(), 2);
    for (vis, owner) in owners {
        assert_eq!((vis.as_str(), owner), ("group", caller_group));
    }
}

/// A public paragraph's membership row inherits `('public', world)`, and the
/// world group is in nobody's writable set, so on the application role the
/// stamped write is refused. The handler answers 403 and commits nothing: no
/// run row, no cluster rows, no membership rows. Whether a corpus-wide bridge
/// run belongs on the request path at all is an operator decision (it is
/// maintenance-shaped); this arm pins today's behaviour so it changes only on
/// purpose.
#[sqlx::test(migrations = "../../migrations")]
async fn on_the_app_role_a_public_paragraph_is_a_refused_write_and_nothing_commits(pool: PgPool) {
    let (caller, caller_group) = viewer_fixture::seed_agent_with_group(&pool, "67c9-caller").await;
    let (foreign, _) = viewer_fixture::seed_agent_with_group(&pool, "67c9-foreign").await;
    own_private_pair(&pool, caller, caller_group).await;
    public_pair(&pool, foreign).await;

    let (status, body) = build(app_role_router(&pool).await, caller).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    for table in [
        "graph_cluster_runs",
        "graph_clusters",
        "claim_cluster_membership",
    ] {
        let n: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0, "{table}: a refused run commits nothing");
    }
}

/// A `42501` from the retention sweep is a 500, not the row-security 403.
///
/// The sweep's tables (`graph_cluster_runs`, `graph_clusters`) carry no row
/// security, so a `42501` there can only be a missing table grant: a
/// deployment problem, not a caller without write authority. Answering the
/// 403 ("no write authority over the group ...") would send an operator to
/// group membership instead of the grant. Instrument: DELETE on
/// `graph_cluster_runs` is revoked from `epigraph_app` in this test's own
/// database (table privileges are per database), and the caller clusters only
/// its own private pair, whose inserts row security admits. Nothing commits.
#[sqlx::test(migrations = "../../migrations")]
async fn on_the_app_role_a_missing_grant_in_the_retention_sweep_is_a_500_not_a_403(pool: PgPool) {
    let (caller, caller_group) = viewer_fixture::seed_agent_with_group(&pool, "67c9-caller").await;
    own_private_pair(&pool, caller, caller_group).await;
    let app = app_role_router(&pool).await;

    // Calibration first, with the grant in place: the same caller and the
    // same paragraphs are a 200, so the failure below is the revoke's.
    let (status, body) = build(app.clone(), caller).await;
    assert_eq!(status, StatusCode::OK, "calibration: {body}");
    sqlx::query("DELETE FROM graph_cluster_runs")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM graph_clusters")
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query("REVOKE DELETE ON public.graph_cluster_runs FROM epigraph_app")
        .execute(&pool)
        .await
        .expect("revoke");
    let (status, body) = build(app, caller).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a missing grant is not a refused row write: {body}"
    );
    assert!(
        !body.contains("no write authority"),
        "the 403 wording must not appear: {body}"
    );
    for table in [
        "graph_cluster_runs",
        "graph_clusters",
        "claim_cluster_membership",
    ] {
        let n: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0, "{table}: a failed sweep commits nothing");
    }
}
