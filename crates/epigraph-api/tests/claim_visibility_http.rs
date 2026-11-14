//! The HTTP half of the claim visibility controls
//! (docs/tenancy/claim-visibility-controls.md, migration 206) on the
//! APPLICATION ROLE: `POST /api/v1/claims` (plain tier),
//! `POST /api/v1/claims/publicize`, `PUT /api/v1/agents/me/default-group` and
//! (migration 209) `PUT /api/v1/agents/:id/default-group`,
//! each on a transaction stamped from the caller as `epigraph_app`
//! (`connect_downgraded_for_tests`), and (migration 215) the publicize refold
//! of the published claim's cached belief. The raw `db_pool` is the harness
//! superuser, used only to seed and to read state back.
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

async fn spawn_app(pool: &PgPool) -> (SocketAddr, oneshot::Sender<()>) {
    spawn_app_with(pool, false).await
}

/// `server_shaped`: build the state as `bin/server.rs` does
/// (`AppState::with_scoped_pool`), so `state.db_pool` is the application-role
/// pool too, not the harness superuser. Any read a handler makes on the raw
/// pool then sees what the server's would: unstamped, so public rows only.
async fn spawn_app_with(pool: &PgPool, server_shaped: bool) -> (SocketAddr, oneshot::Sender<()>) {
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
    let state = if server_shaped {
        AppState::with_scoped_pool(scoped, ApiConfig::default())
    } else {
        let mut state = AppState::with_db(pool.clone(), ApiConfig::default());
        state.scoped = Some(scoped);
        state
    };
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    let app = epigraph_api::routes::create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    (addr, tx)
}

async fn team(pool: &PgPool, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, $2, 'did:epigraph:test-team:' || $1::text, $3, 'team')",
    )
    .bind(id)
    .bind(label)
    .bind(&key)
    .execute(pool)
    .await
    .expect("seed team");
    id
}

async fn add_member(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed membership");
}

async fn send(
    addr: SocketAddr,
    method: reqwest::Method,
    path: &str,
    agent: Uuid,
    body: Value,
) -> (u16, Value) {
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], agent);
    let resp = reqwest::Client::new()
        .request(method, format!("http://{addr}{path}"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("body");
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

async fn tenancy(pool: &PgPool, id: Uuid) -> (String, Uuid) {
    sqlx::query_as("SELECT visibility::text, owner_group_id FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("tenancy")
}

fn claim_body(agent: Uuid, content: &str, extra: Value) -> Value {
    let mut b = json!({"content": content, "agent_id": agent, "if_not_exists": true});
    if let (Some(o), Some(e)) = (b.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            o.insert(k.clone(), v.clone());
        }
    }
    b
}

/// `POST /api/v1/claims` with no visibility lands in the caller's team; a
/// reader of the team naming it is refused 403 with nothing written; a group
/// beside `public` is a 400; `private` is the home group.
#[sqlx::test(migrations = "../../migrations")]
async fn post_claims_defaults_to_the_team_and_refuses_a_reader(pool: PgPool) {
    let (addr, _stop) = spawn_app(&pool).await;
    let t = team(&pool, "http-team").await;
    let (alice, home) = fixture::seed_agent_with_group(&pool, "http-alice").await;
    let (bob, _) = fixture::seed_agent_with_group(&pool, "http-bob").await;
    add_member(&pool, t, alice, "writer").await;
    add_member(&pool, t, bob, "reader").await;

    let (status, body) = send(
        addr,
        reqwest::Method::POST,
        "/api/v1/claims",
        alice,
        claim_body(alice, "http team default", json!({})),
    )
    .await;
    assert!(status == 200 || status == 201, "{status} {body}");
    assert_eq!(body["visibility"], "team", "{body}");
    assert_eq!(body["owner_group_id"], t.to_string(), "{body}");
    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(tenancy(&pool, id).await, ("group".to_string(), t));

    let (status, body) = send(
        addr,
        reqwest::Method::POST,
        "/api/v1/claims",
        bob,
        claim_body(bob, "http reader write", json!({"group_id": t})),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM claims WHERE content = 'http reader write'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(n, 0, "nothing written");

    let (status, body) = send(
        addr,
        reqwest::Method::POST,
        "/api/v1/claims",
        alice,
        claim_body(
            alice,
            "http contradiction",
            json!({"visibility": "public", "group_id": t}),
        ),
    )
    .await;
    assert_eq!(status, 400, "{body}");

    let (status, body) = send(
        addr,
        reqwest::Method::POST,
        "/api/v1/claims",
        alice,
        claim_body(alice, "http private", json!({"visibility": "private"})),
    )
    .await;
    assert!(status == 200 || status == 201, "{status} {body}");
    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(tenancy(&pool, id).await, ("group".to_string(), home));
}

/// `POST /api/v1/claims/publicize`: a writer is refused 403, a non-member gets
/// 404, a team admin publishes (and the audit row names the admin).
/// `PUT /api/v1/agents/me/default-group` refuses a group the caller does not
/// write.
#[sqlx::test(migrations = "../../migrations")]
async fn publicize_over_http_is_for_team_admins(pool: PgPool) {
    let (addr, _stop) = spawn_app(&pool).await;
    let t = team(&pool, "http-team").await;
    let other = team(&pool, "http-other").await;
    let (alice, _) = fixture::seed_agent_with_group(&pool, "http-writer").await;
    let (eve, _) = fixture::seed_agent_with_group(&pool, "http-admin").await;
    let (carol, _) = fixture::seed_agent_with_group(&pool, "http-stranger").await;
    add_member(&pool, t, alice, "writer").await;
    add_member(&pool, t, eve, "admin").await;

    let (_, body) = send(
        addr,
        reqwest::Method::POST,
        "/api/v1/claims",
        alice,
        claim_body(alice, "http finding", json!({})),
    )
    .await;
    let c: Uuid = body["id"].as_str().expect("id").parse().unwrap();
    let req = json!({"claim_ids": [c], "reason": "publish"});

    let (status, body) = send(
        addr,
        reqwest::Method::POST,
        "/api/v1/claims/publicize",
        alice,
        req.clone(),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    let (status, body) = send(
        addr,
        reqwest::Method::POST,
        "/api/v1/claims/publicize",
        carol,
        req.clone(),
    )
    .await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(tenancy(&pool, c).await, ("group".to_string(), t));

    let (status, body) = send(
        addr,
        reqwest::Method::POST,
        "/api/v1/claims/publicize",
        eve,
        req,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["results"][0]["outcome"], "publicized", "{body}");
    assert_eq!(tenancy(&pool, c).await, ("public".to_string(), t));
    let who: Option<Uuid> = sqlx::query_scalar(
        "SELECT agent_id FROM security_events WHERE event_type = 'claim.publicized'",
    )
    .fetch_one(&pool)
    .await
    .expect("audit row");
    assert_eq!(who, Some(eve));

    let (status, body) = send(
        addr,
        reqwest::Method::PUT,
        "/api/v1/agents/me/default-group",
        alice,
        json!({"group_id": other}),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    let (status, body) = send(
        addr,
        reqwest::Method::PUT,
        "/api/v1/agents/me/default-group",
        alice,
        json!({"group_id": t}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["default_group_id"], t.to_string(), "{body}");
}

/// D-V4 over REST on a server-shaped state: resubmitting content the caller
/// already holds PRIVATE, with no visibility (so the default, its team),
/// returns the existing claim unchanged and SAYS so. The response reports the
/// stored tenancy (private, the home group) and the "NOT re-scoped" note. Both
/// come from reading the claim back, which only a read stamped with the caller
/// can do: on the raw application pool the private row is invisible, and the
/// response would echo the requested team with no note.
#[sqlx::test(migrations = "../../migrations")]
async fn a_rest_resubmit_reports_the_stored_private_tenancy_and_the_note(pool: PgPool) {
    let (addr, _stop) = spawn_app_with(&pool, true).await;
    let t = team(&pool, "http-team").await;
    let (alice, home) = fixture::seed_agent_with_group(&pool, "http-resubmit").await;
    add_member(&pool, t, alice, "writer").await;

    let (status, body) = send(
        addr,
        reqwest::Method::POST,
        "/api/v1/claims",
        alice,
        claim_body(alice, "http resubmit", json!({"visibility": "private"})),
    )
    .await;
    assert!(status == 200 || status == 201, "{status} {body}");
    let id: Uuid = body["id"].as_str().expect("id").parse().unwrap();
    assert_eq!(tenancy(&pool, id).await, ("group".to_string(), home));

    let (status, body) = send(
        addr,
        reqwest::Method::POST,
        "/api/v1/claims",
        alice,
        claim_body(alice, "http resubmit", json!({})),
    )
    .await;
    assert!(status == 200 || status == 201, "{status} {body}");
    assert_eq!(body["id"], id.to_string(), "the existing claim: {body}");
    assert_eq!(body["visibility"], "private", "{body}");
    assert_eq!(body["owner_group_id"], home.to_string(), "{body}");
    assert!(
        body["visibility_note"]
            .as_str()
            .is_some_and(|n| n.contains("NOT re-scoped")),
        "{body}"
    );
    assert_eq!(tenancy(&pool, id).await, ("group".to_string(), home));
}

/// Migration 209 over REST. A human operator sets the agent it operates
/// PRIVATE through `PUT /api/v1/agents/:id/default-group`, and the agent's
/// write that names no visibility then resolves to the operator's personal
/// group although the operator's own default is the team. A human
/// operator that does not operate the agent gets 403 and changes nothing; a
/// group together with `private` is a 400; a `null` body clears; and
/// `PUT /api/v1/agents/me/default-group` takes `private` for the caller itself.
#[sqlx::test(migrations = "../../migrations")]
async fn an_operator_sets_its_agents_default_private_over_rest(pool: PgPool) {
    let (addr, _stop) = spawn_app_with(&pool, true).await;
    let ndi = team(&pool, "http-ndi").await;
    let (human, human_home) = fixture::seed_human_operator(&pool, "http-def-human").await;
    let (stranger, _) = fixture::seed_human_operator(&pool, "http-def-stranger").await;
    let (crew, _) = fixture::seed_agent_with_group(&pool, "http-def-crew").await;
    add_member(&pool, ndi, human, "writer").await;
    add_member(&pool, ndi, stranger, "admin").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, crew, human)
            .await
            .expect("live link");
    }
    let default_of = |agent: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, (Option<Uuid>, bool)>(
                "SELECT default_group_id, default_private FROM agents WHERE id = $1",
            )
            .bind(agent)
            .fetch_one(&pool)
            .await
            .expect("default")
        }
    };
    let path = format!("/api/v1/agents/{crew}/default-group");

    let (status, body) = send(
        addr,
        reqwest::Method::PUT,
        "/api/v1/agents/me/default-group",
        human,
        json!({"group_id": ndi}),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let (status, body) = send(
        addr,
        reqwest::Method::PUT,
        &path,
        stranger,
        json!({"private": true}),
    )
    .await;
    assert_eq!(
        status, 403,
        "a human operator that does not operate it: {body}"
    );
    assert_eq!(default_of(crew).await, (None, false));

    let (status, body) = send(
        addr,
        reqwest::Method::PUT,
        &path,
        human,
        json!({"group_id": ndi, "private": true}),
    )
    .await;
    assert_eq!(status, 400, "{body}");

    let (status, body) = send(
        addr,
        reqwest::Method::PUT,
        &path,
        human,
        json!({"private": true}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["agent_id"], crew.to_string(), "{body}");
    assert_eq!(body["set_by"], "operator", "{body}");
    assert_eq!(body["default_private"], true, "{body}");
    assert_eq!(default_of(crew).await, (None, true));

    // An operated agent writes over stdio only (its HTTP token is refused), so
    // the default the REST route set is checked where every surface's write
    // resolves it: `resolve_write_decl` with no visibility named. The MCP
    // app-role suite (Part D) writes the claim and checks who can read it.
    let resolved = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::ClaimRepository::resolve_write_decl(
            &mut conn,
            crew,
            epigraph_core::VisibilityChoice::Default,
        )
        .await
        .expect("resolve")
    };
    assert_eq!(resolved.resolved, "private");
    assert_eq!(resolved.home_group, human_home);
    assert_eq!(
        resolved.decl,
        epigraph_core::TenancyDecl::group(human_home),
        "private to the operator's personal group, not the operator's default team"
    );

    let (status, body) = send(addr, reqwest::Method::PUT, &path, human, Value::Null).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(default_of(crew).await, (None, false), "a null body clears");

    let (status, body) = send(
        addr,
        reqwest::Method::PUT,
        "/api/v1/agents/me/default-group",
        human,
        json!({"private": true}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["set_by"], "self", "{body}");
    assert_eq!(default_of(human).await, (None, true));
}

/// A BBA on (`claim`, binary frame) by `agent`, citing `evidence`.
async fn bba(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Uuid, evidence: Uuid, m: Value) {
    epigraph_db::PerspectiveRepository::ensure_evidence_perspective(pool, evidence, Some(agent))
        .await
        .expect("evidence perspective");
    epigraph_db::MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        Some(evidence),
        &m,
        None,
        Some("auto_wire"),
        Some(1.0),
        None,
        "unknown",
        Some(evidence),
    )
    .await
    .expect("store a BBA");
}

async fn belief_cache(pool: &PgPool, claim: Uuid) -> (Option<f64>, Option<f64>, Option<f64>) {
    sqlx::query_as("SELECT pignistic_prob, belief, plausibility FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("cache")
}

/// Backlog 31285392 over REST: `POST /api/v1/claims/publicize` refolds the
/// published claim's cached belief for its new audience in the same
/// transaction. The team claim's cache folded a supporting BBA and a refuting
/// one citing evidence an operator pinned to the team; after the publicize
/// the claim serves exactly the fold of a public control claim that carries
/// only the supporting BBA. Against 206 as built the team's fold, refuting
/// BBA included, stays the public value.
#[sqlx::test(migrations = "../../migrations")]
async fn publicize_over_http_refolds_the_belief_for_the_public(pool: PgPool) {
    let (addr, _stop) = spawn_app(&pool).await;
    let t = team(&pool, "http-team").await;
    let (eve, _) = fixture::seed_agent_with_group(&pool, "http-admin").await;
    add_member(&pool, t, eve, "admin").await;
    let eve_viewer = epigraph_db::Viewer::resolve(&pool, eve)
        .await
        .expect("viewer");
    let mut conn = pool.acquire().await.expect("acquire");
    let binary = epigraph_engine::edge_factor::ensure_binary_frame(&mut conn, &eve_viewer)
        .await
        .expect("binary_truth");
    let support = json!({"0": 0.8, "0,1": 0.2});

    let c = fixture::seed_group_claim(&pool, eve, t, "http team finding").await;
    let ev = fixture::seed_evidence(&pool, c, "observation").await;
    let hidden = fixture::seed_evidence(&pool, c, "reference").await;
    sqlx::query(
        "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) \
         VALUES ($1, $2, 'test: hidden')",
    )
    .bind(hidden)
    .bind(eve)
    .execute(&pool)
    .await
    .expect("pin");
    bba(&pool, c, binary, eve, ev, support.clone()).await;
    bba(&pool, c, binary, eve, hidden, json!({"1": 0.9, "0,1": 0.1})).await;

    let control = fixture::seed_public_claim(&pool, eve, "http public control").await;
    let cev = fixture::seed_evidence(&pool, control, "observation").await;
    bba(&pool, control, binary, eve, cev, support).await;

    for claim in [c, control] {
        epigraph_engine::edge_factor::recompute_claim_cached_belief(&mut conn, &eve_viewer, claim)
            .await
            .expect("fold");
    }
    drop(conn);
    let stale = belief_cache(&pool, c).await;
    let expected = belief_cache(&pool, control).await;
    let near = |a: Option<f64>, b: Option<f64>| match (a, b) {
        (Some(a), Some(b)) => (a - b).abs() < 1e-9,
        _ => false,
    };
    assert!(
        !near(stale.0, expected.0),
        "PREMISE: the team fold took in the pinned BBA ({stale:?} vs {expected:?})"
    );

    let (status, body) = send(
        addr,
        reqwest::Method::POST,
        "/api/v1/claims/publicize",
        eve,
        json!({"claim_ids": [c], "reason": "publish"}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let served = belief_cache(&pool, c).await;
    assert!(
        near(served.0, expected.0) && near(served.1, expected.1) && near(served.2, expected.2),
        "the published claim serves the fold of its public sources ({served:?}), not the \
         team's ({stale:?}); control {expected:?}"
    );
}
