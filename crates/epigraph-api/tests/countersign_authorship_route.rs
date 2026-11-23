#![cfg(feature = "db")]
//! `POST /api/v1/papers/:id/authors/countersign` (backlog 04c02296): the REST
//! twin of MCP `countersign_authorship`, with the same outcome and refusals.
//!
//! Ported from the MCP tool's cases (`epigraph-mcp/tests/
//! claim_provenance_across_surfaces.rs`, the countersign pair) and the
//! definer's own (`epigraph-db/tests/ingest_marker_labels.rs`):
//! * a third party and the naming ingester are refused (403, `CSG02`) with
//!   nothing written;
//! * the named person confirms: one row `confirmed`, the reserved label on
//!   the row, the agent card over HTTP flips from pending to authored, and
//!   the act is audited once;
//! * a repeat is a 200 no-op with the "nothing pending" message, no new
//!   audit row;
//! * a live operator declines for its agent (`agent_id`): the naming is
//!   retracted and audited as the operator's act;
//! * no bearer is 401, a token without `claims:write` is 403, a bad decision
//!   is 400, each with nothing written.
//!
//! Every request goes through the full router with a real bearer, on an
//! `AppState` whose pools both run as the APPLICATION ROLE, so the definer's
//! refusals and row security answer as in production. The harness superuser
//! pool only seeds fixtures and reads state back. All names are invented.

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use viewer_fixture::{as_role, database_url_for, downgraded_pool};

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
}

async fn named(pool: &PgPool, agent: Uuid, name: &str) {
    sqlx::query("UPDATE agents SET display_name = $2 WHERE id = $1")
        .bind(agent)
        .bind(name)
        .execute(pool)
        .await
        .expect("name the agent");
}

/// A registered human operator named `name`.
async fn human(pool: &PgPool, name: &str) -> Uuid {
    let (id, _) = viewer_fixture::seed_human_operator(pool, "countersign-human").await;
    named(pool, id, name).await;
    id
}

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let out = as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_operator(&mut conn, agent, operator).await;
        (conn, r)
    })
    .await
    .expect("the maintenance role links the agent");
    assert!(out.link_live, "CALIBRATION: the manual link is live");
}

async fn paper(pool: &PgPool, doi: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO papers (doi, title) VALUES ($1, 'A Fixture Paper') RETURNING id",
    )
    .bind(doi)
    .fetch_one(pool)
    .await
    .expect("paper")
}

/// Ingester `s` named person `h` on paper `p` without speaking for them: a
/// pending authorship, written through the document walk's own writer.
async fn pending_naming(pool: &PgPool, s: Uuid, h: Uuid, p: Uuid) -> Uuid {
    let mut conn = pool.acquire().await.expect("conn");
    let (row, created) = epigraph_db::create_ingest_written_edge_if_absent_conn(
        &mut conn,
        None,
        "ingest_document",
        s,
        h,
        "agent",
        p,
        "paper",
        "authored",
        Some(json!({
            "pending_countersign": true,
            "ingested_by": s.to_string(),
            "position": 0,
        })),
    )
    .await
    .expect("pending naming");
    assert!(created, "CALIBRATION: a fresh naming");
    row.id
}

/// `(labels, in force, properties)` of an edge, read on the superuser pool.
async fn edge_state(pool: &PgPool, e: Uuid) -> (Vec<String>, bool, Value) {
    sqlx::query_as(
        "SELECT labels, (valid_to IS NULL OR valid_to > now()), properties FROM edges WHERE id = $1",
    )
    .bind(e)
    .fetch_one(pool)
    .await
    .expect("edge")
}

async fn audit_rows(pool: &PgPool, event: &str) -> Vec<(Option<Uuid>, Value)> {
    sqlx::query_as(
        "SELECT agent_id, details FROM security_events WHERE event_type = $1 ORDER BY created_at",
    )
    .bind(event)
    .fetch_all(pool)
    .await
    .expect("audit")
}

async fn send(
    state: &AppState,
    method: Method,
    uri: &str,
    token: Option<String>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let req = match body {
        Some(b) => req
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .expect("request");
    let resp = create_router(state.clone())
        .oneshot(req)
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}

/// `POST /api/v1/papers/{paper}/authors/countersign` as `caller`.
async fn countersign_as(
    state: &AppState,
    caller: Uuid,
    paper: Uuid,
    decision: &str,
    agent: Option<Uuid>,
) -> (StatusCode, Value) {
    let token = common::mint_token_with_agent(&["claims:write"], caller);
    let mut body = json!({"decision": decision});
    if let Some(a) = agent {
        body["agent_id"] = json!(a);
    }
    send(
        state,
        Method::POST,
        &format!("/api/v1/papers/{paper}/authors/countersign"),
        Some(token),
        Some(body),
    )
    .await
}

/// The agent card's `(authored_papers, pending_authored_papers)` for `agent`,
/// read by `caller` through `GET /api/v1/agents/search`.
async fn card_counts(state: &AppState, caller: Uuid, agent: Uuid, name: &str) -> (Value, Value) {
    let token = common::mint_token_with_agent(&["claims:read"], caller);
    let (status, body) = send(
        state,
        Method::GET,
        &format!("/api/v1/agents/search?name={}", name.replace(' ', "%20")),
        Some(token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let hit = body["results"]
        .as_array()
        .and_then(|r| r.iter().find(|h| h["id"] == json!(agent)))
        .unwrap_or_else(|| panic!("{agent} not in {body}"))
        .clone();
    (
        hit["counts"]["authored_papers"].clone(),
        hit["counts"]["pending_authored_papers"].clone(),
    )
}

fn refused_with(status: StatusCode, body: &Value, code: &str) -> bool {
    status == StatusCode::FORBIDDEN
        && body["details"]["reason"]
            .as_str()
            .is_some_and(|r| r.starts_with(code))
}

/// A stranger's ingest names a registered person pending. Only that person
/// may countersign it here: a third party and the naming ingester are
/// refused with the definer's code and nothing written. The person's
/// confirmation flips the card from pending to authored, a repeat is a no-op
/// with a message, and the one act is audited once.
#[sqlx::test(migrations = "../../migrations")]
async fn the_named_person_confirms_over_http_and_a_repeat_is_a_noop(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (s, _) = viewer_fixture::seed_agent_with_group(&pool, "countersign-ingester").await;
    let h = human(&pool, "Hesper Quill").await;
    let (third, _) = viewer_fixture::seed_agent_with_group(&pool, "countersign-third").await;
    let p = paper(&pool, "10.9999/countersign-http-confirm").await;
    let e = pending_naming(&pool, s, h, p).await;
    let before = edge_state(&pool, e).await;
    assert_eq!(
        card_counts(&state, third, h, "Hesper Quill").await,
        (json!(0), json!(1)),
        "CALIBRATION: the naming is pending"
    );

    for who in [third, s] {
        let (status, body) = countersign_as(&state, who, p, "confirm", Some(h)).await;
        assert!(
            refused_with(status, &body, "CSG02"),
            "{who} must be refused: {status} {body}"
        );
    }
    assert_eq!(
        edge_state(&pool, e).await,
        before,
        "a refusal writes nothing"
    );

    let (status, out) = countersign_as(&state, h, p, "confirm", None).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(
        out["changed"],
        json!([{"edge_id": e, "ingested_by": s, "outcome": "confirmed"}]),
        "{out}"
    );
    assert_eq!(out["paper_id"], json!(p), "{out}");
    assert_eq!(out["decision"], json!("confirm"), "{out}");
    let (labels, in_force, props) = edge_state(&pool, e).await;
    assert!(
        labels.contains(&format!("epigraph:countersigned_by:{h}")),
        "the confirmation committed: {labels:?}"
    );
    assert!(in_force);
    assert_eq!(props, before.2, "the signed properties are never edited");
    assert_eq!(
        card_counts(&state, third, h, "Hesper Quill").await,
        (json!(1), json!(0)),
        "the card flips to authored"
    );

    let (status, again) = countersign_as(&state, h, p, "confirm", None).await;
    assert_eq!(status, StatusCode::OK, "a repeat is a no-op: {again}");
    assert_eq!(again["changed"], json!([]), "{again}");
    assert!(
        again["message"]
            .as_str()
            .unwrap_or("")
            .contains("nothing pending"),
        "{again}"
    );
    let audit = audit_rows(&pool, "authorship.countersigned").await;
    assert_eq!(
        audit.len(),
        1,
        "one audit row, none for a refusal or a repeat"
    );
    assert_eq!(audit[0].0, Some(h));
    assert_eq!(audit[0].1["acting_as"], json!("self"));
}

/// A live operator declines its agent's pending naming by passing
/// `agent_id`: the naming is retracted and audited as the operator's act; a
/// third party passing the same `agent_id` is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn the_live_operator_declines_over_http_for_its_agent(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (s, _) = viewer_fixture::seed_agent_with_group(&pool, "countersign-ingester").await;
    let operator = human(&pool, "Orla Vance").await;
    let (g, _) = viewer_fixture::seed_agent_with_group(&pool, "countersign-operated").await;
    named(&pool, g, "Gale Ferro").await;
    link(&pool, g, operator).await;
    let (third, _) = viewer_fixture::seed_agent_with_group(&pool, "countersign-third").await;
    let p = paper(&pool, "10.9999/countersign-http-decline").await;
    let e = pending_naming(&pool, s, g, p).await;
    let before = edge_state(&pool, e).await;

    let (status, body) = countersign_as(&state, third, p, "decline", Some(g)).await;
    assert!(refused_with(status, &body, "CSG02"), "{status} {body}");
    assert_eq!(
        edge_state(&pool, e).await,
        before,
        "a refusal writes nothing"
    );

    let (status, out) = countersign_as(&state, operator, p, "decline", Some(g)).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(
        out["changed"],
        json!([{"edge_id": e, "ingested_by": s, "outcome": "declined"}]),
        "{out}"
    );
    let (labels, in_force, _) = edge_state(&pool, e).await;
    assert!(!in_force, "a declined naming is retracted");
    assert!(
        labels.contains(&format!("epigraph:countersign_declined_by:{operator}")),
        "{labels:?}"
    );
    assert_eq!(
        card_counts(&state, third, g, "Gale Ferro").await,
        (json!(0), json!(0)),
        "the naming disappears from the card"
    );
    let audit = audit_rows(&pool, "authorship.countersign_declined").await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].0, Some(operator));
    assert_eq!(audit[0].1["acting_as"], json!("operator"));
}

/// No bearer is 401, a token without `claims:write` is 403, and a decision
/// other than confirm / decline is 400; each writes nothing, and the named
/// person can still confirm afterwards.
#[sqlx::test(migrations = "../../migrations")]
async fn unauthenticated_unscoped_and_malformed_requests_write_nothing(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (s, _) = viewer_fixture::seed_agent_with_group(&pool, "countersign-ingester").await;
    let h = human(&pool, "Ines Marrow").await;
    let p = paper(&pool, "10.9999/countersign-http-auth").await;
    let e = pending_naming(&pool, s, h, p).await;
    let before = edge_state(&pool, e).await;
    let uri = format!("/api/v1/papers/{p}/authors/countersign");

    let (status, body) = send(
        &state,
        Method::POST,
        &uri,
        None,
        Some(json!({"decision": "confirm"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let read_only = common::mint_token_with_agent(&["claims:read"], h);
    let (status, body) = send(
        &state,
        Method::POST,
        &uri,
        Some(read_only),
        Some(json!({"decision": "confirm"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, body) = countersign_as(&state, h, p, "approve", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["details"]["field"], json!("decision"), "{body}");

    assert_eq!(edge_state(&pool, e).await, before, "nothing was written");
    assert!(audit_rows(&pool, "authorship.countersigned")
        .await
        .is_empty());

    let (status, out) = countersign_as(&state, h, p, "Confirm", None).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(out["changed"][0]["outcome"], json!("confirmed"), "{out}");
}

/// Two ingesters named the same person on the same paper. `ingested_by`
/// confirms only that ingester's naming: the other stays pending (no label,
/// in force), so the card still counts the paper as pending until the
/// person acts on it too.
#[sqlx::test(migrations = "../../migrations")]
async fn ingested_by_confirms_only_that_ingesters_naming(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (s1, _) = viewer_fixture::seed_agent_with_group(&pool, "countersign-ingester-1").await;
    let (s2, _) = viewer_fixture::seed_agent_with_group(&pool, "countersign-ingester-2").await;
    let h = human(&pool, "Juno Ashgrove").await;
    let (third, _) = viewer_fixture::seed_agent_with_group(&pool, "countersign-third").await;
    let p = paper(&pool, "10.9999/countersign-http-one-ingest").await;
    let e1 = pending_naming(&pool, s1, h, p).await;
    let e2 = pending_naming(&pool, s2, h, p).await;
    let before2 = edge_state(&pool, e2).await;

    let token = common::mint_token_with_agent(&["claims:write"], h);
    let (status, out) = send(
        &state,
        Method::POST,
        &format!("/api/v1/papers/{p}/authors/countersign"),
        Some(token),
        Some(json!({"decision": "confirm", "ingested_by": s1})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(
        out["changed"],
        json!([{"edge_id": e1, "ingested_by": s1, "outcome": "confirmed"}]),
        "only s1's naming: {out}"
    );
    assert!(edge_state(&pool, e1)
        .await
        .0
        .contains(&format!("epigraph:countersigned_by:{h}")));
    assert_eq!(
        edge_state(&pool, e2).await,
        before2,
        "the other ingester's naming is untouched"
    );
    assert_eq!(
        card_counts(&state, third, h, "Juno Ashgrove").await,
        (json!(1), json!(0)),
        "one confirmed row makes the paper authored"
    );

    let (status, rest) = countersign_as(&state, h, p, "confirm", None).await;
    assert_eq!(status, StatusCode::OK, "{rest}");
    assert_eq!(
        rest["changed"],
        json!([{"edge_id": e2, "ingested_by": s2, "outcome": "confirmed"}]),
        "the remaining naming is s2's: {rest}"
    );
}
