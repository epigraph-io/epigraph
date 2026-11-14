#![cfg(feature = "db")]
//! Every HTTP route that writes requires a write scope, checked before the
//! request body is parsed (backlog f00d75ab).
//!
//! These handlers took `State` and a body and nothing else, or a
//! `ViewerExtractor` and no scope. Bearer authentication alone admitted them,
//! so a `claims:read` token could create frames, spans, propaganda
//! techniques, coalitions, counterfactuals, events, activities, contexts and
//! perspectives, fold evidence into a frame, assess a claim, store a gap
//! analysis, open challenges from gaps, create or promote a hypothesis, share a
//! workflow, or submit a whole epistemic packet. Each route's MCP twin, where
//! one exists, already required `claims:write` (`epigraph-mcp`'s
//! `scope_map.rs`), and `POST /api/v1/claims` required it while
//! `POST /api/v1/submit/packet`, which creates a claim too, did not.
//!
//! # The two halves
//!
//! * [`every_gated_route_refuses_a_token_without_its_scope`] walks the whole
//!   list: a `claims:read` token gets `403` naming the missing scope, and the
//!   same request with the scope gets past the gate (whatever the handler then
//!   says about an empty body, it is not `401` or `403`). The calibration is
//!   what stops a broken fixture or a wrong path from passing as a refusal.
//! * The `a_refused_*_writes_nothing` tests send a VALID body for the routes
//!   named in the backlog item's evidence and assert the EFFECT: a refused request
//!   leaves no row, and the same body with the scope writes one, so the body
//!   was never the reason for the refusal.
//!
//! `build_app_for_tests` runs on the harness superuser, which bypasses row
//! security: the database would admit every one of these writes, so the only
//! thing that can refuse them is the route's own scope check.

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const READ_ONLY: &[&str] = &["claims:read"];
const READ_WRITE: &[&str] = &["claims:read", "claims:write"];
const ADMIN: &[&str] = &["claims:read", "claims:write", "claims:admin"];

struct World {
    pool: PgPool,
    router: axum::Router,
    agent: Uuid,
}

async fn world(pool: PgPool, label: &str) -> World {
    let url = viewer_fixture::database_url_for(&pool).await;
    let router = epigraph_api::build_app_for_tests(&url)
        .await
        .expect("app builds for tests");
    let (agent, _group) = viewer_fixture::seed_agent_with_group(&pool, label).await;
    World {
        pool,
        router,
        agent,
    }
}

impl World {
    async fn call(
        &self,
        method: Method,
        uri: &str,
        scopes: &[&str],
        body: &Value,
    ) -> (StatusCode, Value) {
        let token = common::mint_token_with_agent(scopes, self.agent);
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request");
        let resp = self.router.clone().oneshot(req).await.expect("router");
        let status = resp.status();
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
        };
        (status, value)
    }

    /// `token_scopes` is refused `403` naming `missing`.
    async fn assert_refused(
        &self,
        method: Method,
        uri: &str,
        token_scopes: &[&str],
        missing: &str,
        body: &Value,
    ) {
        let (status, out) = self.call(method.clone(), uri, token_scopes, body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {uri} with {token_scopes:?}: a token without {missing} must be refused \
             403, got {status} {out}"
        );
        assert!(
            out.to_string().contains(missing),
            "{method} {uri}: the refusal names the missing scope {missing}: {out}"
        );
    }

    /// `token_scopes` gets past the gate: not `401`, not `403`.
    async fn assert_admitted(
        &self,
        method: Method,
        uri: &str,
        token_scopes: &[&str],
        body: &Value,
    ) {
        let (status, out) = self.call(method.clone(), uri, token_scopes, body).await;
        assert!(
            status != StatusCode::FORBIDDEN && status != StatusCode::UNAUTHORIZED,
            "{method} {uri} with {token_scopes:?}: the scope gate must admit this token \
             (calibration), got {status} {out}"
        );
    }

    async fn count(&self, sql: &str, key: &str) -> i64 {
        sqlx::query_scalar(sql)
            .bind(key)
            .fetch_one(&self.pool)
            .await
            .unwrap_or_else(|e| panic!("count with {sql}: {e}"))
    }
}

/// The routes gated on `claims:write` by this change, with a path whose ids
/// are random (the gate runs before anything reads them).
fn claims_write_routes() -> Vec<(Method, String)> {
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    vec![
        (Method::POST, "/api/v1/frames".into()),
        (Method::POST, format!("/api/v1/frames/{a}/evidence")),
        (Method::POST, format!("/api/v1/frames/{a}/refine")),
        (Method::POST, "/api/v1/spans".into()),
        (Method::PUT, format!("/api/v1/spans/{a}/close")),
        (Method::POST, "/api/v1/propaganda-techniques".into()),
        (Method::POST, "/api/v1/coalitions".into()),
        (
            Method::POST,
            format!("/api/v1/conflicts/{a}/{b}/counterfactuals"),
        ),
        (Method::POST, "/api/v1/events".into()),
        (Method::POST, "/api/v1/activities".into()),
        (Method::PUT, format!("/api/v1/activities/{a}/complete")),
        (Method::POST, "/api/v1/contexts".into()),
        (Method::POST, "/api/v1/perspectives".into()),
        (Method::POST, format!("/api/v1/claims/{a}/assess")),
        (Method::POST, "/api/v1/skills/share".into()),
        (Method::POST, "/api/v1/hypothesis".into()),
        (Method::POST, format!("/api/v1/hypothesis/{a}/promote")),
        (Method::POST, "/api/v1/submit/packet".into()),
        (Method::POST, "/api/v1/gaps/analysis".into()),
        (Method::POST, "/api/v1/gaps/surface".into()),
        (Method::POST, "/api/v1/harvest".into()),
    ]
}

#[sqlx::test(migrations = "../../migrations")]
async fn every_gated_route_refuses_a_token_without_its_scope(pool: PgPool) {
    let w = world(pool, "scope-walk").await;
    let empty = json!({});
    for (method, uri) in claims_write_routes() {
        w.assert_refused(method.clone(), &uri, READ_ONLY, "claims:write", &empty)
            .await;
        w.assert_admitted(method, &uri, READ_WRITE, &empty).await;
    }
    // `POST /api/v1/ingest/paper` creates a directory at a caller-chosen path,
    // reads a caller-named local PDF and runs a host script: `claims:admin`.
    for uri in ["/api/v1/ingest/paper", "/api/v1/ingest/paper-url"] {
        w.assert_refused(Method::POST, uri, READ_ONLY, "claims:admin", &empty)
            .await;
        w.assert_refused(Method::POST, uri, READ_WRITE, "claims:admin", &empty)
            .await;
        w.assert_admitted(Method::POST, uri, ADMIN, &empty).await;
    }
}

/// One route of the backlog item's evidence: a valid `body`, the row it
/// writes counted by `count_sql` keyed on `key`.
async fn assert_write_needs_scope(w: &World, uri: &str, body: Value, count_sql: &str, key: &str) {
    w.assert_refused(Method::POST, uri, READ_ONLY, "claims:write", &body)
        .await;
    assert_eq!(
        w.count(count_sql, key).await,
        0,
        "POST {uri}: a refused request writes no row"
    );
    let (status, out) = w.call(Method::POST, uri, READ_WRITE, &body).await;
    assert!(
        status.is_success(),
        "POST {uri}: the same body with claims:write is written (calibration), got {status} {out}"
    );
    assert_eq!(
        w.count(count_sql, key).await,
        1,
        "POST {uri}: the admitted request writes its row"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_frame_context_or_perspective_writes_nothing(pool: PgPool) {
    let w = world(pool, "scope-frames").await;
    let name = format!("scope frame {}", Uuid::new_v4());
    assert_write_needs_scope(
        &w,
        "/api/v1/frames",
        json!({ "name": name, "hypotheses": ["yes", "no"] }),
        "SELECT count(*) FROM frames WHERE name = $1",
        &name,
    )
    .await;

    let name = format!("scope context {}", Uuid::new_v4());
    assert_write_needs_scope(
        &w,
        "/api/v1/contexts",
        json!({ "name": name, "context_type": "domain" }),
        "SELECT count(*) FROM contexts WHERE name = $1",
        &name,
    )
    .await;

    let name = format!("scope perspective {}", Uuid::new_v4());
    assert_write_needs_scope(
        &w,
        "/api/v1/perspectives",
        json!({ "name": name }),
        "SELECT count(*) FROM perspectives WHERE name = $1",
        &name,
    )
    .await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_span_event_or_activity_writes_nothing(pool: PgPool) {
    let w = world(pool, "scope-telemetry").await;
    // `agent_spans.trace_id` is `varchar(32)`: a bare simple UUID fits.
    let trace = Uuid::new_v4().simple().to_string();
    assert_write_needs_scope(
        &w,
        "/api/v1/spans",
        json!({ "trace_id": trace, "span_name": "scope span", "attributes": {} }),
        "SELECT count(*) FROM agent_spans WHERE trace_id = $1",
        &trace,
    )
    .await;

    let event_type = format!("scope.event.{}", Uuid::new_v4().simple());
    assert_write_needs_scope(
        &w,
        "/api/v1/events",
        json!({ "event_type": event_type, "payload": {} }),
        "SELECT count(*) FROM events WHERE event_type = $1",
        &event_type,
    )
    .await;

    let description = format!("scope activity {}", Uuid::new_v4());
    assert_write_needs_scope(
        &w,
        "/api/v1/activities",
        json!({ "activity_type": "ingestion", "description": description }),
        "SELECT count(*) FROM activities WHERE description = $1",
        &description,
    )
    .await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_counterfactual_writes_nothing(pool: PgPool) {
    // `POST /api/v1/propaganda-techniques` and `POST /api/v1/coalitions` are
    // gated in the walk above but have no effect arm: their tables
    // (`propaganda_techniques`, `coalitions`) are created by no migration, so
    // the handlers answer 500 whatever the scope and there is no row to count.
    let w = world(pool, "scope-counterfactual").await;
    // `counterfactual_scenarios` references both claims.
    let a = viewer_fixture::seed_public_claim(&w.pool, w.agent, "scope counterfactual a").await;
    let b = viewer_fixture::seed_public_claim(&w.pool, w.agent, "scope counterfactual b").await;
    assert_write_needs_scope(
        &w,
        &format!("/api/v1/conflicts/{a}/{b}/counterfactuals"),
        json!({ "scenario_a": { "if": "a" }, "scenario_b": { "if": "b" } }),
        "SELECT count(*) FROM counterfactual_scenarios WHERE claim_a_id::text = $1",
        &a.to_string(),
    )
    .await;
}
