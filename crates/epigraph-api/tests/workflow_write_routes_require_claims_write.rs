#![cfg(feature = "db")]
//! Every flat workflow write route requires `claims:write`, checked before the
//! handler reads or writes anything (backlog 05eb8b4a).
//!
//! `POST /api/v1/workflows`, `POST /api/v1/workflows/:id/outcome`,
//! `DELETE /api/v1/workflows/:id` and
//! `POST /api/v1/workflows/:id/behavioral-executions` took no `AuthContext` and
//! called no `check_scopes`, so any authenticated bearer, a `claims:read`-only
//! token included, could store a workflow, move a workflow's truth value and
//! usage counters, retire it, or append behavioral-execution rows. Their
//! siblings (`/steps`, `/steps/delete`, `/steps/:id/evolve`,
//! `/hierarchical/:id/outcome`) and every MCP twin (`scope_map.rs`) require
//! `claims:write`. `POST /api/v1/workflows/ingest` is pinned with its group
//! tenancy in `workflow_ingest_group_tenancy.rs`.
//!
//! Each arm sends a `claims:read` token for two callers: the workflow's owner,
//! whose write the route would otherwise admit, and a stranger with no
//! membership in the owning group. Both must get the same `403` naming
//! `claims:write`, so the scope is decided before anything about the target is
//! read. The arm then asserts the EFFECT (nothing written) and calibrates with
//! the same owner holding `claims:write`, which must succeed, so a refusal
//! cannot come from a broken fixture.
//!
//! The app runs on the harness superuser (`build_app_for_tests`), which
//! bypasses row security: the database would admit every one of these writes,
//! so the only thing that can refuse them is the route's own scope check.

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

struct World {
    pool: PgPool,
    router: axum::Router,
    /// Admin of its personal group, which owns `workflow`.
    owner: Uuid,
    /// A member of its own personal group only.
    stranger: Uuid,
    /// A flat (`'workflow'`-labelled) workflow claim owned by `owner`'s group.
    workflow: Uuid,
}

async fn world(pool: PgPool, label: &str) -> World {
    let url = viewer_fixture::database_url_for(&pool).await;
    let router = epigraph_api::build_app_for_tests(&url)
        .await
        .expect("app builds for tests");
    let (owner, group) =
        viewer_fixture::seed_agent_with_group(&pool, &format!("{label}-owner")).await;
    let (stranger, _) =
        viewer_fixture::seed_agent_with_group(&pool, &format!("{label}-stranger")).await;
    let content = json!({
        "goal": format!("{label} flat workflow goal {}", Uuid::new_v4()),
        "steps": ["first step", "second step"],
    })
    .to_string();
    let workflow = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, labels, properties) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5, ARRAY['workflow'], \
                 '{\"generation\": 0, \"use_count\": 0, \"success_count\": 0, \
                   \"failure_count\": 0, \"avg_variance\": 0.0}'::jsonb)",
    )
    .bind(workflow)
    .bind(&content)
    .bind(blake3::hash(content.as_bytes()).as_bytes().to_vec())
    .bind(owner)
    .bind(group)
    .execute(&pool)
    .await
    .expect("seed a public flat workflow claim owned by the owner's group");
    World {
        pool,
        router,
        owner,
        stranger,
        workflow,
    }
}

impl World {
    async fn call(
        &self,
        method: Method,
        uri: &str,
        agent: Uuid,
        scopes: &[&str],
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        let token = common::mint_token_with_agent(scopes, agent);
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        let body = match body {
            Some(b) => {
                req = req.header(header::CONTENT_TYPE, "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        let resp = self
            .router
            .clone()
            .oneshot(req.body(body).expect("request"))
            .await
            .expect("router");
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

    /// Send the call for the owner and the stranger with a `claims:read`
    /// token: each is the scope refusal, with one body for both.
    async fn assert_read_only_refused(
        &self,
        what: &str,
        method: Method,
        uri: &str,
        body: Option<&Value>,
    ) {
        let mut bodies = Vec::new();
        for (agent, who) in [(self.owner, "the owner"), (self.stranger, "a stranger")] {
            let (status, out) = self.call(method.clone(), uri, agent, READ_ONLY, body).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{what}, by {who}: a token without claims:write must be refused 403, got {status} {out}"
            );
            assert!(
                out.to_string().contains("claims:write"),
                "{what}, by {who}: the refusal names the missing scope: {out}"
            );
            bodies.push(out);
        }
        assert_eq!(
            bodies[0], bodies[1],
            "{what}: the scope refusal must not depend on the caller's access to the workflow"
        );
    }

    /// `(truth_value, is_current, use_count, behavioral rows)` of the workflow.
    async fn footprint(&self) -> (f64, bool, i64, i64) {
        sqlx::query_as(
            "SELECT c.truth_value, COALESCE(c.is_current, true), \
                    COALESCE((c.properties->>'use_count')::bigint, 0), \
                    (SELECT count(*) FROM behavioral_executions b WHERE b.workflow_id = c.id) \
               FROM claims c WHERE c.id = $1",
        )
        .bind(self.workflow)
        .fetch_one(&self.pool)
        .await
        .expect("the workflow's footprint")
    }
}

/// `POST /api/v1/workflows/:id/outcome` moves the truth value and the usage
/// counters and appends a behavioral row; a read-only token moves nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn reporting_an_outcome_requires_the_claims_write_scope(pool: PgPool) {
    let w = world(pool, "scope-outcome").await;
    let uri = format!("/api/v1/workflows/{}/outcome", w.workflow);
    let body = json!({ "success": true, "outcome_details": "scope arm", "quality": 1.0 });
    let before = w.footprint().await;

    w.assert_read_only_refused("outcome", Method::POST, &uri, Some(&body))
        .await;
    assert_eq!(
        w.footprint().await,
        before,
        "a refused outcome moves no truth value, no counter and writes no row"
    );

    let (status, out) = w
        .call(Method::POST, &uri, w.owner, READ_WRITE, Some(&body))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "calibration: the same owner with claims:write: {out}"
    );
    let after = w.footprint().await;
    assert_eq!(
        after.2,
        before.2 + 1,
        "the report counts one use: {after:?}"
    );
    assert_eq!(
        after.3,
        before.3 + 1,
        "the report writes one behavioral row"
    );
}

/// `DELETE /api/v1/workflows/:id` retires the workflow; a read-only token
/// leaves it current.
#[sqlx::test(migrations = "../../migrations")]
async fn deprecating_a_workflow_requires_the_claims_write_scope(pool: PgPool) {
    let w = world(pool, "scope-deprecate").await;
    let uri = format!("/api/v1/workflows/{}?reason=scope-arm", w.workflow);
    let before = w.footprint().await;
    assert!(before.1, "the fixture's workflow starts current");

    w.assert_read_only_refused("deprecate", Method::DELETE, &uri, None)
        .await;
    assert_eq!(
        w.footprint().await,
        before,
        "a refused deprecation leaves the workflow current and its truth unchanged"
    );

    let (status, out) = w
        .call(Method::DELETE, &uri, w.owner, READ_WRITE, None)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "calibration: the same owner with claims:write: {out}"
    );
    assert!(
        !w.footprint().await.1,
        "the deprecation retires the workflow"
    );
}
