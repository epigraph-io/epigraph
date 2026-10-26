//! `POST /api/v1/workflows/steps/:id/evolve` is gated on authority over EVERY
//! workflow that executes the step's lineage (the REST half; the MCP half is
//! `epigraph-mcp/tests/evolve_step_lineage_authority.rs`).
//!
//! Before this gate the route checked only `claims:write` and row security, so
//! any principal that writes the step's owning group could evolve a step a
//! workflow executes: for a group-private workflow that is every writer and
//! admin of the group, not only the workflow's submitter. `add_step`,
//! `delete_step` and `deprecate_workflow` already require the workflow
//! authority (the submitter, its operator, or the audited `claims:admin`
//! path); `evolve_step` now requires the same over each workflow with an
//! `executes` edge into ANY member of the parent's `step_lineage_id`, so:
//!
//! * a writer of the group who is not the submitter is refused, with nothing
//!   written;
//! * the submitter and its operator are admitted, each write recorded as a
//!   `workflows.caller_write` row;
//! * an agent bound to the submitting human is refused (the operator ruling of
//!   2026-10-13: the shared host credential gains no edit rights over a human's
//!   workflows);
//! * an already-evolved head that no workflow executes directly (the
//!   `executes` edge stays on the frozen step) is still gated, because the
//!   gate reads the whole lineage, not the parent's own edges;
//! * a step two workflows execute needs authority over both;
//! * a RETRACTED `executes` edge still counts: any writer of the group can
//!   retract one, so a gate that skipped retracted edges would let that writer
//!   lift it;
//! * a workflow with no recorded submitter is admin-only, and the admin write
//!   records a `workflows.admin_write` row;
//! * a claim no workflow executes is unaffected.
//!
//! Every arm runs on the production pool shape: the router's connections are
//! `epigraph_app` (no BYPASSRLS), every request carries a real JWT through
//! `create_router`, and the harness superuser only seeds and inspects. The
//! plan is made group-private the way an administrative restriction does it
//! (`PrivatizationRepository::restrict_claims_conn`), and the curator is given
//! a writer row in the group, so that every refusal asserted here is the
//! workflow gate's (its own text), never row security's.
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::repos::privatization::PrivatizationRepository;
use epigraph_db::{AgentRepository, GroupRepository, ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const WRITE_SCOPES: &[&str] = &["claims:read", "claims:write", "edges:write"];
const CALLER_WRITE: &str = "workflows.caller_write";
const ADMIN_WRITE: &str = "workflows.admin_write";
const GATE_TEXT: &str = "was submitted by agent";
const NOTHING_WRITTEN: &str = "Nothing was written";

// ─────────────────────────────────────────────────────────────────────────────
// The production-shaped API
// ─────────────────────────────────────────────────────────────────────────────

struct Api {
    router: axum::Router,
}

impl Api {
    /// The router over an `epigraph_app` `ScopedPool`, whose inner pool is also
    /// the router's raw `db_pool` (`AppState::with_scoped_pool`, as
    /// `bin/server.rs` builds it).
    async fn prod_shaped(pool: &PgPool) -> Self {
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
        let state = AppState::with_scoped_pool(scoped, ApiConfig::default());
        state
            .load_entity_type_cache()
            .await
            .expect("load the entity-type cache");
        Self {
            router: epigraph_api::routes::create_router(state),
        }
    }

    async fn call(
        &self,
        method: Method,
        uri: &str,
        token: &str,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
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

    /// `POST /api/v1/workflows/ingest`, insisting on 200.
    async fn ingest(&self, token: &str, extraction: &Value) -> Uuid {
        let (status, body) = self
            .call(
                Method::POST,
                "/api/v1/workflows/ingest",
                token,
                Some(extraction),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "ingest: {body}");
        uuid_of(&body["workflow_id"])
    }

    /// `POST /api/v1/workflows/steps/:parent/evolve`.
    async fn evolve(
        &self,
        token: &str,
        parent: Uuid,
        content: &str,
        edge_type: &str,
    ) -> (StatusCode, Value) {
        self.call(
            Method::POST,
            &format!("/api/v1/workflows/steps/{parent}/evolve"),
            token,
            Some(&json!({"parent_id": parent, "content": content, "edge_type": edge_type})),
        )
        .await
    }
}

fn uuid_of(v: &Value) -> Uuid {
    v.as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("not a uuid: {v}"))
}

fn token(agent: Uuid) -> String {
    common::mint_token_with_agent(WRITE_SCOPES, agent)
}

/// A JWT whose `sub` is the OAuth client row `client` (as `/oauth/token`
/// mints it), naming `agent` as its principal.
fn token_for_client(client: Uuid, agent: Uuid, scopes: &[&str]) -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    cfg.issue_access_token(
        client,
        scopes.iter().map(|s| (*s).to_string()).collect(),
        "service",
        None,
        Some(agent),
        chrono::Duration::minutes(60),
        epigraph_auth::AccessTokenBinding::NONE,
    )
    .expect("test JWT")
    .0
}

/// One phase of `steps` level-2 steps, no operations.
fn extraction(canonical_name: &str, steps: usize) -> Value {
    let steps: Vec<Value> = (0..steps)
        .map(|i| {
            json!({"compound": format!("{canonical_name} step {i}"),
                   "rationale": "ordered", "operations": [], "generality": [],
                   "confidence": 0.8})
        })
        .collect();
    json!({
        "source": {"canonical_name": canonical_name,
                   "goal": format!("workflow-plan goal for {canonical_name}"),
                   "generation": 0, "metadata": {}},
        "thesis_derivation": "TopDown",
        "phases": [{"title": "Body", "summary": format!("{canonical_name} phase"),
                    "steps": steps}],
        "relationships": []
    })
}

/// Every claim the workflow executes (harness read).
async fn plan_claims(pool: &PgPool, workflow_id: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT target_id FROM edges WHERE source_id = $1 AND relationship = 'executes' \
          ORDER BY (properties->>'plan_index')::int NULLS LAST, created_at",
    )
    .bind(workflow_id)
    .fetch_all(pool)
    .await
    .expect("plan claims")
}

/// The first level-2 step the workflow executes, and its `executes` edge.
async fn first_step(pool: &PgPool, workflow_id: Uuid) -> (Uuid, Uuid) {
    sqlx::query_as(
        "SELECT e.target_id, e.id FROM edges e JOIN claims c ON c.id = e.target_id \
          WHERE e.source_id = $1 AND e.relationship = 'executes' \
            AND (c.properties->>'level')::int = 2 \
          ORDER BY (e.properties->>'plan_index')::int NULLS LAST, e.created_at LIMIT 1",
    )
    .bind(workflow_id)
    .fetch_one(pool)
    .await
    .expect("a level-2 step")
}

/// A `team` group whose creator `admin` holds its `admin` row (harness,
/// standing in for the maintenance session that provisions a role group).
async fn role_group(pool: &PgPool, admin: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let public_key = blake3::hash(id.as_bytes()).as_bytes().to_vec();
    GroupRepository::create_with_admin(
        pool,
        id,
        Some("workflow-plan role group"),
        &format!("did:epigraph:test:workflow-plan:{id}"),
        &public_key,
        None,
        admin,
    )
    .await
    .expect("the role group");
    id
}

/// Give `agent` a live `writer` row in `g`.
async fn add_writer(pool: &PgPool, g: Uuid, agent: Uuid) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(g)
    .bind(agent)
    .execute(pool)
    .await
    .expect("the writer row");
}

/// Restrict every claim the workflow executes to `('group', g)`, and check the
/// tenancy trigger took the `executes` edges with them.
async fn restrict_plan(pool: &PgPool, workflow_id: Uuid, g: Uuid) {
    let claims = plan_claims(pool, workflow_id).await;
    assert!(!claims.is_empty(), "the workflow executes nothing");
    let mut conn = pool.acquire().await.expect("acquire");
    let moved = PrivatizationRepository::restrict_claims_conn(&mut conn, &claims, g)
        .await
        .expect("restrict the plan's claims");
    assert_eq!(moved.len(), claims.len(), "every plan claim moved");
    let private_edges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND relationship = 'executes' \
            AND visibility::text = 'group' AND owner_group_id = $2",
    )
    .bind(workflow_id)
    .bind(g)
    .fetch_one(pool)
    .await
    .expect("edge tenancy");
    assert_eq!(
        private_edges,
        claims.len() as i64,
        "the executes edges follow their claims into ('group', G)"
    );
}

/// Record `agent` as workflow `wf`'s submitter (harness), as the audited
/// backfill of legacy workflows did; `None` removes the record.
async fn set_submitter(pool: &PgPool, wf: Uuid, agent: Option<Uuid>) {
    let q = match agent {
        Some(a) => sqlx::query(
            "UPDATE workflows SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), \
                    '{epigraph_submitted_by}', to_jsonb($2::text)) WHERE id = $1",
        )
        .bind(wf)
        .bind(a.to_string()),
        None => sqlx::query(
            "UPDATE workflows SET metadata = metadata - 'epigraph_submitted_by' WHERE id = $1",
        )
        .bind(wf),
    };
    q.execute(pool).await.expect("record the submitter");
}

async fn claims_with_content(pool: &PgPool, content: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .expect("count claims")
}

async fn is_current(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT COALESCE(is_current, true) FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("is_current")
}

/// Every `event_type` row recording an `evolve_step`, oldest first:
/// `(attributed agent, details)`.
async fn evolve_rows(pool: &PgPool, event_type: &str) -> Vec<(Option<Uuid>, Value)> {
    sqlx::query_as(
        "SELECT agent_id, details FROM security_events \
          WHERE event_type = $1 AND details->>'action' = 'evolve_step' \
          ORDER BY created_at, id",
    )
    .bind(event_type)
    .fetch_all(pool)
    .await
    .expect("read the evolve_step rows")
}

/// A group-private workflow ingested over REST by `curator` (its recorded
/// submitter), restricted to G. `writer` created G (its `admin` row); the
/// curator holds a `writer` row, so row security admits both of them on every
/// write here and only the workflow gate tells them apart.
struct Plan {
    api: Api,
    workflow_id: Uuid,
    g: Uuid,
    curator: Uuid,
    writer: Uuid,
    step: Uuid,
    step_edge: Uuid,
}

async fn private_plan(pool: &PgPool, name: &str) -> Plan {
    let (curator, _) = fixture::seed_agent_with_group(pool, "workflow-plan-curator").await;
    let (writer, _) = fixture::seed_agent_with_group(pool, "workflow-plan-writer").await;
    let g = role_group(pool, writer).await;
    add_writer(pool, g, curator).await;
    let api = Api::prod_shaped(pool).await;
    let workflow_id = api.ingest(&token(curator), &extraction(name, 3)).await;
    restrict_plan(pool, workflow_id, g).await;
    let (step, step_edge) = first_step(pool, workflow_id).await;
    Plan {
        api,
        workflow_id,
        g,
        curator,
        writer,
        step,
        step_edge,
    }
}

/// Send `POST .../steps/:parent/evolve` as `token` and assert the shape of
/// every gate refusal: 403 with the workflow gate's own text naming
/// `workflow`, and nothing written (no claim with `content`, the parent still
/// current, no `workflows.caller_write` or `workflows.admin_write` row).
#[allow(clippy::too_many_arguments)]
async fn assert_gate_refused(
    pool: &PgPool,
    api: &Api,
    token: &str,
    parent: Uuid,
    content: &str,
    edge_type: &str,
    workflow: Uuid,
    expect_text: &str,
) {
    let callers_before = evolve_rows(pool, CALLER_WRITE).await.len();
    let admins_before = evolve_rows(pool, ADMIN_WRITE).await.len();
    let (status, body) = api.evolve(token, parent, content, edge_type).await;
    let text = body.to_string();
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    assert!(
        text.contains(expect_text) && text.contains(NOTHING_WRITTEN),
        "the refusal is the workflow gate's, not row security's: {text}"
    );
    assert!(
        text.contains(&workflow.to_string()),
        "the refusal names workflow {workflow}: {text}"
    );
    assert_eq!(claims_with_content(pool, content).await, 0, "no claim");
    assert!(is_current(pool, parent).await, "the parent is not retired");
    assert_eq!(
        evolve_rows(pool, CALLER_WRITE).await.len(),
        callers_before,
        "no caller_write row"
    );
    assert_eq!(
        evolve_rows(pool, ADMIN_WRITE).await.len(),
        admins_before,
        "no admin_write row"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The arms
// ─────────────────────────────────────────────────────────────────────────────

/// A writer (here G's own admin) who is not the submitter is refused on both
/// edge types; the submitter is admitted and its write recorded.
#[sqlx::test(migrations = "../../migrations")]
async fn a_group_writer_who_is_not_the_submitter_cannot_evolve_an_executed_step(pool: PgPool) {
    let p = private_plan(&pool, "acme-evolve-writer").await;

    for edge_type in ["supersedes", "revises"] {
        let content = format!("the writer's {edge_type} of the step");
        assert_gate_refused(
            &pool,
            &p.api,
            &token(p.writer),
            p.step,
            &content,
            edge_type,
            p.workflow_id,
            GATE_TEXT,
        )
        .await;
    }
    assert!(evolve_rows(&pool, CALLER_WRITE).await.is_empty());

    // CALIBRATION: the submitter evolves the same step, and the write's
    // provenance row lands on the application role.
    let (status, body) = p
        .api
        .evolve(
            &token(p.curator),
            p.step,
            "the curator's revision",
            "supersedes",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "the submitter evolves: {body}");
    let head = uuid_of(&body["claim_id"]);
    let rows = evolve_rows(&pool, CALLER_WRITE).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let (agent, d) = &rows[0];
    assert_eq!(*agent, Some(p.curator), "attributed to the caller: {d}");
    assert_eq!(d["workflow_id"], p.workflow_id.to_string(), "{d}");
    assert_eq!(d["submitter"], p.curator.to_string(), "{d}");
    assert_eq!(d["arm"], "submitter", "{d}");
    assert_eq!(d["acting_agent"], p.curator.to_string(), "{d}");
    assert_eq!(d["write"]["parent_claim_id"], p.step.to_string(), "{d}");
    assert_eq!(d["write"]["claim_id"], head.to_string(), "{d}");
    assert_eq!(d["write"]["edge_type"], "supersedes", "{d}");
}

/// The operator arm admits the submitter's human; an agent bound to that
/// human through an allowlisted service client is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn the_submitters_operator_may_evolve_and_a_bound_agent_may_not(pool: PgPool) {
    let p = private_plan(&pool, "acme-evolve-operator").await;
    let (h, _) = fixture::seed_human_operator(&pool, "workflow-plan-human").await;
    let (s, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-operated").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        let out = AgentRepository::link_operator(&mut conn, s, h)
            .await
            .expect("link");
        assert!(out.membership_live && out.link_live, "calibration: {out:?}");
    }
    set_submitter(&pool, p.workflow_id, Some(s)).await;
    add_writer(&pool, p.g, h).await;

    // An agent bound to H through an allowlisted service client (migration
    // 149, arm (c)), itself a writer of G.
    let (bound, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-bound").await;
    add_writer(&pool, p.g, bound).await;
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, legal_entity_name, legal_contact_email) \
         VALUES ($1, 'bound agent', 'service', ARRAY['claims:write'], 'active', $2, \
                 'Fixture Org', 'fixture@example.invalid') RETURNING id",
    )
    .bind(format!("bound-agent-{bound}"))
    .bind(bound)
    .fetch_one(&pool)
    .await
    .expect("the bound agent's client");
    let binding: Option<String> =
        fixture::as_role(&pool, "epigraph_maintenance", |mut c| async move {
            let b = sqlx::query_scalar(
                "SELECT effective_binding \
                   FROM public.epigraph_allow_author_binding_client($1, $2, 'test')",
            )
            .bind(client)
            .bind(h)
            .fetch_one(&mut *c)
            .await
            .expect("allow the bound agent's client");
            (c, b)
        })
        .await;
    assert_eq!(
        binding.as_deref(),
        Some(epigraph_db::CLIENT_ALLOWLIST_BINDING),
        "calibration: the agent is bound to H"
    );

    assert_gate_refused(
        &pool,
        &p.api,
        &token_for_client(client, bound, WRITE_SCOPES),
        p.step,
        "the bound agent's revision",
        "revises",
        p.workflow_id,
        GATE_TEXT,
    )
    .await;

    let (status, body) = p
        .api
        .evolve(&token(h), p.step, "the operator's revision", "revises")
        .await;
    assert_eq!(status, StatusCode::OK, "the submitter's operator: {body}");
    let rows = evolve_rows(&pool, CALLER_WRITE).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let d = &rows[0].1;
    assert_eq!(d["arm"], "operator", "{d}");
    assert_eq!(d["operator"], h.to_string(), "{d}");
    assert_eq!(d["submitter"], s.to_string(), "{d}");
}

/// `executes` stays on the frozen step when the submitter evolves it, so the
/// new head is executed by nothing directly. Evolving THAT head is still
/// gated: the gate reads the whole lineage. The submitter still evolves it,
/// recorded against the workflow, so the gate admits through the lineage
/// rather than freezing executed heads.
#[sqlx::test(migrations = "../../migrations")]
async fn a_second_evolve_of_an_unexecuted_head_is_still_gated(pool: PgPool) {
    let p = private_plan(&pool, "acme-evolve-second").await;
    let (status, body) = p
        .api
        .evolve(
            &token(p.curator),
            p.step,
            "the first revision",
            "supersedes",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "the submitter evolves: {body}");
    let head = uuid_of(&body["claim_id"]);
    let direct: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE target_id = $1 AND relationship = 'executes'",
    )
    .bind(head)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(direct, 0, "calibration: no workflow executes the new head");

    for edge_type in ["supersedes", "revises"] {
        let content = format!("the writer's {edge_type} of the head");
        assert_gate_refused(
            &pool,
            &p.api,
            &token(p.writer),
            head,
            &content,
            edge_type,
            p.workflow_id,
            GATE_TEXT,
        )
        .await;
    }

    // CALIBRATION: the gate admits the submitter through the lineage; it does
    // not freeze an executed lineage's head.
    let before = evolve_rows(&pool, CALLER_WRITE).await.len();
    let (status, body) = p
        .api
        .evolve(
            &token(p.curator),
            head,
            "the curator's revision of the head",
            "revises",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the submitter evolves the head: {body}"
    );
    let rows = evolve_rows(&pool, CALLER_WRITE).await;
    assert_eq!(rows.len(), before + 1, "exactly one new row: {rows:?}");
    let (agent, d) = &rows[before];
    assert_eq!(*agent, Some(p.curator), "{d}");
    assert_eq!(d["workflow_id"], p.workflow_id.to_string(), "{d}");
    assert_eq!(d["arm"], "submitter", "{d}");
    assert_eq!(d["write"]["parent_claim_id"], head.to_string(), "{d}");
    assert_eq!(
        d["write"]["claim_id"],
        uuid_of(&body["claim_id"]).to_string(),
        "{d}"
    );
}

/// A step two workflows execute: the submitter of only one of them is
/// refused, naming the other. With authority over both it is admitted, and
/// the write is recorded once per workflow.
#[sqlx::test(migrations = "../../migrations")]
async fn a_step_two_workflows_execute_needs_authority_over_both(pool: PgPool) {
    let p = private_plan(&pool, "acme-evolve-shared").await;
    let (other, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-other").await;
    add_writer(&pool, p.g, other).await;
    let second = p
        .api
        .ingest(&token(other), &extraction("acme-evolve-shared-b", 1))
        .await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'workflow', $2, 'claim', 'executes')",
    )
    .bind(second)
    .bind(p.step)
    .execute(&pool)
    .await
    .expect("the second workflow executes the step");

    assert_gate_refused(
        &pool,
        &p.api,
        &token(p.curator),
        p.step,
        "the first curator's revision",
        "revises",
        second,
        GATE_TEXT,
    )
    .await;
    assert_gate_refused(
        &pool,
        &p.api,
        &token(other),
        p.step,
        "the second curator's revision",
        "revises",
        p.workflow_id,
        GATE_TEXT,
    )
    .await;
    assert!(evolve_rows(&pool, CALLER_WRITE).await.is_empty());

    // CALIBRATION: authority over both.
    set_submitter(&pool, second, Some(p.curator)).await;
    let (status, body) = p
        .api
        .evolve(
            &token(p.curator),
            p.step,
            "a revision both allow",
            "revises",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "authority over both: {body}");
    let mut recorded: Vec<String> = evolve_rows(&pool, CALLER_WRITE)
        .await
        .into_iter()
        .map(|(_, d)| d["workflow_id"].as_str().expect("id").to_string())
        .collect();
    recorded.sort();
    let mut want = vec![p.workflow_id.to_string(), second.to_string()];
    want.sort();
    assert_eq!(recorded, want, "one provenance row per workflow");
}

/// Any writer of G can retract an `executes` edge of a G-private plan
/// (`DELETE /api/v1/edges/:id`). Retracting it does not lift the gate, and
/// does not lock the submitter out either.
#[sqlx::test(migrations = "../../migrations")]
async fn retracting_the_executes_edge_does_not_lift_the_gate(pool: PgPool) {
    let p = private_plan(&pool, "acme-evolve-retracted").await;
    let (status, body) = p
        .api
        .call(
            Method::DELETE,
            &format!("/api/v1/edges/{}", p.step_edge),
            &token(p.writer),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the writer retracts: {body}"
    );
    let live: bool = sqlx::query_scalar("SELECT valid_to IS NULL FROM edges WHERE id = $1")
        .bind(p.step_edge)
        .fetch_one(&pool)
        .await
        .expect("edge");
    assert!(!live, "calibration: the executes edge is retracted");

    assert_gate_refused(
        &pool,
        &p.api,
        &token(p.writer),
        p.step,
        "the writer's revision after the retraction",
        "supersedes",
        p.workflow_id,
        GATE_TEXT,
    )
    .await;

    // CALIBRATION: the retraction did not make the step unevolvable; the
    // submitter is still admitted, and the write is recorded against the
    // workflow whose edge was retracted.
    let (status, body) = p
        .api
        .evolve(
            &token(p.curator),
            p.step,
            "the curator's revision after the retraction",
            "supersedes",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "the submitter evolves: {body}");
    let rows = evolve_rows(&pool, CALLER_WRITE).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let d = &rows[0].1;
    assert_eq!(d["workflow_id"], p.workflow_id.to_string(), "{d}");
    assert_eq!(d["write"]["parent_claim_id"], p.step.to_string(), "{d}");
}

/// A workflow with no recorded submitter is platform corpus: a writer of G,
/// even the agent that ingested it, is refused; the audited admin path is
/// admitted and records a `workflows.admin_write` row on the application
/// role; a `claims:admin` token whose client record grants nothing is
/// refused ADM02.
#[sqlx::test(migrations = "../../migrations")]
async fn an_executed_step_of_a_legacy_workflow_is_admin_only(pool: PgPool) {
    let p = private_plan(&pool, "acme-evolve-legacy").await;
    set_submitter(&pool, p.workflow_id, None).await;

    assert_gate_refused(
        &pool,
        &p.api,
        &token(p.curator),
        p.step,
        "the ingester's revision of a legacy step",
        "revises",
        p.workflow_id,
        "has no recorded submitter",
    )
    .await;

    let (admin, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-admin").await;
    add_writer(&pool, p.g, admin).await;
    let admin_scopes = &["claims:read", "claims:write", "claims:admin"];
    let grantless = token_for_client(Uuid::new_v4(), admin, admin_scopes);
    assert_gate_refused(
        &pool,
        &p.api,
        &grantless,
        p.step,
        "a grantless admin's revision",
        "revises",
        p.workflow_id,
        "ADM02",
    )
    .await;

    let client = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO oauth_clients (id, client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, agent_id) \
         VALUES ($1, $2, 'test admin', 'human', ARRAY['claims:admin'], ARRAY['claims:admin'], \
                 'active', $3)",
    )
    .bind(client)
    .bind(format!("test-admin-{client}"))
    .bind(admin)
    .execute(&pool)
    .await
    .expect("the admin's client record");
    let (status, body) = p
        .api
        .evolve(
            &token_for_client(client, admin, admin_scopes),
            p.step,
            "the admin's revision",
            "revises",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "the audited admin path: {body}");
    let rows = evolve_rows(&pool, ADMIN_WRITE).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let (agent, d) = &rows[0];
    assert_eq!(*agent, Some(admin), "the audit row names the admin: {d}");
    assert_eq!(d["workflow_id"], p.workflow_id.to_string(), "{d}");
    assert!(d["submitter"].is_null(), "{d}");
    assert!(evolve_rows(&pool, CALLER_WRITE).await.is_empty());
}

/// A G-private claim no workflow executes is evolved exactly as before, by
/// any writer of G, and records nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_no_workflow_executes_is_unaffected(pool: PgPool) {
    let p = private_plan(&pool, "acme-evolve-plain").await;
    let plain = fixture::seed_group_claim(&pool, p.writer, p.g, "a plain group claim").await;
    for edge_type in ["revises", "supersedes"] {
        let (status, body) = p
            .api
            .evolve(
                &token(p.writer),
                plain,
                &format!("the plain claim, {edge_type}"),
                edge_type,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{edge_type}: {body}");
    }
    assert!(evolve_rows(&pool, CALLER_WRITE).await.is_empty());
    assert!(evolve_rows(&pool, ADMIN_WRITE).await.is_empty());
}
