//! The read contract a PINNED-workflow resolver depends on, and a
//! characterization of the paths around it.
//!
//! A pinned-workflow resolver (a host that runs a stored workflow by
//! `(canonical_name, generation)` and refuses anything it cannot verify)
//! recomputes every id itself, reads the plan through the public REST surface
//! and trusts nothing the server derives. These tests pin what it reads, on the
//! production pool shape: every connection the router uses is `epigraph_app`
//! (`ScopedPool::connect_downgraded_for_tests`, `AppState::with_scoped_pool`,
//! so `db_pool` is the app role too), and every request carries a real JWT
//! through `create_router`. The harness superuser only seeds and inspects.
//!
//! Two kinds of test live here, and the difference matters to a reader:
//!
//! * CONTRACT tests ((a1), (a2), (b), (c), (d)) pin behaviour the resolver is
//!   built on. A change that fails one of them breaks every resolver.
//! * CHARACTERIZATION tests ((e), (f), (g), (h), the outcome report, the
//!   `executes` edge mutation) record what the code does TODAY, including
//!   behaviour nobody would design. They are evidence for a decision, not an
//!   endorsement, and they say so where they pin a gap.
//!
//! # The cases
//!
//! * (a1) A READER of group G, after the workflow's claims are restricted to
//!   `('group', G)`, sees every `executes` edge and every claim.
//! * (a2) A non-member sees zero `executes` edges and a 404 on every claim. It
//!   still sees the `workflows` row (goal, name, submitter): that table has no
//!   row security. The case runs on a clean schema only. A schema carrying
//!   extra PERMISSIVE policies on `claims`/`edges`/`evidence` is not a shape
//!   this repository creates, and no fixture here installs one.
//! * (b) Every ingest `executes` edge carries an integer `plan_index` and a
//!   `level`. An `add_step` append to an all-public plan carries
//!   `plan_index = max + 1`; an insert, or any add to a plan with a non-public
//!   `executes` edge, carries none (#639). The plan includes the level-3
//!   operation atoms: an ingest `executes` every one of them.
//! * (c) `GET /api/v1/workflows/:id` returns the recorded submitter.
//! * (d) `workflow_root_id`, `compound_claim_id`, `compound_content_hash`,
//!   `atom_id` and the plan order equal frozen vectors
//!   (`fixtures/workflow-ids-vectors.json`) computed by an implementation
//!   independent of these crates, and a real ingest writes exactly those ids
//!   and stored hashes.
//! * (e) Workflow authority and an operator RE-LINK. No shipped path re-points
//!   an agent's operator (`epigraph_link_operator` and
//!   `epigraph_link_retired_agent` both refuse a second operator with 55000,
//!   and neither application role may UPDATE or DELETE `operator_links`). So
//!   the test characterizes the refusal: after the curator's acting link is
//!   ended the documented way (its writer row in the operator group revoked),
//!   `operator_of_author` still names the FIRST operator, who keeps the
//!   operator arm over the curator's workflows on REST and on MCP, and the
//!   second human never gains it. A linked curator cannot publish over REST:
//!   the ingest route refuses its token, before and after the acting link
//!   ends.
//! * (f) Who can publish once operator binding is ARMED, with the ingest
//!   system agent live-linked to the first human: that human over REST; its
//!   linked curator over stdio (the REST ingest refuses its token); an
//!   unlinked curator nowhere over REST
//!   (`OPL01`); and a curator of a SECOND human nowhere (refused by the REST
//!   ingest as an operated agent, `OPL02` over stdio, nothing written). A curator re-linked to the second human cannot be
//!   constructed, as in (e).
//! * (g) An `epigraph_app` session that sets `epigraph.group_ids` itself reads
//!   a G-private claim and its `executes` edge: the GUCs are session
//!   settings, not credentials, so a session on the application role reads
//!   whichever group it names.
//! * (h) The same role can `UPDATE workflows` (truth and the submitter key) of
//!   a row it reads: migration 183's row security admits an UPDATE of any
//!   readable row (a public one here) and guards only the tenancy columns. A
//!   rewritten submitter is then honoured by the workflow authority gate.
//! * Outcome report (as changed by #632, then by the visibility gate): `POST
//!   /api/v1/workflows/hierarchical/:id/outcome` needs `claims:write`; on a
//!   group-private plan a member's report resolves the steps, and a
//!   non-member, which reads none of the plan's `executes` edges, is answered
//!   404 (MCP: the unknown-id error) with nothing written.
//! * `executes` edge mutation: any principal that writes G (an `admin` or a
//!   plain `writer` row) can rewrite `plan_index` and retract an `executes`
//!   edge of a G-private workflow, over REST and over the stdio MCP tools; a
//!   reader and a non-member cannot, on either.
//!
//! # How a workflow becomes group-private here
//!
//! `ingest_workflow` has no tenancy parameter yet, so the workflow is ingested
//! public and its claims are then moved with
//! `PrivatizationRepository::restrict_claims_conn`, the claims UPDATE an
//! administrative restriction performs. Migration 072's tenancy trigger
//! re-meets the edges; the tests assert the `executes` edges ended up
//! `('group', G)` rather than assume it.
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

/// Frozen vectors, computed outside these crates. Compared, never regenerated.
const VECTORS: &str = include_str!("fixtures/workflow-ids-vectors.json");

const WRITE_SCOPES: &[&str] = &["claims:read", "claims:write", "edges:write"];
const READ_SCOPES: &[&str] = &["claims:read"];

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("the vectors file parses")
}

fn uuid_of(v: &Value) -> Uuid {
    v.as_str()
        .unwrap_or_else(|| panic!("expected a uuid string, got {v}"))
        .parse()
        .unwrap_or_else(|e| panic!("{v} is not a uuid: {e}"))
}

fn hex32(v: &Value) -> [u8; 32] {
    let bytes = hex::decode(v.as_str().expect("hex string")).expect("hex");
    bytes.try_into().expect("32 bytes")
}

fn sqlstate(e: &sqlx::Error) -> String {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.to_string())
        .unwrap_or_default()
}

// ─────────────────────────────────────────────────────────────────────────────
// (d) without a database: the vectors against the Rust derivations
// ─────────────────────────────────────────────────────────────────────────────

/// (d) Every frozen vector equals what `epigraph-ingest`'s derivations
/// compute, and the plan the builder makes from the fixture's extraction is
/// the fixture's plan, item for item and in order.
#[test]
fn id_derivations_equal_the_frozen_vectors() {
    use epigraph_ingest::common::ids;
    let v = vectors();

    let namespaces = &v["namespaces"];
    assert_eq!(uuid_of(&namespaces["workflow"]), ids::WORKFLOW_NAMESPACE);
    assert_eq!(uuid_of(&namespaces["compound"]), ids::COMPOUND_NAMESPACE);
    assert_eq!(uuid_of(&namespaces["atom"]), ids::ATOM_NAMESPACE);

    let roots = v["workflow_root_ids"].as_array().expect("roots");
    assert!(roots.len() >= 4, "the root vectors were truncated");
    for r in roots {
        let name = r["canonical_name"].as_str().expect("name");
        let generation = u32::try_from(r["generation"].as_u64().expect("generation"))
            .expect("generation fits u32");
        assert_eq!(
            ids::workflow_root_id(name, generation),
            uuid_of(&r["workflow_id"]),
            "workflow_root_id({name:?}, {generation})"
        );
    }

    for c in v["compound_claims"].as_array().expect("compound vectors") {
        let content = c["content"].as_str().expect("content");
        let seed = c["seed"].as_str().expect("seed");
        let plain = ids::content_hash(content);
        assert_eq!(
            plain,
            hex32(&c["plain_content_hash"]),
            "blake3({content:?})"
        );
        assert_eq!(
            ids::compound_claim_id(&plain, seed),
            uuid_of(&c["claim_id"]),
            "compound_claim_id({content:?}, {seed:?})"
        );
        assert_eq!(
            ids::compound_content_hash(&plain, seed),
            hex32(&c["content_hash"]),
            "compound_content_hash({content:?}, {seed:?})"
        );
    }

    for a in v["atoms"].as_array().expect("atom vectors") {
        let content = a["content"].as_str().expect("content");
        let plain = ids::content_hash(content);
        assert_eq!(plain, hex32(&a["content_hash"]));
        assert_eq!(
            ids::atom_id(&plain),
            uuid_of(&a["claim_id"]),
            "atom_id({content:?})"
        );
    }

    let extraction: epigraph_ingest::workflow::WorkflowExtraction =
        serde_json::from_value(v["extraction"].clone()).expect("the fixture extraction");
    assert_eq!(
        epigraph_ingest::workflow::builder::root_workflow_id(&extraction),
        uuid_of(&v["workflow_id"])
    );
    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(&extraction);
    let expected = v["plan"].as_array().expect("plan");
    let got: Vec<(usize, u8, String, Uuid, [u8; 32])> = plan
        .claims
        .iter()
        .enumerate()
        .map(|(i, c)| (i, c.level, c.content.clone(), c.id, c.content_hash))
        .collect();
    let want: Vec<(usize, u8, String, Uuid, [u8; 32])> = expected
        .iter()
        .map(|p| {
            (
                usize::try_from(p["plan_index"].as_u64().expect("plan_index")).unwrap(),
                u8::try_from(p["level"].as_u64().expect("level")).unwrap(),
                p["content"].as_str().expect("content").to_string(),
                uuid_of(&p["claim_id"]),
                hex32(&p["content_hash"]),
            )
        })
        .collect();
    assert_eq!(got, want, "the builder's plan is the frozen plan, in order");
    // The fixture exercises every level and the blank-summary fallback.
    for level in 0..=3u8 {
        assert!(
            want.iter().any(|w| w.1 == level),
            "the fixture plan has no level-{level} item"
        );
    }
    let phase_titles: Vec<&str> = v["extraction"]["phases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["summary"].as_str().unwrap_or("").trim().is_empty())
        .map(|p| p["title"].as_str().unwrap())
        .collect();
    assert!(
        !phase_titles.is_empty()
            && phase_titles
                .iter()
                .all(|t| want.iter().any(|w| w.1 == 1 && w.2 == *t)),
        "a phase with a blank summary is stored under its title"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The production-shaped API
// ─────────────────────────────────────────────────────────────────────────────

struct Api {
    router: axum::Router,
}

impl Api {
    /// The router over an `epigraph_app` `ScopedPool`, whose inner pool is
    /// also the router's raw `db_pool`: the production wiring
    /// (`bin/server.rs` builds `AppState::with_scoped_pool`).
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

    async fn get(&self, uri: &str, token: &str) -> (StatusCode, Value) {
        self.call(Method::GET, uri, token, None).await
    }

    async fn post(&self, uri: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        self.call(Method::POST, uri, token, Some(body)).await
    }

    /// `POST /api/v1/workflows/ingest`, insisting on 200.
    async fn ingest(&self, token: &str, extraction: &Value) -> Value {
        let (status, body) = self
            .post("/api/v1/workflows/ingest", token, extraction)
            .await;
        assert_eq!(status, StatusCode::OK, "ingest: {body}");
        body
    }

    /// `POST /api/v1/workflows/steps` (append).
    async fn add_step(&self, token: &str, canonical_name: &str, text: &str) -> (StatusCode, Value) {
        self.post(
            "/api/v1/workflows/steps",
            token,
            &json!({"canonical_name": canonical_name, "step_text": text}),
        )
        .await
    }

    /// What the resolver's fallback reader reads: the workflow's `executes`
    /// edges, insisting on 200.
    async fn executes_edges(&self, token: &str, workflow_id: Uuid) -> Vec<Value> {
        let (status, body) = self
            .get(
                &format!("/api/v1/edges?source_id={workflow_id}&relationship=executes"),
                token,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "GET executes edges: {body}");
        body.as_array().expect("an edge array").clone()
    }
}

fn token(agent: Uuid, scopes: &[&str]) -> String {
    common::mint_token_with_agent(scopes, agent)
}

/// The fixture's extraction, under `canonical_name` when given.
fn fixture_extraction(canonical_name: Option<&str>) -> Value {
    let mut e = vectors()["extraction"].clone();
    if let Some(name) = canonical_name {
        e["source"]["canonical_name"] = json!(name);
    }
    e
}

/// A small extraction for the tests that need a workflow but not the vectors:
/// one phase, `steps` level-2 steps, no operations.
fn small_extraction(canonical_name: &str, steps: usize) -> Value {
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

/// The claim ids the workflow `executes`, in `plan_index` order (harness read).
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

/// A `team` group G (the role group): `writer` is its creator (`admin`), and
/// `reader` holds a `reader` row. Written on the harness, standing in for the
/// maintenance session that provisions a role group.
async fn role_group(pool: &PgPool, writer: Uuid, reader: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let public_key = blake3::hash(id.as_bytes()).as_bytes().to_vec();
    GroupRepository::create_with_admin(
        pool,
        id,
        Some("workflow-plan role group"),
        &format!("did:epigraph:test:workflow-plan:{id}"),
        &public_key,
        None,
        writer,
    )
    .await
    .expect("the role group");
    add_member(pool, id, reader, "reader").await;
    id
}

/// Give `agent` a live `role` row in group `g` (harness, standing in for the
/// maintenance session that grants it).
async fn add_member(pool: &PgPool, g: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(g)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .unwrap_or_else(|e| panic!("the {role} row: {e}"));
}

/// Restrict every claim the workflow executes to `('group', g)`, and check the
/// tenancy trigger took the `executes` edges with them.
async fn restrict_plan(pool: &PgPool, workflow_id: Uuid, g: Uuid) -> Vec<Uuid> {
    let claims = plan_claims(pool, workflow_id).await;
    assert!(!claims.is_empty(), "the workflow executes nothing");
    let mut conn = pool.acquire().await.expect("acquire");
    let moved = PrivatizationRepository::restrict_claims_conn(&mut conn, &claims, g)
        .await
        .expect("restrict the plan's claims");
    assert_eq!(moved.len(), claims.len(), "every plan claim moved");
    let edge_tenancy: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT visibility::text, owner_group_id FROM edges \
          WHERE source_id = $1 AND relationship = 'executes'",
    )
    .bind(workflow_id)
    .fetch_all(pool)
    .await
    .expect("edge tenancy");
    assert_eq!(edge_tenancy.len(), claims.len());
    assert!(
        edge_tenancy.iter().all(|(v, o)| v == "group" && *o == g),
        "the executes edges follow their claims into ('group', G): {edge_tenancy:?}"
    );
    claims
}

/// A G-private workflow ingested by `curator`, plus G's writer, reader and a
/// stranger, on the production-shaped API.
struct PrivateWorkflow {
    api: Api,
    workflow_id: Uuid,
    canonical_name: String,
    claims: Vec<Uuid>,
    g: Uuid,
    curator: Uuid,
    writer: Uuid,
    reader: Uuid,
    stranger: Uuid,
}

async fn private_workflow(pool: &PgPool, extraction: Value) -> PrivateWorkflow {
    let (curator, _) = fixture::seed_agent_with_group(pool, "workflow-plan-curator").await;
    let (writer, _) = fixture::seed_agent_with_group(pool, "workflow-plan-writer").await;
    let (reader, _) = fixture::seed_agent_with_group(pool, "workflow-plan-reader").await;
    let (stranger, _) = fixture::seed_agent_with_group(pool, "workflow-plan-stranger").await;
    let g = role_group(pool, writer, reader).await;
    let api = Api::prod_shaped(pool).await;
    let canonical_name = extraction["source"]["canonical_name"]
        .as_str()
        .expect("name")
        .to_string();
    let out = api.ingest(&token(curator, WRITE_SCOPES), &extraction).await;
    let workflow_id = uuid_of(&out["workflow_id"]);
    let claims = restrict_plan(pool, workflow_id, g).await;
    PrivateWorkflow {
        api,
        workflow_id,
        canonical_name,
        claims,
        g,
        curator,
        writer,
        reader,
        stranger,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// (a1) / (a2): who reads a group-private plan
// ─────────────────────────────────────────────────────────────────────────────

/// (a1) A READER of G reads the whole plan: every `executes` edge, with its
/// `plan_index`, and every claim, with its content. If this fails, the
/// resolver's fallback reader (edges, then each claim) is invalid.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reader_of_the_group_reads_every_executes_edge_and_claim(pool: PgPool) {
    let w = private_workflow(&pool, fixture_extraction(None)).await;
    let reader = token(w.reader, READ_SCOPES);
    let v = vectors();
    let expected = v["plan"].as_array().unwrap();

    let edges = w.api.executes_edges(&reader, w.workflow_id).await;
    assert_eq!(
        edges.len(),
        expected.len(),
        "the reader sees every executes edge"
    );
    let mut by_index: Vec<(u64, Uuid)> = edges
        .iter()
        .map(|e| {
            (
                e["properties"]["plan_index"].as_u64().expect("plan_index"),
                uuid_of(&e["target_id"]),
            )
        })
        .collect();
    by_index.sort_unstable();
    let want: Vec<(u64, Uuid)> = expected
        .iter()
        .map(|p| (p["plan_index"].as_u64().unwrap(), uuid_of(&p["claim_id"])))
        .collect();
    assert_eq!(
        by_index, want,
        "the reader reads the plan in plan_index order"
    );

    for p in expected {
        let id = uuid_of(&p["claim_id"]);
        let (status, body) = w.api.get(&format!("/api/v1/claims/{id}"), &reader).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the reader reads claim {id}: {body}"
        );
        assert_eq!(body["content"], p["content"], "claim {id} content");
    }
}

/// (a2) A non-member reads none of it: zero `executes` edges (not even a
/// count) and a 404 on every claim. Calibrated by the same claims answering
/// the reader. The `workflows` ROW is a different matter: it has no row
/// security, so the non-member reads its goal, name and submitter.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_reads_no_executes_edge_and_gets_404_per_claim(pool: PgPool) {
    let w = private_workflow(&pool, fixture_extraction(None)).await;
    let stranger = token(w.stranger, READ_SCOPES);

    assert!(
        w.api
            .executes_edges(&stranger, w.workflow_id)
            .await
            .is_empty(),
        "a non-member sees no executes edge"
    );
    let reader = token(w.reader, READ_SCOPES);
    for id in &w.claims {
        let (status, body) = w.api.get(&format!("/api/v1/claims/{id}"), &stranger).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "claim {id} for a non-member: {body}"
        );
        let (status, _) = w.api.get(&format!("/api/v1/claims/{id}"), &reader).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "calibration: the reader reads claim {id}"
        );
    }

    // The residual: the workflow row itself is world-readable.
    let (status, body) = w
        .api
        .get(&format!("/api/v1/workflows/{}", w.workflow_id), &stranger)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["canonical_name"], json!(w.canonical_name));
    assert_eq!(
        body["goal"],
        vectors()["extraction"]["source"]["goal"],
        "the goal is readable by a non-member"
    );
    assert_eq!(
        body["properties"]["epigraph_submitted_by"],
        json!(w.curator.to_string()),
        "the submitter is readable by a non-member"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (b) plan_index and level, (c) submitter, (d) ids on a real ingest
// ─────────────────────────────────────────────────────────────────────────────

/// (b) + (d) A real ingest of the fixture's extraction writes the frozen ids,
/// the frozen stored hashes, and `executes` edges whose `plan_index` is a JSON
/// integer, contiguous from 0, in the frozen order, each with its `level`.
#[sqlx::test(migrations = "../../migrations")]
async fn an_ingest_writes_the_frozen_ids_and_integer_contiguous_plan_indices(pool: PgPool) {
    let (curator, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-curator").await;
    let api = Api::prod_shaped(&pool).await;
    let t = token(curator, WRITE_SCOPES);
    let v = vectors();
    let out = api.ingest(&t, &v["extraction"]).await;
    assert_eq!(uuid_of(&out["workflow_id"]), uuid_of(&v["workflow_id"]));

    let expected = v["plan"].as_array().unwrap();
    let edges = api.executes_edges(&t, uuid_of(&v["workflow_id"])).await;
    assert_eq!(edges.len(), expected.len());
    let mut rows: Vec<(u64, u64, Uuid)> = Vec::new();
    for e in &edges {
        let props = &e["properties"];
        assert!(
            props["plan_index"].is_u64(),
            "plan_index must be a JSON integer, got {}",
            props["plan_index"]
        );
        assert!(
            props["level"].is_u64(),
            "level must be a JSON integer: {props}"
        );
        assert!(e["valid_to"].is_null(), "a fresh executes edge is in force");
        rows.push((
            props["plan_index"].as_u64().unwrap(),
            props["level"].as_u64().unwrap(),
            uuid_of(&e["target_id"]),
        ));
    }
    rows.sort_unstable();
    let want: Vec<(u64, u64, Uuid)> = expected
        .iter()
        .map(|p| {
            (
                p["plan_index"].as_u64().unwrap(),
                p["level"].as_u64().unwrap(),
                uuid_of(&p["claim_id"]),
            )
        })
        .collect();
    assert_eq!(rows, want, "plan_index 0..n-1, levels and ids as frozen");

    for p in expected {
        let (content, hash): (String, Vec<u8>) =
            sqlx::query_as("SELECT content, content_hash FROM claims WHERE id = $1")
                .bind(uuid_of(&p["claim_id"]))
                .fetch_one(&pool)
                .await
                .expect("the planned claim exists");
        assert_eq!(json!(content), p["content"]);
        assert_eq!(
            hash.as_slice(),
            hex32(&p["content_hash"]).as_slice(),
            "stored content_hash of level-{} {:?}",
            p["level"],
            p["content"]
        );
    }
}

/// (b) An `add_step` append to an all-public plan carries `level` and
/// `plan_index = max + 1` (#639), so a reader that requires a contiguous
/// `plan_index` sees the appended step as the plan's last item and no
/// unindexed edge.
#[sqlx::test(migrations = "../../migrations")]
async fn an_add_step_append_to_a_public_plan_carries_the_next_plan_index(pool: PgPool) {
    let (curator, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-curator").await;
    let api = Api::prod_shaped(&pool).await;
    let t = token(curator, WRITE_SCOPES);
    let name = "acme-add-step-plan";
    let wf = uuid_of(&api.ingest(&t, &small_extraction(name, 2)).await["workflow_id"]);
    let before = api.executes_edges(&t, wf).await;
    assert!(before
        .iter()
        .all(|e| e["properties"]["plan_index"].is_u64()));

    let (status, body) = api.add_step(&t, name, "ACME-123456 appended step").await;
    assert_eq!(status, StatusCode::OK, "add_step: {body}");
    let step = uuid_of(&body["step_claim_id"]);
    let after = api.executes_edges(&t, wf).await;
    assert_eq!(after.len(), before.len() + 1);
    let added: Vec<&Value> = after
        .iter()
        .filter(|e| uuid_of(&e["target_id"]) == step)
        .collect();
    assert_eq!(added.len(), 1);
    let max_before = before
        .iter()
        .filter_map(|e| e["properties"]["plan_index"].as_u64())
        .max()
        .expect("an indexed plan");
    assert_eq!(
        added[0]["properties"],
        json!({"level": 2, "plan_index": max_before + 1}),
        "the appended edge takes the next index"
    );
    assert_eq!(
        after
            .iter()
            .filter(|e| e["properties"].get("plan_index").is_none())
            .count(),
        0,
        "no unindexed edge"
    );
    let mut indices: Vec<u64> = after
        .iter()
        .filter_map(|e| e["properties"]["plan_index"].as_u64())
        .collect();
    indices.sort_unstable();
    assert_eq!(
        indices,
        (0..=max_before + 1).collect::<Vec<_>>(),
        "still contiguous from 0"
    );
}

/// (c) `GET /api/v1/workflows/:id` returns the recorded submitter, which is
/// the authenticated caller of the ingest.
#[sqlx::test(migrations = "../../migrations")]
async fn get_workflow_returns_the_submitter(pool: PgPool) {
    let (curator, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-curator").await;
    let (other, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-other").await;
    let api = Api::prod_shaped(&pool).await;
    let mut e = small_extraction("acme-submitter-plan", 1);
    // A caller-supplied submitter is stripped.
    e["source"]["metadata"] = json!({"epigraph_submitted_by": other.to_string()});
    let wf = uuid_of(&api.ingest(&token(curator, WRITE_SCOPES), &e).await["workflow_id"]);

    let (status, body) = api
        .get(
            &format!("/api/v1/workflows/{wf}"),
            &token(other, READ_SCOPES),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["workflow_id"], json!(wf.to_string()));
    assert_eq!(body["canonical_name"], json!("acme-submitter-plan"));
    assert_eq!(
        body["properties"]["epigraph_submitted_by"],
        json!(curator.to_string())
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (e) / (f): authority and an operator re-link
// ─────────────────────────────────────────────────────────────────────────────

/// Run `sql` (binding two uuids) as `epigraph_maintenance`, the role
/// `epigraph-operator link` connects as.
async fn as_maintenance(
    pool: &PgPool,
    sql: &'static str,
    a: Uuid,
    b: Uuid,
) -> Result<(), sqlx::Error> {
    fixture::as_role(pool, "epigraph_maintenance", move |mut conn| async move {
        let r = sqlx::query(sql)
            .bind(a)
            .bind(b)
            .execute(&mut *conn)
            .await
            .map(|_| ());
        (conn, r)
    })
    .await
}

async fn link_as_maintenance(
    pool: &PgPool,
    agent: Uuid,
    operator: Uuid,
) -> Result<(), sqlx::Error> {
    as_maintenance(
        pool,
        "SELECT * FROM public.epigraph_link_operator($1, $2)",
        agent,
        operator,
    )
    .await
}

/// Every shipped way to re-point `agent` from its operator to `second` is
/// refused, and refused as a re-point (55000 naming the out-of-band act).
async fn assert_relink_refused(pool: &PgPool, agent: Uuid, second: Uuid) {
    for (what, sql) in [
        (
            "epigraph_link_operator",
            "SELECT * FROM public.epigraph_link_operator($1, $2)",
        ),
        (
            "epigraph_link_retired_agent",
            "SELECT * FROM public.epigraph_link_retired_agent($1, $2)",
        ),
    ] {
        let err = as_maintenance(pool, sql, agent, second)
            .await
            .expect_err("a second operator must be refused");
        assert_eq!(sqlstate(&err), "55000", "{what}: {err}");
        assert!(
            err.to_string().contains("out-of-band"),
            "{what} names the re-point as an out-of-band act: {err}"
        );
    }
    for (role, sql) in [
        (
            "epigraph_maintenance",
            "UPDATE public.operator_links SET operator_id = $2 WHERE agent_id = $1",
        ),
        (
            "epigraph_maintenance",
            "DELETE FROM public.operator_links WHERE agent_id = $1 AND operator_id <> $2",
        ),
    ] {
        let err = as_maintenance(pool, sql, agent, second)
            .await
            .expect_err("the link row is not writable");
        assert_eq!(sqlstate(&err), "42501", "{role}: {err}");
    }
    let app = fixture::as_role(pool, "epigraph_app", move |mut conn| async move {
        let r =
            sqlx::query("UPDATE public.operator_links SET operator_id = $2 WHERE agent_id = $1")
                .bind(agent)
                .bind(second)
                .execute(&mut *conn)
                .await;
        (conn, r.map(|_| ()))
    })
    .await
    .expect_err("the app role cannot write the link row");
    assert_eq!(sqlstate(&app), "42501", "{app}");
}

/// End `agent`'s acting link the documented way: revoke its live rows in the
/// operator's group (harness, standing in for the maintenance revocation).
async fn revoke_membership(pool: &PgPool, group: Uuid, agent: Uuid) {
    let n = sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(group)
    .bind(agent)
    .execute(pool)
    .await
    .expect("revoke")
    .rows_affected();
    assert!(n >= 1, "the agent held a live row in {group}");
}

/// An app-role stdio server whose own agent is keyed by `seed`, as a
/// container's `epigraph-mcp` is. Without an `AuthContext` its tools run on
/// the stdio transport; with one, on the authenticated transport.
async fn mcp_server(pool: &PgPool, seed: u8) -> epigraph_mcp::server::EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let embedder =
        epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None).with_scoped_pool(scoped.clone());
    epigraph_mcp::server::EpiGraphMcpFull::new(plain, signer, embedder, false)
        .with_scoped_pool(scoped)
}

/// The stdio server's own agent: resolving its viewer creates the row (and its
/// personal group) on first use, as its first tool call would.
async fn stdio_agent(
    pool: &PgPool,
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    seed: u8,
) -> Uuid {
    epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("the stdio viewer");
    let key = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32])
        .expect("signer")
        .public_key();
    sqlx::query_scalar("SELECT id FROM agents WHERE public_key = $1")
        .bind(key.as_slice())
        .fetch_one(pool)
        .await
        .expect("the stdio server's agent row")
}

/// MCP `ingest_workflow` on the stdio transport, as the server's own agent.
async fn stdio_ingest(
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    extraction: &Value,
) -> Result<(), String> {
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .map_err(|e| e.message.to_string())?;
    let extraction: epigraph_ingest::workflow::WorkflowExtraction =
        serde_json::from_value(extraction.clone()).expect("extraction");
    epigraph_mcp::tools::workflow_ingest::ingest_workflow(
        server,
        &viewer,
        epigraph_mcp::types::IngestWorkflowParams {
            extraction,
            tenancy: None,
            embed: None,
        },
        None,
    )
    .await
    .map(|_| ())
    .map_err(|e| e.message.to_string())
}

fn auth_for(agent: Uuid) -> epigraph_auth::AuthContext {
    epigraph_auth::AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: epigraph_auth::ClientType::Agent,
        scopes: WRITE_SCOPES.iter().map(|s| (*s).to_string()).collect(),
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        delegated_by: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
    }
}

/// MCP `add_step` as `agent` on the authenticated transport, which is where
/// `require_workflow_authority` runs its arms.
async fn mcp_add_step(
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    agent: Uuid,
    canonical_name: &str,
    text: &str,
) -> Result<(), String> {
    // The viewer the served tool builds: `request_viewer` on the server's
    // app-role pool, with its refusal of an operated principal, from the same
    // `AuthContext` the tool then authorizes.
    let auth = auth_for(agent);
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, Some(&auth))
        .await
        .map_err(|e| e.message.to_string())?;
    epigraph_mcp::tools::step_ops::add_step(
        server,
        &viewer,
        epigraph_mcp::tools::step_ops::AddStepParams {
            canonical_name: canonical_name.to_string(),
            step_text: text.to_string(),
            position: None,
        },
        Some(&auth),
    )
    .await
    .map(|_| ())
    .map_err(|e| e.message.to_string())
}

/// The REST ingest's refusal of an operated agent's token.
fn assert_operated_refusal(status: StatusCode, body: &Value, what: &str) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{what}: {body}");
    assert!(
        body.to_string().contains("operated agents are stdio-only"),
        "{what}: refused as an operated agent: {body}"
    );
}

/// (e) CHARACTERIZATION. Workflow authority does not "follow a re-link",
/// because no shipped path can make one: both link definers refuse a second
/// operator and neither application role can write `operator_links`.
///
/// The curator ingests over REST while UNLINKED, because once linked the
/// REST ingest refuses its token (the test pins that too). Once linked, its
/// first operator holds the operator arm over its workflow. Ending the
/// curator's acting link the documented way (revoking its writer row in the
/// operator group) leaves `operator_of_author` on the FIRST operator, so that
/// human keeps the operator arm, on REST and on MCP, the second human never
/// gets it, and the REST ingest still refuses the curator's token.
#[sqlx::test(migrations = "../../migrations")]
async fn workflow_authority_keeps_the_first_operator_because_a_relink_is_refused(pool: PgPool) {
    let (o1, og1) = fixture::seed_human_operator(&pool, "workflow-plan-o1").await;
    let (o2, _og2) = fixture::seed_human_operator(&pool, "workflow-plan-o2").await;
    let (curator, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-curator").await;
    let api = Api::prod_shaped(&pool).await;
    let server = mcp_server(&pool, 0x5E).await;
    let name = "acme-handover-plan";
    let curator_t = token(curator, WRITE_SCOPES);
    api.ingest(&curator_t, &small_extraction(name, 1)).await;

    link_as_maintenance(&pool, curator, o1)
        .await
        .expect("link the curator to the first operator");
    let next_generation = |g: u64| {
        let mut e = small_extraction(name, 1);
        e["source"]["generation"] = json!(g);
        e
    };
    let (s, b) = api
        .post("/api/v1/workflows/ingest", &curator_t, &next_generation(1))
        .await;
    assert_operated_refusal(s, &b, "the linked curator publishing over REST");

    let o1_t = token(o1, WRITE_SCOPES);
    let o2_t = token(o2, WRITE_SCOPES);
    let (s, b) = api.add_step(&o1_t, name, "first operator, before").await;
    assert_eq!(
        s,
        StatusCode::OK,
        "the first operator holds the operator arm: {b}"
    );
    let (s, b) = api.add_step(&o2_t, name, "second operator, before").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{b}");

    // The re-link the handover needs is refused through every shipped path.
    assert_relink_refused(&pool, curator, o2).await;
    // End the acting link the documented way, then try the re-link again.
    revoke_membership(&pool, og1, curator).await;
    let err = link_as_maintenance(&pool, curator, o2)
        .await
        .expect_err("still refused after the acting link ended");
    assert_eq!(sqlstate(&err), "55000", "{err}");

    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let author = AgentRepository::operator_of_author_pool(&app, curator)
        .await
        .expect("operator_of_author")
        .expect("the curator still has an author operator");
    assert_eq!(
        author.operator_id, o1,
        "ownership stays with the first operator"
    );
    assert!(
        AgentRepository::operator_actor_pool(&app, curator)
            .await
            .expect("operator_actor")
            .is_none(),
        "the curator no longer acts for anyone"
    );

    // REST: the first operator keeps the arm; the second never gains it.
    let (s, b) = api.add_step(&o1_t, name, "first operator, after").await;
    assert_eq!(
        s,
        StatusCode::OK,
        "the first operator keeps the operator arm: {b}"
    );
    let (s, b) = api.add_step(&o2_t, name, "second operator, after").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{b}");
    // MCP (`require_workflow_authority`): the same.
    mcp_add_step(&server, o1, name, "first operator, mcp")
        .await
        .expect("MCP: the first operator keeps the operator arm");
    let refused = mcp_add_step(&server, o2, name, "second operator, mcp")
        .await
        .expect_err("MCP: the second operator is refused");
    assert!(refused.contains("was submitted by agent"), "{refused}");
    // The curator's refusal is keyed on the link record, not on acting.
    let (s, b) = api
        .post("/api/v1/workflows/ingest", &curator_t, &next_generation(1))
        .await;
    assert_operated_refusal(s, &b, "the curator after its acting link ended");
}

async fn arm(pool: &PgPool) {
    let armed: bool = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let armed: bool =
            sqlx::query_scalar("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
                .fetch_one(&mut *conn)
                .await
                .expect("arm");
        (conn, armed)
    })
    .await;
    assert!(armed, "the database arms");
}

async fn workflows_named(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM workflows WHERE canonical_name = $1")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("count workflows")
}

/// The owner groups of the claims a workflow named `name` executes.
async fn plan_owners(pool: &PgPool, name: &str) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT DISTINCT c.owner_group_id FROM workflows w \
           JOIN edges e ON e.source_id = w.id AND e.relationship = 'executes' \
           JOIN claims c ON c.id = e.target_id \
          WHERE w.canonical_name = $1",
    )
    .bind(name)
    .fetch_all(pool)
    .await
    .expect("plan owners")
}

/// (f) CHARACTERIZATION, armed. Who can publish a workflow once operator
/// binding is armed, with the ingest system agent registered and live-linked
/// to the first human (the deploy order):
///
/// * the first human itself, over REST;
/// * NOT an unlinked curator over REST: the ingest's caller check refuses an
///   unbound caller (`OPL01`);
/// * NOT a curator linked to the first human over REST: the REST ingest
///   refuses an operated agent's token. Over stdio it publishes, into the
///   first human's group;
/// * NOT a curator linked to a SECOND human, on either transport: the REST
///   ingest refuses its token as an operated agent's, and over stdio the
///   caller check refuses it `OPL02` (it must belong to the system agent's
///   human); it writes nothing on either. This is the nearest shipped shape of "a
///   curator re-linked to a second human": the re-link itself is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn armed_publishing_is_bound_to_the_system_agents_human(pool: PgPool) {
    let (o1, og1) = fixture::seed_human_operator(&pool, "workflow-plan-o1").await;
    let (o2, _) = fixture::seed_human_operator(&pool, "workflow-plan-o2").await;
    let system = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_ingest_executor::get_or_create_system_agent(&mut conn)
            .await
            .expect("the system agent")
    };
    assert!(fixture::register_system_agent(&pool, system).await);
    let api = Api::prod_shaped(&pool).await;
    // History first, as on a live instance: the system agent ingested (and so
    // was provisioned its personal group) before it was linked.
    let (unlinked, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-unlinked").await;
    api.ingest(
        &token(unlinked, WRITE_SCOPES),
        &small_extraction("acme-armed-history", 1),
    )
    .await;
    link_as_maintenance(&pool, system, o1)
        .await
        .expect("live-link the system agent to the first human");
    let first_server = mcp_server(&pool, 0xA1).await;
    let first_curator = stdio_agent(&pool, &first_server, 0xA1).await;
    link_as_maintenance(&pool, first_curator, o1)
        .await
        .expect("link a curator to the first human");
    let second_server = mcp_server(&pool, 0xB2).await;
    let second_curator = stdio_agent(&pool, &second_server, 0xB2).await;
    link_as_maintenance(&pool, second_curator, o2)
        .await
        .expect("link a curator to the second human");
    arm(&pool).await;

    // The first human publishes over REST, into its own group.
    api.ingest(
        &token(o1, WRITE_SCOPES),
        &small_extraction("acme-armed-human", 1),
    )
    .await;
    assert_eq!(plan_owners(&pool, "acme-armed-human").await, vec![og1]);

    // An unlinked curator over REST: OPL01, nothing written.
    let (s, b) = api
        .post(
            "/api/v1/workflows/ingest",
            &token(unlinked, WRITE_SCOPES),
            &small_extraction("acme-armed-unlinked", 1),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{b}");
    assert!(b.to_string().contains("OPL01"), "{b}");
    assert_eq!(workflows_named(&pool, "acme-armed-unlinked").await, 0);

    // The first human's curator: refused by the REST ingest; publishes over
    // stdio.
    let (s, b) = api
        .post(
            "/api/v1/workflows/ingest",
            &token(first_curator, WRITE_SCOPES),
            &small_extraction("acme-armed-curator-http", 1),
        )
        .await;
    assert_operated_refusal(s, &b, "a linked curator over REST");
    assert_eq!(workflows_named(&pool, "acme-armed-curator-http").await, 0);
    stdio_ingest(&first_server, &small_extraction("acme-armed-curator", 1))
        .await
        .expect("the first human's curator publishes over stdio");
    assert_eq!(plan_owners(&pool, "acme-armed-curator").await, vec![og1]);

    // It cannot be re-linked to the second human.
    assert_relink_refused(&pool, first_curator, o2).await;

    // The second human's curator: refused by the REST ingest as an operated
    // agent, OPL02 over stdio, nothing written on either.
    let (s, b) = api
        .post(
            "/api/v1/workflows/ingest",
            &token(second_curator, WRITE_SCOPES),
            &small_extraction("acme-armed-second-http", 1),
        )
        .await;
    assert_operated_refusal(s, &b, "a curator of another human over REST");
    assert_eq!(workflows_named(&pool, "acme-armed-second-http").await, 0);
    let refused = stdio_ingest(&second_server, &small_extraction("acme-armed-second", 1))
        .await
        .expect_err("a curator of another human must not publish through the system agent");
    assert!(refused.contains("OPL02"), "{refused}");
    assert_eq!(workflows_named(&pool, "acme-armed-second").await, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// (g) / (h): what an application-role DSN can do by itself
// ─────────────────────────────────────────────────────────────────────────────

/// (g) CHARACTERIZATION. The tenancy GUCs are not authenticated: an
/// `epigraph_app` session that names G in `epigraph.group_ids` itself reads a
/// G-private claim and its `executes` edge. Calibrated by the same session
/// reading nothing before it sets them.
#[sqlx::test(migrations = "../../migrations")]
async fn an_app_role_session_that_sets_the_group_guc_reads_the_private_plan(pool: PgPool) {
    let w = private_workflow(&pool, small_extraction("acme-guc-plan", 1)).await;
    let claim = w.claims[0];
    let (g, wf) = (w.g, w.workflow_id);
    async fn read(c: &mut sqlx::PgConnection, claim: Uuid, wf: Uuid) -> (i64, i64) {
        let claims: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&mut *c)
            .await
            .expect("read the claim");
        let edges: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM edges WHERE source_id = $1 AND relationship = 'executes'",
        )
        .bind(wf)
        .fetch_one(&mut *c)
        .await
        .expect("read the edges");
        (claims, edges)
    }
    let (before, after) = fixture::as_role(&pool, "epigraph_app", move |mut conn| async move {
        let before = read(&mut conn, claim, wf).await;
        sqlx::query("SELECT set_config('epigraph.group_ids', $1, false)")
            .bind(g.to_string())
            .execute(&mut *conn)
            .await
            .expect("self-set the group GUC");
        let after = read(&mut conn, claim, wf).await;
        sqlx::query("SELECT set_config('epigraph.group_ids', '', false)")
            .execute(&mut *conn)
            .await
            .expect("clear the GUC");
        (conn, (before, after))
    })
    .await;
    assert_eq!(
        before,
        (0, 0),
        "unstamped, the app role reads nothing of the plan"
    );
    assert_eq!(
        after,
        (1, i64::try_from(w.claims.len()).unwrap()),
        "self-stamped, the app role reads the claim and every executes edge"
    );
}

/// (h) CHARACTERIZATION. `workflows`' row security (migration 183) admits an
/// UPDATE of any row the session reads: the application role rewrites a
/// public workflow's truth and its recorded submitter, and the
/// workflow authority gate then honours the rewritten submitter (it reads the
/// row) and refuses the original one.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_rewrites_workflow_truth_and_submitter(pool: PgPool) {
    let (curator, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-curator").await;
    let (other, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-other").await;
    let api = Api::prod_shaped(&pool).await;
    let name = "acme-rewritten-plan";
    let wf = uuid_of(
        &api.ingest(&token(curator, WRITE_SCOPES), &small_extraction(name, 1))
            .await["workflow_id"],
    );
    let (s, b) = api
        .add_step(&token(other, WRITE_SCOPES), name, "other agent, before")
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "calibration: {b}");

    let (truth_rows, submitter_rows) =
        fixture::as_role(&pool, "epigraph_app", move |mut conn| async move {
            let t = sqlx::query("UPDATE workflows SET truth_value = 0.05 WHERE id = $1")
                .bind(wf)
                .execute(&mut *conn)
                .await
                .expect("the app role updates workflows.truth_value")
                .rows_affected();
            let s = sqlx::query(
                "UPDATE workflows SET metadata = jsonb_set(metadata, '{epigraph_submitted_by}', \
                 to_jsonb($2::text)) WHERE id = $1",
            )
            .bind(wf)
            .bind(other.to_string())
            .execute(&mut *conn)
            .await
            .expect("the app role rewrites the submitter")
            .rows_affected();
            (conn, (t, s))
        })
        .await;
    assert_eq!((truth_rows, submitter_rows), (1, 1));

    let (status, body) = api
        .get(
            &format!("/api/v1/workflows/{wf}"),
            &token(curator, READ_SCOPES),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["truth_value"].as_f64(), Some(0.05));
    assert_eq!(
        body["properties"]["epigraph_submitted_by"],
        json!(other.to_string())
    );
    let (s, b) = api
        .add_step(&token(other, WRITE_SCOPES), name, "other agent, after")
        .await;
    assert_eq!(
        s,
        StatusCode::OK,
        "the rewritten submitter passes the gate: {b}"
    );
    let (s, b) = api
        .add_step(&token(curator, WRITE_SCOPES), name, "curator, after")
        .await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "the original submitter is refused: {b}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The outcome report on a group-private plan
// ─────────────────────────────────────────────────────────────────────────────

async fn step_rows(pool: &PgPool, wf: Uuid, label: &str) -> Vec<Option<Uuid>> {
    sqlx::query_scalar(
        "SELECT step_claim_id FROM behavioral_executions WHERE workflow_id = $1 AND run_label = $2",
    )
    .bind(wf)
    .bind(label)
    .fetch_all(pool)
    .await
    .expect("behavioral rows")
}

async fn use_count(pool: &PgPool, wf: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COALESCE((metadata->>'use_count')::bigint, 0) FROM workflows WHERE id = $1",
    )
    .bind(wf)
    .fetch_one(pool)
    .await
    .expect("use_count")
}

/// CHARACTERIZATION (as changed by #632, the stamped outcome report, and by
/// the visibility gate). A hierarchical outcome report on a G-private plan
/// runs on ONE transaction stamped with the caller's viewer, and the REST
/// route needs `claims:write`:
///
/// * a non-member holding only `claims:read` is refused (403) and nothing
///   moves;
/// * a non-member holding `claims:write` reads none of the plan's `executes`
///   edges, so it is answered 404, as for an unknown id, and nothing moves;
/// * a member's report resolves the group's steps (the plan's level-2 claims);
/// * the MCP twin, as the stdio server's own agent (not a member of G), is
///   refused with the unknown-id error and writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn an_outcome_report_on_a_private_plan_resolves_steps_only_for_members(pool: PgPool) {
    let w = private_workflow(&pool, small_extraction("acme-outcome-plan", 2)).await;
    let steps: Vec<Value> = (0..2)
        .map(|i| json!({"step_index": i, "planned": format!("step {i}"), "actual": "done", "deviated": false}))
        .collect();
    let uri = format!("/api/v1/workflows/hierarchical/{}/outcome", w.workflow_id);
    let body = |label: &str| {
        json!({"success": true, "outcome_details": label, "quality": 0.9,
               "step_executions": steps, "goal_text": null})
    };
    // REST records no run label, so its rows are the NULL-label ones.
    let rest_rows = |pool: PgPool, wf: Uuid| async move {
        sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT step_claim_id FROM behavioral_executions \
              WHERE workflow_id = $1 AND run_label IS NULL ORDER BY step_claim_id NULLS FIRST",
        )
        .bind(wf)
        .fetch_all(&pool)
        .await
        .expect("rows")
    };
    let mut level2: Vec<Uuid> = sqlx::query_scalar(
        "SELECT c.id FROM edges e JOIN claims c ON c.id = e.target_id \
          WHERE e.source_id = $1 AND e.relationship = 'executes' \
            AND (c.properties->>'level')::int = 2",
    )
    .bind(w.workflow_id)
    .fetch_all(&pool)
    .await
    .expect("level-2 steps");
    level2.sort();
    assert_eq!(level2.len(), 2, "precondition: the plan's two steps");
    let start = use_count(&pool, w.workflow_id).await;

    // A non-member holding claims:read only: refused, nothing moves.
    let (status, resp) = w
        .api
        .post(&uri, &token(w.stranger, READ_SCOPES), &body("read only"))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert_eq!(use_count(&pool, w.workflow_id).await, start);
    assert!(rest_rows(pool.clone(), w.workflow_id).await.is_empty());

    // A non-member holding claims:write: it reads none of the plan, so the
    // workflow is "not found" to it, and nothing moves.
    let (status, resp) = w
        .api
        .post(&uri, &token(w.stranger, WRITE_SCOPES), &body("non-member"))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{resp}");
    assert_eq!(use_count(&pool, w.workflow_id).await, start);
    assert!(
        rest_rows(pool.clone(), w.workflow_id).await.is_empty(),
        "the non-member writes no row"
    );

    // A member: the group's steps resolve.
    let (status, resp) = w
        .api
        .post(&uri, &token(w.reader, WRITE_SCOPES), &body("member"))
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(use_count(&pool, w.workflow_id).await, start + 1);
    assert!(
        resp["unresolved_step_indices"]
            .as_array()
            .is_none_or(Vec::is_empty),
        "{resp}"
    );
    let mut rows = rest_rows(pool.clone(), w.workflow_id).await;
    rows.retain(Option::is_some);
    let mut resolved: Vec<Uuid> = rows.into_iter().flatten().collect();
    resolved.sort();
    assert_eq!(resolved, level2, "the member's rows name the plan's steps");

    // The MCP twin, as the stdio server's own agent (not a member of G).
    let server = mcp_server(&pool, 0x0C).await;
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&server, None)
        .await
        .expect("the stdio viewer");
    let r = epigraph_mcp::tools::workflow_hierarchical::report_hierarchical_outcome(
        &server,
        &viewer,
        epigraph_mcp::types::ReportHierarchicalOutcomeParams {
            workflow_id: w.workflow_id.to_string(),
            success: true,
            step_executions: serde_json::from_value(json!(steps)).expect("step executions"),
            outcome_details: "mcp report".to_string(),
            quality: Some(0.9),
            run_label: Some("mcp-report".to_string()),
            goal_text: Some("workflow-plan goal".to_string()),
        },
    )
    .await;
    let err = r.expect_err("a non-member's MCP report is refused");
    assert!(
        err.message.contains("no hierarchical workflow with id"),
        "refused as for an unknown id: {err:?}"
    );
    assert_eq!(use_count(&pool, w.workflow_id).await, start + 1);
    assert!(
        step_rows(&pool, w.workflow_id, "mcp-report")
            .await
            .is_empty(),
        "a non-member's MCP report writes no row"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// executes edge mutation
// ─────────────────────────────────────────────────────────────────────────────

/// An `executes` edge's `plan_index` and whether it is still in force
/// (harness read).
async fn executes_edge_state(pool: &PgPool, edge: Uuid) -> (Option<i64>, bool) {
    sqlx::query_as(
        "SELECT (properties->>'plan_index')::bigint, valid_to IS NULL FROM edges WHERE id = $1",
    )
    .bind(edge)
    .fetch_one(pool)
    .await
    .expect("edge state")
}

/// MCP `patch_edge` on the stdio transport, as the server's own agent.
async fn stdio_patch_edge(
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    edge: Uuid,
    properties: Value,
) -> Result<(), epigraph_mcp::errors::McpError> {
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, None).await?;
    let r = epigraph_mcp::tools::edge_mutation::do_patch_edge(
        server,
        &viewer,
        epigraph_mcp::types::PatchEdgeParams {
            edge_id: edge.to_string(),
            valid_to: None,
            properties: Some(properties),
        },
        None,
    )
    .await?;
    assert_ne!(r.is_error, Some(true), "{r:?}");
    Ok(())
}

/// MCP `delete_edge` (a soft retraction) on the stdio transport, as the
/// server's own agent.
async fn stdio_delete_edge(
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    edge: Uuid,
) -> Result<(), epigraph_mcp::errors::McpError> {
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, None).await?;
    let r = epigraph_mcp::tools::edge_mutation::do_delete_edge(
        server,
        &viewer,
        epigraph_mcp::types::DeleteEdgeParams {
            edge_id: edge.to_string(),
        },
        None,
    )
    .await?;
    assert_ne!(r.is_error, Some(true), "{r:?}");
    Ok(())
}

/// CHARACTERIZATION. Nothing in the edge mutation paths looks at
/// `relationship`: any principal that writes G rewrites an `executes` edge's
/// `plan_index` and retracts another, on REST with real tokens and on the
/// stdio MCP tools; a reader of G and a non-member are refused on both and
/// write nothing. "Writes G" is an `admin` or a plain `writer` row, and both
/// are exercised. A retracted edge stays in the edge listing with `valid_to`
/// set, so a reader that does not filter on `valid_to` still counts it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_group_writer_rewrites_plan_index_and_retracts_an_executes_edge(pool: PgPool) {
    let w = private_workflow(&pool, small_extraction("acme-mutable-plan", 4)).await;
    let reader_t = token(w.reader, WRITE_SCOPES);
    let edges = w.api.executes_edges(&reader_t, w.workflow_id).await;
    let id_at = |i: u64| {
        edges
            .iter()
            .find(|e| e["properties"]["plan_index"].as_u64() == Some(i))
            .map(|e| uuid_of(&e["id"]))
            .unwrap_or_else(|| panic!("no edge at plan_index {i}"))
    };
    // REST rewrites/retracts the first two; MCP the last two.
    let (first, second, third, fourth) = (id_at(0), id_at(1), id_at(2), id_at(3));
    let patch = json!({"properties": {"plan_index": 7}});

    // ── REST ──
    // A reader can see the edge but does not write G: 403. A non-member cannot
    // see it at all: 404.
    for (who, label, refused) in [
        (w.reader, "reader", StatusCode::FORBIDDEN),
        (w.stranger, "non-member", StatusCode::NOT_FOUND),
    ] {
        let (status, body) = w
            .api
            .call(
                Method::PATCH,
                &format!("/api/v1/edges/{first}"),
                &token(who, WRITE_SCOPES),
                Some(&patch),
            )
            .await;
        assert_eq!(
            status, refused,
            "{label} must not patch the executes edge: {body}"
        );
        let (status, body) = w
            .api
            .call(
                Method::DELETE,
                &format!("/api/v1/edges/{second}"),
                &token(who, WRITE_SCOPES),
                None,
            )
            .await;
        assert_eq!(
            status, refused,
            "{label} must not retract the executes edge: {body}"
        );
    }
    assert_eq!(executes_edge_state(&pool, first).await, (Some(0), true));
    assert_eq!(executes_edge_state(&pool, second).await, (Some(1), true));

    // G's creator (an `admin` row) patches; a member with a plain `writer`
    // row retracts.
    let (plain_writer, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-writer").await;
    add_member(&pool, w.g, plain_writer, "writer").await;
    let (status, body) = w
        .api
        .call(
            Method::PATCH,
            &format!("/api/v1/edges/{first}"),
            &token(w.writer, WRITE_SCOPES),
            Some(&patch),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "G's admin patches plan_index: {body}"
    );
    assert_eq!(body["properties"]["plan_index"], json!(7));
    let (status, body) = w
        .api
        .call(
            Method::DELETE,
            &format!("/api/v1/edges/{second}"),
            &token(plain_writer, WRITE_SCOPES),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "a plain writer of G retracts it: {body}"
    );

    let after = w.api.executes_edges(&reader_t, w.workflow_id).await;
    let indices: Vec<Option<u64>> = {
        let mut v: Vec<Option<u64>> = after
            .iter()
            .filter(|e| e["valid_to"].is_null())
            .map(|e| e["properties"]["plan_index"].as_u64())
            .collect();
        v.sort_unstable();
        v
    };
    assert!(
        indices.contains(&Some(7)) && !indices.contains(&Some(0)),
        "the in-force plan now has an index 7 and no index 0: {indices:?}"
    );
    let retracted = after
        .iter()
        .find(|e| uuid_of(&e["id"]) == second)
        .expect("the retracted edge is still listed");
    assert!(!retracted["valid_to"].is_null(), "and carries valid_to");

    // ── stdio MCP (`do_patch_edge`, `do_delete_edge`) ──
    // Each server acts as its own agent, as a container's `epigraph-mcp` does.
    let mcp_writer = mcp_server(&pool, 0xC3).await;
    let writer_agent = stdio_agent(&pool, &mcp_writer, 0xC3).await;
    add_member(&pool, w.g, writer_agent, "writer").await;
    let mcp_reader = mcp_server(&pool, 0xD4).await;
    let reader_agent = stdio_agent(&pool, &mcp_reader, 0xD4).await;
    add_member(&pool, w.g, reader_agent, "reader").await;
    let mcp_stranger = mcp_server(&pool, 0xE5).await;
    stdio_agent(&pool, &mcp_stranger, 0xE5).await;

    // A reader of G sees the edge, so its refusal is the named owner refusal;
    // a non-member does not, so its refusal is "not found". Neither writes.
    for (server, label, owner_refusal) in [
        (&mcp_reader, "MCP reader", true),
        (&mcp_stranger, "MCP non-member", false),
    ] {
        for (what, refusal) in [
            (
                "patch",
                stdio_patch_edge(server, third, json!({"plan_index": 9}))
                    .await
                    .err(),
            ),
            ("retract", stdio_delete_edge(server, fourth).await.err()),
        ] {
            let e = refusal.unwrap_or_else(|| panic!("{label} must not {what} the executes edge"));
            let not_owner = e.data.as_ref().map(|d| d["error"] == "not_owner");
            assert_eq!(
                not_owner == Some(true),
                owner_refusal,
                "{label}: refused as not_owner = {owner_refusal}: {e:?}"
            );
            assert_eq!(
                e.message.contains("not found"),
                !owner_refusal,
                "{label}: {e:?}"
            );
        }
    }
    assert_eq!(executes_edge_state(&pool, third).await, (Some(2), true));
    assert_eq!(executes_edge_state(&pool, fourth).await, (Some(3), true));

    stdio_patch_edge(&mcp_writer, third, json!({"plan_index": 9}))
        .await
        .expect("a plain writer of G patches plan_index over stdio");
    stdio_delete_edge(&mcp_writer, fourth)
        .await
        .expect("a plain writer of G retracts over stdio");
    assert_eq!(
        executes_edge_state(&pool, third).await,
        (Some(9), true),
        "the stdio patch rewrote plan_index and left the edge in force"
    );
    assert_eq!(
        executes_edge_state(&pool, fourth).await,
        (Some(3), false),
        "the stdio retraction set valid_to and kept the row"
    );
}
