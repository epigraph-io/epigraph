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
//! * CHARACTERIZATION tests ((e), (f)) record what the code does TODAY,
//!   including behaviour nobody would design. They are evidence for a
//!   decision, not an endorsement, and they say so where they pin a gap.
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
//!   `level`; an `add_step` edge carries `level` only. The plan includes the
//!   level-3 operation atoms: an ingest `executes` every one of them.
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
//!   second human never gains it. A linked curator itself holds no HTTP
//!   authority (operated agents are stdio-only), before or after the
//!   revocation.
//! * (f) Who can publish once operator binding is ARMED, with the ingest
//!   system agent live-linked to the first human: that human over REST; its
//!   linked curator over stdio only; an unlinked curator nowhere over REST
//!   (`OPL01`); and a curator of a SECOND human nowhere (`OPL02` over stdio,
//!   nothing written). A curator re-linked to the second human cannot be
//!   constructed, as in (e).
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
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(id)
    .bind(reader)
    .execute(pool)
    .await
    .expect("the reader row");
    id
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
    curator: Uuid,
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
        curator,
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

/// (b) An `add_step` edge carries `level` and NO `plan_index`, so a reader
/// that requires a contiguous `plan_index` sees one unindexed edge after it.
#[sqlx::test(migrations = "../../migrations")]
async fn an_add_step_executes_edge_carries_level_but_no_plan_index(pool: PgPool) {
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
    assert_eq!(
        added[0]["properties"],
        json!({"level": 2}),
        "the add_step edge is unindexed"
    );
    assert_eq!(
        after
            .iter()
            .filter(|e| e["properties"].get("plan_index").is_none())
            .count(),
        1
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
        epigraph_mcp::types::IngestWorkflowParams { extraction },
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
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
    }
}

/// MCP `add_step` as `agent` on the authenticated transport, which is where
/// `require_workflow_authority` runs its arms.
async fn mcp_add_step(
    pool: &PgPool,
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    agent: Uuid,
    canonical_name: &str,
    text: &str,
) -> Result<(), String> {
    let viewer = epigraph_db::Viewer::resolve(pool, agent)
        .await
        .expect("viewer");
    epigraph_mcp::tools::step_ops::add_step(
        server,
        &viewer,
        epigraph_mcp::tools::step_ops::AddStepParams {
            canonical_name: canonical_name.to_string(),
            step_text: text.to_string(),
            position: None,
        },
        Some(&auth_for(agent)),
    )
    .await
    .map(|_| ())
    .map_err(|e| e.message.to_string())
}

/// The REST refusal of an operated agent's token.
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
/// The curator ingests over REST while UNLINKED: a linked (operated) agent
/// holds no HTTP authority at all, which the test also pins. Once linked, its
/// first operator holds the operator arm over its workflow. Ending the
/// curator's acting link the documented way (revoking its writer row in the
/// operator group) leaves `operator_of_author` on the FIRST operator, so that
/// human keeps the operator arm, on REST and on MCP, the second human never
/// gets it, and the curator itself stays refused on HTTP.
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
    mcp_add_step(&pool, &server, o1, name, "first operator, mcp")
        .await
        .expect("MCP: the first operator keeps the operator arm");
    let refused = mcp_add_step(&pool, &server, o2, name, "second operator, mcp")
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
/// * NOT a curator linked to the first human over REST: an operated agent
///   holds no HTTP authority. Over stdio it publishes, into the first human's
///   group;
/// * NOT a curator linked to a SECOND human, on any transport: over stdio the
///   caller check refuses it `OPL02` (it must belong to the system agent's
///   human), and it writes nothing. This is the nearest shipped shape of "a
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

    // The first human's curator: no HTTP authority; publishes over stdio.
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

    // The second human's curator: OPL02 over stdio, nothing written.
    let refused = stdio_ingest(&second_server, &small_extraction("acme-armed-second", 1))
        .await
        .expect_err("a curator of another human must not publish through the system agent");
    assert!(refused.contains("OPL02"), "{refused}");
    assert_eq!(workflows_named(&pool, "acme-armed-second").await, 0);
}
