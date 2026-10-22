//! `GET /api/v1/workflows/:id/plan`: the frozen plan of ONE workflow
//! generation, read as the caller, on the production pool shape.
//!
//! A pinned-workflow resolver holds a digest of the plan it published and
//! recomputes every id itself. This read gives it what it needs to do that and
//! nothing it must trust:
//!
//! * the generation's `executes` targets at every level, in the order their
//!   edges' `plan_index` values give, with content, stored hash, tenancy and
//!   the seed-aware `content_hash_ok` flag;
//! * integrity counts for everything that makes that order unusable: hidden
//!   targets, unindexed edges, gaps, duplicates and retracted edges;
//! * a `wfd1` digest echo, ONLY when the stored indices are exactly `0..n-1`
//!   and nothing is hidden or retracted. It is informational: the resolver's
//!   own digest decides.
//!
//! `plan_index` is a mutable edge property. Any writer of the plan's group can
//! rewrite it with `patch_edge` or retract the edge (pinned by the read
//! contract's edge-mutation characterization). So the read never repairs an
//! order: a reordered plan is reported in its new order with the digest of that
//! order, which no longer equals the published digest.
//!
//! Every connection the router uses is `epigraph_app`
//! (`ScopedPool::connect_downgraded_for_tests`, `AppState::with_scoped_pool`),
//! and every request carries a real JWT. The harness superuser only seeds,
//! inspects and, in the tamper cases, writes what no API route can.
//!
//! The workflows are made group-private by ingesting them public and moving
//! their claims with `PrivatizationRepository::restrict_claims_conn`; the
//! tenancy trigger re-meets the `executes` edges, which the fixture asserts.
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::repos::privatization::PrivatizationRepository;
use epigraph_db::{GroupRepository, ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// Frozen vectors computed outside these crates. Compared, never regenerated.
const VECTORS: &str = include_str!("../../epigraph-ingest/tests/fixtures/wfd1-vectors.json");

const WRITE_SCOPES: &[&str] = &["claims:read", "claims:write", "edges:write"];
const READ_SCOPES: &[&str] = &["claims:read"];

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("the vectors file parses")
}

fn extraction() -> Value {
    vectors()["ingest"]["extraction"].clone()
}

fn vector_plan() -> Vec<Value> {
    vectors()["ingest"]["plan"].as_array().unwrap().clone()
}

fn uuid_of(v: &Value) -> Uuid {
    v.as_str()
        .unwrap_or_else(|| panic!("expected a uuid string, got {v}"))
        .parse()
        .unwrap_or_else(|e| panic!("{v} is not a uuid: {e}"))
}

fn token(agent: Uuid, scopes: &[&str]) -> String {
    common::mint_token_with_agent(scopes, agent)
}

// ─────────────────────────────────────────────────────────────────────────────
// The production-shaped API
// ─────────────────────────────────────────────────────────────────────────────

struct Api {
    router: axum::Router,
}

impl Api {
    async fn prod_shaped(pool: &PgPool) -> Self {
        let bypassrls: bool =
            sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
                .fetch_one(pool)
                .await
                .expect("read epigraph_app");
        assert!(
            !bypassrls,
            "epigraph_app holds BYPASSRLS: every arm is vacuous"
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

    async fn ingest(&self, token: &str, extraction: &Value) -> Uuid {
        let (status, body) = self
            .post("/api/v1/workflows/ingest", token, extraction)
            .await;
        assert_eq!(status, StatusCode::OK, "ingest: {body}");
        uuid_of(&body["workflow_id"])
    }

    async fn plan_status(&self, token: &str, workflow_id: Uuid) -> (StatusCode, Value) {
        self.get(&format!("/api/v1/workflows/{workflow_id}/plan"), token)
            .await
    }

    /// `GET /api/v1/workflows/:id/plan`, insisting on 200.
    async fn plan(&self, token: &str, workflow_id: Uuid) -> Value {
        let (status, body) = self.plan_status(token, workflow_id).await;
        assert_eq!(status, StatusCode::OK, "GET plan: {body}");
        body
    }

    /// `PATCH /api/v1/edges/:id` with a properties merge, insisting on 200.
    async fn patch_edge(&self, token: &str, edge: Uuid, properties: Value) {
        let (status, body) = self
            .call(
                Method::PATCH,
                &format!("/api/v1/edges/{edge}"),
                token,
                Some(&json!({"properties": properties})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "patch edge {edge}: {body}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixture
// ─────────────────────────────────────────────────────────────────────────────

/// The workflow's `executes` edges as `(edge id, target claim, plan_index)`
/// in `plan_index` order (harness read).
async fn executes_edges(pool: &PgPool, workflow_id: Uuid) -> Vec<(Uuid, Uuid, i64)> {
    sqlx::query_as(
        "SELECT id, target_id, (properties->>'plan_index')::bigint FROM edges \
          WHERE source_id = $1 AND relationship = 'executes' \
            AND properties ? 'plan_index' \
          ORDER BY (properties->>'plan_index')::bigint",
    )
    .bind(workflow_id)
    .fetch_all(pool)
    .await
    .expect("executes edges")
}

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

/// A `team` group whose creator (`admin`) is `writer`.
async fn team_group(pool: &PgPool, writer: Uuid, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    let public_key = blake3::hash(id.as_bytes()).as_bytes().to_vec();
    GroupRepository::create_with_admin(
        pool,
        id,
        Some(label),
        &format!("did:epigraph:test:workflow-plan:{id}"),
        &public_key,
        None,
        writer,
    )
    .await
    .expect("the group");
    id
}

/// Move `claims` to `('group', g)` and check the `executes` edges followed.
async fn restrict(pool: &PgPool, workflow_id: Uuid, claims: &[Uuid], g: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    let moved = PrivatizationRepository::restrict_claims_conn(&mut conn, claims, g)
        .await
        .expect("restrict");
    assert_eq!(moved.len(), claims.len(), "every claim moved");
    let off: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND relationship = 'executes' \
            AND target_id = ANY($2) AND NOT (visibility = 'group' AND owner_group_id = $3)",
    )
    .bind(workflow_id)
    .bind(claims)
    .bind(g)
    .fetch_one(pool)
    .await
    .expect("edge tenancy");
    assert_eq!(
        off, 0,
        "the executes edges follow their claims into ('group', G)"
    );
}

/// The vectors' workflow, ingested by `curator` and restricted to G, whose
/// `admin` is `writer` and which `reader` reads; `stranger` is in no group.
struct Private {
    api: Api,
    workflow_id: Uuid,
    g: Uuid,
    curator: Uuid,
    writer: Uuid,
    reader: Uuid,
    stranger: Uuid,
}

async fn private_workflow(pool: &PgPool) -> Private {
    let (curator, _) = fixture::seed_agent_with_group(pool, "workflow-plan-curator").await;
    let (writer, _) = fixture::seed_agent_with_group(pool, "workflow-plan-writer").await;
    let (reader, _) = fixture::seed_agent_with_group(pool, "workflow-plan-reader").await;
    let (stranger, _) = fixture::seed_agent_with_group(pool, "workflow-plan-stranger").await;
    let g = team_group(pool, writer, "workflow-plan role group").await;
    add_member(pool, g, reader, "reader").await;
    let api = Api::prod_shaped(pool).await;
    let workflow_id = api
        .ingest(&token(curator, WRITE_SCOPES), &extraction())
        .await;
    let claims: Vec<Uuid> = vector_plan()
        .iter()
        .map(|i| uuid_of(&i["claim_id"]))
        .collect();
    restrict(pool, workflow_id, &claims, g).await;
    Private {
        api,
        workflow_id,
        g,
        curator,
        writer,
        reader,
        stranger,
    }
}

fn flags(p: &Value) -> [(&'static str, u64); 5] {
    let f = |k: &str| {
        p[k].as_u64()
            .unwrap_or_else(|| panic!("{k} is a non-negative integer in {p}"))
    };
    [
        ("hidden_count", f("hidden_count")),
        ("unindexed_edges", f("unindexed_edges")),
        ("plan_index_gaps", f("plan_index_gaps")),
        ("duplicate_plan_indices", f("duplicate_plan_indices")),
        ("retracted_edges", f("retracted_edges")),
    ]
}

fn clean() -> [(&'static str, u64); 5] {
    [
        ("hidden_count", 0),
        ("unindexed_edges", 0),
        ("plan_index_gaps", 0),
        ("duplicate_plan_indices", 0),
        ("retracted_edges", 0),
    ]
}

fn item_ids(p: &Value) -> Vec<Uuid> {
    p["items"]
        .as_array()
        .unwrap_or_else(|| panic!("items array in {p}"))
        .iter()
        .map(|i| uuid_of(&i["claim_id"]))
        .collect()
}

/// Every item equals its vector: index, level, id, content and stored hash.
fn assert_items_are_the_vectors(p: &Value) {
    let items = p["items"].as_array().expect("items");
    let want = vector_plan();
    assert_eq!(items.len(), want.len(), "one item per executes target");
    for (got, want) in items.iter().zip(&want) {
        for key in ["plan_index", "level", "claim_id", "content", "content_hash"] {
            assert_eq!(got[key], want[key], "{key} of item {}", want["plan_index"]);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The read
// ─────────────────────────────────────────────────────────────────────────────

/// A reader of G (holding `claims:read` only) reads the whole frozen plan of a
/// group-private workflow: every level, the vectors' ids, hashes and order,
/// the per-item tenancy, the row's fields, and a digest echo equal to the
/// independently computed `wfd1`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reader_reads_the_frozen_plan_and_its_digest_equals_the_vectors(pool: PgPool) {
    let w = private_workflow(&pool).await;
    let v = vectors();
    let p = w
        .api
        .plan(&token(w.reader, READ_SCOPES), w.workflow_id)
        .await;

    assert_items_are_the_vectors(&p);
    assert_eq!(flags(&p), clean());
    assert_eq!(p["digest_echo"], v["ingest"]["wfd1"]);
    for item in p["items"].as_array().unwrap() {
        assert_eq!(item["visibility"], json!("group"), "{item}");
        assert_eq!(item["owner_group_id"], json!(w.g.to_string()), "{item}");
        assert_eq!(item["content_hash_ok"], json!(true), "{item}");
        assert_eq!(item["is_current"], json!(true), "{item}");
        assert_eq!(item["heads_diverged"], json!(false), "{item}");
        assert!(item["truth_value"].is_number(), "{item}");
    }
    assert_eq!(p["workflow_id"], v["ingest"]["workflow_id"]);
    assert_eq!(p["canonical_name"], v["ingest"]["canonical_name"]);
    assert_eq!(p["generation"], json!(0));
    assert_eq!(p["goal"], v["ingest"]["extraction"]["source"]["goal"]);
    assert_eq!(p["parent_id"], Value::Null);
    assert_eq!(p["truth_value"], json!(1.0));
    assert_eq!(p["submitter"], json!(w.curator.to_string()));
    let phase = &p["items"][2]["phase"];
    assert_eq!(phase, &json!("Collect"), "a step carries its phase title");
}

/// Tenancy is reported, not assumed: the same plan left public reads as
/// public items, each with the owner group its row actually carries (the
/// ingest system agent's, not G), and the same digest.
#[sqlx::test(migrations = "../../migrations")]
async fn a_public_plan_reports_public_items_and_their_stored_owner(pool: PgPool) {
    let (curator, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-curator").await;
    let (other, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-other").await;
    let api = Api::prod_shaped(&pool).await;
    let wf = api
        .ingest(&token(curator, WRITE_SCOPES), &extraction())
        .await;
    let p = api.plan(&token(other, READ_SCOPES), wf).await;
    assert_items_are_the_vectors(&p);
    assert_eq!(flags(&p), clean());
    assert_eq!(p["digest_echo"], vectors()["ingest"]["wfd1"]);
    for item in p["items"].as_array().unwrap() {
        let stored: (String, Uuid) =
            sqlx::query_as("SELECT visibility::text, owner_group_id FROM claims WHERE id = $1")
                .bind(uuid_of(&item["claim_id"]))
                .fetch_one(&pool)
                .await
                .expect("harness: stored tenancy");
        assert_eq!(stored.0, "public", "calibration: the ingest is public");
        assert_eq!(item["visibility"], json!("public"), "{item}");
        assert_eq!(
            item["owner_group_id"],
            json!(stored.1.to_string()),
            "{item}"
        );
    }
}

/// A non-member sees no `executes` edge of a G-private plan, so it has no plan
/// to read: 404, with no claim id and no content in the body. (The exact
/// number of hidden items is not countable on an RLS-bound connection: each
/// `executes` edge carries its target's tenancy, so the edges are as hidden as
/// the claims.) Calibrated by the reader reading the same plan.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_gets_404_and_nothing_of_the_plan(pool: PgPool) {
    let w = private_workflow(&pool).await;
    let (status, body) = w
        .api
        .plan_status(&token(w.stranger, READ_SCOPES), w.workflow_id)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    // A typed answer, not a missing route (which 404s with an empty body): a
    // caller can tell "this plan is hidden from you" from "no such route".
    assert_eq!(body["error"], json!("NotFound"), "{body}");
    assert_eq!(body["details"]["entity"], json!("workflow plan"), "{body}");
    let text = body.to_string();
    for item in vector_plan() {
        assert!(
            !text.contains(item["claim_id"].as_str().unwrap()),
            "no claim id: {text}"
        );
        assert!(
            !text.contains(item["content"].as_str().unwrap()),
            "no content: {text}"
        );
    }
    let p = w
        .api
        .plan(&token(w.reader, READ_SCOPES), w.workflow_id)
        .await;
    assert_eq!(item_ids(&p).len(), vector_plan().len(), "calibration");
}

/// An id that names no workflow is 404, and it is not the absence of the
/// route that answers it: the same caller reads an existing plan.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_workflow_is_404(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-reader").await;
    let api = Api::prod_shaped(&pool).await;
    let t = token(agent, WRITE_SCOPES);
    let wf = api.ingest(&t, &extraction()).await;
    let (status, body) = api.plan_status(&t, Uuid::new_v4()).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(item_ids(&api.plan(&t, wf).await).len(), vector_plan().len());
}

/// The read is `claims:read`: a token without it is refused, and it is not the
/// absence of the route that refuses it (the same agent with `claims:read`
/// reads the plan).
#[sqlx::test(migrations = "../../migrations")]
async fn a_token_without_claims_read_is_refused(pool: PgPool) {
    let w = private_workflow(&pool).await;
    let (status, body) = w
        .api
        .plan_status(&token(w.reader, &["edges:write"]), w.workflow_id)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    w.api
        .plan(&token(w.reader, READ_SCOPES), w.workflow_id)
        .await;
}

/// An item moved to a second group G2 is invisible to a G-only reader, edge
/// and claim alike, so it is not countable. What the read does report is the
/// hole it leaves in the index sequence, and it withholds the digest echo.
#[sqlx::test(migrations = "../../migrations")]
async fn an_item_in_another_group_leaves_a_gap_and_no_digest(pool: PgPool) {
    let w = private_workflow(&pool).await;
    let (other_admin, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-other").await;
    let g2 = team_group(&pool, other_admin, "workflow-plan second group").await;
    let moved = uuid_of(&vector_plan()[4]["claim_id"]);
    restrict(&pool, w.workflow_id, &[moved], g2).await;

    let p = w
        .api
        .plan(&token(w.reader, READ_SCOPES), w.workflow_id)
        .await;
    assert!(!item_ids(&p).contains(&moved));
    assert_eq!(
        p["items"].as_array().unwrap().len(),
        vector_plan().len() - 1
    );
    assert_eq!(p["plan_index_gaps"], json!(1));
    assert_eq!(p["digest_echo"], Value::Null);
    assert!(
        !p.to_string().contains(&moved.to_string()),
        "no id of the moved item"
    );
}

/// The limit of what the read can say. When the LAST item moves to G2, its
/// edge goes with it, nothing is left behind in the index sequence, and every
/// count reads 0: the read returns a non-null echo of the SHORTENED plan. Only
/// a comparison with the digest the publisher pinned (here, the vectors')
/// detects it. Nothing of the moved item is named.
#[sqlx::test(migrations = "../../migrations")]
async fn a_hidden_tail_is_detectable_only_against_the_pinned_digest(pool: PgPool) {
    let w = private_workflow(&pool).await;
    let (other_admin, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-other").await;
    let g2 = team_group(&pool, other_admin, "workflow-plan second group").await;
    let tail = vector_plan()[8].clone();
    let moved = uuid_of(&tail["claim_id"]);
    restrict(&pool, w.workflow_id, &[moved], g2).await;

    let p = w
        .api
        .plan(&token(w.reader, READ_SCOPES), w.workflow_id)
        .await;
    assert_eq!(flags(&p), clean(), "{p}");
    assert_eq!(
        p["items"].as_array().unwrap().len(),
        vector_plan().len() - 1
    );
    let echo = p["digest_echo"]
        .as_str()
        .unwrap_or_else(|| panic!("a clean-looking plan echoes: {p}"));
    assert_ne!(echo, vectors()["ingest"]["wfd1"].as_str().unwrap());
    let text = p.to_string();
    assert!(
        !text.contains(&moved.to_string()),
        "no id of the moved item"
    );
    assert!(
        !text.contains(tail["content"].as_str().unwrap()),
        "no content of the moved item"
    );
}

/// An `executes` edge the caller CAN see whose target it cannot read is a
/// hidden item: counted, never named. The shape is written by the harness
/// (the tenancy trigger keeps an edge with its target, so no API path makes
/// it); it is what a policy or trigger regression would produce.
#[sqlx::test(migrations = "../../migrations")]
async fn a_visible_edge_to_an_unreadable_claim_is_counted_and_never_named(pool: PgPool) {
    let w = private_workflow(&pool).await;
    let (other_admin, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-other").await;
    let g2 = team_group(&pool, other_admin, "workflow-plan second group").await;
    let hidden = vector_plan()[5].clone();
    let hidden_id = uuid_of(&hidden["claim_id"]);
    restrict(&pool, w.workflow_id, &[hidden_id], g2).await;
    let mut conn = pool.acquire().await.expect("acquire");
    sqlx::query("SET session_replication_role = replica")
        .execute(&mut *conn)
        .await
        .expect("harness: skip triggers");
    let n = sqlx::query(
        "UPDATE edges SET owner_group_id = $3 \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'executes'",
    )
    .bind(w.workflow_id)
    .bind(hidden_id)
    .bind(w.g)
    .execute(&mut *conn)
    .await
    .expect("harness: keep the edge in G")
    .rows_affected();
    assert_eq!(n, 1);
    sqlx::query("SET session_replication_role = origin")
        .execute(&mut *conn)
        .await
        .expect("restore");
    drop(conn);

    let p = w
        .api
        .plan(&token(w.reader, READ_SCOPES), w.workflow_id)
        .await;
    assert_eq!(p["hidden_count"], json!(1), "{p}");
    assert_eq!(p["digest_echo"], Value::Null);
    let text = p.to_string();
    assert!(
        !text.contains(&hidden_id.to_string()),
        "no hidden id: {text}"
    );
    assert!(
        !text.contains(hidden["content"].as_str().unwrap()),
        "no hidden content"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// add_step and plan_index
// ─────────────────────────────────────────────────────────────────────────────

/// The vectors' three level-2 steps, in plan order: 1.1, 1.2, 2.1.
fn vector_steps() -> [Uuid; 3] {
    let plan = vector_plan();
    [2, 5, 7].map(|i| uuid_of(&plan[i]["claim_id"]))
}

/// The workflow-ingest system agent: the author of every claim the ingest
/// wrote (harness read of the vectors' thesis row).
async fn ingest_system_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(uuid_of(&vector_plan()[0]["claim_id"]))
        .fetch_one(pool)
        .await
        .expect("the thesis row's author")
}

/// The two step orders `add_step` must keep equal (harness reads): the
/// `step_follows` chain `workflow_steps::ordered_steps` walks, and the
/// workflow's live level-2 `executes` targets by their integer `plan_index`.
async fn chain_and_plan_steps(pool: &PgPool, workflow_id: Uuid) -> (Vec<Uuid>, Vec<Uuid>) {
    let mut conn = pool.acquire().await.expect("acquire");
    let chain = epigraph_ingest_executor::workflow_steps::ordered_steps(&mut conn, workflow_id)
        .await
        .expect("ordered_steps");
    let by_index: Vec<Uuid> = sqlx::query_scalar(
        "SELECT e.target_id FROM edges e JOIN claims c ON c.id = e.target_id \
          WHERE e.source_id = $1 AND e.relationship = 'executes' AND e.valid_to IS NULL \
            AND (c.properties->>'level')::int = 2 \
            AND jsonb_typeof(e.properties->'plan_index') = 'number' \
          ORDER BY (e.properties->>'plan_index')::bigint",
    )
    .bind(workflow_id)
    .fetch_all(pool)
    .await
    .expect("level-2 targets by plan_index");
    (chain, by_index)
}

/// `POST /api/v1/workflows/steps`, insisting on 200.
async fn add_step(api: &Api, t: &str, text: &str, position: Option<u32>) -> Value {
    let mut req = json!({"canonical_name": "acme-frozen-plan", "step_text": text});
    if let Some(p) = position {
        req["position"] = json!(p);
    }
    let (status, body) = api.post("/api/v1/workflows/steps", t, &req).await;
    assert_eq!(status, StatusCode::OK, "add_step {text:?}: {body}");
    body
}

/// The plan's items are the vectors with `added` spliced in at index `at`:
/// every vector item keeps its id, level, content and hash, and its index
/// moves up by one exactly when it sat at or after `at`.
fn assert_vectors_with_one_insert(p: &Value, at: u64, added: Uuid) {
    let items = p["items"].as_array().expect("items");
    let want = vector_plan();
    assert_eq!(items.len(), want.len() + 1, "one more item: {p}");
    let inserted = &items[at as usize];
    assert_eq!(uuid_of(&inserted["claim_id"]), added, "{p}");
    assert_eq!(inserted["plan_index"], json!(at));
    assert_eq!(inserted["level"], json!(2));
    let rest: Vec<&Value> = items
        .iter()
        .filter(|i| uuid_of(&i["claim_id"]) != added)
        .collect();
    for (got, want) in rest.iter().zip(&want) {
        let old = want["plan_index"].as_u64().unwrap();
        let moved = if old >= at { old + 1 } else { old };
        assert_eq!(got["plan_index"], json!(moved), "vector item {old}: {p}");
        for key in ["level", "claim_id", "content", "content_hash"] {
            assert_eq!(got[key], want[key], "{key} of vector item {old}");
        }
    }
}

/// An appended step is indexed one past the plan's last item, on the
/// production shape (a public plan, whose `executes` edges are world-owned
/// and which no application session may update): appending moves no existing
/// index. The plan reads clean, the step is an item, both step orders agree,
/// and the echo is the digest of the new plan, not the published one.
#[sqlx::test(migrations = "../../migrations")]
async fn an_appended_step_is_indexed_after_the_last_item(pool: PgPool) {
    let (curator, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-curator").await;
    let api = Api::prod_shaped(&pool).await;
    let t = token(curator, WRITE_SCOPES);
    let wf = api.ingest(&t, &extraction()).await;
    let body = add_step(&api, &t, "ACME-123456 appended step", None).await;
    let added = uuid_of(&body["step_claim_id"]);

    let p = api.plan(&t, wf).await;
    assert_eq!(flags(&p), clean(), "{p}");
    assert_eq!(body["plan_index"], json!(9), "{body}");
    assert_vectors_with_one_insert(&p, 9, added);
    assert!(p["digest_echo"].is_string(), "{p}");
    assert_ne!(p["digest_echo"], vectors()["ingest"]["wfd1"]);
    let [s11, s12, s21] = vector_steps();
    let (chain, by_index) = chain_and_plan_steps(&pool, wf).await;
    assert_eq!(chain, vec![s11, s12, s21, added]);
    assert_eq!(
        by_index, chain,
        "plan_index order equals step_follows order"
    );

    // An idempotent re-add reports the index the step already has.
    let again = add_step(&api, &t, "ACME-123456 appended step", None).await;
    assert_eq!(again["already_present"], json!(true), "{again}");
    assert_eq!(uuid_of(&again["step_claim_id"]), added);
    assert_eq!(again["plan_index"], json!(9), "{again}");
}

/// The tenancy and properties of `target`'s `executes` edge from
/// `workflow_id` (harness read).
async fn executes_edge_of(pool: &PgPool, workflow_id: Uuid, target: Uuid) -> (String, Uuid, Value) {
    sqlx::query_as(
        "SELECT visibility::text, owner_group_id, properties FROM edges \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'executes'",
    )
    .bind(workflow_id)
    .bind(target)
    .fetch_one(pool)
    .await
    .expect("harness: the added step's executes edge")
}

/// A step added to a group-private plan is a public claim, and its
/// `executes` edge is public and world-owned, so every reader sees that edge
/// and its properties. An index on it derived from the plan's group-private
/// edges would tell a non-member the private plan's size (an append) or a
/// private step's position (an insert). So no step added to a plan with a
/// non-public `executes` edge is indexed, even when the workflow-ingest stamp
/// is a writer of the group and could see and move every one of them.
///
/// A non-member sees the one public edge as unindexed: no item, no index, no
/// gap that counts the hidden items. A member reads the published items
/// unchanged, with no duplicate and no gap.
#[sqlx::test(migrations = "../../migrations")]
async fn a_step_added_to_a_group_plan_carries_no_index_a_non_member_could_read(pool: PgPool) {
    let w = private_workflow(&pool).await;
    // The stamp sees (and writes) every private edge: the index would be
    // derivable, so the test covers the derivation, not a blind stamp.
    let system = ingest_system_agent(&pool).await;
    add_member(&pool, w.g, system, "writer").await;
    let curator = token(w.curator, WRITE_SCOPES);
    let reader = token(w.reader, READ_SCOPES);
    let stranger = token(w.stranger, READ_SCOPES);
    let [s11, s12, s21] = vector_steps();

    let body = add_step(&w.api, &curator, "ACME-123456 appended step", None).await;
    let appended = uuid_of(&body["step_claim_id"]);
    assert_eq!(body.get("plan_index"), Some(&Value::Null), "{body}");
    let (visibility, owner, properties) = executes_edge_of(&pool, w.workflow_id, appended).await;
    assert_eq!(
        (visibility.as_str(), owner),
        ("public", Uuid::nil()),
        "calibration: every reader sees the added step's edge"
    );
    assert_eq!(properties, json!({"level": 2}), "no plan_index on it");

    let (status, p) = w.api.plan_status(&stranger, w.workflow_id).await;
    assert_eq!(status, StatusCode::OK, "{p}");
    assert_eq!(item_ids(&p), Vec::<Uuid>::new(), "{p}");
    assert_eq!(p["unindexed_edges"], json!(1), "{p}");
    assert_eq!(
        p["plan_index_gaps"],
        json!(0),
        "no count of hidden items: {p}"
    );

    let p = w.api.plan(&reader, w.workflow_id).await;
    assert_items_are_the_vectors(&p);
    assert_eq!(p["unindexed_edges"], json!(1), "{p}");
    assert_eq!(p["duplicate_plan_indices"], json!(0), "{p}");
    assert_eq!(p["plan_index_gaps"], json!(0), "{p}");

    // A middle insert: same rule, and nothing the members read moves.
    let body = add_step(&w.api, &curator, "ACME-123456 inserted step", Some(1)).await;
    let mid = uuid_of(&body["step_claim_id"]);
    assert_eq!(body.get("plan_index"), Some(&Value::Null), "{body}");
    assert_eq!(
        executes_edge_of(&pool, w.workflow_id, mid).await.2,
        json!({"level": 2})
    );
    let (_, p) = w.api.plan_status(&stranger, w.workflow_id).await;
    assert_eq!(item_ids(&p), Vec::<Uuid>::new(), "{p}");
    assert_eq!(p["plan_index_gaps"], json!(0), "{p}");
    let p = w.api.plan(&reader, w.workflow_id).await;
    assert_items_are_the_vectors(&p);
    assert_eq!(p["unindexed_edges"], json!(2), "{p}");
    let (chain, _) = chain_and_plan_steps(&pool, w.workflow_id).await;
    assert_eq!(
        chain,
        vec![s11, mid, s12, s21, appended],
        "the chain was rewired"
    );
}

/// A retracted `executes` edge is not a plan item for any reader, so it takes
/// no part in where an appended step goes: retracting the last item and then
/// appending gives the new step the retracted item's index, and the items
/// read with no gap and no duplicate.
#[sqlx::test(migrations = "../../migrations")]
async fn an_append_after_a_retracted_last_item_leaves_no_gap(pool: PgPool) {
    let (curator, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-curator").await;
    let api = Api::prod_shaped(&pool).await;
    let t = token(curator, WRITE_SCOPES);
    let wf = api.ingest(&t, &extraction()).await;
    let edges = executes_edges(&pool, wf).await;
    let (last_edge, last_target, last_index) = *edges.last().expect("edges");
    assert_eq!(last_index, 8, "calibration: the vectors' last item");
    // World-owned: only a privileged session retracts it (harness write).
    sqlx::query("UPDATE edges SET valid_to = now() WHERE id = $1")
        .bind(last_edge)
        .execute(&pool)
        .await
        .expect("harness: retract the last executes edge");

    let body = add_step(&api, &t, "ACME-123456 appended step", None).await;
    let added = uuid_of(&body["step_claim_id"]);
    assert_eq!(body["plan_index"], json!(8), "{body}");
    let p = api.plan(&t, wf).await;
    assert_eq!(p["retracted_edges"], json!(1), "{p}");
    assert_eq!(p["plan_index_gaps"], json!(0), "{p}");
    assert_eq!(p["duplicate_plan_indices"], json!(0), "{p}");
    assert_eq!(p["unindexed_edges"], json!(0), "{p}");
    let ids = item_ids(&p);
    assert_eq!(ids.len(), 9, "{p}");
    assert_eq!(ids[8], added);
    assert!(!ids.contains(&last_target));
}

/// How many claims hold exactly `content` (harness read).
async fn claims_with_content(pool: &PgPool, content: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .expect("harness: count")
}

/// `add_step` locks the `workflows` row before it reads the plan, so a
/// concurrent `add_step` on the same workflow waits for it and cannot take
/// the same next `plan_index`. Here a transaction holds that row lock and the
/// call, with a short `lock_timeout`, fails on it with nothing written; once
/// the lock is released the same call goes through.
#[sqlx::test(migrations = "../../migrations")]
async fn add_step_waits_for_the_workflow_row_lock(pool: PgPool) {
    let (curator, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-curator").await;
    let api = Api::prod_shaped(&pool).await;
    let t = token(curator, WRITE_SCOPES);
    let wf = api.ingest(&t, &extraction()).await;
    let text = "ACME-123456 concurrent step";

    let mut holder = pool.begin().await.expect("holder");
    sqlx::query("SELECT id FROM workflows WHERE id = $1 FOR UPDATE")
        .bind(wf)
        .execute(&mut *holder)
        .await
        .expect("hold the workflow row");

    let mut conn = pool.acquire().await.expect("acquire");
    sqlx::query("SET lock_timeout = '200ms'")
        .execute(&mut *conn)
        .await
        .expect("lock_timeout");
    let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
    let r =
        epigraph_ingest_executor::workflow_steps::add_step(&mut tx, "acme-frozen-plan", text, None)
            .await;
    let code = match &r {
        Err(epigraph_ingest_executor::workflow_steps::StepOpError::Db(e)) => e
            .as_database_error()
            .and_then(|d| d.code())
            .map(|c| c.into_owned()),
        _ => None,
    };
    assert_eq!(code.as_deref(), Some("55P03"), "lock_not_available: {r:?}");
    tx.rollback().await.expect("rollback");
    assert_eq!(
        claims_with_content(&pool, text).await,
        0,
        "nothing was written"
    );

    holder.rollback().await.expect("release");
    let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
    let r =
        epigraph_ingest_executor::workflow_steps::add_step(&mut tx, "acme-frozen-plan", text, None)
            .await
            .expect("calibration: the same call once the lock is released");
    tx.commit().await.expect("commit");
    assert_eq!(r.plan_index, Some(9));
    assert_eq!(claims_with_content(&pool, text).await, 1);
}

/// A middle insert into a public plan cannot renumber it: the `executes`
/// edges past the insertion point are world-owned and no application session
/// may update them. The chain is rewired as before, no existing index moves,
/// the new edge is left unindexed (so the read flags the plan as mutated in
/// place) and the response says so with a null `plan_index`, rather than
/// writing an index that collides with the step it precedes.
#[sqlx::test(migrations = "../../migrations")]
async fn a_middle_insert_into_a_public_plan_is_left_unindexed_and_says_so(pool: PgPool) {
    let (curator, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-curator").await;
    let api = Api::prod_shaped(&pool).await;
    let t = token(curator, WRITE_SCOPES);
    let wf = api.ingest(&t, &extraction()).await;
    let body = add_step(&api, &t, "ACME-123456 inserted step", Some(1)).await;
    let mid = uuid_of(&body["step_claim_id"]);
    assert_eq!(
        body.get("plan_index"),
        Some(&Value::Null),
        "the response names the missing index: {body}"
    );

    let p = api.plan(&t, wf).await;
    assert_eq!(p["unindexed_edges"], json!(1), "{p}");
    assert_eq!(p["duplicate_plan_indices"], json!(0), "{p}");
    assert!(!item_ids(&p).contains(&mid));
    assert_items_are_the_vectors(&p);
    assert_eq!(p["digest_echo"], Value::Null);
    let [s11, s12, s21] = vector_steps();
    let (chain, _) = chain_and_plan_steps(&pool, wf).await;
    assert_eq!(chain, vec![s11, mid, s12, s21], "the chain was rewired");
}

/// `evolve_step` writes a new head in the step's lineage; the generation's
/// `executes` edge stays on the frozen step. The plan's items and its digest
/// are unchanged, the frozen step reports `heads_diverged` (and is no longer
/// current after a `supersedes`), and no other item does.
#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_leaves_the_items_and_digest_and_sets_heads_diverged(pool: PgPool) {
    let w = private_workflow(&pool).await;
    // evolve_step needs workflow authority (#636): the submitter, its operator,
    // or claims:admin. A plain writer of G is refused, so evolve as the curator
    // that ingested the workflow, given a writer row in G so it can read the step.
    add_member(&pool, w.g, w.curator, "writer").await;
    let step = uuid_of(&vector_plan()[2]["claim_id"]);
    let (status, body) = w
        .api
        .post(
            &format!("/api/v1/workflows/steps/{step}/evolve"),
            &token(w.curator, WRITE_SCOPES),
            &json!({"parent_id": step, "content": "acme-frozen-plan \u{2014} step 1.1: read the queue twice",
                    "edge_type": "supersedes", "reason": "workflow-plan evolve"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "evolve_step: {body}");

    let p = w
        .api
        .plan(&token(w.reader, READ_SCOPES), w.workflow_id)
        .await;
    assert_items_are_the_vectors(&p);
    assert_eq!(p["digest_echo"], vectors()["ingest"]["wfd1"]);
    for item in p["items"].as_array().unwrap() {
        let is_step = uuid_of(&item["claim_id"]) == step;
        assert_eq!(item["heads_diverged"], json!(is_step), "{item}");
        assert_eq!(item["is_current"], json!(!is_step), "{item}");
    }
}

/// The same with a `revises` evolve, which leaves BOTH heads current: the
/// frozen step reports `heads_diverged` while it is still current. This is
/// what tells `heads_diverged` apart from `!is_current`, which the
/// `supersedes` case cannot.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revises_evolve_sets_heads_diverged_on_a_step_that_stays_current(pool: PgPool) {
    let w = private_workflow(&pool).await;
    // evolve_step needs workflow authority (#636): the submitter, its operator,
    // or claims:admin. A plain writer of G is refused, so evolve as the curator
    // that ingested the workflow, given a writer row in G so it can read the step.
    add_member(&pool, w.g, w.curator, "writer").await;
    let step = uuid_of(&vector_plan()[5]["claim_id"]);
    let (status, body) = w
        .api
        .post(
            &format!("/api/v1/workflows/steps/{step}/evolve"),
            &token(w.curator, WRITE_SCOPES),
            &json!({"parent_id": step, "content": "acme-frozen-plan \u{2014} step 1.2: keep the new rows, sorted",
                    "edge_type": "revises", "reason": "workflow-plan branch"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "evolve_step: {body}");

    let p = w
        .api
        .plan(&token(w.reader, READ_SCOPES), w.workflow_id)
        .await;
    assert_items_are_the_vectors(&p);
    assert_eq!(flags(&p), clean());
    assert_eq!(p["digest_echo"], vectors()["ingest"]["wfd1"]);
    for item in p["items"].as_array().unwrap() {
        let is_step = uuid_of(&item["claim_id"]) == step;
        assert_eq!(item["heads_diverged"], json!(is_step), "{item}");
        assert_eq!(item["is_current"], json!(true), "{item}");
    }
}

/// `content_hash_ok` is seed-aware. A legacy row (no scope marker, plain
/// digest) and the rows the builder writes today (marked, digest scoped to the
/// workflow's name) are both `true`. A body edited out of band is `false`, and
/// so is a marked row carrying the plain digest: the plain digest is accepted
/// only on unmarked rows. Every edit here is the harness's: no API route
/// rewrites `content` or `content_hash`.
#[sqlx::test(migrations = "../../migrations")]
async fn content_hash_ok_accepts_legacy_and_scoped_rows_and_rejects_tampered_ones(pool: PgPool) {
    let w = private_workflow(&pool).await;
    let plan = vector_plan();
    let legacy = uuid_of(&plan[2]["claim_id"]);
    let tampered = uuid_of(&plan[5]["claim_id"]);
    let marked_plain = uuid_of(&plan[7]["claim_id"]);
    let mut conn = pool.acquire().await.expect("acquire");
    sqlx::query("SET session_replication_role = replica")
        .execute(&mut *conn)
        .await
        .expect("harness: skip triggers");
    // Postgres has no blake3: the plain digest is computed here and bound.
    let plain_digest = |text: &str| blake3::hash(text.as_bytes()).as_bytes().to_vec();
    let content_of = |id: Uuid| {
        plan.iter()
            .find(|i| uuid_of(&i["claim_id"]) == id)
            .and_then(|i| i["content"].as_str())
            .unwrap()
            .to_string()
    };
    let edits = [
        sqlx::query(
            "UPDATE claims SET properties = properties - 'content_hash_scope', content_hash = $2 \
              WHERE id = $1",
        )
        .bind(legacy)
        .bind(plain_digest(&content_of(legacy))),
        sqlx::query("UPDATE claims SET content = content || ' (edited)' WHERE id = $1")
            .bind(tampered),
        sqlx::query("UPDATE claims SET content_hash = $2 WHERE id = $1")
            .bind(marked_plain)
            .bind(plain_digest(&content_of(marked_plain))),
    ];
    for edit in edits {
        let n = edit
            .execute(&mut *conn)
            .await
            .expect("harness edit")
            .rows_affected();
        assert_eq!(n, 1);
    }
    sqlx::query("SET session_replication_role = origin")
        .execute(&mut *conn)
        .await
        .expect("restore");
    drop(conn);

    let p = w
        .api
        .plan(&token(w.reader, READ_SCOPES), w.workflow_id)
        .await;
    for item in p["items"].as_array().unwrap() {
        let id = uuid_of(&item["claim_id"]);
        let want = !(id == tampered || id == marked_plain);
        assert_eq!(item["content_hash_ok"], json!(want), "{item}");
    }
}

/// PM-7 over REST, as a plain member of the plan's group would do it: a G
/// writer exchanges two `plan_index` values, then writes a STRING index on a
/// third edge, then retracts a fourth. Each step is reported as what it is:
///
/// 1. the exchange: the items follow the stored indices, no flag is raised,
///    and the echo is the digest of the new order (an independent vector),
///    not the published one;
/// 2. the string index: the edge is unindexed, not an item, no echo;
/// 3. the retraction (of the tail edge, after the string index is undone):
///    counted, not an item, no echo, though no gap is left.
#[sqlx::test(migrations = "../../migrations")]
async fn a_group_writer_reordering_or_retracting_edges_changes_what_the_read_reports(pool: PgPool) {
    let w = private_workflow(&pool).await;
    let v = vectors();
    let writer = token(w.writer, WRITE_SCOPES);
    let reader = token(w.reader, READ_SCOPES);
    let edges = executes_edges(&pool, w.workflow_id).await;
    assert_eq!(edges.len(), vector_plan().len());
    let before = item_ids(&w.api.plan(&reader, w.workflow_id).await);

    // 1. exchange 1 <-> 2
    w.api
        .patch_edge(&writer, edges[1].0, json!({"plan_index": 2}))
        .await;
    w.api
        .patch_edge(&writer, edges[2].0, json!({"plan_index": 1}))
        .await;
    let p = w.api.plan(&reader, w.workflow_id).await;
    assert_eq!(flags(&p), clean());
    let after = item_ids(&p);
    assert_eq!((after[1], after[2]), (before[2], before[1]));
    assert_eq!(
        p["digest_echo"],
        v["ingest"]["wfd1_with_plan_index_1_and_2_swapped"]
    );
    assert_ne!(p["digest_echo"], v["ingest"]["wfd1"]);

    // 2. a string index
    w.api
        .patch_edge(&writer, edges[3].0, json!({"plan_index": "3"}))
        .await;
    let p = w.api.plan(&reader, w.workflow_id).await;
    assert_eq!(p["unindexed_edges"], json!(1), "{p}");
    assert!(!item_ids(&p).contains(&edges[3].1));
    assert_eq!(p["digest_echo"], Value::Null);

    // 3. a retraction. Undo the string index first, so the null echo below
    //    follows from the retraction alone: back to the exchanged order.
    w.api
        .patch_edge(&writer, edges[3].0, json!({"plan_index": 3}))
        .await;
    let p = w.api.plan(&reader, w.workflow_id).await;
    assert_eq!(flags(&p), clean(), "calibration: {p}");
    assert_eq!(
        p["digest_echo"],
        v["ingest"]["wfd1_with_plan_index_1_and_2_swapped"]
    );
    let (status, body) = w
        .api
        .call(
            Method::DELETE,
            &format!("/api/v1/edges/{}", edges[8].0),
            &writer,
            None,
        )
        .await;
    assert!(status.is_success(), "retract: {status} {body}");
    let p = w.api.plan(&reader, w.workflow_id).await;
    assert_eq!(p["retracted_edges"], json!(1), "{p}");
    assert_eq!(
        p["plan_index_gaps"],
        json!(0),
        "the tail leaves no gap: {p}"
    );
    assert!(!item_ids(&p).contains(&edges[8].1));
    assert_eq!(p["digest_echo"], Value::Null);
}
