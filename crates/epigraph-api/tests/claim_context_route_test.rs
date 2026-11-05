#![cfg(feature = "db")]
//! `GET /api/v1/claims/:id/context`.
//!
//! Hermetic `#[sqlx::test]`: totals and tallies count rows, so they only mean
//! anything on a database that holds nothing but this test's fixtures.
//!
//! Harness as `claim_ego_route_test.rs`: the router is built over
//! `AppState::with_scoped_pool` (every other constructor leaves the scoped pool
//! unset and `read_as` refuses), and every request carries a bearer, because
//! `ViewerExtractor` has no anonymous shape.
//!
//! # Tenancy fixtures
//!
//! A private claim is seeded public, wired up, and only THEN privatized, so
//! the edges that touch it keep the public stamp migration 070's trigger gave
//! them at insert. The claim predicate alone must then hide the row; an edge
//! the trigger had stamped private would be hidden by the edge predicate and
//! leave the claim predicate untested. Edges that must be private are forced
//! private explicitly. Every stranger assertion has an owner calibration, and
//! every hidden id is checked absent from the raw body in both its hyphenated
//! form and the `simple()` form a cursor token carries.

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::BTreeSet;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use chrono::{DateTime, Utc};
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_db::repos::claim::LabelCursor;
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

async fn router(pool: &PgPool) -> Router {
    create_router(AppState::with_scoped_pool(
        fixture::scoped_pool(pool).await,
        ApiConfig::default(),
    ))
}

/// A principal with no group memberships: it reads exactly the public corpus.
fn reader() -> String {
    common::mint_token_with_agent(&["claims:read"], Uuid::new_v4())
}

fn owner_token(owner: Uuid) -> String {
    common::mint_token_with_agent(&["claims:read"], owner)
}

async fn raw(router: &Router, path: &str, bearer: Option<&str>) -> (StatusCode, String, String) {
    let mut req = Request::builder().method(Method::GET).uri(path);
    if let Some(token) = bearer {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = router
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap_or_default().to_string())
        .unwrap_or_default();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, content_type, String::from_utf8_lossy(&bytes).into())
}

/// GET, assert 200, and return `(raw text, parsed body)`.
async fn ok(router: &Router, path: &str, bearer: &str) -> (String, Value) {
    let (status, _, text) = raw(router, path, Some(bearer)).await;
    assert_eq!(status, StatusCode::OK, "GET {path}: {text}");
    let body = serde_json::from_str(&text).expect("JSON body");
    (text, body)
}

fn ctx(id: Uuid) -> String {
    format!("/api/v1/claims/{id}/context")
}

/// `body` names `id` in neither its hyphenated form nor the `simple()` form
/// inside a cursor token.
fn assert_no_trace(body: &str, id: Uuid, what: &str) {
    assert!(
        !body.contains(&id.to_string()),
        "{what} ({id}) leaked in hyphenated form: {body}"
    );
    assert!(
        !body.contains(&id.simple().to_string()),
        "{what} ({id}) leaked in simple form (a cursor?): {body}"
    );
}

fn decode_cursor(tok: &Value) -> LabelCursor {
    LabelCursor::decode(tok.as_str().expect("cursor string")).expect("a decodable cursor")
}

fn item_ids(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap_or_else(|| panic!("items array in {page}"))
        .iter()
        .map(|n| n["id"].as_str().expect("id").to_string())
        .collect()
}

fn id_set(page: &Value) -> BTreeSet<String> {
    item_ids(page).into_iter().collect()
}

fn s<const N: usize>(ids: [Uuid; N]) -> BTreeSet<String> {
    ids.iter().map(Uuid::to_string).collect()
}

fn edge_ids(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .expect("edge items")
        .iter()
        .map(|e| e["edge_id"].as_str().expect("edge_id").to_string())
        .collect()
}

fn edge_by_id(edges: &Value, id: Uuid) -> &Value {
    edges["items"]
        .as_array()
        .expect("edge items")
        .iter()
        .find(|e| e["edge_id"] == id.to_string())
        .unwrap_or_else(|| panic!("edge {id} missing: {edges}"))
}

fn tally_sum(edges: &Value) -> i64 {
    edges["by_relationship"]
        .as_array()
        .expect("by_relationship")
        .iter()
        .map(|t| t["count"].as_i64().expect("count"))
        .sum()
}

fn keys(v: &Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().expect("object").keys().cloned().collect();
    k.sort();
    k
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

async fn edge(pool: &PgPool, src: Uuid, tgt: Uuid, rel: &str) -> Uuid {
    common::insert_edge(pool, src, tgt, "claim", "claim", rel).await
}

async fn asserts(pool: &PgPool, paper: Uuid, claim: Uuid) -> Uuid {
    common::insert_edge(pool, paper, claim, "paper", "claim", "asserts").await
}

async fn seed_paper(pool: &PgPool, title: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(format!("10.1234/{id}"))
        .bind(title)
        .execute(pool)
        .await
        .expect("seed paper");
    id
}

async fn set_level(pool: &PgPool, id: Uuid, level: i32) {
    sqlx::query(
        "UPDATE claims SET properties = properties || jsonb_build_object('level', $2::int) \
         WHERE id = $1",
    )
    .bind(id)
    .bind(level)
    .execute(pool)
    .await
    .expect("set level");
}

fn ts(secs: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(1_700_000_000 + secs, 0).expect("in range")
}

async fn set_created_at(pool: &PgPool, id: Uuid, at: DateTime<Utc>) {
    sqlx::query("UPDATE claims SET created_at = $2 WHERE id = $1")
        .bind(id)
        .bind(at)
        .execute(pool)
        .await
        .expect("set claim created_at");
}

async fn set_edge_created_at(pool: &PgPool, id: Uuid, at: DateTime<Utc>) {
    sqlx::query("UPDATE edges SET created_at = $2 WHERE id = $1")
        .bind(id)
        .bind(at)
        .execute(pool)
        .await
        .expect("set edge created_at");
}

async fn created_at_of(pool: &PgPool, id: Uuid) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT created_at FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read created_at")
}

/// Force every edge in `ids` public (see the module doc).
async fn force_edges_public(pool: &PgPool, ids: &[Uuid]) {
    sqlx::query(
        "UPDATE edges SET visibility = 'public', owner_group_id = \
         '00000000-0000-0000-0000-000000000000'::uuid, co_owner_group_id = NULL \
         WHERE id = ANY($1)",
    )
    .bind(ids.to_vec())
    .execute(pool)
    .await
    .expect("force edges public");
}

/// Force an edge group-private to `owner`'s personal group.
async fn force_edge_private(pool: &PgPool, id: Uuid, owner: Uuid) {
    let pk: Vec<u8> = owner.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(owner)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed the owning agent");
    let group = common::personal_group_of(pool, owner).await;
    let got: (String, Uuid) = sqlx::query_as(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
         WHERE id = $1 RETURNING visibility, owner_group_id",
    )
    .bind(id)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("force edge private");
    assert_eq!(got, ("group".to_string(), group));
}

/// A claim authored by `owner`, still public: wire it up first, then call
/// [`common::seed_private_ownership`].
async fn owned_claim(pool: &PgPool, content: &str, owner: Uuid) -> Uuid {
    common::seed_claim_with_agent(pool, content, owner).await
}

async fn privatize(pool: &PgPool, id: Uuid, owner: Uuid) {
    common::seed_private_ownership(pool, id, owner).await;
}

/// `n` public level-3 claims under `parent`, with `content_sql` as the SQL
/// expression for each claim's content (`g` is the series index). Bulk, so
/// the 200-row fixtures stay fast.
async fn seed_atoms(pool: &PgPool, parent: Uuid, n: i32, content_sql: &str) -> Vec<Uuid> {
    let agent = common::seed_system_agent(pool).await;
    let sql = format!(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             labels, properties, created_at) \
         SELECT gen_random_uuid(), {content_sql}, \
                sha256(($1::text || ':' || g::text)::bytea), 0.5, $1, true, \
                ARRAY[]::text[], jsonb_build_object('level', 3), \
                now() - make_interval(secs => 10000 - g) \
         FROM generate_series(1, $2) AS g \
         RETURNING id"
    );
    let ids: Vec<Uuid> = sqlx::query_scalar(&sql)
        .bind(agent)
        .bind(n)
        .fetch_all(pool)
        .await
        .expect("seed atoms");
    sqlx::query(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship) \
         SELECT $1, t, 'claim', 'claim', 'decomposes_to' FROM unnest($2::uuid[]) AS t",
    )
    .bind(parent)
    .bind(&ids)
    .execute(pool)
    .await
    .expect("seed atom edges");
    ids
}

async fn seed_theme(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description, claim_count) \
         VALUES ($1, 'seeded by claim_context_route_test', 0) RETURNING id",
    )
    .bind(format!("theme-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed theme")
}

// ---------------------------------------------------------------------------
// C1-C4
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn happy_path_returns_the_documented_shape(pool: PgPool) {
    let thesis = common::seed_claim(&pool, "c1 thesis").await;
    let section = common::seed_claim(&pool, "c1 methods").await;
    let root = common::seed_claim(&pool, "c1 the root paragraph").await;
    let sib_a = common::seed_claim(&pool, "c1 sibling a").await;
    let sib_b = common::seed_claim(&pool, "c1 sibling b").await;
    set_level(&pool, thesis, 0).await;
    set_level(&pool, section, 1).await;
    for p in [root, sib_a, sib_b] {
        set_level(&pool, p, 2).await;
        edge(&pool, section, p, "decomposes_to").await;
    }
    edge(&pool, thesis, section, "decomposes_to").await;
    let mut atoms = Vec::new();
    for i in 0..3 {
        let a = common::seed_claim(&pool, &format!("c1 atom {i}")).await;
        set_level(&pool, a, 3).await;
        edge(&pool, root, a, "decomposes_to").await;
        atoms.push(a);
    }
    let paper = seed_paper(&pool, "c1 paper").await;
    for c in [thesis, section, root] {
        asserts(&pool, paper, c).await;
    }
    let refuter = common::seed_claim(&pool, "c1 refuter").await;
    let supported = common::seed_claim(&pool, "c1 supported").await;
    let corroborator = common::seed_claim(&pool, "c1 corroborator").await;
    let e_refutes = edge(&pool, refuter, root, "refutes").await;
    let e_supports = edge(&pool, root, supported, "supports").await;
    let e_corr = edge(&pool, corroborator, root, "corroborates").await;
    sqlx::query("UPDATE edges SET properties = jsonb_build_object('strength', 0.8) WHERE id = $1")
        .bind(e_corr)
        .execute(&pool)
        .await
        .expect("strength");
    let theme = seed_theme(&pool).await;
    sqlx::query("UPDATE claims SET theme_id = $2 WHERE id = $1")
        .bind(supported)
        .bind(theme)
        .execute(&pool)
        .await
        .expect("theme");
    // A cached BetP on every claim, so the absence asserted below is the
    // route declining to serve the columns, not the columns being null.
    sqlx::query("UPDATE claims SET belief = 0.4, plausibility = 0.9, pignistic_prob = 0.65")
        .execute(&pool)
        .await
        .expect("cache a BetP");
    let app = router(&pool).await;

    let (text, body) = ok(&app, &ctx(root), &reader()).await;
    assert_eq!(
        keys(&body),
        ["claim", "edges", "paper", "papers", "parents", "parts", "section", "siblings"]
    );
    for word in ["belief", "plausibility", "pignistic_prob"] {
        assert!(!text.contains(word), "the body names `{word}`: {text}");
    }

    let claim = &body["claim"];
    assert_eq!(
        keys(claim),
        [
            "content",
            "content_truncated",
            "id",
            "is_current",
            "level",
            "theme_id",
            "truth_value"
        ]
    );
    assert_eq!(claim["id"], root.to_string());
    assert_eq!(claim["content"], "c1 the root paragraph");
    assert_eq!(claim["content_truncated"], false);
    assert_eq!(claim["truth_value"], 0.5);
    assert_eq!(claim["is_current"], true);
    assert_eq!(claim["level"], 2);
    assert_eq!(claim["theme_id"], Value::Null);

    assert_eq!(body["paper"]["id"], paper.to_string());
    assert_eq!(body["paper"]["doi"], format!("10.1234/{paper}"));
    assert_eq!(body["paper"]["title"], "c1 paper");
    assert_eq!(body["paper"]["truncated"], false);
    assert_eq!(body["papers"]["total"], 1);
    assert_eq!(item_ids(&body["papers"]), vec![paper.to_string()]);
    assert_eq!(body["papers"]["next_cursor"], Value::Null);

    assert_eq!(body["section"]["id"], section.to_string());
    assert_eq!(body["section"]["level"], 1);
    assert_eq!(body["section"]["content"], "c1 methods");
    assert_eq!(body["parents"]["total"], 1);
    assert_eq!(item_ids(&body["parents"]), vec![section.to_string()]);
    assert_eq!(body["parts"]["total"], 3);
    assert_eq!(id_set(&body["parts"]), s([atoms[0], atoms[1], atoms[2]]));
    assert_eq!(body["siblings"]["parent_id"], section.to_string());
    assert_eq!(body["siblings"]["total"], 2);
    assert_eq!(id_set(&body["siblings"]), s([sib_a, sib_b]));
    for list in ["parents", "parts", "siblings"] {
        assert_eq!(body[list]["next_cursor"], Value::Null, "{list}");
        for n in body[list]["items"].as_array().unwrap() {
            assert!(n["truth_value"].is_number(), "{n}");
            assert!(n.get("theme_id").is_some(), "theme_id always present: {n}");
        }
    }

    let edges = &body["edges"];
    assert_eq!(edges["total"], 3);
    assert_eq!(edges["next_cursor"], Value::Null);
    let mut tallies: Vec<(String, String, i64)> = edges["by_relationship"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| {
            (
                t["relationship"].as_str().unwrap().to_string(),
                t["direction"].as_str().unwrap().to_string(),
                t["count"].as_i64().unwrap(),
            )
        })
        .collect();
    tallies.sort();
    assert_eq!(
        tallies,
        vec![
            ("corroborates".to_string(), "incoming".to_string(), 1),
            ("refutes".to_string(), "incoming".to_string(), 1),
            ("supports".to_string(), "outgoing".to_string(), 1),
        ]
    );
    let by_id = |id: Uuid| edge_by_id(edges, id);
    let refutes = by_id(e_refutes);
    assert_eq!(refutes["relationship"], "refutes");
    assert_eq!(refutes["direction"], "incoming");
    assert_eq!(refutes["neighbor"]["id"], refuter.to_string());
    assert!(
        refutes.get("strength").is_none(),
        "absent strength is omitted"
    );
    let supports = by_id(e_supports);
    assert_eq!(supports["direction"], "outgoing");
    assert_eq!(supports["neighbor"]["id"], supported.to_string());
    assert_eq!(supports["neighbor"]["theme_id"], theme.to_string());
    assert!(supports["neighbor"]["truth_value"].is_number());
    assert!(
        supports["neighbor"].get("level").is_none(),
        "absent level is omitted"
    );
    let corr = by_id(e_corr);
    assert_eq!(corr["strength"], 0.8);
    assert_eq!(corr["neighbor"]["theme_id"], Value::Null);
}

#[sqlx::test(migrations = "../../migrations")]
async fn no_bearer_is_401(pool: PgPool) {
    let root = common::seed_claim(&pool, "c2 root").await;
    let app = router(&pool).await;
    let (status, _, _) = raw(&app, &ctx(root), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // 401 wins over the 400 a malformed id or limit would earn.
    let (status, _, _) = raw(&app, "/api/v1/claims/not-a-uuid/context", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = raw(&app, &format!("{}?list=parts&limit=-1", ctx(root)), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn missing_claim_is_404(pool: PgPool) {
    let app = router(&pool).await;
    let (status, ct, text) = raw(&app, &ctx(Uuid::new_v4()), Some(&reader())).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{text}");
    assert!(ct.contains("json"), "{ct}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_root_is_the_same_404_as_a_claim_that_does_not_exist(pool: PgPool) {
    let owner = Uuid::new_v4();
    let root = owned_claim(&pool, "c4 classified root", owner).await;
    let part = common::seed_claim(&pool, "c4 public part").await;
    edge(&pool, root, part, "decomposes_to").await;
    privatize(&pool, root, owner).await;
    let app = router(&pool).await;
    let stranger = reader();
    let absent = Uuid::new_v4();
    let cursor = LabelCursor {
        created_at: ts(0),
        id: Uuid::new_v4(),
    }
    .encode();

    for suffix in [String::new(), format!("?list=parts&after={cursor}")] {
        let (p_status, p_ct, p_body) =
            raw(&app, &format!("{}{suffix}", ctx(root)), Some(&stranger)).await;
        let (a_status, a_ct, a_body) =
            raw(&app, &format!("{}{suffix}", ctx(absent)), Some(&stranger)).await;
        assert_eq!(p_status, StatusCode::NOT_FOUND, "{p_body}");
        assert_eq!(
            p_status, a_status,
            "status must not discriminate ({suffix})"
        );
        assert_eq!(p_ct, a_ct, "content-type must not discriminate ({suffix})");
        assert_eq!(
            p_body.replace(&root.to_string(), "<ID>"),
            a_body.replace(&absent.to_string(), "<ID>"),
            "a private claim and a nonexistent one are one answer ({suffix})"
        );
    }

    // Calibration: the owner gets the context.
    let (_, body) = ok(&app, &ctx(root), &owner_token(owner)).await;
    assert_eq!(body["claim"]["content"], "c4 classified root");
    assert_eq!(body["parts"]["total"], 1);
    let (_, body) = ok(
        &app,
        &format!("{}?list=parts&after={cursor}", ctx(root)),
        &owner_token(owner),
    )
    .await;
    assert_eq!(keys(&body), ["claim", "parts"]);
}

// ---------------------------------------------------------------------------
// C5: the tenancy test
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_sees_no_private_node_no_id_and_no_count(pool: PgPool) {
    let owner = Uuid::new_v4();
    let section = common::seed_claim(&pool, "c5 section").await;
    let root = common::seed_claim(&pool, "c5 paragraph").await;
    let public_sib = common::seed_claim(&pool, "c5 public sibling").await;
    let private_sib = owned_claim(&pool, "c5 private sibling", owner).await;
    let public_atom = common::seed_claim(&pool, "c5 public atom").await;
    let private_atom = owned_claim(&pool, "c5 private atom", owner).await;
    let public_n = common::seed_claim(&pool, "c5 public neighbour").await;
    let private_n = owned_claim(&pool, "c5 private neighbour", owner).await;
    let behind_private_edge = common::seed_claim(&pool, "c5 behind a private edge").await;
    set_level(&pool, section, 1).await;
    for p in [root, public_sib, private_sib] {
        set_level(&pool, p, 2).await;
        edge(&pool, section, p, "decomposes_to").await;
    }
    for a in [public_atom, private_atom] {
        set_level(&pool, a, 3).await;
        edge(&pool, root, a, "decomposes_to").await;
    }
    edge(&pool, root, public_n, "supports").await;
    let e_private_n = edge(&pool, private_n, root, "refutes").await;
    let e_private_edge = edge(&pool, root, behind_private_edge, "contradicts").await;
    force_edge_private(&pool, e_private_edge, owner).await;
    let paper_y = seed_paper(&pool, "c5 public paper").await;
    let paper_z = seed_paper(&pool, "c5 paper behind a private edge").await;
    asserts(&pool, paper_y, root).await;
    asserts(&pool, paper_y, section).await;
    let e_z = asserts(&pool, paper_z, root).await;
    force_edge_private(&pool, e_z, owner).await;
    for c in [private_sib, private_atom, private_n] {
        privatize(&pool, c, owner).await;
    }
    // The private neighbour's edge stays public: only the claim predicate
    // can hide it.
    force_edges_public(&pool, &[e_private_n]).await;
    let app = router(&pool).await;
    let stranger = reader();

    let (text, body) = ok(&app, &ctx(root), &stranger).await;
    for (id, what) in [
        (private_sib, "private sibling"),
        (private_atom, "private atom"),
        (private_n, "private neighbour"),
        (e_private_n, "edge to the private neighbour"),
        (e_private_edge, "private edge"),
        (behind_private_edge, "claim behind a private edge"),
        (paper_z, "paper behind a private asserts edge"),
        (e_z, "private asserts edge"),
    ] {
        assert_no_trace(&text, id, what);
    }
    assert_eq!(body["siblings"]["total"], 1);
    assert_eq!(id_set(&body["siblings"]), s([public_sib]));
    assert_eq!(body["parts"]["total"], 1);
    assert_eq!(id_set(&body["parts"]), s([public_atom]));
    assert_eq!(body["edges"]["total"], 1);
    assert_eq!(tally_sum(&body["edges"]), 1);
    assert_eq!(body["edges"]["items"].as_array().unwrap().len(), 1);
    assert_eq!(body["papers"]["total"], 1);
    assert_eq!(body["paper"]["id"], paper_y.to_string());
    for t in body["edges"]["by_relationship"].as_array().unwrap() {
        assert_eq!(t["relationship"], "supports", "{t}");
        assert_eq!(t["count"], 1);
    }

    // A caller-supplied agent id changes nothing: the viewer is the bearer's.
    let (text_spoofed, _) = ok(&app, &format!("{}?agent_id={owner}", ctx(root)), &stranger).await;
    assert_eq!(text_spoofed, text);

    // Calibration: the owner sees all of it, and every total is larger.
    let (owner_text, body) = ok(&app, &ctx(root), &owner_token(owner)).await;
    assert_eq!(body["siblings"]["total"], 2);
    assert_eq!(id_set(&body["siblings"]), s([public_sib, private_sib]));
    assert_eq!(body["parts"]["total"], 2);
    assert_eq!(body["edges"]["total"], 3);
    assert_eq!(tally_sum(&body["edges"]), 3);
    assert_eq!(body["papers"]["total"], 2);
    for id in [
        private_sib,
        private_atom,
        private_n,
        paper_z,
        e_private_edge,
    ] {
        assert!(owner_text.contains(&id.to_string()), "owner misses {id}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_page_cursor_next_to_a_hidden_part_names_a_visible_one(pool: PgPool) {
    let owner = Uuid::new_v4();
    let root = common::seed_claim(&pool, "c5b paragraph").await;
    let a1 = common::seed_claim(&pool, "c5b atom 1").await;
    let a2 = owned_claim(&pool, "c5b hidden atom 2", owner).await;
    let a3 = common::seed_claim(&pool, "c5b atom 3").await;
    set_level(&pool, root, 2).await;
    for (i, a) in [a1, a2, a3].into_iter().enumerate() {
        set_level(&pool, a, 3).await;
        set_created_at(&pool, a, ts(i as i64)).await;
        edge(&pool, root, a, "decomposes_to").await;
    }
    privatize(&pool, a2, owner).await;
    let app = router(&pool).await;
    let stranger = reader();

    let base = format!("{}?list=parts&limit=1", ctx(root));
    let (t1, p1) = ok(&app, &base, &stranger).await;
    assert_eq!(keys(&p1), ["claim", "parts"]);
    assert_eq!(item_ids(&p1["parts"]), vec![a1.to_string()]);
    assert_eq!(p1["parts"]["total"], 2);
    let c1 = decode_cursor(&p1["parts"]["next_cursor"]);
    assert_eq!(c1.id, a1);

    let next = format!("{base}&after={}", c1.encode());
    let (t2, p2) = ok(&app, &next, &stranger).await;
    assert_eq!(item_ids(&p2["parts"]), vec![a3.to_string()]);
    let c2 = decode_cursor(&p2["parts"]["next_cursor"]);
    assert_eq!(
        c2.id, a3,
        "the cursor names the emitted row, not the hidden one"
    );

    let last = format!("{base}&after={}", c2.encode());
    let (t3, p3) = ok(&app, &last, &stranger).await;
    assert!(item_ids(&p3["parts"]).is_empty());
    assert_eq!(p3["parts"]["next_cursor"], Value::Null);
    for t in [&t1, &t2, &t3] {
        assert_no_trace(t, a2, "hidden atom");
    }

    // Calibration: the owner's second page is the hidden atom.
    let (_, o2) = ok(&app, &next, &owner_token(owner)).await;
    assert_eq!(item_ids(&o2["parts"]), vec![a2.to_string()]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_page_cursor_next_to_a_hidden_edge_names_a_visible_one(pool: PgPool) {
    let owner = Uuid::new_v4();
    let root = common::seed_claim(&pool, "c5c root").await;
    let x1 = common::seed_claim(&pool, "c5c newest").await;
    let x2 = common::seed_claim(&pool, "c5c behind the private edge").await;
    let x3 = common::seed_claim(&pool, "c5c oldest").await;
    let e1 = edge(&pool, root, x1, "supports").await;
    let e2 = edge(&pool, root, x2, "supports").await;
    let e3 = edge(&pool, x3, root, "refutes").await;
    set_edge_created_at(&pool, e1, ts(30)).await;
    set_edge_created_at(&pool, e2, ts(20)).await;
    set_edge_created_at(&pool, e3, ts(10)).await;
    force_edge_private(&pool, e2, owner).await;
    let app = router(&pool).await;
    let stranger = reader();
    let visible: BTreeSet<Uuid> = [e1, e3].into_iter().collect();

    let base = format!("{}?list=edges&limit=1", ctx(root));
    let mut path = base.clone();
    let mut served = Vec::new();
    for _ in 0..4 {
        let (text, body) = ok(&app, &path, &stranger).await;
        assert_eq!(keys(&body), ["claim", "edges"]);
        assert_no_trace(&text, e2, "hidden edge");
        assert_no_trace(&text, x2, "claim behind the hidden edge");
        assert_eq!(tally_sum(&body["edges"]), 2);
        assert_eq!(body["edges"]["total"], 2);
        served.extend(edge_ids(&body["edges"]));
        let cur = &body["edges"]["next_cursor"];
        if cur.is_null() {
            break;
        }
        let c = decode_cursor(cur);
        assert!(
            visible.contains(&c.id),
            "cursor names {} not an emitted edge",
            c.id
        );
        path = format!("{base}&after={}", c.encode());
    }
    assert_eq!(served, vec![e1.to_string(), e3.to_string()]);
}

// ---------------------------------------------------------------------------
// C6-C8
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_parent_hides_section_parents_and_siblings(pool: PgPool) {
    let owner = Uuid::new_v4();
    let section = owned_claim(&pool, "c6 private section", owner).await;
    let root = common::seed_claim(&pool, "c6 paragraph").await;
    let sib = common::seed_claim(&pool, "c6 sibling").await;
    set_level(&pool, section, 1).await;
    for p in [root, sib] {
        set_level(&pool, p, 2).await;
        edge(&pool, section, p, "decomposes_to").await;
    }
    privatize(&pool, section, owner).await;
    let app = router(&pool).await;

    let (text, body) = ok(&app, &ctx(root), &reader()).await;
    assert_eq!(body["section"], Value::Null);
    assert_eq!(body["parents"]["total"], 0);
    assert_eq!(body["siblings"]["parent_id"], Value::Null);
    assert_eq!(body["siblings"]["total"], 0);
    assert_no_trace(&text, section, "private section");
    assert_no_trace(
        &text,
        sib,
        "sibling reachable only through the private section",
    );

    let (_, body) = ok(&app, &ctx(root), &owner_token(owner)).await;
    assert_eq!(body["section"]["id"], section.to_string());
    assert_eq!(item_ids(&body["parents"]), vec![section.to_string()]);
    assert_eq!(body["siblings"]["parent_id"], section.to_string());
    assert_eq!(id_set(&body["siblings"]), s([sib]));
}

#[sqlx::test(migrations = "../../migrations")]
async fn lists_are_capped_and_cursor_paged(pool: PgPool) {
    let root = common::seed_claim(&pool, "c7 paragraph").await;
    set_level(&pool, root, 2).await;
    let atoms = seed_atoms(&pool, root, 60, "'c7 atom ' || g::text").await;
    let app = router(&pool).await;
    let stranger = reader();

    let (_, body) = ok(&app, &ctx(root), &stranger).await;
    let first = item_ids(&body["parts"]);
    assert_eq!(first.len(), 50);
    assert_eq!(body["parts"]["total"], 60);
    let cur = decode_cursor(&body["parts"]["next_cursor"]);
    assert_eq!(cur.id.to_string(), *first.last().unwrap());
    let items: usize = ["papers", "parents", "parts", "siblings", "edges"]
        .iter()
        .map(|l| body[l]["items"].as_array().unwrap().len())
        .sum();
    assert!(items + 3 <= 200, "full mode carries {items} list items");

    let (_, page) = ok(
        &app,
        &format!("{}?list=parts&after={}", ctx(root), cur.encode()),
        &stranger,
    )
    .await;
    assert_eq!(keys(&page), ["claim", "parts"]);
    let second = item_ids(&page["parts"]);
    assert_eq!(second.len(), 10);
    assert_eq!(page["parts"]["next_cursor"], Value::Null);
    let all: BTreeSet<String> = first.iter().chain(second.iter()).cloned().collect();
    assert_eq!(all.len(), 60, "no overlap between the pages");
    assert_eq!(all, atoms.iter().map(Uuid::to_string).collect());
}

#[sqlx::test(migrations = "../../migrations")]
async fn bad_parameters_are_400_whatever_the_root(pool: PgPool) {
    let owner = Uuid::new_v4();
    let public_root = common::seed_claim(&pool, "c8 public").await;
    let private_root = owned_claim(&pool, "c8 private", owner).await;
    privatize(&pool, private_root, owner).await;
    let absent = Uuid::new_v4();
    let app = router(&pool).await;
    let stranger = reader();
    let cursor = LabelCursor {
        created_at: ts(0),
        id: Uuid::new_v4(),
    }
    .encode();

    let json_cases = [
        format!("?after={cursor}"),
        "?limit=5".to_string(),
        "?list=bogus".to_string(),
        "?list=parts&after=garbage".to_string(),
    ];
    let text_cases = [
        "?list=parts&limit=-1",
        "?list=parts&limit=abc",
        "?list=parts&limit=4294967296",
    ];
    for (suffix, want_json) in json_cases
        .iter()
        .map(|s| (s.as_str(), true))
        .chain(text_cases.iter().map(|s| (*s, false)))
    {
        let mut answers = Vec::new();
        for root in [public_root, private_root, absent] {
            let (status, ct, body) =
                raw(&app, &format!("{}{suffix}", ctx(root)), Some(&stranger)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{suffix}: {body}");
            if want_json {
                assert!(ct.contains("json"), "{suffix}: {ct}");
            } else {
                assert!(ct.starts_with("text/plain"), "{suffix}: {ct}");
            }
            assert!(!body.contains(&root.to_string()), "{suffix}: {body}");
            answers.push((status, ct, body));
        }
        assert_eq!(answers[0], answers[1], "{suffix}: public vs private");
        assert_eq!(answers[0], answers[2], "{suffix}: public vs absent");
    }

    let (status, ct, _) = raw(&app, "/api/v1/claims/not-a-uuid/context", Some(&stranger)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(ct.starts_with("text/plain"), "{ct}");
}

// ---------------------------------------------------------------------------
// C9-C11
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn a_cursor_built_from_a_hidden_claim_reveals_nothing(pool: PgPool) {
    let owner = Uuid::new_v4();
    let section = common::seed_claim(&pool, "c9 section").await;
    set_level(&pool, section, 1).await;
    let v1 = common::seed_claim(&pool, "c9 root v1").await;
    let v4 = common::seed_claim(&pool, "c9 v4").await;
    // Three claims at one created_at; by uuid order the middle one becomes
    // the hidden P3, so V2 sorts just below it and V3 just above.
    let mut trio = [
        owned_claim(&pool, "c9 trio a", owner).await,
        owned_claim(&pool, "c9 trio b", owner).await,
        owned_claim(&pool, "c9 trio c", owner).await,
    ];
    trio.sort();
    let (v2, p3, v3) = (trio[0], trio[1], trio[2]);
    for c in [v1, v2, p3, v3, v4] {
        set_level(&pool, c, 2).await;
        edge(&pool, section, c, "decomposes_to").await;
    }
    set_created_at(&pool, v1, ts(0)).await;
    for c in [v2, p3, v3] {
        set_created_at(&pool, c, ts(10)).await;
    }
    set_created_at(&pool, v4, ts(20)).await;
    privatize(&pool, p3, owner).await;
    let app = router(&pool).await;
    let stranger = reader();

    let p3_at = created_at_of(&pool, p3).await;
    let forged = LabelCursor {
        created_at: p3_at,
        id: p3,
    }
    .encode();
    let (text, body) = ok(
        &app,
        &format!("{}?list=siblings&after={forged}", ctx(v1)),
        &stranger,
    )
    .await;
    assert_no_trace(&text, p3, "hidden claim named by the forged cursor");

    // Expected: the stranger's own visible siblings, filtered to the rows
    // after the cursor's position.
    let (_, full) = ok(&app, &ctx(v1), &stranger).await;
    let mut expected = Vec::new();
    for id in item_ids(&full["siblings"]) {
        let uuid: Uuid = id.parse().unwrap();
        let at = created_at_of(&pool, uuid).await;
        if (at, uuid) > (p3_at, p3) {
            expected.push(id);
        }
    }
    assert_eq!(item_ids(&body["siblings"]), expected);
    assert_eq!(
        item_ids(&body["siblings"]),
        vec![v3.to_string(), v4.to_string()],
        "the fixture's own expectation agrees"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn limit_is_clamped(pool: PgPool) {
    let root = common::seed_claim(&pool, "c10 paragraph").await;
    set_level(&pool, root, 2).await;
    seed_atoms(&pool, root, 201, "'c10 atom ' || g::text").await;
    let app = router(&pool).await;
    let stranger = reader();

    let (_, big) = ok(
        &app,
        &format!("{}?list=parts&limit=1000", ctx(root)),
        &stranger,
    )
    .await;
    assert_eq!(item_ids(&big["parts"]).len(), 200);
    assert!(big["parts"]["next_cursor"].is_string());
    assert_eq!(big["parts"]["total"], 201);

    let (_, small) = ok(
        &app,
        &format!("{}?list=parts&limit=0", ctx(root)),
        &stranger,
    )
    .await;
    assert_eq!(item_ids(&small["parts"]).len(), 1);
    assert!(small["parts"]["next_cursor"].is_string());
}

#[sqlx::test(migrations = "../../migrations")]
async fn long_content_is_clipped_on_a_char_boundary(pool: PgPool) {
    let content = "é".repeat(2500);
    let root = common::seed_claim(&pool, &content).await;
    let title = "t".repeat(400);
    let paper = seed_paper(&pool, &title).await;
    asserts(&pool, paper, root).await;
    let app = router(&pool).await;

    let (_, body) = ok(&app, &ctx(root), &reader()).await;
    let got = body["claim"]["content"].as_str().unwrap();
    assert_eq!(got.chars().count(), 1500);
    assert_eq!(got, "é".repeat(1500));
    assert_eq!(body["claim"]["content_truncated"], true);
    let t = body["paper"]["title"].as_str().unwrap();
    assert_eq!(t.chars().count(), 300);
    assert_eq!(body["paper"]["truncated"], true);
    assert_eq!(body["papers"]["items"][0]["truncated"], true);
}

// ---------------------------------------------------------------------------
// C12-C15
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn an_atom_root_finds_its_paragraph_and_the_section_above_it(pool: PgPool) {
    let owner = Uuid::new_v4();
    let atom = common::seed_claim(&pool, "c12 shared atom").await;
    let section_s = common::seed_claim(&pool, "c12 section s").await;
    let para_p = common::seed_claim(&pool, "c12 paragraph p").await;
    let section_q = common::seed_claim(&pool, "c12 section of q").await;
    let para_q = owned_claim(&pool, "c12 private paragraph q", owner).await;
    let p_sib = common::seed_claim(&pool, "c12 other atom of p").await;
    let q_sib = common::seed_claim(&pool, "c12 other atom of q").await;
    set_level(&pool, atom, 3).await;
    for c in [section_s, section_q] {
        set_level(&pool, c, 1).await;
    }
    for c in [para_p, para_q] {
        set_level(&pool, c, 2).await;
    }
    for c in [p_sib, q_sib] {
        set_level(&pool, c, 3).await;
    }
    set_created_at(&pool, para_q, ts(0)).await;
    set_created_at(&pool, para_p, ts(10)).await;
    edge(&pool, section_s, para_p, "decomposes_to").await;
    edge(&pool, section_q, para_q, "decomposes_to").await;
    edge(&pool, para_p, atom, "decomposes_to").await;
    edge(&pool, para_q, atom, "decomposes_to").await;
    edge(&pool, para_p, p_sib, "decomposes_to").await;
    edge(&pool, para_q, q_sib, "decomposes_to").await;
    privatize(&pool, para_q, owner).await;
    let app = router(&pool).await;

    let (text, body) = ok(&app, &ctx(atom), &reader()).await;
    assert_eq!(body["parents"]["total"], 1);
    assert_no_trace(&text, para_q, "private paragraph");
    assert_no_trace(&text, section_q, "section reachable only through it");
    assert_no_trace(&text, q_sib, "atom reachable only through it");
    assert_eq!(body["siblings"]["parent_id"], para_p.to_string());
    assert_eq!(body["section"]["id"], section_s.to_string());
    assert_eq!(id_set(&body["siblings"]), s([p_sib]));

    let (_, body) = ok(&app, &ctx(atom), &owner_token(owner)).await;
    assert_eq!(body["parents"]["total"], 2);
    assert_eq!(
        body["siblings"]["parent_id"],
        para_q.to_string(),
        "the owner's first paragraph by created_at is its own"
    );
    assert_eq!(body["section"]["id"], section_q.to_string());
    assert_eq!(id_set(&body["siblings"]), s([q_sib]));
}

#[sqlx::test(migrations = "../../migrations")]
async fn superseded_and_retracted_edges_are_absent_and_relationships_are_lower_cased(pool: PgPool) {
    let root = common::seed_claim(&pool, "c13 root").await;
    let live = common::seed_claim(&pool, "c13 live").await;
    let superseded = common::seed_claim(&pool, "c13 superseded").await;
    let retracted = common::seed_claim(&pool, "c13 retracted").await;
    let e_live = edge(&pool, root, live, "SUPPORTS").await;
    let e_sup = edge(&pool, superseded, root, "supports").await;
    let e_ret = edge(&pool, root, retracted, "refutes").await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(superseded)
        .execute(&pool)
        .await
        .expect("supersede");
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 hour' WHERE id = $1")
        .bind(e_ret)
        .execute(&pool)
        .await
        .expect("retract");
    let app = router(&pool).await;

    let (text, body) = ok(&app, &ctx(root), &reader()).await;
    assert_eq!(edge_ids(&body["edges"]), vec![e_live.to_string()]);
    assert_eq!(body["edges"]["items"][0]["relationship"], "supports");
    assert_eq!(body["edges"]["total"], 1);
    assert_eq!(tally_sum(&body["edges"]), 1);
    assert_no_trace(&text, e_sup, "edge to a superseded claim");
    assert_no_trace(&text, e_ret, "retracted edge");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_shared_atom_reports_paper_and_section_from_the_same_document(pool: PgPool) {
    let atom = common::seed_claim(&pool, "c14 shared atom").await;
    set_level(&pool, atom, 3).await;
    let mut docs = Vec::new();
    for (name, para_at) in [("a", ts(10)), ("b", ts(0))] {
        let thesis = common::seed_claim(&pool, &format!("c14 thesis {name}")).await;
        let section = common::seed_claim(&pool, &format!("c14 section {name}")).await;
        let para = common::seed_claim(&pool, &format!("c14 paragraph {name}")).await;
        set_level(&pool, thesis, 0).await;
        set_level(&pool, section, 1).await;
        set_level(&pool, para, 2).await;
        set_created_at(&pool, para, para_at).await;
        edge(&pool, thesis, section, "decomposes_to").await;
        edge(&pool, section, para, "decomposes_to").await;
        edge(&pool, para, atom, "decomposes_to").await;
        let paper = seed_paper(&pool, &format!("c14 paper {name}")).await;
        for c in [thesis, section, para, atom] {
            asserts(&pool, paper, c).await;
        }
        docs.push((section, para, paper));
    }
    let (_section_a, _para_a, paper_a) = docs[0];
    let (section_b, para_b, paper_b) = docs[1];
    // Paper A is the older paper; paragraph B is the older paragraph.
    sqlx::query("UPDATE papers SET created_at = $2 WHERE id = $1")
        .bind(paper_a)
        .bind(ts(0))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE papers SET created_at = $2 WHERE id = $1")
        .bind(paper_b)
        .bind(ts(10))
        .execute(&pool)
        .await
        .unwrap();
    // A compound claim with no level, older than both paragraphs.
    let compound = common::seed_claim(&pool, "c14 compound").await;
    set_created_at(&pool, compound, ts(-10)).await;
    edge(&pool, compound, atom, "decomposes_to").await;
    let app = router(&pool).await;

    let (_, body) = ok(&app, &ctx(atom), &reader()).await;
    assert_eq!(body["siblings"]["parent_id"], para_b.to_string());
    assert_eq!(body["section"]["id"], section_b.to_string());
    assert_eq!(
        body["paper"]["id"],
        paper_b.to_string(),
        "the paper of the chain's document, not the oldest asserting paper"
    );
    assert_eq!(body["papers"]["total"], 2);
    assert_eq!(
        item_ids(&body["papers"]),
        vec![paper_a.to_string(), paper_b.to_string()]
    );
    assert_eq!(body["parents"]["total"], 3);
    assert!(id_set(&body["parents"]).contains(&compound.to_string()));
    assert_ne!(body["siblings"]["parent_id"], compound.to_string());
    assert_ne!(body["section"]["id"], compound.to_string());
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_maximal_page_fits_under_two_megabytes(pool: PgPool) {
    let root = common::seed_claim(&pool, "c15 paragraph").await;
    set_level(&pool, root, 2).await;
    seed_atoms(&pool, root, 200, "repeat(chr(1), 1600)").await;
    let app = router(&pool).await;

    let (text, body) = ok(
        &app,
        &format!("{}?list=parts&limit=200", ctx(root)),
        &reader(),
    )
    .await;
    assert_eq!(item_ids(&body["parts"]).len(), 200);
    assert_eq!(body["parts"]["items"][0]["content_truncated"], true);
    assert!(
        text.len() <= 2_000_000,
        "a maximal page is {} bytes",
        text.len()
    );
    assert!(text.len() > 200 * 1500 * 6, "the fixture is the worst case");
}
