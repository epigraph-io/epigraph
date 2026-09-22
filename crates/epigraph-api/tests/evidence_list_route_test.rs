//! Regression tests for backlog `d7aab418`: `GET /api/v1/evidence` (the
//! collection path) had no reader at all.
//!
//! `routes/mod.rs` registered `post(crud::create_evidence)` and
//! `put(crud::update_evidence)` on the evidence paths, and the only reader was
//! `get(edges::get_evidence)` on `/api/v1/evidence/:id` — one row at a time. A
//! `GET` on the collection therefore fell through to axum's **405 Method Not
//! Allowed**, so the 123k-row `evidence` table could not be enumerated,
//! filtered or swept through the API. Both tests below FAIL at the branch point
//! with `405` where they assert `200`.
//!
//! The tenancy half is the part that matters most. Evidence rows hold
//! verbatim tool/API transcripts and routinely name people the claim text
//! never mentions, so a collection route that returned `raw_content` unscoped
//! would be a worse disclosure than the 405 it replaces. That half is a
//! DISCRIMINATING PAIR (owner sees / stranger does not).
//!
//! It asserts ABSENCE, not blanking. The original draft of this file asserted
//! `content == "[REDACTED]"` and `redacted == true` against the now-deleted
//! `check_content_access`; the tenancy series removed that shape deliberately,
//! because a placeholder body still discloses that the row EXISTS, and
//! `no_redaction_sentinel.rs` now fails the build on the literal. A row the
//! viewer cannot read is simply not in the page — and, just as importantly,
//! not in `total`, which is the assertion that would catch a page filtered by
//! a predicate its count does not share.
//!
//! Uses `#[sqlx::test]` (ephemeral per-test database) rather than the shared
//! `DATABASE_URL`, so `total` can be asserted as an exact number and the run
//! neither sees nor pollutes other suites' rows.
#![cfg(feature = "db")]

mod common;

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

/// The collection path answers with a body, not a 405 — and `total` is a real
/// `COUNT(*)` over the filter, not the length of the page.
#[sqlx::test(migrations = "../../migrations")]
async fn list_evidence_answers_the_collection_path_with_an_exact_total(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    // `#[sqlx::test]` accepts either a `PgPool` or the (options, options) pair,
    // not a mix — and the pair is what `spawn_app` needs, because `ScopedPool`
    // connects by URL and the ephemeral database name lives in `conn_opts`.
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let agent = seed_agent(&pool).await;
    let claim_a = seed_claim(&pool, agent, "claim A body").await;
    let claim_b = seed_claim(&pool, agent, "claim B body").await;

    // 7 rows on claim_a (4 observations, 3 documents), 2 on claim_b.
    for i in 0..4 {
        seed_evidence(
            &pool,
            claim_a,
            "observation",
            Some(&format!("obs transcript {i}")),
            None,
        )
        .await;
    }
    for i in 0..3 {
        seed_evidence(
            &pool,
            claim_a,
            "document",
            Some(&format!("doc transcript {i}")),
            None,
        )
        .await;
    }
    for i in 0..2 {
        seed_evidence(
            &pool,
            claim_b,
            "document",
            Some(&format!("other doc {i}")),
            None,
        )
        .await;
    }

    let (addr, _shutdown) = spawn_app(pool.clone(), &conn_opts).await;
    let client = reqwest::Client::new();
    // These fixtures declare no tenancy, so migration 070 stamps them
    // `visibility = 'public'` and any authenticated reader sees all 9.
    let token = common::mint_token_with_agent(&["claims:read"], agent);

    // ---- (1) The collection path is readable at all (was 405) ----
    let resp = client
        .get(format!("http://{addr}/api/v1/evidence?limit=3"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        200,
        "GET /api/v1/evidence must be a registered reader, not axum's 405"
    );
    let body: Value = resp.json().await.expect("json body");

    // ---- (2) total is a COUNT(*), not evidence.len() ----
    assert_eq!(
        body["evidence"].as_array().expect("evidence array").len(),
        3,
        "limit=3 must bound the page: {body}"
    );
    assert_eq!(
        body["total"],
        Value::from(9),
        "total must be the exact COUNT(*) over the whole table (9), not the page length: {body}"
    );
    assert_eq!(body["limit"], Value::from(3));
    assert_eq!(body["offset"], Value::from(0));

    // ---- (3) Filters push down, and total tracks them ----
    let body = get(
        &client,
        addr,
        &format!("/api/v1/evidence?claim_id={claim_a}"),
        &token,
    )
    .await;
    assert_eq!(body["total"], Value::from(7), "claim_id filter: {body}");

    let body = get(
        &client,
        addr,
        "/api/v1/evidence?evidence_type=observation",
        &token,
    )
    .await;
    assert_eq!(
        body["total"],
        Value::from(4),
        "evidence_type filter: {body}"
    );

    let body = get(
        &client,
        addr,
        &format!("/api/v1/evidence?claim_id={claim_a}&evidence_type=document"),
        &token,
    )
    .await;
    assert_eq!(
        body["total"],
        Value::from(3),
        "filters must AND together, not OR: {body}"
    );

    // Case-insensitive substring over raw_content.
    let body = get(
        &client,
        addr,
        "/api/v1/evidence?content_contains=OTHER%20doc",
        &token,
    )
    .await;
    assert_eq!(
        body["total"],
        Value::from(2),
        "content_contains must be case-insensitive: {body}"
    );

    // ---- (4) Paging enumerates the whole set exactly once ----
    let mut seen = std::collections::HashSet::new();
    for page in 0..3 {
        let body = get(
            &client,
            addr,
            &format!("/api/v1/evidence?limit=3&offset={}", page * 3),
            &token,
        )
        .await;
        for row in body["evidence"].as_array().unwrap() {
            assert!(
                seen.insert(row["id"].as_str().unwrap().to_string()),
                "evidence appeared on two pages — paging is unstable: {row}"
            );
        }
    }
    assert_eq!(seen.len(), 9, "three pages of 3 must cover all 9 rows");
}

/// DISCRIMINATING PAIR. Evidence attached to a `group`-private claim:
///
/// * a STRANGER's token does not see the row at all — not blanked, ABSENT —
///   and `total` does not count it;
/// * the owner's token sees the row with its real `content`, `source_url` and
///   `caption`, and `total` counts it.
///
/// The owner half is what makes the stranger half non-vacuous: it proves the
/// row exists and those fields are populated, so its absence above is the
/// viewer predicate rather than an empty fixture.
///
/// A second claim in the same fixture is public and its evidence stays visible
/// to the stranger in the SAME response, which rules out a "return nothing
/// unless you own it" implementation that would pass an absence-only assertion
/// while destroying the route.
///
/// `total` is asserted on BOTH sides on purpose. The page and the count are
/// two statements, and a count that skipped the visibility predicate would
/// leak the exact number of rows a caller may not read while the page itself
/// looked correct — the defect the shared `FILTER_WHERE` exists to prevent.
#[sqlx::test(migrations = "../../migrations")]
async fn list_evidence_hides_group_private_rows_from_a_stranger(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    // `#[sqlx::test]` accepts either a `PgPool` or the (options, options) pair,
    // not a mix — and the pair is what `spawn_app` needs, because `ScopedPool`
    // connects by URL and the ephemeral database name lives in `conn_opts`.
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let (owner, owner_group) = viewer_fixture::seed_agent_with_group(&pool, "evidence-owner").await;

    let private_claim =
        viewer_fixture::seed_group_claim(&pool, owner, owner_group, "PRIVATE claim body").await;
    let public_claim = viewer_fixture::seed_public_claim(&pool, owner, "public claim body").await;

    let private_ev = seed_evidence(
        &pool,
        private_claim,
        "figure",
        Some("verbatim transcript naming a third party"),
        Some(("https://secret.example/leak", "SECRET CAPTION substance")),
    )
    .await;
    let public_ev = seed_evidence(
        &pool,
        public_claim,
        "document",
        Some("harmless public transcript"),
        Some(("https://public.example/ok", "public caption")),
    )
    .await;

    // Migration 070 inherits tenancy from the linked claim on INSERT; assert it
    // rather than trust it, so a trigger change turns into a failure HERE
    // instead of silently making the stranger assertions vacuous.
    let (vis, grp): (String, Option<Uuid>) =
        sqlx::query_as("SELECT visibility, owner_group_id FROM evidence WHERE id = $1")
            .bind(private_ev)
            .fetch_one(&pool)
            .await
            .expect("read back the private evidence row");
    assert_eq!(
        (vis.as_str(), grp),
        ("group", Some(owner_group)),
        "fixture precondition: the evidence row must have inherited the \
         claim's group tenancy, or the stranger assertions below prove nothing"
    );

    let (addr, _shutdown) = spawn_app(pool.clone(), &conn_opts).await;
    let client = reqwest::Client::new();

    // ---- A stranger: the private row is ABSENT, and uncounted ----
    let stranger = viewer_fixture::seed_agent_with_group(&pool, "evidence-stranger")
        .await
        .0;
    let stranger_token = common::mint_token_with_agent(&["claims:read"], stranger);

    let body = get(&client, addr, "/api/v1/evidence?limit=50", &stranger_token).await;
    let rows = body["evidence"].as_array().expect("evidence array");
    assert!(
        !rows
            .iter()
            .any(|r| r["id"].as_str() == Some(private_ev.to_string().as_str())),
        "a stranger must not receive the group-private evidence row at all — \
         absence, not a blanked body: {body}"
    );
    // Same response: the PUBLIC claim's evidence is untouched.
    assert!(
        rows.iter()
            .any(|r| r["id"].as_str() == Some(public_ev.to_string().as_str())),
        "public evidence must stay readable to any authenticated reader: {body}"
    );

    // Scoped to the private claim, a stranger sees an empty page AND a zero
    // total — the count must carry the same predicate as the page.
    let body = get(
        &client,
        addr,
        &format!("/api/v1/evidence?claim_id={private_claim}"),
        &stranger_token,
    )
    .await;
    assert_eq!(
        body["evidence"].as_array().expect("evidence array").len(),
        0,
        "stranger's page over the private claim must be empty: {body}"
    );
    assert_eq!(
        body["total"],
        Value::from(0),
        "total must apply the visibility predicate too; a non-zero total here \
         leaks the row count behind a claim the caller cannot read: {body}"
    );

    // ---- The owner: the row is present, complete, and counted ----
    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let body = get(
        &client,
        addr,
        &format!("/api/v1/evidence?claim_id={private_claim}"),
        &owner_token,
    )
    .await;
    assert_eq!(
        body["total"],
        Value::from(1),
        "the owner must count the row (this is what makes the stranger's 0 \
         non-vacuous): {body}"
    );
    let private_row = find_row(body["evidence"].as_array().expect("array"), private_ev);
    assert_eq!(
        private_row["content"].as_str(),
        Some("verbatim transcript naming a third party"),
        "the owner must see the full content: {private_row}"
    );
    assert_eq!(
        private_row["source_url"].as_str(),
        Some("https://secret.example/leak"),
        "owner must see source_url: {private_row}"
    );
    assert_eq!(
        private_row["caption"].as_str(),
        Some("SECRET CAPTION substance"),
        "owner must see caption: {private_row}"
    );
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

fn find_row(rows: &[Value], id: Uuid) -> &Value {
    rows.iter()
        .find(|r| r["id"].as_str() == Some(id.to_string().as_str()))
        .unwrap_or_else(|| panic!("evidence {id} missing from response: {rows:?}"))
}

/// Every request carries a token: post-tenancy there is no anonymous `Viewer`,
/// so `ViewerExtractor` 401s a tokenless caller before the handler runs.
async fn get(client: &reqwest::Client, addr: SocketAddr, path: &str, token: &str) -> Value {
    let resp = client
        .get(format!("http://{addr}{path}"))
        .bearer_auth(token)
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 200, "GET {path} must answer 200");
    resp.json().await.expect("json body")
}

/// Same wiring as `epigraph_api::build_app_for_tests`, pointed at the existing
/// `#[sqlx::test]` ephemeral database so that database is the one under test.
///
/// Builds through `AppState::with_scoped_pool`, NOT `with_db`. `with_db` leaves
/// `scoped: None`, and every viewer-scoped read reaches the pool through
/// `AppState::read_as`, which FAIL-CLOSES on a `None` scoped pool rather than
/// silently falling back to the raw one — so `with_db` here made
/// `GET /api/v1/evidence` answer 500 and the route look broken when it was the
/// harness that was wrong. The fail-closed behaviour is correct and deliberate;
/// see the ~10 sibling `*_scoped_read` tests that wire it this way.
///
/// The DSN is rebuilt from `conn_opts` because `#[sqlx::test]` mints a fresh
/// database per test and `ScopedPool` connects by URL, not from an existing
/// `PgPool`.
async fn spawn_app(
    pool: PgPool,
    conn_opts: &PgConnectOptions,
) -> (SocketAddr, oneshot::Sender<()>) {
    let _ = &pool;
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let db = conn_opts.get_database().expect("test database name");
    let prefix = base
        .split_once('?')
        .map_or(base.as_str(), |(a, _)| a)
        .trim_end_matches('/')
        .rsplit_once('/')
        .expect("DATABASE_URL must carry a database path")
        .0
        .to_string();
    let scoped = epigraph_db::ScopedPool::connect(
        &format!("{prefix}/{db}"),
        epigraph_db::SessionGucMode::Session,
    )
    .await
    .expect("ScopedPool::connect");
    let state =
        epigraph_api::AppState::with_scoped_pool(scoped, epigraph_api::ApiConfig::default());
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

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(pool: &PgPool, agent_id: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id) \
         VALUES ($1, $2, $3, 0.5, $4)",
    )
    .bind(id)
    .bind(content)
    .bind(hash)
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// `evidence_type` is the stored vocabulary (`evidence_type_valid` CHECK):
/// document / observation / testimony / computation / reference / figure /
/// conversational.
async fn seed_evidence(
    pool: &PgPool,
    claim_id: Uuid,
    evidence_type: &str,
    raw_content: Option<&str>,
    url_and_caption: Option<(&str, &str)>,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    let (source_url, properties) = match url_and_caption {
        Some((url, caption)) => (
            Some(url.to_string()),
            serde_json::json!({"evidence_type": evidence_type, "caption": caption}),
        ),
        None => (None, serde_json::json!({"evidence_type": evidence_type})),
    };
    sqlx::query(
        "INSERT INTO evidence (id, content_hash, evidence_type, raw_content, claim_id, \
                               source_url, properties) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(hash)
    .bind(evidence_type)
    .bind(raw_content)
    .bind(claim_id)
    .bind(source_url)
    .bind(properties)
    .execute(pool)
    .await
    .expect("seed evidence");
    id
}
