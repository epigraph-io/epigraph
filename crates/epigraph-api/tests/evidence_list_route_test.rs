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
//! The redaction half is the part that matters most. Evidence rows hold
//! verbatim tool/API transcripts and routinely name people the claim text
//! never mentions, so a collection route that returned `raw_content`
//! ungated would be a worse disclosure than the 405 it replaces. That half is
//! a DISCRIMINATING PAIR (owner sees / stranger does not), and it was verified
//! by mutation: deleting the `check_content_access` call from
//! `crud::list_evidence` makes `list_evidence_redacts_private_claim_content`
//! fail while the rest of the file still passes.
//!
//! Uses `#[sqlx::test]` (ephemeral per-test database) rather than the shared
//! `DATABASE_URL`, so `total` can be asserted as an exact number and the run
//! neither sees nor pollutes other suites' rows.
#![cfg(feature = "db")]

mod common;

use serde_json::Value;
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

/// The collection path answers with a body, not a 405 — and `total` is a real
/// `COUNT(*)` over the filter, not the length of the page.
#[sqlx::test(migrations = "../../migrations")]
async fn list_evidence_answers_the_collection_path_with_an_exact_total(pool: PgPool) {
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

    let (addr, _shutdown) = spawn_app(pool.clone()).await;
    let client = reqwest::Client::new();

    // ---- (1) The collection path is readable at all (was 405) ----
    let resp = client
        .get(format!("http://{addr}/api/v1/evidence?limit=3"))
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
    )
    .await;
    assert_eq!(body["total"], Value::from(7), "claim_id filter: {body}");

    let body = get(&client, addr, "/api/v1/evidence?evidence_type=observation").await;
    assert_eq!(
        body["total"],
        Value::from(4),
        "evidence_type filter: {body}"
    );

    let body = get(
        &client,
        addr,
        &format!("/api/v1/evidence?claim_id={claim_a}&evidence_type=document"),
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

/// DISCRIMINATING PAIR. Evidence attached to a `private`-partition claim:
///
/// * a no-token caller (who additionally *spoofs* `?agent_id=<owner>`, which the
///   handler must ignore) sees `content == "[REDACTED]"`, no `source_url`, no
///   `caption`, and `redacted == true`;
/// * the owner's bearer token sees the real content, `source_url` and
///   `caption`, and `redacted == false`.
///
/// The owner half is what makes the redacted half non-vacuous: it proves those
/// fields are populated to begin with, so their absence above is gating rather
/// than an empty fixture.
///
/// A second claim in the same fixture is public, and its evidence stays
/// readable to the no-token caller in the SAME response — so the test also
/// rules out a blanket "redact everything when unauthenticated" implementation,
/// which would pass a redaction-only assertion while destroying the route.
#[sqlx::test(migrations = "../../migrations")]
async fn list_evidence_redacts_private_claim_content(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    let private_claim = seed_claim(&pool, owner, "PRIVATE claim body").await;
    let public_claim = seed_claim(&pool, owner, "public claim body").await;

    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id) \
         VALUES ($1, 'claim', 'private', $2)",
    )
    .bind(private_claim)
    .bind(owner)
    .execute(&pool)
    .await
    .expect("seed private ownership");

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

    let (addr, _shutdown) = spawn_app(pool.clone()).await;
    let client = reqwest::Client::new();

    // ---- No token, spoofing the owner's agent_id on the wire ----
    let body = get(
        &client,
        addr,
        &format!("/api/v1/evidence?limit=10&agent_id={owner}"),
    )
    .await;
    let rows = body["evidence"].as_array().expect("evidence array");
    let private_row = find_row(rows, private_ev);
    assert_eq!(
        private_row["content"].as_str(),
        Some("[REDACTED]"),
        "a no-token caller must not receive the verbatim transcript behind a \
         private claim, even when spoofing ?agent_id=<owner>: {private_row}"
    );
    assert!(
        private_row["source_url"].is_null(),
        "source_url identifies the transcript's origin and must be gated too: {private_row}"
    );
    assert!(
        private_row["caption"].is_null(),
        "caption carries free-form substance and must be gated too: {private_row}"
    );
    assert_eq!(
        private_row["redacted"],
        Value::Bool(true),
        "the row must declare that it was withheld, so a sweep can tell \
         'withheld' from 'no transcript stored': {private_row}"
    );

    // Same response: the PUBLIC claim's evidence is untouched. Rules out a
    // blanket redact-when-unauthenticated implementation.
    let public_row = find_row(rows, public_ev);
    assert_eq!(
        public_row["content"].as_str(),
        Some("harmless public transcript"),
        "public evidence must stay readable without a token: {public_row}"
    );
    assert_eq!(
        public_row["source_url"].as_str(),
        Some("https://public.example/ok")
    );
    assert_eq!(public_row["redacted"], Value::Bool(false));

    // ---- Owner's bearer token, with a DIFFERENT (random) wire agent_id ----
    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let random = Uuid::new_v4();
    let resp = client
        .get(format!(
            "http://{addr}/api/v1/evidence?limit=10&agent_id={random}"
        ))
        .bearer_auth(&owner_token)
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("json body");
    let rows = body["evidence"].as_array().expect("evidence array");
    let private_row = find_row(rows, private_ev);
    assert_eq!(
        private_row["content"].as_str(),
        Some("verbatim transcript naming a third party"),
        "the owner must see the full content (this is what makes the redacted \
         assertions above non-vacuous): {private_row}"
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
    assert_eq!(private_row["redacted"], Value::Bool(false));
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

fn find_row(rows: &[Value], id: Uuid) -> &Value {
    rows.iter()
        .find(|r| r["id"].as_str() == Some(id.to_string().as_str()))
        .unwrap_or_else(|| panic!("evidence {id} missing from response: {rows:?}"))
}

async fn get(client: &reqwest::Client, addr: SocketAddr, path: &str) -> Value {
    let resp = client
        .get(format!("http://{addr}{path}"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 200, "GET {path} must answer 200");
    resp.json().await.expect("json body")
}

/// Same wiring as `epigraph_api::build_app_for_tests`, but from the existing
/// `#[sqlx::test]` pool so the ephemeral database is the one under test.
async fn spawn_app(pool: PgPool) -> (SocketAddr, oneshot::Sender<()>) {
    let state = epigraph_api::AppState::with_db(pool, epigraph_api::ApiConfig::default());
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
