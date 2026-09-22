//! HTTP regression test for backlog bug `f1992766`: `GET /api/v1/claims`
//! serialised `is_current: true` on every row because
//! `ClaimRepository::list` never projected the column, and
//! `list_claims_query`'s `?is_current=false` filter — an in-memory
//! `retain(|c| c.is_current == is_current)` over that result — therefore
//! compared against a constant and could never match, returning an empty set
//! with HTTP 200.
//!
//! Both handler paths are exercised: the COUNT(*) fast path (no filters) must
//! report the real currency per row, and the in-memory slow path (reached by
//! `is_current`, which sets `needs_in_memory_filters`) must actually partition
//! the seeded rows. `content_contains` is pushed into the SQL `ILIKE`, so the
//! slow path's 10,000-row working set is already restricted to our marker and
//! this test is unaffected by the size of the shared test database (that cap
//! is separately tracked as backlog `2265a67b`).
#![cfg(feature = "db")]

use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn claims_query_is_current_reflects_the_stored_column() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    // Per-run marker so concurrent runs against a shared database don't see
    // each other's rows through `content_contains`.
    let run = Uuid::new_v4();
    let marker = format!("zzq-is-current-{run}");

    let agent = seed_agent(&pool).await;
    let live = seed_claim(&pool, agent, &format!("{marker} live row"), true, None).await;
    let superseded = seed_claim(
        &pool,
        agent,
        &format!("{marker} superseded row"),
        false,
        Some(live),
    )
    .await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let client = reqwest::Client::new();
    // Tenancy has no anonymous viewer — `ViewerExtractor` rejects an
    // unauthenticated request with 401, which is pinned by
    // `epigraph-db/tests/no_anonymous_viewer.rs`. This test predates that and was
    // calling the endpoint bare, so it failed on a missing `claims` key rather
    // than on the `is_current` projection it exists to check.
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, &["claims:read"]).await;

    // ---- Fast path (no filters): per-row is_current must be the real column ----
    let body: Value = client
        .get(format!(
            "http://{addr}/api/v1/claims?content_contains={marker}&limit=50"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rows = body["claims"].as_array().expect("claims array");
    assert_eq!(rows.len(), 2, "expected both seeded rows: got {body}");
    let current_of = |id: Uuid| -> &Value {
        rows.iter()
            .find(|c| c["id"].as_str() == Some(&id.to_string()))
            .unwrap_or_else(|| panic!("claim {id} missing from response: {body}"))
            .get("is_current")
            .unwrap()
    };
    assert_eq!(current_of(live), &Value::Bool(true));
    assert_eq!(
        current_of(superseded),
        &Value::Bool(false),
        "the superseded row must serialise is_current: false — `true` here is the \
         f1992766 fabrication"
    );

    // ---- Slow path: ?is_current=false must return the superseded row ----
    let body: Value = client
        .get(format!(
            "http://{addr}/api/v1/claims?content_contains={marker}&is_current=false&limit=50"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rows = body["claims"].as_array().expect("claims array");
    assert_eq!(
        rows.len(),
        1,
        "?is_current=false must match the one superseded row, not return empty: {body}"
    );
    assert_eq!(rows[0]["id"].as_str().unwrap(), superseded.to_string());
    assert_eq!(body["total"], Value::from(1));

    // ---- Slow path complement: ?is_current=true excludes the superseded row ----
    let body: Value = client
        .get(format!(
            "http://{addr}/api/v1/claims?content_contains={marker}&is_current=true&limit=50"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rows = body["claims"].as_array().expect("claims array");
    assert_eq!(
        rows.len(),
        1,
        "?is_current=true must match only the live row: {body}"
    );
    assert_eq!(rows[0]["id"].as_str().unwrap(), live.to_string());
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    // Per-test-binary distinct prefix (EE) so we don't collide with other test
    // binaries' agent public_keys (by-labels uses DD, graph_routes AA, ...).
    let pk: Vec<u8> = std::iter::repeat_n(0xEE, 16)
        .chain(id.as_bytes().iter().copied())
        .take(32)
        .collect();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(
    pool: &PgPool,
    agent_id: Uuid,
    content: &str,
    is_current: bool,
    supersedes: Option<Uuid>,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    // `visibility = 'public'` is explicit, not incidental: this test drives
    // `GET /api/v1/claims` through the `ViewerExtractor`, so an unauthenticated
    // request resolves a public viewer. A row seeded without it is filtered out
    // and the assertion below fails on a missing `claims` array rather than on
    // the `is_current` projection it is actually about.
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             is_current, supersedes, visibility) \
         VALUES ($1, $2, $3, 0.5, $4, $5, $6, 'public')",
    )
    .bind(id)
    .bind(content)
    .bind(hash)
    .bind(agent_id)
    .bind(is_current)
    .bind(supersedes)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}
