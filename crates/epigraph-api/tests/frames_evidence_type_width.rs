//! `POST /api/v1/frames/:id/evidence` and the width of
//! `mass_functions.evidence_type` (backlog candidate
//! B101-rest-length-and-whitespace).
//!
//! The column is `varchar(50)` (migration 001). The route stores the caller's
//! `evidence_type` canonicalised (trimmed and lowercased, or mapped to its
//! canonical key), so a key the calibration does not know is stored as the
//! caller's own key. A stored key longer than 50 characters reached the
//! INSERT, failed with 22001 and came back as a 500 database error. The route
//! now refuses it as a 400 naming the stored length and the limit, before
//! anything is written, counting the STORED form in characters as `varchar`
//! does.
//!
//! The last test is a regression pin, not a proof of this change: a
//! whitespace-only `evidence_type` already behaved like an omitted one on
//! REST (the canonicaliser trims it to no key, and the route applies
//! `reliability` whether or not a type is sent).
//!
//! `#[sqlx::test]` gives each test an ephemeral database; the harness is
//! `frames_evidence_recompute_parity.rs`'s (superuser raw pool, `ScopedPool`
//! for the stamped write).
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

const EPS: f64 = 1e-9;

async fn spawn_app(conn_opts: &PgConnectOptions) -> (SocketAddr, oneshot::Sender<()>) {
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

struct World {
    pool: PgPool,
    addr: SocketAddr,
    _shutdown: oneshot::Sender<()>,
    agent: Uuid,
    group: Uuid,
    token: String,
    frame: Uuid,
}

async fn world(pool_opts: PgPoolOptions, conn_opts: PgConnectOptions) -> World {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let (agent, group) = fixture::seed_agent_with_group(&pool, "et-width").await;
    let frame = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO frames (id, name, hypotheses) VALUES ($1, $2, ARRAY['h0','h1']::text[])",
    )
    .bind(frame)
    .bind(format!("et-width-frame-{frame}"))
    .execute(&pool)
    .await
    .expect("seed frame");
    let (addr, shutdown) = spawn_app(&conn_opts).await;
    let token = common::mint_token_with_agent(&["claims:write"], agent);
    World {
        pool,
        addr,
        _shutdown: shutdown,
        agent,
        group,
        token,
        frame,
    }
}

/// A fresh public claim the caller owns, so every case has its own rows.
async fn seed_claim(w: &World, tag: &str) -> Uuid {
    let claim = Uuid::new_v4();
    let hash: Vec<u8> = claim.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, visibility, \
                             owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, 'public', $5)",
    )
    .bind(claim)
    .bind(format!("et-width {tag} {claim}"))
    .bind(hash)
    .bind(w.agent)
    .bind(w.group)
    .execute(&w.pool)
    .await
    .expect("seed claim");
    claim
}

async fn post_evidence(w: &World, body: Value) -> (u16, String) {
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{}/api/v1/frames/{}/evidence",
            w.addr, w.frame
        ))
        .bearer_auth(&w.token)
        .json(&body)
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    (status, resp.text().await.expect("body"))
}

async fn submit(w: &World, claim: Uuid, evidence_type: Option<&str>) -> (u16, String) {
    let mut body = serde_json::json!({
        "claim_id": claim, "reliability": 0.5,
        "masses": {"0": 0.7, "0,1": 0.3},
    });
    if let Some(et) = evidence_type {
        body["evidence_type"] = Value::from(et);
    }
    post_evidence(w, body).await
}

async fn stored_types(w: &World, claim: Uuid) -> Vec<Option<String>> {
    sqlx::query_scalar("SELECT evidence_type::text FROM mass_functions WHERE claim_id = $1")
        .bind(claim)
        .fetch_all(&w.pool)
        .await
        .expect("read BBAs")
}

async fn frame_assignments(w: &World, claim: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claim_frames WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(&w.pool)
        .await
        .expect("count frame assignments")
}

/// A refusal is a 400 naming the field, the stored length and the limit, and
/// it leaves neither the BBA nor the claim's frame assignment behind.
async fn assert_refused(w: &World, claim: Uuid, (status, text): (u16, String), stored_len: usize) {
    assert_eq!(
        status, 400,
        "an over-long evidence_type is the caller's error, not a 500: {text}"
    );
    assert!(
        text.contains("evidence_type")
            && text.contains(&format!("{stored_len} characters"))
            && text.contains("at most 50"),
        "the refusal names the field, the stored length and the limit: {text}"
    );
    assert!(stored_types(w, claim).await.is_empty(), "no BBA written");
    assert_eq!(
        frame_assignments(w, claim).await,
        0,
        "no frame assignment written"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_over_long_stored_evidence_type_is_a_400_with_nothing_written(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;

    // 50 characters of an unknown key, multi-byte (100 bytes): stored as
    // given, because the limit is counted in characters as varchar counts it.
    let c = seed_claim(&w, "50").await;
    let type50 = "é".repeat(50);
    let (status, text) = submit(&w, c, Some(&type50)).await;
    assert_eq!(status, 201, "a 50-character evidence_type fits: {text}");
    assert_eq!(stored_types(&w, c).await, [Some(type50)]);

    // 51 characters of an unknown key: refused before anything is written.
    // (The old code reached the INSERT: 22001, answered as a 500.)
    let c = seed_claim(&w, "51").await;
    let res = submit(&w, c, Some(&"x".repeat(51))).await;
    assert_refused(&w, c, res, 51).await;

    // A known alias padded far past 50 with whitespace and sent mixed-case is
    // stored as its canonical key: the limit applies to what is STORED.
    let c = seed_claim(&w, "padded").await;
    let padded = format!("{}Testimony{}", " ".repeat(40), " ".repeat(40));
    assert!(padded.chars().count() > 50);
    let (status, text) = submit(&w, c, Some(&padded)).await;
    assert_eq!(
        status, 201,
        "a padded known key canonicalises to a short stored key: {text}"
    );
    assert_eq!(stored_types(&w, c).await, [Some("testimonial".to_string())]);

    // 26 characters as sent, but lowercasing grows each one into two (the
    // dotted capital I lowercases to `i` plus a combining dot), so the STORED
    // key is longer than the column. Counting the raw input would let it
    // through to a 22001.
    let c = seed_claim(&w, "lowercase growth").await;
    let raw = "\u{130}".repeat(26);
    let stored_len = raw.to_lowercase().chars().count();
    assert_eq!(raw.chars().count(), 26);
    assert!(
        stored_len > 50,
        "fixture: the lowercased key must exceed the column ({stored_len})"
    );
    let res = submit(&w, c, Some(&raw)).await;
    assert_refused(&w, c, res, stored_len).await;
}

/// REGRESSION PIN (passes before and after this change): a whitespace-only
/// `evidence_type` stores exactly what an omitted one stores, the
/// reliability-discounted masses with no type.
#[sqlx::test(migrations = "../../migrations")]
async fn a_whitespace_only_evidence_type_stores_what_an_omitted_one_does(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;
    let row = |claim: Uuid| {
        let pool = w.pool.clone();
        async move {
            sqlx::query_as::<_, (f64, Option<String>, Option<String>, Option<f64>)>(
                "SELECT (masses->>'0')::float8, evidence_type::text, locality_tag::text, \
                        source_strength \
                   FROM mass_functions WHERE claim_id = $1",
            )
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("the caller's BBA")
        }
    };

    let omitted = seed_claim(&w, "omitted").await;
    let (status, text) = submit(&w, omitted, None).await;
    assert_eq!(status, 201, "{text}");
    let want = row(omitted).await;
    assert!(
        (want.0 - 0.35).abs() < EPS,
        "reliability 0.5 discounts m({{0}}) = 0.7 to 0.35, got {}",
        want.0
    );
    assert_eq!(want.1, None);

    for (tag, et) in [("spaces", "   "), ("tab-newline", "\t\n")] {
        let c = seed_claim(&w, tag).await;
        let (status, text) = submit(&w, c, Some(et)).await;
        assert_eq!(status, 201, "{tag}: {text}");
        assert_eq!(row(c).await, want, "{tag}: stored like an omitted type");
    }
}
