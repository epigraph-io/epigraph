#![cfg(feature = "db")]
//! Backlog 07ed8d4d: the API checked its signing key's admission at boot
//! only, so a key revoked, rotated out or past its window while the server
//! ran kept signing every HTTP edge, and the verifier (which judges a key at
//! the edge's `created_at`) refuses each of them. The running server now
//! watches the key (`edge_signer::watch_admission`, spawned by
//! `bin/server.rs`, which exits the process when it returns): these tests pin
//! the watch's verdict against the verifier's, with a positive control
//! before every change. `api_signing_key_watch_server.rs` pins that the
//! server binary runs the watch and exits on it.
//!
//! The watch runs here at a 50 ms interval; production reads
//! `EPIGRAPH_API_SIGNING_KEY_RECHECK_SECS` (default 30 s).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use epigraph_api::edge_signer::{self, ApiEdgeSigner};
use epigraph_crypto::AgentSigner;
use epigraph_db::repos::EdgeSignatureRepository;
use epigraph_db::visibility::Viewer;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use uuid::Uuid;

mod common;
mod viewer_fixture;

const TICK: Duration = Duration::from_millis(50);

async fn pool() -> (String, PgPool) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    (url, pool)
}

/// The same key twice: one copy for the server, one for the watch.
fn twin(key: &AgentSigner) -> AgentSigner {
    AgentSigner::from_bytes(&key.secret_key()).expect("same key")
}

fn watch(pool: &PgPool, key: &AgentSigner, signer_id: Uuid) -> JoinHandle<String> {
    tokio::spawn(edge_signer::watch_admission(
        pool.clone(),
        Arc::new(ApiEdgeSigner::new(twin(key), signer_id)),
        TICK,
    ))
}

/// Positive control: the watch has not stopped after several re-checks.
async fn still_watching(w: &mut JoinHandle<String>, what: &str) {
    if let Ok(stop) = tokio::time::timeout(TICK * 8, &mut *w).await {
        panic!("{what}: the watch stopped on an admitted key: {stop:?}");
    }
}

async fn stopped(w: JoinHandle<String>, what: &str) -> String {
    tokio::time::timeout(Duration::from_secs(10), w)
        .await
        .unwrap_or_else(|_| panic!("{what}: the watch kept signing with an inadmissible key"))
        .expect("watch task")
}

async fn spawn_signed(url: &str, signer: ApiEdgeSigner) -> (SocketAddr, oneshot::Sender<()>) {
    let app = epigraph_api::build_app_for_tests_with_edge_signer(url, signer)
        .await
        .expect("app builds");
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

/// `POST /api/v1/edges/hierarchical` between two fresh claims; the edge id.
async fn write_edge(pool: &PgPool, addr: SocketAddr, token: &str) -> Uuid {
    let tag = Uuid::new_v4();
    let a = common::seed_claim(pool, &format!("admission watch source {tag}")).await;
    let b = common::seed_claim(pool, &format!("admission watch target {tag}")).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/edges/hierarchical"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "source_claim_id": a, "target_claim_id": b, "relationship": "decomposes_to",
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert!(status.is_success(), "{status}: {text}");
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["edge_id"].as_str().expect("edge_id").parse().unwrap()
}

/// (signed, signature_valid) as the edge verifier reports them.
async fn verdict(pool: &PgPool, edge: Uuid) -> (bool, bool) {
    let viewer = Viewer::resolve(pool, Uuid::nil()).await.expect("viewer");
    let mut conn = pool.acquire().await.expect("conn");
    let c = EdgeSignatureRepository::verify_conn(&mut conn, &viewer, edge)
        .await
        .expect("verify")
        .expect("readable");
    (c.signed, c.signature_valid)
}

/// The API's key is an attested, ACTIVE `signing` row of its agent. While it
/// is, the server signs edges that verify and the watch keeps going; once the
/// row is revoked (as a maintenance session would), the watch stops, naming
/// the key and the remedy. Why it must: an edge the server signs after the
/// revocation fails verification. A restart would refuse the key too (the
/// boot rule agrees).
///
/// Mutation: `signer_key_admission` reading every key as `Open` -> the watch never
/// stops and this fails.
#[tokio::test(flavor = "multi_thread")]
async fn revoking_the_running_apis_signing_key_stops_its_signer() {
    let (url, pool) = pool().await;
    let owner = common::seed_system_agent(&pool).await;
    let key = AgentSigner::generate();
    let row = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agent_keys (id, agent_id, public_key, key_type, status, valid_from) \
         VALUES ($1, $2, $3, 'signing', 'active', now() - interval '1 minute')",
    )
    .bind(row)
    .bind(owner)
    .bind(key.public_key().as_slice())
    .execute(&pool)
    .await
    .expect("register the API key as an active signing row (test superuser)");
    assert_eq!(
        edge_signer::resolve_signer_agent(&pool, &key)
            .await
            .expect("boot admits the key"),
        owner
    );
    let (addr, _shutdown) = spawn_signed(&url, ApiEdgeSigner::new(twin(&key), owner)).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, &["edges:write"]).await;
    let mut w = watch(&pool, &key, owner);

    // Positive control: admitted, so the edge verifies and the watch goes on.
    let before = write_edge(&pool, addr, &token).await;
    assert_eq!(verdict(&pool, before).await, (true, true));
    still_watching(&mut w, "active key").await;

    sqlx::query(
        "UPDATE agent_keys SET status = 'revoked', valid_until = now(), \
                revocation_reason = 'suspected exposure' WHERE id = $1",
    )
    .bind(row)
    .execute(&pool)
    .await
    .unwrap();

    let stop = stopped(w, "revoked key").await;
    assert!(stop.contains(&hex::encode(key.public_key())), "{stop}");
    assert!(stop.contains(&owner.to_string()), "{stop}");
    assert!(stop.contains(edge_signer::KEY_NO_LONGER_ADMITTED), "{stop}");

    // What the stop prevents: a server still signing with the key writes an
    // edge the verifier refuses.
    let after = write_edge(&pool, addr, &token).await;
    assert_eq!(verdict(&pool, after).await, (true, false));
    // The boot rule agrees: a restart refuses the key.
    let err = edge_signer::resolve_signer_agent(&pool, &key)
        .await
        .expect_err("a revoked key is refused at boot");
    assert!(
        err.contains("not an active, in-window signing key"),
        "{err}"
    );
}

/// The API's key is only its signer agent's bare `agents.public_key` (a key
/// the first boot registered). The rotation runbook retires it with a
/// `rotated` row whose `valid_until` is the cut-over: until the cut-over the
/// watch goes on, and once it passes the watch stops. A row of an
/// application-insertable type (`encryption`, revoked) carrying the key is
/// not a recorded lifecycle (the verifier ignores it), so it does not stop
/// the API: an application session cannot take the server down by planting
/// one.
///
/// Mutations: `signer_key_admission` reading every key as `Open` -> never stops; the
/// window's end ignored (`key_window_admits` without `valid_until`) -> never
/// stops; non-attested rows treated as a lifecycle -> stops on the planted
/// row.
#[tokio::test(flavor = "multi_thread")]
async fn a_bare_key_stops_when_the_runbooks_rotated_row_closes_its_window() {
    let (_url, pool) = pool().await;
    let key = AgentSigner::generate();
    let signer_id = edge_signer::resolve_signer_agent(&pool, &key)
        .await
        .expect("boot registers a signer agent for a fresh key");
    let mut w = watch(&pool, &key, signer_id);
    still_watching(&mut w, "bare key").await;

    sqlx::query(
        "INSERT INTO agent_keys (agent_id, public_key, key_type, status, valid_from, valid_until) \
         VALUES ($1, $2, 'encryption', 'revoked', now() - interval '1 day', now())",
    )
    .bind(signer_id)
    .bind(key.public_key().as_slice())
    .execute(&pool)
    .await
    .expect("plant a non-attested row");
    still_watching(&mut w, "planted non-attested row").await;

    let row = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agent_keys (id, agent_id, public_key, key_type, status, valid_from, valid_until) \
         SELECT $1, a.id, a.public_key, 'signing', 'rotated', a.created_at, now() + interval '1 hour' \
           FROM agents a WHERE a.id = $2",
    )
    .bind(row)
    .bind(signer_id)
    .execute(&pool)
    .await
    .expect("record the old key as rotated, cut-over in an hour (test superuser)");
    still_watching(&mut w, "cut-over not reached").await;

    sqlx::query("UPDATE agent_keys SET valid_until = now() WHERE id = $1")
        .bind(row)
        .execute(&pool)
        .await
        .unwrap();
    let stop = stopped(w, "cut-over passed").await;
    assert!(stop.contains(&hex::encode(key.public_key())), "{stop}");
    let err = edge_signer::resolve_signer_agent(&pool, &key)
        .await
        .expect_err("a retired key is refused at boot");
    assert!(
        err.contains("not an active, in-window signing key"),
        "{err}"
    );
}

/// A failed re-read is not a verdict: the watch logs it and goes on, so a
/// transient database error never stops the server. Mutation: treating
/// `Err` as a stop -> this fails.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_recheck_does_not_stop_the_signer() {
    let (_url, pool) = pool().await;
    let key = AgentSigner::generate();
    let signer_id = edge_signer::resolve_signer_agent(&pool, &key)
        .await
        .expect("signer agent");
    let closed = pool.clone();
    closed.close().await;
    let mut w = watch(&closed, &key, signer_id);
    still_watching(&mut w, "every re-read fails").await;
    w.abort();
}

/// Production runs the watch on the server's scoped pool, on the APPLICATION
/// ROLE, not on a superuser pool where `epigraph_bypass()` is true. On that
/// pool the watch must read the signer's keys and bare agent key the same
/// way: a bare-key signer and an attested `signing` key both keep serving
/// (a false "not admitted" would restart the server every interval), and
/// both stop once retired (a read the role cannot make would only WARN, and
/// the watch would never stop).
#[sqlx::test(migrations = "../../migrations")]
async fn the_watch_judges_the_key_on_the_application_role(pool: PgPool) {
    let url = viewer_fixture::database_url_for(&pool).await;
    let scoped = epigraph_db::ScopedPool::connect_downgraded_for_tests(
        &url,
        epigraph_db::SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool");
    let app = scoped.inner().clone();
    let bypass: bool = sqlx::query_scalar("SELECT public.epigraph_bypass()")
        .fetch_one(&app)
        .await
        .expect("epigraph_bypass");
    assert!(
        !bypass,
        "CALIBRATION: the watch's pool must not be privileged"
    );

    // A bare key (a signer agent the first boot registered).
    let bare = AgentSigner::generate();
    let bare_id = edge_signer::resolve_signer_agent(&pool, &bare)
        .await
        .expect("signer agent");
    let mut bare_watch = watch(&app, &bare, bare_id);

    // An attested, active signing row of another agent.
    let owner = common::seed_system_agent(&pool).await;
    let attested = AgentSigner::generate();
    let row = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agent_keys (id, agent_id, public_key, key_type, status, valid_from) \
         VALUES ($1, $2, $3, 'signing', 'active', now() - interval '1 minute')",
    )
    .bind(row)
    .bind(owner)
    .bind(attested.public_key().as_slice())
    .execute(&pool)
    .await
    .expect("register the signing row (test superuser)");
    let mut attested_watch = watch(&app, &attested, owner);

    still_watching(&mut bare_watch, "bare key, application role").await;
    still_watching(&mut attested_watch, "active signing key, application role").await;

    sqlx::query(
        "INSERT INTO agent_keys (agent_id, public_key, key_type, status, valid_from, valid_until) \
         SELECT a.id, a.public_key, 'signing', 'rotated', a.created_at, now() \
           FROM agents a WHERE a.id = $1",
    )
    .bind(bare_id)
    .execute(&pool)
    .await
    .expect("retire the bare key (test superuser)");
    sqlx::query("UPDATE agent_keys SET status = 'revoked', valid_until = now() WHERE id = $1")
        .bind(row)
        .execute(&pool)
        .await
        .unwrap();

    let stop = stopped(bare_watch, "retired bare key, application role").await;
    assert!(stop.contains(&hex::encode(bare.public_key())), "{stop}");
    let stop = stopped(attested_watch, "revoked key, application role").await;
    assert!(stop.contains(&hex::encode(attested.public_key())), "{stop}");
}

/// A PLANNED cut-over (the rotation runbook's future `valid_until`) stops the
/// watch BEFORE the window closes, by the database clock that dates the
/// edges, even with the longest interval (300 s): a fixed-interval sleep
/// would keep signing for up to an interval past the cut-over, and every
/// edge in that span fails verification.
///
/// Verified to fail: the watch ignoring the recorded end (sleeping the full
/// interval) -> no stop within 20 s; `STOP_LEAD_SECS` = 0 -> the stop comes
/// after the cut-over.
#[tokio::test(flavor = "multi_thread")]
async fn a_planned_cut_over_stops_the_signer_before_the_window_closes() {
    let (_url, pool) = pool().await;
    let owner = common::seed_system_agent(&pool).await;
    let key = AgentSigner::generate();
    let lead = edge_signer::STOP_LEAD_SECS;
    let cut_over: DateTime<Utc> = sqlx::query_scalar(
        "INSERT INTO agent_keys (agent_id, public_key, key_type, status, valid_from, valid_until) \
         VALUES ($1, $2, 'signing', 'active', now() - interval '1 minute', \
                 clock_timestamp() + make_interval(secs => $3)) \
         RETURNING valid_until",
    )
    .bind(owner)
    .bind(key.public_key().as_slice())
    .bind((lead + 3) as f64)
    .fetch_one(&pool)
    .await
    .expect("an active signing row with a cut-over a few seconds out (test superuser)");
    let mut w = tokio::spawn(edge_signer::watch_admission(
        pool.clone(),
        Arc::new(ApiEdgeSigner::new(twin(&key), owner)),
        Duration::from_secs(300),
    ));
    // Positive control: well before the lead, it keeps signing.
    still_watching(&mut w, "cut-over not yet within the lead").await;

    let stop = tokio::time::timeout(Duration::from_secs(20), w)
        .await
        .expect("the watch kept signing toward a known cut-over (an interval-only sleep)")
        .expect("watch task");
    let db_now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        db_now < cut_over,
        "the watch stopped at {db_now}, not before the cut-over {cut_over}: {stop}"
    );
    assert!(stop.contains(&hex::encode(key.public_key())), "{stop}");
    assert!(stop.contains("its admission ends at"), "{stop}");
}

/// Boot and the watch agree: a key whose window ends within the stop lead
/// passes the boot rule (an ACTIVE, in-window row) but the watch would stop
/// the server at once, so the unit would restart in a loop until the end.
/// Boot refuses it; the same key with an hour left boots (positive control).
///
/// Verified to fail: the admission verdict in `decide` disabled, or
/// `STOP_LEAD_SECS` = 0 -> the second decision boots.
#[tokio::test(flavor = "multi_thread")]
async fn boot_refuses_a_key_the_watch_would_stop_at_once() {
    let (_url, pool) = pool().await;
    let owner = common::seed_system_agent(&pool).await;
    let key = AgentSigner::generate();
    let row = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agent_keys (id, agent_id, public_key, key_type, status, valid_from, valid_until) \
         VALUES ($1, $2, $3, 'signing', 'active', now() - interval '1 minute', \
                 now() + interval '1 hour')",
    )
    .bind(row)
    .bind(owner)
    .bind(key.public_key().as_slice())
    .execute(&pool)
    .await
    .expect("an active signing row (test superuser)");
    let file = std::env::temp_dir().join(format!("api-signing-key-boot-{}.hex", Uuid::new_v4()));
    std::fs::write(&file, hex::encode(key.secret_key())).expect("key file");
    let path = file.to_str().unwrap().to_string();

    let booted = edge_signer::decide(&pool, Some(&path))
        .await
        .expect("CALIBRATION: an hour left boots");
    assert_eq!(booted.signer.map(|s| s.signer_id()), Some(owner));

    sqlx::query(
        "UPDATE agent_keys SET valid_until = clock_timestamp() + interval '2 seconds' \
         WHERE id = $1",
    )
    .bind(row)
    .execute(&pool)
    .await
    .unwrap();
    let refused = edge_signer::decide(&pool, Some(&path)).await;
    std::fs::remove_file(&file).ok();
    let err = refused.expect_err("a key ending within the stop lead is refused at boot");
    assert!(err.contains(edge_signer::KEY_ADMISSION_ENDING), "{err}");
    assert!(err.contains(&hex::encode(key.public_key())), "{err}");
}
