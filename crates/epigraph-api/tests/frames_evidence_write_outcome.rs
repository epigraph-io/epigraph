//! `POST /api/v1/frames/:id/evidence` says what its write did to the caller's
//! BBA slot (backlog 6f82db4f), as its MCP twin `submit_ds_evidence` does
//! since #675 (backlog bcbe34b2).
//!
//! # What was wrong, measured at origin/main before this file
//!
//! The BBA is upserted on `(claim, frame, source agent, perspective)`, and the
//! route answered an identical resubmission exactly like a first submission
//! (201, the same `mass_function_id`) and a resubmission with different masses
//! the same way, though it silently REPLACED the earlier BBA under that id. A
//! caller could not tell a real update from a no-op.
//!
//! Now the response carries `write_outcome` (`inserted` | `unchanged` |
//! `replaced`) and `deduplicated` (true iff `unchanged`), decided by the same
//! probe the MCP tool uses (`epigraph_db::bba_write_outcome`), against what
//! this route STORES: the masses after the reliability discount,
//! `combination_method = 'discount'`, `source_strength = 1.0`, the canonical
//! evidence type. Assertions read JSON keys, so this file compiles against the
//! pre-fix response type and fails on the assertions.
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

/// The app on the per-test database, built from a `ScopedPool` so the
/// handler's stamped write transaction is available.
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
    claim: Uuid,
    frame: Uuid,
}

async fn world(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
    owner: Uuid,
    group: Uuid,
) -> World {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let claim = Uuid::new_v4();
    let hash: Vec<u8> = claim.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, visibility, \
                             owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, 'public', $5)",
    )
    .bind(claim)
    .bind(format!("6f82db4f write outcome claim {claim}"))
    .bind(hash)
    .bind(owner)
    .bind(group)
    .execute(&pool)
    .await
    .expect("seed claim");
    let frame = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO frames (id, name, hypotheses) VALUES ($1, $2, ARRAY['h0','h1']::text[])",
    )
    .bind(frame)
    .bind(format!("6f82db4f-frame-{frame}"))
    .execute(&pool)
    .await
    .expect("seed frame");
    let (addr, shutdown) = spawn_app(&conn_opts).await;
    World {
        pool,
        addr,
        _shutdown: shutdown,
        claim,
        frame,
    }
}

/// POST the evidence and insist on 201, printing the body otherwise.
async fn post(w: &World, token: &str, body: Value) -> Value {
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{}/api/v1/frames/{}/evidence",
            w.addr, w.frame
        ))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("body");
    assert_eq!(status, 201, "POST evidence must be 201: {text}");
    serde_json::from_str(&text).expect("json body")
}

fn warnings(out: &Value) -> Vec<String> {
    out.get("warnings")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|w| w.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

async fn stored(pool: &PgPool, id: &Value) -> (Value, Option<String>) {
    sqlx::query_as("SELECT masses, evidence_type FROM mass_functions WHERE id = $1::uuid")
        .bind(id.as_str().expect("mass_function_id"))
        .fetch_one(pool)
        .await
        .expect("read the stored BBA")
}

async fn created_at(pool: &PgPool, id: &Value) -> chrono::DateTime<chrono::Utc> {
    sqlx::query_scalar("SELECT created_at FROM mass_functions WHERE id = $1::uuid")
        .bind(id.as_str().expect("mass_function_id"))
        .fetch_one(pool)
        .await
        .expect("read the stored BBA's created_at")
}

#[sqlx::test(migrations = "../../migrations")]
async fn each_rest_write_reports_whether_it_inserted_deduplicated_or_replaced(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let seed = pool_opts
        .clone()
        .connect_with(conn_opts.clone())
        .await
        .expect("seed pool");
    let (a, group_a) = fixture::seed_agent_with_group(&seed, "6f82db4f-a").await;
    let (b, _) = fixture::seed_agent_with_group(&seed, "6f82db4f-b").await;
    let w = world(pool_opts, conn_opts, a, group_a).await;
    let token_a = common::mint_token_with_agent(&["claims:write"], a);
    let token_b = common::mint_token_with_agent(&["claims:write"], b);
    // Reliability below 1: the route stores DISCOUNTED masses, so the probe
    // must compare against those, not against the raw request.
    let body = serde_json::json!({
        "claim_id": w.claim, "reliability": 0.8, "evidence_type": "statistical",
        "masses": {"0": 0.7, "0,1": 0.3},
    });

    let first = post(&w, &token_a, body.clone()).await;
    assert_eq!(first["write_outcome"], "inserted", "{first}");
    assert_eq!(first["deduplicated"], false, "{first}");
    assert!(
        first.get("warnings").is_none(),
        "a first submission carries no warning (the field is omitted): {first}"
    );
    let first_row = stored(&w.pool, &first["mass_function_id"]).await;
    let first_created = created_at(&w.pool, &first["mass_function_id"]).await;

    // The identical request: one row, its stored values unchanged, and the
    // caller is told.
    let again = post(&w, &token_a, body.clone()).await;
    assert_eq!(again["write_outcome"], "unchanged", "{again}");
    assert_eq!(again["deduplicated"], true, "{again}");
    assert_eq!(again["mass_function_id"], first["mass_function_id"]);
    assert!(
        warnings(&again).iter().any(|x| x.contains("identical")),
        "an unchanged write says so: {again}"
    );
    assert_eq!(stored(&w.pool, &again["mass_function_id"]).await, first_row);
    // What the warning promises about the row: the upsert still rewrites it,
    // so its created_at (which latest-row readers order by) moves forward.
    assert!(
        created_at(&w.pool, &again["mass_function_id"]).await > first_created,
        "an unchanged write still refreshes the row's created_at, as its warning says"
    );
    assert!(
        warnings(&again)
            .iter()
            .any(|x| x.contains("created_at is refreshed")),
        "the warning says the row's created_at moved: {again}"
    );

    // The same raw masses at another reliability store other masses: a
    // replacement under the same id, never "unchanged".
    let mut rediscounted = body.clone();
    rediscounted["reliability"] = serde_json::json!(0.5);
    let replaced = post(&w, &token_a, rediscounted).await;
    assert_eq!(replaced["write_outcome"], "replaced", "{replaced}");
    assert_eq!(replaced["deduplicated"], false, "{replaced}");
    assert_eq!(replaced["mass_function_id"], first["mass_function_id"]);
    assert!(
        warnings(&replaced).iter().any(|x| x.contains("REPLACED")),
        "a replacement says so: {replaced}"
    );
    let replaced_row = stored(&w.pool, &replaced["mass_function_id"]).await;
    assert_ne!(
        replaced_row.0, first_row.0,
        "CALIBRATION: the replacement did change the stored masses"
    );

    // Same masses, another evidence type: a column the upsert writes changed.
    let mut retyped = body.clone();
    retyped["reliability"] = serde_json::json!(0.5);
    retyped["evidence_type"] = serde_json::json!("testimonial");
    let retyped = post(&w, &token_a, retyped).await;
    assert_eq!(retyped["write_outcome"], "replaced", "{retyped}");
    let retyped_row = stored(&w.pool, &retyped["mass_function_id"]).await;
    assert_eq!(
        retyped_row.0, replaced_row.0,
        "CALIBRATION: only evidence_type differs from the previous write"
    );
    assert_ne!(
        retyped_row.1, replaced_row.1,
        "CALIBRATION: the stored evidence_type did change"
    );

    // Another agent's identical BBA is its own slot.
    let other = post(&w, &token_b, body.clone()).await;
    assert_eq!(other["write_outcome"], "inserted", "{other}");
    assert_ne!(other["mass_function_id"], first["mass_function_id"]);

    // So is the same agent's identical BBA under a perspective: the key's
    // other half. A perspective the caller owns, with its confidence
    // calibration cleared (the column defaults to 0.5, a further discount),
    // so the stored masses equal those in the slot without a perspective and
    // only the key tells the two writes apart.
    let perspective: Uuid = sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id, confidence_calibration) \
         VALUES ($1, $2, NULL) RETURNING id",
    )
    .bind(format!("6f82db4f-p-{}", Uuid::new_v4()))
    .bind(a)
    .fetch_one(&w.pool)
    .await
    .expect("seed perspective");
    let mut in_perspective = body;
    in_perspective["perspective_id"] = serde_json::json!(perspective);
    let scoped = post(&w, &token_a, in_perspective).await;
    assert_eq!(scoped["write_outcome"], "inserted", "{scoped}");
    assert_eq!(scoped["deduplicated"], false, "{scoped}");
    assert_ne!(scoped["mass_function_id"], first["mass_function_id"]);
    assert_eq!(
        stored(&w.pool, &scoped["mass_function_id"]).await,
        first_row,
        "CALIBRATION: the perspective's row stores what the first write stored"
    );
    assert_eq!(
        stored(&w.pool, &first["mass_function_id"]).await,
        retyped_row,
        "the perspective's write left the slot without a perspective as it was"
    );
}

async fn beta(pool: &PgPool, claim: Uuid) -> (f64, f64) {
    sqlx::query_as("SELECT beta_alpha, beta_beta FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read the claim's Beta parameters")
}

/// Backlog 33ce3f5d: an identical resubmission stores nothing new (its write
/// outcome is `unchanged`), so the parallel Beta-Bernoulli update must not
/// count it again. At origin/main the route applied the Beta update on every
/// call, so `bayesian_posterior` (and the claim's `beta_alpha`) moved on a
/// resubmission whose stored BBA did not change.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unchanged_resubmission_leaves_bayesian_posterior_where_it_was(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let seed = pool_opts
        .clone()
        .connect_with(conn_opts.clone())
        .await
        .expect("seed pool");
    let (a, group_a) = fixture::seed_agent_with_group(&seed, "33ce3f5d-a").await;
    let w = world(pool_opts, conn_opts, a, group_a).await;
    // The claim asserts hypothesis 0 of the frame, so the Beta update has a
    // singleton to read the evidence's support from.
    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, 0)",
    )
    .bind(w.claim)
    .bind(w.frame)
    .execute(&w.pool)
    .await
    .expect("assign the claim to hypothesis 0");
    let token_a = common::mint_token_with_agent(&["claims:write"], a);
    let body = serde_json::json!({
        "claim_id": w.claim, "reliability": 0.8, "evidence_type": "statistical",
        "masses": {"0": 0.7, "0,1": 0.3},
    });
    let before = beta(&w.pool, w.claim).await;

    let first = post(&w, &token_a, body.clone()).await;
    assert_eq!(first["write_outcome"], "inserted", "{first}");
    let after_first = beta(&w.pool, w.claim).await;
    assert!(
        after_first.0 > before.0,
        "CALIBRATION: a first submission applies the Beta update ({before:?} -> {after_first:?})"
    );
    let posterior = first["bayesian_posterior"]
        .as_f64()
        .expect("bayesian_posterior");

    let again = post(&w, &token_a, body.clone()).await;
    assert_eq!(again["write_outcome"], "unchanged", "{again}");
    assert_eq!(
        beta(&w.pool, w.claim).await,
        after_first,
        "an unchanged resubmission must not apply the Beta update again"
    );
    assert_eq!(
        again["bayesian_posterior"].as_f64(),
        Some(posterior),
        "an unchanged resubmission reports the posterior it left: {again}"
    );
    assert!(
        warnings(&again)
            .iter()
            .any(|x| x.contains("bayesian_posterior did not move")),
        "the unchanged warning says the posterior did not move: {again}"
    );

    // A replacement stores a different BBA and moves the track by the
    // difference (backlog 862d8404): the replaced BBA's increment is withdrawn
    // and the new one's added, so the claim holds the new BBA's evidence only.
    // m({h0}) = 0.7 at reliability 0.5 is 0.35, the rest (0.65) on Θ.
    let mut replaced = body;
    replaced["reliability"] = serde_json::json!(0.5);
    let replaced = post(&w, &token_a, replaced).await;
    assert_eq!(replaced["write_outcome"], "replaced", "{replaced}");
    let (alpha, beta_) = beta(&w.pool, w.claim).await;
    assert!(
        (alpha - 1.35).abs() < 1e-12 && (beta_ - 1.65).abs() < 1e-12,
        "a replaced BBA's Beta increment is withdrawn: Beta(1.35, 1.65), got ({alpha}, {beta_})"
    );
}

/// POST the evidence and return the status and the raw body, whatever it is.
async fn post_raw(w: &World, token: &str, body: Value) -> (u16, String) {
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{}/api/v1/frames/{}/evidence",
            w.addr, w.frame
        ))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    (status, resp.text().await.expect("body"))
}

/// Backlog 2b992740: two `masses` keys that name the same focal element
/// (`"0,1"` and `"1,0"`, `"0"` and `" 0"`, `"0"` and `"0,0"`) are refused with
/// a 400 naming `masses`, and nothing is stored, as MCP `submit_ds_evidence`
/// refuses them. At origin/main the route's inline parser let the later key
/// silently replace the earlier one, so each body below (whose raw masses sum
/// to 1.5) collapsed to a valid BBA summing to 1 and was stored as a 201: a
/// BBA different from the one sent.
#[sqlx::test(migrations = "../../migrations")]
async fn colliding_mass_keys_are_refused_and_nothing_is_stored(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let seed = pool_opts
        .clone()
        .connect_with(conn_opts.clone())
        .await
        .expect("seed pool");
    let (a, group_a) = fixture::seed_agent_with_group(&seed, "2b992740-a").await;
    let w = world(pool_opts, conn_opts, a, group_a).await;
    let token_a = common::mint_token_with_agent(&["claims:write"], a);

    for masses in [
        serde_json::json!({"0": 0.5, "0,1": 0.5, "1,0": 0.5}),
        serde_json::json!({"1": 0.5, "0": 0.5, " 0": 0.5}),
        serde_json::json!({"1": 0.5, "0": 0.5, "0,0": 0.5}),
    ] {
        let (status, text) = post_raw(
            &w,
            &token_a,
            serde_json::json!({"claim_id": w.claim, "reliability": 1.0, "masses": masses}),
        )
        .await;
        assert_eq!(
            status, 400,
            "colliding keys {masses} must be refused, got {status}: {text}"
        );
        assert!(
            text.contains("masses") && text.contains("same focal element"),
            "the refusal names the field and the collision: {text}"
        );
    }
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE claim_id = $1")
        .bind(w.claim)
        .fetch_one(&w.pool)
        .await
        .expect("count BBAs");
    assert_eq!(stored, 0, "a refused request stores no BBA");
    let linked: i64 = sqlx::query_scalar("SELECT count(*) FROM claim_frames WHERE claim_id = $1")
        .bind(w.claim)
        .fetch_one(&w.pool)
        .await
        .expect("count frame links");
    assert_eq!(linked, 0, "a refused request links no frame");

    // CALIBRATION: the same focal elements given once each are accepted, so
    // the refusals above are about the collision and nothing else.
    let ok = post(
        &w,
        &token_a,
        serde_json::json!({"claim_id": w.claim, "reliability": 1.0,
                           "masses": {"0": 0.5, "1,0": 0.5}}),
    )
    .await;
    assert_eq!(ok["write_outcome"], "inserted", "{ok}");
}

/// Assign the test claim to hypothesis 0 of the test frame.
async fn assign_hypothesis_zero(w: &World) {
    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, 0)",
    )
    .bind(w.claim)
    .bind(w.frame)
    .execute(&w.pool)
    .await
    .expect("assign the claim to hypothesis 0");
}

fn assert_beta(got: (f64, f64), want: (f64, f64), what: &str) {
    assert!(
        (got.0 - want.0).abs() < 1e-12 && (got.1 - want.1).abs() < 1e-12,
        "{what}: want Beta{want:?}, got Beta{got:?}"
    );
}

/// Backlog 862d8404: a write that REPLACES the caller's earlier BBA moves the
/// Beta track by the difference between the two, never by the new BBA alone.
///
/// - Replacing a BBA with the same masses (only `evidence_type` differs, so
///   the write is a genuine replacement, not `unchanged`) leaves the track and
///   `bayesian_posterior` where they were.
/// - Replacing it with different masses leaves the track a fresh claim holding
///   only the new BBA has.
///
/// At origin/main the route added the new BBA's full increment on every
/// replacement and withdrew nothing: the first arm moved Beta(1.56, 1.44) to
/// Beta(2.12, 1.88), and each revision of one source's evidence counted as new
/// independent evidence.
#[sqlx::test(migrations = "../../migrations")]
async fn a_replaced_bba_moves_the_beta_track_by_the_difference_only(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let seed = pool_opts
        .clone()
        .connect_with(conn_opts.clone())
        .await
        .expect("seed pool");
    let (a, group_a) = fixture::seed_agent_with_group(&seed, "862d8404-a").await;
    let w = world(pool_opts, conn_opts, a, group_a).await;
    assign_hypothesis_zero(&w).await;
    let token_a = common::mint_token_with_agent(&["claims:write"], a);
    // Stored (reliability 0.8): m({h0}) = 0.56, m(Θ) = 0.44.
    let body = serde_json::json!({
        "claim_id": w.claim, "reliability": 0.8, "evidence_type": "statistical",
        "masses": {"0": 0.7, "0,1": 0.3},
    });
    let first = post(&w, &token_a, body.clone()).await;
    assert_eq!(first["write_outcome"], "inserted", "{first}");
    assert_beta(beta(&w.pool, w.claim).await, (1.56, 1.44), "first write");
    let posterior = first["bayesian_posterior"].as_f64().expect("posterior");

    let mut retyped = body.clone();
    retyped["evidence_type"] = serde_json::json!("testimonial");
    let retyped = post(&w, &token_a, retyped).await;
    assert_eq!(retyped["write_outcome"], "replaced", "{retyped}");
    assert_beta(
        beta(&w.pool, w.claim).await,
        (1.56, 1.44),
        "a BBA replaced by the same masses leaves the track where it was",
    );
    let after = retyped["bayesian_posterior"].as_f64().expect("posterior");
    assert!(
        (after - posterior).abs() < 1e-12,
        "and bayesian_posterior with it: {posterior} -> {after}"
    );

    // Different masses: m({h0}) = 0.2 at reliability 1, the rest on Θ.
    let other = post(
        &w,
        &token_a,
        serde_json::json!({"claim_id": w.claim, "reliability": 1.0,
                           "evidence_type": "testimonial",
                           "masses": {"0": 0.2, "0,1": 0.8}}),
    )
    .await;
    assert_eq!(other["write_outcome"], "replaced", "{other}");
    assert_beta(
        beta(&w.pool, w.claim).await,
        (1.2, 1.8),
        "a replaced track holds only the new BBA, as a fresh claim would",
    );
    let reported = other["bayesian_posterior"].as_f64().expect("posterior");
    assert!(
        (reported - 1.2 / 3.0).abs() < 1e-12,
        "the reported posterior is the fresh-claim one: {reported}"
    );
}

/// The guard on backlog 862d8404's withdrawal: a replaced row that the Beta
/// track never counted withdraws nothing. `submit_claim`'s seed wire stores its
/// BBA in the author's slot with no perspective (`combination_method =
/// 'auto_wire'`) and keeps no Beta track, so the author's first evidence on
/// that slot replaces it. Withdrawing the seed would take out mass that was
/// never added; the track must end as a fresh claim holding only the new BBA.
/// (This holds at origin/main, which withdrew nothing at all; it pins that the
/// withdrawal is limited to the writers that count.)
#[sqlx::test(migrations = "../../migrations")]
async fn replacing_an_uncounted_seed_bba_withdraws_nothing(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let seed = pool_opts
        .clone()
        .connect_with(conn_opts.clone())
        .await
        .expect("seed pool");
    let (a, group_a) = fixture::seed_agent_with_group(&seed, "862d8404-seed").await;
    let w = world(pool_opts, conn_opts, a, group_a).await;
    assign_hypothesis_zero(&w).await;
    epigraph_db::MassFunctionRepository::store_with_perspective(
        &w.pool,
        w.claim,
        w.frame,
        Some(a),
        None,
        &serde_json::json!({"0": 0.9, "0,1": 0.1}),
        None,
        Some("auto_wire"),
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("seed the author's auto_wire BBA");
    let token_a = common::mint_token_with_agent(&["claims:write"], a);

    let out = post(
        &w,
        &token_a,
        serde_json::json!({"claim_id": w.claim, "reliability": 1.0,
                           "masses": {"0": 0.2, "0,1": 0.8}}),
    )
    .await;
    assert_eq!(out["write_outcome"], "replaced", "{out}");
    assert_beta(
        beta(&w.pool, w.claim).await,
        (1.2, 1.8),
        "an uncounted seed's mass is not withdrawn",
    );
}

/// The floor under backlog 862d8404's withdrawal: a replaced row from a
/// counting writer that the track nonetheless never counted (an MCP
/// `submit_ds_evidence` row stored before the MCP paths kept the track) can
/// withdraw more than the track holds. Each parameter stays at or above the
/// prior's 1.0: here alpha would be 1 + 0.2 - 0.9 = 0.3 without the floor.
#[sqlx::test(migrations = "../../migrations")]
async fn a_withdrawal_never_takes_the_track_below_the_prior(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let seed = pool_opts
        .clone()
        .connect_with(conn_opts.clone())
        .await
        .expect("seed pool");
    let (a, group_a) = fixture::seed_agent_with_group(&seed, "862d8404-floor").await;
    let w = world(pool_opts, conn_opts, a, group_a).await;
    assign_hypothesis_zero(&w).await;
    epigraph_db::MassFunctionRepository::store_with_perspective(
        &w.pool,
        w.claim,
        w.frame,
        Some(a),
        None,
        &serde_json::json!({"0": 0.9, "0,1": 0.1}),
        None,
        Some("Dempster"),
        None,
        None,
        "unknown",
        None,
    )
    .await
    .expect("seed an uncounted MCP-shaped BBA in the author's slot");
    let token_a = common::mint_token_with_agent(&["claims:write"], a);

    let out = post(
        &w,
        &token_a,
        serde_json::json!({"claim_id": w.claim, "reliability": 1.0,
                           "masses": {"0": 0.2, "0,1": 0.8}}),
    )
    .await;
    assert_eq!(out["write_outcome"], "replaced", "{out}");
    assert_beta(
        beta(&w.pool, w.claim).await,
        (1.0, 1.7),
        "alpha is held at the prior; beta moves by 0.8 - 0.1",
    );
}

/// Backlog 1ce62137: a REST evidence write on a claim with no frame link links
/// it at hypothesis_index 0 (what every belief read resolves a missing index
/// to), so the write moves the claim's Beta track and the next write records a
/// divergence row. No `claim_frames` row is seeded here.
///
/// At origin/main the route linked the claim with a NULL index, which
/// `beta_increments` counts as nothing: the claim stayed at Beta(1, 1), every
/// later update was a cold start, and no divergence row was ever written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_rest_write_on_an_unlinked_claim_moves_beta_and_then_records_divergence(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let seed = pool_opts
        .clone()
        .connect_with(conn_opts.clone())
        .await
        .expect("seed pool");
    let (a, group_a) = fixture::seed_agent_with_group(&seed, "1ce62137-a").await;
    let w = world(pool_opts, conn_opts, a, group_a).await;
    let token_a = common::mint_token_with_agent(&["claims:write"], a);
    let body = serde_json::json!({
        "claim_id": w.claim, "reliability": 1.0, "masses": {"0": 0.7, "0,1": 0.3},
    });

    let first = post(&w, &token_a, body.clone()).await;
    assert_eq!(first["write_outcome"], "inserted", "{first}");
    assert_beta(
        beta(&w.pool, w.claim).await,
        (1.7, 1.3),
        "the first write moves the track",
    );
    let index: Option<i32> = sqlx::query_scalar(
        "SELECT hypothesis_index FROM claim_frames WHERE claim_id = $1 AND frame_id = $2",
    )
    .bind(w.claim)
    .bind(w.frame)
    .fetch_one(&w.pool)
    .await
    .expect("the write links the claim to the frame");
    assert_eq!(index, Some(0), "a new link names hypothesis 0");

    // A second, independent BBA (an Inserted write under a perspective the
    // caller owns, its confidence calibration cleared): the track is no longer
    // at the prior, so this write records the claim's divergence.
    let perspective: Uuid = sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id, confidence_calibration) \
         VALUES ($1, $2, NULL) RETURNING id",
    )
    .bind(format!("1ce62137-p-{}", Uuid::new_v4()))
    .bind(a)
    .fetch_one(&w.pool)
    .await
    .expect("seed perspective");
    let mut second = body;
    second["perspective_id"] = serde_json::json!(perspective);
    let second = post(&w, &token_a, second).await;
    assert_eq!(second["write_outcome"], "inserted", "{second}");
    assert_beta(
        beta(&w.pool, w.claim).await,
        (2.4, 1.6),
        "the second write adds its own increment",
    );
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM ds_bayesian_divergence WHERE claim_id = $1")
            .bind(w.claim)
            .fetch_one(&w.pool)
            .await
            .expect("count divergence rows");
    assert_eq!(rows, 1, "the second write records one divergence row");
}

async fn divergence_count(w: &World) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM ds_bayesian_divergence WHERE claim_id = $1")
        .bind(w.claim)
        .fetch_one(&w.pool)
        .await
        .expect("count divergence rows")
}

/// Backlog 862d8404's change to the cold-start rule: a replacement whose
/// withdrawal leaves the track holding only the new BBA has no other evidence
/// to diverge from, so it is a cold start and records no divergence row, as a
/// fresh claim's first write does.
///
/// At origin/main the replacement counted the new BBA on top of the replaced
/// one, so the track was no longer at the prior and the replacement recorded
/// a divergence row against evidence that was the caller's own, revised.
#[sqlx::test(migrations = "../../migrations")]
async fn a_replacement_that_leaves_only_the_new_bba_records_no_divergence(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let seed = pool_opts
        .clone()
        .connect_with(conn_opts.clone())
        .await
        .expect("seed pool");
    let (a, group_a) = fixture::seed_agent_with_group(&seed, "862d8404-cold").await;
    let w = world(pool_opts, conn_opts, a, group_a).await;
    assign_hypothesis_zero(&w).await;
    let token_a = common::mint_token_with_agent(&["claims:write"], a);

    let first = post(
        &w,
        &token_a,
        serde_json::json!({"claim_id": w.claim, "reliability": 1.0,
                           "masses": {"0": 0.7, "0,1": 0.3}}),
    )
    .await;
    assert_eq!(first["write_outcome"], "inserted", "{first}");
    let replaced = post(
        &w,
        &token_a,
        serde_json::json!({"claim_id": w.claim, "reliability": 1.0,
                           "masses": {"0": 0.2, "0,1": 0.8}}),
    )
    .await;
    assert_eq!(replaced["write_outcome"], "replaced", "{replaced}");
    assert_beta(
        beta(&w.pool, w.claim).await,
        (1.2, 1.8),
        "the track holds only the new BBA",
    );
    assert_eq!(
        divergence_count(&w).await,
        0,
        "a replacement leaving only its own BBA on the track is a cold start"
    );
}

/// The converse: a replacement on a track that also holds OTHER evidence (an
/// independent BBA under a perspective the caller owns) is not a cold start.
/// It records a divergence row, and the track holds the other evidence plus
/// the new BBA. (This holds at origin/main too, where every write after the
/// first recorded a row; it pins that the withdrawal does not make every
/// replacement cold. Mutation-proved: treating any write that withdraws as a
/// cold start fails it.)
#[sqlx::test(migrations = "../../migrations")]
async fn a_replacement_beside_other_evidence_records_divergence(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let seed = pool_opts
        .clone()
        .connect_with(conn_opts.clone())
        .await
        .expect("seed pool");
    let (a, group_a) = fixture::seed_agent_with_group(&seed, "862d8404-warm").await;
    let w = world(pool_opts, conn_opts, a, group_a).await;
    assign_hypothesis_zero(&w).await;
    let token_a = common::mint_token_with_agent(&["claims:write"], a);
    let perspective: Uuid = sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id, confidence_calibration) \
         VALUES ($1, $2, NULL) RETURNING id",
    )
    .bind(format!("862d8404-warm-p-{}", Uuid::new_v4()))
    .bind(a)
    .fetch_one(&w.pool)
    .await
    .expect("seed perspective");

    let other = post(
        &w,
        &token_a,
        serde_json::json!({"claim_id": w.claim, "reliability": 1.0,
                           "perspective_id": perspective,
                           "masses": {"0": 0.6, "0,1": 0.4}}),
    )
    .await;
    assert_eq!(other["write_outcome"], "inserted", "{other}");
    let first = post(
        &w,
        &token_a,
        serde_json::json!({"claim_id": w.claim, "reliability": 1.0,
                           "masses": {"0": 0.7, "0,1": 0.3}}),
    )
    .await;
    assert_eq!(first["write_outcome"], "inserted", "{first}");
    assert_eq!(
        divergence_count(&w).await,
        1,
        "the second BBA records a row"
    );

    let replaced = post(
        &w,
        &token_a,
        serde_json::json!({"claim_id": w.claim, "reliability": 1.0,
                           "masses": {"0": 0.2, "0,1": 0.8}}),
    )
    .await;
    assert_eq!(replaced["write_outcome"], "replaced", "{replaced}");
    assert_beta(
        beta(&w.pool, w.claim).await,
        (1.8, 2.2),
        "the other evidence plus the new BBA",
    );
    assert_eq!(
        divergence_count(&w).await,
        2,
        "a replacement beside other evidence records its divergence"
    );
}
