//! `POST /api/v1/frames/:id/evidence` must leave the claim where the shared
//! belief pipeline would put it (backlogs 2bffdfdc / I075 and 82dcff9d / I228,
//! REST twins of the MCP fixes in #317 and #513).
//!
//! The MCP `submit_ds_evidence` delegates its combine and cache write to
//! `epigraph_engine::edge_factor::recompute_claim_belief_on_frame`, the same
//! function `recompute_beliefs` and the framed `get_belief` use, so on MCP a
//! submit and a later recompute agree by construction. The REST handler ran
//! its own combine (only `'discount'` rows, independence analysis, the
//! caller's threshold), wrote the cache unattributed (`belief_frame_id` NULL),
//! stored its pre-discounted masses with `source_strength = reliability` (which
//! the shared pipeline discounts AGAIN), and stored the combined result back
//! as an agent-less "cached combination" row beside the inputs.
//!
//! Since b5cb3efb (#584) the combine-input readers no longer fold a LABELLED
//! cached row back in, so on main a recompute of agent-attributed, fully
//! reliable inputs no longer drifts. What main still gets wrong, and what these
//! tests pin:
//! * a derived row is stored beside the inputs, and `total_sources` counts it;
//! * the cache carries no `belief_frame_id`;
//! * `reliability` < 1 is applied twice (stored masses AND `source_strength`);
//! * an input another transport stored (not labelled `'discount'`) is ignored
//!   by the response;
//! * an unreadable claim is answered with 201 and a stored BBA;
//! * the deprecated combination parameters are silently ignored.
//!
//! Every test here asserts STORED state (rows, the claims cache after a
//! no-new-evidence recompute) or a hand-computed Dempster value, never the
//! response against a function the response was itself computed from.
//!
//! These run on the superuser harness, so RLS is bypassed; the application
//! role's paths are `frames_evidence_app_role.rs`.
//!
//! `#[sqlx::test]` gives each test an ephemeral database.
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

/// The app on the per-test database (not `DATABASE_URL`'s), built from a
/// `ScopedPool` so the handler's stamped write transaction is available.
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
    /// The claim's author, owning the claim through its personal group.
    agent_a: Uuid,
    token_a: String,
    claim: Uuid,
    frame: Uuid,
}

async fn world(pool_opts: PgPoolOptions, conn_opts: PgConnectOptions) -> World {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let (agent_a, group_a) = fixture::seed_agent_with_group(&pool, "u024-a").await;

    let claim = Uuid::new_v4();
    let hash: Vec<u8> = claim.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, visibility, \
                             owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, 'public', $5)",
    )
    .bind(claim)
    .bind(format!("u024 parity claim {claim}"))
    .bind(hash)
    .bind(agent_a)
    .bind(group_a)
    .execute(&pool)
    .await
    .expect("seed claim");

    let frame = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO frames (id, name, hypotheses) VALUES ($1, $2, ARRAY['h0','h1']::text[])",
    )
    .bind(frame)
    .bind(format!("u024-parity-frame-{frame}"))
    .execute(&pool)
    .await
    .expect("seed frame");

    let (addr, shutdown) = spawn_app(&conn_opts).await;
    let token_a = common::mint_token_with_agent(&["claims:write"], agent_a);
    World {
        pool,
        addr,
        _shutdown: shutdown,
        agent_a,
        token_a,
        claim,
        frame,
    }
}

/// POST the evidence and return the status and the body text.
async fn post_evidence_raw(w: &World, token: &str, body: Value) -> (u16, String) {
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

/// POST the evidence and insist on 201, printing the body otherwise so a 401
/// or 500 can never pose as the behaviour under test.
async fn post_evidence(w: &World, token: &str, body: Value) -> Value {
    let (status, text) = post_evidence_raw(w, token, body).await;
    assert_eq!(status, 201, "POST evidence must be 201: {text}");
    serde_json::from_str(&text).expect("json body")
}

async fn bba_rows(w: &World) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE claim_id = $1 AND frame_id = $2")
        .bind(w.claim)
        .bind(w.frame)
        .fetch_one(&w.pool)
        .await
        .expect("count BBAs")
}

async fn cached(w: &World) -> (Option<f64>, Option<Uuid>) {
    sqlx::query_as("SELECT belief, belief_frame_id FROM claims WHERE id = $1")
        .bind(w.claim)
        .fetch_one(&w.pool)
        .await
        .expect("read the cache")
}

/// Recompute the claim on the frame with no new evidence, the maintenance way
/// (`recompute_beliefs`), and return the cached belief it leaves.
async fn recompute(w: &World) -> f64 {
    let (_scoped, viewer) = fixture::bypass(&w.pool).await;
    let mut conn = w.pool.acquire().await.expect("acquire");
    let wrote = epigraph_engine::edge_factor::recompute_claim_belief_on_frame(
        &mut conn, &viewer, w.claim, w.frame,
    )
    .await
    .expect("recompute");
    assert!(
        wrote,
        "the claim has BBAs on the frame, so recompute writes"
    );
    drop(conn);
    cached(w).await.0.expect("belief after recompute")
}

fn reports(resp: &Value) -> &Vec<Value> {
    resp["combination_reports"]
        .as_array()
        .unwrap_or_else(|| panic!("combination_reports must be an array: {resp}"))
}

/// I075's literal symptom: a submit's belief must already be the shared
/// pipeline's fixpoint, and nothing derived may be stored to get there. On
/// main the handler stores a second, agent-less "cached combination" row
/// beside the input (2 rows) and leaves `belief_frame_id` NULL. (Before
/// b5cb3efb a recompute with no new evidence also folded that row back in and
/// moved the belief from 0.60 to 0.72.)
#[sqlx::test(migrations = "../../migrations")]
async fn rest_evidence_leaves_the_claim_at_the_shared_pipelines_fixpoint(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;
    let resp = post_evidence(
        &w,
        &w.token_a,
        serde_json::json!({
            "claim_id": w.claim,
            "agent_id": w.agent_a,
            "reliability": 1.0,
            "masses": {"0": 0.6, "0,1": 0.4},
        }),
    )
    .await;

    assert_eq!(
        bba_rows(&w).await,
        1,
        "one submission is one BBA; no derived combined row may be stored beside it"
    );
    let (b1, frame_of_cache) = cached(&w).await;
    let b1 = b1.expect("the submit wrote the claim's cache");
    assert_eq!(
        frame_of_cache,
        Some(w.frame),
        "the cache must record the frame whose combination it holds"
    );
    let b2 = recompute(&w).await;
    assert!(
        (b2 - b1).abs() < EPS,
        "a recompute with no new evidence must not move the belief: submit left {b1}, \
         recompute gives {b2}"
    );
    assert!(
        (b2 - 0.6).abs() < EPS,
        "one fully reliable BBA with m({{0}}) = 0.6 has Bel = 0.6; got {b2}"
    );
    let reported = resp["updated_belief"].as_f64().expect("updated_belief");
    assert!(
        (reported - b2).abs() < EPS,
        "the response must report the belief the store holds: {reported} vs {b2}"
    );
    assert!(
        reports(&resp).is_empty(),
        "a single BBA is not folded, so there is no combination step to report: {resp}"
    );
    assert_eq!(resp["total_sources"], 1, "one BBA: {resp}");
}

/// Two independent agents, Dempster with K = 0: Bel = 1 - 0.4 * 0.5 = 0.80,
/// both in the second response and after a recompute. On main the response
/// and the recompute agree at 0.80 since b5cb3efb, but the handler stores a
/// derived row beside the two inputs and `total_sources` counts it (3).
#[sqlx::test(migrations = "../../migrations")]
async fn two_agents_combine_to_the_hand_computed_belief(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;
    let (agent_b, _) = fixture::seed_agent_with_group(&w.pool, "u024-b").await;
    let token_b = common::mint_token_with_agent(&["claims:write"], agent_b);

    post_evidence(
        &w,
        &w.token_a,
        serde_json::json!({
            "claim_id": w.claim, "agent_id": w.agent_a, "reliability": 1.0,
            "masses": {"0": 0.6, "0,1": 0.4},
        }),
    )
    .await;
    let resp = post_evidence(
        &w,
        &token_b,
        serde_json::json!({
            "claim_id": w.claim, "agent_id": agent_b, "reliability": 1.0,
            "masses": {"0": 0.5, "0,1": 0.5},
        }),
    )
    .await;

    let reported = resp["updated_belief"].as_f64().expect("updated_belief");
    assert!(
        (reported - 0.8).abs() < EPS,
        "Dempster of m1({{0}})=0.6 and m2({{0}})=0.5 is 0.80; response said {reported}"
    );
    assert_eq!(
        resp["total_sources"], 2,
        "two submissions, two BBAs: {resp}"
    );
    assert_eq!(bba_rows(&w).await, 2, "two BBAs stored, nothing derived");
    let reps = reports(&resp);
    assert_eq!(reps.len(), 1, "one Dempster fold of the two inputs: {resp}");
    assert_eq!(reps[0]["method_used"], "Dempster", "{resp}");
    let k = reps[0]["conflict_k"].as_f64().expect("conflict_k");
    assert!(
        k.abs() < EPS,
        "{{0}} and Θ never intersect empty, so K = 0; got {k}"
    );
    let after = recompute(&w).await;
    assert!(
        (after - 0.8).abs() < EPS,
        "recompute over the same two BBAs must stay at 0.80; got {after}"
    );
}

/// `reliability` is applied exactly once. The stored masses are the
/// discounted ones, and the shared pipeline must not discount them again. On
/// main the row carries `source_strength = 0.8`, which an untyped row's
/// `effective_source_strength` (tier 1) applies a second time: 0.64.
#[sqlx::test(migrations = "../../migrations")]
async fn reliability_is_applied_once(pool_opts: PgPoolOptions, conn_opts: PgConnectOptions) {
    let w = world(pool_opts, conn_opts).await;
    let resp = post_evidence(
        &w,
        &w.token_a,
        serde_json::json!({
            "claim_id": w.claim, "agent_id": w.agent_a, "reliability": 0.8,
            "masses": {"0": 1.0},
        }),
    )
    .await;

    let stored: f64 = sqlx::query_scalar(
        "SELECT (masses->>'0')::float8 FROM mass_functions \
          WHERE claim_id = $1 AND frame_id = $2 AND source_agent_id = $3",
    )
    .bind(w.claim)
    .bind(w.frame)
    .bind(w.agent_a)
    .fetch_one(&w.pool)
    .await
    .expect("the caller's BBA");
    assert!(
        (stored - 0.8).abs() < EPS,
        "the stored BBA is the reliability-discounted one: m({{0}}) = 0.8, got {stored}"
    );
    let reported = resp["updated_belief"].as_f64().expect("updated_belief");
    assert!(
        (reported - 0.8).abs() < EPS,
        "response belief must be 0.80, got {reported}"
    );
    let after = recompute(&w).await;
    assert!(
        (after - 0.8).abs() < EPS,
        "a recompute must not apply the reliability a second time: expected 0.80, got {after}"
    );
}

/// The same, for a TYPED row whose type is not calibrated, which is what the
/// in-tree caller `scripts/lib/nli_stance.py` sends
/// (`evidence_type = "nli_cross_encoder"`, absent from `calibration.toml`).
/// `effective_source_strength` then falls to tier 4, which also returns the
/// stored `source_strength`: on main 0.8, so a recompute gives 0.64.
#[sqlx::test(migrations = "../../migrations")]
async fn reliability_is_applied_once_on_an_uncalibrated_type(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;
    let resp = post_evidence(
        &w,
        &w.token_a,
        serde_json::json!({
            "claim_id": w.claim, "agent_id": w.agent_a, "reliability": 0.8,
            "evidence_type": "nli_cross_encoder",
            "masses": {"0": 1.0},
        }),
    )
    .await;

    let (m0, strength, etype): (f64, Option<f64>, Option<String>) = sqlx::query_as(
        "SELECT (masses->>'0')::float8, source_strength, evidence_type FROM mass_functions \
          WHERE claim_id = $1 AND frame_id = $2 AND source_agent_id = $3",
    )
    .bind(w.claim)
    .bind(w.frame)
    .bind(w.agent_a)
    .fetch_one(&w.pool)
    .await
    .expect("the caller's BBA");
    assert!(
        (m0 - 0.8).abs() < EPS,
        "the stored BBA is the reliability-discounted one: m({{0}}) = 0.8, got {m0}"
    );
    assert_eq!(
        strength,
        Some(1.0),
        "the reliability is already in the masses, so the row's own strength is 1.0"
    );
    assert_eq!(
        etype.as_deref(),
        Some("nli_cross_encoder"),
        "an uncalibrated type is stored as the caller's key, lowercased"
    );
    let reported = resp["updated_belief"].as_f64().expect("updated_belief");
    assert!(
        (reported - 0.8).abs() < EPS,
        "response belief must be 0.80, got {reported}"
    );
    let after = recompute(&w).await;
    assert!(
        (after - 0.8).abs() < EPS,
        "a recompute must not apply the reliability a second time: expected 0.80, got {after}"
    );
}

/// I228's REST twin: `combination_method`, `gamma` and `assume_independent`
/// are accepted but do not change the belief, and the caller is told so.
#[sqlx::test(migrations = "../../migrations")]
async fn deprecated_combination_parameters_are_reported(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;
    let resp = post_evidence(
        &w,
        &w.token_a,
        serde_json::json!({
            "claim_id": w.claim, "agent_id": w.agent_a, "reliability": 1.0,
            "masses": {"0": 0.6, "0,1": 0.4},
            "combination_method": "yager_open",
            "gamma": 0.5,
            "assume_independent": true,
        }),
    )
    .await;

    let warnings: Vec<String> = resp["warnings"]
        .as_array()
        .unwrap_or_else(|| {
            panic!("`warnings` must be present when deprecated fields are sent: {resp}")
        })
        .iter()
        .map(|v| v.as_str().expect("warning string").to_string())
        .collect();
    let names = |needle: &str| {
        warnings
            .iter()
            .any(|m| m.contains(needle) && m.contains("deprecated"))
    };
    assert!(
        names("combination_method=yager_open"),
        "combination_method: {warnings:?}"
    );
    assert!(names("gamma=0.5"), "gamma: {warnings:?}");
    assert!(
        names("assume_independent"),
        "assume_independent: {warnings:?}"
    );

    // And a plain submission earns no deprecated-parameter warning. It restates
    // the BBA stored above (the deprecated fields change nothing stored), so
    // its one warning is the write outcome's (backlog 6f82db4f).
    let plain = post_evidence(
        &w,
        &w.token_a,
        serde_json::json!({
            "claim_id": w.claim, "agent_id": w.agent_a, "reliability": 1.0,
            "masses": {"0": 0.6, "0,1": 0.4},
        }),
    )
    .await;
    assert_eq!(plain["write_outcome"], "unchanged", "{plain}");
    let plain_warnings: Vec<&str> = plain["warnings"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    assert!(
        plain_warnings.len() == 1 && plain_warnings[0].contains("identical"),
        "no deprecated field, no deprecated warning; only the restatement's: {plain}"
    );
}

/// A claim the caller cannot read gets the same 404 a nonexistent one gets,
/// and nothing is stored: the route is no existence oracle. On main the
/// handler stores the BBA on the unreadable claim and answers 201.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unreadable_claim_is_not_found_and_nothing_is_stored(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;
    let (agent_b, group_b) = fixture::seed_agent_with_group(&w.pool, "u024-private").await;
    let private = fixture::seed_group_claim(&w.pool, agent_b, group_b, "u024 private claim").await;

    let (status, text) = post_evidence_raw(
        &w,
        &w.token_a,
        serde_json::json!({
            "claim_id": private, "agent_id": w.agent_a, "reliability": 1.0,
            "masses": {"0": 0.6, "0,1": 0.4},
        }),
    )
    .await;
    assert_eq!(
        status, 404,
        "an unreadable claim must read as absent: {text}"
    );
    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions WHERE claim_id = $1 AND frame_id = $2",
    )
    .bind(private)
    .bind(w.frame)
    .fetch_one(&w.pool)
    .await
    .expect("count BBAs");
    assert_eq!(
        rows, 0,
        "nothing may be stored on a claim the caller cannot read"
    );
}

/// The response folds EVERY input on (claim, frame), not only the
/// `'discount'` rows REST itself writes: an input another transport stored
/// (MCP `submit_ds_evidence` labels its rows `"Dempster"`, with its agent)
/// counts too. On main the response ignores it (0.60, from the REST row
/// alone), while a recompute folds it: the two disagree.
#[sqlx::test(migrations = "../../migrations")]
async fn an_input_from_another_transport_counts_toward_the_response(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;
    let (agent_c, _) = fixture::seed_agent_with_group(&w.pool, "u024-mcp").await;
    epigraph_db::MassFunctionRepository::store_with_perspective(
        &w.pool,
        w.claim,
        w.frame,
        Some(agent_c),
        None,
        &serde_json::json!({"0": 0.5, "0,1": 0.5}),
        None,
        Some("Dempster"),
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("seed an MCP-shaped input");

    let resp = post_evidence(
        &w,
        &w.token_a,
        serde_json::json!({
            "claim_id": w.claim, "agent_id": w.agent_a, "reliability": 1.0,
            "masses": {"0": 0.6, "0,1": 0.4},
        }),
    )
    .await;
    let reported = resp["updated_belief"].as_f64().expect("updated_belief");
    assert!(
        (reported - 0.8).abs() < EPS,
        "Dempster of the seeded m({{0}})=0.5 and the posted m({{0}})=0.6 is 0.80; \
         response said {reported}"
    );
    assert_eq!(resp["total_sources"], 2, "both inputs count: {resp}");
    let after = recompute(&w).await;
    assert!(
        (after - reported).abs() < EPS,
        "the response is the recompute's value: {reported} vs {after}"
    );
}

/// A legacy cached combination row (agent-less, perspective-less, labelled
/// `"Dempster"`: the shape of the ~15.5k rows the writers left on prod) is not
/// an input. The combine-input readers exclude it (b5cb3efb), so beside one
/// real input the response must report ONE source and no fold. On main
/// `total_sources` counts every row on the pair (2).
#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_cached_combination_row_is_not_a_source(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;
    epigraph_db::MassFunctionRepository::store(
        &w.pool,
        w.claim,
        w.frame,
        None,
        &serde_json::json!({"0": 0.9, "0,1": 0.1}),
        Some(0.0),
        Some("Dempster"),
        None,
        "unknown",
        None,
    )
    .await
    .expect("seed a legacy cached combination row");

    let resp = post_evidence(
        &w,
        &w.token_a,
        serde_json::json!({
            "claim_id": w.claim, "agent_id": w.agent_a, "reliability": 1.0,
            "masses": {"0": 0.6, "0,1": 0.4},
        }),
    )
    .await;
    assert_eq!(
        resp["total_sources"], 1,
        "the cached row is not a source: {resp}"
    );
    assert!(
        reports(&resp).is_empty(),
        "one input is not folded, whatever cached row sits beside it: {resp}"
    );
    let reported = resp["updated_belief"].as_f64().expect("updated_belief");
    assert!(
        (reported - 0.6).abs() < EPS,
        "the cached row's m({{0}}) = 0.9 must not be folded in: {reported}"
    );
}
