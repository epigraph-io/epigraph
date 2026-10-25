//! An agent-less, perspective-less INPUT and the writers' cached combination
//! must not erase each other (backlog b5cb3efb).
//!
//! `mass_functions` is unique on (claim, frame, source_agent_id,
//! perspective_id) `NULLS NOT DISTINCT` (migration 034), so a pair has ONE
//! agent-less, perspective-less slot. Two writers put an input there:
//! * `POST /api/v1/claims/:id/assess` stored its input BBA with no agent and
//!   no perspective until U027 (it now keys each input by its own evidence
//!   perspective and stores no cached row, so the arms below pin that it
//!   still folds exactly once);
//! * `POST /api/v1/frames/:id/evidence` did when the body omitted both
//!   `agent_id` and `perspective_id`. Since the 2026-10-22 ruling ("Evidence
//!   shouldn't be able to have no agent_id") an omitted `agent_id` is the
//!   caller's own, so `/evidence` no longer writes that slot; the arm below
//!   pins that such an input is the caller's and still folds exactly once.
//!
//! Both handlers used to cache their fold result in that same slot, which
//! overwrote the input. Since U024 `/evidence` caches nothing (it delegates to
//! the shared recompute), so only `/assess` still has a guarded cache store,
//! and its own input always holds the slot. Once the combine-input readers
//! exclude cached rows,
//! the input written to that slot would then disappear from every fold:
//! `recompute_claim_belief_on_frame` returns `Ok(false)`, and `get_belief`
//! reads vacuous. When the cache is not written over the input, the input
//! survives and is folded exactly once.
//!
//! Expected values come from the DS primitives over the rows that SHOULD be
//! folded, each discounted at the reliability `effective_source_strength`
//! gives the stored row. A row with no `evidence_type` keeps its stored
//! `source_strength`. That is 1.0 for an `/evidence` input submitted at
//! reliability 1.0. The `/assess` input stores none, so it falls back to 0.5.
//!
//! Its own binary because `/assess` reads `calibration.toml` relative to the
//! working directory, so this test moves the process to the workspace root
//! (as `assess_combined_cache_untyped.rs` does).
#![cfg(feature = "db")]

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_ds::{combination, measures, FrameOfDiscernment, MassFunction};
use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

use epigraph_engine::belief_query;
use epigraph_engine::edge_factor::{
    preview_claim_belief_on_frame, recompute_claim_belief_on_frame,
};

/// `effective_source_strength`'s fallback for a row with neither an
/// `evidence_type` nor a stored `source_strength`: the `/assess` input.
const UNTYPED_FALLBACK_RELIABILITY: f64 = 0.5;

/// The masses every `/evidence` submission below uses, at reliability 1.0.
fn agent_masses() -> Value {
    serde_json::json!({"0": 0.6, "0,1": 0.4})
}

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

/// A claim and a binary {TRUE, FALSE} frame, plus a running app on this
/// test's database.
struct World {
    pool: PgPool,
    owner: Uuid,
    claim: Uuid,
    frame: Uuid,
    addr: SocketAddr,
    _shutdown: oneshot::Sender<()>,
    client: reqwest::Client,
}

async fn world(pool_opts: PgPoolOptions, conn_opts: PgConnectOptions, tag: &str) -> World {
    // `/assess` loads `calibration.toml` from the working directory.
    std::env::set_current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
        .expect("cd to the workspace root");
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let owner = seed_agent(&pool).await;
    let claim: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
    )
    .bind(format!("b5cb3efb slot collision {tag} {}", Uuid::new_v4()))
    .bind(owner)
    .fetch_one(&pool)
    .await
    .expect("seed claim");
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['TRUE','FALSE']::text[]) \
         RETURNING id",
    )
    .bind(format!("b5cb3efb-slot-{tag}-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed frame");
    let (addr, shutdown) = spawn_app(&conn_opts).await;
    World {
        pool,
        owner,
        claim,
        frame,
        addr,
        _shutdown: shutdown,
        client: reqwest::Client::new(),
    }
}

impl World {
    /// `POST /api/v1/claims/:id/assess` on this world's frame; the input BBA
    /// the handler built (`bba` in the response).
    async fn assess(&self) -> Value {
        let token = common::mint_token_with_agent(&["claims:read", "claims:write"], self.owner);
        let resp = self
            .client
            .post(format!(
                "http://{}/api/v1/claims/{}/assess",
                self.addr, self.claim
            ))
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "evidence_type": "Observation",
                "methodology": "instrumental",
                "confidence": 0.8,
                "supports": true,
                "frame_id": self.frame,
            }))
            .send()
            .await
            .expect("assess request");
        let status = resp.status();
        let body: Value = resp.json().await.expect("json body");
        assert!(status.is_success(), "assess: {status} {body}");
        body["bba"].clone()
    }

    /// `POST /api/v1/frames/:id/evidence` with [`agent_masses`] at
    /// reliability 1.0. With `agent = None` the body carries neither
    /// `agent_id` nor `perspective_id`.
    async fn submit(&self, agent: Option<Uuid>) {
        let token = common::mint_token_with_agent(
            &["claims:read", "claims:write"],
            agent.unwrap_or(self.owner),
        );
        let mut body = serde_json::json!({
            "claim_id": self.claim,
            "masses": agent_masses(),
            "reliability": 1.0,
            "assume_independent": true,
        });
        if let Some(a) = agent {
            body["agent_id"] = serde_json::json!(a);
        }
        let resp = self
            .client
            .post(format!(
                "http://{}/api/v1/frames/{}/evidence",
                self.addr, self.frame
            ))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .expect("evidence request");
        let status = resp.status();
        let body: Value = resp.json().await.expect("json body");
        assert_eq!(status, 201, "POST evidence as {agent:?}: {body}");
    }

    /// Every fold reader's BetP(TRUE) for the pair, after a recompute that
    /// writes the claim cache. Panics if a reader sees no BBA: that is the
    /// erased-input failure itself.
    async fn fold_readers(&self) -> Vec<(&'static str, f64)> {
        let viewer = fixture::public_viewer(&self.pool).await;
        let mut conn = self.pool.acquire().await.expect("acquire");
        let preview = preview_claim_belief_on_frame(&mut conn, &viewer, self.claim, self.frame)
            .await
            .expect("preview")
            .unwrap_or_else(|| {
                panic!("preview_claim_belief_on_frame found no BBA: the input was erased")
            });
        assert!(
            recompute_claim_belief_on_frame(&mut conn, &viewer, self.claim, self.frame)
                .await
                .expect("recompute"),
            "recompute_claim_belief_on_frame found no BBA: the input was erased"
        );
        drop(conn);
        let cached: f64 = sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
            .bind(self.claim)
            .fetch_one(&self.pool)
            .await
            .expect("read cache");
        let framed = belief_query::get_belief(&self.pool, &viewer, self.claim, Some(self.frame))
            .await
            .expect("framed get_belief");
        vec![
            ("preview_claim_belief_on_frame", preview.pignistic_prob),
            ("recompute -> claims.pignistic_prob", cached),
            ("belief_query::get_belief", framed.pignistic_prob),
        ]
    }

    /// The fold readers agree on `expected`, twice (idempotent recompute).
    async fn assert_folds_to(&self, expected: f64, when: &str) {
        for pass in ["first recompute", "second recompute"] {
            for (who, got) in self.fold_readers().await {
                assert!(
                    (got - expected).abs() < 1e-9,
                    "{when}, {pass}: {who} BetP(TRUE) = {got}, expected {expected}"
                );
            }
        }
    }
}

/// BetP(TRUE) of the Dempster fold of `inputs`, each `(masses, reliability)`
/// discounted first: what `edge_factor`'s fold must produce from exactly
/// these rows.
fn expected_betp(inputs: &[(&Value, f64)]) -> f64 {
    let frame = FrameOfDiscernment::new("b5cb3efb", vec!["TRUE".into(), "FALSE".into()])
        .expect("binary frame");
    let discounted: Vec<MassFunction> = inputs
        .iter()
        .map(|(m, r)| {
            let mf = MassFunction::from_json_masses(frame.clone(), m).expect("masses");
            combination::discount(&mf, *r).expect("discount")
        })
        .collect();
    let combined = if discounted.len() == 1 {
        discounted[0].clone()
    } else {
        combination::combine_multiple(&discounted, 0.9)
            .expect("combine")
            .0
    };
    measures::pignistic_probability(&combined, 0)
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_lone_assess_input_is_folded_once(pool_opts: PgPoolOptions, conn_opts: PgConnectOptions) {
    let w = world(pool_opts, conn_opts, "lone-assess").await;
    let assess_bba = w.assess().await;
    w.assert_folds_to(
        expected_betp(&[(&assess_bba, UNTYPED_FALLBACK_RELIABILITY)]),
        "lone /assess",
    )
    .await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_assess_input_then_an_agent_input_are_each_folded_once(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts, "assess-then-agent").await;
    let agent = seed_agent(&w.pool).await;
    let assess_bba = w.assess().await;
    w.submit(Some(agent)).await;
    w.assert_folds_to(
        expected_betp(&[
            (&agent_masses(), 1.0),
            (&assess_bba, UNTYPED_FALLBACK_RELIABILITY),
        ]),
        "/assess, then an agent's /evidence",
    )
    .await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_input_then_an_assess_input_are_each_folded_once(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts, "agent-then-assess").await;
    let agent = seed_agent(&w.pool).await;
    w.submit(Some(agent)).await;
    let assess_bba = w.assess().await;
    w.assert_folds_to(
        expected_betp(&[
            (&agent_masses(), 1.0),
            (&assess_bba, UNTYPED_FALLBACK_RELIABILITY),
        ]),
        "an agent's /evidence, then /assess",
    )
    .await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_evidence_input_with_no_agent_id_is_the_callers_and_folded_once(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts, "lone-anonymous").await;
    // No `agent_id` in the body; the token's agent is the owner.
    w.submit(None).await;
    let rows: Vec<(Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
        "SELECT source_agent_id, perspective_id FROM mass_functions \
          WHERE claim_id = $1 AND frame_id = $2",
    )
    .bind(w.claim)
    .bind(w.frame)
    .fetch_all(&w.pool)
    .await
    .expect("read the pair's rows");
    assert_eq!(
        rows,
        vec![(Some(w.owner), None)],
        "the input is the caller's own, and nothing occupies the agent-less slot"
    );
    // 0.6 + 0.4/2: the input at its stored reliability 1.0.
    w.assert_folds_to(0.8, "/evidence with no agent_id").await;
    assert!((expected_betp(&[(&agent_masses(), 1.0)]) - 0.8).abs() < 1e-12);
}
