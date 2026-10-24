//! `POST /api/v1/experiments/:eid/results/:rid/analyze` writes an
//! `error_derived` BBA through `MassFunctionRepository::store` (backlog
//! bc06ec6f). The row stays untyped for every `data_source`.
//!
//! `experiment_results.data_source` is declared by whoever submits the result
//! and is checked only against a CHECK list. Typing the BBA from it would let
//! the submitter lift the row from the 0.5 unknown-type weight to the
//! calibrated weight of `empirical` (1.0) or `statistical` (0.9). A
//! caller-declared type must not raise a BBA's weight above what the writer
//! could already assign, so the type waits for a server-side derivation.
//!
//! `POST /api/v1/hypothesis/:id/promote` moves the latest
//! `hypothesis_assessment` BBA onto `research_validity`. The raw INSERT it
//! used kept only the masses and the method, so the copy lost its type,
//! reliability, locality and evidence link and was weighted 0.5;
//! `MassFunctionRepository::copy_to_frame` keeps all four. The source row is
//! then retired (backlog 846b808e, `promoted_hypothesis_bba_folded_once.rs`).
#![cfg(feature = "db")]

mod common;
mod viewer_fixture;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

/// The app on the per-test database (not `DATABASE_URL`'s), so the routes
/// read the rows this test seeds.
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

/// (source_agent_id, combination_method, evidence_type) of every BBA on the pair.
async fn bbas(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
) -> Vec<(Option<Uuid>, Option<String>, Option<String>)> {
    sqlx::query_as(
        "SELECT source_agent_id, combination_method, evidence_type FROM mass_functions \
         WHERE claim_id = $1 AND frame_id = $2 ORDER BY source_agent_id NULLS FIRST",
    )
    .bind(claim)
    .bind(frame)
    .fetch_all(pool)
    .await
    .expect("read BBAs")
}

/// What `analyze` seeded: the hypothesis claim, the `hypothesis_assessment`
/// frame, the experiment and the agent that owns all three.
struct Analyzed {
    hypothesis: Uuid,
    frame: Uuid,
    experiment: Uuid,
    agent: Uuid,
}

/// Seed hypothesis claim + `hypothesis_assessment` frame + experiment + result
/// with `data_source`, then call the analyze route with `scope_limitations`.
async fn analyze(
    pool: &PgPool,
    conn_opts: &PgConnectOptions,
    data_source: &str,
    scope_limitations: serde_json::Value,
) -> Analyzed {
    // The promoter writes the claim's group: promotion retires the source BBA
    // under the caller's write predicate (backlog 846b808e).
    let (agent, group) = viewer_fixture::seed_agent_with_group(pool, "bc06ec6f").await;
    let hypothesis = viewer_fixture::seed_group_claim(
        pool,
        agent,
        group,
        &format!("bc06ec6f error_derived hypothesis {}", Uuid::new_v4()),
    )
    .await;
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ('hypothesis_assessment', \
         ARRAY['true','false']::text[]) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed hypothesis_assessment frame");
    let experiment: Uuid = sqlx::query_scalar(
        "INSERT INTO experiments (hypothesis_id, created_by, status) \
         VALUES ($1, $2, 'collecting') RETURNING id",
    )
    .bind(hypothesis)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed experiment");
    let result: Uuid = sqlx::query_scalar(
        "INSERT INTO experiment_results (experiment_id, data_source, raw_measurements, measurement_count) \
         VALUES ($1, $2, $3, 2) RETURNING id",
    )
    .bind(experiment)
    .bind(data_source)
    .bind(serde_json::json!([
        {"value": 1.2, "random_error": 0.05, "systematic_error": 0.02},
        {"value": 1.1, "random_error": 0.05, "systematic_error": 0.02}
    ]))
    .fetch_one(pool)
    .await
    .expect("seed result");

    let (addr, _shutdown) = spawn_app(conn_opts).await;
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], agent);
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/experiments/{experiment}/results/{result}/analyze"
        ))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "agent_id": agent,
            "direction": "supports",
            "scope_limitations": scope_limitations,
            "expected_value": 0.0,
        }))
        .send()
        .await
        .expect("analyze request");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert!(
        status.is_success(),
        "analyze ({data_source}): {status} {body}"
    );
    Analyzed {
        hypothesis,
        frame,
        experiment,
        agent,
    }
}

/// Seed through `analyze` with no scope limitation; return (claim, frame).
async fn analyze_with_data_source(
    pool: &PgPool,
    conn_opts: &PgConnectOptions,
    data_source: &str,
) -> (Uuid, Uuid) {
    let a = analyze(pool, conn_opts, data_source, serde_json::json!([])).await;
    (a.hypothesis, a.frame)
}

async fn error_derived_type(pool: &PgPool, claim: Uuid, frame: Uuid) -> Option<String> {
    let rows = bbas(pool, claim, frame).await;
    let derived: Vec<_> = rows
        .iter()
        .filter(|(_, m, _)| m.as_deref() == Some("error_derived"))
        .collect();
    assert_eq!(derived.len(), 1, "one error_derived BBA: {rows:?}");
    derived[0].2.clone()
}

/// An `instrument` result is the case typing would have raised: `empirical`
/// carries the top calibrated weight. The submitter declares `data_source`,
/// so it does not type the row.
#[sqlx::test(migrations = "../../migrations")]
async fn analyze_does_not_type_an_instrument_result_from_its_declared_data_source(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let (claim, frame) = analyze_with_data_source(&pool, &conn_opts, "instrument").await;
    assert_eq!(error_derived_type(&pool, claim, frame).await, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn analyze_leaves_a_literature_result_untyped(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let (claim, frame) = analyze_with_data_source(&pool, &conn_opts, "literature").await;
    assert_eq!(error_derived_type(&pool, claim, frame).await, None);
}

/// Every BBA on (claim, frame), oldest first, as the repo reads them.
async fn rows(pool: &PgPool, claim: Uuid, frame: Uuid) -> Vec<epigraph_db::MassFunctionRow> {
    sqlx::query_as(
        "SELECT * FROM mass_functions WHERE claim_id = $1 AND frame_id = $2 \
         ORDER BY created_at ASC",
    )
    .bind(claim)
    .bind(frame)
    .fetch_all(pool)
    .await
    .expect("read BBA rows")
}

/// Promotion moves the latest `hypothesis_assessment` BBA with its
/// provenance, so the moved row keeps the source's effective weight, and the
/// source row is gone afterwards. The source row
/// is seeded typed, with a reliability, an intra locality and an evidence
/// link: an untyped error_derived source would let a copy that drops all four
/// columns pass.
#[sqlx::test(migrations = "../../migrations")]
async fn promote_copies_the_source_bba_with_its_provenance(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    // The promotion gate: a completed experiment whose result has an analysis,
    // an analysis with an explicit scope, and a latest BBA with Bel >= 0.6.
    let a = analyze(
        &pool,
        &conn_opts,
        "instrument",
        serde_json::json!([{"type": "small_sample_size"}]),
    )
    .await;
    sqlx::query("UPDATE experiments SET status = 'complete' WHERE id = $1")
        .bind(a.experiment)
        .execute(&pool)
        .await
        .expect("complete the experiment");
    let rv_frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ('research_validity', \
         ARRAY['true','false']::text[]) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name \
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed research_validity frame");
    let evidence: Uuid = sqlx::query_scalar(
        "INSERT INTO evidence (content_hash, evidence_type, claim_id) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'reference', $1) RETURNING id",
    )
    .bind(a.hypothesis)
    .fetch_one(&pool)
    .await
    .expect("seed evidence");
    let source_agent = seed_agent(&pool).await;
    let source_id = epigraph_db::MassFunctionRepository::store_with_perspective(
        &pool,
        a.hypothesis,
        a.frame,
        Some(source_agent),
        None,
        &serde_json::json!({"0": 0.8, "0,1": 0.2}),
        Some(0.05),
        Some("auto_wire"),
        Some(0.85),
        Some("logical"),
        "intra_self_cite",
        Some(evidence),
    )
    .await
    .expect("store the typed source BBA");
    // Latest by construction, so the route copies this row.
    sqlx::query("UPDATE mass_functions SET created_at = NOW() + interval '1 minute' WHERE id = $1")
        .bind(source_id)
        .execute(&pool)
        .await
        .expect("make the typed source the latest row");

    // Snapshot the source BEFORE promoting: the promotion retires it.
    let source = rows(&pool, a.hypothesis, a.frame)
        .await
        .into_iter()
        .find(|r| r.id == source_id)
        .expect("source row");

    let (addr, _shutdown) = spawn_app(&conn_opts).await;
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], a.agent);
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/hypothesis/{}/promote",
            a.hypothesis
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("promote request");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert!(status.is_success(), "promote: {status} {body}");

    assert!(
        rows(&pool, a.hypothesis, a.frame)
            .await
            .iter()
            .all(|r| r.id != source_id),
        "the promoted source row is retired from hypothesis_assessment"
    );
    let copies = rows(&pool, a.hypothesis, rv_frame).await;
    assert_eq!(copies.len(), 1, "one promoted BBA: {copies:?}");
    let copy = &copies[0];
    assert_eq!(copy.source_agent_id, Some(source_agent));
    assert_eq!(copy.masses, source.masses);
    assert_eq!(copy.combination_method.as_deref(), Some("auto_wire"));
    assert_eq!(copy.evidence_type.as_deref(), Some("logical"));
    assert_eq!(copy.source_strength, Some(0.85));
    assert_eq!(copy.locality_tag, "intra_self_cite");
    assert_eq!(copy.evidence_id, Some(evidence));

    // The copy is weighted as its source is, not at the 0.5 unknown-type
    // fallback the old copy fell to.
    let cal = epigraph_engine::calibration::CalibrationConfig::cached();
    let weight = |r: &epigraph_db::MassFunctionRow| {
        epigraph_engine::edge_factor::effective_source_strength(r, None, None, cal)
    };
    assert!(
        (weight(copy) - weight(&source)).abs() < 1e-12,
        "copy weight {} != source weight {}",
        weight(copy),
        weight(&source)
    );
    assert!(
        (weight(copy) - 0.5).abs() > 1e-6,
        "non-vacuity: the source's weight must differ from the 0.5 fallback"
    );
}
