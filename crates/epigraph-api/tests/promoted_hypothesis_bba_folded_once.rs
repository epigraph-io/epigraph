//! `POST /api/v1/hypothesis/:id/promote` MOVES the latest
//! `hypothesis_assessment` BBA onto `research_validity`; it must not leave a
//! second copy behind (backlog 846b808e).
//!
//! # What was wrong, measured at origin/main before this file
//!
//! `routes/hypothesis.rs::promote_hypothesis` (and the CLI twin
//! `epigraph-cli/src/bin/hypothesis.rs::promote`) ran
//! `MassFunctionRepository::copy_to_frame(.., latest, research_validity)` and
//! never retired `latest`. Both frames are 2-hypothesis frames, so
//! `MassFunctionRepository::get_for_claim_binary_frames` (the reader
//! `ds_auto::auto_wire_ds_update` folds) returned the original AND the copy.
//! An evidence-less row (the `error_derived` BBA `analyze` writes has no
//! `evidence_id`, so it gets no source key) was then Dempster-folded twice as
//! independent evidence.
//!
//! # Harness
//!
//! The app runs on the per-test database through `ScopedPool::connect`, as in
//! `error_derived_bba_provenance.rs`. Its promote route writes on the
//! unstamped `state.db_pool`, which on a non-bypassing role is refused at the
//! copy on BOTH code versions, so this cannot be run there faithfully; the
//! retirement is instead gated by the caller's write predicate, which the
//! refusal arm below pins.

#![cfg(feature = "db")]

mod common;
mod viewer_fixture;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

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

async fn ensure_frame(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['true','false']::text[]) \
         ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {name} frame: {e}"))
}

/// Every BBA on (claim, frame), oldest first.
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

struct Ready {
    addr: SocketAddr,
    _shutdown: oneshot::Sender<()>,
    claim: Uuid,
    hyp_frame: Uuid,
    rv_frame: Uuid,
}

/// Bring `claim` to a promotable state through the real `analyze` route: a
/// completed experiment whose result has an analysis with an explicit scope,
/// and the `error_derived` BBA that route writes (untyped, no `evidence_id`)
/// as the latest `hypothesis_assessment` row.
async fn make_promotable(
    pool: &PgPool,
    conn_opts: &PgConnectOptions,
    agent: Uuid,
    claim: Uuid,
) -> Ready {
    let hyp_frame = ensure_frame(pool, "hypothesis_assessment").await;
    let rv_frame = ensure_frame(pool, "research_validity").await;
    let experiment: Uuid = sqlx::query_scalar(
        "INSERT INTO experiments (hypothesis_id, created_by, status) \
         VALUES ($1, $2, 'collecting') RETURNING id",
    )
    .bind(claim)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed experiment");
    let result: Uuid = sqlx::query_scalar(
        "INSERT INTO experiment_results (experiment_id, data_source, raw_measurements, measurement_count) \
         VALUES ($1, 'instrument', $2, 2) RETURNING id",
    )
    .bind(experiment)
    .bind(serde_json::json!([
        {"value": 1.2, "random_error": 0.05, "systematic_error": 0.02},
        {"value": 1.1, "random_error": 0.05, "systematic_error": 0.02}
    ]))
    .fetch_one(pool)
    .await
    .expect("seed result");

    let (addr, shutdown) = spawn_app(conn_opts).await;
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], agent);
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/experiments/{experiment}/results/{result}/analyze"
        ))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "agent_id": agent,
            "direction": "supports",
            "scope_limitations": [{"type": "small_sample_size"}],
            "expected_value": 0.0,
        }))
        .send()
        .await
        .expect("analyze request");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert!(status.is_success(), "analyze: {status} {body}");
    sqlx::query("UPDATE experiments SET status = 'complete' WHERE id = $1")
        .bind(experiment)
        .execute(pool)
        .await
        .expect("complete the experiment");

    let source = rows(pool, claim, hyp_frame).await;
    assert_eq!(
        source.len(),
        1,
        "CALIBRATION: analyze wrote one BBA: {source:?}"
    );
    assert_eq!(
        (
            source[0].combination_method.as_deref(),
            source[0].evidence_type.as_deref(),
            source[0].evidence_id
        ),
        (Some("error_derived"), None, None),
        "CALIBRATION: the source is the untyped, evidence-less row that was double-folded"
    );
    Ready {
        addr,
        _shutdown: shutdown,
        claim,
        hyp_frame,
        rv_frame,
    }
}

async fn promote(addr: SocketAddr, agent: Uuid, claim: Uuid) -> (reqwest::StatusCode, String) {
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], agent);
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/hypothesis/{claim}/promote"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("promote request");
    (resp.status(), resp.text().await.unwrap_or_default())
}

/// The promoter writes the claim's group, so the promotion lands; afterwards
/// the evidence exists on exactly ONE binary frame, as the fold reads it.
#[sqlx::test(migrations = "../../migrations")]
async fn promoted_hypothesis_bba_is_folded_once(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let (agent, group) = viewer_fixture::seed_agent_with_group(&pool, "846b808e-promoter").await;
    let claim =
        viewer_fixture::seed_group_claim(&pool, agent, group, "846b808e promoted hypothesis").await;
    let r = make_promotable(&pool, &conn_opts, agent, claim).await;
    let source = rows(&pool, r.claim, r.hyp_frame).await.remove(0);
    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT owner_group_id FROM mass_functions WHERE id = $1")
            .bind(source.id)
            .fetch_one(&pool)
            .await
            .expect("source owner");
    assert_eq!(
        owner,
        Some(group),
        "CALIBRATION: the source BBA is owned by the promoter's group"
    );

    let (status, body) = promote(r.addr, agent, r.claim).await;
    assert!(status.is_success(), "promote: {status} {body}");

    // The production reader the ds_auto fold uses.
    let viewer = epigraph_db::visibility::Viewer::resolve(&pool, agent)
        .await
        .expect("promoter viewer");
    let folded: Vec<epigraph_db::MassFunctionRow> =
        epigraph_db::MassFunctionRepository::get_for_claim_binary_frames(&pool, &viewer, r.claim)
            .await
            .expect("binary-frame BBAs")
            .into_iter()
            .filter(|row| row.source_agent_id == source.source_agent_id)
            .collect();
    assert_eq!(
        folded.len(),
        1,
        "the promoted evidence must be read ONCE across binary frames, got {:?}",
        folded
            .iter()
            .map(|r| (r.id, r.frame_id))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        folded[0].frame_id, r.rv_frame,
        "it lives on research_validity"
    );
    assert_eq!(folded[0].masses, source.masses, "with the source's masses");
    assert!(
        rows(&pool, r.claim, r.hyp_frame)
            .await
            .iter()
            .all(|row| row.id != source.id),
        "the hypothesis_assessment source row is retired by the promotion"
    );
}

/// A promoter that cannot write the source row is refused, and NOTHING is
/// written: no copy on research_validity, the source still in place. A
/// promotion that copied without retiring would leave the double count.
#[sqlx::test(migrations = "../../migrations")]
async fn a_promoter_who_cannot_retire_the_source_writes_nothing(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    // A public (world-owned) claim: readable by the promoter, so the gate
    // passes, but outside its writable set.
    let (agent, group) = viewer_fixture::seed_agent_with_group(&pool, "846b808e-outsider").await;
    let claim = viewer_fixture::seed_public_claim(&pool, agent, "846b808e public hypothesis").await;
    let r = make_promotable(&pool, &conn_opts, agent, claim).await;
    let source = rows(&pool, r.claim, r.hyp_frame).await.remove(0);

    // CALIBRATION: the premise of this arm is that the source BBA lies
    // OUTSIDE the promoter's writable set. Without it the refusal below would
    // have no explanation.
    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT owner_group_id FROM mass_functions WHERE id = $1")
            .bind(source.id)
            .fetch_one(&pool)
            .await
            .expect("source owner");
    let viewer = epigraph_db::visibility::Viewer::resolve(&pool, agent)
        .await
        .expect("promoter viewer");
    assert_ne!(
        owner,
        Some(group),
        "CALIBRATION: the source BBA is not owned by the promoter's group"
    );
    assert!(
        owner.is_none_or(|g| !viewer.writable_groups().contains(&g)),
        "CALIBRATION: the source BBA's owner {owner:?} is outside the promoter's writable \
         set {:?}",
        viewer.writable_groups()
    );

    let (status, body) = promote(r.addr, agent, r.claim).await;
    assert_eq!(
        status,
        reqwest::StatusCode::FORBIDDEN,
        "a promotion that cannot retire the source must be refused: {status} {body}"
    );
    assert!(
        body.contains("cannot retire that BBA"),
        "the refusal names the retire, not some other failure: {body}"
    );
    assert!(
        rows(&pool, r.claim, r.rv_frame).await.is_empty(),
        "a refused promotion writes no research_validity copy"
    );
    assert!(
        rows(&pool, r.claim, r.hyp_frame)
            .await
            .iter()
            .any(|row| row.id == source.id),
        "a refused promotion leaves the source in place"
    );
}
