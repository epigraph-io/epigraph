//! `POST /api/v1/hypothesis/:id/promote` on the APPLICATION ROLE answers
//! 404, 403 and 409 for three different reasons, and writes nothing in each
//! (backlog b9c4e809).
//!
//! # What was wrong, measured before this file
//!
//! `routes/hypothesis.rs::promote_hypothesis` mapped a 0-row result of its
//! conditional status write to ONE 409, "already promoted ... or its status
//! could not be written", for both a lost race and a write the caller may not
//! make. Its transaction was also unstamped (`state.db_pool.begin()`): on the
//! application role row security then hides every group-owned hypothesis from
//! the status write, so a caller with full write authority got the same 409 and
//! nobody could promote at all. A reader-only caller was told "conflict" when
//! the answer is "you may not".
//!
//! # The instrument
//!
//! The app under test runs both its raw `db_pool` and its stamped `ScopedPool`
//! as `epigraph_app` (`frames_evidence_app_role.rs`'s `RawPool::AppRole`
//! shape), as on a production deployment. The hypothesis is made promotable
//! through the real `analyze` route on a second app whose pools are the harness
//! superuser, so seeding cannot fail for a tenancy reason unrelated to the
//! promotion. Every "nothing was written" check reads through the superuser
//! seeding pool.
//!
//! # The factor move (migration 311, backlog 9a9d6850)
//!
//! The world also holds a factor in `hypothesis_assessment` over the
//! hypothesis and a second claim, and a bystander factor in the same frame
//! that does not name it. A promotion moves the first to `research_validity`
//! and leaves the bystander; a refused one moves neither. Since 311 the
//! application role holds no UPDATE on `factors.frame_id`, so the move runs
//! through `epigraph_promote_hypothesis_factors`.
//!
//! Verified to fail: with 311 applied and the route still running its direct
//! `UPDATE factors SET frame_id`, the owner's promotion answers 500 (42501 on
//! `factors`) in `a_group_writer_promotes_on_the_application_role`.
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;
mod viewer_fixture;

use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use sqlx::PgPool;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::oneshot;
use uuid::Uuid;

async fn serve(state: AppState) -> (SocketAddr, oneshot::Sender<()>) {
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

/// The app under test: raw and stamped pools both `epigraph_app`.
async fn spawn_app_role(pool: &PgPool) -> (SocketAddr, oneshot::Sender<()>) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = viewer_fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = viewer_fixture::downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    serve(state).await
}

/// The seeding app: the harness superuser behind both pools.
async fn spawn_seeding_app(pool: &PgPool) -> (SocketAddr, oneshot::Sender<()>) {
    let url = viewer_fixture::database_url_for(pool).await;
    let scoped = ScopedPool::connect(&url, SessionGucMode::Session)
        .await
        .expect("ScopedPool::connect");
    serve(AppState::with_scoped_pool(scoped, ApiConfig::default())).await
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

async fn join(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .unwrap_or_else(|e| panic!("{role} membership: {e}"));
}

/// One group-private, promotable hypothesis and the callers around it.
struct World {
    pool: PgPool,
    addr: SocketAddr,
    _shutdown: oneshot::Sender<()>,
    _seeding_shutdown: oneshot::Sender<()>,
    /// Admin of the hypothesis's group and its author: may write it.
    owner: Uuid,
    /// `reader` member of that group: may read it, may not write it.
    reader: Uuid,
    /// A member of its own group only: may not read it.
    stranger: Uuid,
    claim: Uuid,
    hyp_frame: Uuid,
    rv_frame: Uuid,
    /// The `hypothesis_assessment` BBA a promotion would move.
    source_bba: Uuid,
    /// A `hypothesis_assessment` factor over the hypothesis: a promotion
    /// moves it to `research_validity`.
    hyp_factor: Uuid,
    /// A `hypothesis_assessment` factor that does not name the hypothesis:
    /// no promotion of it moves this one.
    bystander_factor: Uuid,
}

async fn seed_factor(pool: &PgPool, frame: Uuid, a: Uuid, b: Uuid) -> Uuid {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    sqlx::query_scalar(
        "INSERT INTO factors (factor_type, variable_ids, potential, frame_id) \
         VALUES ('evidential_support', $1, '{\"strength\": 0.8}', $2) RETURNING id",
    )
    .bind(vec![lo, hi])
    .bind(frame)
    .fetch_one(pool)
    .await
    .expect("seed factor")
}

async fn factor_frame(w: &World, factor: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT frame_id FROM factors WHERE id = $1")
        .bind(factor)
        .fetch_one(&w.pool)
        .await
        .expect("read factor frame")
}

async fn world(pool: PgPool, label: &str) -> World {
    let hyp_frame = ensure_frame(&pool, "hypothesis_assessment").await;
    let rv_frame = ensure_frame(&pool, "research_validity").await;
    let (owner, group) =
        viewer_fixture::seed_agent_with_group(&pool, &format!("{label}-owner")).await;
    let (reader, _) =
        viewer_fixture::seed_agent_with_group(&pool, &format!("{label}-reader")).await;
    let (stranger, _) =
        viewer_fixture::seed_agent_with_group(&pool, &format!("{label}-stranger")).await;
    join(&pool, group, reader, "reader").await;
    let claim = viewer_fixture::seed_group_claim(
        &pool,
        owner,
        group,
        &format!("{label} hypothesis {}", Uuid::new_v4()),
    )
    .await;

    let (seeding_addr, seeding_shutdown) = spawn_seeding_app(&pool).await;
    analyze_supporting_result(&pool, seeding_addr, owner, claim).await;
    let source: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM mass_functions WHERE claim_id = $1 AND frame_id = $2")
            .bind(claim)
            .bind(hyp_frame)
            .fetch_all(&pool)
            .await
            .expect("source BBA");
    assert_eq!(source.len(), 1, "CALIBRATION: analyze wrote one BBA");
    let partner = viewer_fixture::seed_group_claim(
        &pool,
        owner,
        group,
        &format!("{label} partner {}", Uuid::new_v4()),
    )
    .await;
    let other = viewer_fixture::seed_group_claim(
        &pool,
        owner,
        group,
        &format!("{label} bystander {}", Uuid::new_v4()),
    )
    .await;
    let hyp_factor = seed_factor(&pool, hyp_frame, claim, partner).await;
    let bystander_factor = seed_factor(&pool, hyp_frame, partner, other).await;

    let (addr, shutdown) = spawn_app_role(&pool).await;
    let w = World {
        pool,
        addr,
        _shutdown: shutdown,
        _seeding_shutdown: seeding_shutdown,
        owner,
        reader,
        stranger,
        claim,
        hyp_frame,
        rv_frame,
        source_bba: source[0],
        hyp_factor,
        bystander_factor,
    };
    // CALIBRATION: the hypothesis is promotable, read through the app under
    // test as its owner, so every refusal below is about the caller.
    let s = status_of(&w, owner).await;
    assert_eq!(
        s["promotion"]["ready"], true,
        "CALIBRATION: the promotion gate passes for the owner: {s}"
    );
    w
}

/// A completed experiment with a scoped, supporting analysis on `claim`, via
/// the real `analyze` route on the seeding app.
async fn analyze_supporting_result(pool: &PgPool, addr: SocketAddr, agent: Uuid, claim: Uuid) {
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
    let body = resp.text().await.unwrap_or_default();
    assert!(status.is_success(), "analyze: {status} {body}");
    sqlx::query("UPDATE experiments SET status = 'complete' WHERE id = $1")
        .bind(experiment)
        .execute(pool)
        .await
        .expect("complete the experiment");
}

async fn status_of(w: &World, agent: Uuid) -> serde_json::Value {
    let token = common::mint_token_with_agent(&["claims:read"], agent);
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{}/api/v1/hypothesis/{}/status",
            w.addr, w.claim
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("status request");
    assert!(resp.status().is_success(), "status: {}", resp.status());
    resp.json().await.expect("status json")
}

async fn promote(addr: SocketAddr, agent: Uuid, claim: Uuid) -> (u16, serde_json::Value) {
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], agent);
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/hypothesis/{claim}/promote"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("promote request");
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(serde_json::Value::Null))
}

async fn hypothesis_status(w: &World) -> Option<String> {
    sqlx::query_scalar("SELECT properties->>'hypothesis_status' FROM claims WHERE id = $1")
        .bind(w.claim)
        .fetch_one(&w.pool)
        .await
        .expect("read status")
}

/// Nothing the promotion writes is there: no `research_validity` BBA or frame
/// binding, and the source BBA is still in place. The status is checked by
/// each arm, because the race arm's winner promoted it.
async fn assert_nothing_moved(w: &World, arm: &str) {
    let rv_bbas: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions WHERE claim_id = $1 AND frame_id = $2",
    )
    .bind(w.claim)
    .bind(w.rv_frame)
    .fetch_one(&w.pool)
    .await
    .expect("count research_validity BBAs");
    assert_eq!(rv_bbas, 0, "{arm}: no research_validity BBA was written");
    let source_left: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mass_functions WHERE id = $1 AND frame_id = $2)",
    )
    .bind(w.source_bba)
    .bind(w.hyp_frame)
    .fetch_one(&w.pool)
    .await
    .expect("source BBA");
    assert!(source_left, "{arm}: the source BBA is still in place");
    let bound: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM claim_frames WHERE claim_id = $1 AND frame_id = $2)",
    )
    .bind(w.claim)
    .bind(w.rv_frame)
    .fetch_one(&w.pool)
    .await
    .expect("claim_frames");
    assert!(
        !bound,
        "{arm}: the claim was not bound to research_validity"
    );
    assert_eq!(
        factor_frame(w, w.hyp_factor).await,
        Some(w.hyp_frame),
        "{arm}: the hypothesis's factor stayed in hypothesis_assessment"
    );
}

/// CALIBRATION for every refusal below: a caller with write authority over the
/// hypothesis promotes it on the application role, and the evidence moves.
#[sqlx::test(migrations = "../../migrations")]
async fn a_group_writer_promotes_on_the_application_role(pool: PgPool) {
    let w = world(pool, "b9c4e809-writer").await;
    let (status, body) = promote(w.addr, w.owner, w.claim).await;
    assert_eq!(status, 200, "the owner promotes its hypothesis: {body}");
    assert_eq!(hypothesis_status(&w).await.as_deref(), Some("promoted"));
    let moved: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM mass_functions WHERE claim_id = $1 AND frame_id = $2")
            .bind(w.claim)
            .bind(w.rv_frame)
            .fetch_all(&w.pool)
            .await
            .expect("research_validity BBAs");
    assert_eq!(moved.len(), 1, "the BBA moved onto research_validity");
    let source_left: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mass_functions WHERE id = $1)")
            .bind(w.source_bba)
            .fetch_one(&w.pool)
            .await
            .expect("source BBA");
    assert!(!source_left, "the source BBA was retired");
    assert_eq!(
        factor_frame(&w, w.hyp_factor).await,
        Some(w.rv_frame),
        "the hypothesis's factor moved to research_validity (311's definer)"
    );
    assert_eq!(
        factor_frame(&w, w.bystander_factor).await,
        Some(w.hyp_frame),
        "a factor that does not name the hypothesis stays where it was"
    );
}

/// A caller that READS the hypothesis but may not write it is told so: 403
/// `not_owner` / `not_claim_writer`, not a conflict. Once the hypothesis IS
/// promoted it is still told "you may not", not "someone else already did".
#[sqlx::test(migrations = "../../migrations")]
async fn a_reader_only_caller_is_refused_403_and_nothing_is_written(pool: PgPool) {
    let w = world(pool, "b9c4e809-reader").await;
    let s = status_of(&w, w.reader).await;
    assert_eq!(
        s["promotion"]["ready"], true,
        "CALIBRATION: the reader reads the hypothesis and its readiness: {s}"
    );

    let (status, body) = promote(w.addr, w.reader, w.claim).await;
    assert_eq!(status, 403, "a reader-only caller may not promote: {body}");
    assert_eq!(body["error"], "not_owner", "{body}");
    assert_eq!(body["rule"], "not_claim_writer", "{body}");
    assert_eq!(body["claim_id"], w.claim.to_string(), "{body}");
    assert_eq!(
        hypothesis_status(&w).await,
        None,
        "a refused promotion leaves the status unwritten"
    );
    assert_nothing_moved(&w, "reader-only").await;

    // Promoted by its owner, it is still "you may not" for the reader.
    let (status, body) = promote(w.addr, w.owner, w.claim).await;
    assert_eq!(status, 200, "CALIBRATION: the owner promotes: {body}");
    let (status, body) = promote(w.addr, w.reader, w.claim).await;
    assert_eq!(
        status, 403,
        "a reader-only caller is refused for authority, not told it lost a race: {body}"
    );
    assert_eq!(body["rule"], "not_claim_writer", "{body}");
}

/// A caller that cannot read the hypothesis gets the 404 a missing one gets,
/// and nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_reader_is_404_and_nothing_is_written(pool: PgPool) {
    let w = world(pool, "b9c4e809-stranger").await;
    let (status, body) = promote(w.addr, w.stranger, w.claim).await;
    assert_eq!(status, 404, "a non-reader sees no hypothesis: {body}");
    let (missing, body_missing) = promote(w.addr, w.stranger, Uuid::new_v4()).await;
    assert_eq!(missing, 404, "{body_missing}");
    assert_eq!(
        body["error"], body_missing["error"],
        "an unreadable hypothesis answers like a missing one: {body} vs {body_missing}"
    );
    assert_eq!(hypothesis_status(&w).await, None);
    assert_nothing_moved(&w, "non-reader").await;
}

/// A writer whose promotion queues behind another transaction's promotion of
/// the same hypothesis, which then commits, loses the race: 409 naming the
/// concurrent promotion, and nothing of its own is written.
///
/// The race is deterministic: the winner holds the row lock in an open
/// transaction until the loser's status write is seen WAITING on it in
/// `pg_stat_activity`, and only then commits.
#[sqlx::test(migrations = "../../migrations")]
async fn a_concurrent_loser_is_409_and_writes_nothing(pool: PgPool) {
    let w = world(pool, "b9c4e809-race").await;

    let mut winner = w.pool.begin().await.expect("winner transaction");
    sqlx::query(
        "UPDATE claims SET properties = properties || '{\"hypothesis_status\": \"promoted\"}' \
         WHERE id = $1",
    )
    .bind(w.claim)
    .execute(&mut *winner)
    .await
    .expect("winner's status write");

    let (addr, owner, claim) = (w.addr, w.owner, w.claim);
    let loser = tokio::spawn(async move { promote(addr, owner, claim).await });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE datname = current_database() AND wait_event_type = 'Lock' \
               AND query LIKE 'UPDATE claims SET properties%'",
        )
        .fetch_one(&w.pool)
        .await
        .expect("pg_stat_activity");
        if waiting > 0 {
            break;
        }
        assert!(
            !loser.is_finished(),
            "the loser answered without ever waiting on the winner's row lock: its \
             status write did not reach the row ({:?})",
            loser.await
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "the loser's status write never waited on the winner's row lock"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    winner.commit().await.expect("winner commits");

    let (status, body) = loser.await.expect("loser task");
    assert_eq!(status, 409, "the concurrent loser is a conflict: {body}");
    assert!(
        body.to_string().contains("concurrent promotion committed"),
        "the 409 names the race: {body}"
    );
    assert_eq!(hypothesis_status(&w).await.as_deref(), Some("promoted"));
    assert_nothing_moved(&w, "concurrent loser").await;
}
