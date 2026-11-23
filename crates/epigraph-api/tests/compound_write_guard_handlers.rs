//! `EPIGRAPH_COMPOUND_WRITE_GUARD` (backlog 7435772c) at the two REST
//! writers' call sites, driven through the handlers directly (so the
//! journal is captured in the test's own span):
//!
//! - **The journal counts committed writes only.** Under `warn`, a request
//!   on a compound that the guard admits but that then fails (a frame that
//!   does not exist) adds no `accepted (inert)` line; the same request on a
//!   real frame adds exactly one. The operator reads that journal to size a
//!   flip to `refuse`, so a line per failed request would over-count it.
//!
//! Fixtures are seeded on the harness superuser pool, which is also the
//! handlers' `db_pool`.
#![cfg(feature = "db")]

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::Json;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::assess::{assess_claim, AssessClaimRequest};
use epigraph_api::routes::belief::{submit_evidence, SubmitEvidenceRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_engine::belief_modes::CompoundWriteGuard;
use sqlx::PgPool;
use tracing_test::traced_test;
use uuid::Uuid;
use viewer_fixture::{scoped_pool, seed_agent_with_group};

/// The `warn` acceptance line's message
/// (`CompoundTarget::log_accepted`).
const ACCEPTED: &str = "textless BBA write on a compound accepted (inert)";

fn write_scope() -> epigraph_api::middleware::bearer::RequireScopeWrite {
    let principal = Uuid::new_v4();
    epigraph_api::middleware::bearer::RequireScopeWrite(
        epigraph_api::middleware::bearer::AuthContext {
            client_id: principal,
            agent_id: Some(principal),
            owner_id: Some(principal),
            client_type: epigraph_api::middleware::ClientType::Service,
            scopes: vec!["claims:write".to_string()],
            jti: Uuid::new_v4(),
            family_id: None,
            elevation_claim: None,
            elevation: None,
            admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
            delegated_by: None,
        },
    )
}

async fn claim(pool: &PgPool, author: Uuid, group: Uuid, visibility: &str, what: &str) -> Uuid {
    let content = format!("7435772c handlers {what} {}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, true, $3, $4) RETURNING id",
    )
    .bind(&content)
    .bind(author)
    .bind(visibility)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

/// A compound with two atoms, every row and edge at `(visibility, group)`:
/// `(compound, atoms sorted by id)`.
async fn compound(pool: &PgPool, author: Uuid, group: Uuid, visibility: &str) -> (Uuid, Vec<Uuid>) {
    let compound = claim(pool, author, group, visibility, "compound").await;
    let mut atoms = vec![
        claim(pool, author, group, visibility, "atom a").await,
        claim(pool, author, group, visibility, "atom b").await,
    ];
    for a in &atoms {
        let edge: Uuid = sqlx::query_scalar(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, \
                                relationship, valid_from) \
             VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to', \
                     now() - interval '1 day') RETURNING id",
        )
        .bind(compound)
        .bind(*a)
        .fetch_one(pool)
        .await
        .expect("seed decomposes_to");
        sqlx::query(
            "UPDATE edges SET visibility = $2, owner_group_id = $3, co_owner_group_id = NULL \
             WHERE id = $1",
        )
        .bind(edge)
        .bind(visibility)
        .bind(group)
        .execute(pool)
        .await
        .expect("force edge tenancy");
    }
    atoms.sort();
    (compound, atoms)
}

async fn frame(pool: &PgPool) -> Uuid {
    epigraph_db::FrameRepository::create(
        pool,
        &format!("7435772c-handlers-{}", Uuid::new_v4()),
        None,
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("create frame")
    .id
}

async fn evidence(
    state: &AppState,
    pool: &PgPool,
    caller: Uuid,
    frame: Uuid,
    claim: Uuid,
) -> Result<(), ApiError> {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve caller");
    let request: SubmitEvidenceRequest = serde_json::from_value(serde_json::json!({
        "claim_id": claim,
        "reliability": 1.0,
        "masses": {"0": 0.7, "0,1": 0.3},
    }))
    .expect("evidence request");
    submit_evidence(
        write_scope(),
        ViewerExtractor(viewer),
        State(state.clone()),
        Path(frame),
        Json(request),
    )
    .await
    .map(|_| ())
}

async fn assess(
    state: &AppState,
    pool: &PgPool,
    caller: Uuid,
    claim: Uuid,
    frame: Option<Uuid>,
) -> Result<(), ApiError> {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve caller");
    let request: AssessClaimRequest = serde_json::from_value(serde_json::json!({
        "evidence_type": "empirical",
        "methodology": "instrumental",
        "confidence": 0.8,
        "supports": true,
        "frame_id": frame,
    }))
    .expect("assess request");
    assess_claim(
        write_scope(),
        ViewerExtractor(viewer),
        State(state.clone()),
        Path(claim),
        Json(request),
    )
    .await
    .map(|_| ())
}

async fn bbas(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("count BBAs")
}

/// How many `warn` acceptance lines this test's journal holds.
fn accepted_lines(lines: &[&str]) -> usize {
    lines.iter().filter(|l| l.contains(ACCEPTED)).count()
}

#[traced_test]
#[sqlx::test(migrations = "../../migrations")]
async fn a_warn_mode_request_that_fails_after_the_guard_adds_no_journal_line(pool: PgPool) {
    let (caller, group) = seed_agent_with_group(&pool, "7435772c-handlers-log").await;
    let (compound, _atoms) = compound(&pool, caller, group, "public").await;
    let real_frame = frame(&pool).await;
    let missing_frame = Uuid::new_v4();
    let mut state = AppState::with_db(pool.clone(), ApiConfig::default())
        .with_compound_write_guard(CompoundWriteGuard::Warn);
    state.scoped = Some(scoped_pool(&pool).await);

    // The guard admits both (warn, a visible compound); each then fails on
    // its frame, which does not exist, and writes nothing.
    let err = evidence(&state, &pool, caller, missing_frame, compound)
        .await
        .expect_err("frames evidence on a missing frame");
    assert!(matches!(err, ApiError::NotFound { .. }), "{err:?}");
    let err = assess(&state, &pool, caller, compound, Some(missing_frame))
        .await
        .expect_err("assess on a missing frame");
    assert!(matches!(err, ApiError::NotFound { .. }), "{err:?}");
    assert_eq!(bbas(&pool, compound).await, 0, "nothing was written");
    logs_assert(|lines| match accepted_lines(lines) {
        0 => Ok(()),
        n => Err(format!(
            "{n} acceptance line(s) for requests that wrote nothing: the journal must count \
             only committed compound writes"
        )),
    });

    // Calibration: the same requests on a real frame commit, and each adds
    // exactly one line.
    evidence(&state, &pool, caller, real_frame, compound)
        .await
        .expect("frames evidence on a real frame");
    assess(&state, &pool, caller, compound, Some(real_frame))
        .await
        .expect("assess on a real frame");
    assert_eq!(bbas(&pool, compound).await, 2, "both writes landed");
    logs_assert(|lines| match accepted_lines(lines) {
        2 => Ok(()),
        n => Err(format!("{n} acceptance line(s) for 2 committed writes")),
    });
    assert!(logs_contain("frames_evidence"));
    assert!(logs_contain(&caller.to_string()));
}
