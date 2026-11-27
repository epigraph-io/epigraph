#![cfg(feature = "db")]
//! `POST /api/v1/gaps/analysis` and `POST /api/v1/gaps/surface` on the
//! PRODUCTION pool shape (both pools log in as `epigraph_app`, row security
//! FORCEd).
//!
//! # What is pinned
//!
//! * `gap_analysis` reads through the caller's stamped connection, so a
//!   member's own group-private claim is analysed, and the `gap_analyses` row it
//!   writes carries that claim's id and none of its text. `gap_analyses` has no
//!   tenancy columns: whatever lands there is readable by every caller of
//!   `surface_gaps`, so it may hold ids, scores and fixed templates only.
//! * `surface_gaps` loads the analysis it was asked for (not only the newest
//!   one), resolves each stored claim id through the CALLER's viewer, skips a
//!   claim the caller cannot read, and files a challenge whose text names the
//!   gap type and the claim id only, even when a legacy row still stores text.

mod viewer_fixture;

use axum::extract::State;
use axum::Json;
use epigraph_api::middleware::bearer::{AuthContext, RequireScopeWrite, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::gaps::{gap_analysis, surface_gaps, GapAnalysisRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, seed_agent_with_group, seed_group_claim};

/// A statement whose every 6-character window is foreign to the handler's own
/// templates and recommendations, so "no substring of the statement is stored"
/// is a meaningful assertion.
const STATEMENT: &str = "Quokkas7 hibernate beneath Zanzibar glaciers";
/// Deliberately disjoint from [`STATEMENT`]: the `question` column stores the
/// caller's question verbatim, and a question equal to the statement would
/// make the no-text assertion fail for a reason that is not a leak.
const QUESTION: &str = "gap probe query";

/// `AppState` exactly as `bin/server.rs` builds it, on the application role.
async fn production_state(pool: &PgPool) -> AppState {
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("epigraph_app ScopedPool");
    let state = AppState::with_scoped_pool(scoped, ApiConfig::default());
    let (user, privileged): (String, bool) = sqlx::query_as(
        "SELECT current_user::text, rolsuper OR rolbypassrls \
           FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&state.db_pool)
    .await
    .expect("role of the production pool");
    assert_eq!(user, "epigraph_app", "CALIBRATION: db_pool is the app role");
    assert!(
        !privileged,
        "CALIBRATION: epigraph_app must be subject to row security"
    );
    state
}

async fn viewer(pool: &PgPool, agent: Uuid) -> ViewerExtractor {
    ViewerExtractor(Viewer::resolve(pool, agent).await.expect("resolve viewer"))
}

fn write_scope(agent: Uuid) -> RequireScopeWrite {
    RequireScopeWrite(AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: ClientType::Service,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    })
}

fn pgvec(v: &[f32]) -> String {
    format!(
        "[{}]",
        v.iter().map(f32::to_string).collect::<Vec<_>>().join(",")
    )
}

/// Every lower-cased 6-character window of [`STATEMENT`] found in `text`.
fn statement_windows_in(text: &str) -> Vec<String> {
    let hay = text.to_lowercase();
    let chars: Vec<char> = STATEMENT.to_lowercase().chars().collect();
    chars
        .windows(6)
        .map(|w| w.iter().collect::<String>())
        .filter(|w| hay.contains(w.as_str()))
        .collect()
}

/// Member A's group-private claim, ranked at similarity 1.0 for [`QUESTION`]
/// and with a low truth value, so the analysis reports it as a blind spot.
async fn private_claim(pool: &PgPool, embedder: &dyn EmbeddingService) -> (Uuid, Uuid, Uuid) {
    let (member, group) = seed_agent_with_group(pool, "gaps-member").await;
    let (stranger, _) = seed_agent_with_group(pool, "gaps-stranger").await;
    let claim = seed_group_claim(pool, member, group, STATEMENT).await;
    let vector = pgvec(&embedder.generate(QUESTION).await.expect("mock embedding"));
    viewer_fixture::set_claim_embedding(pool, claim, &vector).await;
    sqlx::query("UPDATE claims SET truth_value = 0.1 WHERE id = $1")
        .bind(claim)
        .execute(pool)
        .await
        .expect("lower the truth value");
    (member, stranger, claim)
}

// ── gap_analysis ──

#[sqlx::test(migrations = "../../migrations")]
async fn gap_analysis_sees_the_members_private_claim_and_stores_its_id_not_its_text(pool: PgPool) {
    let embedder: std::sync::Arc<dyn EmbeddingService> =
        std::sync::Arc::new(MockProvider::new(EmbeddingConfig::openai(1536)));
    let (member, _stranger, claim) = private_claim(&pool, embedder.as_ref()).await;
    let state = production_state(&pool)
        .await
        .with_embedding_service(embedder);

    let Json(body) = gap_analysis(
        write_scope(member),
        viewer(&pool, member).await,
        State(state),
        Json(GapAnalysisRequest {
            question: QUESTION.to_string(),
            min_gap_severity: None,
        }),
    )
    .await
    .expect("gap_analysis");

    // The caller's own view may carry text: it is the caller's claim.
    let response = body.to_string();
    assert!(
        body["graph_claims_count"] == 1 && response.contains(&claim.to_string()),
        "POSITIVE CONTROL: the member's own private claim must be analysed on the \
         stamped connection (an unstamped read on the app role sees it as absent): {body}"
    );

    let analysis_id: Uuid = body["gap_analysis_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("gap_analysis_id");
    let (gaps, question, boundary): (serde_json::Value, String, Option<String>) = sqlx::query_as(
        "SELECT gaps, question, confidence_boundary FROM gap_analyses WHERE id = $1",
    )
    .bind(analysis_id)
    .fetch_one(&pool)
    .await
    .expect("the stored analysis");

    let ids: Vec<String> = gaps
        .as_array()
        .expect("gaps array")
        .iter()
        .filter_map(|g| g["nearest_claim_id"].as_str().map(String::from))
        .collect();
    assert!(
        ids.contains(&claim.to_string()),
        "the stored row must name the analysed claim by id: {gaps}"
    );
    let stored = format!("{gaps} {question} {}", boundary.unwrap_or_default());
    let leaked = statement_windows_in(&stored);
    assert!(
        leaked.is_empty(),
        "gap_analyses has no tenancy, so it must hold no claim text; found \
         statement fragments {leaked:?} in {stored}"
    );
}

// ── surface_gaps ──

/// A stored analysis in the pre-fix shape: claim text in both text fields, and
/// the claim id. `surface_gaps` must use the id and ignore the text. A second
/// gap has text and NO id (every row written before ids were stored): it has
/// no claim to target, so it is skipped rather than served.
async fn legacy_analysis(
    pool: &PgPool,
    claim: Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Uuid {
    let id = Uuid::new_v4();
    let gaps = serde_json::json!([
        {
            "gap_type": "blind_spot",
            "severity": 0.9,
            "unconstrained_claim": format!("Low truth (0.10) on relevant claim: {STATEMENT}"),
            "nearest_graph_claim": STATEMENT,
            "nearest_claim_id": claim,
            "nearest_similarity": 1.0,
            "graph_inference_path": null,
            "recommendation": "Investigate low-truth claim for missing evidence",
        },
        {
            "gap_type": "confidence_divergence",
            "severity": 0.9,
            "unconstrained_claim": format!("High ignorance (0.60) on: {STATEMENT}"),
            "nearest_graph_claim": STATEMENT,
            "nearest_similarity": 1.0,
            "graph_inference_path": null,
            "recommendation": "Gather more evidence to reduce ignorance",
        },
    ]);
    sqlx::query(
        "INSERT INTO gap_analyses (id, question, graph_claims_count, \
         unconstrained_claims_count, matched_count, gap_count, proprietary_count, gaps, \
         created_at) VALUES ($1, $2, 1, 0, 0, 2, 0, $3, $4)",
    )
    .bind(id)
    .bind(QUESTION)
    .bind(&gaps)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("plant a stored analysis");
    id
}

/// A newer, unrelated analysis, so the one under test is NOT the newest row.
async fn newer_analysis(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO gap_analyses (id, question, graph_claims_count, \
         unconstrained_claims_count, matched_count, gap_count, proprietary_count, gaps, \
         created_at) VALUES ($1, 'a later question', 0, 0, 0, 0, 0, '[]'::jsonb, now())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("plant a newer analysis");
    id
}

async fn surface(
    pool: &PgPool,
    state: AppState,
    caller: Uuid,
    analysis: Uuid,
) -> Result<serde_json::Value, epigraph_api::errors::ApiError> {
    let request: epigraph_api::routes::gaps::SurfaceGapsRequest =
        serde_json::from_value(serde_json::json!({ "gap_analysis_id": analysis }))
            .expect("request");
    surface_gaps(
        write_scope(caller),
        viewer(pool, caller).await,
        State(state),
        Json(request),
    )
    .await
    .map(|Json(v)| v)
}

/// `(challenger, explanation)` of every challenge filed against `claim`.
async fn challenges_on(pool: &PgPool, claim: Uuid) -> Vec<(Option<Uuid>, String)> {
    sqlx::query_as("SELECT challenger_id, explanation FROM challenges WHERE claim_id = $1")
        .bind(claim)
        .fetch_all(pool)
        .await
        .expect("challenges on the claim")
}

#[sqlx::test(migrations = "../../migrations")]
async fn surface_gaps_files_an_id_only_challenge_for_the_member(pool: PgPool) {
    let embedder = MockProvider::new(EmbeddingConfig::openai(1536));
    let (member, _stranger, claim) = private_claim(&pool, &embedder).await;
    let analysis = legacy_analysis(&pool, claim, chrono::Utc::now()).await;
    let state = production_state(&pool).await;

    let body = surface(&pool, state, member, analysis)
        .await
        .expect("surface_gaps for the member");
    assert_eq!(
        body["challenges_created"], 1,
        "exactly the gap that names a claim the member can read is surfaced; the \
         text-only legacy gap has no target: {body}"
    );

    let filed = challenges_on(&pool, claim).await;
    assert_eq!(filed.len(), 1, "one challenge on the claim: {filed:?}");
    let (challenger, explanation) = &filed[0];
    assert_eq!(*challenger, Some(member), "the caller is the challenger");
    assert_eq!(
        explanation,
        &format!("gap_blind_spot: claim {claim}"),
        "the challenge names the gap type and the claim id only"
    );
    let leaked = statement_windows_in(&format!("{explanation} {body}"));
    assert!(
        leaked.is_empty(),
        "no stored statement text may be copied into a challenge: {leaked:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn surface_gaps_skips_a_claim_the_caller_cannot_read(pool: PgPool) {
    let embedder = MockProvider::new(EmbeddingConfig::openai(1536));
    let (_member, stranger, claim) = private_claim(&pool, &embedder).await;
    let analysis = legacy_analysis(&pool, claim, chrono::Utc::now()).await;
    let state = production_state(&pool).await;

    let body = surface(&pool, state, stranger, analysis)
        .await
        .expect("surface_gaps for the stranger answers, it does not error");
    assert_eq!(
        body["challenges_created"], 0,
        "the stranger cannot read the member's private claim: {body}"
    );
    assert!(
        challenges_on(&pool, claim).await.is_empty(),
        "nothing may be filed against a claim the caller cannot read"
    );
    let leaked = statement_windows_in(&body.to_string());
    assert!(leaked.is_empty(), "the response leaks {leaked:?}: {body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn surface_gaps_finds_an_analysis_that_is_not_the_newest(pool: PgPool) {
    let embedder = MockProvider::new(EmbeddingConfig::openai(1536));
    let (member, _stranger, claim) = private_claim(&pool, &embedder).await;
    let older = legacy_analysis(&pool, claim, chrono::Utc::now() - chrono::Duration::days(1)).await;
    let newest = newer_analysis(&pool).await;
    assert_ne!(older, newest);
    let state = production_state(&pool).await;

    let body = surface(&pool, state, member, older)
        .await
        .expect("an older analysis id must be found, not answered 404");
    assert_eq!(body["challenges_created"], 1, "{body}");
}
