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
use epigraph_api::routes::gaps::{gap_analysis, GapAnalysisRequest};
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
