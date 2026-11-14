#![cfg(feature = "db")]
//! `POST /api/v1/claims/:id/assess` never puts a vector on a sealed claim
//! (backlog f78526ad).
//!
//! Step 9 of `assess_claim` embedded the claim's content and stored it with a
//! bare `UPDATE claims SET embedding = $1::vector WHERE id = $2` on the
//! unstamped pool. That statement carried none of the predicates the shared
//! writer `ClaimRepository::store_embedding_if_unsealed` carries: no
//! `claim_encryption` check, no `is_current` check, no writable-group splice.
//! A sealed claim's whole point is that no plaintext-derived vector survives
//! (CLAUDE.md's `sealed_with_embedding` audit is a page-the-on-call
//! condition), and assessing one put a vector back. The store now goes through
//! `AppState::store_claim_embedding_as`, which runs the shared writer on a
//! transaction stamped with the caller's viewer.
//!
//! The state is `AppState::with_db` on the harness superuser, so the old
//! statement was admitted on every row: only the statement's own predicates
//! can refuse it. The unsealed claim is the calibration that the embedder is
//! wired and the route does embed.

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::Json;
use epigraph_api::routes::assess::{assess_claim, AssessClaimRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

fn request() -> AssessClaimRequest {
    serde_json::from_value(serde_json::json!({
        "evidence_type": "empirical",
        "methodology": "instrumental",
        "confidence": 0.8,
        "supports": true,
    }))
    .expect("AssessClaimRequest deserializes")
}

fn state(pool: &PgPool) -> AppState {
    let svc: Arc<dyn EmbeddingService> = Arc::new(MockProvider::new(EmbeddingConfig::openai(1536)));
    AppState::with_db(pool.clone(), ApiConfig::default()).with_embedding_service(svc)
}

/// A `claim_encryption` row for a group-private claim (migration 081 refuses
/// a seal on a public one).
async fn seal(pool: &PgPool, claim: Uuid, group: Uuid) {
    sqlx::query(
        "INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active') \
         ON CONFLICT DO NOTHING",
    )
    .bind(group)
    .execute(pool)
    .await
    .expect("seed the group key epoch the FK requires");
    sqlx::query(
        "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, \
                                       encrypted_content) \
         VALUES ($1, $2, 0, 'fully_private', decode('0badc0de', 'hex'))",
    )
    .bind(claim)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed a claim_encryption row");
}

async fn has_vector(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read claim vector")
}

async fn assess(pool: &PgPool, caller: Uuid, claim: Uuid) -> bool {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve caller");
    let Json(resp) = assess_claim(
        write_scope(),
        epigraph_api::middleware::bearer::ViewerExtractor(viewer),
        State(state(pool)),
        Path(claim),
        Json(request()),
    )
    .await
    .unwrap_or_else(|e| panic!("assess_claim failed: {e:?}"));
    resp.embedded
}

#[sqlx::test(migrations = "../../migrations")]
async fn assessing_a_sealed_claim_stores_no_vector(pool: PgPool) {
    let (owner, group) = viewer_fixture::seed_agent_with_group(&pool, "assess-seal").await;

    // CALIBRATION: an unsealed claim of the same owner and group is embedded.
    let open = viewer_fixture::seed_group_claim(&pool, owner, group, "assess open claim").await;
    assert!(!has_vector(&pool, open).await, "starts without a vector");
    assert!(assess(&pool, owner, open).await, "reported embedded");
    assert!(
        has_vector(&pool, open).await,
        "CALIBRATION: the vector is stored"
    );

    let sealed = viewer_fixture::seed_group_claim(&pool, owner, group, "assess sealed claim").await;
    seal(&pool, sealed, group).await;
    let embedded = assess(&pool, owner, sealed).await;
    assert!(
        !has_vector(&pool, sealed).await,
        "a sealed claim must not regain a plaintext-derived vector"
    );
    assert!(
        !embedded,
        "the response does not claim an embedding it did not store"
    );
}

/// The `claims:write` scope `assess_claim` takes first (backlog f00d75ab).
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
