//! `PATCH /api/v1/claims/:id` writes on the CALLER's stamped transaction on
//! every path, not only the audited admin path (backlog 7c2a0b36).
//!
//! The non-admin branch (the claim's author, or a `claims:admin` caller that
//! can write the owning group) opened `state.db_pool.begin()`: a transaction
//! that told the database nothing about who was writing. Two failures follow,
//! one per deployment shape:
//!
//! * both pools on the application role (no BYPASSRLS, FORCEd tenancy
//!   policies), the shape production serves from: an unstamped session has an
//!   empty writable set, so `claims_tenancy`'s `WITH CHECK` refused EVERY
//!   author, including one patching a claim in its own group, and the refusal
//!   surfaced as a 500;
//! * a privileged raw pool with an application-role `ScopedPool` (a
//!   deployment whose `DATABASE_URL` is the owner): row security never ran,
//!   so an author patched a claim owned by a group it cannot write.
//!
//! Stamped with the caller's viewer, the author's own group's claim patches
//! (200) and a claim owned by a group the caller cannot write is a 403 with
//! nothing written (no label, no property, no provenance row), on both shapes.
//!
//! The refused claim is the shape `update_labels` pins over MCP: PUBLIC (so the
//! caller can read it, and the 404 for an unreadable claim does not fire),
//! AUTHORED by the caller (so the Rust ownership gate admits it), and OWNED by
//! another group (so only the database can refuse it).
#![cfg(feature = "db")]

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::{Extension, Json};
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::claims::{patch_claim, PatchClaimRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool, seed_agent_with_group};

async fn app_role_scoped(pool: &PgPool) -> ScopedPool {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = database_url_for(pool).await;
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("app-role ScopedPool")
}

/// Both pools on the application role.
async fn app_role_state(pool: &PgPool) -> AppState {
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(app_role_scoped(pool).await);
    state
}

/// The raw pool is the harness superuser; the stamped pool is the app role.
async fn privileged_raw_state(pool: &PgPool) -> AppState {
    let mut state = AppState::with_db(pool.clone(), ApiConfig::default());
    state.scoped = Some(app_role_scoped(pool).await);
    state
}

async fn viewer(pool: &PgPool, agent: Uuid) -> ViewerExtractor {
    ViewerExtractor(Viewer::resolve(pool, agent).await.expect("resolve"))
}

fn auth(agent: Uuid) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: agent,
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: ClientType::Human,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }))
}

/// The author with its OAuth client. The fixture gives the client the
/// agent's own id, so `require_owner_or_admin`'s principal (the token's
/// `owner_id`) is the claim's author, and the provenance row's
/// `submitted_by` / `principal_id` foreign keys to `oauth_clients` hold.
async fn seed_author(pool: &PgPool, label: &str) -> (Uuid, Uuid) {
    let (agent, group) = seed_agent_with_group(pool, label).await;
    sqlx::query(
        "INSERT INTO oauth_clients (id, client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id) \
         VALUES ($1, $2, '7c2a0b36 author', 'human', ARRAY['claims:write'], 'active', $1)",
    )
    .bind(agent)
    .bind(format!("fixture-7c2a0b36-{agent}"))
    .execute(pool)
    .await
    .expect("the author's OAuth client");
    (agent, group)
}

/// A PUBLIC claim authored by `agent` and owned by `group`.
async fn public_claim(pool: &PgPool, agent: Uuid, group: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, labels, properties) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5, ARRAY['before']::text[], \
                 '{\"kept\": 1}'::jsonb)",
    )
    .bind(id)
    .bind(format!("7c2a0b36 claim {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

fn request() -> Json<PatchClaimRequest> {
    Json(
        serde_json::from_value(serde_json::json!({
            "properties": { "patched": true },
            "add_labels": ["patched-7c2a0b36"],
        }))
        .expect("request"),
    )
}

/// `(labels, properties, provenance rows)` of `claim`, read on the superuser
/// harness connection so nothing is filtered.
async fn state_of(pool: &PgPool, claim: Uuid) -> (Vec<String>, serde_json::Value, i64) {
    let (labels, properties): (Vec<String>, serde_json::Value) =
        sqlx::query_as("SELECT labels, properties FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(pool)
            .await
            .expect("claim");
    let provenance: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM provenance_log WHERE record_type = 'claim' AND record_id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("provenance");
    (labels, properties, provenance)
}

/// The author patches a claim its own group owns: 200, and the row changed.
async fn assert_author_patches_own_groups_claim(pool: PgPool, state: AppState, label: &str) {
    let (author, group) = seed_author(&pool, &format!("{label}-author")).await;
    let claim = public_claim(&pool, author, group).await;

    let Json(body) = patch_claim(
        viewer(&pool, author).await,
        State(state),
        auth(author),
        Path(claim),
        request(),
    )
    .await
    .unwrap_or_else(|e| panic!("{label}: the author patches its own group's claim: {e:?}"));
    assert_eq!(body.id, claim, "{label}");

    let (labels, properties, provenance) = state_of(&pool, claim).await;
    assert!(
        labels.contains(&"patched-7c2a0b36".to_string()) && labels.contains(&"before".to_string()),
        "{label}: the label landed beside the existing one: {labels:?}"
    );
    assert_eq!(
        properties,
        serde_json::json!({ "kept": 1, "patched": true }),
        "{label}: the properties were merged"
    );
    assert_eq!(provenance, 1, "{label}: one provenance row for the patch");
}

/// The author patches its own claim owned by a group it cannot write: 403,
/// and nothing about the claim or its provenance changed.
async fn assert_unwritable_group_is_refused(pool: PgPool, state: AppState, label: &str) {
    let (author, _) = seed_author(&pool, &format!("{label}-author")).await;
    let (_, other_group) = seed_agent_with_group(&pool, &format!("{label}-other")).await;
    let claim = public_claim(&pool, author, other_group).await;
    let before = state_of(&pool, claim).await;

    let res = patch_claim(
        viewer(&pool, author).await,
        State(state),
        auth(author),
        Path(claim),
        request(),
    )
    .await;
    match res {
        Err(ApiError::Forbidden { ref reason }) => assert!(
            reason.contains("nothing was written") && !reason.contains(&other_group.to_string()),
            "{label}: the 403 says nothing was written and does not name the group: {reason}"
        ),
        other => panic!(
            "{label}: an author without write authority over the owning group must get 403, \
             got {other:?}"
        ),
    }
    assert_eq!(
        state_of(&pool, claim).await,
        before,
        "{label}: nothing written (labels, properties, provenance)"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn author_patches_own_groups_claim_on_the_app_role(pool: PgPool) {
    let state = app_role_state(&pool).await;
    assert_author_patches_own_groups_claim(pool, state, "app-role").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn author_patches_own_groups_claim_on_a_privileged_raw_pool(pool: PgPool) {
    let state = privileged_raw_state(&pool).await;
    assert_author_patches_own_groups_claim(pool, state, "privileged-raw").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn unwritable_group_is_a_403_with_nothing_written_on_the_app_role(pool: PgPool) {
    let state = app_role_state(&pool).await;
    assert_unwritable_group_is_refused(pool, state, "app-role").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn unwritable_group_is_a_403_with_nothing_written_on_a_privileged_raw_pool(pool: PgPool) {
    let state = privileged_raw_state(&pool).await;
    assert_unwritable_group_is_refused(pool, state, "privileged-raw").await;
}
