#![cfg(feature = "db")]
//! The request-validation refusals of the db `supersede_claim`
//! (`POST /api/v1/claims/:id/supersede`), on a fresh database through the
//! application role.
//!
//! Each refusal is a 400 `ValidationError` naming its field, and it writes
//! nothing: no replacement claim, no `supersedes` edge, no version row, no
//! cascade audit row, and the original stays current. Its only coverage used
//! to be the in-memory `not(db)` tests in `routes/versioning.rs`, which ran
//! against a 503 stub and so proved nothing about this arm (backlog candidate
//! B100-supersede-validation-tests).
//!
//! One test per check: removing or weakening a check fails at least one test,
//! and only that check's tests (the boundary control below catches an
//! off-by-one in either cap or in the range).
//! The truth-value refusal is enforced twice in the handler (the explicit
//! bounds check, then `TruthValue::new`), with the same field and text; the
//! tests here pin the refusal, which only removing both would change.
//!
//! The controls at the end supersede at the exact boundaries (content and
//! reason at their byte caps, truth 1.0 and then 0.0) and assert that the same
//! snapshot DOES move, so "nothing written" is not an observer that cannot
//! see the writes.

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Extension;
use axum::Json;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::AuthContext;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::versioning::{supersede_claim, SupersedeRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool, seed_agent_with_group, seed_group_claim};

/// `routes::versioning::MAX_CONTENT_LENGTH`, in bytes (private there).
const MAX_CONTENT_BYTES: usize = 65_536;
/// `routes::versioning::MAX_REASON_LENGTH`, in bytes (private there).
const MAX_REASON_BYTES: usize = 32_768;

async fn app_role_state(pool: &PgPool) -> AppState {
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

fn auth(agent: Uuid) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: agent,
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
    }))
}

fn request(
    content: impl Into<String>,
    truth_value: f64,
    reason: impl Into<String>,
) -> SupersedeRequest {
    SupersedeRequest {
        content: content.into(),
        truth_value,
        reason: reason.into(),
    }
}

/// A valid request, for a case to break one field of.
fn valid() -> SupersedeRequest {
    request("v-test the restated claim", 0.6, "v-test a reason")
}

async fn rendered(e: ApiError) -> (u16, serde_json::Value) {
    let resp = e.into_response();
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// Everything a supersession of `old` writes, read on the test's own pool.
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    claims: i64,
    edges: i64,
    claim_versions: i64,
    security_events: i64,
    successors_of_old: i64,
    supersedes_edges_into_old: i64,
    old_is_current: bool,
}

async fn count(pool: &PgPool, sql: &str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
}

async fn snapshot(pool: &PgPool, old: Uuid) -> Snapshot {
    Snapshot {
        claims: count(pool, "SELECT count(*) FROM claims").await,
        edges: count(pool, "SELECT count(*) FROM edges").await,
        claim_versions: count(pool, "SELECT count(*) FROM claim_versions").await,
        security_events: count(pool, "SELECT count(*) FROM security_events").await,
        successors_of_old: sqlx::query_scalar("SELECT count(*) FROM claims WHERE supersedes = $1")
            .bind(old)
            .fetch_one(pool)
            .await
            .expect("successors"),
        supersedes_edges_into_old: sqlx::query_scalar(
            "SELECT count(*) FROM edges WHERE target_id = $1 \
               AND lower(relationship) = 'supersedes'",
        )
        .bind(old)
        .fetch_one(pool)
        .await
        .expect("supersedes edges"),
        old_is_current: sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
            .bind(old)
            .fetch_one(pool)
            .await
            .expect("old is_current"),
    }
}

/// An author, its group, a claim of theirs to supersede, and the app-role
/// state.
async fn setup(pool: &PgPool, label: &str) -> (AppState, Uuid, Uuid) {
    let state = app_role_state(pool).await;
    let (h, hg) = seed_agent_with_group(pool, label).await;
    let old = seed_group_claim(pool, h, hg, &format!("{label} a claim to restate")).await;
    (state, h, old)
}

async fn supersede(
    pool: &PgPool,
    state: &AppState,
    caller: Uuid,
    old: Uuid,
    req: SupersedeRequest,
) -> Result<Uuid, ApiError> {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve");
    supersede_claim(
        ViewerExtractor(viewer),
        State(state.clone()),
        auth(caller),
        Path(old),
        Json(req),
    )
    .await
    .map(|(status, Json(resp))| {
        assert_eq!(status.as_u16(), 201, "a supersession is 201");
        resp.new_claim_id
    })
}

/// The author's supersession `req` of their own claim is refused with a 400
/// `ValidationError` on `field` whose reason contains `reason`, and nothing
/// is written.
async fn assert_refused(
    pool: &PgPool,
    label: &str,
    req: SupersedeRequest,
    field: &str,
    reason: &str,
) {
    let (state, h, old) = setup(pool, label).await;
    let before = snapshot(pool, old).await;
    assert!(
        before.old_is_current,
        "{label}: the seeded claim is current"
    );

    let e = supersede(pool, &state, h, old, req)
        .await
        .expect_err("an invalid supersession is refused");
    let (status, json) = rendered(e).await;
    assert_eq!(status, 400, "{label}: {json}");
    assert_eq!(json["error"], "ValidationError", "{label}: {json}");
    assert_eq!(json["details"]["field"], field, "{label}: {json}");
    let got = json["details"]["reason"].as_str().unwrap_or_default();
    assert!(
        got.contains(reason),
        "{label}: reason {got:?} should contain {reason:?}"
    );

    assert_eq!(
        snapshot(pool, old).await,
        before,
        "{label}: a refused supersession writes nothing"
    );
}

// --- content ---------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn empty_content_is_refused(pool: PgPool) {
    let req = SupersedeRequest {
        content: String::new(),
        ..valid()
    };
    assert_refused(
        &pool,
        "v-empty-content",
        req,
        "content",
        "Content cannot be empty",
    )
    .await;
}

/// The check trims: whitespace alone is empty content.
#[sqlx::test(migrations = "../../migrations")]
async fn whitespace_only_content_is_refused(pool: PgPool) {
    let req = SupersedeRequest {
        content: " \t\n ".to_string(),
        ..valid()
    };
    assert_refused(
        &pool,
        "v-ws-content",
        req,
        "content",
        "Content cannot be empty",
    )
    .await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn content_one_byte_over_the_cap_is_refused(pool: PgPool) {
    let req = SupersedeRequest {
        content: "c".repeat(MAX_CONTENT_BYTES + 1),
        ..valid()
    };
    assert_refused(&pool, "v-long-content", req, "content", "Content too long").await;
}

/// The cap is in BYTES: 32,769 two-byte characters (65,538 bytes) are over
/// it although their character count is half of it.
#[sqlx::test(migrations = "../../migrations")]
async fn content_cap_counts_bytes_not_characters(pool: PgPool) {
    let content = "\u{e9}".repeat(MAX_CONTENT_BYTES / 2 + 1);
    assert!(content.len() > MAX_CONTENT_BYTES && content.chars().count() <= MAX_CONTENT_BYTES);
    let req = SupersedeRequest { content, ..valid() };
    assert_refused(&pool, "v-mb-content", req, "content", "Content too long").await;
}

// --- reason ----------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn empty_reason_is_refused(pool: PgPool) {
    let req = SupersedeRequest {
        reason: String::new(),
        ..valid()
    };
    assert_refused(
        &pool,
        "v-empty-reason",
        req,
        "reason",
        "Reason cannot be empty",
    )
    .await;
}

/// The check trims: whitespace alone is an empty reason.
#[sqlx::test(migrations = "../../migrations")]
async fn whitespace_only_reason_is_refused(pool: PgPool) {
    let req = SupersedeRequest {
        reason: "\n  \t".to_string(),
        ..valid()
    };
    assert_refused(
        &pool,
        "v-ws-reason",
        req,
        "reason",
        "Reason cannot be empty",
    )
    .await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn reason_one_byte_over_the_cap_is_refused(pool: PgPool) {
    let req = SupersedeRequest {
        reason: "r".repeat(MAX_REASON_BYTES + 1),
        ..valid()
    };
    assert_refused(&pool, "v-long-reason", req, "reason", "Reason too long").await;
}

// --- truth_value -----------------------------------------------------------

const TRUTH_RANGE: &str = "Truth value must be between 0.0 and 1.0";

#[sqlx::test(migrations = "../../migrations")]
async fn truth_value_above_one_is_refused(pool: PgPool) {
    let req = SupersedeRequest {
        truth_value: 1.5,
        ..valid()
    };
    assert_refused(&pool, "v-truth-high", req, "truth_value", TRUTH_RANGE).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn truth_value_below_zero_is_refused(pool: PgPool) {
    let req = SupersedeRequest {
        truth_value: -0.1,
        ..valid()
    };
    assert_refused(&pool, "v-truth-low", req, "truth_value", TRUTH_RANGE).await;
}

/// JSON cannot carry these, but the handler is also called in-process; a NaN
/// fails every range comparison, so it is the case a bounds check written as
/// `v < 0.0 || v > 1.0` lets through.
#[sqlx::test(migrations = "../../migrations")]
async fn non_finite_truth_values_are_refused(pool: PgPool) {
    for (label, tv) in [
        ("v-truth-nan", f64::NAN),
        ("v-truth-inf", f64::INFINITY),
        ("v-truth-neg-inf", f64::NEG_INFINITY),
    ] {
        let req = SupersedeRequest {
            truth_value: tv,
            ..valid()
        };
        assert_refused(&pool, label, req, "truth_value", TRUTH_RANGE).await;
    }
}

// --- controls --------------------------------------------------------------

/// CONTROL, at the exact boundaries: content at its byte cap, reason at its
/// byte cap and truth 1.0 supersede (201), and the replacement then supersedes
/// at truth 0.0. Each moves the snapshot the refusals leave unchanged, so the
/// observer above can see a supersession's writes, and the caps and the range
/// are inclusive.
#[sqlx::test(migrations = "../../migrations")]
async fn boundary_values_supersede_and_move_the_snapshot(pool: PgPool) {
    let (state, h, old) = setup(&pool, "v-boundary").await;
    let before = snapshot(&pool, old).await;

    let content = "b".repeat(MAX_CONTENT_BYTES);
    let reason = "r".repeat(MAX_REASON_BYTES);
    let new = supersede(&pool, &state, h, old, request(content, 1.0, reason))
        .await
        .unwrap_or_else(|e| panic!("CONTROL: content and reason at their caps, truth 1.0: {e:?}"));

    let after = snapshot(&pool, old).await;
    assert!(!after.old_is_current, "the original is retired");
    assert_eq!(after.successors_of_old, before.successors_of_old + 1);
    assert_eq!(
        after.supersedes_edges_into_old,
        before.supersedes_edges_into_old + 1
    );
    assert_eq!(after.claims, before.claims + 1, "one replacement claim");
    assert!(after.edges > before.edges, "the lineage edge is visible");
    assert!(
        after.claim_versions > before.claim_versions,
        "the version row is visible"
    );
    assert!(
        after.security_events > before.security_events,
        "the cascade audit row is visible"
    );

    let new_before = snapshot(&pool, new).await;
    supersede(
        &pool,
        &state,
        h,
        new,
        request(
            "v-boundary the second restatement",
            0.0,
            "v-boundary truth 0.0",
        ),
    )
    .await
    .unwrap_or_else(|e| panic!("CONTROL: truth 0.0 supersedes: {e:?}"));
    let new_after = snapshot(&pool, new).await;
    assert!(!new_after.old_is_current);
    assert_eq!(new_after.claims, new_before.claims + 1);
}
