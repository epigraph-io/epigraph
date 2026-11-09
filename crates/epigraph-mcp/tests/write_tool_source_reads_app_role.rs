//! The READS inside four MCP write tools run as the CALLER, on the application
//! role: a member's own group-private sources, frame and workflow steps are
//! found, and a stranger's lookup of the same private steps is not.
//!
//! # The defect this pins
//!
//! The read-conversion moved every content-READING tool onto
//! `EpiGraphMcpFull::read_as`, but four reads inside WRITE tools still ran on
//! the server's plain pool with the caller's `Viewer`:
//!
//! * `consolidate_claims`' default confidence (`confidence` omitted) read each
//!   source's `truth_value` there. Row security on the application login admits
//!   public rows only on an unstamped connection, so a member's own
//!   group-private sources read as missing, `best` stayed 0 and the merged claim
//!   was written with `truth_value = 0`: silently, no error.
//! * `submit_ds_evidence` read its frame there, so a member's own group-private
//!   frame answered `frame <id> not found`.
//! * `update_with_evidence` and `evolve_step`, addressed by `canonical_name` +
//!   `step_index`, resolved the step there, so a workflow whose steps and
//!   `executes` edges are group-private answered `no step at index 0` to the
//!   group's own members.
//!
//! The in-query viewer predicate admitted every one of these rows; the session
//! policy dropped them. CI did not see it because `#[sqlx::test]` connects as a
//! BYPASSRLS superuser. Here BOTH of the server's pools are `epigraph_app`:
//! the `ScopedPool` and the plain pool, which is that `ScopedPool`'s own inner
//! pool, as `main.rs` builds it. Seeding and `Viewer::resolve` run on the
//! superuser pool.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_auth::AuthContext;
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::types::{ConsolidateClaimsParams, SubmitDsEvidenceParams};
use sqlx::PgPool;
use uuid::Uuid;

/// The production server shape on the application role. Refuses to run
/// vacuously: the role must not bypass row security, and the plain pool must
/// really be `epigraph_app`.
async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every assertion here would be vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = scoped.inner().clone();
    let who: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&plain)
        .await
        .expect("session_user");
    assert_eq!(
        who, "epigraph_app",
        "PREMISE: the plain pool must be the application role, or a raw-pool read \
         would see every row and the red half of this file would be vacuous"
    );
    build_scoped_test_server(plain, scoped)
}

/// A `claims:write` caller with its own personal group (as `seed_caller`), and
/// that group.
async fn member(pool: &PgPool) -> (Uuid, AuthContext, Viewer, Uuid) {
    let (agent, auth, _) = seed_caller(pool, &["claims:write"]).await;
    let group = personal_group_of(pool, agent).await;
    // Re-resolve now that the group is certainly there.
    let viewer = Viewer::resolve(pool, agent).await.expect("member viewer");
    (agent, auth, viewer, group)
}

async fn private_claim(pool: &PgPool, agent: Uuid, group: Uuid, content: &str, truth: f64) -> Uuid {
    let id = fixture::seed_group_claim(pool, agent, group, content).await;
    sqlx::query("UPDATE claims SET truth_value = $2 WHERE id = $1")
        .bind(id)
        .bind(truth)
        .execute(pool)
        .await
        .expect("set truth_value");
    let (vis, owner): (String, Uuid) =
        sqlx::query_as("SELECT visibility::text, owner_group_id FROM claims WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("tenancy read-back");
    assert_eq!(
        (vis.as_str(), owner),
        ("group", group),
        "fixture: the claim is private to the member's group"
    );
    id
}

// ───────────────────────────── consolidate_claims ─────────────────────────────

/// Two group-private sources at 0.8, merged by their own member with
/// `confidence` omitted: the default is the strongest source discounted by
/// 0.95, so 0.76. On the plain pool both sources read as missing and the
/// merged claim was written at 0.
#[sqlx::test(migrations = "../../migrations")]
async fn consolidate_default_confidence_reads_the_members_private_sources(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (agent, auth, viewer, group) = member(&pool).await;
    let a = private_claim(&pool, agent, group, "consolidate source A (private)", 0.8).await;
    let b = private_claim(&pool, agent, group, "consolidate source B (private)", 0.8).await;

    let res = epigraph_mcp::tools::consolidate::consolidate_claims(
        &server,
        &viewer,
        ConsolidateClaimsParams {
            source_claim_ids: vec![a.to_string(), b.to_string()],
            merged_content: "the two private sources, merged".to_string(),
            mode: "merge".to_string(),
            reason: "app-role default-confidence probe".to_string(),
            confidence: None,
        },
        Some(&auth),
    )
    .await
    .unwrap_or_else(|e| panic!("a member merges its own private claims: {}", e.message));
    let merged = parse_uuid_field(&first_text(&res), "merged_claim_id");

    let truth: f64 = sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
        .bind(merged)
        .fetch_one(&pool)
        .await
        .expect("merged truth");
    assert!(
        (truth - 0.76).abs() < 1e-9,
        "the merged claim's default confidence is 0.8 * 0.95 = 0.76, read from the member's \
         own private sources; got {truth} (0 means the sources were read on an unstamped \
         session and seen as missing)"
    );
}

// ───────────────────────────── submit_ds_evidence ─────────────────────────────

/// A member files a BBA on its own private claim against its own private
/// frame. On the plain pool the frame read answered `frame <id> not found`.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_ds_evidence_reads_the_members_private_frame(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (agent, auth, viewer, group) = member(&pool).await;
    let claim = private_claim(&pool, agent, group, "ds evidence target (private)", 0.5).await;

    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("private-frame-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed frame");
    sqlx::query("UPDATE frames SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(frame)
        .bind(group)
        .execute(&pool)
        .await
        .expect("privatise frame");

    let params: SubmitDsEvidenceParams = serde_json::from_value(serde_json::json!({
        "claim_id": claim.to_string(),
        "frame_id": frame.to_string(),
        "hypothesis_index": 0,
        "masses": {"0": 0.7, "0,1": 0.3},
    }))
    .expect("params");
    epigraph_mcp::tools::ds::submit_ds_evidence(&server, &viewer, params, Some(&auth))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "a member files evidence against its own private frame (an unstamped frame \
                 read reports it missing): {}",
                e.message
            )
        });

    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions WHERE claim_id = $1 AND frame_id = $2",
    )
    .bind(claim)
    .bind(frame)
    .fetch_one(&pool)
    .await
    .expect("count BBAs");
    assert_eq!(n, 1, "the BBA landed on the private frame");
}
