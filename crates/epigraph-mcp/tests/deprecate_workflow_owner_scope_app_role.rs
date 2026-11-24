//! Migration 237 (backlog 524f89c1) at the `deprecate_workflow` entry point,
//! on the APPLICATION ROLE.
//!
//! Since 237 a `workflows` UPDATE reaches only a row whose owner group the
//! session WRITES, and a filtered row raises nothing. The workflow authority
//! gate admits callers that write no such group: the recorded submitter (and
//! its operator, and a delegate) by identity, and the audited admin arm. So:
//!
//! * the admin arm deprecates the row through 237's audited admin definer,
//!   which re-checks the live grant and writes the one `workflows.admin_write`
//!   row, so an admin deprecation of another group's plan (here one with no
//!   claim left to retire) lands and is audited; on the stamp it would have
//!   committed "success" with the row still live;
//! * a caller admitted by identity that does not write the row's owner group
//!   is REFUSED, nothing written, instead of retiring the plan's claims (in a
//!   group it does write) and leaving the row live;
//! * the flat path refuses the same split when a flat workflow claim and a
//!   hierarchical row share an id.
//!
//! The MCP server under test runs both of its pools as `epigraph_app` (a
//! superuser pool bypasses row security and proves nothing here; the
//! `deprecate_hierarchical_workflow.rs` suite runs on one). Plans are ingested
//! through a second, superuser-pooled server and inspected on the harness pool.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, first_text, seed_admin_grant, seed_caller};
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools;
use epigraph_mcp::types::{DeprecateWorkflowParams, IngestWorkflowParams};
use sqlx::PgPool;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    build_scoped_test_server(plain, scoped)
}

fn extraction(canonical: &str) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical.to_string(),
            goal: format!("237 workflow {canonical}"),
            generation: 0,
            parent_canonical_name: None,
            authors: vec![],
            expected_outcome: None,
            tags: vec![],
            metadata: serde_json::json!({}),
        },
        thesis: None,
        thesis_derivation: ThesisDerivation::TopDown,
        phases: vec![Phase {
            title: "Body".to_string(),
            summary: format!("237 phase for {canonical}"),
            steps: vec![Step {
                compound: format!("the one step of {canonical}"),
                rationale: "because".to_string(),
                operations: vec![format!("the one operation of {canonical}")],
                generality: vec![1],
                confidence: 0.7,
                evidence_type: None,
            }],
        }],
        relationships: vec![],
    }
}

/// Ingest `canonical` as `token`'s caller, PUBLIC in the caller's own group,
/// through the superuser-pooled `server`; the new row's id.
async fn ingest(
    pool: &PgPool,
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    token: &epigraph_auth::AuthContext,
    canonical: &str,
) -> Uuid {
    tools::workflow_ingest::ingest_workflow(
        server,
        viewer,
        IngestWorkflowParams {
            extraction: extraction(canonical),
            tenancy: Some(common::public_tenancy_for(viewer)),
            embed: None,
        },
        Some(token),
    )
    .await
    .expect("ingest");
    sqlx::query_scalar("SELECT id FROM workflows WHERE canonical_name = $1 AND generation = 0")
        .bind(canonical)
        .fetch_one(pool)
        .await
        .expect("workflows row")
}

/// The level 0-2 claims `wf` executes.
async fn structural(pool: &PgPool, wf: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT c.id FROM edges e JOIN claims c ON c.id = e.target_id \
          WHERE e.source_id = $1 AND e.relationship = 'executes' \
            AND c.properties->>'level' IN ('0', '1', '2') ORDER BY c.id",
    )
    .bind(wf)
    .fetch_all(pool)
    .await
    .expect("executed claims")
}

async fn truth(pool: &PgPool, wf: Uuid) -> f64 {
    sqlx::query_scalar("SELECT truth_value FROM workflows WHERE id = $1")
        .bind(wf)
        .fetch_one(pool)
        .await
        .expect("workflow truth")
}

async fn is_current(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("claim row")
}

async fn admin_audits(pool: &PgPool, admin: Uuid) -> Vec<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT details FROM security_events \
          WHERE event_type = 'workflows.admin_write' AND agent_id = $1 ORDER BY created_at",
    )
    .bind(admin)
    .fetch_all(pool)
    .await
    .expect("audit rows")
}

async fn writes(pool: &PgPool, agent: Uuid, group: Uuid) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM group_memberships \
                         WHERE agent_id = $1 AND group_id = $2 AND revoked_at IS NULL \
                           AND role IN ('writer', 'admin'))",
    )
    .bind(agent)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("membership")
}

fn params(wf: Uuid) -> DeprecateWorkflowParams {
    DeprecateWorkflowParams {
        workflow_id: wf.to_string(),
        reason: "obsolete".into(),
        cascade: Some(false),
    }
}

/// The admin arm, end to end on the app role. The plan is another caller's,
/// PUBLIC in that caller's group, and every claim it executes is already
/// retired, so the row is the only thing left to write.
///
/// * A `claims:admin` token whose client was revoked is refused, nothing
///   written and nothing audited.
/// * With the grant live, the row is deprecated (0.05) and exactly one
///   `workflows.admin_write` row records it, written by 237's definer (its
///   `workflow_row` facts) around the tool's own record (`write.reason`).
///
/// On the stamp (the code before this change) the admin's UPDATE matched no
/// row, the tool committed and answered success, and the row stayed at 1.0.
#[sqlx::test(migrations = "../../migrations")]
async fn an_admin_deprecates_another_groups_plan_through_the_audited_definer(pool: PgPool) {
    let su = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let app = app_role_server(&pool).await;
    let (_owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let wf = ingest(&pool, &su, &owner_viewer, &owner_token, "wf237-admin").await;
    let claims = structural(&pool, wf).await;
    assert!(!claims.is_empty(), "fixture: the plan executes claims");
    sqlx::query("UPDATE claims SET is_current = false WHERE id = ANY($1)")
        .bind(&claims)
        .execute(&pool)
        .await
        .expect("retire the plan's claims");
    let owner_group: Uuid =
        sqlx::query_scalar("SELECT owner_group_id FROM workflows WHERE id = $1")
            .bind(wf)
            .fetch_one(&pool)
            .await
            .expect("owner group");

    let (admin, admin_token, admin_viewer) =
        seed_caller(&pool, &["claims:write", "claims:admin"]).await;
    assert!(
        !writes(&pool, admin, owner_group).await,
        "fixture: the admin does not write the plan's group"
    );
    seed_admin_grant(&pool, &admin_token).await;

    sqlx::query("UPDATE oauth_clients SET status = 'revoked' WHERE id = $1")
        .bind(admin_token.client_id)
        .execute(&pool)
        .await
        .expect("revoke");
    tools::workflows::deprecate_workflow(&app, &admin_viewer, params(wf), Some(&admin_token))
        .await
        .expect_err("a revoked grant deprecates nothing");
    assert!(
        (truth(&pool, wf).await - 1.0).abs() < 1e-12,
        "row untouched"
    );
    assert!(
        admin_audits(&pool, admin).await.is_empty(),
        "nothing audited"
    );
    sqlx::query("UPDATE oauth_clients SET status = 'active' WHERE id = $1")
        .bind(admin_token.client_id)
        .execute(&pool)
        .await
        .expect("restore");

    let out =
        tools::workflows::deprecate_workflow(&app, &admin_viewer, params(wf), Some(&admin_token))
            .await
            .expect("the audited admin arm deprecates the plan");
    let body = first_text(&out);
    assert_eq!(
        body["deprecated_ids"],
        serde_json::json!([wf.to_string()]),
        "{body}"
    );
    assert!(
        (truth(&pool, wf).await - 0.05).abs() < 1e-12,
        "the row is deprecated"
    );
    let audits = admin_audits(&pool, admin).await;
    assert_eq!(audits.len(), 1, "one audit row per target: {audits:?}");
    let a = &audits[0];
    assert_eq!(a["action"], "deprecate_workflow");
    assert_eq!(a["write"]["reason"], "obsolete");
    assert_eq!(a["workflow_id"], serde_json::json!(wf.to_string()));
    assert_eq!(
        a["client_id"],
        serde_json::json!(admin_token.client_id.to_string())
    );
    assert_eq!(a["workflow_row"]["changed"], serde_json::json!(true));
    assert_eq!(
        a["workflow_row"]["owner_group_id"],
        serde_json::json!(owner_group.to_string())
    );
}

/// A caller admitted by IDENTITY (here the recorded submitter) whose row now
/// sits in a group it does not write, while the plan's claims stay in its own
/// group, is refused whole: the row stays live AND every claim stays current.
/// On the stamp before this change the row's UPDATE matched nothing, the
/// claims were retired, and the tool committed and answered success.
#[sqlx::test(migrations = "../../migrations")]
async fn an_identity_arm_caller_that_does_not_write_the_rows_group_is_refused_whole(pool: PgPool) {
    let su = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let app = app_role_server(&pool).await;
    let (owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let wf = ingest(&pool, &su, &owner_viewer, &owner_token, "wf237-identity").await;
    let claims = structural(&pool, wf).await;
    assert!(!claims.is_empty(), "fixture: the plan executes claims");
    let (_, other) = fixture::seed_agent_with_group(&pool, "wf237-other").await;
    assert!(
        !writes(&pool, owner, other).await,
        "fixture: the submitter does not write the other group"
    );
    sqlx::query("UPDATE workflows SET owner_group_id = $2 WHERE id = $1")
        .bind(wf)
        .bind(other)
        .execute(&pool)
        .await
        .expect("move the row to the other group");

    let err =
        tools::workflows::deprecate_workflow(&app, &owner_viewer, params(wf), Some(&owner_token))
            .await
            .expect_err("the row cannot be written, so nothing may be");
    assert!(
        err.message.contains("was not deprecated") && err.message.contains("owner group"),
        "refused by the row check: {}",
        err.message
    );
    assert!(
        (truth(&pool, wf).await - 1.0).abs() < 1e-12,
        "row untouched"
    );
    for c in &claims {
        assert!(is_current(&pool, *c).await, "claim {c} untouched");
    }

    // CALIBRATION: back in the submitter's group, the same call lands.
    let own: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(claims[0])
        .fetch_one(&pool)
        .await
        .expect("the claims' group");
    sqlx::query("UPDATE workflows SET owner_group_id = $2 WHERE id = $1")
        .bind(wf)
        .bind(own)
        .execute(&pool)
        .await
        .expect("move the row back");
    tools::workflows::deprecate_workflow(&app, &owner_viewer, params(wf), Some(&owner_token))
        .await
        .expect("a writer of the row's group deprecates it");
    assert!((truth(&pool, wf).await - 0.05).abs() < 1e-12);
    for c in &claims {
        assert!(!is_current(&pool, *c).await, "claim {c} retired");
    }
}

/// The flat path: a flat workflow claim the caller writes and a hierarchical
/// row with the SAME id in a group it does not write. The claim's half alone
/// is never committed: refused, the claim stays current and the row live. On
/// the stamp before this change the claim was retired and the row kept 1.0.
#[sqlx::test(migrations = "../../migrations")]
async fn a_flat_deprecation_never_leaves_its_hierarchical_row_live(pool: PgPool) {
    let app = app_role_server(&pool).await;
    let (owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let own_group = common::personal_group_of(&pool, owner).await;
    let (_, other) = fixture::seed_agent_with_group(&pool, "wf237-flat-other").await;
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, labels) \
         VALUES ($1, 'a flat workflow', $2, 0.8, $3, true, 'public', $4, ARRAY['workflow'])",
    )
    .bind(id)
    .bind(&hash)
    .bind(owner)
    .bind(own_group)
    .execute(&pool)
    .await
    .expect("flat workflow claim");
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, goal, visibility, owner_group_id) \
         VALUES ($1, $2, 'a goal', 'public', $3)",
    )
    .bind(id)
    .bind(format!("wf237-flat-{id}"))
    .bind(other)
    .execute(&pool)
    .await
    .expect("the row sharing its id");

    let err =
        tools::workflows::deprecate_workflow(&app, &owner_viewer, params(id), Some(&owner_token))
            .await
            .expect_err("the row cannot be written, so nothing may be");
    assert!(
        err.message.contains("was not deprecated"),
        "refused by the row check: {}",
        err.message
    );
    assert!(is_current(&pool, id).await, "the claim stays current");
    assert!(
        (truth(&pool, id).await - 1.0).abs() < 1e-12,
        "row untouched"
    );

    // CALIBRATION: with the row in the caller's group, both halves land.
    sqlx::query("UPDATE workflows SET owner_group_id = $2 WHERE id = $1")
        .bind(id)
        .bind(own_group)
        .execute(&pool)
        .await
        .expect("move the row");
    tools::workflows::deprecate_workflow(&app, &owner_viewer, params(id), Some(&owner_token))
        .await
        .expect("a writer of both deprecates both");
    assert!(!is_current(&pool, id).await);
    assert!((truth(&pool, id).await - 0.05).abs() < 1e-12);
}
