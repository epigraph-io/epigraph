//! The four attach tools, driven end to end on the APPLICATION ROLE, onto a
//! public claim owned by the world group and authored by another agent
//! (migration 114, writer-owned derived rows).
//!
//! # Why a downgraded pool on both sides
//!
//! `#[sqlx::test]` connects as the superuser `epigraph`, which bypasses RLS and
//! which 114 deliberately leaves on the old path, so a tool test on that pool
//! passes identically on a tree without 114. Here BOTH of the server's pools are
//! downgraded with `SET SESSION AUTHORIZATION epigraph_app` (so `session_user` is
//! the app role, as for the production app DSN): the `ScopedPool` its stamped
//! transactions come from (`ScopedPool::connect_downgraded_for_tests`, the
//! `test-support` feature) and the plain pool its unstamped reads use
//! (`fixture::downgraded_pool`). Seeding and `Viewer::resolve` run on the
//! original superuser pool, as the fixture's own header requires.
//!
//! `mark_duplicate` is not driven here: the tool runs its dedup on the
//! UNSTAMPED pool (`tools::supersede::mark_duplicate`), which the application
//! role refuses before 114 is reached. Its repo path on a stamped application
//! session is pinned in `epigraph-db/tests/writer_owned_derived_rows.rs::
//! mark_duplicate_onto_a_world_canonical_moves_every_writers_bba`.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::types::{
    LinkEpistemicParams, ReportWorkflowOutcomeParams, StepExecution, SubmitDsEvidenceParams,
    UpdateWithEvidenceParams,
};
use sqlx::PgPool;
use uuid::Uuid;

/// The two memberless owners an undeclared superuser-seeded claim can land in:
/// the world group, and the seed group 074's seed escape stamps.
const WORLD: Uuid = Uuid::nil();
const SEED: Uuid = Uuid::from_u128(0xdead);

/// The claim's owner, asserted to be one of the two groups nobody can write,
/// which is the shape of a shared claim this batch is about.
async fn memberless_owner(pool: &PgPool, claim: Uuid) -> Uuid {
    let owner = claim_row(pool, claim).await.0;
    assert!(
        owner == WORLD || owner == SEED,
        "fixture: expected a memberless (world / seed) owner, got {owner}"
    );
    let members: i64 =
        sqlx::query_scalar("SELECT count(*) FROM group_memberships WHERE group_id = $1")
            .bind(owner)
            .fetch_one(pool)
            .await
            .expect("members");
    assert_eq!(members, 0, "fixture: the owning group must be memberless");
    owner
}

/// A server whose every connection is the application role, its agent, the
/// agent's personal group, and the agent's viewer (resolved on the superuser
/// pool).
async fn app_role_server(pool: &PgPool) -> (EpiGraphMcpFull, Uuid, Uuid, Viewer) {
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
    let who: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&plain)
        .await
        .expect("session_user");
    assert_eq!(
        who, "epigraph_app",
        "the unstamped pool must be the app role too"
    );
    let server = build_scoped_test_server(plain, scoped);
    let agent = server.server_agent_id().await.expect("server agent");
    let group = personal_group_of(pool, agent).await;
    let viewer = Viewer::resolve(pool, agent).await.expect("viewer");
    (server, agent, group, viewer)
}

async fn tenancy(pool: &PgPool, table: &str, id: Uuid) -> (Uuid, String, bool) {
    sqlx::query_as(&format!(
        "SELECT owner_group_id, visibility::text, writer_owned FROM {table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("read {table} {id}: {e}"))
}

async fn claim_row(pool: &PgPool, claim: Uuid) -> (Uuid, f64, Vec<String>, Option<f64>) {
    sqlx::query_as(
        "SELECT owner_group_id, truth_value, labels, pignistic_prob FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("claim row")
}

async fn binary_truth(pool: &PgPool) -> Uuid {
    epigraph_db::FrameRepository::create(
        pool,
        "binary_truth",
        Some("canonical binary frame"),
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("binary_truth")
    .id
}

fn uwe(claim: Uuid, data: &str, labels: Vec<String>) -> UpdateWithEvidenceParams {
    UpdateWithEvidenceParams {
        canonical_name: None,
        step_index: None,
        claim_id: claim.to_string(),
        evidence_type: "empirical".into(),
        evidence_data: data.into(),
        source_url: None,
        supports: true,
        strength: 0.8,
        labels,
    }
}

/// update_with_evidence onto another agent's world claim: the evidence and its
/// BBA are the writer's (its personal group, public), the claim's cache is
/// seeded, and its truth_value and labels are untouched. A label-carrying call
/// is refused with nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn update_with_evidence_attaches_writer_owned_rows_to_a_world_claim(pool: PgPool) {
    let (server, _agent, group, viewer) = app_role_server(&pool).await;
    binary_truth(&pool).await;
    let claim = seed_claim(&pool, "a world claim someone else wrote", 0.5).await;
    let owner0 = memberless_owner(&pool, claim).await;

    let refused = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        uwe(claim, "labelled evidence", vec!["run-tag".into()]),
    )
    .await;
    assert!(
        refused.is_err(),
        "labels on a claim the caller does not own are refused"
    );

    let res = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        uwe(claim, "an observation supporting the claim", vec![]),
    )
    .await
    .expect("a non-owner attaches evidence on the app role");
    let body = first_text(&res);
    assert_eq!(body["truth_written"], false);
    assert_eq!(body["evidence_owner"], "writer");
    assert_eq!(
        body["cache_written"], true,
        "an uncached claim is seeded on binary_truth"
    );
    let ev = parse_uuid_field(&body, "evidence_id");
    assert_eq!(
        tenancy(&pool, "evidence", ev).await,
        (group, "public".into(), true)
    );
    let bba: Uuid = sqlx::query_scalar("SELECT id FROM mass_functions WHERE evidence_id = $1")
        .bind(ev)
        .fetch_one(&pool)
        .await
        .expect("the evidence's BBA");
    assert_eq!(
        tenancy(&pool, "mass_functions", bba).await,
        (group, "public".into(), true)
    );
    let (owner, truth, labels, betp) = claim_row(&pool, claim).await;
    assert_eq!(owner, owner0, "attaching never re-owns the claim");
    assert!(
        (truth - 0.5).abs() < 1e-12,
        "truth_value is the owner's: {truth}"
    );
    assert!(labels.is_empty(), "no label landed: {labels:?}");
    assert!(betp.is_some(), "the cache was seeded");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, 1, "the refused labelled call wrote nothing");
}

/// W11: on a world claim whose cache carries an older frameless value, the
/// evidence lands but the cache is not overwritten, and the response says so
/// instead of presenting the call's combination as the claim's cache.
#[sqlx::test(migrations = "../../migrations")]
async fn update_with_evidence_reports_a_cache_it_did_not_write(pool: PgPool) {
    let (server, _agent, _group, viewer) = app_role_server(&pool).await;
    binary_truth(&pool).await;
    let claim = seed_claim(&pool, "a world claim with an older cache", 0.5).await;
    sqlx::query(
        "UPDATE claims SET belief = 0.8, plausibility = 0.9, pignistic_prob = 0.85, \
                           belief_frame_id = NULL WHERE id = $1",
    )
    .bind(claim)
    .execute(&pool)
    .await
    .expect("older frameless cache");

    let res = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        uwe(claim, "weak counter-observation", vec![]),
    )
    .await
    .expect("the evidence still lands");
    let body = first_text(&res);
    assert_eq!(body["cache_written"], false);
    assert!(
        body["warning"]
            .as_str()
            .unwrap_or_default()
            .contains("NOT updated"),
        "{body}"
    );
    assert_eq!(
        claim_row(&pool, claim).await.3,
        Some(0.85),
        "the cache is untouched"
    );
}

/// W12: the agent's OWN group-private claim is found (the read is on the
/// stamped transaction); another group's private claim answers exactly as a
/// missing id does.
#[sqlx::test(migrations = "../../migrations")]
async fn update_with_evidence_reads_the_claim_on_the_stamped_transaction(pool: PgPool) {
    let (server, agent, group, viewer) = app_role_server(&pool).await;
    binary_truth(&pool).await;
    let own_private = fixture::seed_group_claim(&pool, agent, group, "my own private claim").await;
    let (stranger, stranger_group) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let foreign_private =
        fixture::seed_group_claim(&pool, stranger, stranger_group, "not mine").await;
    let missing = Uuid::new_v4();

    let res = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        uwe(own_private, "evidence on my own private claim", vec![]),
    )
    .await
    .expect("an agent's own group-private claim is found on the app role");
    let body = first_text(&res);
    assert_eq!(body["truth_written"], true);
    assert_eq!(body["evidence_owner"], "claim_owner");

    let msg = |r: Result<rmcp::model::CallToolResult, rmcp::ErrorData>, id: Uuid| {
        r.expect_err("refused")
            .message
            .replace(&id.to_string(), "<id>")
    };
    let a = msg(
        epigraph_mcp::tools::claims::update_with_evidence(
            &server,
            &viewer,
            uwe(foreign_private, "x", vec![]),
        )
        .await,
        foreign_private,
    );
    let b = msg(
        epigraph_mcp::tools::claims::update_with_evidence(
            &server,
            &viewer,
            uwe(missing, "x", vec![]),
        )
        .await,
        missing,
    );
    assert_eq!(a, b, "an unreadable private claim answers as a missing one");
}

/// submit_ds_evidence onto another agent's world claim: the BBA is the
/// writer's, the claim-frame row is the claim's (world), a FALSE binding on
/// binary_truth is refused with nothing written, and the TRUE one lands.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_ds_evidence_attaches_a_writer_owned_bba_to_a_world_claim(pool: PgPool) {
    let (server, agent, group, viewer) = app_role_server(&pool).await;
    let bt = binary_truth(&pool).await;
    let claim = seed_claim(&pool, "a world claim for DS evidence", 0.5).await;
    let owner0 = memberless_owner(&pool, claim).await;
    let params = |idx: i32| -> SubmitDsEvidenceParams {
        serde_json::from_value(serde_json::json!({
            "claim_id": claim.to_string(),
            "frame_id": bt.to_string(),
            "hypothesis_index": idx,
            "masses": {"0": 0.7, "0,1": 0.3},
        }))
        .expect("params")
    };

    let refused = epigraph_mcp::tools::ds::submit_ds_evidence(&server, &viewer, params(1)).await;
    let e = refused.expect_err("a non-owner cannot bind a world claim to FALSE");
    assert!(e.message.contains("FA07"), "{e:?}");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, 0, "the refused call wrote nothing");

    epigraph_mcp::tools::ds::submit_ds_evidence(&server, &viewer, params(0))
        .await
        .expect("the TRUE binding lands on the app role");
    let bba: Uuid = sqlx::query_scalar(
        "SELECT id FROM mass_functions WHERE claim_id = $1 AND source_agent_id = $2",
    )
    .bind(claim)
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("the BBA");
    assert_eq!(
        tenancy(&pool, "mass_functions", bba).await,
        (group, "public".into(), true)
    );
    let (cf_owner, idx): (Uuid, Option<i32>) = sqlx::query_as(
        "SELECT owner_group_id, hypothesis_index FROM claim_frames WHERE claim_id = $1",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("assignment");
    assert_eq!(
        (cf_owner, idx),
        (owner0, Some(0)),
        "the assignment is the claim's"
    );
    assert!(
        claim_row(&pool, claim).await.3.is_some(),
        "the cache was seeded"
    );
}

/// link_epistemic into another agent's world claim: belief_wired=true, the
/// edge's BBA on the target is the writer's, and the target's truth_value is
/// untouched.
#[sqlx::test(migrations = "../../migrations")]
async fn link_epistemic_wires_belief_into_a_world_claim(pool: PgPool) {
    let (server, _agent, group, viewer) = app_role_server(&pool).await;
    binary_truth(&pool).await;
    let source = seed_claim_with_belief(&pool, 0.8, 0.95, Some(0.9)).await;
    let target = seed_claim(&pool, "a world target someone else wrote", 0.5).await;
    let owner0 = memberless_owner(&pool, target).await;

    let res = epigraph_mcp::tools::link_epistemic::link_epistemic(
        &server,
        &viewer,
        LinkEpistemicParams {
            source_claim_id: source.to_string(),
            target_claim_id: target.to_string(),
            relationship: "supports".into(),
            properties: None,
        },
    )
    .await
    .expect("link_epistemic on the app role");
    let body = first_text(&res);
    assert_eq!(body["belief_wired"], true, "{body}");
    let edge = parse_uuid_field(&body, "edge_id");
    let bba: Uuid = sqlx::query_scalar(
        "SELECT id FROM mass_functions WHERE claim_id = $1 AND perspective_id = $2",
    )
    .bind(target)
    .bind(edge)
    .fetch_one(&pool)
    .await
    .expect("the edge's BBA on the target");
    assert_eq!(
        tenancy(&pool, "mass_functions", bba).await,
        (group, "public".into(), true)
    );
    let (owner, truth, _, betp) = claim_row(&pool, target).await;
    assert_eq!(owner, owner0, "attaching never re-owns the claim");
    assert!((truth - 0.5).abs() < 1e-12);
    assert!(betp.is_some(), "the target's cache was wired");
}

/// W4(a): report_workflow_outcome on a shared (world-owned) legacy flat
/// workflow claim: the outcome evidence is the reporter's, the claim's
/// truth_value is not written, and the call succeeds.
#[sqlx::test(migrations = "../../migrations")]
async fn report_workflow_outcome_on_a_world_workflow_claim_leaves_its_truth_alone(pool: PgPool) {
    let (server, _agent, group, viewer) = app_role_server(&pool).await;
    binary_truth(&pool).await;
    let wf = seed_workflow_claim(&pool, "ship a shared workflow", &["build", "test"]).await;
    let owner0 = memberless_owner(&pool, wf).await;

    let res = epigraph_mcp::tools::workflows::report_workflow_outcome(
        &server,
        &viewer,
        ReportWorkflowOutcomeParams {
            workflow_id: wf.to_string(),
            success: true,
            execution_log: vec![StepExecution {
                step_index: 0,
                planned: "build".into(),
                actual: "build".into(),
                deviated: false,
                deviation_reason: None,
            }],
            outcome_details: "ran clean".into(),
            quality: Some(0.9),
            goal_text: None,
        },
    )
    .await
    .expect("reporting on a shared workflow lands on the app role");
    let body = first_text(&res);
    assert_eq!(body["truth_written"], false, "{body}");
    assert_eq!(body["truth_after"], body["truth_before"]);
    let ev = parse_uuid_field(&body, "evidence_id");
    assert_eq!(
        tenancy(&pool, "evidence", ev).await,
        (group, "public".into(), true)
    );
    let (owner, truth, _, _) = claim_row(&pool, wf).await;
    assert_eq!(owner, owner0, "reporting never re-owns the workflow claim");
    assert!(
        (truth - 0.5).abs() < 1e-12,
        "the workflow claim's truth stays its owner's"
    );
}

async fn set_frameless_cache(pool: &PgPool, claim: Uuid) {
    sqlx::query(
        "UPDATE claims SET belief = 0.8, plausibility = 0.9, pignistic_prob = 0.85, \
                           mass_on_empty = 0, mass_on_missing = 0, belief_frame_id = NULL \
          WHERE id = $1",
    )
    .bind(claim)
    .execute(pool)
    .await
    .expect("older frameless cache");
}

/// link_epistemic into a world claim whose cache is an older frameless one:
/// the edge's BBA is stored (belief_wired=true) but the cache is not
/// overwritten, and target_belief reports the cache AS STORED, not a value the
/// database does not hold.
#[sqlx::test(migrations = "../../migrations")]
async fn link_epistemic_reports_the_stored_cache_when_it_may_not_write_it(pool: PgPool) {
    let (server, _agent, group, viewer) = app_role_server(&pool).await;
    binary_truth(&pool).await;
    let source = seed_claim_with_belief(&pool, 0.8, 0.95, Some(0.9)).await;
    let target = seed_claim(&pool, "a world target with an older cache", 0.5).await;
    memberless_owner(&pool, target).await;
    set_frameless_cache(&pool, target).await;

    let res = epigraph_mcp::tools::link_epistemic::link_epistemic(
        &server,
        &viewer,
        LinkEpistemicParams {
            source_claim_id: source.to_string(),
            target_claim_id: target.to_string(),
            relationship: "supports".into(),
            properties: None,
        },
    )
    .await
    .expect("link_epistemic on the app role");
    let body = first_text(&res);
    assert_eq!(
        body["belief_wired"], true,
        "the edge's BBA was stored: {body}"
    );
    let edge = parse_uuid_field(&body, "edge_id");
    let bba: Uuid = sqlx::query_scalar(
        "SELECT id FROM mass_functions WHERE claim_id = $1 AND perspective_id = $2",
    )
    .bind(target)
    .bind(edge)
    .fetch_one(&pool)
    .await
    .expect("the edge's BBA");
    assert_eq!(
        tenancy(&pool, "mass_functions", bba).await,
        (group, "public".into(), true)
    );
    let stored = claim_row(&pool, target).await.3;
    assert_eq!(stored, Some(0.85), "the older cache is not overwritten");
    assert_eq!(
        body["target_belief"]["pignistic_prob"].as_f64(),
        stored,
        "target_belief is the cache as stored: {body}"
    );
}

/// submit_ds_evidence onto an uncached world claim on a frame the writer made:
/// the BBA is stored, the cache is not seeded (only binary_truth seeds), and the
/// response returns this frame's combination with a warning instead of failing
/// on the empty cache after the BBA was written.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_ds_evidence_on_a_writer_frame_reports_an_unwritten_cache(pool: PgPool) {
    let (server, agent, group, viewer) = app_role_server(&pool).await;
    binary_truth(&pool).await;
    let own = epigraph_db::FrameRepository::create(
        &pool,
        "wown-writer-frame",
        Some("a writer-made frame"),
        &["h_yes".to_string(), "h_no".to_string()],
    )
    .await
    .expect("writer frame")
    .id;
    let claim = seed_claim(&pool, "an uncached world claim", 0.5).await;
    memberless_owner(&pool, claim).await;

    let params: SubmitDsEvidenceParams = serde_json::from_value(serde_json::json!({
        "claim_id": claim.to_string(),
        "frame_id": own.to_string(),
        "hypothesis_index": 0,
        "masses": {"0": 0.7, "0,1": 0.3},
    }))
    .expect("params");
    let res = epigraph_mcp::tools::ds::submit_ds_evidence(&server, &viewer, params)
        .await
        .expect("the BBA lands and the call answers");
    let body = first_text(&res);
    let warnings = body["warnings"].to_string();
    assert!(warnings.contains("NOT updated"), "{body}");
    assert!(
        body["pignistic_prob"].as_f64().unwrap_or(0.0) > 0.5,
        "the response carries this frame's combination: {body}"
    );
    assert_eq!(
        claim_row(&pool, claim).await.3,
        None,
        "a non-owner never seeds a cache on a frame of its own"
    );
    let bba: Uuid = sqlx::query_scalar(
        "SELECT id FROM mass_functions WHERE claim_id = $1 AND source_agent_id = $2",
    )
    .bind(claim)
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("the BBA");
    assert_eq!(
        tenancy(&pool, "mass_functions", bba).await,
        (group, "public".into(), true)
    );
}

/// RESIDUAL, pinned rather than fixed here: the mark_duplicate TOOL runs its
/// dedup on the UNSTAMPED pool, so on the application role it is refused even
/// for the agent's own duplicate, before migration 114's dedup move is reached.
/// When the tool moves to a stamped transaction this arm flips and must be
/// rewritten to assert the writer-owned move instead.
#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_tool_is_refused_on_the_app_role_because_it_runs_unstamped(pool: PgPool) {
    let (server, agent, group, viewer) = app_role_server(&pool).await;
    let dup = Uuid::new_v4();
    let hash: Vec<u8> = dup.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, 'my duplicate', $2, 0.5, $3, true, 'public', $4)",
    )
    .bind(dup)
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(&pool)
    .await
    .expect("a public duplicate owned by the agent's group");
    let canonical = seed_claim(&pool, "a world canonical", 0.5).await;

    let r = epigraph_mcp::tools::supersede::mark_duplicate(
        &server,
        &viewer,
        epigraph_mcp::types::MarkDuplicateParams {
            claim_id: dup.to_string(),
            canonical_id: canonical.to_string(),
            reason: None,
        },
        None,
    )
    .await;
    let e = r.expect_err("the unstamped dedup is refused on the app role");
    assert!(e.message.contains("row-level security"), "{e:?}");
    let current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(dup)
        .fetch_one(&pool)
        .await
        .expect("dup");
    assert!(current, "nothing was written");
}
