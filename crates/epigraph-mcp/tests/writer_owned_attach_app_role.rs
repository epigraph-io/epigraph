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
//! `mark_duplicate` is driven here once, for the server agent's own duplicate
//! (it now dedups on a connection stamped from the server agent). The move of
//! OTHER writers' BBAs on a stamped application session is pinned in
//! `epigraph-db/tests/writer_owned_derived_rows.rs::
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
    // Get-or-create: `frames.name` is UNIQUE, and a test that builds two
    // fixtures asks for the frame twice.
    let existing: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM frames WHERE name = 'binary_truth'")
            .fetch_optional(pool)
            .await
            .expect("read binary_truth");
    if let Some(id) = existing {
        return id;
    }
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

/// Migration 117 (batch W10), the dedup on the APPLICATION ROLE, driven through
/// the real tool by a caller that is NOT an admin: the duplicate's own writer
/// (a `claims:write` token whose owner is the server agent).
///
/// The ACT -- marking the agent's own duplicate of a WORLD canonical -- runs on
/// the transaction stamped from the server agent. The CASCADE runs on the
/// server's maintenance connection and reaches rows the agent does not own:
/// the duplicate's outgoing edge collides with the canonical's, so it is
/// retracted and its edge-keyed BBA (owned by a memberless group) dropped; and
/// ANOTHER writer's edge into the duplicate is re-pointed onto the canonical.
/// One `security_events` row names the caller -- the stamped agent, and the
/// OAuth owner -- the cause and what it touched.
#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_tool_lands_on_the_app_role_for_the_agents_own_duplicate(pool: PgPool) {
    let (server, agent, group, viewer) = app_role_server_with_admin(&pool).await;
    let f = dedup_fixture(&pool, agent, group).await;

    let r = epigraph_mcp::tools::supersede::mark_duplicate(
        &server,
        &viewer,
        epigraph_mcp::types::MarkDuplicateParams {
            claim_id: f.dup.to_string(),
            canonical_id: f.canonical.to_string(),
            reason: None,
        },
        Some(&non_admin_owner(agent)),
    )
    .await
    .expect("the stamped dedup lands on the app role");
    let body = first_text(&r);
    assert_eq!(body["mode"], "mark_duplicate", "{body}");
    assert_eq!(body["cascade"]["status"], "applied", "{body}");
    let (current, supersedes): (bool, Option<Uuid>) =
        sqlx::query_as("SELECT is_current, supersedes FROM claims WHERE id = $1")
            .bind(f.dup)
            .fetch_one(&pool)
            .await
            .expect("dup");
    assert!(!current, "the duplicate is retired");
    assert_eq!(supersedes, Some(f.canonical));
    let gone: bool =
        sqlx::query_scalar("SELECT NOT EXISTS (SELECT 1 FROM mass_functions WHERE id = $1)")
            .bind(f.bba)
            .fetch_one(&pool)
            .await
            .expect("bba");
    assert!(
        gone,
        "the retracted collision edge's BBA, which the agent does not own, was dropped"
    );
    let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(f.other_writers_edge)
        .fetch_one(&pool)
        .await
        .expect("other writer's edge");
    assert_eq!(
        target, f.canonical,
        "another writer's edge into the duplicate now points at the canonical"
    );

    let event_id: Uuid = body["cascade"]["audit_event_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("the applied cascade carries its audit row id");
    let (et, who, details): (String, Option<Uuid>, serde_json::Value) = sqlx::query_as(
        "SELECT event_type::text, agent_id, details FROM security_events WHERE id = $1",
    )
    .bind(event_id)
    .fetch_one(&pool)
    .await
    .expect("the cascade's audit row");
    assert_eq!(et, "cascade.admin_applied");
    assert_eq!(who, Some(agent), "attributed to the caller's stamped agent");
    assert_eq!(details["cause"], "dedup");
    assert_eq!(
        details["trigger"]["oauth"]["owner_id"],
        serde_json::json!(agent),
        "and to the OAuth principal behind the call: {details}"
    );
    assert_eq!(
        details["touched"]["edges_retracted"],
        serde_json::json!([f.dup_edge]),
        "{details}"
    );
    assert!(
        details["touched"]["edges_retargeted"]
            .as_array()
            .is_some_and(|a| a.contains(&serde_json::json!(f.other_writers_edge))),
        "{details}"
    );
    let definer_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'derived.cascade_bba_delete'",
    )
    .fetch_one(&pool)
    .await
    .expect("definer audit");
    assert_eq!(
        definer_rows, 0,
        "the cascade never took the non-privileged definer path"
    );
}

// ===========================================================================
// Migration 117 (batch W10): the retraction cascade is an administrative act.
// ===========================================================================

/// [`app_role_server`] whose `ScopedPool` also carries a MAINTENANCE pool: a
/// second downgraded pool whose sessions are `epigraph_maintenance`, the shape
/// `main` attaches for an explicitly configured `MAINTENANCE_DATABASE_URL`.
async fn app_role_server_with_admin(pool: &PgPool) -> (EpiGraphMcpFull, Uuid, Uuid, Viewer) {
    let url = fixture::database_url_for(pool).await;
    let maintenance = fixture::downgraded_pool(pool, "epigraph_maintenance").await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool")
            .with_maintenance_pool(maintenance);
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let server = build_scoped_test_server(plain, scoped);
    let agent = server.server_agent_id().await.expect("server agent");
    let group = personal_group_of(pool, agent).await;
    let viewer = Viewer::resolve(pool, agent).await.expect("viewer");
    (server, agent, group, viewer)
}

/// A caller that is NOT an admin: a `claims:write` token issued to `owner`.
fn non_admin_owner(owner: Uuid) -> epigraph_auth::AuthContext {
    epigraph_auth::AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: None,
        owner_id: Some(owner),
        client_type: epigraph_auth::ClientType::Service,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
    }
}

/// A public claim owned by `group`, authored by `agent`.
async fn public_claim_of(pool: &PgPool, agent: Uuid, group: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("a public claim owned by a group");
    id
}

async fn edge_between(pool: &PgPool, source: Uuid, target: Uuid) -> Uuid {
    let e = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'claim', $3, 'claim', 'supports')",
    )
    .bind(e)
    .bind(source)
    .bind(target)
    .execute(pool)
    .await
    .expect("edge");
    sqlx::query("INSERT INTO perspectives (id, name) VALUES ($1, $2)")
        .bind(e)
        .bind(format!("edge {e}"))
        .execute(pool)
        .await
        .expect("edge perspective");
    e
}

/// An edge-keyed BBA written by the (privileged) harness: claim-owned, i.e.
/// owned by whatever group the target claim is -- never the agent's.
async fn harness_edge_bba(
    pool: &PgPool,
    target: Uuid,
    frame: Uuid,
    source_agent: Uuid,
    edge: Uuid,
) -> Uuid {
    epigraph_db::MassFunctionRepository::store_with_perspective(
        pool,
        target,
        frame,
        Some(source_agent),
        Some(edge),
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        Some("test"),
        None,
        None,
        "unknown",
        None,
    )
    .await
    .expect("edge BBA")
}

struct DedupFixture {
    dup: Uuid,
    canonical: Uuid,
    dup_edge: Uuid,
    bba: Uuid,
    other_writers_edge: Uuid,
}

/// The agent's public duplicate of a WORLD canonical. `dup -> third` collides
/// with `canonical -> third` and carries a BBA the agent does not own; another
/// writer X's public claim points INTO the duplicate.
async fn dedup_fixture(pool: &PgPool, agent: Uuid, group: Uuid) -> DedupFixture {
    let dup = public_claim_of(pool, agent, group, "my duplicate").await;
    let canonical = seed_claim(pool, "a world canonical", 0.5).await;
    let third = seed_claim(pool, "a world third claim", 0.5).await;
    let (x, x_group) = fixture::seed_agent_with_group(pool, "writer-x").await;
    let xc = public_claim_of(pool, x, x_group, "X's claim about the duplicate").await;
    let bt = binary_truth(pool).await;
    let dup_edge = edge_between(pool, dup, third).await;
    let _canon_edge = edge_between(pool, canonical, third).await;
    let other_writers_edge = edge_between(pool, xc, dup).await;
    let bba = harness_edge_bba(pool, third, bt, agent, dup_edge).await;
    let bba_owner = tenancy(pool, "mass_functions", bba).await.0;
    assert_eq!(bba_owner, memberless_owner(pool, third).await);
    DedupFixture {
        dup,
        canonical,
        dup_edge,
        bba,
        other_writers_edge,
    }
}

/// The same dedup on a server with NO administrative connection: the act
/// commits (the duplicate is retired), the cascade is reported deferred with
/// a `security_events` row naming the caller, and nothing the agent does not
/// own was touched.
#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_without_an_admin_connection_commits_the_act_and_defers(pool: PgPool) {
    let (server, agent, group, viewer) = app_role_server(&pool).await;
    let f = dedup_fixture(&pool, agent, group).await;

    let r = epigraph_mcp::tools::supersede::mark_duplicate(
        &server,
        &viewer,
        epigraph_mcp::types::MarkDuplicateParams {
            claim_id: f.dup.to_string(),
            canonical_id: f.canonical.to_string(),
            reason: None,
        },
        Some(&non_admin_owner(agent)),
    )
    .await
    .expect("the act commits");
    let body = first_text(&r);
    assert_eq!(body["cascade"]["status"], "deferred", "{body}");
    let current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(f.dup)
        .fetch_one(&pool)
        .await
        .expect("dup");
    assert!(!current, "the act committed");
    let (bba_left, still_on_dup): (bool, bool) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM mass_functions WHERE id = $1), \
                (SELECT target_id = $3 FROM edges WHERE id = $2)",
    )
    .bind(f.bba)
    .bind(f.other_writers_edge)
    .bind(f.dup)
    .fetch_one(&pool)
    .await
    .expect("state");
    assert!(
        bba_left && still_on_dup,
        "the deferred cascade touched nothing"
    );
    let event_id: Uuid = body["cascade"]["audit_event_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("the deferral carries its audit row id");
    let (et, who, cause): (String, Option<Uuid>, String) = sqlx::query_as(
        "SELECT event_type::text, agent_id, details->>'cause' FROM security_events WHERE id = $1",
    )
    .bind(event_id)
    .fetch_one(&pool)
    .await
    .expect("the deferral row");
    assert_eq!(
        (et.as_str(), who, cause.as_str()),
        ("cascade.deferred", Some(agent), "dedup")
    );
}

struct SupersedeFixture {
    old: Uuid,
    incoming: Uuid,
    outgoing: Uuid,
    bba: Uuid,
}

/// The agent's own public claim S; another writer X's public claim points INTO
/// it; S supports a WORLD claim T, whose edge-keyed BBA (frozen from S's
/// interval, owned by T's memberless group) the agent does not own.
async fn supersede_fixture(pool: &PgPool, agent: Uuid, group: Uuid) -> SupersedeFixture {
    let old = public_claim_of(pool, agent, group, "my claim, about to be corrected").await;
    let (x, x_group) = fixture::seed_agent_with_group(pool, "writer-x").await;
    let xc = public_claim_of(pool, x, x_group, "X's claim that cites mine").await;
    let t = seed_claim(pool, "a world claim my claim supports", 0.5).await;
    let bt = binary_truth(pool).await;
    let incoming = edge_between(pool, xc, old).await;
    let outgoing = edge_between(pool, old, t).await;
    let bba = harness_edge_bba(pool, t, bt, agent, outgoing).await;
    assert_eq!(
        tenancy(pool, "mass_functions", bba).await.0,
        memberless_owner(pool, t).await
    );
    SupersedeFixture {
        old,
        incoming,
        outgoing,
        bba,
    }
}

/// Migration 117, the supersede on the APPLICATION ROLE by a caller that is not
/// an admin (the claim's own writer). The act -- retire the claim, insert the
/// replacement -- runs on the stamped transaction; the cascade runs on the
/// maintenance connection: ANOTHER writer's incoming edge and the claim's
/// outgoing edge move onto the replacement, and the BBA frozen from the old
/// claim's interval (a row the agent does not own) is invalidated. One
/// `security_events` row names the caller.
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_tool_on_the_app_role_runs_its_cascade_with_admin_authority(pool: PgPool) {
    let (server, agent, group, viewer) = app_role_server_with_admin(&pool).await;
    let f = supersede_fixture(&pool, agent, group).await;

    let r = epigraph_mcp::tools::supersede::supersede_claim(
        &server,
        &viewer,
        epigraph_mcp::types::SupersedeClaimParams {
            claim_id: f.old.to_string(),
            content: "my claim, corrected".to_string(),
            truth_value: 0.6,
            reason: "a correction".to_string(),
        },
        Some(&non_admin_owner(agent)),
    )
    .await
    .expect("the owner's supersede lands on the app role");
    let body = first_text(&r);
    assert_eq!(body["cascade"]["status"], "applied", "{body}");
    let new_id: Uuid = body["new_claim_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("new id");
    let (inc_target, out_source): (Uuid, Uuid) = sqlx::query_as(
        "SELECT (SELECT target_id FROM edges WHERE id = $1), \
                (SELECT source_id FROM edges WHERE id = $2)",
    )
    .bind(f.incoming)
    .bind(f.outgoing)
    .fetch_one(&pool)
    .await
    .expect("edges");
    assert_eq!(
        (inc_target, out_source),
        (new_id, new_id),
        "another writer's edge and the claim's own edge moved onto the replacement"
    );
    let gone: bool =
        sqlx::query_scalar("SELECT NOT EXISTS (SELECT 1 FROM mass_functions WHERE id = $1)")
            .bind(f.bba)
            .fetch_one(&pool)
            .await
            .expect("bba");
    assert!(
        gone,
        "the BBA frozen from the retired claim was invalidated"
    );
    assert!(
        body["belief_cascade"]["invalidated_bbas"].as_u64() >= Some(1),
        "{body}"
    );

    let event_id: Uuid = body["cascade"]["audit_event_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("audit row id");
    let (et, who, details): (String, Option<Uuid>, serde_json::Value) = sqlx::query_as(
        "SELECT event_type::text, agent_id, details FROM security_events WHERE id = $1",
    )
    .bind(event_id)
    .fetch_one(&pool)
    .await
    .expect("the cascade's audit row");
    assert_eq!(et, "cascade.admin_applied");
    assert_eq!(who, Some(agent));
    assert_eq!(details["cause"], "supersede");
    assert_eq!(details["trigger"]["subject_id"], serde_json::json!(f.old));
    assert_eq!(details["trigger"]["object_id"], serde_json::json!(new_id));
    assert_eq!(
        details["trigger"]["oauth"]["owner_id"],
        serde_json::json!(agent)
    );
    assert_eq!(
        details["touched"]["edges_retargeted"],
        serde_json::json!([f.incoming]),
        "{details}"
    );
}

/// The same supersede with NO administrative connection: the act commits (the
/// claim is retired, its replacement exists), the edges stay where they were,
/// the BBA is untouched, and the deferral is recorded under the caller.
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_without_an_admin_connection_commits_the_act_and_defers(pool: PgPool) {
    let (server, agent, group, viewer) = app_role_server(&pool).await;
    let f = supersede_fixture(&pool, agent, group).await;

    let r = epigraph_mcp::tools::supersede::supersede_claim(
        &server,
        &viewer,
        epigraph_mcp::types::SupersedeClaimParams {
            claim_id: f.old.to_string(),
            content: "my claim, corrected".to_string(),
            truth_value: 0.6,
            reason: "a correction".to_string(),
        },
        Some(&non_admin_owner(agent)),
    )
    .await
    .expect("the act commits");
    let body = first_text(&r);
    assert_eq!(body["cascade"]["status"], "deferred", "{body}");
    let new_id: Uuid = body["new_claim_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("new id");
    let (old_current, new_sup): (bool, Option<Uuid>) = sqlx::query_as(
        "SELECT (SELECT is_current FROM claims WHERE id = $1), \
                (SELECT supersedes FROM claims WHERE id = $2)",
    )
    .bind(f.old)
    .bind(new_id)
    .fetch_one(&pool)
    .await
    .expect("claims");
    assert_eq!(
        (old_current, new_sup),
        (false, Some(f.old)),
        "the act committed"
    );
    let (inc_target, bba_left): (Uuid, bool) = sqlx::query_as(
        "SELECT (SELECT target_id FROM edges WHERE id = $1), \
                EXISTS (SELECT 1 FROM mass_functions WHERE id = $2)",
    )
    .bind(f.incoming)
    .bind(f.bba)
    .fetch_one(&pool)
    .await
    .expect("state");
    assert_eq!(inc_target, f.old, "the deferred cascade moved no edge");
    assert!(bba_left, "and invalidated nothing");
    let event_id: Uuid = body["cascade"]["audit_event_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("the deferral carries its audit row id");
    let (et, who, cause, reason): (String, Option<Uuid>, String, String) = sqlx::query_as(
        "SELECT event_type::text, agent_id, details->>'cause', details->>'reason' \
           FROM security_events WHERE id = $1",
    )
    .bind(event_id)
    .fetch_one(&pool)
    .await
    .expect("the deferral row");
    assert_eq!(
        (et.as_str(), who, cause.as_str()),
        ("cascade.deferred", Some(agent), "supersede")
    );
    assert!(reason.contains("MAINTENANCE_DATABASE_URL"), "{reason}");
}

// ===========================================================================
// W10 revision: what the caller is told, consolidation, and the replay.
// ===========================================================================

/// The ids a JSON body spells.
fn mentions(body: &serde_json::Value, id: Uuid) -> bool {
    body.to_string().contains(&id.to_string())
}

/// The supersede cascade re-points EVERY writer's edge on the retired claim,
/// including edges between another group's PRIVATE claims and the caller's
/// public one, and re-derives the private downstream claim. The caller cannot
/// read those rows, so the tool result names none of them: `cascade.touched`
/// is counts, and the belief report keeps only claims the caller can read
/// (the world claim T is still reported). The audit rows keep every id.
#[sqlx::test(migrations = "../../migrations")]
async fn the_supersede_result_names_no_row_the_caller_cannot_read(pool: PgPool) {
    let (server, agent, group, viewer) = app_role_server_with_admin(&pool).await;
    let f = supersede_fixture(&pool, agent, group).await;
    let t: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(f.outgoing)
        .fetch_one(&pool)
        .await
        .expect("T");
    let (h, h_group) = fixture::seed_agent_with_group(&pool, "private-group-h").await;
    let hp1 = fixture::seed_group_claim(&pool, h, h_group, "H's private citing claim").await;
    let hp2 = fixture::seed_group_claim(&pool, h, h_group, "H's private downstream claim").await;
    let into_old = edge_between(&pool, hp1, f.old).await;
    let out_of_old = edge_between(&pool, f.old, hp2).await;
    let bt = binary_truth(&pool).await;
    harness_edge_bba(&pool, hp2, bt, h, out_of_old).await;
    // A cached belief on both downstream claims, so the belief cascade reports
    // each one (as unbacked: its only BBA is invalidated).
    sqlx::query(
        "UPDATE claims SET belief = 0.8, plausibility = 0.9, pignistic_prob = 0.85 \
          WHERE id = ANY($1)",
    )
    .bind(vec![t, hp2])
    .execute(&pool)
    .await
    .expect("plant cached beliefs");
    let visible = epigraph_db::ClaimRepository::visible_claim_ids(&pool, &viewer, &[hp1, hp2, t])
        .await
        .expect("visible ids");
    assert_eq!(
        visible,
        std::iter::once(t).collect(),
        "fixture: the caller reads T and neither of H's private claims"
    );

    let r = epigraph_mcp::tools::supersede::supersede_claim(
        &server,
        &viewer,
        epigraph_mcp::types::SupersedeClaimParams {
            claim_id: f.old.to_string(),
            content: "my claim, corrected".to_string(),
            truth_value: 0.6,
            reason: "a correction".to_string(),
        },
        Some(&non_admin_owner(agent)),
    )
    .await
    .expect("the owner's supersede lands on the app role");
    let body = first_text(&r);
    assert_eq!(body["cascade"]["status"], "applied", "{body}");
    let new_id = parse_uuid_field(&body, "new_claim_id");
    let (moved_in, moved_out): (Uuid, Uuid) = sqlx::query_as(
        "SELECT (SELECT target_id FROM edges WHERE id = $1), \
                (SELECT source_id FROM edges WHERE id = $2)",
    )
    .bind(into_old)
    .bind(out_of_old)
    .fetch_one(&pool)
    .await
    .expect("edges");
    assert_eq!(
        (moved_in, moved_out),
        (new_id, new_id),
        "calibration: the cascade DID touch the private rows"
    );
    for (id, what) in [
        (hp1, "H's private claim"),
        (hp2, "H's private downstream claim"),
        (into_old, "the private edge into the retired claim"),
        (out_of_old, "the private edge out of it"),
        (f.incoming, "another writer's edge id"),
    ] {
        assert!(
            !mentions(&body, id),
            "the result names {what} ({id}): {body}"
        );
    }
    assert!(
        body["cascade"]["touched"]["edges_retargeted"].is_u64(),
        "touched carries counts: {body}"
    );
    assert_eq!(
        body["cascade"]["touched"]["edges_retargeted"],
        serde_json::json!(2),
        "{body}"
    );
    assert!(
        body["belief_cascade"]["targets"]
            .as_array()
            .is_some_and(|a| a.contains(&serde_json::json!(t))),
        "a downstream claim the caller CAN read is still reported: {body}"
    );

    let event = parse_uuid_field(&body["cascade"], "audit_event_id");
    let touched: serde_json::Value =
        sqlx::query_scalar("SELECT details->'touched' FROM security_events WHERE id = $1")
            .bind(event)
            .fetch_one(&pool)
            .await
            .expect("applied row");
    assert!(
        mentions(&touched, into_old) && mentions(&touched, out_of_old),
        "the audit row keeps the ids: {touched}"
    );
    let belief_event = parse_uuid_field(&body["cascade"], "belief_audit_event_id");
    let belief: serde_json::Value =
        sqlx::query_scalar("SELECT details->'belief' FROM security_events WHERE id = $1")
            .bind(belief_event)
            .fetch_one(&pool)
            .await
            .expect("belief row");
    assert!(
        mentions(&belief, hp2),
        "the belief audit row keeps it: {belief}"
    );
}

fn consolidate_params(ids: &[Uuid], content: &str) -> epigraph_mcp::types::ConsolidateClaimsParams {
    epigraph_mcp::types::ConsolidateClaimsParams {
        source_claim_ids: ids.iter().map(ToString::to_string).collect(),
        merged_content: content.to_string(),
        mode: "merge".to_string(),
        reason: "w10 consolidation".to_string(),
        confidence: Some(0.7),
    }
}

/// `consolidate_claims` on the APPLICATION ROLE by a `claims:write` caller:
/// the merge is its act; another writer's edges on the retired sources (world
/// edges no app session can update) move onto the merged claim through the
/// maintenance connection, audited under the caller. Before 117's split this
/// reported success with zero edges migrated.
#[sqlx::test(migrations = "../../migrations")]
async fn consolidate_tool_on_the_app_role_runs_its_edge_migration_with_admin_authority(
    pool: PgPool,
) {
    let (server, agent, group, viewer) = app_role_server_with_admin(&pool).await;
    let s1 = public_claim_of(&pool, agent, group, "my source one").await;
    let s2 = public_claim_of(&pool, agent, group, "my source two").await;
    let (x, x_group) = fixture::seed_agent_with_group(&pool, "writer-x").await;
    let xc = public_claim_of(&pool, x, x_group, "X's claim").await;
    let into_s1 = edge_between(&pool, xc, s1).await;
    let out_of_s2 = edge_between(&pool, s2, xc).await;

    let r = epigraph_mcp::tools::consolidate::consolidate_claims(
        &server,
        &viewer,
        consolidate_params(&[s1, s2], "my merged claim"),
        Some(&non_admin_owner(agent)),
    )
    .await
    .expect("the owner's consolidation lands on the app role");
    let body = first_text(&r);
    assert_eq!(body["cascade"]["status"], "applied", "{body}");
    assert_eq!(body["edges_migrated"], serde_json::json!(2), "{body}");
    let merged = parse_uuid_field(&body, "merged_claim_id");
    let (t, s): (Uuid, Uuid) = sqlx::query_as(
        "SELECT (SELECT target_id FROM edges WHERE id = $1), \
                (SELECT source_id FROM edges WHERE id = $2)",
    )
    .bind(into_s1)
    .bind(out_of_s2)
    .fetch_one(&pool)
    .await
    .expect("edges");
    assert_eq!((t, s), (merged, merged), "both edges follow the merge");
    let event = parse_uuid_field(&body["cascade"], "audit_event_id");
    let (et, who, cause): (String, Option<Uuid>, String) = sqlx::query_as(
        "SELECT event_type::text, agent_id, details->>'cause' FROM security_events WHERE id = $1",
    )
    .bind(event)
    .fetch_one(&pool)
    .await
    .expect("audit row");
    assert_eq!(
        (et.as_str(), who, cause.as_str()),
        ("cascade.admin_applied", Some(agent), "consolidate")
    );
}

/// A server with NO administrative connection (a stdio agent's shape) defers
/// every cascade and records it in the act's transaction. The operator's
/// replay (`replay_deferred`, on a maintenance connection) then applies each
/// one, names the original caller and the deferral it replays, and a second
/// run finds nothing pending.
#[sqlx::test(migrations = "../../migrations")]
async fn deferred_cascades_are_replayed_on_the_maintenance_connection(pool: PgPool) {
    let (server, agent, group, viewer) = app_role_server(&pool).await;
    let sf = supersede_fixture(&pool, agent, group).await;
    let df = dedup_fixture(&pool, agent, group).await;
    let s1 = public_claim_of(&pool, agent, group, "my source one").await;
    let s2 = public_claim_of(&pool, agent, group, "my source two").await;
    let (x, x_group) = fixture::seed_agent_with_group(&pool, "writer-x2").await;
    let xc = public_claim_of(&pool, x, x_group, "X's claim").await;
    let into_s1 = edge_between(&pool, xc, s1).await;
    let auth = non_admin_owner(agent);

    let sup = first_text(
        &epigraph_mcp::tools::supersede::supersede_claim(
            &server,
            &viewer,
            epigraph_mcp::types::SupersedeClaimParams {
                claim_id: sf.old.to_string(),
                content: "my claim, corrected".to_string(),
                truth_value: 0.6,
                reason: "a correction".to_string(),
            },
            Some(&auth),
        )
        .await
        .expect("supersede act"),
    );
    let dedup = first_text(
        &epigraph_mcp::tools::supersede::mark_duplicate(
            &server,
            &viewer,
            epigraph_mcp::types::MarkDuplicateParams {
                claim_id: df.dup.to_string(),
                canonical_id: df.canonical.to_string(),
                reason: None,
            },
            Some(&auth),
        )
        .await
        .expect("dedup act"),
    );
    let cons = first_text(
        &epigraph_mcp::tools::consolidate::consolidate_claims(
            &server,
            &viewer,
            consolidate_params(&[s1, s2], "my merged claim"),
            Some(&auth),
        )
        .await
        .expect("consolidate act"),
    );
    let mut deferrals = Vec::new();
    for b in [&sup, &dedup, &cons] {
        assert_eq!(b["cascade"]["status"], "deferred", "{b}");
        deferrals.push(parse_uuid_field(&b["cascade"], "audit_event_id"));
    }
    let new_id = parse_uuid_field(&sup, "new_claim_id");
    let merged = parse_uuid_field(&cons, "merged_claim_id");

    // Each deferral was written by 117's definer, not by this code: it reads
    // back through `from_audit` as exactly the trigger the tool built, and the
    // database attributed it to the session principal.
    use epigraph_engine::admin_cascade::{CascadeCause, CascadeTrigger, OauthPrincipal};
    let oauth = Some(OauthPrincipal {
        client_id: Some(auth.client_id),
        owner_id: Some(agent),
        agent_id: None,
    });
    let expected = [
        CascadeTrigger::new(
            CascadeCause::Supersede,
            Some(agent),
            oauth.clone(),
            sf.old,
            Some(new_id),
        ),
        CascadeTrigger::new(
            CascadeCause::Dedup,
            Some(agent),
            oauth.clone(),
            df.dup,
            Some(df.canonical),
        ),
        CascadeTrigger {
            sources: vec![s1, s2],
            ..CascadeTrigger::new(
                CascadeCause::Consolidate,
                Some(agent),
                oauth.clone(),
                merged,
                None,
            )
        },
    ];
    for (id, want) in deferrals.iter().zip(expected) {
        let (who, details): (Option<Uuid>, serde_json::Value) = sqlx::query_as(
            "SELECT agent_id, details FROM security_events \
              WHERE id = $1 AND event_type = 'cascade.deferred'",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("the deferral row");
        assert_eq!(who, Some(agent));
        assert_eq!(details["recorded_by"], "epigraph_record_cascade_deferral");
        assert_eq!(
            CascadeTrigger::from_audit(&details),
            Some(want),
            "{details}"
        );
    }
    let target = |e: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>("SELECT target_id FROM edges WHERE id = $1")
                .bind(e)
                .fetch_one(&pool)
                .await
                .expect("edge target")
        }
    };
    assert_eq!(target(sf.incoming).await, sf.old, "deferred: nothing moved");

    let url = fixture::database_url_for(&pool).await;
    let maintenance = fixture::downgraded_pool(&pool, "epigraph_maintenance").await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("ScopedPool")
            .with_maintenance_pool(maintenance);
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance session");
    let (conn, admin_viewer) = session.split();
    let report = epigraph_engine::admin_cascade::replay_deferred(
        conn,
        admin_viewer,
        "w10-test",
        50,
        epigraph_engine::admin_cascade::DEFAULT_MAX_FAILURES,
    )
    .await
    .expect("replay");
    assert_eq!(
        (
            report.pending,
            report.applied,
            report.failed,
            report.unreadable
        ),
        (3, 3, 0, 0),
        "{report:?}"
    );
    assert_eq!(
        target(sf.incoming).await,
        new_id,
        "the supersede cascade replayed"
    );
    assert_eq!(
        target(df.other_writers_edge).await,
        df.canonical,
        "the dedup cascade replayed"
    );
    assert_eq!(
        target(into_s1).await,
        merged,
        "the consolidation cascade replayed"
    );

    let replays: Vec<(Option<Uuid>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT agent_id, details#>>'{replay_of,deferred_event_id}', \
                details#>>'{replay_of,replayed_by}' \
           FROM security_events WHERE event_type = 'cascade.admin_applied' ORDER BY created_at",
    )
    .fetch_all(&pool)
    .await
    .expect("applied rows");
    assert_eq!(replays.len(), 3, "{replays:?}");
    for (who, of, by) in &replays {
        assert_eq!(
            *who,
            Some(agent),
            "the replay still names the original caller"
        );
        assert!(
            of.as_deref()
                .and_then(|s| s.parse::<Uuid>().ok())
                .is_some_and(|d| deferrals.contains(&d)),
            "and the deferral it replays: {of:?}"
        );
        assert_eq!(by.as_deref(), Some("w10-test"));
    }

    let (conn, admin_viewer) = session.split();
    let again = epigraph_engine::admin_cascade::replay_deferred(
        conn,
        admin_viewer,
        "w10-test",
        50,
        epigraph_engine::admin_cascade::DEFAULT_MAX_FAILURES,
    )
    .await
    .expect("second replay");
    assert_eq!((again.pending, again.applied), (0, 0), "{again:?}");
}

/// The repair and its audit row commit together or not at all. With the
/// maintenance role unable to append to `security_events`, the supersede's act
/// still commits, but the cascade reports `failed`: another writer's edge is
/// NOT re-pointed (the repair rolled back with its refused audit row), so no
/// cross-owner change exists without the row naming its caller.
#[sqlx::test(migrations = "../../migrations")]
async fn an_applied_repair_never_commits_without_its_audit_row(pool: PgPool) {
    let (server, agent, group, viewer) = app_role_server_with_admin(&pool).await;
    let f = supersede_fixture(&pool, agent, group).await;
    sqlx::query("REVOKE INSERT ON security_events FROM epigraph_maintenance")
        .execute(&pool)
        .await
        .expect("revoke the maintenance role's audit append");

    let r = epigraph_mcp::tools::supersede::supersede_claim(
        &server,
        &viewer,
        epigraph_mcp::types::SupersedeClaimParams {
            claim_id: f.old.to_string(),
            content: "my claim, corrected".to_string(),
            truth_value: 0.6,
            reason: "a correction".to_string(),
        },
        Some(&non_admin_owner(agent)),
    )
    .await
    .expect("the act still commits");
    let body = first_text(&r);
    assert_eq!(body["cascade"]["status"], "failed", "{body}");
    assert!(
        body["cascade"]["audit_error"].is_string(),
        "and says its audit row could not be written: {body}"
    );
    let current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(f.old)
        .fetch_one(&pool)
        .await
        .expect("old");
    assert!(!current, "the caller's act committed");
    let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(f.incoming)
        .fetch_one(&pool)
        .await
        .expect("X's edge");
    assert_eq!(
        target, f.old,
        "the repair rolled back with its refused audit row: nothing moved unaudited"
    );
    let applied: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'cascade.admin_applied'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(applied, 0);
}
