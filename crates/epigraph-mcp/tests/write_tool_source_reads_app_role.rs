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
use epigraph_mcp::tools::evolve_step::EvolveStepParams;
use epigraph_mcp::types::{
    ConsolidateClaimsParams, EvaluateWorkflowPromotionParams, SubmitDsEvidenceParams,
    UpdateWithEvidenceParams,
};
use sqlx::PgPool;
use uuid::Uuid;

/// The production server shape on the application role. Refuses to run
/// vacuously: the role must not bypass row security, and the plain pool must
/// really be `epigraph_app`.
async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    app_role_server_in(pool, SessionGucMode::Session).await
}

/// [`app_role_server`] in a chosen [`SessionGucMode`]. `Transaction` is the
/// mode a deployment behind a transaction-mode pooler runs, where every
/// stamped read is one transaction and one SQL error aborts the rest of it.
async fn app_role_server_in(pool: &PgPool, mode: SessionGucMode) -> EpiGraphMcpFull {
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
    let scoped = ScopedPool::connect_downgraded_for_tests(&url, mode, "epigraph_app")
        .await
        .expect("app-role ScopedPool");
    assert_eq!(
        scoped.mode(),
        mode,
        "PREMISE: the ScopedPool runs in the requested mode"
    );
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

/// Fault injection for one source's read: a RESTRICTIVE select policy on
/// `claims` for `epigraph_app` that raises when the statement being run is
/// `ClaimRepository::get_by_id` (the only claims read selecting
/// `signer_public_key`) and the row is `target`. Every other statement and row
/// passes it, so the merge's own write transaction is untouched and only the
/// default-confidence read of `target` fails. Created on the superuser pool in
/// this test's own throwaway database.
async fn fail_source_read_of(pool: &PgPool, target: Uuid) {
    sqlx::query(&format!(
        "CREATE FUNCTION public.test_fail_source_read(p_id uuid) RETURNS boolean \
         LANGUAGE plpgsql VOLATILE AS $f$ \
         BEGIN \
           IF p_id = '{target}'::uuid AND current_query() LIKE '%signer_public_key%' THEN \
             RAISE EXCEPTION 'injected fault: read of source %', p_id; \
           END IF; \
           RETURN true; \
         END $f$"
    ))
    .execute(pool)
    .await
    .expect("fault function");
    sqlx::query(
        "CREATE POLICY test_fail_source_read ON public.claims AS RESTRICTIVE FOR SELECT \
         TO epigraph_app USING (public.test_fail_source_read(id))",
    )
    .execute(pool)
    .await
    .expect("fault policy");
}

/// Transaction GUC mode: the default-confidence reads share ONE transaction,
/// so a failed read of one source aborts it and every later read in the loop
/// fails too. Swallowing those errors wrote the merge at a confidence drawn
/// from nothing (here 0 where 0.76 is due), without a word. The tool must
/// refuse instead, name the source, and write nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn consolidate_default_confidence_refuses_when_a_source_read_fails_in_transaction_mode(
    pool: PgPool,
) {
    let server = app_role_server_in(&pool, SessionGucMode::Transaction).await;
    let (agent, auth, viewer, group) = member(&pool).await;
    let faulty = private_claim(&pool, agent, group, "consolidate source, read fails", 0.8).await;
    let good = private_claim(&pool, agent, group, "consolidate source, read ok", 0.8).await;
    fail_source_read_of(&pool, faulty).await;

    let merged_content = "the two private sources, merged after a failed read";
    let res = epigraph_mcp::tools::consolidate::consolidate_claims(
        &server,
        &viewer,
        ConsolidateClaimsParams {
            // The failing source FIRST: in one transaction its error aborts the
            // read of the good source after it.
            source_claim_ids: vec![faulty.to_string(), good.to_string()],
            merged_content: merged_content.to_string(),
            mode: "merge".to_string(),
            reason: "transaction-mode failed-read probe".to_string(),
            confidence: None,
        },
        Some(&auth),
    )
    .await;

    let written: Option<f64> =
        sqlx::query_scalar("SELECT truth_value FROM claims WHERE content = $1")
            .bind(merged_content)
            .fetch_optional(&pool)
            .await
            .expect("look for the merged claim");
    let err = match res {
        Err(e) => e,
        Ok(r) => panic!(
            "a failed source read must refuse the merge, not write it at a deflated \
             default confidence; it answered {} and wrote truth_value {written:?}",
            first_text(&r)
        ),
    };
    assert_eq!(
        err.code,
        rmcp::model::ErrorCode::INTERNAL_ERROR,
        "{}",
        err.message
    );
    assert!(
        err.message.contains(&format!(
            "consolidate_claims: could not read source claim {faulty}"
        )) && err.message.contains("nothing was written"),
        "the refusal names the source whose read failed: {}",
        err.message
    );
    assert_eq!(written, None, "no merged claim was written");
    let current: Vec<bool> =
        sqlx::query_scalar("SELECT COALESCE(is_current, true) FROM claims WHERE id = ANY($1)")
            .bind(vec![faulty, good])
            .fetch_all(&pool)
            .await
            .expect("sources' is_current");
    assert_eq!(current, vec![true, true], "neither source was retired");
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

// ──────────────── update_with_evidence / evolve_step, by step name ────────────────

async fn binary_truth(pool: &PgPool) {
    let existing: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM frames WHERE name = 'binary_truth'")
            .fetch_optional(pool)
            .await
            .expect("read binary_truth");
    if existing.is_none() {
        epigraph_db::FrameRepository::create(
            pool,
            "binary_truth",
            Some("canonical binary frame"),
            &["TRUE".to_string(), "FALSE".to_string()],
        )
        .await
        .expect("binary_truth");
    }
}

struct PrivateWorkflow {
    canonical: String,
    /// The step claims, in plan order.
    steps: Vec<Uuid>,
}

/// A PUBLIC workflows row whose two level-2 steps and their `executes` edges
/// are private to `group` (the shape of `hierarchical_outcome_stamped_reads.rs`),
/// recorded as submitted by `submitter` so `evolve_step`'s lineage gate admits
/// it. Only a stamped member session can walk this plan.
async fn private_workflow(pool: &PgPool, submitter: Uuid, group: Uuid) -> PrivateWorkflow {
    let canonical = format!("private-steps-{}", Uuid::new_v4());
    let workflow_id = Uuid::new_v4();
    epigraph_db::WorkflowRepository::insert_root(
        pool,
        workflow_id,
        &canonical,
        0,
        "A workflow whose steps only one group can read.",
        None,
        serde_json::json!({ "epigraph_submitted_by": submitter.to_string() }),
        epigraph_core::TenancyDecl::inherited(),
    )
    .await
    .expect("insert workflow root");

    let mut steps = Vec::new();
    for i in 0..2 {
        let c = private_claim(
            pool,
            submitter,
            group,
            &format!("{canonical} private step {i}"),
            0.5,
        )
        .await;
        sqlx::query("UPDATE claims SET properties = jsonb_build_object('level', 2) WHERE id = $1")
            .bind(c)
            .execute(pool)
            .await
            .expect("level 2");
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) \
             VALUES ($1, 'workflow', $2, 'claim', 'executes', jsonb_build_object('plan_index', $3::int))",
        )
        .bind(workflow_id)
        .bind(c)
        .bind(i)
        .execute(pool)
        .await
        .expect("executes edge");
        steps.push(c);
    }

    let shapes: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT visibility::text, owner_group_id FROM claims WHERE id = ANY($1) \
         UNION ALL \
         SELECT visibility::text, owner_group_id FROM edges \
          WHERE source_id = $2 AND relationship = 'executes'",
    )
    .bind(&steps)
    .bind(workflow_id)
    .fetch_all(pool)
    .await
    .expect("tenancy read-back");
    assert_eq!(shapes.len(), 4, "two step claims and two executes edges");
    for (vis, owner) in &shapes {
        assert_eq!(
            (vis.as_str(), *owner),
            ("group", group),
            "fixture shape: {shapes:?}"
        );
    }
    PrivateWorkflow { canonical, steps }
}

fn uwe_by_name(canonical: &str, data: &str) -> UpdateWithEvidenceParams {
    UpdateWithEvidenceParams {
        canonical_name: Some(canonical.to_string()),
        step_index: Some(0),
        claim_id: String::new(),
        evidence_type: "empirical".into(),
        evidence_data: data.into(),
        source_url: None,
        supports: true,
        strength: 0.8,
        labels: vec![],
    }
}

async fn evidence_on(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM evidence WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("count evidence")
}

/// A member adds evidence to step 0 of a workflow whose steps are private to
/// its group, addressing it by name. A stranger's identical call cannot
/// resolve the step and writes nothing (the fail-open half).
#[sqlx::test(migrations = "../../migrations")]
async fn update_with_evidence_by_name_resolves_the_members_private_step(pool: PgPool) {
    let server = app_role_server(&pool).await;
    binary_truth(&pool).await;
    let (agent, auth, viewer, group) = member(&pool).await;
    let (_s, stranger_auth, stranger) = seed_caller(&pool, &["claims:write"]).await;
    let wf = private_workflow(&pool, agent, group).await;

    let theirs = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &stranger,
        uwe_by_name(&wf.canonical, "a stranger's evidence by name"),
        Some(&stranger_auth),
    )
    .await;
    assert!(
        matches!(&theirs, Err(e) if e.message.contains("no step at index 0")),
        "a stranger must not resolve another group's private step: {:?}",
        theirs.map(|r| first_text(&r))
    );
    assert_eq!(
        evidence_on(&pool, wf.steps[0]).await,
        0,
        "the stranger wrote nothing"
    );

    let mine = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        uwe_by_name(&wf.canonical, "the member's evidence by name"),
        Some(&auth),
    )
    .await
    .unwrap_or_else(|e| {
        panic!(
            "a member resolves its own group's private step by name (an unstamped walk \
             answers `no step at index 0`): {}",
            e.message
        )
    });
    let ev = parse_uuid_field(&first_text(&mine), "evidence_id");
    let on: Uuid = sqlx::query_scalar("SELECT claim_id FROM evidence WHERE id = $1")
        .bind(ev)
        .fetch_one(&pool)
        .await
        .expect("the evidence row");
    assert_eq!(on, wf.steps[0], "the evidence is on step 0 of the plan");
}

fn evolve_by_name(canonical: &str, content: &str) -> EvolveStepParams {
    EvolveStepParams {
        parent_id: String::new(),
        canonical_name: Some(canonical.to_string()),
        step_index: Some(0),
        step_lineage_id: String::new(),
        content: content.to_string(),
        edge_type: "revises".to_string(),
        rationale: Some("app-role step resolution".to_string()),
        level: Some(2),
    }
}

/// The submitting member evolves step 0 of its group-private plan by name; a
/// stranger's identical call cannot resolve the step and writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_by_name_resolves_the_members_private_step(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (agent, auth, viewer, group) = member(&pool).await;
    let (_s, stranger_auth, stranger) = seed_caller(&pool, &["claims:write"]).await;
    let wf = private_workflow(&pool, agent, group).await;

    let stranger_content = "a stranger's revision by name";
    let theirs = epigraph_mcp::tools::evolve_step::evolve_step(
        &server,
        &stranger,
        evolve_by_name(&wf.canonical, stranger_content),
        Some(&stranger_auth),
    )
    .await;
    assert!(
        matches!(&theirs, Err(e) if e.message.contains("no step at index 0")),
        "a stranger must not resolve another group's private step: {:?}",
        theirs.map(|r| first_text(&r))
    );
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE content = $1")
        .bind(stranger_content)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, 0, "the stranger wrote nothing");

    let mine = epigraph_mcp::tools::evolve_step::evolve_step(
        &server,
        &viewer,
        evolve_by_name(&wf.canonical, "the member's revision by name"),
        Some(&auth),
    )
    .await
    .unwrap_or_else(|e| {
        panic!(
            "the submitting member evolves its own group's private step by name (an \
             unstamped walk answers `no step at index 0`): {}",
            e.message
        )
    });
    let edge = parse_uuid_field(&first_text(&mine), "edge_id");
    let ends: (Uuid, Uuid) = sqlx::query_as("SELECT source_id, target_id FROM edges WHERE id = $1")
        .bind(edge)
        .fetch_one(&pool)
        .await
        .expect("the lineage edge");
    assert!(
        ends.0 == wf.steps[0] || ends.1 == wf.steps[0],
        "the new step's lineage edge joins step 0 of the plan: {ends:?} vs {}",
        wf.steps[0]
    );
}

// ──────────────── evaluate / refresh_workflow_promotion ────────────────

/// A member's group-private variant and parent, joined by a `variant_of` edge
/// that is itself group-private. Returns `(variant, parent)`.
async fn private_variant(pool: &PgPool, agent: Uuid, group: Uuid) -> (Uuid, Uuid) {
    let parent = private_claim(pool, agent, group, "private workflow parent", 0.5).await;
    let variant = private_claim(pool, agent, group, "private workflow variant", 0.5).await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'variant_of')",
    )
    .bind(variant)
    .bind(parent)
    .execute(pool)
    .await
    .expect("variant_of edge");
    let (vis, owner): (String, Uuid) = sqlx::query_as(
        "SELECT visibility::text, owner_group_id FROM edges \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'variant_of'",
    )
    .bind(variant)
    .bind(parent)
    .fetch_one(pool)
    .await
    .expect("edge tenancy read-back");
    assert_eq!(
        (vis.as_str(), owner),
        ("group", group),
        "fixture: the variant_of edge is private to the member's group"
    );
    (variant, parent)
}

fn promotion_params(variant: Uuid) -> EvaluateWorkflowPromotionParams {
    EvaluateWorkflowPromotionParams {
        workflow_id: variant.to_string(),
        window: Some(50),
    }
}

/// The variant-parent lookup behind `evaluate_workflow_promotion` (and
/// `refresh_workflow_promotion`, which shares `assess_workflow_promotion`)
/// runs as the caller: a member's own private variant reports its private
/// parent. On the plain pool the edge read as missing and the member was told,
/// with no error, that its variant is a lineage root with nothing to promote
/// over. A stranger still gets no parent.
///
/// `refresh_workflow_promotion` is not called here: its `properties.promotion`
/// write is still on the plain pool (registered in
/// `residual_unstamped_writes.rs`), so on this server it fails at that write
/// for a group-private variant, a defect this read conversion does not own.
#[sqlx::test(migrations = "../../migrations")]
async fn promotion_reads_the_members_private_variant_edge(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (agent, _auth, viewer, group) = member(&pool).await;
    let (_s, _stranger_auth, stranger) = seed_caller(&pool, &["claims:write"]).await;
    let (variant, parent) = private_variant(&pool, agent, group).await;

    let theirs = epigraph_mcp::tools::workflows::evaluate_workflow_promotion(
        &server,
        &stranger,
        promotion_params(variant),
    )
    .await
    .unwrap_or_else(|e| panic!("a stranger's evaluation answers: {}", e.message));
    assert_eq!(
        first_text(&theirs)["parent_id"],
        serde_json::Value::Null,
        "a stranger must not see another group's private variant edge"
    );

    let mine = epigraph_mcp::tools::workflows::evaluate_workflow_promotion(
        &server,
        &viewer,
        promotion_params(variant),
    )
    .await
    .unwrap_or_else(|e| panic!("a member evaluates its own private variant: {}", e.message));
    assert_eq!(
        first_text(&mine)["parent_id"],
        serde_json::Value::String(parent.to_string()),
        "the member's own private variant reports its private parent (null means the edge \
         was read on an unstamped session and seen as missing): {}",
        first_text(&mine)
    );
}
