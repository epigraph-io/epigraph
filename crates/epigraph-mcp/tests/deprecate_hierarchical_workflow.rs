//! U017 (backlog fe874d2a): `deprecate_workflow` on a HIERARCHICAL workflow id
//! (the `workflows`-table id that `store_workflow`, `ingest_workflow`,
//! `find_workflow` and `find_workflow_hierarchical` return) must retire the
//! workflow as a unit, check the caller's authority over it, and report only
//! what changed.
//!
//! Before this change the tool ran `ClaimRepository::deprecate_claim` on the
//! `workflows` id (zero rows: it is not a claim), set the `workflows` row's
//! truth to 0.05 with no authority check, and pushed the id into
//! `deprecated_ids` unconditionally. The thesis, phase and step claims stayed
//! `is_current = true` with their embeddings, so they kept surfacing in recall;
//! a random UUID was "deprecated" too; `cascade: true` walked only
//! claim-to-claim edges and so never reached a workflow-to-workflow variant.
//!
//! Every assertion reads PERSISTED state (`claims.is_current`, the two ANN
//! columns, `workflows.truth_value`, `security_events`), never only the
//! response, because the response is the thing that lied.
//!
//! The claims are SHARED: a step's id is `compound_claim_id(hash(text),
//! canonical_name)`, with no generation in the seed, so every generation of a
//! lineage that keeps a step's text executes the same claim row, and an
//! operation atom's id is content-only and global. The calibrations below pin
//! that a deprecation retires only the level 0-2 claims no other live workflow
//! executes, so a "retire every executes target" implementation fails them.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, first_text, seed_admin_grant, seed_caller};
use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;
use epigraph_mcp::tools;
use epigraph_mcp::types::{
    DeprecateWorkflowParams, ImproveWorkflowHierarchyParams, IngestWorkflowParams,
};
use sqlx::PgPool;
use uuid::Uuid;

fn extraction(canonical: &str) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical.to_string(),
            goal: format!("U017 workflow {canonical}"),
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
            summary: format!("U017 phase for {canonical}"),
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

async fn ingest(
    pool: &PgPool,
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    token: Option<&epigraph_auth::AuthContext>,
    canonical: &str,
) -> Uuid {
    ingest_extraction(pool, server, viewer, token, extraction(canonical)).await
}

async fn ingest_extraction(
    pool: &PgPool,
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    token: Option<&epigraph_auth::AuthContext>,
    extraction: WorkflowExtraction,
) -> Uuid {
    let canonical = extraction.source.canonical_name.clone();
    tools::workflow_ingest::ingest_workflow(
        server,
        viewer,
        IngestWorkflowParams { extraction },
        token,
    )
    .await
    .expect("ingest");
    workflow_row(pool, &canonical, 0).await
}

/// Generation 1 of `canonical`: the same step and operation text (so the same
/// step claim row), a refined phase summary (so a DIFFERENT phase claim).
async fn improve(
    pool: &PgPool,
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    token: Option<&epigraph_auth::AuthContext>,
    canonical: &str,
) -> Uuid {
    improve_to(pool, server, viewer, token, canonical, 1).await
}

/// The next generation of `canonical` (`generation` is the one it must land
/// at): the same step and operation text, a phase summary of its own.
async fn improve_to(
    pool: &PgPool,
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    token: Option<&epigraph_auth::AuthContext>,
    canonical: &str,
    generation: i32,
) -> Uuid {
    let mut refined = extraction(canonical);
    refined.phases[0].summary = format!("U017 refined phase {generation} for {canonical}");
    tools::workflow_ingest::improve_workflow_hierarchy(
        server,
        viewer,
        ImproveWorkflowHierarchyParams {
            parent_canonical_name: canonical.to_string(),
            extraction: refined,
        },
        token,
    )
    .await
    .expect("improve");
    workflow_row(pool, canonical, generation).await
}

async fn parent_of(pool: &PgPool, wf: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT parent_id FROM workflows WHERE id = $1")
        .bind(wf)
        .fetch_one(pool)
        .await
        .expect("workflow parent")
}

/// Record `agent` as `wf`'s submitter, as if another caller had submitted it.
async fn set_submitter(pool: &PgPool, wf: Uuid, agent: Uuid) {
    sqlx::query(
        "UPDATE workflows \
            SET metadata = jsonb_set(metadata, '{epigraph_submitted_by}', to_jsonb($2::text)) \
          WHERE id = $1",
    )
    .bind(wf)
    .bind(agent)
    .execute(pool)
    .await
    .expect("re-record the submitter");
    let got: Option<String> = sqlx::query_scalar(
        "SELECT metadata->>'epigraph_submitted_by' FROM workflows WHERE id = $1",
    )
    .bind(wf)
    .fetch_one(pool)
    .await
    .expect("read the submitter back");
    assert_eq!(
        got,
        Some(agent.to_string()),
        "calibration: {wf}'s submitter is {agent}"
    );
}

async fn level_of(pool: &PgPool, claim: Uuid) -> String {
    sqlx::query_scalar("SELECT properties->>'level' FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("claim level")
}

async fn claim_truth(pool: &PgPool, claim: Uuid) -> f64 {
    sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("claim truth")
}

async fn workflow_row(pool: &PgPool, canonical: &str, generation: i32) -> Uuid {
    sqlx::query_scalar("SELECT id FROM workflows WHERE canonical_name = $1 AND generation = $2")
        .bind(canonical)
        .bind(generation)
        .fetch_one(pool)
        .await
        .expect("workflows row")
}

/// The claims `wf` executes at the given levels (as recorded on the claim).
async fn executed(pool: &PgPool, wf: Uuid, levels: &[&str]) -> Vec<Uuid> {
    let levels: Vec<String> = levels.iter().map(|s| (*s).to_string()).collect();
    sqlx::query_scalar(
        "SELECT c.id FROM edges e JOIN claims c ON c.id = e.target_id \
          WHERE e.source_id = $1 AND e.relationship = 'executes' \
            AND c.properties->>'level' = ANY($2) ORDER BY c.id",
    )
    .bind(wf)
    .bind(&levels)
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

/// Plant a vector in BOTH ANN columns, so "the embeddings were nulled" is not
/// vacuously true of a harness that never embedded anything.
async fn plant_embeddings(pool: &PgPool, claim: Uuid) {
    let vec_of = |n: usize| {
        let mut v = vec!["0.0"; n];
        v[0] = "0.1";
        format!("[{}]", v.join(","))
    };
    sqlx::query(
        "UPDATE claims SET embedding = $1::vector, embedding_3072 = $2::vector WHERE id = $3",
    )
    .bind(vec_of(1536))
    .bind(vec_of(3072))
    .bind(claim)
    .execute(pool)
    .await
    .expect("plant embeddings");
}

async fn embeddings(pool: &PgPool, claim: Uuid) -> (bool, bool) {
    sqlx::query_as(
        "SELECT embedding IS NOT NULL, embedding_3072 IS NOT NULL FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("embedding columns")
}

fn params(wf: Uuid, cascade: bool) -> DeprecateWorkflowParams {
    DeprecateWorkflowParams {
        workflow_id: wf.to_string(),
        reason: "obsolete".into(),
        cascade: Some(cascade),
    }
}

/// The string array at `key` of a tool response (empty when absent).
fn ids(body: &serde_json::Value, key: &str) -> Vec<String> {
    let mut v: Vec<String> = body[key]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|x| x.as_str().expect("id string").to_string())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

async fn workflow_admin_audits(pool: &PgPool, admin: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM security_events \
          WHERE event_type = 'workflows.admin_write' AND agent_id = $1",
    )
    .bind(admin)
    .fetch_one(pool)
    .await
    .expect("count audit rows")
}

/// THE DEFECT. The workflow's thesis, phase and step claims are retired with
/// it, both ANN columns nulled, and the operation atom (a global,
/// content-addressed id a document may share) is left alone.
#[sqlx::test(migrations = "../../migrations")]
async fn deprecating_a_hierarchical_workflow_retires_its_claims(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let mut with_thesis = extraction("u017-solo");
    with_thesis.thesis = Some("U017 thesis for u017-solo".to_string());
    let wf = ingest_extraction(&pool, &server, &viewer, Some(&token), with_thesis).await;
    let owned = executed(&pool, wf, &["0", "1", "2"]).await;
    let atoms = executed(&pool, wf, &["3"]).await;
    assert_eq!(
        owned.len(),
        3,
        "calibration: one thesis, one phase and one step claim"
    );
    let mut levels = Vec::new();
    for c in &owned {
        levels.push(level_of(&pool, *c).await);
    }
    levels.sort();
    assert_eq!(
        levels,
        vec!["0", "1", "2"],
        "calibration: exactly one claim per structural level, the thesis at level 0"
    );
    assert_eq!(atoms.len(), 1, "calibration: one operation atom");
    for c in owned.iter().chain(&atoms) {
        assert!(
            is_current(&pool, *c).await,
            "calibration: {c} starts current"
        );
        plant_embeddings(&pool, *c).await;
    }

    let res =
        tools::workflows::deprecate_workflow(&server, &viewer, params(wf, false), Some(&token))
            .await
            .expect("the submitter deprecates its own workflow");

    for c in &owned {
        assert!(
            !is_current(&pool, *c).await,
            "claim {c} of a deprecated workflow must be retired"
        );
        assert_eq!(
            embeddings(&pool, *c).await,
            (false, false),
            "claim {c} must leave both ANN columns"
        );
    }
    assert!(
        (truth(&pool, wf).await - 0.05).abs() < 1e-12,
        "the workflows row is deprecated"
    );
    for a in &atoms {
        assert!(
            is_current(&pool, *a).await,
            "operation atom {a} is never retired: its id is global"
        );
        assert_eq!(
            embeddings(&pool, *a).await,
            (true, true),
            "atom {a} keeps its embeddings"
        );
    }
    let body = first_text(&res);
    assert_eq!(ids(&body, "deprecated_ids"), vec![wf.to_string()]);
    let mut want: Vec<String> = owned.iter().map(Uuid::to_string).collect();
    want.sort();
    assert_eq!(ids(&body, "retired_claim_ids"), want, "{body}");
}

/// A step claim shared by a LIVE generation stays current, and is reported as
/// kept; once no live workflow executes it, deprecating the last one retires
/// it. The phase each generation owns alone is retired with it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_shared_step_of_a_live_generation_stays_current(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let gen0 = ingest(&pool, &server, &viewer, Some(&token), "u017-shared").await;
    let gen1 = improve(&pool, &server, &viewer, Some(&token), "u017-shared").await;
    let steps0 = executed(&pool, gen0, &["2"]).await;
    let steps1 = executed(&pool, gen1, &["2"]).await;
    let phase0 = executed(&pool, gen0, &["1"]).await;
    let phase1 = executed(&pool, gen1, &["1"]).await;
    assert_eq!(steps0.len(), 1, "calibration: one step");
    assert_eq!(
        steps0, steps1,
        "calibration: both generations execute the SAME step claim row"
    );
    assert_ne!(
        phase0, phase1,
        "calibration: each generation has its own phase"
    );
    let step = steps0[0];

    let res =
        tools::workflows::deprecate_workflow(&server, &viewer, params(gen0, false), Some(&token))
            .await
            .expect("deprecate gen0");
    assert!(
        is_current(&pool, step).await,
        "the step gen1 still executes must stay current"
    );
    assert!(
        !is_current(&pool, phase0[0]).await,
        "gen0's own phase is retired"
    );
    assert!(
        is_current(&pool, phase1[0]).await,
        "gen1's phase is untouched"
    );
    assert!(
        (truth(&pool, gen1).await - 1.0).abs() < 1e-12,
        "gen1 is untouched"
    );
    let body = first_text(&res);
    assert_eq!(
        ids(&body, "kept_shared_claim_ids"),
        vec![step.to_string()],
        "{body}"
    );

    tools::workflows::deprecate_workflow(&server, &viewer, params(gen1, false), Some(&token))
        .await
        .expect("deprecate gen1");
    assert!(
        !is_current(&pool, step).await,
        "with no live workflow left executing it, the step is retired"
    );
    assert!(!is_current(&pool, phase1[0]).await);
}

/// `cascade: true` on gen0 walks the workflow-to-workflow lineage (gen1 is
/// linked to gen0 by `parent_id` and a `workflow -variant_of-> workflow`
/// edge), deprecates both rows, and retires the step they share in the same
/// call, because the whole target set is going.
#[sqlx::test(migrations = "../../migrations")]
async fn cascade_walks_workflow_variants(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let gen0 = ingest(&pool, &server, &viewer, Some(&token), "u017-cascade").await;
    let gen1 = improve(&pool, &server, &viewer, Some(&token), "u017-cascade").await;
    let all: Vec<Uuid> = [
        executed(&pool, gen0, &["0", "1", "2"]).await,
        executed(&pool, gen1, &["0", "1", "2"]).await,
    ]
    .concat();

    let res =
        tools::workflows::deprecate_workflow(&server, &viewer, params(gen0, true), Some(&token))
            .await
            .expect("cascade");
    for wf in [gen0, gen1] {
        assert!(
            (truth(&pool, wf).await - 0.05).abs() < 1e-12,
            "workflow {wf} is deprecated by the cascade"
        );
    }
    for c in &all {
        assert!(
            !is_current(&pool, *c).await,
            "claim {c} retired by the cascade"
        );
    }
    let body = first_text(&res);
    let mut want = vec![gen0.to_string(), gen1.to_string()];
    want.sort();
    assert_eq!(ids(&body, "deprecated_ids"), want, "{body}");
    assert!(ids(&body, "kept_shared_claim_ids").is_empty(), "{body}");
}

/// A second call changes nothing and says so. Before the fix it reported the
/// id again.
#[sqlx::test(migrations = "../../migrations")]
async fn a_rerun_reports_nothing(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let wf = ingest(&pool, &server, &viewer, Some(&token), "u017-rerun").await;
    tools::workflows::deprecate_workflow(&server, &viewer, params(wf, false), Some(&token))
        .await
        .expect("first");
    let res =
        tools::workflows::deprecate_workflow(&server, &viewer, params(wf, false), Some(&token))
            .await
            .expect("a re-run is not an error");
    let body = first_text(&res);
    assert!(ids(&body, "deprecated_ids").is_empty(), "{body}");
    assert!(ids(&body, "retired_claim_ids").is_empty(), "{body}");
}

/// The flat path reports only a real change too: a re-run on an already
/// deprecated workflow CLAIM lists nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_flat_rerun_reports_nothing(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = fixture::public_viewer(&pool).await;
    let id = common::seed_workflow_claim(&pool, "u017-flat", &["s1"]).await;
    let first = tools::workflows::deprecate_workflow(&server, &viewer, params(id, false), None)
        .await
        .expect("first");
    assert_eq!(
        ids(&first_text(&first), "deprecated_ids"),
        vec![id.to_string()],
        "calibration: the first call deprecates the flat claim"
    );
    assert!(!is_current(&pool, id).await);
    let res = tools::workflows::deprecate_workflow(&server, &viewer, params(id, false), None)
        .await
        .expect("a re-run is not an error");
    let body = first_text(&res);
    assert!(ids(&body, "deprecated_ids").is_empty(), "{body}");
}

/// An id that is neither a claim the caller can read nor a `workflows` row is
/// an error, not a reported deprecation.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_id_is_an_error(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = fixture::public_viewer(&pool).await;
    let ghost = Uuid::new_v4();
    let err = tools::workflows::deprecate_workflow(&server, &viewer, params(ghost, true), None)
        .await
        .expect_err("an unknown id must not be reported as deprecated");
    assert!(
        err.message.contains("nothing was deprecated"),
        "{}",
        err.message
    );
}

/// Over the authenticated transport a stranger may not deprecate a workflow
/// another agent submitted: refused by the workflow authority rule, nothing
/// written. The submitter may; so may the audited admin arm, which records
/// exactly one `workflows.admin_write` row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stranger_cannot_deprecate_a_submitted_workflow(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (_stranger, stranger_token, stranger_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let wf = ingest(
        &pool,
        &server,
        &owner_viewer,
        Some(&owner_token),
        "u017-owned",
    )
    .await;
    let owned = executed(&pool, wf, &["0", "1", "2"]).await;

    let err = tools::workflows::deprecate_workflow(
        &server,
        &stranger_viewer,
        params(wf, true),
        Some(&stranger_token),
    )
    .await
    .expect_err("a stranger must not deprecate another agent's workflow");
    assert!(
        err.message.contains("was submitted by agent"),
        "refused by the workflow authority rule: {}",
        err.message
    );
    assert!(
        (truth(&pool, wf).await - 1.0).abs() < 1e-12,
        "row untouched"
    );
    for c in &owned {
        assert!(is_current(&pool, *c).await, "claim {c} untouched");
    }

    // CALIBRATION: the submitter may.
    tools::workflows::deprecate_workflow(
        &server,
        &owner_viewer,
        params(wf, false),
        Some(&owner_token),
    )
    .await
    .expect("the submitter deprecates its own workflow");
    assert!(!is_current(&pool, owned[0]).await);

    // CALIBRATION: the audited admin arm may, on another submitted workflow,
    // and the write is audited exactly once.
    let other = ingest(
        &pool,
        &server,
        &owner_viewer,
        Some(&owner_token),
        "u017-owned-admin",
    )
    .await;
    let (admin_token, admin_viewer) = common::server_admin(&server).await;
    seed_admin_grant(&pool, &admin_token).await;
    let admin = admin_token.agent_id.expect("admin agent");
    tools::workflows::deprecate_workflow(
        &server,
        &admin_viewer,
        params(other, false),
        Some(&admin_token),
    )
    .await
    .expect("a live claims:admin grant deprecates another agent's workflow");
    assert!((truth(&pool, other).await - 0.05).abs() < 1e-12);
    assert_eq!(workflow_admin_audits(&pool, admin).await, 1, "audited once");
    let audited: Option<String> = sqlx::query_scalar(
        "SELECT details->>'workflow_id' FROM security_events \
          WHERE event_type = 'workflows.admin_write' AND agent_id = $1",
    )
    .bind(admin)
    .fetch_one(&pool)
    .await
    .expect("audit row");
    assert_eq!(audited, Some(other.to_string()));
}

/// A workflow with no recorded submitter is platform corpus (U005, default
/// decision A): over the authenticated transport even its original ingester
/// is refused, and only the audited admin arm admits.
#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_workflow_is_deprecated_only_through_the_audited_admin_arm(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let wf = ingest(
        &pool,
        &server,
        &owner_viewer,
        Some(&owner_token),
        "u017-legacy",
    )
    .await;
    sqlx::query("UPDATE workflows SET metadata = metadata - 'epigraph_submitted_by' WHERE id = $1")
        .bind(wf)
        .execute(&pool)
        .await
        .expect("forget the submitter");
    let owned = executed(&pool, wf, &["0", "1", "2"]).await;

    let err = tools::workflows::deprecate_workflow(
        &server,
        &owner_viewer,
        params(wf, false),
        Some(&owner_token),
    )
    .await
    .expect_err("claims:write alone may not deprecate a legacy workflow");
    assert!(
        err.message.contains("no recorded submitter"),
        "refused by the legacy rule: {}",
        err.message
    );
    assert!(
        (truth(&pool, wf).await - 1.0).abs() < 1e-12,
        "row untouched"
    );
    for c in &owned {
        assert!(is_current(&pool, *c).await, "claim {c} untouched");
    }

    let (admin_token, admin_viewer) = common::server_admin(&server).await;
    seed_admin_grant(&pool, &admin_token).await;
    let admin = admin_token.agent_id.expect("admin agent");
    tools::workflows::deprecate_workflow(
        &server,
        &admin_viewer,
        params(wf, false),
        Some(&admin_token),
    )
    .await
    .expect("the audited admin arm deprecates a legacy workflow");
    for c in &owned {
        assert!(
            !is_current(&pool, *c).await,
            "claim {c} retired by the admin"
        );
    }
    assert_eq!(workflow_admin_audits(&pool, admin).await, 1);
    let submitter_kind: Option<String> = sqlx::query_scalar(
        "SELECT jsonb_typeof(details->'submitter') FROM security_events \
          WHERE event_type = 'workflows.admin_write' AND agent_id = $1",
    )
    .bind(admin)
    .fetch_one(&pool)
    .await
    .expect("audit row");
    assert_eq!(submitter_kind.as_deref(), Some("null"));
}

/// stdio is unchanged (the batch H-b bar): an unauthenticated stdio caller is
/// not checked, and its deprecation retires the claims like any other.
#[sqlx::test(migrations = "../../migrations")]
async fn stdio_deprecates_without_an_authority_check(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let wf = ingest(
        &pool,
        &server,
        &owner_viewer,
        Some(&owner_token),
        "u017-stdio",
    )
    .await;
    let owned = executed(&pool, wf, &["0", "1", "2"]).await;
    let public = fixture::public_viewer(&pool).await;
    tools::workflows::deprecate_workflow(&server, &public, params(wf, false), None)
        .await
        .expect("stdio is not checked");
    assert!((truth(&pool, wf).await - 0.05).abs() < 1e-12);
    for c in &owned {
        assert!(!is_current(&pool, *c).await, "claim {c} retired over stdio");
    }
}

/// The authority rule runs over EVERY target of a cascade, not only the root,
/// and one refusal writes nothing: an owner whose lineage has a generation
/// another agent submitted cannot retire that generation through a cascade
/// from its own.
#[sqlx::test(migrations = "../../migrations")]
async fn cascade_refuses_when_any_descendant_is_anothers(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (stranger, stranger_token, stranger_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let gen0 = ingest(
        &pool,
        &server,
        &owner_viewer,
        Some(&owner_token),
        "u017-mixed",
    )
    .await;
    let gen1 = improve(
        &pool,
        &server,
        &owner_viewer,
        Some(&owner_token),
        "u017-mixed",
    )
    .await;
    assert_eq!(
        parent_of(&pool, gen1).await,
        Some(gen0),
        "calibration: gen1 descends from gen0"
    );
    set_submitter(&pool, gen1, stranger).await;
    let gen0_claims = executed(&pool, gen0, &["0", "1", "2"]).await;
    assert!(
        !gen0_claims.is_empty(),
        "calibration: gen0 executes structural claims"
    );

    let err = tools::workflows::deprecate_workflow(
        &server,
        &owner_viewer,
        params(gen0, true),
        Some(&owner_token),
    )
    .await
    .expect_err("the owner of gen0 must not retire gen1, which another agent submitted");
    assert!(
        err.message.contains("was submitted by agent")
            && err.message.contains(&stranger.to_string()),
        "refused over gen1's submitter: {}",
        err.message
    );
    // ALL OR NOTHING: gen0, which the caller may deprecate, is untouched too.
    assert!(
        (truth(&pool, gen0).await - 1.0).abs() < 1e-12,
        "gen0 row untouched"
    );
    assert!(
        (truth(&pool, gen1).await - 1.0).abs() < 1e-12,
        "gen1 row untouched"
    );
    for c in &gen0_claims {
        assert!(is_current(&pool, *c).await, "gen0 claim {c} untouched");
    }

    // CALIBRATION: gen1's submitter may deprecate gen1 on its own.
    tools::workflows::deprecate_workflow(
        &server,
        &stranger_viewer,
        params(gen1, false),
        Some(&stranger_token),
    )
    .await
    .expect("gen1's submitter deprecates gen1");
    assert!((truth(&pool, gen1).await - 0.05).abs() < 1e-12);
}

/// The audited admin arm records one `workflows.admin_write` row PER target
/// of a cascade, each naming its own workflow.
#[sqlx::test(migrations = "../../migrations")]
async fn an_admin_cascade_audits_every_target(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let gen0 = ingest(
        &pool,
        &server,
        &owner_viewer,
        Some(&owner_token),
        "u017-admin-cascade",
    )
    .await;
    let gen1 = improve(
        &pool,
        &server,
        &owner_viewer,
        Some(&owner_token),
        "u017-admin-cascade",
    )
    .await;
    let (admin_token, admin_viewer) = common::server_admin(&server).await;
    seed_admin_grant(&pool, &admin_token).await;
    let admin = admin_token.agent_id.expect("admin agent");
    assert_eq!(
        workflow_admin_audits(&pool, admin).await,
        0,
        "calibration: no audit yet"
    );

    tools::workflows::deprecate_workflow(
        &server,
        &admin_viewer,
        params(gen0, true),
        Some(&admin_token),
    )
    .await
    .expect("the audited admin arm cascades over another agent's lineage");
    for wf in [gen0, gen1] {
        assert!(
            (truth(&pool, wf).await - 0.05).abs() < 1e-12,
            "{wf} deprecated"
        );
    }
    assert_eq!(
        workflow_admin_audits(&pool, admin).await,
        2,
        "one audit row per target"
    );
    let mut audited: Vec<String> = sqlx::query_scalar(
        "SELECT details->>'workflow_id' FROM security_events \
          WHERE event_type = 'workflows.admin_write' AND agent_id = $1",
    )
    .bind(admin)
    .fetch_all(&pool)
    .await
    .expect("audit rows");
    audited.sort();
    let mut want = vec![gen0.to_string(), gen1.to_string()];
    want.sort();
    assert_eq!(audited, want, "each audit row names its own target");
}

/// The cascade follows the lineage TRANSITIVELY and only DOWNWARD: from gen0
/// it reaches gen2 through gen1; from gen1 it takes gen1 and gen2 and leaves
/// gen0 (and gen0's own phase) live, keeping the step gen0 still executes.
#[sqlx::test(migrations = "../../migrations")]
async fn cascade_is_transitive_and_never_climbs(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, token, viewer) = seed_caller(&pool, &["claims:write"]).await;

    // Lineage A: cascade from the root reaches the grandchild.
    let a0 = ingest(&pool, &server, &viewer, Some(&token), "u017-deep-a").await;
    let a1 = improve_to(&pool, &server, &viewer, Some(&token), "u017-deep-a", 1).await;
    let a2 = improve_to(&pool, &server, &viewer, Some(&token), "u017-deep-a", 2).await;
    assert_eq!(
        parent_of(&pool, a1).await,
        Some(a0),
        "calibration: a1 descends from a0"
    );
    assert_eq!(
        parent_of(&pool, a2).await,
        Some(a1),
        "calibration: a2 descends from a1, not a0, so reaching it is transitive"
    );
    tools::workflows::deprecate_workflow(&server, &viewer, params(a0, true), Some(&token))
        .await
        .expect("cascade from a0");
    for wf in [a0, a1, a2] {
        assert!(
            (truth(&pool, wf).await - 0.05).abs() < 1e-12,
            "workflow {wf} is reached by the cascade from a0"
        );
    }

    // Lineage B: cascade from the middle never reaches the ancestor.
    let b0 = ingest(&pool, &server, &viewer, Some(&token), "u017-deep-b").await;
    let b1 = improve_to(&pool, &server, &viewer, Some(&token), "u017-deep-b", 1).await;
    let b2 = improve_to(&pool, &server, &viewer, Some(&token), "u017-deep-b", 2).await;
    assert_eq!(
        parent_of(&pool, b2).await,
        Some(b1),
        "calibration: b2 descends from b1"
    );
    let b0_phase = executed(&pool, b0, &["1"]).await;
    let step = executed(&pool, b0, &["2"]).await;
    assert_eq!(
        step,
        executed(&pool, b2, &["2"]).await,
        "calibration: one shared step row"
    );
    let res =
        tools::workflows::deprecate_workflow(&server, &viewer, params(b1, true), Some(&token))
            .await
            .expect("cascade from b1");
    for wf in [b1, b2] {
        assert!(
            (truth(&pool, wf).await - 0.05).abs() < 1e-12,
            "{wf} deprecated"
        );
    }
    assert!(
        (truth(&pool, b0).await - 1.0).abs() < 1e-12,
        "the cascade never climbs to the ancestor b0"
    );
    assert!(
        is_current(&pool, b0_phase[0]).await,
        "b0's own phase stays current"
    );
    assert!(
        is_current(&pool, step[0]).await,
        "the step b0 still executes stays current"
    );
    let body = first_text(&res);
    assert_eq!(
        ids(&body, "kept_shared_claim_ids"),
        vec![step[0].to_string()],
        "{body}"
    );
}

/// The FLAT cascade reports only real changes too: a re-run over a parent and
/// its `variant_of` child lists nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_flat_cascade_rerun_reports_nothing(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = fixture::public_viewer(&pool).await;
    let parent = common::seed_workflow_claim(&pool, "u017-flat-parent", &["s1"]).await;
    let child = common::seed_workflow_claim(&pool, "u017-flat-child", &["s1"]).await;
    common::insert_claim_edge(&pool, child, parent, "variant_of").await;

    let first = tools::workflows::deprecate_workflow(&server, &viewer, params(parent, true), None)
        .await
        .expect("first cascade");
    let mut want = vec![parent.to_string(), child.to_string()];
    want.sort();
    assert_eq!(
        ids(&first_text(&first), "deprecated_ids"),
        want,
        "calibration: the first cascade deprecates the parent and its variant"
    );
    assert!(
        !is_current(&pool, child).await,
        "calibration: the child is retired"
    );

    let res = tools::workflows::deprecate_workflow(&server, &viewer, params(parent, true), None)
        .await
        .expect("a re-run is not an error");
    let body = first_text(&res);
    assert!(ids(&body, "deprecated_ids").is_empty(), "{body}");
}

/// Over HTTP a flat workflow claim the caller cannot read is NOT reported as
/// deprecated. Before U017 the dispatch-free flat path ran the UPDATE on the
/// caller's own stamp, which may not write the claim's group, so it changed
/// nothing and listed the id anyway. Its owner still may.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unreadable_flat_claim_is_an_error_not_a_deprecation(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (_other, other_token, other_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let id = common::seed_workflow_claim(&pool, "u017-private-flat", &["s1"]).await;
    common::seed_private_tenancy(&pool, id, owner).await;
    let before = claim_truth(&pool, id).await;

    let err = tools::workflows::deprecate_workflow(
        &server,
        &other_viewer,
        params(id, false),
        Some(&other_token),
    )
    .await
    .expect_err("a claim the caller cannot read must not be reported as deprecated");
    assert!(
        err.message.contains("nothing was deprecated"),
        "{}",
        err.message
    );
    assert!(is_current(&pool, id).await, "the claim stays current");
    assert!(
        (claim_truth(&pool, id).await - before).abs() < 1e-12,
        "the claim's truth is unchanged"
    );

    // CALIBRATION: the owner's group reads and writes it, so the owner may.
    let res = tools::workflows::deprecate_workflow(
        &server,
        &owner_viewer,
        params(id, false),
        Some(&owner_token),
    )
    .await
    .expect("the owner deprecates its own flat workflow claim");
    assert_eq!(
        ids(&first_text(&res), "deprecated_ids"),
        vec![id.to_string()]
    );
    assert!(!is_current(&pool, id).await, "the owner's call retired it");
}

/// Two deprecations of one lineage cannot both keep a step each thinks the
/// other still runs. gen1's deprecation is held open (its truth is already
/// 0.05, uncommitted) while gen0 is deprecated; gen0's call must wait for it
/// and then see gen1 as dead, so the step they share is retired. Without the
/// lineage lock, gen0's call reads gen1 as live under READ COMMITTED, keeps
/// the step, and the step is stranded current with no live workflow.
#[sqlx::test(migrations = "../../migrations")]
async fn a_concurrent_deprecation_of_the_sharing_generation_is_waited_for(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let gen0 = ingest(&pool, &server, &viewer, Some(&token), "u017-race").await;
    let gen1 = improve(&pool, &server, &viewer, Some(&token), "u017-race").await;
    let step = executed(&pool, gen0, &["2"]).await;
    assert_eq!(
        step,
        executed(&pool, gen1, &["2"]).await,
        "calibration: one shared step row"
    );
    let step = step[0];

    let mut held = pool.begin().await.expect("begin the held deprecation");
    sqlx::query("UPDATE workflows SET truth_value = 0.05 WHERE id = $1")
        .bind(gen1)
        .execute(&mut *held)
        .await
        .expect("gen1 deprecated, uncommitted");

    let deprecate =
        tools::workflows::deprecate_workflow(&server, &viewer, params(gen0, false), Some(&token));
    let release = async move {
        tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
        held.commit().await.expect("commit the held deprecation");
    };
    let (res, ()) = tokio::join!(deprecate, release);
    res.expect("deprecate gen0");

    assert!(
        !is_current(&pool, step).await,
        "with both generations deprecated, the step they shared must be retired"
    );
}

/// Hold `FOR UPDATE` on workflow row `wf` from another connection, the way a
/// concurrent deprecation of that row holds it, until the returned
/// transaction ends.
async fn hold_row_lock(pool: &PgPool, wf: Uuid) -> sqlx::Transaction<'static, sqlx::Postgres> {
    let mut held = pool.begin().await.expect("begin the lock holder");
    let locked: Uuid = sqlx::query_scalar("SELECT id FROM workflows WHERE id = $1 FOR UPDATE")
        .bind(wf)
        .fetch_one(&mut *held)
        .await
        .expect("lock the row");
    assert_eq!(locked, wf, "calibration: the holder locked {wf}");
    held
}

/// LOCK-BEFORE-AUTHZ (security review of U017). A caller with no authority
/// over a lineage must be refused WITHOUT taking a single lineage row lock:
/// otherwise every refused call queues behind, and then blocks, every honest
/// deprecation of that lineage until its refusal rolls back, a contention
/// lever any `claims:write` token can pull on anyone's workflow.
///
/// A sibling generation (gen1: same `canonical_name`, NOT a target, since the
/// call does not cascade) is held `FOR UPDATE` from another connection for
/// `HOLD`. The stranger's refusal must come back well inside `HOLD`; a
/// stranger that tries to lock the lineage first waits out the whole `HOLD`
/// and only then is refused.
///
/// CALIBRATION, so the fast refusal is not vacuous: the SUBMITTER's call
/// against the same held lock does wait for it, so the held row is one the
/// deprecation really locks.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unauthorized_deprecation_takes_no_lineage_lock(pool: PgPool) {
    const HOLD: std::time::Duration = std::time::Duration::from_millis(3000);
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (_stranger, stranger_token, stranger_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let gen0 = ingest(
        &pool,
        &server,
        &owner_viewer,
        Some(&owner_token),
        "u017-lock-authz",
    )
    .await;
    let gen1 = improve(
        &pool,
        &server,
        &owner_viewer,
        Some(&owner_token),
        "u017-lock-authz",
    )
    .await;
    assert_ne!(gen0, gen1, "calibration: two rows of one lineage");

    // The stranger, against a held sibling lock.
    let held = hold_row_lock(&pool, gen1).await;
    let started = std::time::Instant::now();
    let stranger_call = async {
        let r = tools::workflows::deprecate_workflow(
            &server,
            &stranger_viewer,
            params(gen0, false),
            Some(&stranger_token),
        )
        .await;
        (r, started.elapsed())
    };
    let release = async move {
        tokio::time::sleep(HOLD).await;
        held.commit().await.expect("release the sibling lock");
    };
    let ((res, stranger_took), ()) = tokio::join!(stranger_call, release);
    let err = res.expect_err("a stranger must not deprecate another agent's workflow");
    assert!(
        err.message.contains("was submitted by agent"),
        "refused by the workflow authority rule: {}",
        err.message
    );
    assert!(
        stranger_took < std::time::Duration::from_millis(1500),
        "an unauthorized caller must be refused before it locks any lineage row, but its \
         refusal waited {stranger_took:?} on a sibling generation's row lock held for {HOLD:?}"
    );
    assert!(
        (truth(&pool, gen0).await - 1.0).abs() < 1e-12,
        "row untouched"
    );

    // CALIBRATION: the submitter's call waits on the same held lock.
    let held = hold_row_lock(&pool, gen1).await;
    let started = std::time::Instant::now();
    let owner_call = async {
        let r = tools::workflows::deprecate_workflow(
            &server,
            &owner_viewer,
            params(gen0, false),
            Some(&owner_token),
        )
        .await;
        (r, started.elapsed())
    };
    let release = async move {
        tokio::time::sleep(HOLD).await;
        held.commit().await.expect("release the sibling lock");
    };
    let ((res, owner_took), ()) = tokio::join!(owner_call, release);
    res.expect("the submitter deprecates its own workflow");
    assert!(
        owner_took >= HOLD - std::time::Duration::from_millis(500),
        "calibration: an authorized deprecation locks the lineage, so it waited on the held \
         sibling lock (took {owner_took:?}, held {HOLD:?})"
    );
    assert!((truth(&pool, gen0).await - 0.05).abs() < 1e-12);
}

/// TOCTOU. Authority is checked before the lineage lock (so a refusal costs no
/// lock) and RE-CHECKED under it, before any write: the decision that admits
/// the write must be one no concurrent transaction can still change.
///
/// The owner's call passes the pre-lock check, then waits on the target row,
/// which another transaction holds while it re-records the submitter as a
/// stranger. When that commits, the owner no longer has authority, and the
/// call must refuse with nothing written. A fix that checks only before the
/// lock deprecates on a stale grant.
#[sqlx::test(migrations = "../../migrations")]
async fn authority_is_rechecked_under_the_lineage_lock(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (stranger, _stranger_token, _stranger_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let wf = ingest(
        &pool,
        &server,
        &owner_viewer,
        Some(&owner_token),
        "u017-toctou",
    )
    .await;
    let owned = executed(&pool, wf, &["0", "1", "2"]).await;
    assert!(
        !owned.is_empty(),
        "calibration: the workflow executes claims"
    );

    let mut held = pool.begin().await.expect("begin the re-recording tx");
    sqlx::query(
        "UPDATE workflows \
            SET metadata = jsonb_set(metadata, '{epigraph_submitted_by}', to_jsonb($2::text)) \
          WHERE id = $1",
    )
    .bind(wf)
    .bind(stranger)
    .execute(&mut *held)
    .await
    .expect("re-record the submitter, uncommitted");

    let owner_call = tools::workflows::deprecate_workflow(
        &server,
        &owner_viewer,
        params(wf, false),
        Some(&owner_token),
    );
    let release = async move {
        tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
        held.commit()
            .await
            .expect("commit the re-recorded submitter");
    };
    let (res, ()) = tokio::join!(owner_call, release);
    let err = res.expect_err(
        "the submitter changed while the call waited on the lock; the stale grant must not write",
    );
    assert!(
        err.message
            .contains(&format!("was submitted by agent {stranger}")),
        "refused by the re-check, naming the NEW submitter: {}",
        err.message
    );
    assert!(
        (truth(&pool, wf).await - 1.0).abs() < 1e-12,
        "row untouched"
    );
    for c in &owned {
        assert!(is_current(&pool, *c).await, "claim {c} untouched");
    }
}
