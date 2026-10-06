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
    tools::workflow_ingest::ingest_workflow(
        server,
        viewer,
        IngestWorkflowParams {
            extraction: extraction(canonical),
        },
        token,
    )
    .await
    .expect("ingest");
    workflow_row(pool, canonical, 0).await
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
    let mut refined = extraction(canonical);
    refined.phases[0].summary = format!("U017 refined phase for {canonical}");
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
    workflow_row(pool, canonical, 1).await
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

/// THE DEFECT. The workflow's phase and step claims are retired with it, both
/// ANN columns nulled, and the operation atom (a global, content-addressed id
/// a document may share) is left alone.
#[sqlx::test(migrations = "../../migrations")]
async fn deprecating_a_hierarchical_workflow_retires_its_claims(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let wf = ingest(&pool, &server, &viewer, Some(&token), "u017-solo").await;
    let owned = executed(&pool, wf, &["0", "1", "2"]).await;
    let atoms = executed(&pool, wf, &["3"]).await;
    assert_eq!(
        owned.len(),
        2,
        "calibration: one phase and one step claim (no thesis in this extraction)"
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

/// An id that is neither a workflow claim nor a `workflows` row is an error,
/// not a reported deprecation.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_id_is_an_error_and_writes_nothing(pool: PgPool) {
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
