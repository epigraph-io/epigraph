//! A workflow's steps must come back in PLAN order even though the whole plan is
//! written in ONE transaction.
//!
//! # The defect this pins
//!
//! `epigraph_ingest_executor::execute_workflow_ingest_plan` used to run each
//! statement on its own pooled checkout, so each `executes` edge got its own
//! `NOW()` and "plan order" could be read back as `ORDER BY e.created_at, c.id`.
//! Unit E moved the walk into one transaction. `NOW()` is transaction-START
//! time in PostgreSQL, so every edge (and every claim) of a plan now shares one
//! `created_at`, the tiebreak falls through to `c.id` — a content-derived UUID —
//! and a reader keyed on time returns the steps in arbitrary order.
//!
//! Commit 829ceeaa recorded an explicit `plan_index` on each edge and moved TWO
//! readers onto it. The two `report_hierarchical_outcome` handlers, the batched
//! head resolver, and the executor's own `find_phase` / `ordered_steps` were
//! left on the time key. MEASURED on the real binary as `epigraph_app` before
//! this file existed: a 6-step workflow reported with step_index 0..5 attached
//! 4 of 6 `behavioral_executions` rows to the WRONG step claim, on both schema
//! configurations, and the tool said `isError: false`.
//!
//! # Why the existing suite could not see it
//!
//! `do_ingest_workflow_via_pool`, the `#[sqlx::test]` fixture, walked the plan
//! on a bare autocommit checkout — every statement got its own `NOW()`, so the
//! fixture had exactly the strictly-increasing timestamps production no longer
//! has. The fixture now walks in a transaction, and the first test below goes
//! through the production `store_workflow` path anyway.
//!
//! # Why every test asserts its precondition
//!
//! A time-keyed reader is only WRONG when (a) the timestamps tie and (b) the
//! UUID order differs from plan order. If either fails, a reverted reader passes
//! vacuously. Both are asserted, so a green run means the fix was exercised.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_ingest::common::ids::{compound_claim_id, content_hash};
use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;
use epigraph_mcp::types::{ReportWorkflowOutcomeParams, StepExecution, StoreWorkflowParams};
use sqlx::PgPool;
use uuid::Uuid;

/// The six step texts, in plan order. Chosen (and asserted below) so that their
/// deterministic claim ids are NOT in plan order — the condition under which a
/// time-keyed reader goes wrong.
const STEPS: [&str; 6] = [
    "alpha: gather the inputs",
    "bravo: validate the inputs",
    "charlie: run the transform",
    "delta: check the output",
    "echo: publish the output",
    "foxtrot: record the run",
];

/// Assert the two preconditions every arm here depends on: the workflow's
/// `executes` edges tie on `created_at`, and its steps' UUID order is not plan order.
async fn assert_tie_and_scramble(pool: &PgPool, workflow_id: Uuid, plan: &[&str]) {
    let distinct_edge_ts: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT e.created_at) FROM edges e \
         WHERE e.source_id = $1 AND e.relationship = 'executes'",
    )
    .bind(workflow_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        distinct_edge_ts, 1,
        "PRECONDITION: every executes edge of one plan must share ONE created_at (the plan is \
         written in one transaction). If this fails the walk is no longer transactional and \
         this file tests nothing"
    );

    let by_id: Vec<String> = sqlx::query_scalar(
        "SELECT c.content FROM edges e JOIN claims c ON c.id = e.target_id \
         WHERE e.source_id = $1 AND e.relationship = 'executes' \
           AND (c.properties->>'level')::int = 2 \
         ORDER BY c.id",
    )
    .bind(workflow_id)
    .fetch_all(pool)
    .await
    .unwrap();
    let plan: Vec<String> = plan.iter().map(|s| (*s).to_string()).collect();
    assert_ne!(
        by_id, plan,
        "PRECONDITION: the steps' UUID order must differ from plan order, or a reader keyed on \
         (created_at, c.id) would pass by coincidence. Pick different step texts"
    );
}

/// The production path end to end: `store_workflow` (one stamped transaction)
/// then `report_workflow_outcome` (dispatching to the hierarchical handler).
/// Each reported `step_index` must be attributed to the step at that position in
/// the plan the caller stored.
#[sqlx::test(migrations = "../../migrations")]
async fn report_outcome_attributes_each_step_index_to_its_planned_step(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let stored = epigraph_mcp::tools::workflows::store_workflow(
        &server,
        &viewer,
        StoreWorkflowParams {
            goal: "Plan order under one transaction".to_string(),
            steps: STEPS.iter().map(|s| (*s).to_string()).collect(),
            prerequisites: None,
            expected_outcome: None,
            confidence: None,
            tags: None,
        },
        None,
    )
    .await
    .expect("store_workflow");
    let workflow_id = parse_uuid_field(&first_text(&stored), "workflow_id");

    assert_tie_and_scramble(&pool, workflow_id, &STEPS).await;

    let execution_log: Vec<StepExecution> = STEPS
        .iter()
        .enumerate()
        .map(|(i, s)| StepExecution {
            step_index: i,
            planned: (*s).to_string(),
            actual: format!("{s} — done"),
            deviated: false,
            deviation_reason: None,
        })
        .collect();
    epigraph_mcp::tools::workflows::report_workflow_outcome(
        &server,
        &viewer,
        ReportWorkflowOutcomeParams {
            workflow_id: workflow_id.to_string(),
            success: true,
            execution_log,
            outcome_details: "plan-order probe".to_string(),
            quality: None,
            goal_text: None,
        },
        None,
    )
    .await
    .expect("report_workflow_outcome");

    // `tool_pattern[1]` is the `planned` text the caller sent for that index;
    // the joined claim is where the handler attributed it.
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT b.tool_pattern[1], c.content \
         FROM behavioral_executions b LEFT JOIN claims c ON c.id = b.step_claim_id \
         WHERE b.workflow_id = $1 ORDER BY b.tool_pattern[1]",
    )
    .bind(workflow_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        rows.len(),
        STEPS.len(),
        "one behavioral_executions row per step"
    );
    let misattributed: Vec<String> = rows
        .iter()
        .filter(|(planned, attributed)| attributed.as_deref() != Some(planned.as_str()))
        .map(|(planned, attributed)| format!("{planned:?} -> {attributed:?}"))
        .collect();
    assert!(
        misattributed.is_empty(),
        "report_workflow_outcome attributed {} of {} step_index values to the WRONG step claim \
         (planned -> attributed): {misattributed:?}",
        misattributed.len(),
        STEPS.len()
    );
}

/// `WorkflowRepository::resolve_steps_to_heads_batched` — the reader behind
/// HTTP `find_workflow_hierarchical(resolve_to_latest)` — must assign
/// `step_index` in plan order, the same as its single-workflow sibling.
#[sqlx::test(migrations = "../../migrations")]
async fn batched_head_resolution_assigns_step_index_in_plan_order(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let stored = epigraph_mcp::tools::workflows::store_workflow(
        &server,
        &viewer,
        StoreWorkflowParams {
            goal: "Plan order under one transaction".to_string(),
            steps: STEPS.iter().map(|s| (*s).to_string()).collect(),
            prerequisites: None,
            expected_outcome: None,
            confidence: None,
            tags: None,
        },
        None,
    )
    .await
    .expect("store_workflow");
    let workflow_id = parse_uuid_field(&first_text(&stored), "workflow_id");
    assert_tie_and_scramble(&pool, workflow_id, &STEPS).await;

    let mut conn = pool.acquire().await.unwrap();
    let batched = epigraph_db::WorkflowRepository::resolve_steps_to_heads_batched(
        &mut conn,
        &viewer,
        &[workflow_id],
    )
    .await
    .expect("resolve_steps_to_heads_batched");
    let steps = batched.get(&workflow_id).expect("entry for the workflow");
    let mut got = Vec::new();
    for s in steps {
        let content: String = sqlx::query_scalar("SELECT content FROM claims WHERE id = $1")
            .bind(s.frozen_claim_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        got.push((s.step_index, content));
    }
    let want: Vec<(usize, String)> = STEPS
        .iter()
        .enumerate()
        .map(|(i, s)| (i, (*s).to_string()))
        .collect();
    assert_eq!(
        got, want,
        "resolve_steps_to_heads_batched must number steps in PLAN order"
    );

    // And it must agree with the single-workflow reader, which already did.
    let single =
        epigraph_db::WorkflowRepository::resolve_steps_to_heads(&pool, &viewer, workflow_id)
            .await
            .expect("resolve_steps_to_heads");
    let single_ids: Vec<Uuid> = single.iter().map(|s| s.frozen_claim_id).collect();
    let batched_ids: Vec<Uuid> = steps.iter().map(|s| s.frozen_claim_id).collect();
    assert_eq!(
        batched_ids, single_ids,
        "batched and single readers disagree on step order"
    );
}

fn two_phase_extraction(canonical: &str, first: &str, second: &str) -> WorkflowExtraction {
    let phase = |summary: &str, step: &str| Phase {
        title: summary.to_string(),
        summary: summary.to_string(),
        steps: vec![Step {
            compound: step.to_string(),
            rationale: String::new(),
            operations: vec![],
            generality: vec![],
            confidence: 0.8,
            evidence_type: None,
        }],
    };
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical.to_string(),
            goal: "two-phase plan order".to_string(),
            generation: 0,
            parent_canonical_name: None,
            authors: vec![],
            expected_outcome: None,
            tags: vec![],
            metadata: serde_json::json!({}),
        },
        thesis: None,
        thesis_derivation: ThesisDerivation::TopDown,
        phases: vec![
            phase(first, &format!("{first} step")),
            phase(second, &format!("{second} step")),
        ],
        relationships: vec![],
    }
}

/// `workflow_steps::find_phase` — where `add_step` attaches a new step — must
/// return the plan's FIRST phase, not whichever phase has the smaller UUID.
#[sqlx::test(migrations = "../../migrations")]
async fn find_phase_returns_the_plans_first_phase(pool: PgPool) {
    let canonical = "two-phase-plan-order";
    // Pick phase texts whose deterministic ids sort the WRONG way round, so a
    // `(created_at, c.id)` key would return the second phase. Deterministic:
    // ids are `compound_claim_id(blake3(text), canonical_name)`.
    let (first, second) = (0..64)
        .map(|n| (format!("Prepare phase {n}"), format!("Execute phase {n}")))
        .find(|(a, b)| {
            compound_claim_id(&content_hash(a), canonical)
                > compound_claim_id(&content_hash(b), canonical)
        })
        .expect("some pair among 64 has its ids in reverse order");
    let first_id = compound_claim_id(&content_hash(&first), canonical);

    let viewer = fixture::public_viewer(&pool).await;
    let result = epigraph_mcp::tools::workflow_ingest::do_ingest_workflow_via_pool(
        &pool,
        &viewer,
        &two_phase_extraction(canonical, &first, &second),
    )
    .await
    .expect("ingest");
    let workflow_id = Uuid::parse_str(&result.workflow_id).unwrap();

    let distinct_phase_ts: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT c.created_at) FROM edges e JOIN claims c ON c.id = e.target_id \
         WHERE e.source_id = $1 AND e.relationship = 'executes' \
           AND (c.properties->>'level')::int = 1",
    )
    .bind(workflow_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        distinct_phase_ts, 1,
        "PRECONDITION: both phases are written in one transaction and share created_at"
    );

    // The pre-fix key was `ORDER BY c.created_at LIMIT 1` with NO tiebreak, so on
    // a tie PostgreSQL returns whichever row its scan reaches first — in a fresh
    // table that is insertion order, which happens to be plan order. That is an
    // accident of physical layout, not a guarantee: any UPDATE, VACUUM or
    // re-ingest moves tuples. Move the first phase's rows to the physical end
    // (a no-op UPDATE writes a new tuple version) so the test does not depend on
    // the accident. MEASURED: without these two statements, reverting
    // `find_phase` to the old key still passed this test.
    sqlx::query("UPDATE claims SET truth_value = truth_value WHERE id = $1")
        .bind(first_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE edges SET properties = properties \
         WHERE source_id = $1 AND target_id = $2 AND relationship = 'executes'",
    )
    .bind(workflow_id)
    .bind(first_id)
    .execute(&pool)
    .await
    .unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let phase = epigraph_ingest_executor::workflow_steps::find_phase(&mut conn, workflow_id)
        .await
        .expect("find_phase");
    assert_eq!(
        phase, first_id,
        "find_phase returned the second phase ({second:?}); add_step would attach new steps \
         under it"
    );
}

// ── Source ratchet ──────────────────────────────────────────────────────────

/// Every SQL literal in production source that reads `executes` edges and
/// ORDERS by a timestamp must lead with the `plan_index` ordinal.
///
/// The behavioural tests above cover the readers this commit fixed. This covers
/// the one that has no convenient harness here — the HTTP
/// `report_hierarchical_outcome` handler in `epigraph-api` — and any future
/// reader: the defect was exactly "a sibling reader was left on the old key",
/// and that is what a syntactic scan is good at.
///
/// Exemptions are by `(file, fragment)` and each carries its reason.
const TIME_ORDERED_EXECUTES_READS_EXEMPT: &[(&str, &str, &str)] = &[(
    "epigraph-ingest-executor/src/workflow_steps.rs",
    "c.step_lineage_id = $2",
    "`delete_step` picks ONE claim of ONE lineage under ONE workflow. A workflow has at most \
     one `executes`-attached claim per lineage (`evolve_step` supersedes without adding an \
     `executes` edge; `improve_workflow_hierarchy` writes a new workflow row), so there is no \
     tie for the order to break.",
)];

#[test]
fn every_time_ordered_executes_reader_leads_with_plan_index() {
    let crates_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .to_path_buf();
    let mut offenders = Vec::new();
    let mut scanned = 0usize;
    for krate in std::fs::read_dir(&crates_root).expect("read crates/") {
        let src = krate.expect("entry").path().join("src");
        if !src.is_dir() {
            continue;
        }
        let mut stack = vec![src];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read_dir") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("read");
                let rel = path
                    .strip_prefix(&crates_root)
                    .expect("strip")
                    .to_string_lossy()
                    .replace('\\', "/");
                for (idx, _) in text.match_indices("relationship = 'executes'") {
                    // The literal runs to the next unescaped double quote.
                    let tail = &text[idx..];
                    let mut end = tail.len();
                    let bytes = tail.as_bytes();
                    for i in 0..bytes.len() {
                        if bytes[i] == b'"' && (i == 0 || bytes[i - 1] != b'\\') {
                            end = i;
                            break;
                        }
                    }
                    let literal = &tail[..end];
                    if !(literal.contains("ORDER BY") && literal.contains("created_at")) {
                        continue;
                    }
                    scanned += 1;
                    if literal.contains("plan_index") || literal.contains("{PLAN_ORDER}") {
                        continue;
                    }
                    if TIME_ORDERED_EXECUTES_READS_EXEMPT
                        .iter()
                        .any(|(f, frag, _)| rel == *f && literal.contains(frag))
                    {
                        continue;
                    }
                    let line = text[..idx].matches('\n').count() + 1;
                    offenders.push(format!("{rel}:{line}"));
                }
            }
        }
    }
    assert!(
        scanned >= 5,
        "found only {scanned} time-ordered `executes` reads; the scan pattern has drifted from \
         the source and is watching nothing"
    );
    assert!(
        offenders.is_empty(),
        "these SQL literals order a workflow's `executes` edges by a timestamp without leading \
         with `plan_index`. A plan is written in ONE transaction, so every edge and claim of it \
         shares one `NOW()`, and the order falls through to a content-derived UUID: {offenders:?}"
    );
}
