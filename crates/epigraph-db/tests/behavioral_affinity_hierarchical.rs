//! U033 / I229: hierarchical outcome reports must reach behavioral affinity.
//!
//! A hierarchical report writes one `behavioral_executions` row per step with
//! `workflow_id` = a `workflows.id`, never a `claims.id`. The lineage CTE's
//! `live_roots` joins `claims` only, so every hierarchical row drops out
//! there, embedded or not, and `find_workflow`'s hierarchical leg (keyed on
//! `find_lineage_root(row.id)` = `row.id`, since a `workflows` row has no
//! claim→claim lineage edges) never found an affinity entry.
//! `BehavioralExecutionRepository::behavioral_affinity_hierarchical` is the
//! separate query that scores them, so they never compete with flat roots for
//! `behavioral_affinity_lineage`'s `limit`.

use chrono::{Duration, Utc};
use epigraph_db::visibility::Viewer;
use epigraph_db::{BehavioralExecutionRepository, BehavioralExecutionRow, WorkflowRepository};

/// The hierarchical affinity query under test, with the callers' floor and
/// limit defaults spelled out once.
async fn hier_affinity(pool: &PgPool, q: &str, min_executions: i64) -> Vec<(Uuid, f64, i64)> {
    BehavioralExecutionRepository::behavioral_affinity_hierarchical(
        pool,
        q,
        0.5,
        min_executions,
        10,
    )
    .await
    .expect("hierarchical affinity query")
}
use sqlx::PgPool;
use uuid::Uuid;

#[path = "support/statement_log.rs"]
mod statement_log;

const DIM: usize = 1536;

/// A unit vector along axis `axis`, as a pgvector literal.
fn axis_vec(axis: usize) -> String {
    let mut v = vec!["0"; DIM];
    v[axis] = "1";
    format!("[{}]", v.join(","))
}

async fn insert_workflow(pool: &PgPool, canonical_name: &str, truth_value: f64) -> Uuid {
    let id = Uuid::new_v4();
    WorkflowRepository::insert_root(
        pool,
        id,
        canonical_name,
        0,
        "Deploy a service with zero downtime",
        None,
        serde_json::json!({}),
    )
    .await
    .expect("insert workflows row");
    sqlx::query("UPDATE workflows SET truth_value = $1 WHERE id = $2")
        .bind(truth_value)
        .bind(id)
        .execute(pool)
        .await
        .expect("set truth_value");
    id
}

/// One hierarchical outcome report: `steps` rows sharing one `created_at`
/// and one goal embedding, exactly as `do_report_hierarchical_outcome_as`
/// writes them.
async fn insert_report(
    pool: &PgPool,
    workflow_id: Uuid,
    success: bool,
    steps: usize,
    at: chrono::DateTime<Utc>,
    pgvec: &str,
) {
    for i in 0..steps {
        let row = BehavioralExecutionRow {
            id: Uuid::new_v4(),
            workflow_id,
            goal_text: "Deploy a service with zero downtime".to_string(),
            success,
            step_beliefs: serde_json::json!({"deviated": false}),
            tool_pattern: vec![format!("Step {i}")],
            quality: Some(if success { 1.0 } else { 0.0 }),
            deviation_count: 0,
            total_steps: 1,
            created_at: at,
            step_claim_id: None,
            run_label: None,
        };
        BehavioralExecutionRepository::create(pool, row, Some(pgvec))
            .await
            .expect("insert behavioral_executions row");
    }
}

async fn public_viewer(pool: &PgPool) -> Viewer {
    Viewer::resolve(pool, Uuid::nil())
        .await
        .expect("resolve viewer")
}

#[sqlx::test(migrations = "../../migrations")]
async fn hierarchical_executions_reach_affinity(pool: PgPool) {
    let wf = insert_workflow(&pool, "u033-affinity-live", 1.0).await;
    let q = axis_vec(0);
    let t0 = Utc::now();
    // Two successful reports, of 3 steps and 2 steps, plus one failed report.
    insert_report(&pool, wf, true, 3, t0, &q).await;
    insert_report(&pool, wf, true, 2, t0 + Duration::seconds(1), &q).await;
    insert_report(&pool, wf, false, 2, t0 + Duration::seconds(2), &q).await;

    let hits = hier_affinity(&pool, &q, 1).await;

    let hit = hits
        .iter()
        .find(|(id, _, _)| *id == wf)
        .unwrap_or_else(|| panic!("hierarchical workflow {wf} missing from affinity: {hits:?}"));
    assert!(hit.1 > 0.99, "same-goal similarity must be ~1: {hit:?}");
    // The count is per REPORT, not per step row: 2 successful reports, not 5
    // rows. A per-row count would let one many-step report clear any
    // `min_executions` gate on its own, which a flat workflow (one row per
    // report) cannot.
    assert_eq!(
        hit.2, 2,
        "execution_count counts successful reports: {hit:?}"
    );

    // The gate is applied to that per-report count.
    let gated = hier_affinity(&pool, &q, 3).await;
    assert!(
        gated.iter().all(|(id, _, _)| *id != wf),
        "2 reports must not clear min_executions = 3: {gated:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn deprecated_hierarchical_workflows_stay_out_of_affinity(pool: PgPool) {
    // Same shape as the live case; only the deprecation differs, so a missing
    // row here is the truth_value filter and nothing else.
    let live = insert_workflow(&pool, "u033-affinity-live-control", 1.0).await;
    let dead = insert_workflow(&pool, "u033-affinity-deprecated", 0.05).await;
    let q = axis_vec(1);
    let t0 = Utc::now();
    insert_report(&pool, live, true, 2, t0, &q).await;
    insert_report(&pool, dead, true, 2, t0, &q).await;

    let hits = hier_affinity(&pool, &q, 1).await;
    assert!(
        hits.iter().any(|(id, _, _)| *id == live),
        "control: the live workflow must appear: {hits:?}"
    );
    assert!(
        hits.iter().all(|(id, _, _)| *id != dead),
        "a deprecated (truth 0.05) workflow must not appear: {hits:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn hierarchical_affinity_respects_the_similarity_floor(pool: PgPool) {
    let wf = insert_workflow(&pool, "u033-affinity-orthogonal", 1.0).await;
    insert_report(&pool, wf, true, 2, Utc::now(), &axis_vec(2)).await;

    // Positive control: the aligned query finds it, so a missing row below is
    // the similarity floor and nothing else.
    let aligned = hier_affinity(&pool, &axis_vec(2), 1).await;
    assert!(
        aligned.iter().any(|(id, sim, _)| *id == wf && *sim > 0.99),
        "control: the same-goal query must find the workflow: {aligned:?}"
    );

    // Orthogonal query: cosine similarity 0, below the 0.5 floor.
    let hits = hier_affinity(&pool, &axis_vec(3), 1).await;
    assert!(
        hits.iter().all(|(id, _, _)| *id != wf),
        "an unrelated goal must not match: {hits:?}"
    );
}

/// The two stores stay in their own queries: a FLAT execution (its
/// `workflow_id` is a workflow claim) is keyed on that claim and counted once
/// per row by `behavioral_affinity_lineage`, which returns no hierarchical
/// root; `behavioral_affinity_hierarchical` returns the hierarchical root and
/// no flat one.
#[sqlx::test(migrations = "../../migrations")]
async fn flat_and_hierarchical_executions_are_scored_by_separate_queries(pool: PgPool) {
    let agent_id: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id",
    )
    .bind(blake3::hash(b"u033-flat-agent").as_bytes().as_slice())
    .bind("u033-flat-agent")
    .fetch_one(&pool)
    .await
    .unwrap();
    let flat: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind("u033 flat workflow")
    .bind(blake3::hash(b"u033 flat workflow").as_bytes().as_slice())
    .bind(agent_id)
    .bind(0.8_f64)
    .fetch_one(&pool)
    .await
    .unwrap();
    let hier = insert_workflow(&pool, "u033-affinity-beside-flat", 1.0).await;
    let q = axis_vec(4);
    let t0 = Utc::now();
    // Two flat reports (one row each) and one 2-step hierarchical report.
    insert_report(&pool, flat, true, 1, t0, &q).await;
    insert_report(&pool, flat, true, 1, t0 + Duration::seconds(1), &q).await;
    insert_report(&pool, hier, true, 2, t0, &q).await;

    let viewer = public_viewer(&pool).await;
    let hits =
        BehavioralExecutionRepository::behavioral_affinity_lineage(&pool, &viewer, &q, 0.5, 1, 10)
            .await
            .expect("affinity query");
    let flat_hit = hits
        .iter()
        .find(|(id, _, _)| *id == flat)
        .unwrap_or_else(|| panic!("flat workflow claim {flat} missing: {hits:?}"));
    assert_eq!(flat_hit.2, 2, "flat rows count once each: {flat_hit:?}");
    assert!(
        hits.iter().all(|(id, _, _)| *id != hier),
        "the lineage query scores claim roots only: {hits:?}"
    );

    let hier_hits = hier_affinity(&pool, &q, 1).await;
    let hier_hit = hier_hits
        .iter()
        .find(|(id, _, _)| *id == hier)
        .unwrap_or_else(|| panic!("hierarchical workflow {hier} missing: {hier_hits:?}"));
    assert_eq!(hier_hit.2, 1, "one hierarchical report: {hier_hit:?}");
    assert!(
        hier_hits.iter().all(|(id, _, _)| *id != flat),
        "the hierarchical query scores `workflows` rows only: {hier_hits:?}"
    );
}

/// A pgvector literal with cosine similarity `cos` to `axis_vec(axis)`: the
/// remaining weight goes on the next axis, so the vector stays unit length.
fn tilted_vec(axis: usize, cos: f64) -> String {
    let mut v = vec!["0".to_string(); DIM];
    v[axis] = format!("{cos}");
    v[axis + 1] = format!("{}", (1.0 - cos * cos).sqrt());
    format!("[{}]", v.join(","))
}

/// Both callers ask for the top 20 roots and only THEN look up the rows they
/// hold: HTTP `search_workflows` only ever looks up FLAT lineage roots, and
/// `find_workflow`'s flat results do the same. Hierarchical roots must not
/// compete for that budget: more than `limit` hierarchical workflows with a
/// closer goal must not push a flat root (similarity 0.9, well above the 0.5
/// floor) out of `behavioral_affinity_lineage`, which would silently strip
/// `behavioral_affinity` from that flat result.
#[sqlx::test(migrations = "../../migrations")]
async fn flat_roots_keep_their_affinity_when_more_than_limit_hierarchical_roots_outrank_them(
    pool: PgPool,
) {
    let agent_id: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id",
    )
    .bind(
        blake3::hash(b"u033-displacement-agent")
            .as_bytes()
            .as_slice(),
    )
    .bind("u033-displacement-agent")
    .fetch_one(&pool)
    .await
    .unwrap();
    let flat: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind("u033 displaced flat workflow")
    .bind(
        blake3::hash(b"u033 displaced flat workflow")
            .as_bytes()
            .as_slice(),
    )
    .bind(agent_id)
    .bind(0.8_f64)
    .fetch_one(&pool)
    .await
    .unwrap();
    let q = axis_vec(5);
    let t0 = Utc::now();
    insert_report(&pool, flat, true, 1, t0, &tilted_vec(5, 0.9)).await;
    const LIMIT: i64 = 20;
    for i in 0..=LIMIT {
        let hier = insert_workflow(&pool, &format!("u033-outranking-{i}"), 1.0).await;
        insert_report(&pool, hier, true, 1, t0, &q).await;
    }

    let viewer = public_viewer(&pool).await;
    let hits = BehavioralExecutionRepository::behavioral_affinity_lineage(
        &pool, &viewer, &q, 0.5, 1, LIMIT,
    )
    .await
    .expect("affinity query");
    let flat_hit = hits
        .iter()
        .find(|(id, _, _)| *id == flat)
        .unwrap_or_else(|| {
            panic!(
                "flat root {flat} displaced from the top {LIMIT}: {} rows, {hits:?}",
                hits.len()
            )
        });
    assert!(
        (flat_hit.1 - 0.9).abs() < 1e-3,
        "the flat root's similarity is the tilted vector's 0.9: {flat_hit:?}"
    );
}

// ============================================================================
// behavioral_affinity_lineage walks once per WORKFLOW, and terminates
// ============================================================================

async fn seed_flat_agent(pool: &PgPool, label: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id")
        .bind(blake3::hash(label.as_bytes()).as_bytes().as_slice())
        .bind(label)
        .fetch_one(pool)
        .await
        .expect("seed agent")
}

/// A flat (claim-rooted) workflow claim.
async fn seed_flat_workflow(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value) \
         VALUES ($1, $2, $3, 0.8) RETURNING id",
    )
    .bind(content)
    .bind(blake3::hash(content.as_bytes()).as_bytes().as_slice())
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed workflow claim")
}

/// `child -[relationship]-> parent`, the direction the lineage walk climbs.
async fn seed_lineage_edge(pool: &PgPool, child: Uuid, parent: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3)",
    )
    .bind(child)
    .bind(parent)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed lineage edge");
}

/// `n` successful one-row reports on `workflow`, all with goal `pgvec`.
async fn seed_successes(pool: &PgPool, workflow: Uuid, n: usize, pgvec: &str) {
    let t0 = Utc::now();
    for i in 0..n {
        insert_report(
            pool,
            workflow,
            true,
            1,
            t0 + Duration::seconds(i as i64),
            pgvec,
        )
        .await;
    }
}

/// Sum of `Actual Rows` over every `Recursive Union` node in an
/// `EXPLAIN (ANALYZE, FORMAT JSON)` plan.
fn recursive_union_rows(plan: &serde_json::Value) -> u64 {
    let mut total = 0;
    let mut stack = vec![plan];
    while let Some(node) = stack.pop() {
        match node {
            serde_json::Value::Array(items) => stack.extend(items),
            serde_json::Value::Object(map) => {
                if map.get("Node Type").and_then(|v| v.as_str()) == Some("Recursive Union") {
                    total += map.get("Actual Rows").and_then(|v| v.as_u64()).unwrap_or(0);
                }
                stack.extend(map.values());
            }
            _ => {}
        }
    }
    total
}

/// The lineage walk is computed once per distinct WORKFLOW, not once per
/// execution: 50 executions of one leaf workflow with a 2-hop lineage must
/// cost 3 recursion rows (leaf, parent, root), not 150.
///
/// The statement is captured from the real call and re-run under `EXPLAIN
/// (ANALYZE)` with the same binds, so the plan measured is the shipped SQL.
/// The results are pinned to fixed values, including a diamond lineage whose
/// every path is counted, so the rewrite cannot change what is returned.
#[sqlx::test(migrations = "../../migrations")]
async fn lineage_walk_is_per_workflow_not_per_execution(pool: PgPool) {
    const EXECUTIONS: usize = 50;
    let agent = seed_flat_agent(&pool, "affinity-walk-agent").await;
    let q = axis_vec(7);

    // leaf -variant_of-> mid -supersedes-> root
    let root = seed_flat_workflow(&pool, agent, "affinity walk root").await;
    let mid = seed_flat_workflow(&pool, agent, "affinity walk mid").await;
    let leaf = seed_flat_workflow(&pool, agent, "affinity walk leaf").await;
    seed_lineage_edge(&pool, leaf, mid, "variant_of").await;
    seed_lineage_edge(&pool, mid, root, "supersedes").await;
    seed_successes(&pool, leaf, EXECUTIONS, &q).await;

    let viewer = public_viewer(&pool).await;
    let (hits, statements) = statement_log::capture(
        BehavioralExecutionRepository::behavioral_affinity_lineage(&pool, &viewer, &q, 0.5, 1, 20),
    )
    .await;
    let hits = hits.expect("affinity query");

    // ---- semantics: one root, every execution counted once ----
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].0, root, "the lineage root scores: {hits:?}");
    assert!((hits[0].1 - 1.0).abs() < 1e-9, "same goal: {hits:?}");
    assert_eq!(hits[0].2, EXECUTIONS as i64, "{hits:?}");

    // ---- cost: the recursion is per workflow ----
    let sql = statements
        .iter()
        .find(|s| s.normalized().starts_with("WITH RECURSIVE lineage"))
        .unwrap_or_else(|| {
            panic!(
                "CALIBRATION: the capture must see the lineage statement:\n{}",
                statement_log::describe(&statements)
            )
        })
        .text()
        .to_string();
    let explain_sql = format!("EXPLAIN (ANALYZE, FORMAT JSON) {sql}");
    let mut explain = sqlx::query_scalar::<_, serde_json::Value>(&explain_sql)
        .bind(&q)
        .bind(0.5_f64)
        .bind(1_i64)
        .bind(20_i64);
    if let Some(g) = viewer.group_bind() {
        explain = explain.bind(g);
    }
    let plan = explain
        .fetch_one(&pool)
        .await
        .expect("explain the lineage statement");
    let rows = recursive_union_rows(&plan);
    assert!(
        rows > 0,
        "CALIBRATION: the plan must contain the recursive union: {plan}"
    );
    assert!(
        rows <= 3,
        "the lineage walk must run once per distinct workflow (1 workflow x 3 lineage \
         nodes = 3 rows), not once per execution ({EXECUTIONS} x 3 = {}); got {rows}",
        EXECUTIONS * 3
    );
}

/// Results are unchanged by the per-workflow walk, including path
/// multiplicity: an execution under a DIAMOND lineage (two paths to one root)
/// is counted once per path, exactly as the per-execution walk counted it.
#[sqlx::test(migrations = "../../migrations")]
async fn lineage_affinity_counts_are_unchanged_by_the_per_workflow_walk(pool: PgPool) {
    let agent = seed_flat_agent(&pool, "affinity-equivalence-agent").await;
    let q = axis_vec(8);

    // Diamond: leaf -> a -> root, leaf -> b -> root; 4 executions on leaf,
    // 1 on a. Separate standalone workflow with 2 executions.
    let root = seed_flat_workflow(&pool, agent, "diamond root").await;
    let a = seed_flat_workflow(&pool, agent, "diamond a").await;
    let b = seed_flat_workflow(&pool, agent, "diamond b").await;
    let leaf = seed_flat_workflow(&pool, agent, "diamond leaf").await;
    seed_lineage_edge(&pool, leaf, a, "variant_of").await;
    seed_lineage_edge(&pool, leaf, b, "variant_of").await;
    seed_lineage_edge(&pool, a, root, "supersedes").await;
    seed_lineage_edge(&pool, b, root, "variant_of").await;
    seed_successes(&pool, leaf, 4, &q).await;
    seed_successes(&pool, a, 1, &q).await;
    let solo = seed_flat_workflow(&pool, agent, "standalone workflow").await;
    seed_successes(&pool, solo, 2, &q).await;

    let viewer = public_viewer(&pool).await;
    let mut hits =
        BehavioralExecutionRepository::behavioral_affinity_lineage(&pool, &viewer, &q, 0.5, 1, 20)
            .await
            .expect("affinity query");
    hits.sort_by_key(|(id, _, n)| (std::cmp::Reverse(*n), *id));
    let got: Vec<(Uuid, i64)> = hits.iter().map(|(id, _, n)| (*id, *n)).collect();
    // root: 4 leaf executions x 2 paths + 1 execution of a = 9.
    assert_eq!(got, vec![(root, 9), (solo, 2)], "{hits:?}");
    assert!(
        hits.iter().all(|(_, sim, _)| (sim - 1.0).abs() < 1e-9),
        "{hits:?}"
    );
}

/// A `supersedes` cycle must not make the walk run forever. Neither claim in
/// the cycle is a root (each has an outgoing lineage edge), so neither scores,
/// and an unrelated workflow still does.
#[sqlx::test(migrations = "../../migrations")]
async fn lineage_walk_terminates_on_a_supersedes_cycle(pool: PgPool) {
    let agent = seed_flat_agent(&pool, "affinity-cycle-agent").await;
    let q = axis_vec(9);

    let a = seed_flat_workflow(&pool, agent, "cycle a").await;
    let b = seed_flat_workflow(&pool, agent, "cycle b").await;
    seed_lineage_edge(&pool, a, b, "supersedes").await;
    seed_lineage_edge(&pool, b, a, "supersedes").await;
    seed_successes(&pool, a, 2, &q).await;
    let solo = seed_flat_workflow(&pool, agent, "cycle control").await;
    seed_successes(&pool, solo, 1, &q).await;

    let viewer = public_viewer(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    // Fail rather than hang if the walk does not terminate.
    sqlx::query("SET statement_timeout = '5s'")
        .execute(&mut *conn)
        .await
        .expect("set statement_timeout");
    let hits = BehavioralExecutionRepository::behavioral_affinity_lineage(
        &mut *conn, &viewer, &q, 0.5, 1, 20,
    )
    .await
    .expect("the lineage walk must terminate on a cycle instead of timing out");

    assert!(
        hits.iter().all(|(id, _, _)| *id != a && *id != b),
        "no claim inside the cycle is a root: {hits:?}"
    );
    assert!(
        hits.iter().any(|(id, _, n)| *id == solo && *n == 1),
        "CALIBRATION: an unrelated workflow still scores: {hits:?}"
    );
}
