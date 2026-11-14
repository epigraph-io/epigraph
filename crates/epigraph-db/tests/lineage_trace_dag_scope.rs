//! The reasoning-trace DAG both lineage walks return is viewer-scoped
//! (`F-PR26-trace-parents-followup`).
//!
//! On the `#[sqlx::test]` superuser pool row security does not apply, so the
//! in-query predicate is the only control and these arms observe it directly.
//! Each arm carries a calibration partner: a trace private to the VIEWER's own
//! group must still be listed.

mod viewer_fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::LineageRepository;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    seed_agent_with_group, seed_group_claim, seed_public_claim, seed_reasoning_trace,
};

struct Dag {
    viewer: Viewer,
    start: Uuid,
    start_trace: Uuid,
    open_trace: Uuid,
    my_trace: Uuid,
    their_trace: Uuid,
}

async fn link(pool: &PgPool, trace: Uuid, parent: Uuid) {
    sqlx::query("INSERT INTO trace_parents (trace_id, parent_id) VALUES ($1, $2)")
        .bind(trace)
        .bind(parent)
        .execute(pool)
        .await
        .expect("seed trace_parents");
}

async fn seed_dag(pool: &PgPool, label: &str) -> Dag {
    let (agent, group) = seed_agent_with_group(pool, &format!("{label}-mine")).await;
    let (stranger, stranger_group) = seed_agent_with_group(pool, &format!("{label}-theirs")).await;

    let start = seed_public_claim(pool, agent, "trace dag: start").await;
    let start_trace = seed_reasoning_trace(pool, start, "deductive").await;

    let open = seed_public_claim(pool, agent, "trace dag: public").await;
    let open_trace = seed_reasoning_trace(pool, open, "inductive").await;
    let mine = seed_group_claim(pool, agent, group, "trace dag: mine").await;
    let my_trace = seed_reasoning_trace(pool, mine, "abductive").await;
    let theirs = seed_group_claim(pool, stranger, stranger_group, "trace dag: theirs").await;
    let their_trace = seed_reasoning_trace(pool, theirs, "analogical").await;

    for parent in [open_trace, my_trace, their_trace] {
        link(pool, start_trace, parent).await;
    }

    let viewer = Viewer::resolve(pool, agent).await.expect("resolve");
    Dag {
        viewer,
        start,
        start_trace,
        open_trace,
        my_trace,
        their_trace,
    }
}

fn assert_scoped(dag: &Dag, mut got: Vec<Uuid>, walk: &str) {
    got.sort();
    let mut want = vec![dag.open_trace, dag.my_trace];
    want.sort();
    assert!(
        !got.contains(&dag.their_trace),
        "{walk}: parent_trace_ids must list only traces the viewer can read; got {got:?}"
    );
    assert_eq!(
        got, want,
        "{walk}: CALIBRATION: the public trace AND the viewer's own group-private trace \
         must both be listed"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn ancestor_walk_trace_dag_is_viewer_scoped(pool: PgPool) {
    let dag = seed_dag(&pool, "tdag-anc").await;
    let out = LineageRepository::get_lineage(&pool, &dag.viewer, dag.start, None, None)
        .await
        .expect("get_lineage");
    let trace = out
        .traces
        .get(&dag.start_trace)
        .expect("the start claim's own trace is readable and must be returned");
    assert_scoped(&dag, trace.parent_trace_ids.clone(), "get_lineage");
}

#[sqlx::test(migrations = "../../migrations")]
async fn descendant_walk_trace_dag_is_viewer_scoped(pool: PgPool) {
    let dag = seed_dag(&pool, "tdag-desc").await;
    let out = LineageRepository::get_descendants(&pool, &dag.viewer, dag.start, None)
        .await
        .expect("get_descendants");
    let trace = out
        .traces
        .get(&dag.start_trace)
        .expect("the start claim's own trace is readable and must be returned");
    assert_scoped(&dag, trace.parent_trace_ids.clone(), "get_descendants");
}
