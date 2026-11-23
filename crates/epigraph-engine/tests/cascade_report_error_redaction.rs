//! A belief re-derivation step that fails hands a non-bypass caller the step
//! and the ids it ran on, never the error's text (backlog f9acb220).
//!
//! `CascadeReport::errors` reaches callers in 2xx bodies (`belief_cascade` on
//! the supersede, dedup, un-dedup, match-retire and evolve-step answers, over
//! HTTP and MCP). Each entry is `"{context}: {error}"`, and the error is
//! usually a driver error: SQL, a constraint, a statement timeout, another
//! writer's row. The 500-body redaction never sees a 2xx, so
//! `admin_cascade::report_for_caller` is where the text is withheld. The full
//! entry stays in the agent-less belief-ids audit row.
//!
//! The failure is real: after the caller's act, a trigger refuses every write
//! of a claim's cached belief, so each re-derivation step fails on its own
//! savepoint while the repair before it (which moves BBAs and edges, not the
//! cache) commits.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::ClaimId;
use epigraph_db::repos::admin_cascade as audit;
use epigraph_db::{ClaimRepository, FrameRepository, MassFunctionRepository, PgPool};
use epigraph_engine::admin_cascade::{
    apply_after_dedup, CascadeCause, CascadeState, CascadeTrigger,
};
use uuid::Uuid;

const MARKER: &str = "cascade-belief-f9ac-canary-relation-secret_belief_shadow";
/// [`MARKER`] with its middle word left for plpgsql to fill in, so the full
/// marker appears only in the raised error, never in a statement this test runs.
const MARKER_TEMPLATE: &str = "cascade-belief-f9ac-%-relation-secret_belief_shadow";

async fn store(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Uuid, m: serde_json::Value) {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        None,
        &m,
        None,
        None,
        None,
        Some("empirical"),
        "unknown",
        None,
    )
    .await
    .expect("store bba");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_rederivation_step_reaches_the_caller_without_its_error_text(pool: PgPool) {
    let (_scoped, maintenance) = fixture::bypass(&pool).await;
    // A remote caller: never the bypass shape (that is a replay or a
    // maintenance job, which gets the report as written).
    let caller = fixture::public_viewer(&pool).await;
    assert!(!caller.is_bypass(), "calibration: the caller is not bypass");

    let f = FrameRepository::create(
        &pool,
        "binary_truth",
        None,
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("frame")
    .id;
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (other, _) = fixture::seed_agent_with_group(&pool, "other").await;
    let canonical = fixture::seed_public_claim(&pool, author, "f9ac canonical").await;
    let dup = fixture::seed_public_claim(&pool, author, "f9ac duplicate").await;
    for c in [canonical, dup] {
        FrameRepository::assign_claim(&pool, c, f, Some(0))
            .await
            .expect("bind");
    }
    store(
        &pool,
        canonical,
        f,
        other,
        serde_json::json!({"0": 0.3, "0,1": 0.7}),
    )
    .await;
    store(
        &pool,
        dup,
        f,
        author,
        serde_json::json!({"0": 0.8, "0,1": 0.2}),
    )
    .await;

    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::mark_duplicate_act_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("the caller's act");

    sqlx::query(&format!(
        "CREATE FUNCTION test_refuse_belief_cache() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION '{MARKER_TEMPLATE}', 'canary'; END $$"
    ))
    .execute(&pool)
    .await
    .expect("create the refusing function");
    sqlx::query(
        "CREATE TRIGGER test_refuse_belief_cache BEFORE UPDATE OF pignistic_prob ON claims \
         FOR EACH ROW EXECUTE FUNCTION test_refuse_belief_cache()",
    )
    .execute(&pool)
    .await
    .expect("create the refusing trigger");

    let t = CascadeTrigger::new(
        CascadeCause::Dedup,
        Some(author),
        None,
        dup,
        Some(canonical),
    );
    let (status, report) =
        apply_after_dedup(&mut conn, &maintenance, &caller, &t, dup, canonical).await;

    // Calibration: the repair committed, and the re-derivation after it failed
    // on a claim the caller can read, so the entry is redacted for its text,
    // not swapped for the out-of-view line (which the old code also produced).
    assert_eq!(
        status.status,
        CascadeState::Applied,
        "the repair must commit; only the belief steps fail: {status:?}"
    );
    assert!(
        !report.errors.is_empty(),
        "the refused cache write must be reported: {report:?}"
    );
    let expected = format!("recompute claim {canonical}: failed; the details are in the audit row");
    assert!(
        report.errors.contains(&expected),
        "the caller learns which step failed on which claim it can read: {:?}",
        report.errors
    );
    for e in &report.errors {
        assert!(
            !e.contains("f9ac-canary") && !e.contains("secret_belief_shadow"),
            "the database's error text reached the caller's report: {e}"
        );
    }

    // The detail the caller is pointed at exists: the agent-less belief-ids
    // row carries the full entry.
    let ids_rows: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT details FROM security_events WHERE event_type = $1 AND agent_id IS NULL \
           AND details->>'subject_id' = $2::text",
    )
    .bind(audit::EVENT_BELIEF_IDS)
    .bind(dup)
    .fetch_all(&pool)
    .await
    .expect("read the belief-ids rows");
    assert!(
        ids_rows.iter().any(|d| d.to_string().contains(MARKER)),
        "the full error stays in the agent-less belief-ids row: {ids_rows:?}"
    );
}
