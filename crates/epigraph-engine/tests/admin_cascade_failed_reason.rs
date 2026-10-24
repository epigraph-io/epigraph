//! A failed administrative repair leaves a `cascade.admin_failed` audit row
//! whose reason is a static code, not the database's error text (backlog
//! 9d6f21c5, part 1).
//!
//! The row names the triggering agent (`agent_id`), and `security_events_read`
//! lets a principal read the rows naming it, so whatever `details` carries is
//! readable by the caller whose act triggered the cascade. The repair's error
//! is a driver error: it can spell SQL, a constraint, or a row of another
//! writer's. It belongs in the server log, not on that row.
//!
//! The failure is forced with a trigger on `edges` that raises a marker, the
//! technique `epigraph-mcp/tests/challenge_claim_refusal.rs` uses: the dedup
//! repair re-points the duplicate's incoming edge, so its UPDATE hits the
//! trigger and the repair rolls back.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::ClaimId;
use epigraph_db::{ClaimRepository, PgPool};
use epigraph_engine::admin_cascade::{
    apply_after_dedup, CascadeCause, CascadeState, CascadeTrigger,
};
use uuid::Uuid;

const MARKER: &str = "forced-repair-failure-9d6f-relation-secret_edges_shadow";

async fn new_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key) VALUES (sha256(gen_random_uuid()::text::bytea)) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("agent")
}

async fn new_claim(pool: &PgPool, agent: Uuid, tag: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
    )
    .bind(format!("failed cascade {tag} {}", Uuid::new_v4()))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("claim")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_repair_records_a_static_reason_not_the_error_text(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let (author, other) = (new_agent(&pool).await, new_agent(&pool).await);
    let canonical = new_claim(&pool, author, "canonical").await;
    let dup = new_claim(&pool, author, "duplicate").await;
    let supporter = new_claim(&pool, other, "supporter").await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports')",
    )
    .bind(supporter)
    .bind(dup)
    .execute(&pool)
    .await
    .expect("edge onto the duplicate");

    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::mark_duplicate_act_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("the caller's act");

    // After the act (which writes its own identity edge): every further write
    // to `edges` raises the marker, so the repair fails and rolls back.
    sqlx::query(&format!(
        "CREATE FUNCTION test_force_repair_failure() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION '{MARKER}'; END $$"
    ))
    .execute(&pool)
    .await
    .expect("create the forcing function");
    sqlx::query(
        "CREATE TRIGGER test_force_repair_failure BEFORE INSERT OR UPDATE OR DELETE ON edges \
         FOR EACH ROW EXECUTE FUNCTION test_force_repair_failure()",
    )
    .execute(&pool)
    .await
    .expect("create the forcing trigger");

    let t = CascadeTrigger::new(
        CascadeCause::Dedup,
        Some(author),
        None,
        dup,
        Some(canonical),
    );
    let (status, _) = apply_after_dedup(&mut conn, &viewer, &viewer, &t, dup, canonical).await;
    assert_eq!(
        status.status,
        CascadeState::Failed,
        "the forced error must fail the repair: {status:?}"
    );
    let failed_id = status
        .audit_event_id
        .expect("the failed repair writes its audit row");

    // Non-vacuity: exactly one failed row for this subject, and it is the one
    // the status names, attributed to the triggering agent.
    let rows: Vec<(Uuid, Option<Uuid>, serde_json::Value)> = sqlx::query_as(
        "SELECT id, agent_id, details FROM security_events \
         WHERE event_type = 'cascade.admin_failed' \
           AND details->'trigger'->>'subject_id' = $1::text",
    )
    .bind(dup)
    .fetch_all(&pool)
    .await
    .expect("read the failed rows");
    assert_eq!(rows.len(), 1, "one failed row for the subject: {rows:?}");
    let (id, agent_id, details) = &rows[0];
    assert_eq!(*id, failed_id);
    assert_eq!(
        *agent_id,
        Some(author),
        "the row names the triggering agent, who can read it"
    );

    let text = details.to_string();
    assert!(
        !text.contains("forced-repair-failure-9d6f") && !text.contains("secret_edges_shadow"),
        "the database's error text reached an audit row the triggering agent can read: {text}"
    );
    assert_eq!(
        details["reason_code"], "repair_failed",
        "the row carries a static reason code: {details}"
    );
    assert!(
        details["reason"]
            .as_str()
            .is_some_and(|r| r.contains("the dedup repair")),
        "the reason names the step that failed: {details}"
    );
    assert!(
        !status
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("forced-repair-failure-9d6f"),
        "nor does the caller's status carry it: {status:?}"
    );
}
