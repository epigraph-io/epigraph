//! `ClaimRepository::patch_claim_atomic_conn` writes a claim's `trace_id` and
//! `properties` in ONE `UPDATE`, and only when the patch sets either.
//!
//! It used to issue one `UPDATE` for `trace_id` and a second for `properties`
//! (plus `update_labels_conn`'s, which stays separate because it carries the
//! unexpanded-label validation), so a patch of both fields cost two statements
//! and two passes of every row trigger on `claims`.
//!
//! The statements are COUNTED, not timed: a per-row `AFTER UPDATE` trigger,
//! installed only in this test's database (`#[sqlx::test]` gives each test its
//! own), logs one row per `UPDATE` that touches the claim.

use epigraph_core::ClaimId;
use epigraph_db::{ClaimRepository, PatchClaimInput};
use sqlx::PgPool;
use uuid::Uuid;

/// A current claim with `properties = {"keep": 1}` and a trace it can be
/// pointed at (`claims.trace_id` references `reasoning_traces`, whose row names
/// an anchor claim). Returns `(claim, trace)`.
async fn seed(pool: &PgPool) -> (Uuid, Uuid) {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'patch-statements', 'system') \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent");
    let mut ids = Vec::new();
    for what in ["anchor", "patched"] {
        let text = format!("patch statements {what} {}", Uuid::new_v4());
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, properties) \
             VALUES ($1, sha256($1::bytea), 0.5, $2, '{\"keep\": 1}'::jsonb) RETURNING id",
        )
        .bind(&text)
        .bind(agent)
        .fetch_one(pool)
        .await
        .expect("seed claim");
        ids.push(id);
    }
    let trace: Uuid = sqlx::query_scalar(
        "INSERT INTO reasoning_traces (claim_id, reasoning_type, explanation) \
         VALUES ($1, 'deductive', 'patch statements fixture') RETURNING id",
    )
    .bind(ids[0])
    .fetch_one(pool)
    .await
    .expect("seed trace");

    sqlx::raw_sql(
        "CREATE TABLE test_claim_update_log (claim_id uuid NOT NULL); \
         CREATE FUNCTION test_log_claim_update() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN INSERT INTO test_claim_update_log (claim_id) VALUES (NEW.id); RETURN NULL; END $$; \
         CREATE TRIGGER zzz_test_log_claim_update AFTER UPDATE ON claims \
         FOR EACH ROW EXECUTE FUNCTION test_log_claim_update();",
    )
    .execute(pool)
    .await
    .expect("install the UPDATE counter");
    (ids[1], trace)
}

async fn updates_of(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM test_claim_update_log WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("count UPDATEs")
}

async fn stored(pool: &PgPool, claim: Uuid) -> (Option<Uuid>, serde_json::Value) {
    sqlx::query_as("SELECT trace_id, properties FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read stored trace and properties")
}

async fn patch(pool: &PgPool, claim: Uuid, input: &PatchClaimInput) -> epigraph_db::PatchClaimDiff {
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::patch_claim_atomic_conn(&mut conn, ClaimId::from_uuid(claim), input)
        .await
        .expect("patch succeeds")
}

/// The red: a patch of BOTH fields is one statement, and lands both.
#[sqlx::test(migrations = "../../migrations")]
async fn a_trace_and_properties_patch_is_one_update(pool: PgPool) {
    let (claim, trace) = seed(&pool).await;
    assert_eq!(
        updates_of(&pool, claim).await,
        0,
        "calibration: no UPDATE yet"
    );

    let diff = patch(
        &pool,
        claim,
        &PatchClaimInput {
            trace_id: Some(trace),
            properties: Some(serde_json::json!({"added": "x"})),
            add_labels: vec![],
            remove_labels: vec![],
        },
    )
    .await;

    assert_eq!(
        updates_of(&pool, claim).await,
        1,
        "trace_id and properties must be written by ONE UPDATE"
    );
    let merged = serde_json::json!({"keep": 1, "added": "x"});
    assert_eq!(stored(&pool, claim).await, (Some(trace), merged.clone()));
    assert_eq!((diff.before_trace, diff.after_trace), (None, Some(trace)));
    assert_eq!(diff.before_props, serde_json::json!({"keep": 1}));
    assert_eq!(diff.after_props, merged);
    assert_eq!(diff.before_labels, diff.after_labels);
}

/// Guards (not red): an empty patch writes nothing, and a one-field patch
/// leaves the other column's stored value exactly as it was.
#[sqlx::test(migrations = "../../migrations")]
async fn a_patch_writes_only_what_it_sets(pool: PgPool) {
    let (claim, trace) = seed(&pool).await;

    let none = PatchClaimInput {
        trace_id: None,
        properties: None,
        add_labels: vec![],
        remove_labels: vec![],
    };
    let diff = patch(&pool, claim, &none).await;
    assert_eq!(
        updates_of(&pool, claim).await,
        0,
        "an empty patch issues no UPDATE"
    );
    assert_eq!(
        stored(&pool, claim).await,
        (None, serde_json::json!({"keep": 1}))
    );
    assert_eq!((diff.before_trace, diff.after_trace), (None, None));

    let diff = patch(
        &pool,
        claim,
        &PatchClaimInput {
            trace_id: Some(trace),
            ..none.clone()
        },
    )
    .await;
    assert_eq!(updates_of(&pool, claim).await, 1);
    assert_eq!(
        stored(&pool, claim).await,
        (Some(trace), serde_json::json!({"keep": 1})),
        "a trace-only patch leaves properties untouched"
    );
    assert_eq!(diff.after_props, serde_json::json!({"keep": 1}));

    let diff = patch(
        &pool,
        claim,
        &PatchClaimInput {
            properties: Some(serde_json::json!({"keep": 2})),
            ..none.clone()
        },
    )
    .await;
    assert_eq!(updates_of(&pool, claim).await, 2);
    assert_eq!(
        stored(&pool, claim).await,
        (Some(trace), serde_json::json!({"keep": 2})),
        "a properties-only patch keeps the trace it does not name"
    );
    assert_eq!(
        (diff.before_trace, diff.after_trace),
        (Some(trace), Some(trace))
    );
}
