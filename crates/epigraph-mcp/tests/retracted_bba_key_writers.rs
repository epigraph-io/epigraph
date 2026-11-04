//! Operator ruling R-103 on the MCP writers: a retracted BBA HOLDS its upsert
//! key `(claim, frame, source agent, perspective)`. Re-writing that key, by
//! the owner or by an automated writer, is refused (RT07, migration 184) and
//! changes nothing; a retracted BBA becomes live again only through the
//! explicit, audited un-retract.
//!
//! One test per MCP writer path that upserts a BBA key a retracted row can
//! hold:
//! * `submit_ds_evidence` (the caller names the key): the tool answers an
//!   error coded RT07, on the application role;
//! * the ingest batch writer (`ds_auto::auto_wire_ds_batch`, used by
//!   `ingest_document` and workflow ingest): a best-effort loop, so the
//!   retracted entry is skipped (not counted as wired) and the rest wire;
//! * the evidence-update writer (`ds_auto::auto_wire_ds_update`, used by
//!   `update_with_evidence` and `report_workflow_outcome`): its truth-value
//!   seed is keyed on the claim's author; a retracted seed is NOT re-seeded,
//!   so the evidence lands and the retracted row is untouched.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::bba_retract::{retract_bba, RetractBbaParams};
use epigraph_mcp::tools::ds_auto::{
    auto_wire_ds_batch, auto_wire_ds_update, ensure_binary_frame, BatchDsEntry,
};
use epigraph_mcp::types::SubmitDsEvidenceParams;
use sqlx::PgPool;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
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
    build_scoped_test_server(plain, scoped)
}

async fn owned_public_claim(pool: &PgPool, agent: Uuid, group: Uuid, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("r103 mcp claim {tag} {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// `(masses, created_at, retracted_at IS NOT NULL)` of one row.
async fn row_state(
    pool: &PgPool,
    id: Uuid,
) -> (serde_json::Value, chrono::DateTime<chrono::Utc>, bool) {
    sqlx::query_as(
        "SELECT masses, created_at, retracted_at IS NOT NULL FROM mass_functions WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("read mass function {id}: {e}"))
}

/// Mark `id` retracted on the harness connection (a privileged session, which
/// migration 184's marking guard admits), standing in for an earlier
/// retraction.
async fn mark_retracted(pool: &PgPool, id: Uuid) {
    sqlx::query(
        "UPDATE mass_functions \
            SET retracted_at = now(), retracted_by = $2, retract_reason = 'r103 fixture' \
          WHERE id = $1",
    )
    .bind(id)
    .bind(Uuid::new_v4())
    .execute(pool)
    .await
    .expect("mark retracted");
}

async fn unretract_audits(pool: &PgPool, id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM security_events \
          WHERE event_type = 'mass_functions.unretract' \
            AND details->>'mass_function_id' = $1::text",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("count unretract audits")
}

async fn cache_of(pool: &PgPool, claim: Uuid) -> (Option<f64>, Option<f64>, Option<f64>) {
    sqlx::query_as("SELECT belief, plausibility, pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read the cache")
}

/// Rows of `claim` at `(frame, agent, perspective)`, with their ids.
async fn rows_at_key(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    agent: Uuid,
    perspective: Option<Uuid>,
) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT id FROM mass_functions \
          WHERE claim_id = $1 AND frame_id = $2 AND source_agent_id = $3 \
            AND perspective_id IS NOT DISTINCT FROM $4",
    )
    .bind(claim)
    .bind(frame)
    .bind(agent)
    .bind(perspective)
    .fetch_all(pool)
    .await
    .expect("rows at key")
}

async fn submit(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    auth: &epigraph_auth::AuthContext,
    claim: Uuid,
    frame: Uuid,
    perspective: Uuid,
    masses: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let params: SubmitDsEvidenceParams = serde_json::from_value(serde_json::json!({
        "claim_id": claim.to_string(),
        "frame_id": frame.to_string(),
        "hypothesis_index": 0,
        "masses": masses,
        "perspective_id": perspective.to_string(),
    }))
    .expect("params");
    epigraph_mcp::tools::ds::submit_ds_evidence(server, viewer, params, Some(auth))
        .await
        .map(|r| first_text(&r))
        .map_err(|e| e.message.to_string())
}

/// `submit_ds_evidence` to the key of a BBA its owner retracted (over MCP
/// `retract_bba`) is refused with an error coded RT07 that names the row, and
/// changes nothing: the row keeps its retraction, masses and `created_at`,
/// the claim's cache is what the retraction left, and nothing is
/// un-retracted. Driven on the application role.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_ds_evidence_to_a_retracted_key_is_refused_and_changes_nothing(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (owner, auth, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let group = personal_group_of(&pool, owner).await;
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("r103-mcp-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed frame");
    let claim = owned_public_claim(&pool, owner, group, "submit").await;
    let perspective: Uuid = sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(format!("r103-mcp-{}", Uuid::new_v4()))
    .bind(owner)
    .fetch_one(&pool)
    .await
    .expect("seed perspective");

    let first = submit(
        &server,
        &viewer,
        &auth,
        claim,
        frame,
        perspective,
        serde_json::json!({"0": 0.9, "0,1": 0.1}),
    )
    .await
    .expect("CALIBRATION: the first submission lands");
    let id: Uuid = first["mass_function_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("mass_function_id in {first}"));
    retract_bba(
        &server,
        &viewer,
        RetractBbaParams {
            mass_function_id: id.to_string(),
            reason: "duplicate re-observation".to_string(),
        },
        Some(&auth),
    )
    .await
    .expect("the owner retracts its BBA");
    let row_before = row_state(&pool, id).await;
    let cache_before = cache_of(&pool, claim).await;

    let again = submit(
        &server,
        &viewer,
        &auth,
        claim,
        frame,
        perspective,
        serde_json::json!({"0": 0.4, "0,1": 0.6}),
    )
    .await;
    let message = again.expect_err("a write to a retracted key is refused");
    assert!(message.starts_with("RT07: "), "coded RT07: {message}");
    assert!(
        message.contains(&id.to_string()),
        "names the row: {message}"
    );

    assert_eq!(row_state(&pool, id).await, row_before, "nothing changed");
    assert!(row_before.2, "still retracted");
    assert_eq!(row_before.0["0"], 0.9, "the retracted masses");
    assert_eq!(cache_of(&pool, claim).await, cache_before);
    assert_eq!(unretract_audits(&pool, id).await, 0);
    assert_eq!(
        rows_at_key(&pool, claim, frame, owner, Some(perspective)).await,
        vec![id],
        "no second row beside the retracted one"
    );
}

fn entry(claim: Uuid, confidence: f64) -> BatchDsEntry {
    BatchDsEntry {
        claim_id: claim,
        confidence,
        weight: 0.8,
        evidence_type: Some("empirical".to_string()),
        axis: None,
    }
}

/// The ingest batch writer re-ingesting a claim whose BBA (keyed on the
/// ingesting agent, no perspective) was retracted: that entry is refused and
/// skipped, as the loop skips any failing entry, so it is not counted as
/// wired; the retracted row is untouched and no second row appears beside
/// it; a fresh claim in the same batch is wired.
#[sqlx::test(migrations = "../../migrations")]
async fn the_ingest_batch_skips_a_retracted_key_and_wires_the_rest(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let held = seed_claim(&pool, &format!("r103 ingest held {}", Uuid::new_v4()), 0.5).await;
    let fresh = seed_claim(&pool, &format!("r103 ingest fresh {}", Uuid::new_v4()), 0.5).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let frame = ensure_binary_frame(&mut conn, &viewer)
        .await
        .expect("binary frame");

    let (_, first) = auto_wire_ds_batch(&mut conn, &viewer, &[entry(held, 0.9)], agent)
        .await
        .expect("first ingest");
    assert_eq!(first, 1, "CALIBRATION: the first ingest wires the claim");
    let at_key = rows_at_key(&pool, held, frame, agent, None).await;
    assert_eq!(at_key.len(), 1, "{at_key:?}");
    let id = at_key[0];
    mark_retracted(&pool, id).await;
    let before = row_state(&pool, id).await;

    let (_, wired) = auto_wire_ds_batch(
        &mut conn,
        &viewer,
        &[entry(held, 0.6), entry(fresh, 0.6)],
        agent,
    )
    .await
    .expect("the batch runs");
    assert_eq!(wired, 1, "only the fresh claim is wired");
    assert_eq!(
        row_state(&pool, id).await,
        before,
        "the retracted row is untouched"
    );
    assert!(before.2);
    assert_eq!(rows_at_key(&pool, held, frame, agent, None).await, vec![id]);
    assert_eq!(rows_at_key(&pool, fresh, frame, agent, None).await.len(), 1);
    assert_eq!(unretract_audits(&pool, id).await, 0);
}

/// The evidence-update writer seeds a claim's authored `truth_value` as a BBA
/// keyed on the claim's AUTHOR when the claim has no live binary BBA. Once
/// that seed (and every other binary BBA) is retracted, a later update must
/// not re-seed onto the retracted seed's key: the evidence lands on its own
/// key, and the retracted seed keeps its retraction, masses and
/// `created_at`.
#[sqlx::test(migrations = "../../migrations")]
async fn an_evidence_update_does_not_reseed_over_a_retracted_seed(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim = seed_claim(&pool, &format!("r103 seed {}", Uuid::new_v4()), 0.85).await;
    let first_agent = seed_agent(&pool).await;
    let later_agent = seed_agent(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let frame = ensure_binary_frame(&mut conn, &viewer)
        .await
        .expect("binary frame");

    auto_wire_ds_update(
        &mut conn,
        &viewer,
        claim,
        first_agent,
        0.6,
        1.0,
        true,
        Some("empirical"),
        None,
        true,
    )
    .await
    .expect("the first update seeds and lands");
    let seed: Uuid = sqlx::query_scalar(
        "SELECT id FROM mass_functions \
          WHERE claim_id = $1 AND combination_method = 'truth_value_seed'",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("CALIBRATION: the first update wrote a seed");
    let first_rows = rows_at_key(&pool, claim, frame, first_agent, None).await;
    assert_eq!(first_rows.len(), 1, "{first_rows:?}");
    mark_retracted(&pool, seed).await;
    mark_retracted(&pool, first_rows[0]).await;
    let seed_before = row_state(&pool, seed).await;

    let res = auto_wire_ds_update(
        &mut conn,
        &viewer,
        claim,
        later_agent,
        0.6,
        1.0,
        true,
        Some("empirical"),
        None,
        true,
    )
    .await;
    res.expect("the later evidence lands");
    assert_eq!(
        row_state(&pool, seed).await,
        seed_before,
        "the retracted seed is not re-seeded"
    );
    assert!(seed_before.2);
    assert_eq!(
        rows_at_key(&pool, claim, frame, later_agent, None)
            .await
            .len(),
        1,
        "the later evidence is stored on its own key"
    );
    assert_eq!(unretract_audits(&pool, seed).await, 0);
}
