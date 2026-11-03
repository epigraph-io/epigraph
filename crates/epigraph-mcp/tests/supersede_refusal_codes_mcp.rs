//! SPEC §7.1 (SF-18b) and §11 phase 1 S-1 test (l), MCP half: a
//! supersede-architecture refusal code (`epigraph_db::SUPERSEDE_REFUSAL_CODES`;
//! migration 194 introduces `SR09`) passed to `errors::db_caller_error` is a
//! caller error (`INVALID_REQUEST`) carrying its code. Without its arm the
//! coded text still reached the caller through `internal_error`, but as
//! `INTERNAL_ERROR` (-32603), which a client treats as a server fault.
//!
//! MAPPER pin only: after K4a no MCP tool deletes a retracted mass function,
//! so no tool is expected to reach SR09. The refusal is the real one, raised by
//! migration 194's guard on a maintenance-role DELETE of a retracted row (made
//! by migration 184's definer). Fail closed: an unlisted code of the same
//! shape (`SR99`) stays `INTERNAL_ERROR`.

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "../../epigraph-db/tests/support/retracted_bba_fixture.rs"]
mod retracted;

use epigraph_db::MassFunctionRepository;
use epigraph_mcp::errors::db_caller_error;
use rmcp::model::ErrorCode;
use sqlx::PgPool;
use uuid::Uuid;

async fn sr09_refusal(pool: &PgPool) -> (Uuid, sqlx::Error) {
    let (agent, group) = fixture::seed_agent_with_group(pool, "sr09-mcp").await;
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("sr09-mcp-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed frame");
    let claim = fixture::seed_group_claim(pool, agent, group, "sr09 mapper claim").await;
    let bba = MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        None,
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        None,
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("store a BBA");
    retracted::retract_through_definer(pool, bba).await;
    let maintenance = fixture::downgraded_pool(pool, "epigraph_maintenance").await;
    let e = sqlx::query("DELETE FROM mass_functions WHERE id = $1")
        .bind(bba)
        .execute(&maintenance)
        .await
        .expect_err("migration 194 refuses the delete of a retracted mass function");
    (bba, e)
}

#[sqlx::test(migrations = "../../migrations")]
async fn db_caller_error_maps_sr09_to_invalid_request_with_its_code(pool: PgPool) {
    let (bba, e) = sr09_refusal(&pool).await;
    let mcp = db_caller_error(epigraph_db::DbError::from(e));
    assert_eq!(
        mcp.code,
        ErrorCode::INVALID_REQUEST,
        "SR09 is a caller-class denial, not an internal error: {mcp:?}"
    );
    assert!(
        mcp.message.starts_with("SR09: ") && mcp.message.contains("epigraph_purge_mass_functions"),
        "the database's coded message, as written: {:?}",
        mcp.message
    );
    assert!(
        !mcp.message.contains(&bba.to_string()),
        "the row id stays in DETAIL: {:?}",
        mcp.message
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn db_caller_error_keeps_an_unlisted_sr_code_internal(pool: PgPool) {
    let e = sqlx::query(
        "DO $$ BEGIN RAISE EXCEPTION 'SR99: an unlisted refusal of the supersede shape' \
         USING ERRCODE = '42501'; END $$",
    )
    .execute(&pool)
    .await
    .expect_err("the DO block raises");
    let mcp = db_caller_error(epigraph_db::DbError::from(e));
    assert_eq!(mcp.code, ErrorCode::INTERNAL_ERROR, "{mcp:?}");
}
