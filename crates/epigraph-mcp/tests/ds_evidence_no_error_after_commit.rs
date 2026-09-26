//! F3 (`15c00c7a`): `submit_ds_evidence` must never return an error for data it
//! has already committed.
//!
//! The tool's contract (its `#[tool(description)]`): "a refusal … writes
//! nothing". It used to read the returned belief back AFTER `tx.commit()`, on
//! `server.pool`, so any failure of that read — the claim invisible to the
//! request viewer, or invisible to the pool's unstamped connection — turned a
//! committed frame assignment + BBA + recomputed belief into an error response.
//! A caller told "error" retries, or reports the evidence as not submitted,
//! while the belief has already moved.
//!
//! Every arm asserts the one invariant rather than one outcome: EITHER the call
//! succeeded and the BBA it reports is in the database, OR it failed and nothing
//! was written. Error-with-commit is the only failing shape.
//!
//! # The two ways the post-commit read failed
//!
//! * **The production window** ([`an_own_group_claim_on_an_app_role_pool_is_not_error_with_commit`]).
//!   The write transaction is stamped from the server agent, but the readback ran
//!   on `server.pool`: an UNSTAMPED `epigraph_app` connection in production,
//!   where `claims_tenancy` hides every `group`-visibility row. So a BBA against
//!   the server agent's OWN group-private claim committed and then answered
//!   "claim not found". Reproduced here by giving the server a pool
//!   `SET SESSION AUTHORIZATION epigraph_app` (a non-bypassing role) while the
//!   `ScopedPool` that opens the write transaction stays as-is.
//! * **A request viewer that cannot read the claim**
//!   ([`a_caller_who_cannot_read_the_claim_gets_error_with_nothing_written`]).
//!   On HTTP the request viewer is the caller's, not the server agent's, and the
//!   readback splices the caller's predicate.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::tools::ds_auto::ensure_binary_frame;
use epigraph_mcp::types::SubmitDsEvidenceParams;
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use sqlx::PgPool;
use uuid::Uuid;

const SEED: [u8; 32] = [0x3Fu8; 32];

fn server_on(pool: PgPool, scoped: epigraph_db::ScopedPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&SEED).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

fn params(claim_id: Uuid, frame_id: Uuid) -> SubmitDsEvidenceParams {
    SubmitDsEvidenceParams {
        claim_id: claim_id.to_string(),
        frame_id: frame_id.to_string(),
        hypothesis_index: 0,
        masses: serde_json::json!({"0": 0.8, "~": 0.2}),
        reliability: None,
        combination_method: None,
        gamma: None,
        perspective_id: None,
        evidence_type: None,
        locality_tag: None,
    }
}

async fn bbas_for(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn frame_rows_for(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claim_frames WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The server agent (provisioned on the superuser pool), its personal group, a
/// GROUP-visibility claim that group owns, and the binary frame.
async fn plant(pool: &PgPool, scoped: &epigraph_db::ScopedPool) -> (Uuid, Uuid, Uuid) {
    let agent = server_on(pool.clone(), scoped.clone())
        .server_agent_id()
        .await
        .expect("server agent");
    let personal: Uuid = sqlx::query_scalar(
        "SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:' || $1::text",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("personal group");
    let claim = fixture::seed_group_claim(
        pool,
        agent,
        personal,
        &format!("f3 group-private claim {}", Uuid::new_v4()),
    )
    .await;
    let frame = ensure_binary_frame(
        &mut pool.acquire().await.expect("acquire"),
        &fixture::public_viewer(pool).await,
    )
    .await
    .expect("binary frame");
    (agent, claim, frame)
}

/// The invariant: success with the reported BBA stored, or failure with nothing
/// stored.
async fn assert_no_error_with_commit(
    pool: &PgPool,
    claim: Uuid,
    res: &Result<rmcp::model::CallToolResult, rmcp::model::ErrorData>,
) {
    let bbas = bbas_for(pool, claim).await;
    let frames = frame_rows_for(pool, claim).await;
    match res {
        Ok(_) => assert_eq!(bbas, 1, "a success must have stored exactly its BBA"),
        Err(e) => assert!(
            bbas == 0 && frames == 0,
            "ERROR WITH COMMIT: the call returned an error ({}) but {bbas} BBA row(s) and \
             {frames} claim_frames row(s) were committed",
            e.message
        ),
    }
}

/// The production window: the server's own group-private claim, the server's
/// own viewer, and a server `pool` on the non-bypassing `epigraph_app` role.
#[sqlx::test(migrations = "../../migrations")]
async fn an_own_group_claim_on_an_app_role_pool_is_not_error_with_commit(pool: PgPool) {
    let scoped = fixture::scoped_pool(&pool).await;
    let (agent, claim, frame) = plant(&pool, &scoped).await;

    let app_pool = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let server = server_on(app_pool, scoped);
    // The stdio request viewer: the server agent's own.
    let viewer = epigraph_db::Viewer::resolve(&pool, agent)
        .await
        .expect("viewer");

    let res = tools::ds::submit_ds_evidence(&server, &viewer, params(claim, frame), None).await;
    assert_no_error_with_commit(&pool, claim, &res).await;
    // The agent owns the claim and can read it, so this one must SUCCEED: a
    // refusal here would be the old post-commit read's false "not found".
    assert!(
        res.is_ok(),
        "the owner's own evidence must be accepted, got {res:?}"
    );
}

/// A request viewer that cannot read the claim (the nil principal: public
/// rows only). The write is authorised by the server agent's stamp, so the
/// only thing that can refuse is the readback — and it must refuse BEFORE the
/// commit.
#[sqlx::test(migrations = "../../migrations")]
async fn a_caller_who_cannot_read_the_claim_gets_error_with_nothing_written(pool: PgPool) {
    let scoped = fixture::scoped_pool(&pool).await;
    let (_agent, claim, frame) = plant(&pool, &scoped).await;

    let server = server_on(pool.clone(), scoped);
    let viewer = fixture::public_viewer(&pool).await;

    let res = tools::ds::submit_ds_evidence(&server, &viewer, params(claim, frame), None).await;
    assert_no_error_with_commit(&pool, claim, &res).await;
}
