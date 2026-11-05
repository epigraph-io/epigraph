//! MCP `get_claim` carries the same `authored_by` block as
//! `GET /api/v1/claims/:id` (backlog 48421526), computed on the caller's
//! viewer-stamped connection.
//!
//! Both of the server's pools are downgraded to `epigraph_app` (the shape of
//! `retract_bba_app_role.rs`), so the snapshot gate and the edge's row
//! security decide as in production. Fixtures are seeded, and viewers
//! resolved, on the harness superuser pool. The snapshot's audience is the
//! one constant `epigraph_db::PROMPT_SNAPSHOT_AUDIENCE`; the assertions follow
//! whichever setting is live.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::visibility::Viewer;
use epigraph_db::{
    AgentIdentityRepository, AgentRepository, IdentityRegistration, PromptFile,
    PromptSnapshotAudience, ScopedPool, SessionGucMode, PROMPT_SNAPSHOT_AUDIENCE,
};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::claims::get_claim;
use epigraph_mcp::types::GetClaimParams;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    build_scoped_test_server(plain, scoped)
}

fn random32() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    out
}

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let out = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_operator(&mut conn, agent, operator).await;
        (conn, r)
    })
    .await
    .expect("the maintenance role links the agent");
    assert!(out.link_live, "CALIBRATION: the manual link is live");
}

async fn read(server: &EpiGraphMcpFull, pool: &PgPool, caller: Uuid, claim: Uuid) -> Value {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve");
    let out = get_claim(
        server,
        &viewer,
        GetClaimParams {
            claim_id: claim.to_string(),
            frame_id: None,
            perspective_id: None,
        },
    )
    .await
    .expect("get_claim");
    first_text(&out)
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_claim_names_the_agent_the_human_and_the_snapshot_by_audience(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (operator, _) = fixture::seed_agent_with_group(&pool, "operator").await;
    fixture::make_human_operator(&pool, operator).await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;

    let pubkey = random32();
    let reg = IdentityRegistration {
        identity_pubkey: pubkey,
        parent_agent_id: None,
        model: "test-model-9".to_string(),
        prompt_hash: blake3::hash(&pubkey).to_hex().to_string(),
        group_folder: "g-mcp-authored".to_string(),
        signing_pubkey: Some(random32()),
        identity_md: PromptFile::Absent,
        global_claude_md: PromptFile::Absent,
        group_claude_md: PromptFile::Absent,
        learned_md: PromptFile::Absent,
        in_prompt: json!({}),
        runner_version: None,
        host_sha: None,
    };
    let reg_out = fixture::as_role(&pool, "epigraph_identity_attestor", |mut conn| async move {
        let r = AgentIdentityRepository::register(&mut conn, &reg).await;
        (conn, r)
    })
    .await
    .expect("the attestor registers");
    let agent = reg_out.agent_id;
    link(&pool, agent, operator).await;
    let claim = fixture::seed_public_claim(&pool, agent, "mcp authored-by claim").await;

    let mine = read(&server, &pool, operator, claim).await;
    let block = &mine["authored_by"];
    assert_eq!(block["agent"]["id"], json!(agent), "{mine}");
    assert_eq!(block["human"]["id"], json!(operator), "{mine}");
    assert_eq!(
        block["prompt_snapshot"]["snapshot_id"],
        json!(reg_out.snapshot_id),
        "the agent's human sees the snapshot: {mine}"
    );
    assert_eq!(block["prompt_snapshot"]["model"], json!("test-model-9"));

    let theirs = read(&server, &pool, stranger, claim).await;
    let theirs = &theirs["authored_by"];
    assert_eq!(theirs["human"], block["human"], "the link edge is public");
    match PROMPT_SNAPSHOT_AUDIENCE {
        PromptSnapshotAudience::OperatorAndAdmins => assert_eq!(
            theirs["prompt_snapshot"],
            Value::Null,
            "gated: a stranger does not see the snapshot"
        ),
        PromptSnapshotAudience::ClaimReaders => {
            assert_eq!(theirs["prompt_snapshot"], block["prompt_snapshot"]);
        }
    }
}
