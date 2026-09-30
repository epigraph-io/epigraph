//! Operator binding (migration 122) and the `workflow-ingest-system` agent.
//!
//! The workflow executor authors every workflow and step claim as ONE system
//! agent, stamped from that agent's own viewer. It is not a human, so once a
//! database is armed its writes are refused unless it holds a LIVE link; the
//! deploy order live-links it before arming. This pins that the live link is
//! enough on the application role: `store_workflow` then succeeds, and the
//! claims it writes are owned by the OPERATOR's group (the linked system agent
//! holds `writer` there, so the stamped transaction can write it).
//!
//! Both server pools are downgraded to `epigraph_app` (a superuser pool proves
//! nothing about row security); links and arming run on the harness pool, the
//! maintenance connection's stand-in.
//!
//! Verified to fail: `default_decl_for_author`'s acting-link branch removed ->
//! the step claim lands in the system agent's own group and the owner
//! assertion fails.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::types::StoreWorkflowParams;
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

async fn store(server: &EpiGraphMcpFull, step: &str) -> Result<(), String> {
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("stdio viewer");
    epigraph_mcp::tools::workflows::store_workflow(
        server,
        &viewer,
        StoreWorkflowParams {
            goal: format!("operator binding goal {}", Uuid::new_v4()),
            steps: vec![step.to_string()],
            prerequisites: None,
            expected_outcome: None,
            confidence: None,
            tags: None,
        },
        None,
    )
    .await
    .map(|_| ())
    .map_err(|e| e.message.to_string())
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_live_linked_system_agent_keeps_workflow_ingest_working_once_armed(pool: PgPool) {
    let (human, human_group) = fixture::seed_human_operator(&pool, "human").await;
    let system = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_ingest_executor::get_or_create_system_agent(&mut conn)
            .await
            .expect("system agent")
    };
    let server = app_role_server(&pool).await;

    // Armed, system agent unlinked: the ingest is refused by name.
    sqlx::query("INSERT INTO operator_binding_arming DEFAULT VALUES")
        .execute(&pool)
        .await
        .expect("arm (the harness stands in for the maintenance role)");
    let refused = store(&server, &format!("refused step {}", Uuid::new_v4()))
        .await
        .expect_err("an unlinked system agent must be refused once armed");
    assert!(refused.contains("OPL01"), "{refused}");

    // The host's step 3: live-link the system agent to the human.
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, system, human)
            .await
            .expect("live link");
    }
    let step = format!("bound step {}", Uuid::new_v4());
    store(&server, &step)
        .await
        .expect("a live-linked system agent writes on the app role");
    let (author, owner): (Uuid, Uuid) =
        sqlx::query_as("SELECT agent_id, owner_group_id FROM claims WHERE content = $1")
            .bind(&step)
            .fetch_one(&pool)
            .await
            .expect("step claim");
    assert_eq!(
        author, system,
        "the executor still authors as the system agent"
    );
    assert_eq!(
        owner, human_group,
        "a live-linked system agent's claims belong to its operator"
    );
}
