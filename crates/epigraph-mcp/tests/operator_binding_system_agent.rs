//! Operator binding (migration 122) and workflow writes, once armed.
//!
//! Workflow writes used to be authored by ONE shared `workflow-ingest-system`
//! agent, with the caller bound to that agent's human, so a caller of ANOTHER
//! human was refused OPL02 outright. They are now authored by, and stamped
//! from, the CALLER itself (`claim_helper::begin_caller_workflow_tx`), so the
//! database's own operator binding applies to the real writer: an unbound
//! caller is refused (OPL01) whether or not the system agent is linked; a
//! caller of another human writes into ITS OWN operator's group, never into
//! this human's; a caller bound to this human writes into this human's group,
//! as itself.
//!
//! Both server pools are downgraded to `epigraph_app` (a superuser pool proves
//! nothing about row security); links and arming run on the harness pool, the
//! maintenance connection's stand-in.
//!
//! Verified to fail: `default_decl_for_author`'s acting-link branch removed ->
//! the step claim lands in the caller's own group and the owner assertion
//! fails; `tools::evolve_step` back on
//! `ClaimRepository::evolve_step(&server.pool, ..)` (unstamped) -> the bound
//! caller's evolve is refused OPL01 once armed.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::types::StoreWorkflowParams;
use sqlx::PgPool;
use uuid::Uuid;

/// An app-role stdio server whose own agent (the CALLER of every tool) is the
/// one keyed by `seed`.
async fn app_role_server(pool: &PgPool, seed: u8) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let embedder =
        epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(plain, signer, embedder, /* read_only */ false).with_scoped_pool(scoped)
}

/// The agent row the server keyed by `seed` authors as (created by its first
/// tool call).
async fn caller_of(pool: &PgPool, seed: u8) -> Uuid {
    let key = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32])
        .expect("signer")
        .public_key();
    sqlx::query_scalar("SELECT id FROM agents WHERE public_key = $1")
        .bind(key.as_slice())
        .fetch_one(pool)
        .await
        .expect("the caller's agent row")
}

async fn claims_with(pool: &PgPool, content: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .expect("count")
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
    let (other_human, _) = fixture::seed_human_operator(&pool, "other-human").await;
    let system = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_ingest_executor::get_or_create_system_agent(&mut conn)
            .await
            .expect("system agent")
    };
    // Migration 148: registered before arming, as the deploy order does.
    assert!(fixture::register_system_agent(&pool, system).await);
    let server = app_role_server(&pool, 0xA7).await;
    let other = app_role_server(&pool, 0xB7).await;

    // Armed, system agent unlinked: the ingest is refused by name.
    sqlx::query("INSERT INTO operator_binding_arming DEFAULT VALUES")
        .execute(&pool)
        .await
        .expect("arm (the harness stands in for the maintenance role)");
    let refused = store(&server, &format!("refused step {}", Uuid::new_v4()))
        .await
        .expect_err("an unlinked system agent must be refused once armed");
    assert!(refused.contains("OPL01"), "{refused}");
    let _ = store(&other, &format!("refused step {}", Uuid::new_v4())).await;

    // The host's step 3: live-link the system agent to the human.
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, system, human)
            .await
            .expect("live link");
    }

    // The system agent is bound now, but the CALLER is not, and the caller is
    // the author: refused.
    let caller = caller_of(&pool, 0xA7).await;
    let unbound_step = format!("unbound caller step {}", Uuid::new_v4());
    let refused = store(&server, &unbound_step)
        .await
        .expect_err("an unbound caller must not write through the bound system agent");
    assert!(
        refused.contains("OPL01") && refused.contains(&caller.to_string()),
        "the refusal names the unbound caller: {refused}"
    );
    assert_eq!(claims_with(&pool, &unbound_step).await, 0);

    // A caller of ANOTHER human cannot reach this human's group through it.
    let other_caller = caller_of(&pool, 0xB7).await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, other_caller, other_human)
            .await
            .expect("the other caller's live link");
    }
    let other_group: Uuid = sqlx::query_scalar(
        "SELECT g.id FROM groups g WHERE g.did_key = 'did:epigraph:personal:' || $1::text",
    )
    .bind(other_human)
    .fetch_one(&pool)
    .await
    .expect("the other human's group");
    let foreign_step = format!("other human's caller step {}", Uuid::new_v4());
    store(&other, &foreign_step)
        .await
        .expect("another human's caller writes, as itself, into its own operator's group");
    let (author, owner): (Uuid, Uuid) =
        sqlx::query_as("SELECT agent_id, owner_group_id FROM claims WHERE content = $1")
            .bind(&foreign_step)
            .fetch_one(&pool)
            .await
            .expect("the other caller's step claim");
    assert_eq!(author, other_caller, "authored by the other human's caller");
    assert_eq!(
        owner, other_group,
        "owned by the other human's group, never by this human's"
    );
    assert_ne!(owner, human_group);

    // A caller bound to THIS human writes, into the operator's group.
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, caller, human)
            .await
            .expect("the caller's live link");
    }
    let step = format!("bound step {}", Uuid::new_v4());
    store(&server, &step)
        .await
        .expect("a bound caller writes, as itself, on the app role");
    let (author, owner): (Uuid, Uuid) =
        sqlx::query_as("SELECT agent_id, owner_group_id FROM claims WHERE content = $1")
            .bind(&step)
            .fetch_one(&pool)
            .await
            .expect("step claim");
    assert_eq!(author, caller, "the executor authors as the caller");
    assert_ne!(author, system, "not as the shared system agent");
    assert_eq!(
        owner, human_group,
        "a live-linked caller's claims belong to its operator"
    );

    // Delta review (the no-principal rule): `evolve_step` writes its step claim
    // on a transaction stamped with its author, so the bound caller can still
    // evolve the step once armed. On the raw pool (no principal) the database
    // refuses the write (OPL01), which is what it did before the conversion.
    let parent: Uuid = sqlx::query_scalar("SELECT id FROM claims WHERE content = $1")
        .bind(&step)
        .fetch_one(&pool)
        .await
        .expect("the step to evolve");
    let evolved = format!("evolved bound step {}", Uuid::new_v4());
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&server, None)
        .await
        .expect("stdio viewer");
    epigraph_mcp::tools::evolve_step::evolve_step(
        &server,
        &viewer,
        epigraph_mcp::tools::evolve_step::EvolveStepParams {
            parent_id: parent.to_string(),
            canonical_name: None,
            step_index: None,
            step_lineage_id: String::new(),
            content: evolved.clone(),
            edge_type: "revises".to_string(),
            rationale: Some("operator binding probe".to_string()),
            level: None,
        },
        None,
    )
    .await
    .map_err(|e| e.message.to_string())
    .expect("a bound caller evolves a step on the app role once armed");
    let (author, owner): (Uuid, Uuid) =
        sqlx::query_as("SELECT agent_id, owner_group_id FROM claims WHERE content = $1")
            .bind(&evolved)
            .fetch_one(&pool)
            .await
            .expect("evolved step claim");
    assert_eq!(author, caller, "the evolved step is the caller's");
    assert_eq!(owner, human_group, "it inherits the parent's owner");
}
