//! `AgentRepository::create_signer_conn` (backlog 9d4673a0): a process's own
//! signer is stored with the `agent_type` it declares, never migration 001's
//! `'human'` column default that `create_conn` leaves it on.
//!
//! Measured on the APPLICATION ROLE, because that is the role the MCP server's
//! pool writes as and the type cannot be repaired afterwards on it: migration
//! 118 grants `epigraph_app` UPDATE on the profile columns only. A calibration
//! pins that refusal, so the test fails if the type is ever "fixed" by a
//! follow-up UPDATE that would not run in production.

mod viewer_fixture;

use epigraph_core::Agent;
use epigraph_db::{AgentRepository, SignerAgentType};
use sqlx::PgPool;
use uuid::Uuid;

async fn agent_type(pool: &PgPool, id: Uuid) -> String {
    sqlx::query_scalar("SELECT agent_type::text FROM agents WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("agent_type")
}

async fn create_as_app(pool: &PgPool, agent: Agent, ty: Option<SignerAgentType>) -> Uuid {
    viewer_fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        let r = match ty {
            Some(ty) => AgentRepository::create_signer_conn(&mut conn, &agent, ty).await,
            None => AgentRepository::create_conn(&mut conn, &agent).await,
        };
        (conn, r)
    })
    .await
    .expect("the application role may create a signer row")
    .id
    .as_uuid()
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_signer_is_stored_with_its_declared_type_on_the_app_role(pool: PgPool) {
    // Calibration: the plain create leaves the column default, the defect.
    let plain = Agent::new([0x31u8; 32], Some("mcp-agent".to_string()));
    let plain_id = create_as_app(&pool, plain, None).await;
    assert_eq!(
        agent_type(&pool, plain_id).await,
        "human",
        "calibration: create_conn leaves migration 001's default"
    );

    let llm = Agent::new([0x32u8; 32], Some("mcp-agent".to_string()));
    let llm_id = create_as_app(&pool, llm, Some(SignerAgentType::Llm)).await;
    assert_eq!(agent_type(&pool, llm_id).await, "llm");

    let sw = Agent::new([0x33u8; 32], Some("mcp-agent".to_string()));
    let sw_id = create_as_app(&pool, sw, Some(SignerAgentType::SoftwareAgent)).await;
    assert_eq!(agent_type(&pool, sw_id).await, "software_agent");

    // The rest of the row and the registration event are create_conn's.
    let (name, kind): (Option<String>, String) =
        sqlx::query_as("SELECT display_name, key_kind::text FROM agents WHERE id = $1")
            .bind(llm_id)
            .fetch_one(&pool)
            .await
            .expect("row");
    assert_eq!(name.as_deref(), Some("mcp-agent"));
    assert_eq!(kind, "ed25519", "key_kind keeps its default");
    let events = |id: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM events WHERE event_type = 'agent.registered' \
                 AND payload->>'agent_id' = $1",
            )
            .bind(id.to_string())
            .fetch_one(&pool)
            .await
            .expect("events")
        }
    };
    assert_eq!(
        events(llm_id).await,
        events(plain_id).await,
        "agent.registered fires exactly as it does for create_conn"
    );

    // Calibration: the type cannot be corrected after the insert on this
    // role, which is why it is bound at INSERT.
    let refused = viewer_fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let r = sqlx::query("UPDATE agents SET agent_type = 'llm' WHERE id = $1")
            .bind(plain_id)
            .execute(&mut *conn)
            .await;
        (conn, r)
    })
    .await;
    let code = refused
        .expect_err("epigraph_app must not UPDATE agent_type (118)")
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(code, "42501", "insufficient_privilege");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_duplicate_signer_key_is_a_duplicate_key_error(pool: PgPool) {
    let first = Agent::new([0x34u8; 32], Some("mcp-agent".to_string()));
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::create_signer_conn(&mut conn, &first, SignerAgentType::Llm)
        .await
        .expect("first");
    let again = Agent::new([0x34u8; 32], Some("mcp-agent".to_string()));
    let err = AgentRepository::create_signer_conn(&mut conn, &again, SignerAgentType::Llm)
        .await
        .expect_err("same key twice");
    assert!(
        matches!(err, epigraph_db::DbError::DuplicateKey { .. }),
        "got {err:?}"
    );
}
