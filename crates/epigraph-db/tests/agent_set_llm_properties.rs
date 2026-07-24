//! `AgentRepository::set_llm_properties` integration tests.
//!
//! Covers blueprint §2: the `properties || $2::jsonb` MERGE must
//!   * write `llm_model`, `llm_prompt_hash`, and `source = "mcp-llm-agent"`,
//!   * PRESERVE a pre-existing, unrelated `properties` key (no clobber),
//!   * be idempotent on re-run with identical arguments,
//!   * overwrite a stale `llm_model` on re-run with a new value,
//!   * return `DbError::NotFound` for an unknown agent id.
//!
//! All tests run against `epigraph_db_repo_test` via `#[sqlx::test]`.

mod helpers;

use epigraph_db::{AgentRepository, DbError, PgPool};
use helpers::make_agent;
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// Read the raw `properties` JSONB for an agent (bypasses the repo layer so
/// the assertion checks what is actually persisted, not a round-tripped view).
async fn read_properties(pool: &PgPool, id: Uuid) -> JsonValue {
    sqlx::query_scalar::<_, JsonValue>("SELECT properties FROM agents WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read properties")
}

#[sqlx::test(migrations = "../../migrations")]
async fn merges_without_clobbering_existing_key(pool: PgPool) {
    let agent = make_agent(Some("llm-merge"));
    let created = AgentRepository::create(&pool, &agent).await.unwrap();
    let id: Uuid = created.id.into();

    // Seed a pre-existing, unrelated property directly (as e.g. did_key set
    // at registration would appear). This is the survivor under test.
    sqlx::query("UPDATE agents SET properties = properties || $2::jsonb WHERE id = $1")
        .bind(id)
        .bind(serde_json::json!({"did_key": "did:key:zPreExisting"}))
        .execute(&pool)
        .await
        .expect("seed pre-existing property");

    AgentRepository::set_llm_properties(&pool, id, "opus-4-8", "abc123hash")
        .await
        .expect("set_llm_properties");

    let props = read_properties(&pool, id).await;

    // The three LLM keys are present with the expected values.
    assert_eq!(props["llm_model"], "opus-4-8", "llm_model must be set");
    assert_eq!(
        props["llm_prompt_hash"], "abc123hash",
        "llm_prompt_hash must be set"
    );
    assert_eq!(
        props["source"], "mcp-llm-agent",
        "source must be the mcp-llm-agent marker"
    );

    // The pre-existing key MUST survive the merge (|| does not clobber).
    assert_eq!(
        props["did_key"], "did:key:zPreExisting",
        "MERGE must preserve the pre-existing did_key, got {props}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn idempotent_on_identical_rerun(pool: PgPool) {
    let agent = make_agent(Some("llm-idem"));
    let created = AgentRepository::create(&pool, &agent).await.unwrap();
    let id: Uuid = created.id.into();

    AgentRepository::set_llm_properties(&pool, id, "opus-4-8", "hashA")
        .await
        .expect("first write");
    let after_first = read_properties(&pool, id).await;

    AgentRepository::set_llm_properties(&pool, id, "opus-4-8", "hashA")
        .await
        .expect("second write");
    let after_second = read_properties(&pool, id).await;

    assert_eq!(
        after_first, after_second,
        "re-running with identical args must leave properties unchanged"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn rerun_with_new_values_overwrites_llm_keys(pool: PgPool) {
    let agent = make_agent(Some("llm-overwrite"));
    let created = AgentRepository::create(&pool, &agent).await.unwrap();
    let id: Uuid = created.id.into();

    AgentRepository::set_llm_properties(&pool, id, "opus-4-8", "hashOld")
        .await
        .expect("first write");
    AgentRepository::set_llm_properties(&pool, id, "sonnet-5", "hashNew")
        .await
        .expect("second write");

    let props = read_properties(&pool, id).await;
    assert_eq!(
        props["llm_model"], "sonnet-5",
        "second write must overwrite llm_model"
    );
    assert_eq!(
        props["llm_prompt_hash"], "hashNew",
        "second write must overwrite llm_prompt_hash"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn unknown_agent_returns_not_found(pool: PgPool) {
    let missing = Uuid::new_v4();
    let err = AgentRepository::set_llm_properties(&pool, missing, "opus-4-8", "hash")
        .await
        .expect_err("unknown agent must error, not silently no-op");

    match err {
        DbError::NotFound { entity, id } => {
            assert_eq!(entity, "Agent");
            assert_eq!(id, missing);
        }
        other => panic!("expected DbError::NotFound, got {other:?}"),
    }
}
