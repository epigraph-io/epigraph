//! MCP `evolve_step` (id-mode) refusals reach the caller as the CALLER's
//! error, INVALID_PARAMS, on the production branch of the tool: a server
//! built WITH a ScopedPool, on the APPLICATION ROLE where row security is in
//! force, the caller bound to a human operator and the database armed
//! (backlog 769989ae, the MCP twin of the HTTP route's 404 / 409 arms).
//!
//! * a `parent_id` that names no claim, and one naming a group-private claim
//!   the caller cannot see, are refused alike (same code, same wording, no
//!   content of the hidden parent), so the refusal does not disclose which
//!   of the two it was. Before the fix `ClaimRepository::evolve_step_conn`'s
//!   `DbError::NotFound` fell through `db_caller_error` to INTERNAL_ERROR;
//! * `supersedes` on a step that is no longer current is INVALID_PARAMS here
//!   too, not only on the no-ScopedPool fixture branch `step_versioning.rs`
//!   covers.
//!
//! Each arm asserts nothing was written. Seeding, links and arming run on the
//! harness pool, as in `evolve_step_cascade_app_role.rs`.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::evolve_step::{evolve_step, EvolveStepParams};
use rmcp::model::ErrorCode;
use sqlx::PgPool;
use uuid::Uuid;

/// An app-role stdio server (ScopedPool on `epigraph_app`) whose own agent,
/// the CALLER, is pre-created and keyed by `seed`.
async fn app_role_server(pool: &PgPool, seed: u8) -> (EpiGraphMcpFull, Uuid) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: the invisible arm is vacuous"
    );
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let caller: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, 'mcp-agent') RETURNING id",
    )
    .bind(signer.public_key().as_slice())
    .fetch_one(pool)
    .await
    .expect("the caller's agent row");
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let embedder =
        epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None).with_scoped_pool(scoped.clone());
    let server = EpiGraphMcpFull::new(plain, signer, embedder, /* read_only */ false)
        .with_scoped_pool(scoped);
    (server, caller)
}

/// A human operator, the caller live-linked to it, and the database armed.
/// Returns the operator's group, which the caller writes.
async fn bind_and_arm(pool: &PgPool, caller: Uuid) -> Uuid {
    let (human, group) = fixture::seed_human_operator(pool, "evolve-refusal-human").await;
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::AgentRepository::link_operator(&mut conn, caller, human)
        .await
        .expect("live link");
    drop(conn);
    sqlx::query("INSERT INTO operator_binding_arming DEFAULT VALUES")
        .execute(pool)
        .await
        .expect("arm (the harness stands in for the maintenance role)");
    group
}

fn params(parent: Uuid, edge_type: &str, content: &str) -> EvolveStepParams {
    EvolveStepParams {
        parent_id: parent.to_string(),
        canonical_name: None,
        step_index: None,
        step_lineage_id: String::new(),
        content: content.to_string(),
        edge_type: edge_type.to_string(),
        rationale: Some("refusal test".to_string()),
        level: Some(2),
    }
}

/// The tool's result on the caller's own stdio viewer.
async fn evolve(
    server: &EpiGraphMcpFull,
    p: EvolveStepParams,
) -> Result<rmcp::model::CallToolResult, epigraph_mcp::errors::McpError> {
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("stdio viewer");
    evolve_step(server, &viewer, p, None).await
}

async fn claims_with_content(pool: &PgPool, content: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .expect("count")
}

async fn edges_into(pool: &PgPool, target: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE target_id = $1 \
           AND relationship IN ('supersedes', 'revises')",
    )
    .bind(target)
    .fetch_one(pool)
    .await
    .expect("count")
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_on_a_missing_or_invisible_parent_is_invalid_params_alike(pool: PgPool) {
    let (server, caller) = app_role_server(&pool, 0xD1).await;
    // The hidden parent is seeded before arming: once armed, the claims
    // trigger refuses a claim by an agent bound to no operator.
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "evolve-refusal-owner").await;
    let hidden_text = format!("the owner's group-private step {}", Uuid::new_v4());
    let hidden = fixture::seed_group_claim(&pool, owner, owner_group, &hidden_text).await;
    let caller_group = bind_and_arm(&pool, caller).await;
    let missing = Uuid::new_v4();

    // A parent that does not exist.
    let content_missing = format!("evolve of a missing parent {}", Uuid::new_v4());
    let err_missing = evolve(&server, params(missing, "revises", &content_missing))
        .await
        .expect_err("a missing parent is refused");
    assert_eq!(
        err_missing.code,
        ErrorCode::INVALID_PARAMS,
        "a parent that does not exist is the caller's error: {}",
        err_missing.message
    );
    assert!(
        err_missing.message.contains("not found"),
        "the refusal says why: {}",
        err_missing.message
    );
    assert_eq!(claims_with_content(&pool, &content_missing).await, 0);

    // A parent that exists but is private to a group the caller is not in.
    let content_hidden = format!("evolve of a hidden parent {}", Uuid::new_v4());
    let err_hidden = evolve(&server, params(hidden, "supersedes", &content_hidden))
        .await
        .expect_err("a parent the caller cannot see is refused");
    assert_eq!(
        err_hidden.code, err_missing.code,
        "an invisible parent is refused exactly as a missing one is: {}",
        err_hidden.message
    );
    assert_eq!(
        err_hidden.message.replace(&hidden.to_string(), "<id>"),
        err_missing.message.replace(&missing.to_string(), "<id>"),
        "the wording does not tell an invisible parent from a missing one"
    );
    assert!(
        !err_hidden.message.contains(&hidden_text),
        "the refusal discloses nothing of the parent: {}",
        err_hidden.message
    );
    assert_eq!(claims_with_content(&pool, &content_hidden).await, 0);
    assert_eq!(edges_into(&pool, hidden).await, 0, "nothing is written");
    let still_current: bool =
        sqlx::query_scalar("SELECT COALESCE(is_current, true) FROM claims WHERE id = $1")
            .bind(hidden)
            .fetch_one(&pool)
            .await
            .expect("hidden parent");
    assert!(still_current, "a refused supersede retires nothing");

    // Control: the same server evolves a parent the caller CAN see, so the
    // refusals above are the parent and not the harness.
    let own = fixture::seed_group_claim(&pool, caller, caller_group, "the caller's step").await;
    let content_own = format!("evolve of the caller's own step {}", Uuid::new_v4());
    evolve(&server, params(own, "revises", &content_own))
        .await
        .map_err(|e| e.message.to_string())
        .expect("the caller evolves a step it can see");
    assert_eq!(claims_with_content(&pool, &content_own).await, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_supersede_of_a_non_current_step_is_invalid_params_on_the_app_role(
    pool: PgPool,
) {
    let (server, caller) = app_role_server(&pool, 0xD2).await;
    let group = bind_and_arm(&pool, caller).await;
    let retired = fixture::seed_group_claim(&pool, caller, group, "a retired step").await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(retired)
        .execute(&pool)
        .await
        .expect("retire the step");

    let content = format!("supersede of a retired step {}", Uuid::new_v4());
    let err = evolve(&server, params(retired, "supersedes", &content))
        .await
        .expect_err("a non-current step cannot be superseded");
    assert_eq!(
        err.code,
        ErrorCode::INVALID_PARAMS,
        "a non-current parent is the caller's error: {}",
        err.message
    );
    assert!(
        err.message.contains("non-current"),
        "the refusal says why: {}",
        err.message
    );
    assert_eq!(claims_with_content(&pool, &content).await, 0);
    assert_eq!(edges_into(&pool, retired).await, 0, "nothing is written");
}

/// `supersedes` on the caller's own current step, whose retirement the
/// database refuses, is INVALID_REQUEST (a write refusal, the twin of the HTTP
/// route's 403) with nothing written (backlog d34f5096). Before the fix the
/// step was inserted next to a parent that stayed current, leaving the lineage
/// with two current heads.
///
/// A `BEFORE UPDATE` trigger that skips only the parent's `is_current` change
/// produces a retire that changes no row without raising (the claims tenancy
/// policy refuses an unwritable parent by raising at WITH CHECK instead).
#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_supersede_whose_retire_is_refused_is_invalid_request_on_the_app_role(
    pool: PgPool,
) {
    let (server, caller) = app_role_server(&pool, 0xD3).await;
    let group = bind_and_arm(&pool, caller).await;
    let parent = fixture::seed_group_claim(&pool, caller, group, "an unretirable step").await;
    sqlx::raw_sql(&format!(
        "CREATE FUNCTION aaa_test_skip_step_retire() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RETURN NULL; END $$; \
         CREATE TRIGGER aaa_test_skip_step_retire BEFORE UPDATE ON claims FOR EACH ROW \
         WHEN (OLD.id = '{parent}'::uuid AND NEW.is_current IS DISTINCT FROM OLD.is_current) \
         EXECUTE FUNCTION aaa_test_skip_step_retire();"
    ))
    .execute(&pool)
    .await
    .expect("install the retirement stand-in");

    let content = format!("successor of an unretirable step {}", Uuid::new_v4());
    let err = evolve(&server, params(parent, "supersedes", &content))
        .await
        .expect_err("a step whose parent cannot be retired must not evolve");
    assert_eq!(
        err.code,
        ErrorCode::INVALID_REQUEST,
        "a refused retirement is a write refusal: {}",
        err.message
    );
    assert!(
        err.message.contains("was refused"),
        "the refusal says what happened: {}",
        err.message
    );
    assert_eq!(
        claims_with_content(&pool, &content).await,
        0,
        "no successor"
    );
    assert_eq!(edges_into(&pool, parent).await, 0, "nothing is written");
    let still_current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(parent)
        .fetch_one(&pool)
        .await
        .expect("parent");
    assert!(
        still_current,
        "the parent stays the lineage's one current head"
    );
}
