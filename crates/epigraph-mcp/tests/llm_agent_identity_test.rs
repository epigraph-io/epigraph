//! Integration tests for blueprint §3 — LLM-agent identity + auth lineage.
//!
//! Two behaviours are exercised against a live test DB (never the production
//! `epigraph` DB — see repo CLAUDE.md "Test database"):
//!
//!   1. IDENTITY: a server whose keypair is derived from `(model, prompt)` and
//!      that carries the matching `llm_identity` records `llm_model` /
//!      `llm_prompt_hash` on the agent row it CREATES, and a second server built
//!      from the identical signer resolves to the SAME agent id (collapse).
//!
//!   2. LINEAGE: `record_auth_lineage(Some(principal))` writes exactly ONE
//!      `OPERATED_BY` edge (idempotent on repeat), writes NOTHING for `None`,
//!      and is best-effort for a non-existent principal (no panic, no edge).
//!
//! The lineage assertions target the `record_auth_lineage` seam that `call_tool`
//! delegates to — the same wiring `emit_tool_invoked` uses to stay testable
//! without synthesizing a full `rmcp::service::RequestContext`.

use epigraph_crypto::{keypair_from_llm_agent, AgentSigner};
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::EpiGraphMcpFull;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

const MODEL: &str = "claude-opus-4-8";
const PROMPT: &str = "You are Claude Code, Anthropic's official CLI for Claude.";

/// Build a server whose identity is deterministically derived from
/// `(MODEL, PROMPT)`, carrying the matching `llm_identity` so `agent_id()`'s
/// CREATE branch records provenance. Uses the empty federation registry.
fn llm_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = keypair_from_llm_agent(MODEL, PROMPT);
    let prompt_hash = blake3::hash(PROMPT.as_bytes()).to_hex().to_string();
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new_with_federation(
        pool,
        signer,
        embedder,
        /* read_only */ false,
        Arc::new(epigraph_mcp::federation::FederationRegistry::empty()),
        Some((MODEL.to_string(), prompt_hash)),
    )
}

/// Resolve the mcp server's agent id from the DB by the DETERMINISTIC pubkey the
/// `(MODEL, PROMPT)` signer produces. The server's `agent_id()` is `pub(crate)`
/// and not reachable from this (separate) test crate, so tests trigger agent
/// creation via the public `emit_tool_invoked` (which internally calls
/// `agent_id()`) and then look the row up here by public key.
async fn resolve_mcp_agent_id(pool: &PgPool) -> Uuid {
    let pk = keypair_from_llm_agent(MODEL, PROMPT).public_key();
    epigraph_db::AgentRepository::get_by_public_key(pool, &pk)
        .await
        .expect("query agent by public key")
        .expect("mcp agent row exists after emit_tool_invoked")
        .id
        .as_uuid()
}

/// Seed a real agent row and return its id, for use as a valid lineage
/// principal. Public-key is derived from the id so it is unique per call.
async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) \
         VALUES ($1, $2, 'system') ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed agent");
    id
}

async fn count_operated_by(pool: &PgPool, source: Uuid, target: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM edges \
         WHERE source_id = $1 AND target_id = $2 AND relationship = 'OPERATED_BY'",
    )
    .bind(source)
    .bind(target)
    .fetch_one(pool)
    .await
    .expect("count query")
}

// ────────────────────────────────────────────────────────────────────────────
// IDENTITY
// ────────────────────────────────────────────────────────────────────────────

/// `agent_id()` on an LLM-configured server CREATES exactly one agent row and
/// stamps `llm_model` / `llm_prompt_hash` on it; a SECOND server built from the
/// identical `(model, prompt)` signer resolves to the SAME id (the FOUND branch,
/// keyed on public key), proving identical configs collapse to one agent. The
/// stored hash must equal the BLAKE3 digest of the prompt — the anti-drift
/// invariant that keeps the recorded hash corresponding to the key.
#[sqlx::test(migrations = "../../migrations")]
async fn llm_identity_stamps_properties_and_collapses_to_one_agent(pool: PgPool) {
    let server1 = llm_server(pool.clone());
    // emit_tool_invoked internally calls the pub(crate) agent_id(), whose CREATE
    // branch stamps the LLM properties — the production path, driven publicly.
    server1.emit_tool_invoked("query_claims").await;
    let id1 = resolve_mcp_agent_id(&pool).await;

    // Exactly one row for this pubkey-derived identity.
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agents WHERE id = $1")
        .bind(id1)
        .fetch_one(&pool)
        .await
        .expect("count agents");
    assert_eq!(rows, 1, "CREATE branch must produce exactly one agent row");

    // Properties recorded by set_llm_properties on the CREATE branch.
    let (model, hash, source): (Option<String>, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT properties->>'llm_model', properties->>'llm_prompt_hash', \
                    properties->>'source' FROM agents WHERE id = $1",
    )
    .bind(id1)
    .fetch_one(&pool)
    .await
    .expect("read properties");

    assert_eq!(model.as_deref(), Some(MODEL), "llm_model must be recorded");
    let expected_hash = blake3::hash(PROMPT.as_bytes()).to_hex().to_string();
    assert_eq!(
        hash.as_deref(),
        Some(expected_hash.as_str()),
        "llm_prompt_hash must be the BLAKE3 digest of the prompt (anti-drift)"
    );
    assert_eq!(
        source.as_deref(),
        Some("mcp-llm-agent"),
        "source marker must be set by set_llm_properties"
    );

    // A second, independently-constructed server with the SAME derived signer
    // resolves to the SAME agent id via get_by_public_key (the FOUND branch,
    // which does NOT re-set properties — it reads the row server1 created).
    let server2 = llm_server(pool.clone());
    server2.emit_tool_invoked("query_claims").await;
    let id2 = resolve_mcp_agent_id(&pool).await;
    assert_eq!(
        id1, id2,
        "identical (model, prompt) config must collapse to ONE agent"
    );

    // Still exactly one row after the second resolution (no duplicate created).
    let rows_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agents WHERE id = $1")
        .bind(id1)
        .fetch_one(&pool)
        .await
        .expect("count agents after reuse");
    assert_eq!(rows_after, 1, "reuse must not create a second agent row");
}

/// Control: a server with NO `llm_identity` (the legacy generate/agent-key
/// path) must NOT stamp LLM properties on its agent — the backward-compatible
/// behaviour the blueprint preserves. Guards that the CREATE-branch write is
/// gated on `llm_identity.is_some()`, not run unconditionally.
#[sqlx::test(migrations = "../../migrations")]
async fn absent_llm_identity_leaves_agent_properties_clean(pool: PgPool) {
    // Deterministic non-LLM signer so the test is reproducible; llm_identity None.
    let signer_bytes = [0x5Cu8; 32];
    let signer = AgentSigner::from_bytes(&signer_bytes).expect("signer");
    let pk = signer.public_key();
    let embedder = McpEmbedder::new(pool.clone(), None);
    let server = EpiGraphMcpFull::new(pool.clone(), signer, embedder, false);

    server.emit_tool_invoked("query_claims").await;
    let id = epigraph_db::AgentRepository::get_by_public_key(&pool, &pk)
        .await
        .expect("query agent")
        .expect("agent row exists")
        .id
        .as_uuid();

    let source: Option<String> =
        sqlx::query_scalar("SELECT properties->>'source' FROM agents WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("read source");
    assert_ne!(
        source.as_deref(),
        Some("mcp-llm-agent"),
        "an unconfigured server must NOT stamp the mcp-llm-agent marker"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// LINEAGE
// ────────────────────────────────────────────────────────────────────────────

/// `record_auth_lineage(Some(principal))` for a REAL principal writes exactly
/// one `OPERATED_BY` edge; a repeat call writes no second edge (idempotent).
/// The edge is `mcp_agent --OPERATED_BY--> principal`. The one-edge guarantee is
/// asserted against a `COUNT(*)` on the `edges` table — the DB is the dedup
/// authority (`create_if_not_exists`), not the per-session memo set.
#[sqlx::test(migrations = "../../migrations")]
async fn lineage_writes_exactly_one_operated_by_edge_idempotently(pool: PgPool) {
    let server = llm_server(pool.clone());
    server.emit_tool_invoked("query_claims").await; // creates the mcp agent
    let mcp_agent = resolve_mcp_agent_id(&pool).await;
    let principal = seed_agent(&pool).await;

    assert_eq!(
        count_operated_by(&pool, mcp_agent, principal).await,
        0,
        "precondition: no lineage edge yet"
    );

    server.record_auth_lineage(Some(principal)).await;
    assert_eq!(
        count_operated_by(&pool, mcp_agent, principal).await,
        1,
        "first call must write exactly one OPERATED_BY edge"
    );

    // Repeat: the per-session memo short-circuits, and even if it did not the DB
    // create_if_not_exists would refuse a duplicate. Either way -> still one.
    server.record_auth_lineage(Some(principal)).await;
    assert_eq!(
        count_operated_by(&pool, mcp_agent, principal).await,
        1,
        "repeat call must NOT write a second edge"
    );

    // Sanity: the edge really is agent->agent with the OPERATED_BY relationship.
    let (st, tt): (String, String) = sqlx::query_as(
        "SELECT source_type, target_type FROM edges \
         WHERE source_id = $1 AND target_id = $2 AND relationship = 'OPERATED_BY'",
    )
    .bind(mcp_agent)
    .bind(principal)
    .fetch_one(&pool)
    .await
    .expect("edge row");
    assert_eq!((st.as_str(), tt.as_str()), ("agent", "agent"));
}

/// `record_auth_lineage(None)` writes nothing — the stdio / unauthenticated /
/// no-principal path. Guards that a bare tool call from a caller without an
/// `agent_id` never fabricates a lineage edge.
#[sqlx::test(migrations = "../../migrations")]
async fn lineage_none_principal_writes_no_edge(pool: PgPool) {
    let server = llm_server(pool.clone());
    server.emit_tool_invoked("query_claims").await; // creates the mcp agent
    let mcp_agent = resolve_mcp_agent_id(&pool).await;

    server.record_auth_lineage(None).await;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND relationship = 'OPERATED_BY'",
    )
    .bind(mcp_agent)
    .fetch_one(&pool)
    .await
    .expect("count edges");
    assert_eq!(total, 0, "None principal must write zero lineage edges");
}

/// Best-effort contract: a principal that does NOT exist in `agents` trips the
/// `validate_edge_reference` existence trigger inside `create_if_not_exists`.
/// `record_auth_lineage` must SWALLOW that error (no panic) and write no edge —
/// so in production the tool still returns its result. The principal is also NOT
/// inserted into the memo set on failure, so a later valid retry could succeed.
#[sqlx::test(migrations = "../../migrations")]
async fn lineage_nonexistent_principal_is_best_effort(pool: PgPool) {
    let server = llm_server(pool.clone());
    server.emit_tool_invoked("query_claims").await; // creates the mcp agent
    let mcp_agent = resolve_mcp_agent_id(&pool).await;
    let ghost = Uuid::new_v4(); // never inserted into agents

    // Must not panic even though the FK/existence trigger will reject the insert.
    server.record_auth_lineage(Some(ghost)).await;

    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM edges WHERE source_id = $1 AND target_id = $2")
            .bind(mcp_agent)
            .bind(ghost)
            .fetch_one(&pool)
            .await
            .expect("count edges");
    assert_eq!(
        total, 0,
        "a non-existent principal must yield zero edges (best-effort, no panic)"
    );
}
