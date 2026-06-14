//! Consolidated MCP read-path redaction parity test (A3 §7.5, Task 12).
//!
//! Tasks 10/11 relocated `check_content_access` into `epigraph-db` and wired
//! `redact_content` + the per-transport `mcp_requester` into every MCP read
//! tool. This file is the single discriminating regression that exercises the
//! WHOLE matrix the spec enumerates — both transports (HTTP bearer vs. stdio
//! fallback), owner vs. stranger, the public non-regression, and the batch
//! per-id path — in one place, so a future refactor that breaks redaction trips
//! exactly one obviously-named test.
//!
//! Each case runs against its own fresh `#[sqlx::test]` database: the seeded
//! claims are the ONLY rows, so the stranger assertion proves *redaction*, not
//! a missing/not-found row (INDEX §5 residual: a large seeded DB can make a
//! redaction test non-discriminating). `find_claim` / `.expect()` panic on
//! absence, which is the not-found guard.
//!
//! The stranger-via-MCP assertions FAIL on `origin/main` (which returned the
//! owner's content to any caller) and PASS on this branch — that is the
//! discriminating regression. This is a TEST-ONLY task; the redaction
//! implementation already landed in Task 11, so every assertion is GREEN on the
//! first run.

use epigraph_core::{Agent, ClaimId};
use epigraph_crypto::AgentSigner;
use epigraph_db::AgentRepository;
use epigraph_mcp::tools::claims::{get_claim, query_claims};
use epigraph_mcp::tools::redaction::mcp_requester;
use epigraph_mcp::types::{GetClaimParams, QueryClaimsParams};
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::build_test_server;

const REDACTED: &str = "[REDACTED]";

// ── Case: owner (HTTP) sees full content; stranger (HTTP) is redacted ────────
//
// The HTTP transport derives the requester from the validated bearer identity.
// We model that here by passing `Some(agent)` directly to `get_claim` (exactly
// what `mcp_requester(Some(auth), _)` resolves a bearer to). The stranger
// assertion is the discriminating one: on `origin/main` it returned A's
// content; on this branch it must be `"[REDACTED]"`.
#[sqlx::test(migrations = "../../migrations")]
async fn http_owner_sees_content_stranger_is_redacted(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    let claim_id = seed_claim(&pool, owner).await;
    let expected = format!("test claim {}", claim_id.as_uuid());
    seed_private_ownership(&pool, claim_id, owner).await;

    let server = build_test_server(pool.clone());

    // Owner (HTTP) → real content.
    let owner_body = get_claim_as(&server, claim_id, Some(owner)).await;
    assert_eq!(
        owner_body["content"].as_str().unwrap(),
        expected,
        "owner must see the full private content"
    );

    // Stranger (HTTP), B ≠ A → "[REDACTED]". Fails on origin/main.
    let stranger = Uuid::new_v4();
    let stranger_body = get_claim_as(&server, claim_id, Some(stranger)).await;
    assert_eq!(
        stranger_body["content"].as_str().unwrap(),
        REDACTED,
        "stranger must NOT see private content — this is the discriminating \
         assertion that fails on origin/main"
    );
}

// ── Case: stdio fallback resolves the requester to server.agent_id() ─────────
//
// On the stdio transport there is no `AuthContext`, so `mcp_requester(None, _)`
// falls the requester back to the server's own signer identity. We exercise the
// REAL resolution function (`mcp_requester`) rather than passing a literal
// `None` to `get_claim`: a literal `None` would always redact a private claim
// (anonymous), so it cannot model the "owned-by-the-stdio-agent ⇒ full content"
// sub-case the spec requires. Driving the redaction off the resolved requester
// is what ties this test to the stdio arm.
#[sqlx::test(migrations = "../../migrations")]
async fn stdio_fallback_uses_server_identity(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let server_agent = server_agent_id(&pool).await;

    // (a) Private claim OWNED BY the stdio server agent → real content, because
    // the stdio requester resolves to server_agent == owner.
    let owned_id = seed_claim(&pool, server_agent).await;
    let owned_expected = format!("test claim {}", owned_id.as_uuid());
    seed_private_ownership(&pool, owned_id, server_agent).await;

    let requester = mcp_requester(/* auth */ None, server_agent);
    assert_eq!(
        requester,
        Some(server_agent),
        "stdio (no bearer) must resolve the requester to the server's identity"
    );

    let owned_body = get_claim_as(&server, owned_id, requester).await;
    assert_eq!(
        owned_body["content"].as_str().unwrap(),
        owned_expected,
        "stdio agent must see content of the private claim IT owns"
    );

    // (b) Private claim owned by a DIFFERENT agent → "[REDACTED]" for the stdio
    // agent (server.agent_id() ≠ owner).
    let other_owner = seed_agent(&pool).await;
    let foreign_id = seed_claim(&pool, other_owner).await;
    seed_private_ownership(&pool, foreign_id, other_owner).await;

    let foreign_body = get_claim_as(&server, foreign_id, requester).await;
    assert_eq!(
        foreign_body["content"].as_str().unwrap(),
        REDACTED,
        "stdio agent must NOT see a private claim owned by another agent"
    );
}

// ── Case: public (ownership-less) non-regression for ANY requester ───────────
//
// A claim with no `ownership` row is public: `check_content_access` returns
// `Full` regardless of requester. The spec requires this hold "for any
// requester (including `None`)", so we assert all three: owner, stranger, and
// the anonymous stdio `None`. This guards against an over-eager redaction that
// fails closed on public rows.
#[sqlx::test(migrations = "../../migrations")]
async fn public_claim_is_never_redacted(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    let claim_id = seed_claim(&pool, owner).await; // no ownership row → public
    let expected = format!("test claim {}", claim_id.as_uuid());

    let server = build_test_server(pool.clone());

    for (label, requester) in [
        ("owner", Some(owner)),
        ("stranger", Some(Uuid::new_v4())),
        ("anonymous (stdio None)", None),
    ] {
        let body = get_claim_as(&server, claim_id, requester).await;
        assert_eq!(
            body["content"].as_str().unwrap(),
            expected,
            "public claim must show full content to {label}"
        );
    }
}

// ── Case: query_claims batch redacts only the rows the requester can't see ───
//
// `query_claims` uses `batch_check_content_access` + a per-id `access_map`
// lookup — a different code path from singular `get_claim`. Its distinctive
// failure mode is a *mispairing* (the access decision landing on the wrong
// claim), which cannot occur with a single claim. We seed a mixed result set
// (one public, one private-owned-by-a-stranger) and query as a non-owner: each
// row must get ITS OWN decision.
#[sqlx::test(migrations = "../../migrations")]
async fn query_claims_redacts_only_unauthorized_rows(pool: PgPool) {
    let public_owner = seed_agent(&pool).await;
    let private_owner = seed_agent(&pool).await;

    let public_id = seed_claim_with_truth(&pool, public_owner, 0.80).await;
    let public_content = format!("test claim {}", public_id.as_uuid());

    let private_id = seed_claim_with_truth(&pool, private_owner, 0.20).await;
    seed_private_ownership(&pool, private_id, private_owner).await;

    let server = build_test_server(pool.clone());

    // Query as a STRANGER (neither owner). Both claims appear; only the private
    // one is redacted.
    let stranger = Uuid::new_v4();
    let result = query_claims(
        &server,
        QueryClaimsParams {
            min_truth: Some(0.0),
            max_truth: Some(1.0),
            limit: Some(50),
        },
        Some(stranger),
    )
    .await
    .expect("query_claims as stranger");
    let claims = parse_claims(&result);

    let public = find_claim(&claims, public_id);
    assert_eq!(
        public["content"].as_str().unwrap(),
        public_content,
        "public claim must show full content to a stranger in a batch query"
    );

    let private = find_claim(&claims, private_id);
    assert_eq!(
        private["content"].as_str().unwrap(),
        REDACTED,
        "private claim must be redacted for a stranger — fails on a per-id \
         mispairing or a deleted/inverted redaction branch"
    );
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Resolve the server's own agent id the same way `EpiGraphMcpFull::agent_id`
/// does (which is `pub(crate)` and so not reachable from an integration test):
/// derive the signer's public key and get-or-create the agent. The signer bytes
/// MUST stay in lockstep with `build_test_server` in `common/mod.rs`
/// (`AgentSigner::from_bytes(&[0xA7u8; 32])`) — if that constant changes there,
/// change it here too, or this helper resolves a different agent than the server
/// uses and the stdio cases go silently non-discriminating.
async fn server_agent_id(pool: &PgPool) -> Uuid {
    let signer = AgentSigner::from_bytes(&[0xA7u8; 32]).expect("signer");
    let pub_key = signer.public_key();
    if let Some(a) = AgentRepository::get_by_public_key(pool, &pub_key)
        .await
        .expect("get agent by public key")
    {
        return a.id.as_uuid();
    }
    let agent = Agent::new(pub_key, Some("mcp-agent".to_string()));
    AgentRepository::create(pool, &agent)
        .await
        .expect("create server agent");
    agent.id.as_uuid()
}

async fn get_claim_as(
    server: &epigraph_mcp::EpiGraphMcpFull,
    claim_id: ClaimId,
    requester: Option<Uuid>,
) -> Value {
    let result = get_claim(
        server,
        GetClaimParams {
            claim_id: claim_id.as_uuid().to_string(),
            frame_id: None,
            perspective_id: None,
        },
        requester,
    )
    .await
    .expect("get_claim");
    parse_claim(&result)
}

async fn seed_private_ownership(pool: &PgPool, claim_id: ClaimId, owner: Uuid) {
    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id) \
         VALUES ($1, 'claim', 'private', $2)",
    )
    .bind(claim_id.as_uuid())
    .bind(owner)
    .execute(pool)
    .await
    .expect("seed private ownership");
}

fn parse_claim(result: &CallToolResult) -> Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content block");
    serde_json::from_str(&text).expect("response is JSON")
}

fn parse_claims(result: &CallToolResult) -> Vec<Value> {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content block");
    let parsed: Value = serde_json::from_str(&text).expect("response is JSON");
    parsed.as_array().expect("response is JSON array").clone()
}

fn find_claim(claims: &[Value], id: ClaimId) -> &Value {
    let id_str = id.as_uuid().to_string();
    claims
        .iter()
        .find(|c| c["id"].as_str() == Some(id_str.as_str()))
        .unwrap_or_else(|| panic!("claim {id_str} not in response: {claims:?}"))
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    // Derive a unique public key from the agent id so seeding several agents in
    // one test doesn't collide on `agents_public_key_unique`.
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(pool: &PgPool, agent_id: Uuid) -> ClaimId {
    seed_claim_with_truth(pool, agent_id, 0.5).await
}

async fn seed_claim_with_truth(pool: &PgPool, agent_id: Uuid, truth: f64) -> ClaimId {
    let id = Uuid::new_v4();
    // 16-byte UUID padded to a 32-byte content_hash. `repeat(0).take(16)` keeps
    // this MSRV-safe (avoids `iter::repeat_n`).
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat(0).take(16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             labels, is_current) \
         VALUES ($1, $2, $3, $4, $5, ARRAY[]::text[], true)",
    )
    .bind(id)
    .bind(format!("test claim {}", id))
    .bind(hash)
    .bind(truth)
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("seed claim");
    ClaimId::from_uuid(id)
}
