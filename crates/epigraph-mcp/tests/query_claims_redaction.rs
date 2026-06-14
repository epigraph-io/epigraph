//! Discriminating redaction regression for the BATCH read path (A3 §7.5,
//! Task 11). `query_claims` uses `batch_check_content_access` + a per-id
//! `access_map` lookup — a DIFFERENT code path from the singular `get_claim`
//! check. Its distinctive failure mode is a *mispairing*: the access decision
//! landing on the wrong claim's content. That failure mode literally cannot
//! occur with a single claim, so this test seeds TWO claims with DIFFERENT
//! access (one public, one private-owned-by-a-stranger), queries as a
//! non-owner, and asserts each claim gets ITS OWN decision:
//!   - the public claim → full content + real content_hash
//!   - the private claim → "[REDACTED]" content + blank content_hash
//! Under a zip/order mispairing the two decisions swap and BOTH assertions
//! fail; under a deleted/inverted redaction branch the private assertions fail;
//! under the content_hash oracle leak the blank-hash assertion fails.

use epigraph_core::ClaimId;
use epigraph_mcp::tools::claims::query_claims;
use epigraph_mcp::types::QueryClaimsParams;
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::build_test_server;

#[sqlx::test(migrations = "../../migrations")]
async fn query_claims_redacts_only_the_private_claim_per_id(pool: PgPool) {
    let public_owner = seed_agent(&pool).await;
    let private_owner = seed_agent(&pool).await;

    // Public claim (no ownership row → treated as public). Truth 0.80.
    let public_id = seed_claim(&pool, public_owner, 0.80).await;
    let public_content = format!("test claim {}", public_id.as_uuid());

    // Private claim owned by `private_owner`. Truth 0.20 — a distinct truth
    // value so `list_by_truth_range`'s ordering is deterministic and the two
    // rows are unambiguous.
    let private_id = seed_claim(&pool, private_owner, 0.20).await;
    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id) \
         VALUES ($1, 'claim', 'private', $2)",
    )
    .bind(private_id.as_uuid())
    .bind(private_owner)
    .execute(&pool)
    .await
    .expect("seed private ownership");

    let server = build_test_server(pool.clone());

    // Query as a STRANGER (neither owner). Must see both claims, but only the
    // private one redacted.
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
        "public claim must show full content to a stranger"
    );
    assert!(
        !public["content_hash"].as_str().unwrap().is_empty(),
        "public claim must show its real content_hash: {public:?}"
    );

    let private = find_claim(&claims, private_id);
    assert_eq!(
        private["content"].as_str().unwrap(),
        "[REDACTED]",
        "private claim must be redacted for a stranger — fails on a zip \
         mispairing (decision lands on the public claim) or a deleted/inverted \
         redaction branch"
    );
    assert_eq!(
        private["content_hash"].as_str().unwrap(),
        "",
        "private claim must NOT leak its content_hash — BLAKE3(content) is a \
         confirmation oracle for the redacted content"
    );
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
    // Derive a unique public key from the agent id so seeding two agents in one
    // test doesn't collide on `agents_public_key_unique`.
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(pool: &PgPool, agent_id: Uuid, truth: f64) -> ClaimId {
    let id = Uuid::new_v4();
    // 16-byte UUID padded to a 32-byte content_hash. `repeat(0).take(..)` keeps
    // this MSRV-safe (avoids `iter::repeat_n`, stable only since 1.82).
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
