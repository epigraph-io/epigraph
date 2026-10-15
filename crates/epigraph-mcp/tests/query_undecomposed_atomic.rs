//! `query_undecomposed_claims` must say which rows are atomic, and so terminal.
//!
//! Drain unit U073, backlog `5e1debbc`: `decompose_claims` skips claims that
//! `looks_atomic` accepts (one sentence, at most 160 chars) by default. These
//! claims never get a `decomposes_to` edge, so they stay in the undecomposed
//! population forever. That is about 96% of the visible queue. The MCP tool
//! listed them with no signal and told agents to "feed the returned claim_ids
//! to the decompose_claims CLI". The nightly maintenance agents then kept filing
//! the oldest-first queue head (one-sentence measurements) as a backlog bug.
//!
//! The operator ruled (2026-10-14) that atomic is terminal. The tool now flags
//! each row and its description says what the flag means.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_mcp::tools::claims::query_undecomposed_claims;
use epigraph_mcp::types::QueryUndecomposedClaimsParams;
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::build_test_server;

/// Three undecomposed claims, one per branch of the heuristic. A flag that
/// tests only the sentence count, or only the length cap, or that is constant,
/// fails at least one of them.
#[sqlx::test(migrations = "../../migrations")]
async fn query_undecomposed_claims_flags_looks_atomic_rows(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    // One sentence, under the cap: terminal.
    let atomic = seed_claim(
        &pool,
        agent,
        "The rotor arm friction coefficient is about 4e-22 N m s.",
    )
    .await;
    // Two short sentences: compound, decompose_claims will send it to the LLM.
    let two_sentences = seed_claim(
        &pool,
        agent,
        "The rotor arm turns freely. Its friction coefficient is about 4e-22 N m s.",
    )
    .await;
    // One sentence, over the 160-char cap: compound-suspect, not skipped.
    let long_sentence_text = format!(
        "The rotor arm of the DNA origami nanoengine, {}turns with a friction coefficient of about 4e-22 N m s.",
        "measured under several buffer conditions and temperatures, ".repeat(2)
    );
    assert!(
        long_sentence_text.chars().count() > 160,
        "fixture must exceed the cap"
    );
    let long_sentence = seed_claim(&pool, agent, &long_sentence_text).await;

    let server = build_test_server(pool.clone());
    let result = query_undecomposed_claims(
        &server,
        &viewer,
        QueryUndecomposedClaimsParams {
            // Ordered created_at ASC: a large page so any migration-seeded rows
            // cannot push the fixtures off it.
            limit: Some(1000),
            offset: Some(0),
        },
    )
    .await
    .expect("query_undecomposed_claims");
    let claims = parse_array(&result);

    // Control: the flag annotates rows, it does not hide them.
    let atomic_row = find_claim(&claims, atomic);
    let two_row = find_claim(&claims, two_sentences);
    let long_row = find_claim(&claims, long_sentence);

    assert_eq!(
        atomic_row["looks_atomic"],
        Value::Bool(true),
        "query_undecomposed_claims must tell agents which rows decompose_claims will skip as \
         atomic; without it the maintenance agents re-file the queue head as a bug: {atomic_row}"
    );
    assert_eq!(
        two_row["looks_atomic"],
        Value::Bool(false),
        "a two-sentence claim is compound and must not be flagged atomic: {two_row}"
    );
    assert_eq!(
        long_row["looks_atomic"],
        Value::Bool(false),
        "a single sentence over the 160-char cap must not be flagged atomic: {long_row}"
    );

    // The wrapper must not drop the claim fields the other tools serve.
    assert_eq!(
        atomic_row["content"].as_str(),
        Some("The rotor arm friction coefficient is about 4e-22 N m s."),
        "{atomic_row}"
    );
    assert_eq!(atomic_row["is_current"], Value::Bool(true), "{atomic_row}");
}

/// The description is the contract the maintenance agents read. It must say
/// that flagged rows are terminal and must stop sending them to the CLI.
#[test]
fn query_undecomposed_claims_description_says_atomic_rows_are_terminal() {
    let tools = epigraph_mcp::EpiGraphMcpFull::all_tools_json();
    let tool = tools
        .as_array()
        .expect("all_tools_json returns an array")
        .iter()
        .find(|t| t["name"] == "query_undecomposed_claims")
        .expect("query_undecomposed_claims is registered")
        .clone();
    let description = tool["description"]
        .as_str()
        .expect("query_undecomposed_claims has a description")
        .to_string();
    // The published cap must track the heuristic's constant: if
    // ATOMIC_MAX_CHARS changes, this fails until the description does too.
    let cap = format!(
        "one sentence, at most {} chars",
        epigraph_core::atomicity::ATOMIC_MAX_CHARS
    );
    for needle in [
        "Rows with looks_atomic=true are terminal by policy",
        cap.as_str(),
        "they are NOT a backlog or a defect",
        "Feed only looks_atomic=false claim_ids to the decompose_claims CLI",
        "row count is not a progress measure",
    ] {
        assert!(
            description.contains(needle),
            "query_undecomposed_claims' description must say {needle:?}; got: {description}"
        );
    }
    assert!(
        !description.contains("feed the returned claim_ids to the decompose_claims CLI"),
        "the description must no longer tell agents to feed every row to the CLI: {description}"
    );

    // Agents also read the `limit` parameter's doc through inputSchema. The old
    // "monotonic progress" framing invited them to treat the raw row count as
    // a drain metric; atomic rows never leave the list.
    let limit_doc = tool["inputSchema"]["properties"]["limit"]["description"]
        .as_str()
        .expect("query_undecomposed_claims' limit parameter has a description")
        .to_string();
    assert!(
        limit_doc.contains("row count is not a progress measure"),
        "the limit doc must say the row count is not a progress measure; got: {limit_doc}"
    );
    assert!(
        !limit_doc.contains("monotonic progress"),
        "the limit doc must no longer promise monotonic progress; got: {limit_doc}"
    );
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

fn parse_array(result: &CallToolResult) -> Vec<Value> {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content block");
    serde_json::from_str::<Value>(&text)
        .expect("response is JSON")
        .as_array()
        .expect("response is a JSON array")
        .clone()
}

fn find_claim(claims: &[Value], id: Uuid) -> &Value {
    let id_str = id.to_string();
    claims
        .iter()
        .find(|c| c["id"].as_str() == Some(id_str.as_str()))
        .unwrap_or_else(|| panic!("claim {id_str} not in response: {claims:?}"))
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(id)
        .bind("ce".repeat(32))
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

/// A current claim with no labels, no properties and no edges: undecomposed.
async fn seed_claim(pool: &PgPool, agent_id: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id) \
         VALUES ($1, $2, $3, 0.5, $4)",
    )
    .bind(id)
    .bind(content)
    .bind(hash)
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}
