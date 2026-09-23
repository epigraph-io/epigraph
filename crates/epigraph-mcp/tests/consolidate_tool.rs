//! `consolidate_claims` MCP tool wiring (backlog 44b19521 / design F1).
//!
//! Repo semantics are pinned in `epigraph-db/tests/consolidate_test.rs`. This
//! covers the tool layer: that it is reachable, that it is gated as a WRITE
//! (the three tools added alongside it are reads), that the default
//! confidence never exceeds the best source, and that it authorizes the
//! REQUEST principal rather than the server's own signer agent.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_mcp::tools::consolidate::consolidate_claims;
use epigraph_mcp::types::ConsolidateClaimsParams;
use sqlx::PgPool;
use uuid::Uuid;

fn build_server(pool: PgPool, read_only: bool) -> epigraph_mcp::EpiGraphMcpFull {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::EpiGraphMcpFull;
    let signer = AgentSigner::from_bytes(&[0u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, read_only)
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'test-consolidate-mcp', 'system', ARRAY['test'])
         RETURNING id",
    )
    .fetch_one(pool).await.expect("seed agent")
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str, truth: f64) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, sha256($1::bytea), $2, $3, true) RETURNING id",
    )
    .bind(content)
    .bind(truth)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

fn params(ids: &[Uuid], content: &str, confidence: Option<f64>) -> ConsolidateClaimsParams {
    ConsolidateClaimsParams {
        source_claim_ids: ids.iter().map(ToString::to_string).collect(),
        merged_content: content.to_string(),
        mode: "merge".to_string(),
        reason: "test consolidation".to_string(),
        confidence,
    }
}

/// The stdio arm's viewer, through the real `request_viewer`. Its principal is
/// the server's own signer agent, which it also provisions (agent row plus
/// personal group) the same way a tool call would.
async fn stdio_viewer(server: &epigraph_mcp::EpiGraphMcpFull) -> epigraph_db::visibility::Viewer {
    epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("stdio viewer")
}

/// The viewer the HTTP arm builds for an authenticated caller:
/// `Viewer::resolve` over the token's `agents.id`. The tool receives only the
/// viewer, so this is exactly what it sees on that transport.
async fn http_viewer(pool: &PgPool, caller: Uuid) -> epigraph_db::visibility::Viewer {
    epigraph_db::visibility::Viewer::resolve(pool, caller)
        .await
        .expect("http viewer")
}

async fn team_group(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, did_key, public_key, kind, display_name) \
         VALUES ($1, $2, $3, 'team', 'consolidate-tool-test')",
    )
    .bind(id)
    .bind(format!("did:key:consolidate-tool-{id}"))
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed team group");
    id
}

async fn add_member(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, $3, 0, $4)",
    )
    .bind(group)
    .bind(agent)
    .bind(vec![0u8; 48])
    .bind(role)
    .execute(pool)
    .await
    .expect("seed membership");
}

async fn author_of(pool: &PgPool, claim: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("claim author")
}

async fn still_current(pool: &PgPool, ids: &[Uuid]) -> i64 {
    sqlx::query_scalar("SELECT count(*)::bigint FROM claims WHERE id = ANY($1) AND is_current")
        .bind(ids)
        .fetch_one(pool)
        .await
        .expect("source probe")
}

fn json_of(out: rmcp::model::CallToolResult) -> serde_json::Value {
    let text = out
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .unwrap();
    serde_json::from_str(&text).unwrap()
}

/// End-to-end merge through the tool, with the default confidence rule.
///
/// The viewer is the stdio arm's, from the real `request_viewer(_, None)`: the
/// tool now acts as the viewer's principal, and on stdio that principal is the
/// server's own agent, so the merged row's author is unchanged there.
#[sqlx::test(migrations = "../../migrations")]
async fn tool_merges_and_caps_confidence_at_best_source(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let s1 = seed_claim(&pool, agent, "tool src one", 0.6).await;
    let s2 = seed_claim(&pool, agent, "tool src two", 0.9).await;

    let server = build_server(pool.clone(), false);
    let viewer = stdio_viewer(&server).await;
    let server_agent = viewer.principal().expect("stdio viewer has a principal");
    let out = consolidate_claims(&server, &viewer, params(&[s1, s2], "tool merged", None))
        .await
        .expect("consolidate ok");
    let j = json_of(out);

    assert_eq!(j["superseded_ids"].as_array().unwrap().len(), 2);
    assert_eq!(j["already_existed"], serde_json::json!(false));

    let merged_id = Uuid::parse_str(j["merged_claim_id"].as_str().unwrap()).unwrap();
    let tv: f64 = sqlx::query_scalar("SELECT truth_value FROM claims WHERE id=$1")
        .bind(merged_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        (tv - 0.9 * 0.95).abs() < 1e-9,
        "default confidence = best source (0.9) * 0.95, got {tv} — a merge must not \
         claim more certainty than its strongest input"
    );
    assert_eq!(
        author_of(&pool, merged_id).await,
        server_agent,
        "on stdio the request principal IS the server agent, so authorship is unchanged"
    );
}

/// This is a WRITE tool, unlike the reads added alongside it
/// (`get_provenance_chain`, `get_recall_events`). Copying a read's
/// registration would silently drop the write gating, so pin the scope
/// mapping: `claims:read` credentials must NOT satisfy it.
#[test]
fn consolidate_is_gated_as_a_write() {
    assert_eq!(
        epigraph_mcp::scope_map::required_scope("consolidate_claims"),
        Some("claims:write"),
        "consolidate_claims mutates claims and edges; it must require claims:write"
    );
    // Contrast with the reads landed in the same series.
    assert_eq!(
        epigraph_mcp::scope_map::required_scope("get_provenance_chain"),
        Some("claims:read")
    );
    assert_eq!(
        epigraph_mcp::scope_map::required_scope("get_recall_events"),
        Some("claims:read")
    );
}

/// An unknown mode is a parameter error, not a 500.
#[sqlx::test(migrations = "../../migrations")]
async fn unknown_mode_is_rejected(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let s1 = seed_claim(&pool, agent, "mode a", 0.6).await;
    let s2 = seed_claim(&pool, agent, "mode b", 0.6).await;

    let server = build_server(pool, false);
    let mut p = params(&[s1, s2], "x", None);
    p.mode = "obliterate".to_string();
    let err = consolidate_claims(&server, &viewer, p)
        .await
        .expect_err("bad mode rejected");
    let msg = format!("{err:?}").to_lowercase();
    assert!(msg.contains("mode") || msg.contains("invalid"), "{msg}");
}

/// On the HTTP transport the tool authorizes the CALLER, not the server agent.
///
/// The server's own signer agent is a writer in `G`. The caller is only a
/// reader. Before this fix the tool passed `server.agent_id()` as the acting
/// agent, so the server's write authority was checked and any `claims:write`
/// caller could merge and retire private claims in the server agent's groups.
/// Deferred-commitment screen key consolidate-writable-role.
#[sqlx::test(migrations = "../../migrations")]
async fn http_caller_without_write_is_refused_even_where_the_server_agent_can_write(pool: PgPool) {
    let server = build_server(pool.clone(), false);
    let server_agent = stdio_viewer(&server).await.principal().unwrap();
    let (caller, _) = fixture::seed_agent_with_group(&pool, "cons-http-reader").await;
    let group = team_group(&pool).await;
    add_member(&pool, group, server_agent, "writer").await;
    add_member(&pool, group, caller, "reader").await;
    let s1 = fixture::seed_group_claim(&pool, server_agent, group, "http private one").await;
    let s2 = fixture::seed_group_claim(&pool, server_agent, group, "http private two").await;

    let viewer = http_viewer(&pool, caller).await;
    let err = consolidate_claims(
        &server,
        &viewer,
        params(&[s1, s2], "merged by an http reader", Some(0.7)),
    )
    .await
    .expect_err("a reader caller must not merge through the server agent's authority");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("cannot write"),
        "the refusal must reach the caller as the write-authority 409: {msg}"
    );
    assert_eq!(
        still_current(&pool, &[s1, s2]).await,
        2,
        "no source may be retired"
    );
    let merged: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM claims WHERE content = 'merged by an http reader'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(merged, 0, "no merged row may be written");
}

/// The other direction: a caller who CAN write `G` merges even though the
/// server agent is not a member of `G` at all. Before this fix the check
/// tested the server agent, so this merge was refused with a spurious 409.
/// The merged row is authored by the caller, the principal whose authority was
/// checked.
#[sqlx::test(migrations = "../../migrations")]
async fn http_writer_merges_where_the_server_agent_is_not_a_member(pool: PgPool) {
    let server = build_server(pool.clone(), false);
    let server_agent = stdio_viewer(&server).await.principal().unwrap();
    let (caller, _) = fixture::seed_agent_with_group(&pool, "cons-http-writer").await;
    let group = team_group(&pool).await;
    add_member(&pool, group, caller, "writer").await;
    let s1 = fixture::seed_group_claim(&pool, caller, group, "http writer one").await;
    let s2 = fixture::seed_group_claim(&pool, caller, group, "http writer two").await;

    let viewer = http_viewer(&pool, caller).await;
    let out = consolidate_claims(
        &server,
        &viewer,
        params(&[s1, s2], "merged by an http writer", Some(0.7)),
    )
    .await
    .expect("a writer caller merges within its own group");
    let j = json_of(out);
    let merged_id = Uuid::parse_str(j["merged_claim_id"].as_str().unwrap()).unwrap();

    assert_eq!(
        author_of(&pool, merged_id).await,
        caller,
        "the merged row is authored by the request principal"
    );
    assert_ne!(caller, server_agent);
    let owner: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(merged_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(owner, group, "the merge stays in the sources' group");
    assert_eq!(still_current(&pool, &[s1, s2]).await, 0);
}
