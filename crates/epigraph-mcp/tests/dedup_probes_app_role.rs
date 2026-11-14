//! The MCP dedup and idempotency probes read as the CALLER, measured on the
//! APPLICATION ROLE.
//!
//! # Why this file builds its server the way it does
//!
//! In production `server.pool` IS `scoped.inner()`: one pool, logged in as
//! `epigraph_app`, whose unstamped sessions FORCEd row security limits to
//! public rows (`main.rs`). The default MCP harness instead passes an
//! independent superuser pool, which bypasses row security, so a probe that
//! reads on `server.pool` passes every harness test while missing every
//! group-private row in production. [`app_server`] therefore builds the server
//! from ONE `ScopedPool` connected as `epigraph_app` and nothing else: the plain
//! pool is its `inner()`, exactly as `main.rs` does it. The superuser `pool`
//! the harness hands each test only SEEDS rows and reads them back for the
//! assertions.
//!
//! # What each test pins
//!
//! Every probe gets a positive control (a member finds or is deduped against
//! its OWN group-private row, which failed on the unstamped pool) and a
//! negative one (a reader outside the group does not see it).
//!
//! * `submit_claim` / `memorize`'s exact-resubmit probe
//!   (`novelty_gate::exact_resubmit_probe`).
//! * The repair-embed check after a content-hash dedup hit
//!   (`claim_helper::claim_text_if_embedding_missing_as_caller`).
//! * The novelty gate (`novelty_gate::decide`) and its read-back.
//! * `decide_match_candidate`'s current-ness guard and matcher edge
//!   (`MatchCandidateRepo::promote_if_pending_conn` on the author-stamped
//!   transaction).
//! * `check_already_ingested`: a MEASUREMENT, not a leak fix. A `processed_by`
//!   stamp joins a paper and an agent, so migration 120's trigger makes it
//!   world-owned whoever wrote it, and every reader sees it.
//! * The `OPERATED_BY` auth-lineage edge lands on the application role even
//!   though it is written unstamped (agent to agent, so world-owned), so its
//!   warn-only failure branch is not hiding a refusal.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_embeddings::{config::EmbeddingConfig, EmbeddingService, MockProvider};
use epigraph_mcp::tools::novelty_gate::{self, GateDecision, DEFAULT_NOVELTY_THRESHOLD};
use epigraph_mcp::types::{CheckAlreadyIngestedParams, DecideMatchCandidateParams};
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use rmcp::model::{CallToolResult, ContentBlock};
use sqlx::PgPool;
use uuid::Uuid;

/// A server built ONLY from a `ScopedPool` logged in as `epigraph_app`: the
/// plain pool is that pool's `inner()`, as in `main.rs`.
async fn app_server(pool: &PgPool) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = scoped.inner().clone();
    let role: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&plain)
        .await
        .expect("current_user");
    assert_eq!(
        role, "epigraph_app",
        "PREMISE: the server's plain pool must be the application role, or this file proves \
         nothing about row security"
    );
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0x3du8; 32]).expect("signer");
    let embedder = McpEmbedder::new(plain.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(plain, signer, embedder, false).with_scoped_pool(scoped)
}

/// An HTTP caller token naming `agent`, as `oauth/token.rs` mints one.
fn caller_token(agent: Uuid) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Agent,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

async fn viewer_of(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("viewer")
}

async fn content_hash_of(pool: &PgPool, claim: Uuid) -> Vec<u8> {
    sqlx::query_scalar("SELECT content_hash FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("content_hash")
}

fn json_of(result: &CallToolResult) -> serde_json::Value {
    match result.content.first().expect("content") {
        ContentBlock::Text(t) => serde_json::from_str(&t.text).expect("json"),
        other => panic!("expected text, got {other:?}"),
    }
}

/// The exact-resubmit probe: the member's own group-private claim is found as
/// the member (it was missed on the unstamped pool); a stranger's probe for the
/// same `(hash, author)` is not.
#[sqlx::test(migrations = "../../migrations")]
async fn the_exact_resubmit_probe_finds_the_members_own_private_claim(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "probe-member").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "probe-stranger").await;
    let private =
        fixture::seed_group_claim(&pool, member, group, "a private finding resubmitted").await;
    let hash = content_hash_of(&pool, private).await;
    let server = app_server(&pool).await;

    let mine =
        novelty_gate::exact_resubmit_probe(&server, &viewer_of(&pool, member).await, &hash, member)
            .await
            .expect("member probe");
    assert!(
        mine,
        "the member's resubmit of its own group-private claim must take the exact-resubmit \
         path on the application role"
    );

    let theirs = novelty_gate::exact_resubmit_probe(
        &server,
        &viewer_of(&pool, stranger).await,
        &hash,
        member,
    )
    .await
    .expect("stranger probe");
    assert!(
        !theirs,
        "a reader outside the group must not learn that the private claim exists"
    );
}

/// The repair-embed check after a content-hash dedup hit: the member sees that
/// its own group-private claim still lacks a vector (the unstamped pool could
/// not see the row and answered "nothing to embed"); a stranger sees nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn the_repair_embed_check_sees_the_members_own_private_claim(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "repair-member").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "repair-stranger").await;
    let text = "a private claim whose vector never landed";
    let private = fixture::seed_group_claim(&pool, member, group, text).await;
    let server = app_server(&pool).await;

    let mine = epigraph_mcp::claim_helper::claim_text_if_embedding_missing_as_caller(
        &server,
        &viewer_of(&pool, member).await,
        private,
    )
    .await
    .expect("member check");
    assert_eq!(
        mine.as_deref(),
        Some(text),
        "the member's dedup hit on its own unembedded private claim must be re-embedded"
    );

    let theirs = epigraph_mcp::claim_helper::claim_text_if_embedding_missing_as_caller(
        &server,
        &viewer_of(&pool, stranger).await,
        private,
    )
    .await
    .expect("stranger check");
    assert_eq!(
        theirs, None,
        "a stranger must not read the private claim's text"
    );
}

/// The novelty gate: an identical-text group-private neighbour suppresses the
/// member's submission (and reads back as the member); a stranger does not see
/// it and inserts.
#[sqlx::test(migrations = "../../migrations")]
async fn the_novelty_gate_sees_the_members_own_private_neighbour(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "gate-member").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "gate-stranger").await;
    let embedder = MockProvider::new(EmbeddingConfig::openai(1536));
    let text = "Group-private notes on the gate's neighbour lookup";
    let vector = EmbeddingService::generate(&embedder, text)
        .await
        .expect("mock embedding");
    let neighbour = fixture::seed_group_claim(&pool, member, group, "the private neighbour").await;
    fixture::set_claim_embedding(&pool, neighbour, &epigraph_db::pgvector_literal(&vector)).await;
    let server = app_server(&pool).await;

    let member_viewer = viewer_of(&pool, member).await;
    let (mine, _) = novelty_gate::decide(
        &server,
        &member_viewer,
        &embedder,
        text,
        DEFAULT_NOVELTY_THRESHOLD,
        &[],
    )
    .await
    .expect("the mock embedder works");
    assert_eq!(
        mine,
        GateDecision::ReturnExisting(neighbour),
        "the member's near-duplicate of its own group-private claim must be suppressed on the \
         application role (the unstamped pool hid the neighbour and inserted a copy)"
    );
    let read_back = novelty_gate::read_back_existing(&server, &member_viewer, neighbour)
        .await
        .expect("the member reads its own neighbour back");
    assert_eq!(read_back.id.as_uuid(), neighbour);

    let (theirs, _) = novelty_gate::decide(
        &server,
        &viewer_of(&pool, stranger).await,
        &embedder,
        text,
        DEFAULT_NOVELTY_THRESHOLD,
        &[],
    )
    .await
    .expect("the mock embedder works");
    assert_eq!(
        theirs,
        GateDecision::Insert,
        "a reader outside the group must neither be suppressed by nor learn of the private \
         neighbour"
    );
}

async fn seed_pending_candidate(pool: &PgPool, a: Uuid, b: Uuid) -> Uuid {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    sqlx::query_scalar(
        "INSERT INTO match_candidates (claim_a, claim_b, score, features, status) \
         VALUES ($1, $2, 0.97, '{}'::jsonb, 'pending') RETURNING id",
    )
    .bind(lo)
    .bind(hi)
    .fetch_one(pool)
    .await
    .expect("seed candidate")
}

async fn matcher_edges(pool: &PgPool, a: Uuid, b: Uuid) -> Vec<(Uuid, String)> {
    sqlx::query_as(
        "SELECT owner_group_id, visibility::text FROM edges \
         WHERE properties->>'source' = 'cross_source_matcher' \
           AND ((source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1))",
    )
    .bind(a)
    .bind(b)
    .fetch_all(pool)
    .await
    .expect("matcher edges")
}

async fn candidate_status(pool: &PgPool, id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM match_candidates WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("status")
}

/// `decide_match_candidate`'s promote over a pair touching the member's
/// group-private claim: refused for a stranger (who cannot read that claim),
/// and for the member it lands the matcher edge owned by the member's group.
/// On the unstamped pool the member got a false "not current" refusal.
#[sqlx::test(migrations = "../../migrations")]
async fn a_member_promotes_a_candidate_over_its_own_private_claim(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "promote-member").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "promote-stranger").await;
    let (author, _) = fixture::seed_agent_with_group(&pool, "promote-author").await;
    let private = fixture::seed_group_claim(&pool, member, group, "the member's claim").await;
    let public = fixture::seed_public_claim(&pool, author, "a public paraphrase").await;
    let candidate = seed_pending_candidate(&pool, private, public).await;
    let server = app_server(&pool).await;
    let promote = || DecideMatchCandidateParams {
        candidate_id: candidate.to_string(),
        verdict: "promote".to_string(),
    };

    let refused = tools::matching::decide_match_candidate(
        &server,
        &viewer_of(&pool, stranger).await,
        promote(),
        Some(&caller_token(stranger)),
    )
    .await;
    assert!(
        refused.is_err(),
        "a caller outside the group cannot read the private endpoint, so its promote must be \
         refused"
    );
    assert_eq!(candidate_status(&pool, candidate).await, "pending");
    assert!(matcher_edges(&pool, private, public).await.is_empty());

    let out = tools::matching::decide_match_candidate(
        &server,
        &viewer_of(&pool, member).await,
        promote(),
        Some(&caller_token(member)),
    )
    .await
    .expect("the member's promote of a pair touching its own private claim");
    assert_eq!(json_of(&out)["status"], "promoted");
    assert_eq!(
        matcher_edges(&pool, private, public).await,
        vec![(group, "group".to_string())],
        "the matcher edge lands owned by the private endpoint's group"
    );
}

/// `check_already_ingested` reads its `processed_by` stamp as the caller. The
/// stamp written on the member's stamped transaction is world-owned
/// (paper→agent is a structural edge), so the member AND a stranger both see
/// the document as ingested. Pinned so a later change of the stamp's tenancy
/// shows up here rather than as a silent re-ingest.
#[sqlx::test(migrations = "../../migrations")]
async fn a_processed_by_stamp_is_world_owned_and_read_as_the_caller(pool: PgPool) {
    let (member, _) = fixture::seed_agent_with_group(&pool, "ingest-member").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "ingest-stranger").await;
    let doi = "10.5555/raw-pool-probe";
    let paper = epigraph_db::PaperRepository::get_or_create(&pool, doi, Some("t"), None)
        .await
        .expect("paper");
    let server = app_server(&pool).await;
    let scoped = server_scoped(&pool).await;
    let mut tx = scoped
        .begin_as(&viewer_of(&pool, member).await)
        .await
        .expect("member tx");
    epigraph_db::EdgeRepository::create_processed_by_stamp_if_absent_conn(
        &mut tx,
        paper,
        member,
        "probe-pipeline",
        "test",
    )
    .await
    .expect("the member writes its stamp on its own stamped transaction");
    tx.commit().await.expect("commit");
    let (owner, visibility): (Uuid, String) = sqlx::query_as(
        "SELECT owner_group_id, visibility::text FROM edges \
         WHERE source_id = $1 AND relationship = 'processed_by'",
    )
    .bind(paper)
    .fetch_one(&pool)
    .await
    .expect("stamp");
    assert_eq!(
        (owner, visibility.as_str()),
        (fixture::world_group(&pool).await, "public"),
        "MEASUREMENT: a processed_by stamp is world-owned whoever writes it"
    );

    for (who, agent) in [("member", member), ("stranger", stranger)] {
        let out = tools::ingestion::check_already_ingested(
            &server,
            &viewer_of(&pool, agent).await,
            CheckAlreadyIngestedParams {
                doi: doi.to_string(),
                pipeline_version: Some("probe-pipeline".to_string()),
            },
        )
        .await
        .expect("check_already_ingested");
        assert_eq!(
            json_of(&out)["already_ingested"],
            true,
            "{who}: the world-owned stamp is visible on the application role"
        );
    }
}

/// A second app-role `ScopedPool` for writes the test makes AS an agent.
async fn server_scoped(pool: &PgPool) -> ScopedPool {
    let url = fixture::database_url_for(pool).await;
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("app-role ScopedPool")
}

/// The `OPERATED_BY` auth-lineage edge is written on the plain (unstamped)
/// pool. It joins two agents, so it is world-owned and admitted there; this
/// pins that, so the warn-only branch around it is not swallowing a refusal.
#[sqlx::test(migrations = "../../migrations")]
async fn the_auth_lineage_edge_lands_on_the_application_role(pool: PgPool) {
    let (principal, _) = fixture::seed_agent_with_group(&pool, "lineage-principal").await;
    let server = app_server(&pool).await;
    let mcp_agent = server.server_agent_id().await.expect("server agent");
    server.record_auth_lineage(Some(principal)).await;

    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT owner_group_id, visibility::text FROM edges \
         WHERE source_id = $1 AND target_id = $2 AND relationship = $3",
    )
    .bind(mcp_agent)
    .bind(principal)
    .bind(epigraph_core::edge::relationships::OPERATED_BY)
    .fetch_all(&pool)
    .await
    .expect("lineage edge");
    assert_eq!(
        rows,
        vec![(fixture::world_group(&pool).await, "public".to_string())],
        "the OPERATED_BY edge must land, world-owned, on an unstamped application session"
    );
}
