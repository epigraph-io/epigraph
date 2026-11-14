//! Document ingest's background work, on the application role: the detached
//! walk and the post-commit embedding loop are tracked by the server
//! (backlog b928ccc1), so a process that drains its tracker before exiting
//! ends with the walk committed and every claim it created embedded.
//!
//! Every pool the server holds is `epigraph_app` (NOSUPERUSER, NOBYPASSRLS);
//! seeding and assertions run on the harness pool. The embedder's provider is
//! replaced with `McpEmbedder::with_generator`, so vectors are stored without
//! a network call.
//!
//! `#[sqlx::test]` runs each test on a current-thread runtime, so a task the
//! tool spawned has not been polled when the tool returns: `running()` right
//! after the call counts exactly the tasks it left behind, deterministically.
//!
//! Verified to fail: with the detached walk spawned by a bare `tokio::spawn`,
//! `a_queued_ingest_is_tracked_until_its_walk_and_embeddings_finish` sees 0
//! tracked tasks; with the embedding loop spawned that way,
//! `a_waited_ingest_leaves_its_embedding_loop_tracked` does.
//!
//! The rest pin WHERE those vectors are stored (backlog 46902f71). A document
//! ingest that names no visibility lands in the author's team, or private,
//! never public. The embedder's own store path (`McpEmbedder::store_vector`)
//! resolves a claim's author by reading the claim as PUBLIC, so on such a
//! claim it stored nothing, and only a WARN said so. The ingest knows its
//! author, and its team-write grant when the author writes the team only
//! through its human (D-V3), so it stores through those. `consolidate_claims`
//! knows its acting agent the same way.
//!
//! Verified to fail: with both embedding loops and `consolidate_claims` back on
//! `McpEmbedder::embed_and_store`, the team, operated-agent, private, spine
//! and consolidate tests fail with 0 embedded; with the grant dropped from the
//! ingest store, only the operated-agent test fails (its author writes the
//! team through its human alone), which is the calibration that the grant is
//! what admits that row.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::sync::Arc;

use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_ingest::document::schema::DocumentExtraction;
use epigraph_mcp::background::BackgroundTasks;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::claims::submit_claim;
use epigraph_mcp::tools::consolidate::consolidate_claims;
use epigraph_mcp::tools::ingestion::{ingest_document_inline, ingest_document_spine};
use epigraph_mcp::types::{
    ConsolidateClaimsParams, IngestDocumentInlineParams, IngestDocumentSpineParams,
    SubmitClaimParams,
};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

/// An app-role stdio server whose embedder stores a fixed vector for any text.
async fn app_role_server(pool: &PgPool, seed: u8) -> EpiGraphMcpFull {
    app_role_server_with(pool, seed, true).await
}

/// [`app_role_server`], or with no embedding provider at all (`provider:
/// false`: no key and no generator, so `embeddings_disabled()` is true).
async fn app_role_server_with(pool: &PgPool, seed: u8, provider: bool) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let embedder =
        epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None).with_scoped_pool(scoped.clone());
    let embedder = if provider {
        embedder.with_generator(Arc::new(|_text: &str| Ok(vec![0.01_f32; 1536])))
    } else {
        embedder
    };
    EpiGraphMcpFull::new(plain, signer, embedder, /* read_only */ false).with_scoped_pool(scoped)
}

/// A full document: thesis, one section, one paragraph, two atoms.
fn doc(doi: &str) -> DocumentExtraction {
    serde_json::from_value(serde_json::json!({
        "source": {"title": format!("Background embed {doi}"), "doi": doi,
                   "source_type": "Paper", "authors": []},
        "thesis": format!("Background embed thesis {doi}"),
        "thesis_derivation": "TopDown",
        "sections": [{"title": "S", "paragraphs": [{
            "text": format!("Background embed paragraph {doi}"),
            "atoms": [format!("Background embed atom one {doi}"),
                      format!("Background embed atom two {doi}")],
            "generality": [3, 3], "confidence": 0.8
        }]}],
        "relationships": []
    }))
    .expect("extraction")
}

fn params(
    doi: &str,
    wait: bool,
    visibility: Option<&str>,
    group: Option<Uuid>,
) -> IngestDocumentInlineParams {
    IngestDocumentInlineParams {
        extraction: doc(doi),
        wait: Some(wait),
        visibility: visibility.map(str::to_string),
        group_id: group.map(|g| g.to_string()),
    }
}

/// Ingest over stdio (the server's own agent authors); the response body.
async fn ingest(server: &EpiGraphMcpFull, p: IngestDocumentInlineParams) -> serde_json::Value {
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("the stdio viewer");
    let out = ingest_document_inline(server, &viewer, p, None)
        .await
        .expect("the ingest");
    assert_ne!(out.is_error, Some(true), "{out:?}");
    let text = out
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("a text body");
    serde_json::from_str(&text).expect("a JSON body")
}

/// `(claims, embedded, visibility set)` over the document's `doi:` claims.
async fn doc_state(pool: &PgPool, doi: &str) -> (i64, i64, Vec<String>) {
    sqlx::query_as(
        "SELECT count(*), count(embedding), \
                coalesce(array_agg(DISTINCT visibility::text), '{}') \
           FROM claims WHERE $1 = ANY(labels)",
    )
    .bind(format!("doi:{doi}"))
    .fetch_one(pool)
    .await
    .expect("doc state")
}

async fn drained(tasks: &BackgroundTasks) {
    assert_eq!(
        tasks.drain(Duration::from_secs(60)).await,
        0,
        "every background task finishes inside the limit"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_queued_ingest_is_tracked_until_its_walk_and_embeddings_finish(pool: PgPool) {
    let server = app_role_server(&pool, 0xB1).await;
    let doi = "10.0/b928-queued";
    let body = ingest(&server, params(doi, false, Some("public"), None)).await;
    assert_eq!(body["status"], "queued", "{body}");

    let tasks = server.background_tasks();
    assert_eq!(
        tasks.running(),
        1,
        "the detached walk must be spawned on the server's tracker, or a stdio process \
         exits under it"
    );

    drained(&tasks).await;
    let (claims, embedded, _) = doc_state(&pool, doi).await;
    assert!(claims > 0, "the walk committed");
    assert_eq!(
        embedded, claims,
        "the walk's embedding loop is drained with it: every created claim has a vector"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_waited_ingest_leaves_its_embedding_loop_tracked(pool: PgPool) {
    let server = app_role_server(&pool, 0xB2).await;
    let doi = "10.0/b928-waited";
    let body = ingest(&server, params(doi, true, Some("public"), None)).await;
    let created = body["claims_ingested"].as_u64().unwrap_or(0);
    assert!(created > 0, "{body}");
    assert_eq!(
        body["claims_embedding_queued"].as_u64(),
        Some(created),
        "every created claim is queued: {body}"
    );

    let tasks = server.background_tasks();
    assert_eq!(
        tasks.running(),
        1,
        "the post-commit embedding loop must be spawned on the server's tracker"
    );
    drained(&tasks).await;
    let (claims, embedded, _) = doc_state(&pool, doi).await;
    assert_eq!(embedded, claims, "every created claim has a vector");
}

// ── Where the vectors are stored (backlog 46902f71) ────────────────────────

/// A keyed TEAM group with no members.
async fn team(pool: &PgPool, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, $2, 'did:epigraph:test-team:' || $1::text, $3, 'team')",
    )
    .bind(id)
    .bind(label)
    .bind(&key)
    .execute(pool)
    .await
    .expect("seed team");
    id
}

async fn add_member(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed membership");
}

/// `(owner_group_id)` set over the document's `doi:` claims.
async fn doc_owners(pool: &PgPool, doi: &str) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT DISTINCT owner_group_id FROM claims WHERE $1 = ANY(labels) ORDER BY 1",
    )
    .bind(format!("doi:{doi}"))
    .fetch_all(pool)
    .await
    .expect("doc owners")
}

/// A default ingest (no visibility named) with `wait`, drained; asserts the
/// claims landed with `visibility`, owned by `owner`, and every one embedded.
async fn assert_default_ingest_embedded(
    pool: &PgPool,
    server: &EpiGraphMcpFull,
    doi: &str,
    visibility: &str,
    owner: Uuid,
) {
    let body = ingest(server, params(doi, true, None, None)).await;
    assert!(body["claims_ingested"].as_u64().unwrap_or(0) > 0, "{body}");
    drained(&server.background_tasks()).await;
    let (claims, embedded, visibilities) = doc_state(pool, doi).await;
    assert_eq!(
        visibilities,
        vec![visibility.to_string()],
        "fixture: where the default ingest landed"
    );
    assert_eq!(
        doc_owners(pool, doi).await,
        vec![owner],
        "fixture: the owner"
    );
    assert_eq!(
        embedded, claims,
        "every claim a {visibility} ingest created must be embedded"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_default_ingest_into_the_authors_team_is_embedded(pool: PgPool) {
    let server = app_role_server(&pool, 0xB3).await;
    let author = server.server_agent_id().await.expect("server agent");
    let t = team(&pool, "ingest team").await;
    add_member(&pool, t, author, "writer").await;
    assert_default_ingest_embedded(&pool, &server, "10.0/4690-team", "group", t).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agents_default_ingest_into_its_humans_team_is_embedded(pool: PgPool) {
    let server = app_role_server(&pool, 0xB4).await;
    let author = server.server_agent_id().await.expect("server agent");
    let t = team(&pool, "human's team").await;
    let (human, _) = fixture::seed_human_operator(&pool, "ingest-human").await;
    add_member(&pool, t, human, "writer").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, author, human)
            .await
            .expect("live link");
    }
    // The author writes `t` only through its human: the grant is what admits
    // the embedding UPDATE on these rows.
    assert_default_ingest_embedded(&pool, &server, "10.0/4690-operated", "group", t).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_default_ingest_by_a_teamless_author_lands_private_and_is_embedded(pool: PgPool) {
    let server = app_role_server(&pool, 0xB5).await;
    let author = server.server_agent_id().await.expect("server agent");
    let home: Uuid = sqlx::query_scalar(
        "SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:' || $1::text",
    )
    .bind(author)
    .fetch_one(&pool)
    .await
    .expect("the author's personal group");
    // Private is `group` visibility on the author's home group.
    assert_default_ingest_embedded(&pool, &server, "10.0/4690-private", "group", home).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_default_spine_ingest_into_the_authors_team_is_embedded(pool: PgPool) {
    let server = app_role_server(&pool, 0xB7).await;
    let author = server.server_agent_id().await.expect("server agent");
    let t = team(&pool, "spine team").await;
    add_member(&pool, t, author, "writer").await;
    let doi = "10.0/4690-spine";
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&server, None)
        .await
        .expect("the stdio viewer");
    let mut extraction = doc(doi);
    for section in &mut extraction.sections {
        for paragraph in &mut section.paragraphs {
            paragraph.atoms.clear();
            paragraph.generality.clear();
        }
    }
    let out = ingest_document_spine(
        &server,
        &viewer,
        IngestDocumentSpineParams {
            extraction,
            visibility: None,
            group_id: None,
        },
        None,
    )
    .await
    .expect("the spine ingest");
    assert_ne!(out.is_error, Some(true), "{out:?}");
    drained(&server.background_tasks()).await;
    let (claims, embedded, visibilities) = doc_state(&pool, doi).await;
    assert!(claims > 0);
    assert_eq!(visibilities, vec!["group".to_string()], "fixture");
    assert_eq!(doc_owners(&pool, doi).await, vec![t], "fixture: the owner");
    assert_eq!(embedded, claims, "every spine node must be embedded");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_consolidated_team_claim_is_embedded(pool: PgPool) {
    let server = app_role_server(&pool, 0xB6).await;
    let author = server.server_agent_id().await.expect("server agent");
    let t = team(&pool, "consolidate team").await;
    add_member(&pool, t, author, "writer").await;
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&server, None)
        .await
        .expect("the stdio viewer");

    let mut sources = Vec::new();
    for content in ["consolidate source one", "consolidate source two"] {
        let out = submit_claim(
            &server,
            &viewer,
            SubmitClaimParams {
                content: content.to_string(),
                methodology: "direct_observation".to_string(),
                evidence_data: format!("evidence for {content}"),
                evidence_type: "empirical".to_string(),
                confidence: 0.8,
                source_url: None,
                reasoning: None,
                labels: vec![],
                // The generator returns one vector for every text, so the
                // gate would otherwise fold the second source into the first.
                novelty_threshold: Some(0.0),
                visibility: None,
                group_id: None,
            },
            None,
        )
        .await
        .expect("a team source");
        let text = out.content[0].as_text().expect("text").text.clone();
        let body: serde_json::Value = serde_json::from_str(&text).expect("json");
        sources.push(Uuid::parse_str(body["claim_id"].as_str().expect("id")).expect("uuid"));
    }

    let out = consolidate_claims(
        &server,
        &viewer,
        ConsolidateClaimsParams {
            source_claim_ids: sources.iter().map(ToString::to_string).collect(),
            merged_content: "consolidated team claim".to_string(),
            mode: "merge".to_string(),
            reason: "test".to_string(),
            confidence: Some(0.8),
        },
        None,
    )
    .await
    .expect("the merge");
    let text = out.content[0].as_text().expect("text").text.clone();
    let body: serde_json::Value = serde_json::from_str(&text).expect("json");
    let merged = Uuid::parse_str(body["merged_claim_id"].as_str().expect("id")).expect("uuid");
    let (visibility, embedded): (String, bool) =
        sqlx::query_as("SELECT visibility::text, embedding IS NOT NULL FROM claims WHERE id = $1")
            .bind(merged)
            .fetch_one(&pool)
            .await
            .expect("the merged claim");
    assert_eq!(visibility, "group", "fixture: the merge stays in the team");
    assert!(embedded, "the merged team claim must be embedded");
    assert_eq!(
        body["embedded"], true,
        "and the response must say so: {body}"
    );
}

// ── What the response says was embedded (backlog fdacc14f) ─────────────────

/// With no embedding provider, nothing is queued and the response says 0, in
/// both the new field and its deprecated alias; no task is left behind.
/// Verified to fail: with the `embeddings_disabled` check removed from the
/// queueing helper (the old behaviour, `claims_embedded: queue.len()`), the
/// document walk reports all 5 created claims as queued.
#[sqlx::test(migrations = "../../migrations")]
async fn a_server_with_no_embedding_provider_reports_nothing_queued(pool: PgPool) {
    let server = app_role_server_with(&pool, 0xB8, false).await;
    let body = ingest(&server, params("10.0/fdac-doc", true, Some("public"), None)).await;
    assert!(body["claims_ingested"].as_u64().unwrap_or(0) > 0, "{body}");
    assert_eq!(body["claims_embedding_queued"], 0, "{body}");
    assert_eq!(
        body["claims_embedded"], 0,
        "the deprecated alias too: {body}"
    );
    assert_eq!(server.background_tasks().running(), 0, "no embedding task");

    let viewer = epigraph_mcp::tools::viewer::request_viewer(&server, None)
        .await
        .expect("the stdio viewer");
    let mut extraction = doc("10.0/fdac-spine");
    for section in &mut extraction.sections {
        for paragraph in &mut section.paragraphs {
            paragraph.atoms.clear();
            paragraph.generality.clear();
        }
    }
    let out = ingest_document_spine(
        &server,
        &viewer,
        IngestDocumentSpineParams {
            extraction,
            visibility: Some("public".to_string()),
            group_id: None,
        },
        None,
    )
    .await
    .expect("the spine ingest");
    let text = out.content[0].as_text().expect("text").text.clone();
    let body: serde_json::Value = serde_json::from_str(&text).expect("json");
    assert!(body["paragraphs_new"].as_u64().unwrap_or(0) > 0, "{body}");
    assert_eq!(body["paragraphs_embedding_queued"], 0, "{body}");
    assert_eq!(
        body["paragraphs_embedded"], 0,
        "the deprecated alias too: {body}"
    );
    assert_eq!(server.background_tasks().running(), 0, "no embedding task");
}
