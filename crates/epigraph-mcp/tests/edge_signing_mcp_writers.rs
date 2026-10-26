//! Rulings R-49 / R-50 (backlog `dae795f8`): every MCP edge writer attests the
//! edge it INSERTS with the server's key. The row carries the attestation
//! digest, the v1 edge signature and `signer_id` = the server's signer agent
//! (never the edge's author), and `EdgeSignatureRepository::verify_conn`
//! reports it signed, valid as v1, matching its row, by that agent.
//!
//! One test per writer family, each reading the edges back from the table:
//! submit_claim / memorize (AUTHORED, DERIVED_FROM, HAS_TRACE through the
//! verb-edge helper), the link tools (link_epistemic's symmetric and directed
//! arms, link_alternative, link_hierarchical), ingest_document and
//! ingest_document_spine (authored, asserts, the plan's relationships and the
//! world-owned `processed_by` stamp), create_perspective (PERSPECTIVE_OF),
//! resolve_backlog_item (justifies) and the auth-lineage OPERATED_BY edge. A
//! dedup hit returns the existing edge and writes nothing onto it.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::build_scoped_test_server;
use epigraph_crypto::{AgentSigner, SignatureScheme};
use epigraph_db::repos::EdgeSignatureRepository;
use epigraph_mcp::EpiGraphMcpFull;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// The key every `build_scoped_test_server` signs with.
fn server_key() -> [u8; 32] {
    AgentSigner::from_bytes(&[0xA7u8; 32])
        .expect("signer")
        .public_key()
}

async fn server(pool: &PgPool) -> EpiGraphMcpFull {
    build_scoped_test_server(pool.clone(), fixture::scoped_pool(pool).await)
}

/// The server's signer agent (created by the server's first write).
async fn signer_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM agents WHERE public_key = $1")
        .bind(server_key().as_slice())
        .fetch_one(pool)
        .await
        .expect("the server's signer agent")
}

/// The edge carries a verifying v1 attestation by the server's signer agent
/// over the row as stored.
async fn assert_server_attested(pool: &PgPool, edge: Uuid, what: &str) {
    let (_scoped, viewer) = fixture::bypass(pool).await;
    let mut conn = pool.acquire().await.expect("conn");
    let check = EdgeSignatureRepository::verify_conn(&mut conn, &viewer, edge)
        .await
        .expect("verify")
        .unwrap_or_else(|| panic!("{what}: edge {edge} not readable"));
    let signer = signer_agent(pool).await;
    assert!(
        check.signed && check.signature_valid,
        "{what}: edge {edge}: {check:?}"
    );
    assert_eq!(
        check.signature_scheme,
        Some(SignatureScheme::V1),
        "{what}: {check:?}"
    );
    assert_eq!(check.content_matches, Some(true), "{what}: {check:?}");
    assert_eq!(check.signer_id, Some(signer), "{what}: {check:?}");
}

/// The ids of edges with `relationship` touching `endpoint` (either side).
async fn edges_of(pool: &PgPool, endpoint: Uuid, relationship: &str) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT id FROM edges WHERE (source_id = $1 OR target_id = $1) \
            AND relationship = $2 ORDER BY created_at, id",
    )
    .bind(endpoint)
    .bind(relationship)
    .fetch_all(pool)
    .await
    .expect("edges")
}

async fn stored_attestation(pool: &PgPool, edge: Uuid) -> (Option<Vec<u8>>, Option<Uuid>) {
    sqlx::query_as("SELECT signature, signer_id FROM edges WHERE id = $1")
        .bind(edge)
        .fetch_one(pool)
        .await
        .expect("edge row")
}

fn uuid_field(v: &Value, key: &str) -> Uuid {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} in {v}"))
        .parse()
        .expect("uuid")
}

async fn submit(server: &EpiGraphMcpFull, pool: &PgPool, content: &str) -> Uuid {
    let viewer = fixture::public_viewer(pool).await;
    let out = epigraph_mcp::tools::claims::submit_claim(
        server,
        &viewer,
        epigraph_mcp::types::SubmitClaimParams {
            content: content.into(),
            methodology: "deductive_logic".into(),
            evidence_data: format!("evidence for {content}"),
            evidence_type: "logical".into(),
            confidence: 0.6,
            source_url: None,
            reasoning: Some("because".into()),
            labels: vec![],
            novelty_threshold: None,
        },
        None,
    )
    .await
    .expect("submit_claim");
    uuid_field(&common::first_text(&out), "claim_id")
}

/// submit_claim's AUTHORED (agent -> claim, world-owned), DERIVED_FROM and
/// HAS_TRACE, and memorize's AUTHORED: all attested at INSERT.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_claim_and_memorize_attest_their_verb_edges(pool: PgPool) {
    let server = server(&pool).await;
    let claim = submit(&server, &pool, "R-49: submit_claim's verb-edges are signed").await;
    for rel in ["AUTHORED", "DERIVED_FROM", "HAS_TRACE"] {
        let edges = edges_of(&pool, claim, rel).await;
        assert_eq!(edges.len(), 1, "{rel}: {edges:?}");
        assert_server_attested(&pool, edges[0], &format!("submit_claim {rel}")).await;
    }

    let viewer = fixture::public_viewer(&pool).await;
    let out = epigraph_mcp::tools::memory::memorize(
        &server,
        &viewer,
        epigraph_mcp::types::MemorizeParams {
            content: "R-49: memorize's AUTHORED edge is signed".into(),
            confidence: None,
            tags: None,
            novelty_threshold: None,
        },
        None,
    )
    .await
    .expect("memorize");
    let memo = uuid_field(&common::first_text(&out), "claim_id");
    let edges = edges_of(&pool, memo, "AUTHORED").await;
    assert_eq!(edges.len(), 1, "{edges:?}");
    assert_server_attested(&pool, edges[0], "memorize AUTHORED").await;
}

/// The link tools attest the edge they INSERT, and a dedup hit (the same link
/// asserted again, or onto an edge another writer left unsigned) writes
/// nothing onto the existing row.
#[sqlx::test(migrations = "../../migrations")]
async fn the_link_tools_attest_their_edges_and_not_a_dedup_hit(pool: PgPool) {
    use epigraph_mcp::types::{LinkAlternativeParams, LinkEpistemicParams, LinkHierarchicalParams};
    let server = server(&pool).await;
    let viewer = fixture::public_viewer(&pool).await;
    let c: Vec<Uuid> = {
        let mut v = Vec::new();
        for i in 0..8 {
            v.push(submit(&server, &pool, &format!("R-49 link endpoint {i}")).await);
        }
        v
    };
    let epistemic = |s: Uuid, t: Uuid, rel: &str| LinkEpistemicParams {
        source_claim_id: s.to_string(),
        target_claim_id: t.to_string(),
        relationship: rel.to_string(),
        properties: None,
    };

    // link_epistemic, directed arm.
    let out = epigraph_mcp::tools::link_epistemic::do_link_epistemic(
        &server,
        &viewer,
        epistemic(c[0], c[1], "supports"),
        None,
    )
    .await
    .expect("link_epistemic supports");
    let supports = uuid_field(&common::first_text(&out), "edge_id");
    assert_server_attested(&pool, supports, "link_epistemic supports").await;
    let before = stored_attestation(&pool, supports).await;
    let again = epigraph_mcp::tools::link_epistemic::do_link_epistemic(
        &server,
        &viewer,
        epistemic(c[0], c[1], "supports"),
        None,
    )
    .await
    .expect("link_epistemic supports again");
    assert_eq!(uuid_field(&common::first_text(&again), "edge_id"), supports);
    assert_eq!(stored_attestation(&pool, supports).await, before);

    // link_epistemic, symmetric arm.
    let out = epigraph_mcp::tools::link_epistemic::do_link_epistemic(
        &server,
        &viewer,
        epistemic(c[2], c[3], "contradicts"),
        None,
    )
    .await
    .expect("link_epistemic contradicts");
    let contradicts = uuid_field(&common::first_text(&out), "edge_id");
    assert_server_attested(&pool, contradicts, "link_epistemic contradicts").await;

    // link_alternative.
    let out = epigraph_mcp::tools::link_alternative::do_link_alternative(
        &server,
        &viewer,
        LinkAlternativeParams {
            claim_a: c[4].to_string(),
            claim_b: c[5].to_string(),
            target_claim_id: None,
            rationale: Some("two routes".into()),
        },
        None,
    )
    .await
    .expect("link_alternative");
    let alt = uuid_field(&common::first_text(&out), "edge_id");
    assert_server_attested(&pool, alt, "link_alternative").await;

    // link_hierarchical, then a dedup hit onto an edge another writer left
    // unsigned: the tool returns it and writes nothing onto it.
    let hier = |s: Uuid, t: Uuid| LinkHierarchicalParams {
        source_claim_id: s.to_string(),
        target_claim_id: t.to_string(),
        relationship: "decomposes_to".to_string(),
        properties: None,
    };
    let out = epigraph_mcp::tools::link_hierarchical::do_link_hierarchical(
        &server,
        &viewer,
        hier(c[6], c[7]),
        None,
    )
    .await
    .expect("link_hierarchical");
    let h = uuid_field(&common::first_text(&out), "edge_id");
    assert_server_attested(&pool, h, "link_hierarchical").await;

    common::insert_claim_edge(&pool, c[7], c[6], "decomposes_to").await;
    let unsigned = edges_of(&pool, c[7], "decomposes_to")
        .await
        .into_iter()
        .find(|e| *e != h)
        .expect("the seeded edge");
    let out = epigraph_mcp::tools::link_hierarchical::do_link_hierarchical(
        &server,
        &viewer,
        hier(c[7], c[6]),
        None,
    )
    .await
    .expect("link_hierarchical dedup");
    let body = common::first_text(&out);
    assert_eq!(uuid_field(&body, "edge_id"), unsigned, "{body}");
    assert_eq!(body["created"], Value::Bool(false), "{body}");
    assert_eq!(
        stored_attestation(&pool, unsigned).await,
        (None, None),
        "a dedup hit signed another writer's edge"
    );
}

fn extraction(tag: &str) -> epigraph_ingest::schema::DocumentExtraction {
    serde_json::from_value(serde_json::json!({
        "source": {
            "title": format!("dae795f8 {tag}: Signed Edges"),
            "doi": format!("10.9999/dae795f8-{tag}"),
            "source_type": "Paper",
            "authors": [{"name": "Alice Author", "affiliations": [], "roles": ["author"]}]
        },
        "thesis": format!("dae795f8 {tag}: an ingested edge carries its attestation."),
        "thesis_derivation": "TopDown",
        "sections": [{
            "title": "Methods",
            "paragraphs": [{
                "text": format!("dae795f8 {tag}: the walk signs every edge it writes."),
                "atoms": [format!("dae795f8 {tag}: an atom's edges are signed.")],
                "generality": [1],
                "confidence": 0.9
            }]
        }],
        "relationships": []
    }))
    .expect("fixture parses")
}

/// Every edge an ingest walk wrote is attested by the server; at least the
/// named relationships are present, so the check cannot pass vacuously.
async fn assert_every_edge_attested(pool: &PgPool, tool: &str, must_have: &[&str]) {
    let edges: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, relationship::text FROM edges ORDER BY created_at, id")
            .fetch_all(pool)
            .await
            .expect("edges");
    for rel in must_have {
        assert!(
            edges.iter().any(|(_, r)| r == rel),
            "{tool}: no {rel} edge to check: {edges:?}"
        );
    }
    for (id, rel) in edges {
        assert_server_attested(pool, id, &format!("{tool} {rel}")).await;
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn ingest_document_attests_every_edge_it_writes(pool: PgPool) {
    let server = server(&pool).await;
    let viewer = fixture::public_viewer(&pool).await;
    epigraph_mcp::tools::ingestion::do_ingest_document(
        &server,
        &viewer,
        &extraction("document"),
        None,
    )
    .await
    .expect("document ingests");
    assert_every_edge_attested(
        &pool,
        "ingest_document",
        &["authored", "asserts", "decomposes_to", "processed_by"],
    )
    .await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn ingest_document_spine_attests_every_edge_it_writes(pool: PgPool) {
    let server = server(&pool).await;
    let viewer = fixture::public_viewer(&pool).await;
    epigraph_mcp::tools::ingestion::do_ingest_document_spine(
        &server,
        &viewer,
        &extraction("spine"),
        None,
    )
    .await
    .expect("spine ingests");
    assert_every_edge_attested(
        &pool,
        "ingest_document_spine",
        &["authored", "asserts", "processed_by"],
    )
    .await;
}

/// create_perspective's PERSPECTIVE_OF (perspective -> agent, world-owned).
#[sqlx::test(migrations = "../../migrations")]
async fn create_perspective_attests_its_perspective_of_edge(pool: PgPool) {
    let server = server(&pool).await;
    let viewer = fixture::public_viewer(&pool).await;
    let out = epigraph_mcp::tools::perspectives::create_perspective(
        &server,
        &viewer,
        epigraph_mcp::types::CreatePerspectiveParams {
            name: "R-49 perspective".into(),
            description: None,
            owner_agent_id: None,
            perspective_type: None,
            frame_ids: None,
            extraction_method: None,
            confidence_calibration: None,
        },
        None,
    )
    .await
    .expect("create_perspective");
    let perspective = uuid_field(&common::first_text(&out), "perspective_id");
    let edges = edges_of(&pool, perspective, "PERSPECTIVE_OF").await;
    assert_eq!(edges.len(), 1, "{edges:?}");
    assert_server_attested(&pool, edges[0], "create_perspective PERSPECTIVE_OF").await;
}

/// resolve_backlog_item's `justifies` closure-basis edges.
#[sqlx::test(migrations = "../../migrations")]
async fn resolve_backlog_item_attests_its_basis_edges(pool: PgPool) {
    let server = server(&pool).await;
    let viewer = fixture::public_viewer(&pool).await;
    let basis = submit(&server, &pool, "R-49: the measurement that closed it").await;
    let item = submit(&server, &pool, "R-49: an open backlog item").await;
    sqlx::query("UPDATE claims SET labels = ARRAY['backlog']::text[] WHERE id = $1")
        .bind(item)
        .execute(&pool)
        .await
        .expect("label the item backlog");
    let out = epigraph_mcp::tools::claims::resolve_backlog_item(
        &server,
        &viewer,
        epigraph_mcp::types::ResolveBacklogItemParams {
            original_id: item.to_string(),
            resolution_content: "Closed: the run agrees.".into(),
            methodology: None,
            basis_claim_ids: vec![basis.to_string()],
        },
        None,
    )
    .await
    .expect("resolve_backlog_item");
    let resolution = uuid_field(&common::first_text(&out), "resolution_claim_id");
    let edges = edges_of(
        &pool,
        resolution,
        epigraph_mcp::tools::claims::JUSTIFIES_RELATIONSHIP,
    )
    .await;
    assert_eq!(edges.len(), 1, "{edges:?}");
    assert_server_attested(&pool, edges[0], "resolve_backlog_item justifies").await;
}

/// The auth-lineage OPERATED_BY edge (server agent -> principal, world-owned).
#[sqlx::test(migrations = "../../migrations")]
async fn the_auth_lineage_edge_is_attested(pool: PgPool) {
    let server = server(&pool).await;
    let principal = common::seed_agent(&pool).await;
    server.record_auth_lineage(Some(principal)).await;
    let edges = edges_of(
        &pool,
        principal,
        epigraph_core::edge::relationships::OPERATED_BY,
    )
    .await;
    assert_eq!(edges.len(), 1, "{edges:?}");
    assert_server_attested(&pool, edges[0], "auth lineage OPERATED_BY").await;
}
