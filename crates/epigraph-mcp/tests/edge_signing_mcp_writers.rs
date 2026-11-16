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
            visibility: Some("public".to_string()),
            group_id: None,
            dataset: None,
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
            visibility: Some("public".to_string()),
            group_id: None,
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
        for i in 0..10 {
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
    // The symmetric arm's dedup hit, from the reverse direction.
    let before = stored_attestation(&pool, contradicts).await;
    let again = epigraph_mcp::tools::link_epistemic::do_link_epistemic(
        &server,
        &viewer,
        epistemic(c[3], c[2], "contradicts"),
        None,
    )
    .await
    .expect("link_epistemic contradicts reversed");
    assert_eq!(
        uuid_field(&common::first_text(&again), "edge_id"),
        contradicts
    );
    assert_eq!(stored_attestation(&pool, contradicts).await, before);
    // And onto another writer's UNSIGNED symmetric edge: returned, not signed.
    common::insert_claim_edge(&pool, c[8], c[9], "contradicts").await;
    let foreign = edges_of(&pool, c[8], "contradicts").await;
    assert_eq!(foreign.len(), 1, "{foreign:?}");
    let out = epigraph_mcp::tools::link_epistemic::do_link_epistemic(
        &server,
        &viewer,
        epistemic(c[9], c[8], "contradicts"),
        None,
    )
    .await
    .expect("link_epistemic onto an unsigned symmetric edge");
    assert_eq!(uuid_field(&common::first_text(&out), "edge_id"), foreign[0]);
    assert_eq!(
        stored_attestation(&pool, foreign[0]).await,
        (None, None),
        "a symmetric dedup hit signed another writer's edge"
    );

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
        ..Default::default()
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

fn extraction(tag: &str) -> epigraph_ingest::document::schema::DocumentExtraction {
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
            }, {
                "text": format!("dae795f8 {tag}: a second paragraph supports the first."),
                "atoms": [format!("dae795f8 {tag}: the plan's relationships are signed too.")],
                "generality": [1],
                "confidence": 0.9
            }]
        }],
        // An extraction relationship between two paragraphs, so the walks'
        // plan-relationship INSERT sites write a row (the spine skips atom
        // edges, not paragraph ones).
        "relationships": [{
            "source_path": "sections/0/paragraphs/1",
            "target_path": "sections/0/paragraphs/0",
            "relationship": "supports"
        }]
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
        epigraph_core::VisibilityChoice::Public,
    )
    .await
    .expect("document ingests");
    assert_every_edge_attested(
        &pool,
        "ingest_document",
        &[
            "authored",
            "asserts",
            "decomposes_to",
            "supports",
            "processed_by",
        ],
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
        epigraph_core::VisibilityChoice::Public,
    )
    .await
    .expect("spine ingests");
    assert_every_edge_attested(
        &pool,
        "ingest_document_spine",
        &[
            "authored",
            "asserts",
            "decomposes_to",
            "supports",
            "processed_by",
        ],
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

/// The claim was AUTHORED by `caller` (the precondition that makes "the signer
/// is the server, not the caller" mean something: with no token the author IS
/// the server agent, and author and signer collapse).
async fn assert_authored_by(pool: &PgPool, claim: Uuid, caller: Uuid) {
    let author: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("claim");
    assert_eq!(author, caller, "claim {claim} is not caller-authored");
}

/// The edge is attested by the server's signer agent, which is not `caller`.
async fn assert_server_not_caller(pool: &PgPool, edge: Uuid, caller: Uuid, what: &str) {
    assert_server_attested(pool, edge, what).await;
    let (_, signer) = stored_attestation(pool, edge).await;
    assert_ne!(
        signer,
        Some(caller),
        "{what}: the caller signed edge {edge}"
    );
}

/// R-49's distinguishing clause on the MCP transport: an authenticated
/// CALLER's writes are authored by the caller, and their edges are signed by
/// the SERVER's signer agent, never by the caller. submit_claim's AUTHORED
/// (caller -> claim) and DERIVED_FROM, and link_epistemic's edge between two
/// caller-authored claims.
#[sqlx::test(migrations = "../../migrations")]
async fn a_callers_edges_are_signed_by_the_server_not_the_caller(pool: PgPool) {
    use epigraph_mcp::types::LinkEpistemicParams;
    let server = server(&pool).await;
    let server_agent = server.server_agent_id().await.expect("server agent");
    let (caller, token, viewer) =
        common::seed_caller(&pool, &["claims:read", "claims:write"]).await;
    assert_ne!(caller, server_agent);

    let mut claims = Vec::new();
    for i in 0..2 {
        let out = epigraph_mcp::tools::claims::submit_claim(
            &server,
            &viewer,
            epigraph_mcp::types::SubmitClaimParams {
                content: format!("R-49 caller-authored claim {i}"),
                methodology: "deductive_logic".into(),
                evidence_data: format!("evidence for caller claim {i}"),
                evidence_type: "logical".into(),
                confidence: 0.6,
                source_url: None,
                reasoning: Some("because".into()),
                labels: vec![],
                novelty_threshold: Some(0.0),
                visibility: Some("public".to_string()),
                group_id: None,
                dataset: None,
            },
            Some(&token),
        )
        .await
        .expect("submit_claim as the caller");
        let claim = uuid_field(&common::first_text(&out), "claim_id");
        assert_authored_by(&pool, claim, caller).await;
        claims.push(claim);
    }
    let authored = edges_of(&pool, claims[0], "AUTHORED").await;
    assert_eq!(authored.len(), 1, "{authored:?}");
    let (source,): (Uuid,) = sqlx::query_as("SELECT source_id FROM edges WHERE id = $1")
        .bind(authored[0])
        .fetch_one(&pool)
        .await
        .expect("AUTHORED");
    assert_eq!(source, caller, "the AUTHORED edge names the caller");
    assert_server_not_caller(&pool, authored[0], caller, "caller submit_claim AUTHORED").await;
    let derived = edges_of(&pool, claims[0], "DERIVED_FROM").await;
    assert_eq!(derived.len(), 1, "{derived:?}");
    assert_server_not_caller(
        &pool,
        derived[0],
        caller,
        "caller submit_claim DERIVED_FROM",
    )
    .await;

    let out = epigraph_mcp::tools::link_epistemic::do_link_epistemic(
        &server,
        &viewer,
        LinkEpistemicParams {
            source_claim_id: claims[0].to_string(),
            target_claim_id: claims[1].to_string(),
            relationship: "supports".into(),
            properties: None,
        },
        Some(&token),
    )
    .await
    .expect("link_epistemic as the caller");
    let link = uuid_field(&common::first_text(&out), "edge_id");
    assert_server_not_caller(&pool, link, caller, "caller link_epistemic").await;
}

/// ingest_document by an authenticated caller: the ingested claims are
/// authored by the caller, every edge the walk wrote is signed by the server
/// (not the caller), and verify_claim reports a caller-authored, server-signed
/// claim valid (author != signer, through the shared admission rule).
#[sqlx::test(migrations = "../../migrations")]
async fn a_callers_ingest_is_signed_by_the_server_not_the_caller(pool: PgPool) {
    let server = server(&pool).await;
    let server_agent = server.server_agent_id().await.expect("server agent");
    let (caller, token, viewer) =
        common::seed_caller(&pool, &["claims:read", "claims:write"]).await;
    epigraph_mcp::tools::ingestion::do_ingest_document(
        &server,
        &viewer,
        &extraction("caller"),
        Some(&token),
        epigraph_core::VisibilityChoice::Public,
    )
    .await
    .expect("document ingests as the caller");

    let ingested: Vec<(Uuid, Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, agent_id, signer_id FROM claims WHERE content LIKE 'dae795f8 caller:%'",
    )
    .fetch_all(&pool)
    .await
    .expect("ingested claims");
    assert!(!ingested.is_empty(), "nothing ingested");
    for (id, author, signer) in &ingested {
        assert_eq!(*author, caller, "claim {id} is not caller-authored");
        assert_eq!(*signer, Some(server_agent), "claim {id}'s signer");
    }
    let edges: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM edges ORDER BY created_at, id")
        .fetch_all(&pool)
        .await
        .expect("edges");
    assert!(!edges.is_empty(), "the walk wrote no edge");
    for e in edges {
        assert_server_not_caller(&pool, e, caller, "caller ingest_document").await;
    }

    let out = epigraph_mcp::tools::claims::verify_claim(
        &server,
        &viewer,
        epigraph_mcp::types::VerifyClaimParams {
            claim_id: ingested[0].0.to_string(),
        },
    )
    .await
    .expect("verify_claim");
    let resp = common::first_text(&out);
    assert_eq!(resp["signature_valid"], Value::Bool(true), "{resp}");
}

// ── The workflow writers (epigraph-ingest-executor) ─────────────────────────

/// A two-phase, two-steps-per-phase workflow with one named author, so the
/// walk writes every plan relationship it has: `executes`, `decomposes_to`,
/// `step_follows`, `phase_follows` and the author's `asserts`.
fn workflow(canonical: &str, generation: u32) -> epigraph_ingest::workflow::WorkflowExtraction {
    let step = |s: &str| {
        serde_json::json!({
            "compound": format!("dae795f8 {canonical} g{generation}: {s}"),
            "rationale": "because",
            "operations": [format!("dae795f8 {canonical} g{generation}: {s} op")],
            "generality": [1],
            "confidence": 0.7
        })
    };
    serde_json::from_value(serde_json::json!({
        "source": {
            "canonical_name": canonical,
            "goal": format!("dae795f8 signed workflow {canonical} g{generation}"),
            "generation": generation,
            "authors": [{"name": "A Signing Designer"}],
            "tags": []
        },
        "thesis": format!("dae795f8 {canonical} g{generation}: the thesis"),
        "thesis_derivation": "TopDown",
        "phases": [
            {"title": "One", "summary": format!("dae795f8 {canonical} g{generation}: phase one"),
             "steps": [step("first"), step("second")]},
            {"title": "Two", "summary": format!("dae795f8 {canonical} g{generation}: phase two"),
             "steps": [step("third"), step("fourth")]}
        ],
        "relationships": []
    }))
    .expect("a well-formed workflow extraction")
}

async fn edge_ids(pool: &PgPool) -> std::collections::HashSet<Uuid> {
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM edges")
        .fetch_all(pool)
        .await
        .expect("edge ids")
        .into_iter()
        .collect()
}

/// Every edge written since `before` is attested by the server's signer agent
/// (and not by `caller`, when there is one); returns their relationships, so
/// the caller can require the ones it means to cover and the check cannot
/// pass vacuously.
async fn assert_new_edges_attested(
    pool: &PgPool,
    before: &std::collections::HashSet<Uuid>,
    caller: Option<Uuid>,
    what: &str,
) -> std::collections::BTreeSet<String> {
    let new: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, relationship::text FROM edges ORDER BY created_at, id")
            .fetch_all(pool)
            .await
            .expect("edges");
    let mut rels = std::collections::BTreeSet::new();
    for (id, rel) in new.into_iter().filter(|(id, _)| !before.contains(id)) {
        let label = format!("{what} {rel}");
        match caller {
            Some(c) => assert_server_not_caller(pool, id, c, &label).await,
            None => assert_server_attested(pool, id, &label).await,
        }
        rels.insert(rel);
    }
    rels
}

fn require(rels: &std::collections::BTreeSet<String>, must: &[&str], what: &str) {
    for rel in must {
        assert!(
            rels.contains(*rel),
            "{what}: no {rel} edge was written: {rels:?}"
        );
    }
}

fn step_claim(out: &rmcp::model::CallToolResult) -> Uuid {
    uuid_field(&common::first_text(out), "step_claim_id")
}

async fn add_step_at(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    auth: Option<&epigraph_auth::AuthContext>,
    canonical: &str,
    text: &str,
    position: Option<u32>,
) -> Uuid {
    let out = epigraph_mcp::tools::step_ops::add_step(
        server,
        viewer,
        epigraph_mcp::tools::step_ops::AddStepParams {
            canonical_name: canonical.to_string(),
            step_text: text.to_string(),
            position,
        },
        auth,
    )
    .await
    .unwrap_or_else(|e| panic!("add_step {text:?} at {position:?}: {e:?}"));
    step_claim(&out)
}

/// The executor's edge writers, over MCP stdio: `store_workflow`'s plan walk
/// (`execute_plan`: `executes`, the plan edges, a new generation's
/// `variant_of`), the `AUTHORED` record of every claim it created
/// (`record_caller_authorship`), and `add_step`'s `executes`, `decomposes_to`
/// and `step_follows` on all three arms (append, insert at the head, and the
/// mid-chain rewire that writes two). Every edge each call wrote is attested
/// at INSERT by the server's key; an idempotent re-ingest writes no edge.
#[sqlx::test(migrations = "../../migrations")]
async fn the_workflow_writers_attest_every_edge_they_write(pool: PgPool) {
    use epigraph_mcp::types::IngestWorkflowParams;
    let server = server(&pool).await;
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&server, None)
        .await
        .expect("stdio viewer");
    let ingest = |generation: u32| {
        let server = &server;
        let viewer = &viewer;
        async move {
            epigraph_mcp::tools::workflow_ingest::ingest_workflow(
                server,
                viewer,
                IngestWorkflowParams {
                    extraction: workflow("sw-wf", generation),
                    tenancy: None,
                    embed: None,
                },
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("ingest generation {generation}: {e:?}"))
        }
    };

    let before = edge_ids(&pool).await;
    ingest(0).await;
    let rels = assert_new_edges_attested(&pool, &before, None, "ingest g0").await;
    require(
        &rels,
        &[
            "executes",
            "decomposes_to",
            "step_follows",
            "phase_follows",
            "asserts",
            "AUTHORED",
        ],
        "ingest g0",
    );

    // An idempotent re-ingest writes nothing.
    let before = edge_ids(&pool).await;
    ingest(0).await;
    assert_eq!(edge_ids(&pool).await, before, "a re-ingest wrote an edge");

    // A new generation of the lineage: its variant_of edge to generation 0.
    let before = edge_ids(&pool).await;
    ingest(1).await;
    let rels = assert_new_edges_attested(&pool, &before, None, "ingest g1").await;
    require(&rels, &["variant_of", "executes", "AUTHORED"], "ingest g1");

    // add_step: append, insert at the head, and a mid-chain rewire.
    for (text, position) in [
        ("an appended step", None),
        ("a head step", Some(0)),
        ("a mid-chain step", Some(2)),
    ] {
        let before = edge_ids(&pool).await;
        add_step_at(&server, &viewer, None, "sw-wf", text, position).await;
        let what = format!("add_step {text}");
        let rels = assert_new_edges_attested(&pool, &before, None, &what).await;
        require(
            &rels,
            &["executes", "decomposes_to", "step_follows", "AUTHORED"],
            &what,
        );
    }
    // The rewire wrote BOTH `prev -> step` and `step -> next`.
    let mid: Uuid = sqlx::query_scalar("SELECT id FROM claims WHERE content = 'a mid-chain step'")
        .fetch_one(&pool)
        .await
        .expect("the mid-chain step");
    let follows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE relationship = 'step_follows' \
            AND (source_id = $1 OR target_id = $1)",
    )
    .bind(mid)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(follows, 2, "the mid-chain step has both chain edges");
}

/// The workflow writers' signer is the server: an authenticated caller's
/// ingest and add_step are authored by the caller, and every edge they write
/// is signed by the SERVER's signer agent, never by the caller.
#[sqlx::test(migrations = "../../migrations")]
async fn a_callers_workflow_edges_are_signed_by_the_server_not_the_caller(pool: PgPool) {
    use epigraph_mcp::types::IngestWorkflowParams;
    let server = server(&pool).await;
    let server_agent = server.server_agent_id().await.expect("server agent");
    let (caller, token, viewer) =
        common::seed_caller(&pool, &["claims:read", "claims:write"]).await;
    assert_ne!(caller, server_agent);

    let before = edge_ids(&pool).await;
    epigraph_mcp::tools::workflow_ingest::ingest_workflow(
        &server,
        &viewer,
        IngestWorkflowParams {
            extraction: workflow("sw-wf-caller", 0),
            tenancy: Some(common::public_tenancy_for(&viewer)),
            embed: None,
        },
        Some(&token),
    )
    .await
    .expect("the caller ingests");
    let rels = assert_new_edges_attested(&pool, &before, Some(caller), "caller ingest").await;
    require(&rels, &["executes", "AUTHORED"], "caller ingest");

    let before = edge_ids(&pool).await;
    let step = add_step_at(
        &server,
        &viewer,
        Some(&token),
        "sw-wf-caller",
        "the caller's step",
        None,
    )
    .await;
    assert_authored_by(&pool, step, caller).await;
    let rels = assert_new_edges_attested(&pool, &before, Some(caller), "caller add_step").await;
    require(
        &rels,
        &["executes", "step_follows", "AUTHORED"],
        "caller add_step",
    );
}

/// A public claim authored by the caller (submitted with its token).
async fn caller_claim(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    token: &epigraph_auth::AuthContext,
    content: &str,
) -> Uuid {
    let out = epigraph_mcp::tools::claims::submit_claim(
        server,
        viewer,
        epigraph_mcp::types::SubmitClaimParams {
            content: content.into(),
            methodology: "deductive_logic".into(),
            evidence_data: format!("evidence for {content}"),
            evidence_type: "logical".into(),
            confidence: 0.6,
            source_url: None,
            reasoning: Some("because".into()),
            labels: vec![],
            novelty_threshold: Some(0.0),
            visibility: Some("public".to_string()),
            group_id: None,
        },
        Some(token),
    )
    .await
    .expect("submit_claim as the caller");
    uuid_field(&common::first_text(&out), "claim_id")
}

fn params<T: serde::de::DeserializeOwned>(v: Value) -> T {
    serde_json::from_value(v).expect("tool params")
}

/// A server and an authenticated caller that is not the server's agent.
async fn server_and_caller(
    pool: &PgPool,
) -> (
    EpiGraphMcpFull,
    Uuid,
    epigraph_auth::AuthContext,
    epigraph_db::visibility::Viewer,
) {
    let server = server(pool).await;
    let server_agent = server.server_agent_id().await.expect("server agent");
    let (caller, token, viewer) = common::seed_caller(pool, &["claims:read", "claims:write"]).await;
    assert_ne!(caller, server_agent);
    (server, caller, token, viewer)
}

/// Backlog `dae795f8`: the claim acts' edges, written inside a repository act
/// on the caller's stamped transaction, are attested at INSERT with the
/// SERVER's key, never the caller's. supersede_claim: the `supersedes` edge
/// and the actor's `AUTHORED`.
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_claim_attests_its_edges_with_the_server_key(pool: PgPool) {
    let (server, caller, token, viewer) = server_and_caller(&pool).await;
    let old = caller_claim(&server, &viewer, &token, "dae795f8 mcp: to be superseded").await;
    let before = edge_ids(&pool).await;
    epigraph_mcp::tools::supersede::supersede_claim(
        &server,
        &viewer,
        params(serde_json::json!({
            "claim_id": old.to_string(),
            "content": "dae795f8 mcp: the replacement",
            "truth_value": 0.7,
            "reason": "restated",
        })),
        Some(&token),
    )
    .await
    .expect("supersede_claim");
    let rels = assert_new_edges_attested(&pool, &before, Some(caller), "supersede").await;
    require(&rels, &["supersedes", "AUTHORED"], "supersede");
}

/// mark_duplicate: the `same_as` identity edge.
#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_attests_its_identity_edge_with_the_server_key(pool: PgPool) {
    let (server, caller, token, viewer) = server_and_caller(&pool).await;
    let dup = caller_claim(&server, &viewer, &token, "dae795f8 mcp: the duplicate").await;
    let canon = caller_claim(&server, &viewer, &token, "dae795f8 mcp: the canonical").await;
    let before = edge_ids(&pool).await;
    epigraph_mcp::tools::supersede::mark_duplicate(
        &server,
        &viewer,
        params(serde_json::json!({
            "claim_id": dup.to_string(),
            "canonical_id": canon.to_string(),
            "reason": "same",
        })),
        Some(&token),
    )
    .await
    .expect("mark_duplicate");
    let rels = assert_new_edges_attested(&pool, &before, Some(caller), "mark_duplicate").await;
    require(&rels, &["same_as"], "mark_duplicate");
}

/// consolidate_claims: the `supersedes` fan-out, merged -> each source.
#[sqlx::test(migrations = "../../migrations")]
async fn consolidate_claims_attests_its_edges_with_the_server_key(pool: PgPool) {
    let (server, caller, token, viewer) = server_and_caller(&pool).await;
    let s1 = caller_claim(&server, &viewer, &token, "dae795f8 mcp: source one").await;
    let s2 = caller_claim(&server, &viewer, &token, "dae795f8 mcp: source two").await;
    let before = edge_ids(&pool).await;
    epigraph_mcp::tools::consolidate::consolidate_claims(
        &server,
        &viewer,
        params(serde_json::json!({
            "source_claim_ids": [s1.to_string(), s2.to_string()],
            "merged_content": "dae795f8 mcp: one and two, merged",
            "mode": "merge",
            "reason": "the same point twice",
        })),
        Some(&token),
    )
    .await
    .expect("consolidate_claims");
    let rels = assert_new_edges_attested(&pool, &before, Some(caller), "consolidate").await;
    require(&rels, &["supersedes"], "consolidate");
    let lineage: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE relationship = 'supersedes' AND target_id = ANY($1)",
    )
    .bind(vec![s1, s2])
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(lineage, 2, "one supersedes edge per source");
}

/// evolve_step: the step edge (`revises`).
#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_attests_its_step_edge_with_the_server_key(pool: PgPool) {
    let (server, caller, token, viewer) = server_and_caller(&pool).await;
    let parent = caller_claim(&server, &viewer, &token, "dae795f8 mcp: a step").await;
    let before = edge_ids(&pool).await;
    epigraph_mcp::tools::evolve_step::evolve_step(
        &server,
        &viewer,
        params(serde_json::json!({
            "parent_id": parent.to_string(),
            "content": "dae795f8 mcp: a revised step",
            "edge_type": "revises",
            "rationale": null,
            "level": null,
        })),
        Some(&token),
    )
    .await
    .expect("evolve_step");
    let rels = assert_new_edges_attested(&pool, &before, Some(caller), "evolve_step").await;
    require(&rels, &["revises"], "evolve_step");
}

/// Backlog `dae795f8`: the promote arm of decide_match_candidate writes the
/// matcher edge (inside `MatchCandidateRepo::promote_if_pending_conn`, on the
/// caller's stamped transaction) attested with the server's key.
#[sqlx::test(migrations = "../../migrations")]
async fn the_match_promotion_attests_its_edge_with_the_server_key(pool: PgPool) {
    let (server, caller, token, viewer) = server_and_caller(&pool).await;
    let a = caller_claim(&server, &viewer, &token, "dae795f8 mcp: matched a").await;
    let b = caller_claim(&server, &viewer, &token, "dae795f8 mcp: matched b").await;
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let candidate: Uuid = sqlx::query_scalar(
        "INSERT INTO match_candidates (claim_a, claim_b, score, features, status) \
         VALUES ($1, $2, 0.95, '{}'::jsonb, 'pending') RETURNING id",
    )
    .bind(lo)
    .bind(hi)
    .fetch_one(&pool)
    .await
    .expect("candidate");

    let before = edge_ids(&pool).await;
    epigraph_mcp::tools::matching::decide_match_candidate(
        &server,
        &viewer,
        epigraph_mcp::types::DecideMatchCandidateParams {
            candidate_id: candidate.to_string(),
            verdict: "promote".into(),
        },
        Some(&token),
    )
    .await
    .expect("promote");
    let rels = assert_new_edges_attested(&pool, &before, Some(caller), "promote").await;
    require(&rels, &["corroborates"], "promote");
}
