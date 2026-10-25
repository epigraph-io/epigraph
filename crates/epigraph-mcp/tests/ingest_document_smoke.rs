//! End-to-end smoke test for the hierarchical `ingest_document` tool.
//!
//! Drives a tiny synthetic `DocumentExtraction` through `do_ingest_document`
//! and asserts the expected paper/claim/edge graph shape lands in Postgres.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools;
use epigraph_mcp::tools::ingestion::{do_ingest_document, ingest_document, ingest_document_inline};
use epigraph_mcp::types::{
    IngestDocumentInlineParams, IngestDocumentParams, RecomputeBeliefsParams,
};
use sqlx::PgPool;

const FIXTURE: &str = r#"{
  "source": {
    "title": "Test Hierarchical Paper",
    "doi": "10.1234/hierarchy-smoke",
    "source_type": "Paper",
    "authors": [
      {"name": "Alice Author", "affiliations": [], "roles": ["author"]}
    ]
  },
  "thesis": "Hierarchies converge through layered claims",
  "thesis_derivation": "TopDown",
  "sections": [{
    "title": "Intro",
    "paragraphs": [{
      "text": "Atomization aids cross-source matching, and explicit decomposition is necessary",
      "atoms": [
        "Atomization aids cross-source matching",
        "Explicit decomposition is necessary for hierarchical reasoning"
      ],
      "generality": [3, 3],
      "confidence": 0.8
    }]
  }],
  "relationships": [
    {
      "source_path": "sections/0/paragraphs/0/atoms/0",
      "target_path": "sections/0/paragraphs/0/atoms/1",
      "relationship": "supports"
    }
  ]
}"#;

/// Built FROM A `ScopedPool`: the document ingest walk now runs in one
/// transaction stamped from the ingesting agent and refuses (nothing written) on
/// a server that cannot stamp one. `#[sqlx::test]` connects as a BYPASSRLS
/// superuser, so the stamp is inert here — what this buys is that the fixture
/// drives the PRODUCTION code path (`begin_author_stamped_tx`) rather than the
/// refusal.
async fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let scoped = fixture::scoped_pool(&pool).await;
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

#[sqlx::test(migrations = "../../migrations")]
async fn happy_path_ingests_full_hierarchy(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let extraction: DocumentExtraction = serde_json::from_str(FIXTURE).expect("fixture parses");

    let result = do_ingest_document(&server, &viewer, &extraction, None)
        .await
        .expect("ingest_document succeeds");

    // Pull the paper_id out of the structured response.
    let payload = result_text(&result);
    let json: serde_json::Value = serde_json::from_str(&payload).expect("response JSON");
    assert_eq!(json["already_ingested"], serde_json::json!(false));
    assert_eq!(json["doi"], "10.1234/hierarchy-smoke");
    assert_eq!(
        json["claims_ingested"].as_u64().unwrap(),
        5,
        "thesis + section + paragraph + 2 atoms; all newly inserted, no dedup"
    );
    assert_eq!(json["claims_skipped_dedup"].as_u64().unwrap(), 0);
    assert!(json["relationships_created"].as_u64().unwrap() >= 5);

    let paper_id = uuid::Uuid::parse_str(json["paper_id"].as_str().unwrap()).unwrap();

    // 1. Paper row exists with correct DOI.
    let row = sqlx::query!("SELECT doi, title FROM papers WHERE id = $1", paper_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.doi, "10.1234/hierarchy-smoke");

    // 2. Each level is represented as a claim node.
    let claim_count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM claims
        WHERE content IN (
            'Hierarchies converge through layered claims',
            'Intro',
            'Atomization aids cross-source matching, and explicit decomposition is necessary',
            'Atomization aids cross-source matching',
            'Explicit decomposition is necessary for hierarchical reasoning'
        )
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        claim_count.0, 5,
        "all 5 hierarchy levels persisted as claims"
    );

    // 3. Paper -> claim asserts edges exist for every claim.
    let assert_edges: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM edges
        WHERE source_id = $1 AND source_type = 'paper'
          AND target_type = 'claim' AND relationship = 'asserts'
        "#,
    )
    .bind(paper_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(assert_edges.0, 5, "paper asserts every claim level");

    // 4. agent -authored-> paper edge exists.
    let authored: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE target_id = $1 AND relationship = 'authored'",
    )
    .bind(paper_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(authored.0, 1);

    // 5. supports edge between the two atoms exists.
    let supports: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE relationship = 'supports' AND source_type = 'claim' AND target_type = 'claim'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(supports.0, 1, "atom -supports-> atom edge persisted");

    // 6. paper -processed_by-> agent edge marks the version gate.
    let processed: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM edges
        WHERE source_id = $1 AND source_type = 'paper'
          AND target_type = 'agent' AND relationship = 'processed_by'
          AND properties ->> 'pipeline' = 'hierarchical_extraction_v2'
        "#,
    )
    .bind(paper_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(processed.0, 1);
}

/// Backlog c9d12a95: `recompute_beliefs(labels=[doi_slug])` returned 0 claims for
/// a paper freshly ingested via `ingest_document_inline`, even though the
/// claims existed — because ingestion never attached any per-paper label, so
/// the label-based recompute path (and `query_claims_by_label`) can never find
/// a paper's claim set. Every claim `do_ingest_document` writes must carry a
/// `doi:<doi>` label, and `recompute_beliefs` must actually find them by it.
#[sqlx::test(migrations = "../../migrations")]
async fn ingested_claims_carry_doi_label_for_recompute(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let extraction: DocumentExtraction = serde_json::from_str(FIXTURE).expect("fixture parses");

    do_ingest_document(&server, &viewer, &extraction, None)
        .await
        .expect("ingest_document succeeds");

    let doi_label = "doi:10.1234/hierarchy-smoke";
    let labeled_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM claims WHERE $1 = ANY(labels)")
            .bind(doi_label)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        labeled_count.0, 5,
        "all 5 hierarchy-level claims must carry the paper's doi label"
    );

    let result = tools::cdst_maintenance::recompute_beliefs(
        &server,
        &mut fixture::scoped_pool(&pool)
            .await
            .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
            .await
            .expect("a maintenance session over the test database"),
        RecomputeBeliefsParams {
            claim_ids: None,
            labels: Some(vec![doi_label.to_string()]),
            limit: None,
            offset: None,
        },
    )
    .await
    .expect("recompute_beliefs succeeds");
    let json: serde_json::Value = serde_json::from_str(&result_text(&result)).unwrap();
    assert_eq!(
        json["claims_considered"],
        serde_json::json!(5),
        "recompute_beliefs(labels=[doi_label]) must find the paper's full claim \
         set, not 0 (the exact symptom reported in backlog c9d12a95)"
    );
}

/// Re-ingesting the same extraction returns `already_ingested: true` with no new
/// claims or relationships. Previously gated at the paper level; now detected by
/// node-level content-hash dedup: all 5 claims hit the dedup path and no edges
/// are newly created on the second run.
#[sqlx::test(migrations = "../../migrations")]
async fn re_ingest_same_paper_dedup_detected(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let extraction: DocumentExtraction = serde_json::from_str(FIXTURE).expect("fixture parses");

    let _first = do_ingest_document(&server, &viewer, &extraction, None)
        .await
        .expect("first ingest");
    let second = do_ingest_document(&server, &viewer, &extraction, None)
        .await
        .expect("second ingest");

    let payload = result_text(&second);
    let json: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(json["already_ingested"], serde_json::json!(true));
    assert_eq!(json["claims_ingested"], serde_json::json!(0));
    assert_eq!(json["relationships_created"], serde_json::json!(0));
}

/// Cross-chapter isolation: a textbook ingested chapter-by-chapter shares one
/// paper row. Each chapter has unique content so chapter 2's claims aren't
/// deduped by chapter 1's ingest, and `already_ingested` stays false. Re-ingesting
/// the same chapter yields `already_ingested: true` via node-level content-hash
/// dedup (all claims hit the dedup path). The per-chapter `processed_by` edge
/// suffix (`:chN`) is vestigial after gate removal but still written for
/// observability.
#[sqlx::test(migrations = "../../migrations")]
async fn per_chapter_version_gate_isolates_chunks(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;

    let make_chapter = |idx: u64| -> DocumentExtraction {
        let json = format!(
            r#"{{
              "source": {{
                "title": "Test Textbook — Chapter {idx}",
                "doi": "10.1234/textbook-chunked",
                "source_type": "Textbook",
                "authors": [{{"name": "Alice Author", "affiliations": [], "roles": ["author"]}}],
                "metadata": {{"chapter_index": {idx}}}
              }},
              "thesis": "Chapter {idx} thesis",
              "thesis_derivation": "TopDown",
              "sections": [{{
                "title": "Sec",
                "paragraphs": [{{
                  "text": "Chapter {idx} compound claim",
                  "atoms": ["Chapter {idx} atom one"],
                  "generality": [3],
                  "confidence": 0.8
                }}]
              }}],
              "relationships": []
            }}"#
        );
        serde_json::from_str(&json).expect("fixture parses")
    };

    let ch1 = do_ingest_document(&server, &viewer, &make_chapter(1), None)
        .await
        .expect("ch1 ingest");
    let ch1_json: serde_json::Value = serde_json::from_str(&result_text(&ch1)).unwrap();
    assert_eq!(ch1_json["already_ingested"], serde_json::json!(false));
    let paper_id = uuid::Uuid::parse_str(ch1_json["paper_id"].as_str().unwrap()).unwrap();

    let ch2 = do_ingest_document(&server, &viewer, &make_chapter(2), None)
        .await
        .expect("ch2 ingest");
    let ch2_json: serde_json::Value = serde_json::from_str(&result_text(&ch2)).unwrap();
    assert_eq!(
        ch2_json["already_ingested"],
        serde_json::json!(false),
        "chapter 2 must not be blocked by chapter 1's processed_by edge"
    );
    assert_eq!(
        ch2_json["paper_id"], ch1_json["paper_id"],
        "same paper row reused"
    );

    let ch2_repeat = do_ingest_document(&server, &viewer, &make_chapter(2), None)
        .await
        .expect("ch2 re-ingest");
    let repeat_json: serde_json::Value = serde_json::from_str(&result_text(&ch2_repeat)).unwrap();
    assert_eq!(
        repeat_json["already_ingested"],
        serde_json::json!(true),
        "re-ingesting the same chapter must still return already_ingested:true (via node-level dedup)"
    );

    // With node-level idempotency (gate removed), both chapter processed_by edges
    // map to the same (paper → agent, 'processed_by') slot — only the first chapter's
    // edge is retained. The chapter suffix (:chN) is now vestigial/observability-only.
    // Assert at least one processed_by edge exists.
    let count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM edges
        WHERE source_id = $1 AND source_type = 'paper'
          AND relationship = 'processed_by'
        "#,
    )
    .bind(paper_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        count.0 >= 1,
        "at least one processed_by edge must exist for the paper"
    );
}

/// A second fixture sharing one atom and the same author with the primary
/// fixture. Validates cross-paper atom convergence and author dedup.
const FIXTURE_OVERLAP: &str = r#"{
  "source": {
    "title": "Second Hierarchical Paper",
    "doi": "10.1234/hierarchy-second",
    "source_type": "Paper",
    "authors": [
      {"name": "Alice Author", "affiliations": [], "roles": ["author"]}
    ]
  },
  "thesis": "Different thesis but shared atom",
  "thesis_derivation": "TopDown",
  "sections": [{
    "title": "Other Intro",
    "paragraphs": [{
      "text": "A different compound claim that overlaps via one shared atom",
      "atoms": [
        "Atomization aids cross-source matching",
        "A genuinely new atom that has never been ingested before"
      ],
      "generality": [3, 3],
      "confidence": 0.7
    }]
  }],
  "relationships": []
}"#;

#[sqlx::test(migrations = "../../migrations")]
async fn cross_paper_atom_and_author_converge(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let first: DocumentExtraction = serde_json::from_str(FIXTURE).expect("fixture parses");
    let second: DocumentExtraction = serde_json::from_str(FIXTURE_OVERLAP).expect("fixture parses");

    let _ = do_ingest_document(&server, &viewer, &first, None)
        .await
        .expect("first ingest");
    let res = do_ingest_document(&server, &viewer, &second, None)
        .await
        .expect("second ingest");

    let payload = result_text(&res);
    let json: serde_json::Value = serde_json::from_str(&payload).unwrap();

    // The shared atom hits cross-paper dedup; the new atom + thesis +
    // section + paragraph are fresh → 4 newly inserted, 1 deduped.
    assert_eq!(json["claims_skipped_dedup"].as_u64().unwrap(), 1);
    assert_eq!(json["claims_ingested"].as_u64().unwrap(), 4);

    // Same shared atom → exactly one atom claim row for that content.
    let shared_atom_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM claims WHERE content = 'Atomization aids cross-source matching'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        shared_atom_count.0, 1,
        "shared atom must converge to one row"
    );

    // The shared atom is asserted by BOTH papers.
    let asserts_into_shared: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM edges e
        JOIN claims c ON c.id = e.target_id
        WHERE e.relationship = 'asserts'
          AND e.source_type = 'paper'
          AND e.target_type = 'claim'
          AND c.content = 'Atomization aids cross-source matching'
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        asserts_into_shared.0, 2,
        "both papers assert the shared atom"
    );

    // Same author across both papers → exactly one author agent row.
    let alice_agents: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM agents WHERE display_name = 'Alice Author'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(alice_agents.0, 1, "author dedup via deterministic key");

    // ...and Alice authored both papers.
    let authored_edges: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE relationship = 'authored' AND source_type = 'agent'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(authored_edges.0, 2, "alice authored both papers");
}

#[sqlx::test(migrations = "../../migrations")]
async fn ingest_document_persists_planned_properties(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let extraction: DocumentExtraction = serde_json::from_str(FIXTURE).expect("fixture parses");

    do_ingest_document(&server, &viewer, &extraction, None)
        .await
        .expect("ingest succeeds");

    let count_with_props: i64 =
        sqlx::query_scalar("SELECT count(*) FROM claims WHERE properties::text != '{}'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        count_with_props > 0,
        "expected at least one claim with non-empty properties"
    );

    // Thesis is at level 0 — confirm level-based filtering works.
    let level_zero: i64 =
        sqlx::query_scalar("SELECT count(*) FROM claims WHERE properties->>'level' = '0'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        level_zero, 1,
        "thesis (level 0) should be queryable by properties->>'level'"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn ingest_document_handles_compound_equals_atom(pool: sqlx::PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;

    // Reproduces the wrhq 2026-04-30 collision: paragraph compound text
    // is identical to its sole atom — same content_hash → same persisted
    // claim → planned decomposes_to becomes a self-loop after id_map.
    let extraction_json = serde_json::json!({
        "source": {
            "title": "compound-atom-test",
            "doi": "wrhq:test/compound-atom-collision",
            "source_type": "InternalDocument",
            "authors": [{"name": "test", "affiliations": [], "roles": ["author"]}],
            "year": 2026,
            "metadata": {}
        },
        "thesis": "Test of compound==atom collision.",
        "thesis_derivation": "TopDown",
        "sections": [{
            "title": "Body",
            "paragraphs": [{
                "text": "Class B agents have a contract.active flag.",
                "atoms": ["Class B agents have a contract.active flag."],
                "generality": [0],
                "confidence": 0.8,
                "methodology": "extraction",
                "evidence_type": "testimonial"
            }]
        }],
        "relationships": []
    });
    let extraction: epigraph_ingest::schema::DocumentExtraction =
        serde_json::from_value(extraction_json).expect("fixture parses");

    // Must not panic and must not return Err with a CHECK violation.
    let result = do_ingest_document(&server, &viewer, &extraction, None).await;
    assert!(
        result.is_ok(),
        "expected ingest to succeed, got: {result:?}"
    );

    // No self-loop edges should exist.
    let self_loops: i64 =
        sqlx::query_scalar("SELECT count(*) FROM edges WHERE source_id = target_id")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        self_loops, 0,
        "self-loop edges should be filtered, found {self_loops}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn ingest_tags_bbas_with_normalized_evidence_type(pool: sqlx::PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;

    // Two atoms under a paragraph tagged (mixed-case) "Empirical" → their BBAs
    // must carry the normalized canonical tag; nothing should carry the raw
    // pre-normalization string.
    let extraction_json = serde_json::json!({
        "source": {
            "title": "evidence-type-wiring",
            "doi": "test/evidence-type-wiring",
            "source_type": "Paper",
            "authors": [{"name": "test", "affiliations": [], "roles": ["author"]}],
            "metadata": {}
        },
        "thesis": "Evidence-type tags reach the BBA.",
        "thesis_derivation": "TopDown",
        "sections": [{
            "title": "Body",
            "paragraphs": [{
                "text": "Two empirical observations support the thesis.",
                "atoms": [
                    "Observation one holds under standard conditions",
                    "Observation two replicates observation one"
                ],
                "generality": [0, 0],
                "confidence": 0.8,
                "methodology": "extraction",
                "evidence_type": "Empirical"
            }]
        }],
        "relationships": []
    });
    let extraction: epigraph_ingest::schema::DocumentExtraction =
        serde_json::from_value(extraction_json).expect("fixture parses");

    do_ingest_document(&server, &viewer, &extraction, None)
        .await
        .expect("ingest succeeds");

    // Atom BBAs carry the normalized canonical tag.
    let empirical_bbas: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE evidence_type = 'empirical'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        empirical_bbas >= 2,
        "expected >=2 atom BBAs tagged 'empirical', found {empirical_bbas}"
    );

    // The raw (un-normalized) value never reaches the column.
    let raw_case: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE evidence_type = 'Empirical'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        raw_case, 0,
        "raw 'Empirical' should have been normalized to lowercase"
    );
}

// ── Typed-inline ingest variant (for MCP-only agents) ──────────────────────

/// Recursively collect every `$ref` string value in a JSON schema.
fn collect_refs(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                if k == "$ref" {
                    if let Some(s) = val.as_str() {
                        out.push(s.to_string());
                    }
                } else {
                    collect_refs(val, out);
                }
            }
        }
        serde_json::Value::Array(arr) => arr.iter().for_each(|val| collect_refs(val, out)),
        _ => {}
    }
}

/// The deliverable, verified on the wire (not just the param type): the live
/// tool router must expose `ingest_document_inline` with a self-contained
/// `inputSchema` — the nested hierarchy inlined in `$defs` down to the atom
/// layer, and every `$ref` resolvable within that same block. A `$ref` with
/// no matching `$defs` entry would hand an MCP client an unusable schema while
/// the param-type schema test stayed green, so this is the assertion that
/// actually guards the feature.
#[test]
fn inline_tool_wire_schema_is_self_contained() {
    let tools = epigraph_mcp::server::EpiGraphMcpFull::all_tools_json();
    let arr = tools.as_array().expect("tool array");
    let tool = arr
        .iter()
        .find(|t| t["name"] == "ingest_document_inline")
        .expect("ingest_document_inline registered in live tool router");
    let input_schema = &tool["inputSchema"];

    let defs = input_schema["$defs"]
        .as_object()
        .expect("inputSchema carries a $defs block");
    for ty in [
        "DocumentExtraction",
        "DocumentSource",
        "Section",
        "Paragraph",
    ] {
        assert!(
            defs.contains_key(ty),
            "$defs must inline `{ty}`; got keys {:?}",
            defs.keys().collect::<Vec<_>>()
        );
    }

    let schema_str = serde_json::to_string(input_schema).unwrap();
    for field in ["sections", "paragraphs", "text", "atoms", "evidence_type"] {
        assert!(
            schema_str.contains(field),
            "wire schema must expose `{field}` so an MCP client sees the shape"
        );
    }

    // Decisive: every $ref resolves within this schema's own $defs.
    let mut refs = Vec::new();
    collect_refs(input_schema, &mut refs);
    assert!(
        !refs.is_empty(),
        "expected nested $ref pointers in the schema"
    );
    for r in &refs {
        let key = r
            .strip_prefix("#/$defs/")
            .unwrap_or_else(|| panic!("unexpected $ref form: {r}"));
        assert!(
            defs.contains_key(key),
            "dangling $ref `{r}` — not present in $defs"
        );
    }
}

/// `wait` is reachable only through the published schema and the wire
/// payload: every handler test builds the params struct directly. Pin that
/// both detached ingest tools publish a boolean `wait` and that a wire payload
/// carrying it deserializes to `Some(true)`, so a serde or schemars change
/// cannot silently drop it and bring back the queued-only contract.
#[test]
fn ingest_tools_publish_and_deserialize_the_wait_flag() {
    let tools = epigraph_mcp::server::EpiGraphMcpFull::all_tools_json();
    let arr = tools.as_array().expect("tool array");
    for name in ["ingest_document_inline", "ingest_document"] {
        let tool = arr
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("{name} registered in live tool router"));
        let wait = &tool["inputSchema"]["properties"]["wait"];
        let ty = &wait["type"];
        let is_boolean = ty == "boolean"
            || ty
                .as_array()
                .is_some_and(|a| a.iter().any(|t| t == "boolean"));
        assert!(
            is_boolean,
            "{name} must publish a boolean `wait`; got {wait}"
        );
        let required = tool["inputSchema"]["required"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            !required.iter().any(|r| r == "wait"),
            "{name}: `wait` is opt-in and must not be required: {required:?}"
        );
    }

    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture JSON");
    let inline: IngestDocumentInlineParams =
        serde_json::from_value(serde_json::json!({ "extraction": fixture, "wait": true }))
            .expect("inline params with wait deserialize");
    assert_eq!(inline.wait, Some(true));
    let inline: IngestDocumentInlineParams =
        serde_json::from_value(serde_json::json!({ "extraction": fixture }))
            .expect("inline params without wait deserialize");
    assert_eq!(
        inline.wait, None,
        "omitted `wait` keeps the queued contract"
    );
    let file: IngestDocumentParams =
        serde_json::from_value(serde_json::json!({ "file_path": "x.json", "wait": true }))
            .expect("file-path params with wait deserialize");
    assert_eq!(file.wait, Some(true));
}

/// The discoverability fix: the typed inline param must expose the full
/// hierarchical `DocumentExtraction` shape as a JSON schema, so an MCP client
/// can introspect exactly what to produce — down to atoms — instead of
/// guessing at the opaque `file_path` contract `ingest_document` exposes.
#[test]
fn inline_params_expose_hierarchical_json_schema() {
    let schema = schemars::schema_for!(IngestDocumentInlineParams);
    let s = serde_json::to_string(&schema).expect("schema serializes");
    for needle in [
        "extraction",
        "source",
        "thesis",
        "sections",
        "paragraphs",
        "text",
        "atoms",
        "evidence_type",
        "relationships",
    ] {
        assert!(
            s.contains(needle),
            "inline-ingest JSON schema must expose `{needle}` so an MCP client can see the shape; schema was: {s}"
        );
    }
}

/// Parity: the typed-inline path lands the identical full hierarchy as the
/// file-path `do_ingest_document` — thesis + section + paragraph + 2 atoms —
/// with the atoms persisted as their own claim nodes (the "down to atomic
/// claims" resolution the inline variant exists to provide for MCP-only
/// agents).
#[sqlx::test(migrations = "../../migrations")]
async fn inline_param_ingests_full_hierarchy(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let extraction: DocumentExtraction = serde_json::from_str(FIXTURE).expect("fixture parses");
    let params = IngestDocumentInlineParams {
        extraction,
        wait: None,
    };

    let result = ingest_document_inline(&server, &viewer, params, None)
        .await
        .expect("inline ingest succeeds");

    let json: serde_json::Value =
        serde_json::from_str(&result_text(&result)).expect("response JSON");
    assert_eq!(
        json["status"], "queued",
        "fire-and-forget ingest_document_inline returns a queue acknowledgement immediately"
    );

    // Background task writes DB asynchronously; give it time to complete before asserting state.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Atoms landed as their own claim rows — the atomic resolution.
    let atom_count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM claims
        WHERE content IN (
            'Atomization aids cross-source matching',
            'Explicit decomposition is necessary for hierarchical reasoning'
        )
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        atom_count.0, 2,
        "both atoms persisted as claim nodes via the inline path"
    );
}

// ── Backlog b1924b39 / 417ab1c2 / 189d6d8f: `wait` reports the walk's outcome ──
//
// Detached, a walk that fails past the synchronous write-authority preflight
// reaches only the server log: the caller holds `status: queued` and can infer
// the failure only from `query_paper`'s claim_count staying 0. `wait: true` runs
// the same walk in-request and returns its result or its error.

/// A refusal no preflight can see: every `reasoning_traces` INSERT raises
/// 42501, so the walk fails on its FIRST claim's trace, past the verbatim and
/// axis guards and past `preflight_write_authority` (which writes nothing).
async fn refuse_every_trace_insert(pool: &PgPool) {
    sqlx::query(
        "CREATE OR REPLACE FUNCTION refuse_trace_for_test() RETURNS trigger
         LANGUAGE plpgsql AS $$
         BEGIN
             RAISE EXCEPTION 'refused reasoning_traces insert (test trigger)'
                 USING ERRCODE = '42501';
         END $$",
    )
    .execute(pool)
    .await
    .expect("create the refusing trigger function");
    sqlx::query(
        "CREATE TRIGGER refuse_trace_for_test BEFORE INSERT ON reasoning_traces
         FOR EACH ROW EXECUTE FUNCTION refuse_trace_for_test()",
    )
    .execute(pool)
    .await
    .expect("install the refusing trigger");
}

const SMOKE_DOI: &str = "10.1234/hierarchy-smoke";

async fn claims_labelled(pool: &PgPool, label: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE $1 = ANY(labels)")
        .bind(label)
        .fetch_one(pool)
        .await
        .expect("count labelled claims")
}

/// `processed_by` edges from the paper keyed on `doi` (0 when no row exists).
async fn processed_by_edges(pool: &PgPool, doi: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges e JOIN papers p ON p.id = e.source_id
         WHERE p.doi = $1 AND e.relationship = 'processed_by'",
    )
    .bind(doi)
    .fetch_one(pool)
    .await
    .expect("count processed_by edges")
}

/// Asserts the failed walk's error reached the caller and that it wrote nothing.
async fn assert_failed_walk_reported(
    pool: &PgPool,
    outcome: Result<rmcp::model::CallToolResult, rmcp::model::ErrorData>,
) {
    let err = match outcome {
        Ok(ok) => panic!(
            "wait=true must return the walk's error, not an acknowledgement: {}",
            result_text(&ok)
        ),
        Err(e) => e,
    };
    assert!(
        err.message.contains("refused reasoning_traces insert"),
        "the walk's own cause must reach the caller, got: {}",
        err.message
    );
    assert!(
        err.message.contains(SMOKE_DOI) && err.message.contains("retry"),
        "the error must name the document key and say a retry is safe, got: {}",
        err.message
    );
    assert_eq!(
        claims_labelled(pool, &format!("doi:{SMOKE_DOI}")).await,
        0,
        "the walk is one transaction: a failed walk leaves no claim behind"
    );
    assert_eq!(
        processed_by_edges(pool, SMOKE_DOI).await,
        0,
        "a failed walk must not stamp the paper as processed"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn inline_wait_mode_returns_the_walk_error_and_writes_no_claims(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    refuse_every_trace_insert(&pool).await;
    let extraction: DocumentExtraction = serde_json::from_str(FIXTURE).expect("fixture parses");

    let outcome = ingest_document_inline(
        &server,
        &viewer,
        IngestDocumentInlineParams {
            extraction,
            wait: Some(true),
        },
        None,
    )
    .await;
    assert_failed_walk_reported(&pool, outcome).await;
}

/// The file-path entry point is the second detached handler; same contract.
#[sqlx::test(migrations = "../../migrations")]
async fn file_path_wait_mode_returns_the_walk_error_and_writes_no_claims(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    refuse_every_trace_insert(&pool).await;

    // Under the current directory: the handler refuses a path outside it.
    let path = std::env::current_dir()
        .expect("current dir")
        .join(format!("wait-mode-fixture-{}.json", uuid::Uuid::new_v4()));
    std::fs::write(&path, FIXTURE).expect("write fixture");
    let outcome = ingest_document(
        &server,
        &viewer,
        IngestDocumentParams {
            file_path: path.display().to_string(),
            wait: Some(true),
        },
        None,
    )
    .await;
    let _ = std::fs::remove_file(&path);
    assert_failed_walk_reported(&pool, outcome).await;
}

/// In wait mode a GUARD refusal (here the D9 verbatim guard) is returned to the
/// caller and leaves no `papers` row: the wait arm skips the handler's eager
/// `ensure_paper_node`, and the walk's own get-or-create runs after its guards.
#[sqlx::test(migrations = "../../migrations")]
async fn inline_wait_mode_guard_refusal_leaves_no_paper_row(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let extraction: DocumentExtraction = serde_json::from_value(serde_json::json!({
        "source": {
            "title": "Wait Drift Doc",
            "doi": "10.1/wait-drift",
            "source_type": "InternalDocument",
            "authors": [{"name": "test", "affiliations": [], "roles": ["author"]}],
            "metadata": {}
        },
        "thesis": "t",
        "thesis_derivation": "TopDown",
        "sections": [{
            "title": "S",
            "paragraphs": [{
                "text": "TAMPERED",
                "span": { "start": 0, "end": 5 },
                "atoms": ["a"],
                "generality": [0],
                "confidence": 0.8
            }]
        }],
        "relationships": [],
        "source_text": "alpha beta"
    }))
    .unwrap();

    let outcome = ingest_document_inline(
        &server,
        &viewer,
        IngestDocumentInlineParams {
            extraction,
            wait: Some(true),
        },
        None,
    )
    .await;
    let err = match outcome {
        Ok(ok) => panic!(
            "wait=true must return the guard refusal, not an acknowledgement: {}",
            result_text(&ok)
        ),
        Err(e) => e,
    };
    assert!(
        err.message.contains("verbatim guard"),
        "the refusal must be the verbatim guard, got: {}",
        err.message
    );
    let papers: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM papers WHERE doi = $1")
        .bind("10.1/wait-drift")
        .fetch_one(&pool)
        .await
        .expect("count papers");
    assert_eq!(
        papers, 0,
        "a guard refusal in wait mode must leave no papers row"
    );
}

/// Positive arm: with `wait: true` a walk that succeeds returns the walk's own
/// counts (not a queue acknowledgement), and its claims exist the moment the
/// call returns, with no sleep.
#[sqlx::test(migrations = "../../migrations")]
async fn inline_wait_mode_returns_the_walk_result(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let extraction: DocumentExtraction = serde_json::from_str(FIXTURE).expect("fixture parses");

    let result = ingest_document_inline(
        &server,
        &viewer,
        IngestDocumentInlineParams {
            extraction,
            wait: Some(true),
        },
        None,
    )
    .await
    .expect("a valid document ingests in wait mode");
    let json: serde_json::Value =
        serde_json::from_str(&result_text(&result)).expect("response JSON");
    assert!(
        json.get("status").is_none(),
        "wait mode returns the walk's result, not a queue acknowledgement: {json}"
    );
    assert_eq!(json["claims_ingested"], serde_json::json!(5), "{json}");
    assert_eq!(json["doi"], SMOKE_DOI, "{json}");
    assert_eq!(
        claims_labelled(&pool, &format!("doi:{SMOKE_DOI}")).await,
        5,
        "every level is committed by the time the call returns"
    );
    assert_eq!(processed_by_edges(&pool, SMOKE_DOI).await, 1);
}

// ── DOI key canonicalization: a resolver-URL DOI keys the bare-DOI row ─────

/// `check_already_ingested(doi, pipeline_version)`'s JSON answer.
async fn gate_json(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    doi: &str,
    pipeline_version: Option<&str>,
) -> serde_json::Value {
    let viewer = fixture::public_viewer(pool).await;
    let result = tools::ingestion::check_already_ingested(
        server,
        &viewer,
        epigraph_mcp::types::CheckAlreadyIngestedParams {
            doi: doi.to_string(),
            pipeline_version: pipeline_version.map(str::to_string),
        },
    )
    .await
    .expect("check_already_ingested answers");
    serde_json::from_str(&result_text(&result)).expect("check_already_ingested JSON")
}

/// Seed a paper row keyed VERBATIM on `key` (as the writer stored a
/// resolver-URL DOI before keys were canonicalized), stamped `processed_by`
/// the hierarchical pipeline by the server's agent. Returns the paper id.
async fn seed_processed_paper(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    key: &str,
    title: &str,
) -> uuid::Uuid {
    let paper_id = epigraph_db::PaperRepository::get_or_create(pool, key, Some(title), None)
        .await
        .expect("seed a paper row");
    let agent = server.server_agent_id().await.expect("server agent");
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::EdgeRepository::create_processed_by_stamp_if_absent_conn(
        &mut conn,
        paper_id,
        agent,
        "hierarchical_extraction_v2",
        "ingest_document",
    )
    .await
    .expect("stamp the seeded paper processed_by");
    assert_eq!(
        processed_by_edges(pool, key).await,
        1,
        "CALIBRATION: the seeded row carries one processed_by stamp"
    );
    paper_id
}

async fn query_paper_json(server: &EpiGraphMcpFull, pool: &PgPool, doi: &str) -> serde_json::Value {
    let viewer = fixture::public_viewer(pool).await;
    let result = tools::paper_queries::query_paper(
        server,
        &viewer,
        epigraph_mcp::types::QueryPaperParams {
            doi: doi.to_string(),
            limit: None,
            offset: None,
        },
    )
    .await
    .expect("query_paper answers");
    serde_json::from_str(&result_text(&result)).expect("query_paper JSON")
}

/// Observed: an agent ingested with `doi: "https://doi.org/10.1021/..."` and
/// the URL was stored verbatim as the paper key, so `query_paper` on the bare
/// DOI kept answering the zero-shaped "not in the graph" response. The ingest
/// must key the bare DOI, and both probes (`query_paper`,
/// `check_already_ingested`) must find it by the bare DOI.
#[sqlx::test(migrations = "../../migrations")]
async fn query_paper_finds_url_form_ingest_by_bare_doi(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let mut extraction: DocumentExtraction = serde_json::from_str(FIXTURE).expect("fixture parses");
    extraction.source.doi = Some(format!("https://doi.org/{SMOKE_DOI}"));

    do_ingest_document(&server, &viewer, &extraction, None)
        .await
        .expect("ingest succeeds");

    let paper = query_paper_json(&server, &pool, SMOKE_DOI).await;
    assert_eq!(paper["title"], "Test Hierarchical Paper", "{paper}");
    assert_eq!(paper["claim_count"], serde_json::json!(5), "{paper}");
    assert_eq!(
        claims_labelled(&pool, &format!("doi:{SMOKE_DOI}")).await,
        5,
        "the claims carry the bare-DOI label, not `doi:https://doi.org/...`"
    );

    let gate = gate_json(&server, &pool, SMOKE_DOI, None).await;
    assert_eq!(gate["already_ingested"], serde_json::json!(true), "{gate}");
    let stamp = gate["matched_pipeline_versions"][0]
        .as_str()
        .unwrap_or_else(|| panic!("the walk wrote a processed_by stamp: {gate}"))
        .to_string();

    // The URL spelling, asked later, names the same paper: through query_paper
    // and through BOTH arms of the dedup gate (the family arm, and the exact
    // arm that runs through `paper_already_ingested`). A probe that asks with
    // the URL form must not read "not ingested" and re-extract the paper.
    let url = format!("https://doi.org/{SMOKE_DOI}");
    let by_url = query_paper_json(&server, &pool, &url).await;
    assert_eq!(by_url["claim_count"], serde_json::json!(5), "{by_url}");
    for pipeline_version in [None, Some(stamp.as_str())] {
        let gate = gate_json(&server, &pool, &url, pipeline_version).await;
        assert_eq!(
            gate["already_ingested"],
            serde_json::json!(true),
            "check_already_ingested({url:?}, {pipeline_version:?}): {gate}"
        );
    }
}

/// A row written under a resolver-URL key BEFORE keys were canonicalized is
/// still found by that spelling: the lookup falls back to the key as given.
/// The not-found contract (a zero-shaped response, not an error) is unchanged.
#[sqlx::test(migrations = "../../migrations")]
async fn query_paper_still_finds_a_legacy_url_form_row(pool: PgPool) {
    let server = make_server(pool.clone()).await;
    let legacy = "https://doi.org/10.5555/legacy-url-key";
    let paper_id = seed_processed_paper(&server, &pool, legacy, "Legacy URL-keyed").await;

    let paper = query_paper_json(&server, &pool, legacy).await;
    assert_eq!(paper["title"], "Legacy URL-keyed", "{paper}");
    // The dedup gate falls back to the as-given spelling too, on both arms.
    for pipeline_version in [None, Some("hierarchical_extraction_v2")] {
        let gate = gate_json(&server, &pool, legacy, pipeline_version).await;
        assert_eq!(
            gate["already_ingested"],
            serde_json::json!(true),
            "check_already_ingested({legacy:?}, {pipeline_version:?}): {gate}"
        );
        assert_eq!(gate["paper_id"], paper_id.to_string(), "{gate}");
    }

    let unknown = query_paper_json(&server, &pool, "https://doi.org/10.5555/never-ingested").await;
    assert_eq!(unknown["title"], "", "{unknown}");
    assert_eq!(unknown["claim_count"], serde_json::json!(0), "{unknown}");
}

/// The filed probe: the row was written under `https://doi.org/<doi>` before
/// keys were canonicalized, and the monitor asks by the BARE DOI. Both probes
/// must find that legacy row, or the monitor reads "not ingested", re-extracts
/// the paper, and the re-ingest mints a bare-keyed twin of it.
#[sqlx::test(migrations = "../../migrations")]
async fn bare_doi_finds_a_legacy_resolver_url_keyed_row(pool: PgPool) {
    let server = make_server(pool.clone()).await;
    let bare = "10.5555/legacy-bare-probe";
    for (n, prefix) in ["https://doi.org/", "http://dx.doi.org/"]
        .iter()
        .enumerate()
    {
        let bare = format!("{bare}-{n}");
        let legacy = format!("{prefix}{bare}");
        let paper_id = seed_processed_paper(&server, &pool, &legacy, "Legacy by bare").await;

        let paper = query_paper_json(&server, &pool, &bare).await;
        assert_eq!(
            paper["title"], "Legacy by bare",
            "query_paper({bare:?}): {paper}"
        );
        for pipeline_version in [None, Some("hierarchical_extraction_v2")] {
            let gate = gate_json(&server, &pool, &bare, pipeline_version).await;
            assert_eq!(
                gate["already_ingested"],
                serde_json::json!(true),
                "check_already_ingested({bare:?}, {pipeline_version:?}) on {legacy:?}: {gate}"
            );
            assert_eq!(gate["paper_id"], paper_id.to_string(), "{gate}");
        }
    }

    // A bare DOI nobody ingested, under any spelling, is still the
    // zero-shaped not-found answer.
    let unknown = query_paper_json(&server, &pool, "10.5555/never-ingested").await;
    assert_eq!(unknown["title"], "", "{unknown}");
    assert_eq!(unknown["claim_count"], serde_json::json!(0), "{unknown}");
}

/// D9 writer-side guard: when an extraction carries `source_text`, every
/// span-backed paragraph's stored `text` must equal the bytes its span points
/// at. Here the span `0..5` of `"alpha beta"` is `"alpha"` but the paragraph
/// text is `"TAMPERED"` — a verbatim drift that the writer must reject before
/// any DB write. The fixture is otherwise a fully valid extraction (so the
/// rejection comes from the guard, not from a malformed plan).
#[sqlx::test(migrations = "../../migrations")]
async fn writer_rejects_span_text_drift(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool).await;
    let extraction: DocumentExtraction = serde_json::from_value(serde_json::json!({
        "source": {
            "title": "Drift Doc",
            "doi": "10.1/drift",
            "source_type": "InternalDocument",
            "authors": [{"name": "test", "affiliations": [], "roles": ["author"]}],
            "metadata": {}
        },
        "thesis": "t",
        "thesis_derivation": "TopDown",
        "sections": [{
            "title": "S",
            "paragraphs": [{
                "text": "TAMPERED",
                "span": { "start": 0, "end": 5 },
                "atoms": ["a"],
                "generality": [0],
                "confidence": 0.8
            }]
        }],
        "relationships": [],
        "source_text": "alpha beta"
    }))
    .unwrap();

    let err = do_ingest_document(&server, &viewer, &extraction, None).await;
    let err = err.expect_err("drift between span and source_text must be rejected");
    assert!(
        err.message.contains("verbatim guard"),
        "rejection must come from the verbatim guard, got: {err:?}"
    );
}

// ── Backlog a55aac45 / U039: placeholder author names ──────────────────────
//
// arXiv:2606.16707 was ingested with `source.authors = [{"name": "Authors Not
// Specified"}]`. The byline back-fill only fired on an EMPTY list and the author
// loop only skipped EMPTY names, so the placeholder string minted a deterministic
// author agent that `authored` the paper and `asserts`-ed every one of its 269
// claims. These tests pin the tool-boundary behaviour: a placeholder-shaped name
// never becomes an agent, and an all-placeholder list is treated as "no real
// author" so the body-byline backstop gets its chance.

/// `FIXTURE` with its DOI and author list replaced, and an optional
/// `source_text`. Paragraphs carry no `span`, so the D9 verbatim guard has
/// nothing to compare and the byline parser sees exactly `source_text`.
fn placeholder_fixture(
    doi: &str,
    authors: serde_json::Value,
    source_text: Option<&str>,
) -> DocumentExtraction {
    let mut v: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    v["source"]["doi"] = serde_json::json!(doi);
    v["source"]["authors"] = authors;
    if let Some(text) = source_text {
        v["source_text"] = serde_json::json!(text);
    }
    serde_json::from_value(v).expect("modified fixture parses")
}

async fn agents_named(pool: &PgPool, name: &str) -> i64 {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM agents WHERE display_name = $1")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap();
    row.0
}

/// `authored` edges into `paper_id` from the agent(s) whose display name is `name`.
async fn authored_by(pool: &PgPool, paper_id: uuid::Uuid, name: &str) -> i64 {
    let row: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM edges e JOIN agents a ON a.id = e.source_id
        WHERE e.target_id = $1 AND e.relationship = 'authored'
          AND e.source_type = 'agent' AND a.display_name = $2
        "#,
    )
    .bind(paper_id)
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap();
    row.0
}

async fn authored_total(pool: &PgPool, paper_id: uuid::Uuid) -> i64 {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE target_id = $1 AND relationship = 'authored'",
    )
    .bind(paper_id)
    .fetch_one(pool)
    .await
    .unwrap();
    row.0
}

/// agent→claim `asserts` edges from the agent(s) whose display name is `name`.
async fn claim_asserts_by(pool: &PgPool, name: &str) -> i64 {
    let row: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM edges e JOIN agents a ON a.id = e.source_id
        WHERE e.source_type = 'agent' AND e.target_type = 'claim'
          AND e.relationship = 'asserts' AND a.display_name = $1
        "#,
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap();
    row.0
}

/// ALL agent→claim `asserts` edges, whoever the agent is. The document walk
/// writes these only for planned `author_placeholder` edges (its own claim
/// assertions are paper→claim), so this count is name-independent.
async fn agent_claim_asserts_total(pool: &PgPool) -> i64 {
    let row: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM edges
        WHERE source_type = 'agent' AND target_type = 'claim' AND relationship = 'asserts'
        "#,
    )
    .fetch_one(pool)
    .await
    .unwrap();
    row.0
}

/// Edges of ANY relationship whose source is the agent `agent_id`.
async fn edges_from_agent(pool: &PgPool, agent_id: uuid::Uuid) -> i64 {
    let row: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM edges WHERE source_id = $1 AND source_type = 'agent'")
            .bind(agent_id)
            .fetch_one(pool)
            .await
            .unwrap();
    row.0
}

/// Pre-seed the agent a placeholder NAME derives (`did_key_for_author`), as prod
/// already holds one (c12bddb2 "Authors Not Specified").
async fn seed_name_derived_agent(pool: &PgPool, name: &str) -> uuid::Uuid {
    let key = epigraph_crypto::did_key::did_key_for_author(None, name).1;
    let agent = epigraph_core::Agent::new(key, Some(name.to_string()));
    let created = epigraph_db::AgentRepository::create(pool, &agent)
        .await
        .expect("seed the name-derived agent");
    created.id.into()
}

async fn agents_with_name_key(pool: &PgPool, name: &str) -> i64 {
    let key = epigraph_crypto::did_key::did_key_for_author(None, name).1;
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM agents WHERE public_key = $1")
        .bind(key.as_slice())
        .fetch_one(pool)
        .await
        .unwrap();
    row.0
}

fn paper_id_of(result: &rmcp::model::CallToolResult) -> uuid::Uuid {
    let json: serde_json::Value =
        serde_json::from_str(&result_text(result)).expect("response JSON");
    uuid::Uuid::parse_str(json["paper_id"].as_str().expect("paper_id in response"))
        .expect("paper_id is a uuid")
}

/// The 2606.16707 defect at the tool boundary: a lone placeholder author (no
/// `source_text`, so no byline to recover) must leave the paper with NO author
/// rather than a shared fake one.
#[sqlx::test(migrations = "../../migrations")]
async fn placeholder_author_name_mints_no_author_agent(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let extraction = placeholder_fixture(
        "10.1234/placeholder-author",
        serde_json::json!([
            {"name": "Authors Not Specified", "affiliations": [], "roles": ["author"]}
        ]),
        None,
    );

    let result = do_ingest_document(&server, &viewer, &extraction, None)
        .await
        .expect("ingest_document succeeds — a bad author name is dropped, not fatal");
    let paper_id = paper_id_of(&result);

    assert_eq!(
        agents_named(&pool, "Authors Not Specified").await,
        0,
        "a placeholder author name must not mint an agent"
    );
    assert_eq!(
        authored_total(&pool, paper_id).await,
        0,
        "with only a placeholder author the paper has no authored edge"
    );
    assert_eq!(
        agent_claim_asserts_total(&pool).await,
        0,
        "no agent at all asserts the paper's claims: its only author was a placeholder"
    );
    // The ingest itself still lands: dropping a bad name must not cost the claims.
    let json: serde_json::Value =
        serde_json::from_str(&result_text(&result)).expect("response JSON");
    assert_eq!(json["claims_ingested"].as_u64().unwrap(), 5);
}

/// An all-placeholder structured list counts as "no real author", so the
/// body-byline backstop (previously gated on an EMPTY list) recovers the real
/// names. Byline-recovered authors get `authored → paper` only: the planner
/// emitted no `author_placeholder` edges (every structured entry was dropped),
/// so they assert no claims — the same as today's empty-list fallback.
#[sqlx::test(migrations = "../../migrations")]
async fn placeholder_only_authors_fall_back_to_body_byline(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let byline_text = "Test Hierarchical Paper\n\nAlice Smith, Bob Jones\n\nAbstract: Hierarchies converge through layered claims.";
    assert_eq!(
        epigraph_ingest::document::byline::parse_byline_authors(byline_text).len(),
        2,
        "CALIBRATION: the body byline parses to two authors"
    );
    let extraction = placeholder_fixture(
        "10.1234/placeholder-byline",
        serde_json::json!([
            {"name": "Authors Not Specified", "affiliations": [], "roles": ["author"]}
        ]),
        Some(byline_text),
    );

    let result = do_ingest_document(&server, &viewer, &extraction, None)
        .await
        .expect("ingest_document succeeds");
    let paper_id = paper_id_of(&result);

    assert_eq!(authored_by(&pool, paper_id, "Alice Smith").await, 1);
    assert_eq!(authored_by(&pool, paper_id, "Bob Jones").await, 1);
    assert_eq!(
        authored_total(&pool, paper_id).await,
        2,
        "exactly the two byline authors author the paper"
    );
    assert_eq!(agents_named(&pool, "Authors Not Specified").await, 0);
    assert_eq!(
        claim_asserts_by(&pool, "Alice Smith").await + claim_asserts_by(&pool, "Bob Jones").await,
        0,
        "byline-recovered authors get authored→paper only, never per-claim asserts"
    );
}

/// A placeholder BEFORE a real author: the planner and the walk must skip the
/// same ORIGINAL index, so the real author's `asserts` edges (keyed by
/// `author_index`) still resolve to her. A filter-then-enumerate on either side
/// shifts Alice to index 0 on one side only and drops (or misattributes) her
/// per-claim assertions.
#[sqlx::test(migrations = "../../migrations")]
async fn mixed_real_and_placeholder_authors_keep_index_alignment(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let extraction = placeholder_fixture(
        "10.1234/placeholder-mixed",
        serde_json::json!([
            {"name": "Unknown", "affiliations": [], "roles": ["author"]},
            {"name": "Alice Author", "affiliations": [], "roles": ["author"]}
        ]),
        None,
    );

    let result = do_ingest_document(&server, &viewer, &extraction, None)
        .await
        .expect("ingest_document succeeds");
    let paper_id = paper_id_of(&result);

    assert_eq!(
        agents_named(&pool, "Unknown").await,
        0,
        "no 'Unknown' agent"
    );
    assert_eq!(authored_total(&pool, paper_id).await, 1);
    assert_eq!(authored_by(&pool, paper_id, "Alice Author").await, 1);
    assert_eq!(
        claim_asserts_by(&pool, "Alice Author").await,
        5,
        "the real author asserts every one of the 5 claims"
    );
    // `authored.position` is the ORIGINAL extraction index, so a dropped
    // placeholder leaves a gap rather than renumbering the real authors.
    let position: (serde_json::Value,) = sqlx::query_as(
        r#"
        SELECT e.properties->'position' FROM edges e JOIN agents a ON a.id = e.source_id
        WHERE e.target_id = $1 AND e.relationship = 'authored' AND a.display_name = 'Alice Author'
        "#,
    )
    .bind(paper_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(position.0, serde_json::json!(1));
}

/// Prod already holds the placeholder-derived agent (c12bddb2 "Authors Not
/// Specified"). The skip must come BEFORE the lookup by key: a guard on the
/// create branch alone would still REUSE the existing fake agent and keep
/// growing its `authored` / `asserts` edges on every new paper. A real author
/// follows the placeholder so the walk iterates the structured list (a
/// placeholder-only list would take the byline fallback and never look the
/// key up).
#[sqlx::test(migrations = "../../migrations")]
async fn existing_placeholder_agent_is_not_reused(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let fake = seed_name_derived_agent(&pool, "Authors Not Specified").await;
    let extraction = placeholder_fixture(
        "10.1234/placeholder-existing-agent",
        serde_json::json!([
            {"name": "Authors Not Specified", "affiliations": [], "roles": ["author"]},
            {"name": "Alice Author", "affiliations": [], "roles": ["author"]}
        ]),
        None,
    );

    let result = do_ingest_document(&server, &viewer, &extraction, None)
        .await
        .expect("ingest_document succeeds");
    let paper_id = paper_id_of(&result);

    assert_eq!(
        edges_from_agent(&pool, fake).await,
        0,
        "the pre-existing placeholder agent must gain no edge of any kind"
    );
    assert_eq!(
        agents_with_name_key(&pool, "Authors Not Specified").await,
        1,
        "only the seeded agent holds the placeholder key; none re-minted"
    );
    // The walk did run over the structured list: the real author landed.
    assert_eq!(authored_total(&pool, paper_id).await, 1);
    assert_eq!(authored_by(&pool, paper_id, "Alice Author").await, 1);
    assert_eq!(claim_asserts_by(&pool, "Alice Author").await, 5);
}

fn result_text(result: &rmcp::model::CallToolResult) -> String {
    let content = result.content.first().expect("at least one content block");
    content.as_text().expect("text content").text.clone()
}
