//! End-to-end smoke test for the hierarchical `ingest_document` tool.
//!
//! Drives a tiny synthetic `DocumentExtraction` through `do_ingest_document`
//! and asserts the expected paper/claim/edge graph shape lands in Postgres.

use epigraph_crypto::AgentSigner;
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::{do_ingest_document, ingest_document_inline};
use epigraph_mcp::types::IngestDocumentInlineParams;
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

fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

#[sqlx::test(migrations = "../../migrations")]
async fn happy_path_ingests_full_hierarchy(pool: PgPool) {
    let server = make_server(pool.clone());
    let extraction: DocumentExtraction = serde_json::from_str(FIXTURE).expect("fixture parses");

    let result = do_ingest_document(&server, &extraction)
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

/// Re-ingesting the same extraction returns `already_ingested: true` with no new
/// claims or relationships. Previously gated at the paper level; now detected by
/// node-level content-hash dedup: all 5 claims hit the dedup path and no edges
/// are newly created on the second run.
#[sqlx::test(migrations = "../../migrations")]
async fn re_ingest_same_paper_dedup_detected(pool: PgPool) {
    let server = make_server(pool.clone());
    let extraction: DocumentExtraction = serde_json::from_str(FIXTURE).expect("fixture parses");

    let _first = do_ingest_document(&server, &extraction)
        .await
        .expect("first ingest");
    let second = do_ingest_document(&server, &extraction)
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
    let server = make_server(pool.clone());

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

    let ch1 = do_ingest_document(&server, &make_chapter(1))
        .await
        .expect("ch1 ingest");
    let ch1_json: serde_json::Value = serde_json::from_str(&result_text(&ch1)).unwrap();
    assert_eq!(ch1_json["already_ingested"], serde_json::json!(false));
    let paper_id = uuid::Uuid::parse_str(ch1_json["paper_id"].as_str().unwrap()).unwrap();

    let ch2 = do_ingest_document(&server, &make_chapter(2))
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

    let ch2_repeat = do_ingest_document(&server, &make_chapter(2))
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
    let server = make_server(pool.clone());
    let first: DocumentExtraction = serde_json::from_str(FIXTURE).expect("fixture parses");
    let second: DocumentExtraction = serde_json::from_str(FIXTURE_OVERLAP).expect("fixture parses");

    let _ = do_ingest_document(&server, &first)
        .await
        .expect("first ingest");
    let res = do_ingest_document(&server, &second)
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
    let server = make_server(pool.clone());
    let extraction: DocumentExtraction = serde_json::from_str(FIXTURE).expect("fixture parses");

    do_ingest_document(&server, &extraction)
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
    let server = make_server(pool.clone());

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
    let result = do_ingest_document(&server, &extraction).await;
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
    let server = make_server(pool.clone());

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

    do_ingest_document(&server, &extraction)
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
    let server = make_server(pool.clone());
    let extraction: DocumentExtraction = serde_json::from_str(FIXTURE).expect("fixture parses");
    let params = IngestDocumentInlineParams { extraction };

    let result = ingest_document_inline(&server, params)
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

/// D9 writer-side guard: when an extraction carries `source_text`, every
/// span-backed paragraph's stored `text` must equal the bytes its span points
/// at. Here the span `0..5` of `"alpha beta"` is `"alpha"` but the paragraph
/// text is `"TAMPERED"` — a verbatim drift that the writer must reject before
/// any DB write. The fixture is otherwise a fully valid extraction (so the
/// rejection comes from the guard, not from a malformed plan).
#[sqlx::test(migrations = "../../migrations")]
async fn writer_rejects_span_text_drift(pool: PgPool) {
    let server = make_server(pool);
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

    let err = do_ingest_document(&server, &extraction).await;
    let err = err.expect_err("drift between span and source_text must be rejected");
    assert!(
        err.message.contains("verbatim guard"),
        "rejection must come from the verbatim guard, got: {err:?}"
    );
}

fn result_text(result: &rmcp::model::CallToolResult) -> String {
    let content = result.content.first().expect("at least one content block");
    content.as_text().expect("text content").text.clone()
}
