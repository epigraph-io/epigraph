//! Characterization of what the two document walks WRITE (backlog 3716a30b).
//!
//! The spine walk (`do_ingest_document_spine`) and the full walk
//! (`do_ingest_document`) are one walker with a level filter. These tests pin
//! the graph each run leaves behind: the claim set, every edge touching the
//! paper or its claims (endpoints named by role, properties with ids named the
//! same way, so the tool name each walk records is pinned too), the evidence,
//! trace and DS row counts, and the spine response. The snapshot was recorded
//! from the two separate walkers before they were folded, so the fold is held
//! to "no behaviour change" rather than to a re-derivation of it.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::{BTreeMap, HashMap};

use epigraph_crypto::AgentSigner;
use epigraph_ingest::document::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::{do_ingest_document, do_ingest_document_spine};
use sqlx::PgPool;
use uuid::Uuid;

const DOI: &str = "10.1234/walk-levels-parity";

/// Two sections, three paragraphs, atoms under each, a cross-paragraph
/// `supports` between atoms (an edge the spine must skip) and one author (the
/// planner's `author_placeholder -asserts-> claim` edges).
const FIXTURE: &str = r#"{
  "source": {
    "title": "Walk Levels Parity Paper",
    "doi": "10.1234/walk-levels-parity",
    "source_type": "Paper",
    "authors": [
      {"name": "Parity Author", "affiliations": [], "roles": ["author"]}
    ]
  },
  "thesis": "One walker serves both ingest levels",
  "thesis_derivation": "TopDown",
  "sections": [
    {
      "title": "Background",
      "paragraphs": [
        {
          "text": "Spine ingests write structure only, and full ingests add atoms",
          "atoms": [
            "Spine ingests write structure only",
            "Full ingests add atoms beneath the structure"
          ],
          "generality": [2, 3],
          "confidence": 0.8
        },
        {
          "text": "A level filter keeps the two walks from drifting apart",
          "atoms": ["A level filter keeps the two walks from drifting apart"],
          "generality": [2],
          "confidence": 0.7
        }
      ]
    },
    {
      "title": "Method",
      "paragraphs": [
        {
          "text": "The characterization pins every row the walks write",
          "atoms": ["The characterization pins every row the walks write"],
          "generality": [3],
          "confidence": 0.9
        }
      ]
    }
  ],
  "relationships": [
    {
      "source_path": "sections/0/paragraphs/0/atoms/0",
      "target_path": "sections/1/paragraphs/0/atoms/0",
      "relationship": "supports"
    }
  ]
}"#;

async fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let scoped = fixture::scoped_pool(&pool).await;
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

fn body(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = &result
        .content
        .first()
        .expect("a content block")
        .as_text()
        .expect("text content")
        .text;
    serde_json::from_str(text).expect("response JSON")
}

/// Every id the dump can meet, named by role: the paper, the ingesting agent,
/// each other agent by display name, each claim by level and text, and an
/// evidence row by the claim it supports.
async fn role_names(pool: &PgPool, ingester: Uuid) -> HashMap<Uuid, String> {
    let mut names = HashMap::new();
    let paper: Uuid = sqlx::query_scalar("SELECT id FROM papers WHERE doi = $1")
        .bind(DOI)
        .fetch_one(pool)
        .await
        .expect("the paper row");
    names.insert(paper, "PAPER".to_string());
    names.insert(ingester, "INGESTER".to_string());
    let claims: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT id, content, properties ->> 'level' FROM claims WHERE $1 = ANY(labels)",
    )
    .bind(format!("doi:{DOI}"))
    .fetch_all(pool)
    .await
    .expect("the document's claims");
    for (id, content, level) in claims {
        names.insert(id, format!("L{}:{content}", level.unwrap_or_default()));
    }
    let evidence: Vec<(Uuid, Uuid)> =
        sqlx::query_as("SELECT id, claim_id FROM evidence WHERE claim_id = ANY($1)")
            .bind(names.keys().copied().collect::<Vec<_>>())
            .fetch_all(pool)
            .await
            .expect("evidence rows");
    for (id, claim) in evidence {
        let of = names.get(&claim).cloned().unwrap_or_default();
        names.insert(id, format!("EVIDENCE[{of}]"));
    }
    let agents: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT a.id, a.display_name FROM agents a
          WHERE a.id IN (SELECT source_id FROM edges WHERE source_type = 'agent'
                          AND target_id = ANY($1))",
    )
    .bind(names.keys().copied().collect::<Vec<_>>())
    .fetch_all(pool)
    .await
    .expect("author agents");
    for (id, name) in agents {
        names
            .entry(id)
            .or_insert_with(|| format!("AGENT:{}", name.unwrap_or_default()));
    }
    names
}

/// `v` with every UUID string replaced by its role name (`<id>` when it has
/// none), so the dump is stable across databases.
fn canonical(v: &serde_json::Value, names: &HashMap<Uuid, String>) -> serde_json::Value {
    match v {
        serde_json::Value::String(s) => match Uuid::parse_str(s) {
            Ok(id) => serde_json::Value::String(
                names
                    .get(&id)
                    .cloned()
                    .unwrap_or_else(|| "<id>".to_string()),
            ),
            Err(_) => v.clone(),
        },
        serde_json::Value::Array(a) => {
            serde_json::Value::Array(a.iter().map(|x| canonical(x, names)).collect())
        }
        serde_json::Value::Object(m) => serde_json::Value::Object(
            m.iter()
                .map(|(k, x)| (k.clone(), canonical(x, names)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// The graph the walks left for `DOI`, as sorted, role-named lines.
async fn dump(pool: &PgPool, ingester: Uuid) -> Vec<String> {
    let names = role_names(pool, ingester).await;
    let name = |id: Uuid| {
        names
            .get(&id)
            .cloned()
            .unwrap_or_else(|| "<id>".to_string())
    };
    let claim_ids: Vec<Uuid> = names
        .iter()
        .filter(|(_, n)| n.starts_with('L'))
        .map(|(id, _)| *id)
        .collect();
    let mut node_ids = claim_ids.clone();
    node_ids.extend(
        names
            .iter()
            .filter(|(_, n)| *n == "PAPER")
            .map(|(id, _)| *id),
    );

    let mut out = Vec::new();
    let claims: Vec<(Uuid, Vec<String>, Uuid, bool)> = sqlx::query_as(
        "SELECT id, labels, agent_id, trace_id IS NOT NULL FROM claims WHERE id = ANY($1)",
    )
    .bind(&claim_ids)
    .fetch_all(pool)
    .await
    .expect("claims");
    for (id, mut labels, agent, has_trace) in claims {
        labels.sort();
        out.push(format!(
            "claim {} labels={labels:?} author={} trace={has_trace}",
            name(id),
            name(agent)
        ));
    }
    let edges: Vec<(Uuid, String, Uuid, String, String, serde_json::Value, bool)> = sqlx::query_as(
        "SELECT source_id, source_type, target_id, target_type, relationship, properties,
                    signature IS NOT NULL
               FROM edges WHERE source_id = ANY($1) OR target_id = ANY($1)",
    )
    .bind(&node_ids)
    .fetch_all(pool)
    .await
    .expect("edges");
    for (s, st, t, tt, rel, props, signed) in edges {
        out.push(format!(
            "edge {}:{st} -{rel}-> {}:{tt} signed={signed} props={}",
            name(s),
            name(t),
            canonical(&props, &names)
        ));
    }
    let count = |sql: &'static str| {
        let ids = claim_ids.clone();
        async move {
            sqlx::query_scalar::<_, i64>(sql)
                .bind(ids)
                .fetch_one(pool)
                .await
                .expect(sql)
        }
    };
    out.push(format!(
        "count evidence={} traces={} mass_functions={} claim_frames={} factors={}",
        count("SELECT COUNT(*) FROM evidence WHERE claim_id = ANY($1)").await,
        count(
            "SELECT COUNT(*) FROM reasoning_traces t JOIN claims c ON c.trace_id = t.id
              WHERE c.id = ANY($1)"
        )
        .await,
        count("SELECT COUNT(*) FROM mass_functions WHERE claim_id = ANY($1)").await,
        count("SELECT COUNT(*) FROM claim_frames WHERE claim_id = ANY($1)").await,
        count("SELECT COUNT(*) FROM factors WHERE variable_ids && $1").await,
    ));
    out.sort();
    out
}

/// The spine response's walk-describing fields (ids and titles aside).
fn spine_summary(v: &serde_json::Value) -> BTreeMap<&'static str, serde_json::Value> {
    [
        "paragraphs_new",
        "paragraphs_deduped",
        "new_paragraph_paths",
        "converged_claims_unlabelled",
        "converged_claims_caller_labels_withheld",
        "already_ingested",
        "synthesized_key",
        "doi",
    ]
    .into_iter()
    .map(|k| (k, v[k].clone()))
    .collect()
}

/// `actual` equals the recorded `expected`, reported line by line.
fn assert_recorded(what: &str, actual: &[String], expected: &[&str]) {
    let missing: Vec<&&str> = expected
        .iter()
        .filter(|e| !actual.iter().any(|a| a == **e))
        .collect();
    let extra: Vec<&String> = actual
        .iter()
        .filter(|a| !expected.contains(&a.as_str()))
        .collect();
    assert!(
        missing.is_empty() && extra.is_empty() && actual.len() == expected.len(),
        "{what}: the walk wrote a different graph than the recorded one\n\
         missing ({}):\n  {}\nunexpected ({}):\n  {}",
        missing.len(),
        missing
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join("\n  "),
        extra.len(),
        extra
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n  "),
    );
}

async fn spine(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    extraction: &DocumentExtraction,
) -> serde_json::Value {
    body(
        &do_ingest_document_spine(
            server,
            viewer,
            extraction,
            None,
            epigraph_core::VisibilityChoice::Public,
        )
        .await
        .expect("the spine walk succeeds"),
    )
}

async fn full(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    extraction: &DocumentExtraction,
) -> serde_json::Value {
    body(
        &do_ingest_document(
            server,
            viewer,
            extraction,
            None,
            epigraph_core::VisibilityChoice::Public,
        )
        .await
        .expect("the full walk succeeds"),
    )
}

fn ingester_of(response: &serde_json::Value) -> Uuid {
    response["ingested_by"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("ingested_by")
}

/// The full walk's response, ids aside.
fn full_summary(v: &serde_json::Value) -> serde_json::Value {
    let mut v = v.clone();
    let map = v.as_object_mut().expect("an object");
    for k in ["paper_id", "ingested_by", "ds_frame_id"] {
        assert!(map.remove(k).is_some_and(|x| !x.is_null()), "{k} is set");
    }
    for a in map["authors"].as_array_mut().expect("authors") {
        a.as_object_mut().expect("author").remove("agent_id");
    }
    v
}

/// The two-phase flow: a spine run, a spine re-run, then the full walk.
#[sqlx::test(migrations = "../../migrations")]
async fn spine_then_full_walk_write_the_recorded_graph(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let extraction: DocumentExtraction = serde_json::from_str(FIXTURE).expect("fixture parses");

    let first = spine(&server, &viewer, &extraction).await;
    let ingester = ingester_of(&first);
    assert_eq!(
        serde_json::to_value(spine_summary(&first)).unwrap(),
        serde_json::json!({
            "already_ingested": false,
            "converged_claims_caller_labels_withheld": 0,
            "converged_claims_unlabelled": 0,
            "doi": DOI,
            "new_paragraph_paths": [
                "sections[0].paragraphs[0]",
                "sections[0].paragraphs[1]",
                "sections[1].paragraphs[0]"
            ],
            "paragraphs_deduped": 0,
            "paragraphs_new": 3,
            "synthesized_key": false,
        }),
        "the spine response: {first}"
    );
    assert_recorded("spine", &dump(&pool, ingester).await, AFTER_SPINE);

    let again = spine(&server, &viewer, &extraction).await;
    assert_eq!(
        serde_json::to_value(spine_summary(&again)).unwrap(),
        serde_json::json!({
            "already_ingested": true,
            "converged_claims_caller_labels_withheld": 0,
            "converged_claims_unlabelled": 0,
            "doi": DOI,
            "new_paragraph_paths": [],
            "paragraphs_deduped": 3,
            "paragraphs_new": 0,
            "synthesized_key": false,
        }),
        "the spine re-run response: {again}"
    );
    assert_recorded("spine re-run", &dump(&pool, ingester).await, AFTER_SPINE);

    let walked = full(&server, &viewer, &extraction).await;
    assert_eq!(ingester_of(&walked), ingester);
    assert_eq!(
        full_summary(&walked),
        serde_json::json!({
            "already_ingested": false,
            "authors": [{
                "action": "reused_name_key",
                "asserts_claims": true,
                "attribution": "name_derived",
                "name": "Parity Author",
                "position": 0,
                "status": "matched"
            }],
            "claims_ds_wired": 4,
            "claims_embedded": 0,
            "claims_embedding_queued": 0,
            "claims_ingested": 4,
            "claims_skipped_dedup": 6,
            "converged_claims_caller_labels_withheld": 0,
            "converged_claims_unlabelled": 0,
            "doi": DOI,
            "paper_title": "Walk Levels Parity Paper",
            "relationships_created": 9,
            "synthesized_key": false,
        }),
        "the full walk's response after a spine: {walked}"
    );
    assert_recorded(
        "full after spine",
        &dump(&pool, ingester).await,
        AFTER_SPINE_THEN_FULL,
    );
}

/// The single-call flow: the full walk on a new document, then a spine run
/// over it, which converges on every structural node and writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn full_then_spine_walk_write_the_recorded_graph(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let extraction: DocumentExtraction = serde_json::from_str(FIXTURE).expect("fixture parses");

    let walked = full(&server, &viewer, &extraction).await;
    let ingester = ingester_of(&walked);
    assert_eq!(
        full_summary(&walked),
        serde_json::json!({
            "already_ingested": false,
            "authors": [{
                "action": "created_name_key",
                "asserts_claims": true,
                "attribution": "name_derived",
                "name": "Parity Author",
                "position": 0,
                "status": "created"
            }],
            "claims_ds_wired": 4,
            "claims_embedded": 0,
            "claims_embedding_queued": 0,
            "claims_ingested": 10,
            "claims_skipped_dedup": 0,
            "converged_claims_caller_labels_withheld": 0,
            "converged_claims_unlabelled": 0,
            "doi": DOI,
            "paper_title": "Walk Levels Parity Paper",
            "relationships_created": 22,
            "synthesized_key": false,
        }),
        "the full walk's response: {walked}"
    );
    assert_recorded("full", &dump(&pool, ingester).await, AFTER_FULL);

    let after = spine(&server, &viewer, &extraction).await;
    assert_eq!(
        serde_json::to_value(spine_summary(&after)).unwrap(),
        serde_json::json!({
            "already_ingested": true,
            "converged_claims_caller_labels_withheld": 0,
            "converged_claims_unlabelled": 0,
            "doi": DOI,
            "new_paragraph_paths": [],
            "paragraphs_deduped": 3,
            "paragraphs_new": 0,
            "synthesized_key": false,
        }),
        "the spine response after a full walk: {after}"
    );
    assert_recorded("spine after full", &dump(&pool, ingester).await, AFTER_FULL);
}

/// Recorded from the pre-fold walkers.
const AFTER_SPINE: &[&str] = &[
    r##"claim L0:One walker serves both ingest levels labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L1:Background labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L1:Method labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L2:A level filter keeps the two walks from drifting apart labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L2:Spine ingests write structure only, and full ingests add atoms labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L2:The characterization pins every row the walks write labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"count evidence=6 traces=6 mass_functions=0 claim_frames=0 factors=0"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L0:One walker serves both ingest levels:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L1:Background:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L1:Method:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L2:A level filter keeps the two walks from drifting apart:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L2:Spine ingests write structure only, and full ingests add atoms:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L2:The characterization pins every row the walks write:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -authored-> PAPER:paper signed=true props={"affiliations":[],"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"position":0,"role":"author"}"##,
    r##"edge EVIDENCE[L0:One walker serves both ingest levels]:evidence -supports-> L0:One walker serves both ingest levels:claim signed=true props={}"##,
    r##"edge EVIDENCE[L1:Background]:evidence -supports-> L1:Background:claim signed=true props={}"##,
    r##"edge EVIDENCE[L1:Method]:evidence -supports-> L1:Method:claim signed=true props={}"##,
    r##"edge EVIDENCE[L2:A level filter keeps the two walks from drifting apart]:evidence -supports-> L2:A level filter keeps the two walks from drifting apart:claim signed=true props={}"##,
    r##"edge EVIDENCE[L2:Spine ingests write structure only, and full ingests add atoms]:evidence -supports-> L2:Spine ingests write structure only, and full ingests add atoms:claim signed=true props={}"##,
    r##"edge EVIDENCE[L2:The characterization pins every row the walks write]:evidence -supports-> L2:The characterization pins every row the walks write:claim signed=true props={}"##,
    r##"edge L0:One walker serves both ingest levels:claim -decomposes_to-> L1:Background:claim signed=true props={}"##,
    r##"edge L0:One walker serves both ingest levels:claim -decomposes_to-> L1:Method:claim signed=true props={}"##,
    r##"edge L1:Background:claim -decomposes_to-> L2:A level filter keeps the two walks from drifting apart:claim signed=true props={}"##,
    r##"edge L1:Background:claim -decomposes_to-> L2:Spine ingests write structure only, and full ingests add atoms:claim signed=true props={}"##,
    r##"edge L1:Background:claim -section_follows-> L1:Method:claim signed=true props={}"##,
    r##"edge L1:Method:claim -decomposes_to-> L2:The characterization pins every row the walks write:claim signed=true props={}"##,
    r##"edge L2:Spine ingests write structure only, and full ingests add atoms:claim -continues_argument-> L2:A level filter keeps the two walks from drifting apart:claim signed=true props={}"##,
    r##"edge PAPER:paper -asserts-> L0:One walker serves both ingest levels:claim signed=true props={"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"level":0,"source_type":"Paper","thesis_derivation":"TopDown"}"##,
    r##"edge PAPER:paper -asserts-> L1:Background:claim signed=true props={"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"level":1,"section":"Background","source_type":"Paper","spine_text_kind":"extracted_v2"}"##,
    r##"edge PAPER:paper -asserts-> L1:Method:claim signed=true props={"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"level":1,"section":"Method","source_type":"Paper","spine_text_kind":"extracted_v2"}"##,
    r##"edge PAPER:paper -asserts-> L2:A level filter keeps the two walks from drifting apart:claim signed=true props={"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"level":2,"section":"Background","source_type":"Paper","spine_text_kind":"extracted_v2"}"##,
    r##"edge PAPER:paper -asserts-> L2:Spine ingests write structure only, and full ingests add atoms:claim signed=true props={"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"level":2,"section":"Background","source_type":"Paper","spine_text_kind":"extracted_v2"}"##,
    r##"edge PAPER:paper -asserts-> L2:The characterization pins every row the walks write:claim signed=true props={"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"level":2,"section":"Method","source_type":"Paper","spine_text_kind":"extracted_v2"}"##,
    r##"edge PAPER:paper -ingested_claim-> L0:One walker serves both ingest levels:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document_spine"}"##,
    r##"edge PAPER:paper -ingested_claim-> L1:Background:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document_spine"}"##,
    r##"edge PAPER:paper -ingested_claim-> L1:Method:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document_spine"}"##,
    r##"edge PAPER:paper -ingested_claim-> L2:A level filter keeps the two walks from drifting apart:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document_spine"}"##,
    r##"edge PAPER:paper -ingested_claim-> L2:Spine ingests write structure only, and full ingests add atoms:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document_spine"}"##,
    r##"edge PAPER:paper -ingested_claim-> L2:The characterization pins every row the walks write:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document_spine"}"##,
    r##"edge PAPER:paper -processed_by-> INGESTER:agent signed=true props={"pipeline":"hierarchical_extraction_v2","tool":"ingest_document_spine"}"##,
];

/// Recorded from the pre-fold walkers.
const AFTER_SPINE_THEN_FULL: &[&str] = &[
    r##"claim L0:One walker serves both ingest levels labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L1:Background labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L1:Method labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L2:A level filter keeps the two walks from drifting apart labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L2:Spine ingests write structure only, and full ingests add atoms labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L2:The characterization pins every row the walks write labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L3:A level filter keeps the two walks from drifting apart labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L3:Full ingests add atoms beneath the structure labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L3:Spine ingests write structure only labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L3:The characterization pins every row the walks write labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"count evidence=10 traces=10 mass_functions=4 claim_frames=4 factors=1"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L0:One walker serves both ingest levels:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L1:Background:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L1:Method:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L2:A level filter keeps the two walks from drifting apart:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L2:Spine ingests write structure only, and full ingests add atoms:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L2:The characterization pins every row the walks write:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L3:A level filter keeps the two walks from drifting apart:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L3:Full ingests add atoms beneath the structure:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L3:Spine ingests write structure only:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L3:The characterization pins every row the walks write:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -authored-> PAPER:paper signed=true props={"affiliations":[],"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"position":0,"role":"author"}"##,
    r##"edge EVIDENCE[L0:One walker serves both ingest levels]:evidence -supports-> L0:One walker serves both ingest levels:claim signed=true props={}"##,
    r##"edge EVIDENCE[L1:Background]:evidence -supports-> L1:Background:claim signed=true props={}"##,
    r##"edge EVIDENCE[L1:Method]:evidence -supports-> L1:Method:claim signed=true props={}"##,
    r##"edge EVIDENCE[L2:A level filter keeps the two walks from drifting apart]:evidence -supports-> L2:A level filter keeps the two walks from drifting apart:claim signed=true props={}"##,
    r##"edge EVIDENCE[L2:Spine ingests write structure only, and full ingests add atoms]:evidence -supports-> L2:Spine ingests write structure only, and full ingests add atoms:claim signed=true props={}"##,
    r##"edge EVIDENCE[L2:The characterization pins every row the walks write]:evidence -supports-> L2:The characterization pins every row the walks write:claim signed=true props={}"##,
    r##"edge EVIDENCE[L3:A level filter keeps the two walks from drifting apart]:evidence -supports-> L3:A level filter keeps the two walks from drifting apart:claim signed=true props={}"##,
    r##"edge EVIDENCE[L3:Full ingests add atoms beneath the structure]:evidence -supports-> L3:Full ingests add atoms beneath the structure:claim signed=true props={}"##,
    r##"edge EVIDENCE[L3:Spine ingests write structure only]:evidence -supports-> L3:Spine ingests write structure only:claim signed=true props={}"##,
    r##"edge EVIDENCE[L3:The characterization pins every row the walks write]:evidence -supports-> L3:The characterization pins every row the walks write:claim signed=true props={}"##,
    r##"edge L0:One walker serves both ingest levels:claim -decomposes_to-> L1:Background:claim signed=true props={}"##,
    r##"edge L0:One walker serves both ingest levels:claim -decomposes_to-> L1:Method:claim signed=true props={}"##,
    r##"edge L1:Background:claim -decomposes_to-> L2:A level filter keeps the two walks from drifting apart:claim signed=true props={}"##,
    r##"edge L1:Background:claim -decomposes_to-> L2:Spine ingests write structure only, and full ingests add atoms:claim signed=true props={}"##,
    r##"edge L1:Background:claim -section_follows-> L1:Method:claim signed=true props={}"##,
    r##"edge L1:Method:claim -decomposes_to-> L2:The characterization pins every row the walks write:claim signed=true props={}"##,
    r##"edge L2:A level filter keeps the two walks from drifting apart:claim -decomposes_to-> L3:A level filter keeps the two walks from drifting apart:claim signed=true props={}"##,
    r##"edge L2:Spine ingests write structure only, and full ingests add atoms:claim -continues_argument-> L2:A level filter keeps the two walks from drifting apart:claim signed=true props={}"##,
    r##"edge L2:Spine ingests write structure only, and full ingests add atoms:claim -decomposes_to-> L3:Full ingests add atoms beneath the structure:claim signed=true props={}"##,
    r##"edge L2:Spine ingests write structure only, and full ingests add atoms:claim -decomposes_to-> L3:Spine ingests write structure only:claim signed=true props={}"##,
    r##"edge L2:The characterization pins every row the walks write:claim -decomposes_to-> L3:The characterization pins every row the walks write:claim signed=true props={}"##,
    r##"edge L3:Spine ingests write structure only:claim -supports-> L3:The characterization pins every row the walks write:claim signed=true props={}"##,
    r##"edge PAPER:paper -asserts-> L0:One walker serves both ingest levels:claim signed=true props={"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"level":0,"source_type":"Paper","thesis_derivation":"TopDown"}"##,
    r##"edge PAPER:paper -asserts-> L1:Background:claim signed=true props={"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"level":1,"section":"Background","source_type":"Paper","spine_text_kind":"extracted_v2"}"##,
    r##"edge PAPER:paper -asserts-> L1:Method:claim signed=true props={"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"level":1,"section":"Method","source_type":"Paper","spine_text_kind":"extracted_v2"}"##,
    r##"edge PAPER:paper -asserts-> L2:A level filter keeps the two walks from drifting apart:claim signed=true props={"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"level":2,"section":"Background","source_type":"Paper","spine_text_kind":"extracted_v2"}"##,
    r##"edge PAPER:paper -asserts-> L2:Spine ingests write structure only, and full ingests add atoms:claim signed=true props={"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"level":2,"section":"Background","source_type":"Paper","spine_text_kind":"extracted_v2"}"##,
    r##"edge PAPER:paper -asserts-> L2:The characterization pins every row the walks write:claim signed=true props={"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"level":2,"section":"Method","source_type":"Paper","spine_text_kind":"extracted_v2"}"##,
    r##"edge PAPER:paper -asserts-> L3:A level filter keeps the two walks from drifting apart:claim signed=true props={"generality":2,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"level":3,"section":"Background","source_type":"Paper"}"##,
    r##"edge PAPER:paper -asserts-> L3:Full ingests add atoms beneath the structure:claim signed=true props={"generality":3,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"level":3,"section":"Background","source_type":"Paper"}"##,
    r##"edge PAPER:paper -asserts-> L3:Spine ingests write structure only:claim signed=true props={"generality":2,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"level":3,"section":"Background","source_type":"Paper"}"##,
    r##"edge PAPER:paper -asserts-> L3:The characterization pins every row the walks write:claim signed=true props={"generality":3,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"level":3,"section":"Method","source_type":"Paper"}"##,
    r##"edge PAPER:paper -ingested_claim-> L0:One walker serves both ingest levels:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document_spine"}"##,
    r##"edge PAPER:paper -ingested_claim-> L1:Background:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document_spine"}"##,
    r##"edge PAPER:paper -ingested_claim-> L1:Method:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document_spine"}"##,
    r##"edge PAPER:paper -ingested_claim-> L2:A level filter keeps the two walks from drifting apart:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document_spine"}"##,
    r##"edge PAPER:paper -ingested_claim-> L2:Spine ingests write structure only, and full ingests add atoms:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document_spine"}"##,
    r##"edge PAPER:paper -ingested_claim-> L2:The characterization pins every row the walks write:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document_spine"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document_spine"}"##,
    r##"edge PAPER:paper -ingested_claim-> L3:A level filter keeps the two walks from drifting apart:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document"}"##,
    r##"edge PAPER:paper -ingested_claim-> L3:Full ingests add atoms beneath the structure:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document"}"##,
    r##"edge PAPER:paper -ingested_claim-> L3:Spine ingests write structure only:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document"}"##,
    r##"edge PAPER:paper -ingested_claim-> L3:The characterization pins every row the walks write:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document"}"##,
    r##"edge PAPER:paper -processed_by-> INGESTER:agent signed=true props={"pipeline":"hierarchical_extraction_v2","tool":"ingest_document_spine"}"##,
];

/// Recorded from the pre-fold walkers.
const AFTER_FULL: &[&str] = &[
    r##"claim L0:One walker serves both ingest levels labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L1:Background labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L1:Method labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L2:A level filter keeps the two walks from drifting apart labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L2:Spine ingests write structure only, and full ingests add atoms labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L2:The characterization pins every row the walks write labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L3:A level filter keeps the two walks from drifting apart labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L3:Full ingests add atoms beneath the structure labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L3:Spine ingests write structure only labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"claim L3:The characterization pins every row the walks write labels=["doi:10.1234/walk-levels-parity"] author=INGESTER trace=true"##,
    r##"count evidence=10 traces=10 mass_functions=4 claim_frames=4 factors=1"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L0:One walker serves both ingest levels:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L1:Background:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L1:Method:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L2:A level filter keeps the two walks from drifting apart:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L2:Spine ingests write structure only, and full ingests add atoms:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L2:The characterization pins every row the walks write:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L3:A level filter keeps the two walks from drifting apart:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L3:Full ingests add atoms beneath the structure:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L3:Spine ingests write structure only:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -asserts-> L3:The characterization pins every row the walks write:claim signed=true props={"author_index":0,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"role":"author","source":"document_attribution"}"##,
    r##"edge AGENT:Parity Author:agent -authored-> PAPER:paper signed=true props={"affiliations":[],"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"position":0,"role":"author"}"##,
    r##"edge EVIDENCE[L0:One walker serves both ingest levels]:evidence -supports-> L0:One walker serves both ingest levels:claim signed=true props={}"##,
    r##"edge EVIDENCE[L1:Background]:evidence -supports-> L1:Background:claim signed=true props={}"##,
    r##"edge EVIDENCE[L1:Method]:evidence -supports-> L1:Method:claim signed=true props={}"##,
    r##"edge EVIDENCE[L2:A level filter keeps the two walks from drifting apart]:evidence -supports-> L2:A level filter keeps the two walks from drifting apart:claim signed=true props={}"##,
    r##"edge EVIDENCE[L2:Spine ingests write structure only, and full ingests add atoms]:evidence -supports-> L2:Spine ingests write structure only, and full ingests add atoms:claim signed=true props={}"##,
    r##"edge EVIDENCE[L2:The characterization pins every row the walks write]:evidence -supports-> L2:The characterization pins every row the walks write:claim signed=true props={}"##,
    r##"edge EVIDENCE[L3:A level filter keeps the two walks from drifting apart]:evidence -supports-> L3:A level filter keeps the two walks from drifting apart:claim signed=true props={}"##,
    r##"edge EVIDENCE[L3:Full ingests add atoms beneath the structure]:evidence -supports-> L3:Full ingests add atoms beneath the structure:claim signed=true props={}"##,
    r##"edge EVIDENCE[L3:Spine ingests write structure only]:evidence -supports-> L3:Spine ingests write structure only:claim signed=true props={}"##,
    r##"edge EVIDENCE[L3:The characterization pins every row the walks write]:evidence -supports-> L3:The characterization pins every row the walks write:claim signed=true props={}"##,
    r##"edge L0:One walker serves both ingest levels:claim -decomposes_to-> L1:Background:claim signed=true props={}"##,
    r##"edge L0:One walker serves both ingest levels:claim -decomposes_to-> L1:Method:claim signed=true props={}"##,
    r##"edge L1:Background:claim -decomposes_to-> L2:A level filter keeps the two walks from drifting apart:claim signed=true props={}"##,
    r##"edge L1:Background:claim -decomposes_to-> L2:Spine ingests write structure only, and full ingests add atoms:claim signed=true props={}"##,
    r##"edge L1:Background:claim -section_follows-> L1:Method:claim signed=true props={}"##,
    r##"edge L1:Method:claim -decomposes_to-> L2:The characterization pins every row the walks write:claim signed=true props={}"##,
    r##"edge L2:A level filter keeps the two walks from drifting apart:claim -decomposes_to-> L3:A level filter keeps the two walks from drifting apart:claim signed=true props={}"##,
    r##"edge L2:Spine ingests write structure only, and full ingests add atoms:claim -continues_argument-> L2:A level filter keeps the two walks from drifting apart:claim signed=true props={}"##,
    r##"edge L2:Spine ingests write structure only, and full ingests add atoms:claim -decomposes_to-> L3:Full ingests add atoms beneath the structure:claim signed=true props={}"##,
    r##"edge L2:Spine ingests write structure only, and full ingests add atoms:claim -decomposes_to-> L3:Spine ingests write structure only:claim signed=true props={}"##,
    r##"edge L2:The characterization pins every row the walks write:claim -decomposes_to-> L3:The characterization pins every row the walks write:claim signed=true props={}"##,
    r##"edge L3:Spine ingests write structure only:claim -supports-> L3:The characterization pins every row the walks write:claim signed=true props={}"##,
    r##"edge PAPER:paper -asserts-> L0:One walker serves both ingest levels:claim signed=true props={"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"level":0,"source_type":"Paper","thesis_derivation":"TopDown"}"##,
    r##"edge PAPER:paper -asserts-> L1:Background:claim signed=true props={"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"level":1,"section":"Background","source_type":"Paper","spine_text_kind":"extracted_v2"}"##,
    r##"edge PAPER:paper -asserts-> L1:Method:claim signed=true props={"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"level":1,"section":"Method","source_type":"Paper","spine_text_kind":"extracted_v2"}"##,
    r##"edge PAPER:paper -asserts-> L2:A level filter keeps the two walks from drifting apart:claim signed=true props={"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"level":2,"section":"Background","source_type":"Paper","spine_text_kind":"extracted_v2"}"##,
    r##"edge PAPER:paper -asserts-> L2:Spine ingests write structure only, and full ingests add atoms:claim signed=true props={"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"level":2,"section":"Background","source_type":"Paper","spine_text_kind":"extracted_v2"}"##,
    r##"edge PAPER:paper -asserts-> L2:The characterization pins every row the walks write:claim signed=true props={"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"level":2,"section":"Method","source_type":"Paper","spine_text_kind":"extracted_v2"}"##,
    r##"edge PAPER:paper -asserts-> L3:A level filter keeps the two walks from drifting apart:claim signed=true props={"generality":2,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"level":3,"section":"Background","source_type":"Paper"}"##,
    r##"edge PAPER:paper -asserts-> L3:Full ingests add atoms beneath the structure:claim signed=true props={"generality":3,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"level":3,"section":"Background","source_type":"Paper"}"##,
    r##"edge PAPER:paper -asserts-> L3:Spine ingests write structure only:claim signed=true props={"generality":2,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"level":3,"section":"Background","source_type":"Paper"}"##,
    r##"edge PAPER:paper -asserts-> L3:The characterization pins every row the walks write:claim signed=true props={"generality":3,"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"level":3,"section":"Method","source_type":"Paper"}"##,
    r##"edge PAPER:paper -ingested_claim-> L0:One walker serves both ingest levels:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document"}"##,
    r##"edge PAPER:paper -ingested_claim-> L1:Background:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document"}"##,
    r##"edge PAPER:paper -ingested_claim-> L1:Method:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document"}"##,
    r##"edge PAPER:paper -ingested_claim-> L2:A level filter keeps the two walks from drifting apart:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document"}"##,
    r##"edge PAPER:paper -ingested_claim-> L2:Spine ingests write structure only, and full ingests add atoms:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document"}"##,
    r##"edge PAPER:paper -ingested_claim-> L2:The characterization pins every row the walks write:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document"}"##,
    r##"edge PAPER:paper -ingested_claim-> L3:A level filter keeps the two walks from drifting apart:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document"}"##,
    r##"edge PAPER:paper -ingested_claim-> L3:Full ingests add atoms beneath the structure:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document"}"##,
    r##"edge PAPER:paper -ingested_claim-> L3:Spine ingests write structure only:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document"}"##,
    r##"edge PAPER:paper -ingested_claim-> L3:The characterization pins every row the walks write:claim signed=true props={"created_claim":true,"ingest_authors":["AGENT:Parity Author"],"ingest_written":{"by":"INGESTER","tool":"ingest_document"},"ingested_by":"INGESTER","pipeline":"hierarchical_extraction_v2","tool":"ingest_document"}"##,
    r##"edge PAPER:paper -processed_by-> INGESTER:agent signed=true props={"pipeline":"hierarchical_extraction_v2","tool":"ingest_document"}"##,
];
