#![allow(clippy::wildcard_imports)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use rmcp::model::*;
use uuid::Uuid;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;
use crate::tools::ds_auto::{self, BatchDsEntry};
use crate::types::*;

use epigraph_core::{
    AgentId, Claim, ClaimId, Evidence, EvidenceType, Methodology, ReasoningTrace, TraceInput,
    TruthValue,
};
use epigraph_crypto::ContentHasher;
use epigraph_db::{
    AgentRepository, ClaimRepository, EdgeRepository, EvidenceRepository, PaperRepository,
    ReasoningTraceRepository,
};
use epigraph_ingest::builder::{build_ingest_plan, PlannedClaim};
use epigraph_ingest::document::schema::ByteSpan;
use epigraph_ingest::document::structure::{
    parse_structure, slice_segmentation, SourceFormat, StructuredDoc,
};
use epigraph_ingest::schema::{DocumentExtraction, DocumentSource, Paragraph, Section};

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

// ────────────────────────────────────────────────────────────────────────────
// structure_source — raw markdown/plaintext → verbatim DocumentExtraction
// ────────────────────────────────────────────────────────────────────────────

/// Map a verbatim [`StructuredDoc`] into a [`DocumentExtraction`] with atoms
/// EMPTY. The agent fills `atoms` per paragraph and resubmits via
/// `ingest_document_inline`. `source_text` + per-node spans are populated so the
/// writer's verbatim guard re-verifies the round-trip.
fn structured_doc_to_extraction(doc: StructuredDoc, source: DocumentSource) -> DocumentExtraction {
    let sections = doc
        .sections
        .into_iter()
        .map(|s| Section {
            title: s
                .heading
                .as_ref()
                .map(|h| h.text.clone())
                .unwrap_or_default(),
            heading_span: s.heading.map(|h| ByteSpan {
                start: h.start,
                end: h.end,
            }),
            // Deterministic structuring cannot infer a labeled axis from raw
            // bytes (issue #222). The agent adds `axis` to the paragraphs (or
            // sections) it wants placed on one before resubmitting via
            // `ingest_document_inline`.
            axis: None,
            paragraphs: s
                .paragraphs
                .into_iter()
                .map(|p| Paragraph {
                    text: p.span.text,
                    span: Some(ByteSpan {
                        start: p.span.start,
                        end: p.span.end,
                    }),
                    atoms: Vec::new(),
                    generality: Vec::new(),
                    confidence: 0.8,
                    methodology: Some("verbatim_structurer".to_string()),
                    evidence_type: None,
                    axis: None,
                    axis_labels: Vec::new(),
                    page: None,
                    instruments_used: Vec::new(),
                    reagents_involved: Vec::new(),
                    conditions: Vec::new(),
                })
                .collect(),
        })
        .collect();
    DocumentExtraction {
        source,
        thesis: None,
        thesis_derivation: Default::default(),
        sections,
        relationships: Vec::new(),
        source_text: Some(doc.source_text),
    }
}

/// Deterministically structure raw markdown/plaintext (or an agent-supplied
/// messy-input `segmentation`) into a verbatim [`DocumentExtraction`].
/// Read-only / no DB writes — pure compute, hence `clippy::unused_async`: the
/// `#[tool]` server method must be `async`, and it `.await`s this fn.
#[allow(clippy::unused_async)]
pub async fn structure_source(
    _server: &EpiGraphMcpFull,
    params: StructureSourceParams,
) -> Result<CallToolResult, McpError> {
    let doc = if let Some(seg) = params.segmentation {
        slice_segmentation(&params.text, &seg.into())
            .map_err(|e| invalid_params(format!("segmentation failed: {e}")))?
    } else {
        let fmt = match params.format.as_str() {
            "markdown" => SourceFormat::Markdown,
            "plaintext" => SourceFormat::PlainText,
            other => {
                return Err(invalid_params(format!(
                    "unknown format {other:?}; use markdown|plaintext"
                )))
            }
        };
        parse_structure(&params.text, fmt)
            .map_err(|e| invalid_params(format!("structuring failed: {e}")))?
    };
    let extraction = structured_doc_to_extraction(doc, params.source);
    success_json(&extraction)
}

// ────────────────────────────────────────────────────────────────────────────
// ingest_document — hierarchical DocumentExtraction → graph
// ────────────────────────────────────────────────────────────────────────────

const PIPELINE_VERSION_BASE: &str = "hierarchical_extraction_v2";

/// Pipeline version stamp used by the `processed_by` edge and the version gate.
///
/// For documents ingested whole (papers), this is just `PIPELINE_VERSION_BASE`
/// so re-ingesting the same paper short-circuits as before. For chunked
/// ingests where many `DocumentExtraction`s share one paper row (e.g. a
/// textbook ingested chapter-by-chapter), `source.metadata.chapter_index` is
/// appended so each chunk is gated independently — without it, the first
/// chunk's `processed_by` edge would block every subsequent chunk for the
/// same paper.
fn effective_pipeline_version(extraction: &DocumentExtraction) -> String {
    extraction
        .source
        .metadata
        .get("chapter_index")
        .and_then(serde_json::Value::as_u64)
        .map_or_else(
            || PIPELINE_VERSION_BASE.to_string(),
            |n| format!("{PIPELINE_VERSION_BASE}:ch{n}"),
        )
}

pub async fn ingest_document(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: IngestDocumentParams,
) -> Result<CallToolResult, McpError> {
    let canonical = std::fs::canonicalize(&params.file_path)
        .map_err(|e| invalid_params(format!("invalid file path: {e}")))?;
    let cwd = std::env::current_dir()
        .map_err(|e| internal_error(format!("cannot determine CWD: {e}")))?;
    if !canonical.starts_with(&cwd) {
        return Err(invalid_params(
            "file path must be within the working directory",
        ));
    }
    let data = tokio::fs::read_to_string(&canonical)
        .await
        .map_err(|e| invalid_params(format!("cannot read {}: {e}", canonical.display())))?;
    let extraction: DocumentExtraction =
        serde_json::from_str(&data).map_err(|e| invalid_params(format!("invalid JSON: {e}")))?;

    let doi = resolve_doi(&extraction);
    let title = extraction.source.title.clone();
    let paper_id = ensure_paper_node(server, &extraction, &doi).await?;
    let bg = EpiGraphMcpFull::new_shared(
        server.pool.clone(),
        Arc::clone(&server.signer),
        Arc::clone(&server.embedder),
        server.read_only,
    );
    let doi_log = doi.clone();
    let viewer = viewer.clone();
    tokio::spawn(async move {
        if let Err(e) = do_ingest_document(&bg, &viewer, &extraction).await {
            tracing::warn!(doi = doi_log, "background ingest_document failed: {e:?}");
        }
    });
    success_json(&queued_response(&doi, &title, paper_id))
}

/// Inline (typed-param) counterpart to [`ingest_document`]. Takes a
/// `DocumentExtraction` directly instead of a file path and routes it through
/// the same [`do_ingest_document`] core, so an MCP client can produce the
/// hierarchy in-band — without first writing a file it then can't reference.
/// Identical graph result and idempotency gate as the file-path path.
pub async fn ingest_document_inline(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: IngestDocumentInlineParams,
) -> Result<CallToolResult, McpError> {
    let extraction = params.extraction;
    let doi = resolve_doi(&extraction);
    let title = extraction.source.title.clone();
    let paper_id = ensure_paper_node(server, &extraction, &doi).await?;
    let bg = EpiGraphMcpFull::new_shared(
        server.pool.clone(),
        Arc::clone(&server.signer),
        Arc::clone(&server.embedder),
        server.read_only,
    );
    let doi_log = doi.clone();
    let viewer = viewer.clone();
    tokio::spawn(async move {
        if let Err(e) = do_ingest_document(&bg, &viewer, &extraction).await {
            tracing::warn!(
                doi = doi_log,
                "background ingest_document_inline failed: {e:?}"
            );
        }
    });
    success_json(&queued_response(&doi, &title, paper_id))
}

/// Create (or fetch) the document's `papers` row **synchronously**, before the
/// ingest is handed to a detached task, so the caller gets an id it can address
/// what it just wrote by. Idempotent on the identity key, and the background
/// `do_ingest_document` calls the same get-or-create, so this only moves the
/// node creation earlier — it does not create a second row.
///
/// Previously both ingest entry points returned `{doi, status, title, note}`
/// with no id at all (issue #356): a caller could not reference, verify, or
/// link the document it had just created.
async fn ensure_paper_node(
    server: &EpiGraphMcpFull,
    extraction: &DocumentExtraction,
    doi: &str,
) -> Result<Uuid, McpError> {
    PaperRepository::get_or_create(
        &server.pool,
        doi,
        Some(&extraction.source.title),
        extraction.source.journal.as_deref(),
    )
    .await
    .map_err(internal_error)
}

/// Shared response body for the two queued ingest entry points.
fn queued_response(doi: &str, title: &str, paper_id: Uuid) -> serde_json::Value {
    let mut note = String::from(
        "DB writes are running as a detached background task. Call check_already_ingested \
         (or query_paper) with the returned `document_key` to confirm completion before \
         assuming the write landed.",
    );
    if is_synthetic_key(doi) {
        note.push_str(
            " This document has no DOI, so `document_key` was SYNTHESIZED from its identity \
             — it is the key to poll and label with, not a real DOI. Set source.external_id \
             to pin the key to your own run id so re-ingests converge on this same node.",
        );
    }
    serde_json::json!({
        "status": "queued",
        // `paper_id` is the addressable node; `document_key` is what `papers.doi`,
        // the `doi:<key>` claim label, and check_already_ingested are keyed on.
        "paper_id": paper_id,
        "document_key": doi,
        "synthesized_key": is_synthetic_key(doi),
        // Retained under its original name for callers that already read it.
        "doi": doi,
        "title": title,
        "note": note,
    })
}

/// Pool-only gate check: returns `Some(paper_id)` iff a paper with `doi`
/// exists AND has a `processed_by` edge whose `properties.pipeline` equals
/// `pipeline_version`. Mirrors the inline gate used by `do_ingest_document`.
pub async fn paper_already_ingested(
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    doi: &str,
    pipeline_version: &str,
) -> Result<Option<Uuid>, McpError> {
    let Some(prior) = PaperRepository::find_by_doi(pool, doi)
        .await
        .map_err(internal_error)?
    else {
        return Ok(None);
    };
    if PaperRepository::has_processed_by_edge(pool, viewer, prior.id, pipeline_version)
        .await
        .map_err(internal_error)?
    {
        Ok(Some(prior.id))
    } else {
        Ok(None)
    }
}

/// Pre-flight idempotency check exposing the same `(doi, pipeline)` gate that
/// `do_ingest_document` runs internally. Lets callers (skills, orchestrators)
/// short-circuit *before* paying for an `extract-claims` LLM call when a
/// paper has already been processed at the requested pipeline version.
///
/// This tool only reads the gate; it does no extraction or ingestion. To
/// actually save extraction cost on re-runs, callers must invoke this tool
/// first and skip their own LLM call when `already_ingested` is true.
///
/// Defaults to [`PIPELINE_VERSION_BASE`] (the whole-document stamp) when the
/// caller omits `pipeline_version`, mirroring the gate that runs for a paper
/// ingested whole; per-chapter chunked ingests carry a `:ch{n}` suffix and
/// must pass the exact stamp to gate a single chunk.
pub async fn check_already_ingested(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: CheckAlreadyIngestedParams,
) -> Result<CallToolResult, McpError> {
    // A placeholder is not an identity. Answering the gate for `doi: "unknown"`
    // used to report on whatever shared bucket every DOI-less document had
    // collapsed into (issue #356); fail loudly and point at the real key instead.
    if is_placeholder_id(&params.doi) {
        return Err(invalid_params(format!(
            "{:?} is a placeholder, not a document identity. Documents with no DOI are keyed \
             on a synthesized `urn:epigraph:doc:*` key — pass the `document_key` the ingest \
             call returned (set source.external_id to control it).",
            params.doi
        )));
    }
    let pipeline = params
        .pipeline_version
        .unwrap_or_else(|| PIPELINE_VERSION_BASE.to_string());
    let paper_id = paper_already_ingested(&server.pool, viewer, &params.doi, &pipeline).await?;

    success_json(&CheckAlreadyIngestedResponse {
        already_ingested: paper_id.is_some(),
        paper_id: paper_id.map(|id| id.to_string()),
        doi: params.doi,
        pipeline_version: pipeline,
    })
}

/// Phase 1 of the two-phase ingest flow. Writes thesis + sections +
/// paragraphs (levels 0–2) and returns which paragraph paths are NEW so the
/// caller atomizes only those before submitting atoms via
/// `ingest_document_inline`. Skips atoms entirely. Structural nodes are keyed
/// on (document title, structural path, text), so re-ingesting the SAME
/// document reuses them; a DIFFERENT document that happens to share a heading
/// or a boilerplate paragraph gets its own nodes.
pub async fn ingest_document_spine(
    server: &EpiGraphMcpFull,
    params: IngestDocumentSpineParams,
) -> Result<CallToolResult, McpError> {
    do_ingest_document_spine(server, &params.extraction).await
}

/// Core ingestion logic factored out so integration tests can drive a parsed
/// `DocumentExtraction` without round-tripping through the file-path validation
/// in `ingest_document`.
#[allow(clippy::too_many_lines)]
pub async fn do_ingest_document(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    extraction: &DocumentExtraction,
) -> Result<CallToolResult, McpError> {
    // D9 writer-side verbatim re-verification: when the extraction carries
    // `source_text`, every span-backed paragraph's stored `text` must equal the
    // bytes its span points at. Fail closed before any DB write so paraphrase
    // drift can never reach a verbatim_v2 node. No-op for Tier 2 (no source_text).
    epigraph_ingest::document::structure::verify_extraction_verbatim(extraction)
        .map_err(|e| invalid_params(format!("verbatim guard failed: {e}")))?;

    // Declared-axis guard (issue #222): reject a malformed axis before any DB
    // write. Fail closed — silently degrading to the binary frame would record a
    // belief about TRUE for a claim the caller placed on a labeled hypothesis.
    epigraph_ingest::document::axis::validate_axes(extraction)
        .map_err(|e| invalid_params(format!("axis declaration invalid: {e}")))?;

    let plan = build_ingest_plan(extraction);
    let pool = &server.pool;
    let agent_id = server.agent_id().await?;
    let agent_id_typed = AgentId::from_uuid(agent_id);
    let pub_key = server.signer.public_key();

    let paper_title = extraction.source.title.clone();
    let doi = resolve_doi(extraction);
    let pipeline_version = effective_pipeline_version(extraction);
    // Attached to every claim this paper asserts so `query_claims_by_label`
    // and `recompute_beliefs(labels=[...])` can address a paper's full claim
    // set (backlog c9d12a95: neither could ever find it before this label
    // existed).
    let paper_label = format!("doi:{doi}");

    // ── 1. Get-or-create paper node ──
    // (Pipeline-version gate removed: deterministic node ids handle idempotency
    //  so re-ingesting an abstract then the full paper is safe — structural nodes
    //  by document-scoped id, atoms by content hash.
    //  Use ingest_document_spine → ingest_document_inline for the two-phase
    //  flow that avoids redundant LLM atomization.)
    let paper_id = PaperRepository::get_or_create(
        pool,
        &doi,
        Some(&paper_title),
        extraction.source.journal.as_deref(),
    )
    .await
    .map_err(internal_error)?;

    // ── 3. Ensure author agents + agent --authored--> paper ──
    // Each author gets a deterministic ed25519 keypair via
    // `did_key_for_author` — same name (or ORCID, when present in the
    // extraction) maps to the same agent across papers, which is how
    // co-authorship lights up in the graph. Affiliations and roles are
    // not yet first-class on Agent and remain in the extraction JSON
    // pending an AgentRepository properties surface.
    let mut author_responses = Vec::new();
    let mut author_agent_map: HashMap<usize, Uuid> = HashMap::new();
    // Defensive backstop (backlog a55aac45): hierarchical extraction sometimes
    // drops `source.authors` (empty array), so a paper would be recorded with no
    // real authors. When the structured list is empty, fall back to parsing the
    // author byline out of the raw `source_text` body (Tier 1 only; Tier 2 has
    // no `source_text` and silently no-ops). The parser is conservative and
    // returns empty when unsure — it never fabricates a placeholder author, so
    // the empty-fallback case preserves the pre-existing behavior exactly.
    //
    // Gated on `source_type` Paper/Textbook: only those follow the
    // title→authors→abstract convention the byline parser assumes. Reports,
    // legal, transcripts etc. put institution/label lines where a byline would
    // be, so running the parser there is pure false-positive downside.
    let byline_eligible = matches!(
        extraction.source.source_type,
        epigraph_ingest::document::schema::SourceType::Paper
            | epigraph_ingest::document::schema::SourceType::Textbook
    );
    let parsed_fallback;
    let authors: &[epigraph_ingest::common::schema::AuthorEntry] = if extraction
        .source
        .authors
        .is_empty()
        && byline_eligible
    {
        parsed_fallback = extraction
            .source_text
            .as_deref()
            .map(epigraph_ingest::document::byline::parse_byline_authors)
            .unwrap_or_default();
        if parsed_fallback.is_empty() {
            tracing::warn!(
                paper = %paper_title,
                "ingest_document: source.authors empty and no byline recovered from body; paper will have no author agents"
            );
        } else {
            tracing::info!(
                paper = %paper_title,
                count = parsed_fallback.len(),
                "ingest_document: source.authors empty; recovered authors from body byline fallback"
            );
        }
        &parsed_fallback
    } else {
        &extraction.source.authors
    };
    for (idx, author) in authors.iter().enumerate() {
        if author.name.is_empty() {
            continue;
        }
        let (_did, pub_key_bytes) =
            epigraph_crypto::did_key::did_key_for_author(None, &author.name);
        let agent_uuid = if let Some(existing) =
            AgentRepository::get_by_public_key(pool, &pub_key_bytes)
                .await
                .map_err(internal_error)?
        {
            existing.id.into()
        } else {
            let author_agent = epigraph_core::Agent::new(pub_key_bytes, Some(author.name.clone()));
            let created = AgentRepository::create(pool, &author_agent)
                .await
                .map_err(internal_error)?;
            created.id.into()
        };
        let (_row, _was_created) = EdgeRepository::create_if_not_exists(
            pool,
            agent_uuid,
            "agent",
            paper_id,
            "paper",
            "authored",
            Some(serde_json::json!({
                "position": idx,
                "role": author.roles.first().map_or("author", String::as_str),
                "affiliations": author.affiliations,
            })),
            None,
            None,
        )
        .await
        .map_err(internal_error)?;
        author_agent_map.insert(idx, agent_uuid);
        author_responses.push(AuthorResponse {
            agent_id: agent_uuid.to_string(),
            name: author.name.clone(),
        });
    }

    // ── 4. Walk planned claims: dedup → claim/trace/evidence/embed ──
    let source_url = if doi.starts_with("10.") {
        format!("https://doi.org/{doi}")
    } else {
        format!("doi:{doi}")
    };

    let mut claim_ids: Vec<String> = Vec::new();
    let mut id_map: HashMap<Uuid, Uuid> = HashMap::new();
    let mut embed_queue: Vec<(Uuid, String)> = Vec::new();
    let mut dedup_count = 0_usize;
    let mut ds_entries: Vec<BatchDsEntry> = Vec::new();

    for planned in &plan.claims {
        let confidence = planned.confidence.clamp(0.0, 1.0);
        let methodology = methodology_from_planned(planned);
        let weight = methodology.weight_modifier();
        let raw_truth = (confidence * weight).clamp(0.01, 0.99);

        let mut claim = Claim::new(
            planned.content.clone(),
            agent_id_typed,
            pub_key,
            TruthValue::clamped(raw_truth),
        );
        // Override generated id with the planner's deterministic UUID.
        claim.id = ClaimId::from_uuid(planned.id);
        // Bind the PLANNER's hash, not `hash(content)`: for document-scoped
        // nodes it folds in the artifact seed (see `ids::compound_content_hash`).
        claim.content_hash = planned.content_hash;
        claim.signature = Some(server.signer.sign(&claim.content_hash));

        let (persisted_id, resolved_to_existing) = persist_planned_claim(
            pool,
            &claim,
            planned,
            agent_id,
            TruthValue::clamped(raw_truth),
        )
        .await?;
        // Idempotent add: also runs on the dedup branch below, so an atom
        // shared across papers (convergence) picks up every paper's label.
        ClaimRepository::update_labels(pool, persisted_id, std::slice::from_ref(&paper_label), &[])
            .await
            .map_err(internal_error)?;
        if resolved_to_existing {
            let (_row, _was_created) = EdgeRepository::create_if_not_exists(
                pool,
                paper_id,
                "paper",
                persisted_id,
                "claim",
                "asserts",
                Some(planned.properties.clone()),
                None,
                None,
            )
            .await
            .map_err(internal_error)?;
            id_map.insert(planned.id, persisted_id);
            claim_ids.push(persisted_id.to_string());
            dedup_count += 1;
            continue;
        }

        // Persist hierarchy metadata (level, section, source_type, generality)
        // from the ingest plan onto the new claim's `properties` column.
        ClaimRepository::set_properties(
            pool,
            ClaimId::from_uuid(persisted_id),
            planned.properties.clone(),
        )
        .await
        .map_err(internal_error)?;

        // New claim: write the supporting evidence and reasoning trace.
        let evidence_text = planned
            .supporting_text
            .as_deref()
            .unwrap_or(&planned.content);
        let formatted_evidence =
            format!("Source: {paper_title} (DOI: {doi}). Passage: '{evidence_text}'");
        let evidence_hash = ContentHasher::hash(formatted_evidence.as_bytes());
        let mut evidence = Evidence::new(
            agent_id_typed,
            pub_key,
            evidence_hash,
            EvidenceType::Literature {
                doi: doi.clone(),
                extraction_target: format!("level_{}", planned.level),
                page_range: None,
            },
            Some(formatted_evidence),
            claim.id,
        );
        evidence.signature = Some(server.signer.sign(&evidence_hash));

        let trace = ReasoningTrace::new(
            agent_id_typed,
            pub_key,
            methodology,
            vec![TraceInput::Evidence { id: evidence.id }],
            confidence,
            format!(
                "Extracted from '{paper_title}' (DOI: {doi}); level {} ({})",
                planned.level,
                level_label(planned.level),
            ),
        );

        ReasoningTraceRepository::create(pool, &trace, claim.id)
            .await
            .map_err(internal_error)?;
        EvidenceRepository::create(pool, &evidence)
            .await
            .map_err(internal_error)?;
        ClaimRepository::update_trace_id(pool, claim.id, trace.id)
            .await
            .map_err(internal_error)?;

        let (_row, _was_created) = EdgeRepository::create_if_not_exists(
            pool,
            paper_id,
            "paper",
            persisted_id,
            "claim",
            "asserts",
            Some(planned.properties.clone()),
            None,
            None,
        )
        .await
        .map_err(internal_error)?;

        embed_queue.push((persisted_id, planned.content.clone()));

        // Atoms (level 3) are the units we trust to carry CDST evidence.
        if planned.level == 3 {
            ds_entries.push(BatchDsEntry {
                claim_id: persisted_id,
                confidence,
                weight,
                evidence_type: planned.evidence_type.clone(),
                // Declared labeled axis, or None for the binary frame (#222).
                axis: planned.axis.clone(),
            });
        }

        id_map.insert(planned.id, persisted_id);
        claim_ids.push(persisted_id.to_string());

        // Touch source_url (kept for parity with V2 evidence formatting; the
        // current EvidenceType::Literature already carries the DOI).
        let _ = &source_url;
    }

    // ── 5. Plan edges (decomposes_to / section_follows / supports / authored placeholders) ──
    let mut relationships_created = 0_usize;
    for edge in &plan.edges {
        let (src, src_type) = if edge.source_type == "author_placeholder" {
            let idx = edge.properties["author_index"].as_u64().unwrap_or(0) as usize;
            let Some(&agent_uuid) = author_agent_map.get(&idx) else {
                continue;
            };
            (agent_uuid, "agent".to_string())
        } else {
            let mapped = id_map
                .get(&edge.source_id)
                .copied()
                .unwrap_or(edge.source_id);
            (mapped, edge.source_type.clone())
        };
        let tgt = id_map
            .get(&edge.target_id)
            .copied()
            .unwrap_or(edge.target_id);

        // Filter self-loops introduced by content-hash dedup collapsing
        // distinct planned UUIDs onto the same persisted claim. Since
        // structural nodes keep their document-scoped ids, the old
        // paragraph-equals-its-sole-atom collapse no longer happens; this
        // still guards atom-to-atom collapse within one document. The
        // semantically correct outcome is a no-op decomposition; the DB
        // would otherwise reject this with edges_no_self_loop.
        if src == tgt && src_type == edge.target_type {
            continue;
        }

        let (row, was_created) = EdgeRepository::create_if_not_exists(
            pool,
            src,
            &src_type,
            tgt,
            &edge.target_type,
            &edge.relationship,
            Some(edge.properties.clone()),
            None,
            None,
        )
        .await
        .map_err(internal_error)?;
        relationships_created += usize::from(was_created);

        // Epistemic-edge factor auto-wire (best-effort; non-epistemic and
        // non-claim edges are filtered inside the helper).
        ds_auto::auto_wire_edge_if_epistemic(
            pool,
            viewer,
            was_created,
            row.id,
            src,
            &src_type,
            tgt,
            &edge.target_type,
            &edge.relationship,
            agent_id,
        )
        .await;
    }

    // ── 6. Auto-CDST batch wire (atoms only) ──
    let (claims_ds_wired, ds_frame_id) = if ds_entries.is_empty() {
        (None, None)
    } else {
        match ds_auto::auto_wire_ds_batch(pool, viewer, &ds_entries, agent_id).await {
            Ok((fid, count)) => (Some(count), Some(fid.to_string())),
            Err(e) => {
                tracing::warn!("ds auto-wire batch failed: {e}");
                (None, None)
            }
        }
    };

    // ── 7. Mark paper as processed by this pipeline ──
    // Idempotent: first ingest stamps the edge; re-runs (full paper after
    // abstract, or ingest_document_spine + ingest_document_inline) are safe.
    let (_row, _was_created) = EdgeRepository::create_if_not_exists(
        pool,
        paper_id,
        "paper",
        agent_id,
        "agent",
        "processed_by",
        Some(serde_json::json!({
            "pipeline": pipeline_version,
            "tool": "ingest_document",
        })),
        None,
        None,
    )
    .await
    .map_err(internal_error)?;

    // ── 8. Detach embeddings so the MCP response returns immediately after commit ──
    // All DB writes are done. Embed in the background so the caller is not blocked
    // by N × ~0.8 s OpenAI calls. The response reports the number queued; the
    // invariant (every is_current claim has an embedding) is satisfied eventually.
    let queued = embed_queue.len();
    if !embed_queue.is_empty() {
        let embedder = Arc::clone(&server.embedder);
        tokio::spawn(async move {
            for (id, content) in embed_queue {
                if !embedder.embed_and_store(id, &content).await {
                    tracing::warn!("background embedding failed for claim {id}");
                }
            }
        });
    }

    success_json(&IngestDocumentResponse {
        paper_id: paper_id.to_string(),
        paper_title,
        synthesized_key: is_synthetic_key(&doi),
        doi,
        authors: author_responses,
        claims_ingested: claim_ids.len() - dedup_count,
        claims_embedded: queued,
        claims_skipped_dedup: dedup_count,
        relationships_created,
        claims_ds_wired,
        ds_frame_id,
        already_ingested: claim_ids.len() == dedup_count && dedup_count > 0,
    })
}

/// Convert a DOI into a slug form safe for use as a URL path segment or
/// canonical name: every `/` becomes `-`. Casing is left untouched.
#[allow(dead_code)] // not yet wired into a caller; covered by unit tests below
fn doi_to_slug(doi: &str) -> String {
    doi.replace('/', "-")
}

/// URN prefix for a synthesized (non-DOI) document identity key.
const SYNTHETIC_KEY_PREFIX: &str = "urn:epigraph:doc:";

/// Values callers pass to mean "this document has no DOI". Treated as ABSENT,
/// not as an identity: keying on them collapsed every DOI-less document onto a
/// single shared `papers` row (issue #356 — one node had accrued 1244 claims
/// from at least four unrelated sources, with their author lists unioned).
const DOI_PLACEHOLDERS: [&str; 8] = ["unknown", "n/a", "na", "none", "null", "nil", "-", "tbd"];

/// True when `s` is empty/whitespace or one of the [`DOI_PLACEHOLDERS`].
fn is_placeholder_id(s: &str) -> bool {
    let t = s.trim();
    t.is_empty() || DOI_PLACEHOLDERS.contains(&t.to_ascii_lowercase().as_str())
}

/// Legible-but-bounded slug for the human-readable half of a synthetic key:
/// lowercased, non-alphanumerics collapsed to single `-`, capped at 48 bytes on
/// a char boundary. Only a debugging aid — uniqueness comes from the hash half.
fn key_slug(s: &str) -> String {
    let mut out = String::with_capacity(48);
    let mut pending_dash = false;
    for ch in s.chars() {
        if out.len() >= 48 {
            break;
        }
        if ch.is_ascii_alphanumeric() {
            if pending_dash && !out.is_empty() {
                out.push('-');
            }
            pending_dash = false;
            out.push(ch.to_ascii_lowercase());
        } else {
            pending_dash = true;
        }
    }
    out
}

/// Synthesize a stable identity key for a document with no usable DOI.
///
/// Shape: `urn:epigraph:doc:<slug>-<16 hex>`. The hash half is the identity;
/// the slug is there so the key is recognisable in logs and `doi:<key>` labels.
///
/// Two hashing bases, in priority order:
///
/// 1. `source.external_id` — the caller's own run/entry id. Identity is the
///    external id ALONE, so a re-ingest that corrects the title or adds authors
///    converges on the same node.
/// 2. Otherwise the source metadata tuple (title, type, journal, year, sorted
///    authors). Deterministic, but a title edit yields a new node — which is
///    why `external_id` is the documented path for authored records.
fn synthetic_document_key(source: &DocumentSource) -> String {
    let (basis, slug_seed) = match source.external_id.as_deref() {
        Some(ext) if !is_placeholder_id(ext) => {
            (format!("external_id\u{1f}{}", ext.trim()), ext.to_string())
        }
        _ => {
            let mut authors: Vec<String> = source
                .authors
                .iter()
                .map(|a| a.name.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            authors.sort_unstable();
            authors.dedup();
            let basis = format!(
                "title\u{1f}{}\u{1e}type\u{1f}{:?}\u{1e}journal\u{1f}{}\u{1e}year\u{1f}{}\u{1e}authors\u{1f}{}",
                source.title.trim().to_ascii_lowercase(),
                source.source_type,
                source.journal.as_deref().unwrap_or("").trim(),
                source.year.map_or_else(String::new, |y| y.to_string()),
                authors.join(","),
            );
            (basis, source.title.clone())
        }
    };
    let digest = ContentHasher::to_hex(&ContentHasher::hash(basis.as_bytes()));
    let slug = key_slug(&slug_seed);
    if slug.is_empty() {
        format!("{SYNTHETIC_KEY_PREFIX}{}", &digest[..16])
    } else {
        format!("{SYNTHETIC_KEY_PREFIX}{slug}-{}", &digest[..16])
    }
}

/// True when `key` was synthesized by [`synthetic_document_key`] rather than
/// being a real DOI/URI the caller supplied.
fn is_synthetic_key(key: &str) -> bool {
    key.starts_with(SYNTHETIC_KEY_PREFIX)
}

/// Resolve the identity key a document's `papers` row is keyed on.
///
/// Priority: real DOI → arXiv id parsed from `uri` → `uri` → synthesized key.
/// Placeholder DOIs/URIs (`"unknown"`, `"n/a"`, empty, …) are treated as absent
/// so they fall through to synthesis instead of becoming a shared bucket.
fn resolve_doi(extraction: &DocumentExtraction) -> String {
    if let Some(d) = &extraction.source.doi {
        if !is_placeholder_id(d) {
            return d.trim().to_string();
        }
        tracing::warn!(
            doi = %d,
            title = %extraction.source.title,
            "ingest: placeholder DOI treated as absent; synthesizing a stable document key (issue #356). Pass source.external_id to control this key."
        );
    }
    if let Some(uri) = &extraction.source.uri {
        if !is_placeholder_id(uri) {
            // Hand-rolled arXiv pattern: \d{4}\.\d{4,5}
            if let Some(arxiv) = find_arxiv_id(uri) {
                return format!("10.48550/arXiv.{arxiv}");
            }
            return uri.trim().to_string();
        }
    }
    synthetic_document_key(&extraction.source)
}

fn find_arxiv_id(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    'outer: for start in 0..bytes.len() {
        if start + 9 > bytes.len() {
            return None;
        }
        // Need 4 digits, '.', then 4 or 5 digits.
        for i in 0..4 {
            if !bytes[start + i].is_ascii_digit() {
                continue 'outer;
            }
        }
        if bytes[start + 4] != b'.' {
            continue;
        }
        let mut tail = 0;
        while tail < 5 && start + 5 + tail < bytes.len() && bytes[start + 5 + tail].is_ascii_digit()
        {
            tail += 1;
        }
        if tail >= 4 {
            return Some(
                std::str::from_utf8(&bytes[start..start + 5 + tail])
                    .ok()?
                    .to_string(),
            );
        }
    }
    None
}

/// Persist one planned claim, routing on the identity class the PLANNER chose.
///
/// Returns `(persisted_id, resolved_to_existing)`. `resolved_to_existing` means
/// the row was already there with its provenance (trace + evidence) written, so
/// the caller must only wire the `asserts` edge and must NOT clobber it.
///
/// Two classes, per `epigraph_ingest::common::ids`:
///
/// * **document-scoped (COMPOUND, levels 0–2)** — thesis / section / paragraph.
///   `id = uuid_v5(COMPOUND_NAMESPACE, hash(text) ++ "{title}\u{1f}{path}")`, so
///   two papers with a section titled "Introduction" get two different ids *by
///   design*. Written with [`ClaimRepository::create_with_id_if_absent`], which
///   binds the caller's id and hash and resolves on `ON CONFLICT (id)`. This is
///   the same primitive `workflow_ingest` and `epigraph-ingest-executor`
///   already use; the document path was the sole holdout.
///
///   The legacy [`ClaimRepository::create`] instead re-resolves
///   `SELECT id FROM claims WHERE content_hash = $1`, discarding the planner's
///   id — that is what fused 70 papers onto one `Abstract` node and, through
///   `id_map`, remapped every planned structural edge onto it.
///
/// * **content-addressed (ATOM, level 3)** — `id = uuid_v5(ATOM_NAMESPACE,
///   hash(text))`. Convergence across papers IS the feature (it is how
///   cross-source corroboration finds agreement), so these stay on the
///   content-hash path unchanged.
async fn persist_planned_claim(
    pool: &sqlx::PgPool,
    claim: &Claim,
    planned: &PlannedClaim,
    agent_id: Uuid,
    truth: TruthValue,
) -> Result<(Uuid, bool), McpError> {
    if planned.id_is_document_scoped() {
        let was_new = ClaimRepository::create_with_id_if_absent(
            pool,
            planned.id,
            &planned.content,
            &planned.content_hash,
            agent_id,
            truth,
            &[],
        )
        .await
        .map_err(internal_error)?;
        // Idempotency is now by id rather than by content hash: re-ingesting
        // the SAME document re-derives the same seed → the same id → conflict →
        // `was_new == false`. Narrow window: a run that dies between this insert
        // and the trace write below leaves the node without trace/evidence, and
        // the retry takes the reuse branch. The old `already_had_trace` probe
        // covered that; closing it again would cost a SELECT per claim.
        return Ok((planned.id, !was_new));
    }

    // Atom: `create` dedupes on content_hash and returns the existing row.
    // `persisted_id != planned.id` catches a hash collision against some other
    // claim; `trace_id.is_some()` catches genuine atom convergence, where the
    // earlier ingestion already wrote the provenance we must not overwrite.
    let persisted = ClaimRepository::create(pool, claim)
        .await
        .map_err(internal_error)?;
    let persisted_id: Uuid = persisted.id.into();
    Ok((
        persisted_id,
        persisted_id != planned.id || persisted.trace_id.is_some(),
    ))
}

fn methodology_from_planned(planned: &PlannedClaim) -> Methodology {
    match planned.methodology.as_deref() {
        Some("statistical" | "instrumental" | "computational") => Methodology::Instrumental,
        Some("deductive") => Methodology::Deductive,
        Some("inductive") => Methodology::Inductive,
        Some("visual_inspection") => Methodology::VisualInspection,
        Some("expert_elicitation") => Methodology::Heuristic,
        _ => Methodology::Extraction,
    }
}

const fn level_label(level: u8) -> &'static str {
    match level {
        0 => "thesis",
        1 => "section",
        2 => "paragraph",
        3 => "atom",
        _ => "unknown",
    }
}

/// Core spine ingest: thesis + sections + paragraphs (levels 0–2) only.
/// Atoms in the extraction are ignored; the agent atomizes only the NEW
/// paragraph paths returned here, then submits via `ingest_document_inline`.
///
/// Ordering guarantee: the builder iterates sections then paragraphs in
/// extraction order, so `new_paragraph_paths` is in document order.
#[allow(clippy::too_many_lines)]
pub async fn do_ingest_document_spine(
    server: &EpiGraphMcpFull,
    extraction: &DocumentExtraction,
) -> Result<CallToolResult, McpError> {
    epigraph_ingest::document::structure::verify_extraction_verbatim(extraction)
        .map_err(|e| invalid_params(format!("verbatim guard failed: {e}")))?;

    // Declared-axis guard (issue #222): reject a malformed axis before any DB
    // write. Fail closed — silently degrading to the binary frame would record a
    // belief about TRUE for a claim the caller placed on a labeled hypothesis.
    epigraph_ingest::document::axis::validate_axes(extraction)
        .map_err(|e| invalid_params(format!("axis declaration invalid: {e}")))?;

    let plan = build_ingest_plan(extraction);
    let pool = &server.pool;
    let agent_id = server.agent_id().await?;
    let agent_id_typed = AgentId::from_uuid(agent_id);
    let pub_key = server.signer.public_key();

    let paper_title = extraction.source.title.clone();
    let doi = resolve_doi(extraction);
    let pipeline_version = effective_pipeline_version(extraction);
    // See do_ingest_document: attached to every claim so label-based lookup
    // (recompute_beliefs, query_claims_by_label) can find this paper's set.
    let paper_label = format!("doi:{doi}");

    // Atom planned IDs — skip these claims and any edges referencing them.
    let atom_planned_ids: HashSet<Uuid> = plan
        .claims
        .iter()
        .filter(|c| c.level == 3)
        .map(|c| c.id)
        .collect();

    // Map para planned ID → document path e.g. "sections[0].paragraphs[1]".
    // Builder iterates sections/paragraphs in extraction order so zipping is safe.
    let para_id_to_path: HashMap<Uuid, String> = {
        let mut map = HashMap::new();
        let mut level2_iter = plan.claims.iter().filter(|c| c.level == 2);
        for (si, section) in extraction.sections.iter().enumerate() {
            for (pi, _para) in section.paragraphs.iter().enumerate() {
                if let Some(pc) = level2_iter.next() {
                    map.insert(pc.id, format!("sections[{si}].paragraphs[{pi}]"));
                }
            }
        }
        map
    };

    // ── 1. Get-or-create paper node ──
    let paper_id = PaperRepository::get_or_create(
        pool,
        &doi,
        Some(&paper_title),
        extraction.source.journal.as_deref(),
    )
    .await
    .map_err(internal_error)?;

    // ── 2. Ensure author agents + authored edges ──
    let mut author_responses = Vec::new();
    let mut author_agent_map: HashMap<usize, Uuid> = HashMap::new();
    // Same defensive backstop as `do_ingest_document` (backlog a55aac45): the
    // spine path is the recommended two-phase entry and shares the empty-authors
    // failure mode, so recover the byline from `source_text` when the structured
    // author list is absent. Gated on Paper/Textbook source_type (see the
    // `do_ingest_document` rationale). Conservative parser; empty ⇒ pre-existing
    // behavior.
    let byline_eligible = matches!(
        extraction.source.source_type,
        epigraph_ingest::document::schema::SourceType::Paper
            | epigraph_ingest::document::schema::SourceType::Textbook
    );
    let parsed_fallback;
    let authors: &[epigraph_ingest::common::schema::AuthorEntry] = if extraction
        .source
        .authors
        .is_empty()
        && byline_eligible
    {
        parsed_fallback = extraction
            .source_text
            .as_deref()
            .map(epigraph_ingest::document::byline::parse_byline_authors)
            .unwrap_or_default();
        if parsed_fallback.is_empty() {
            tracing::warn!(
                paper = %paper_title,
                "ingest_document_spine: source.authors empty and no byline recovered from body; paper will have no author agents"
            );
        } else {
            tracing::info!(
                paper = %paper_title,
                count = parsed_fallback.len(),
                "ingest_document_spine: source.authors empty; recovered authors from body byline fallback"
            );
        }
        &parsed_fallback
    } else {
        &extraction.source.authors
    };
    for (idx, author) in authors.iter().enumerate() {
        if author.name.is_empty() {
            continue;
        }
        let (_did, pub_key_bytes) =
            epigraph_crypto::did_key::did_key_for_author(None, &author.name);
        let agent_uuid = if let Some(existing) =
            AgentRepository::get_by_public_key(pool, &pub_key_bytes)
                .await
                .map_err(internal_error)?
        {
            existing.id.into()
        } else {
            let author_agent = epigraph_core::Agent::new(pub_key_bytes, Some(author.name.clone()));
            AgentRepository::create(pool, &author_agent)
                .await
                .map_err(internal_error)?
                .id
                .into()
        };
        let (_row, _) = EdgeRepository::create_if_not_exists(
            pool,
            agent_uuid,
            "agent",
            paper_id,
            "paper",
            "authored",
            Some(serde_json::json!({
                "position": idx,
                "role": author.roles.first().map_or("author", String::as_str),
                "affiliations": author.affiliations,
            })),
            None,
            None,
        )
        .await
        .map_err(internal_error)?;
        author_agent_map.insert(idx, agent_uuid);
        author_responses.push(AuthorResponse {
            agent_id: agent_uuid.to_string(),
            name: author.name.clone(),
        });
    }

    // ── 3. Walk claims: levels 0–2 only ──
    let source_url = if doi.starts_with("10.") {
        format!("https://doi.org/{doi}")
    } else {
        format!("doi:{doi}")
    };

    let mut id_map: HashMap<Uuid, Uuid> = HashMap::new();
    let mut embed_queue: Vec<(Uuid, String)> = Vec::new();
    let mut para_new_count = 0_usize;
    let mut para_dedup_count = 0_usize;
    let mut new_paragraph_paths: Vec<String> = Vec::new();

    for planned in &plan.claims {
        if planned.level == 3 {
            continue;
        }

        let confidence = planned.confidence.clamp(0.0, 1.0);
        let methodology = methodology_from_planned(planned);
        let weight = methodology.weight_modifier();
        let raw_truth = (confidence * weight).clamp(0.01, 0.99);

        let mut claim = Claim::new(
            planned.content.clone(),
            agent_id_typed,
            pub_key,
            TruthValue::clamped(raw_truth),
        );
        claim.id = ClaimId::from_uuid(planned.id);
        claim.content_hash = planned.content_hash;
        claim.signature = Some(server.signer.sign(&claim.content_hash));

        let (persisted_id, resolved_to_existing) = persist_planned_claim(
            pool,
            &claim,
            planned,
            agent_id,
            TruthValue::clamped(raw_truth),
        )
        .await?;
        ClaimRepository::update_labels(pool, persisted_id, std::slice::from_ref(&paper_label), &[])
            .await
            .map_err(internal_error)?;

        if resolved_to_existing {
            let (_row, _) = EdgeRepository::create_if_not_exists(
                pool,
                paper_id,
                "paper",
                persisted_id,
                "claim",
                "asserts",
                Some(planned.properties.clone()),
                None,
                None,
            )
            .await
            .map_err(internal_error)?;
            id_map.insert(planned.id, persisted_id);
            if planned.level == 2 {
                para_dedup_count += 1;
            }
            continue;
        }

        ClaimRepository::set_properties(
            pool,
            ClaimId::from_uuid(persisted_id),
            planned.properties.clone(),
        )
        .await
        .map_err(internal_error)?;

        let evidence_text = planned
            .supporting_text
            .as_deref()
            .unwrap_or(&planned.content);
        let formatted_evidence =
            format!("Source: {paper_title} (DOI: {doi}). Passage: '{evidence_text}'");
        let evidence_hash = ContentHasher::hash(formatted_evidence.as_bytes());
        let mut evidence = Evidence::new(
            agent_id_typed,
            pub_key,
            evidence_hash,
            EvidenceType::Literature {
                doi: doi.clone(),
                extraction_target: format!("level_{}", planned.level),
                page_range: None,
            },
            Some(formatted_evidence),
            claim.id,
        );
        evidence.signature = Some(server.signer.sign(&evidence_hash));

        let trace = ReasoningTrace::new(
            agent_id_typed,
            pub_key,
            methodology,
            vec![TraceInput::Evidence { id: evidence.id }],
            confidence,
            format!(
                "Extracted from '{paper_title}' (DOI: {doi}); level {} ({})",
                planned.level,
                level_label(planned.level),
            ),
        );

        ReasoningTraceRepository::create(pool, &trace, claim.id)
            .await
            .map_err(internal_error)?;
        EvidenceRepository::create(pool, &evidence)
            .await
            .map_err(internal_error)?;
        ClaimRepository::update_trace_id(pool, claim.id, trace.id)
            .await
            .map_err(internal_error)?;

        let (_row, _) = EdgeRepository::create_if_not_exists(
            pool,
            paper_id,
            "paper",
            persisted_id,
            "claim",
            "asserts",
            Some(planned.properties.clone()),
            None,
            None,
        )
        .await
        .map_err(internal_error)?;

        embed_queue.push((persisted_id, planned.content.clone()));

        if planned.level == 2 {
            para_new_count += 1;
            if let Some(path) = para_id_to_path.get(&planned.id) {
                new_paragraph_paths.push(path.clone());
            }
        }

        id_map.insert(planned.id, persisted_id);
        let _ = &source_url;
    }

    // ── 4. Plan edges (skip any edge to/from atom planned IDs) ──
    for edge in &plan.edges {
        if atom_planned_ids.contains(&edge.target_id) || atom_planned_ids.contains(&edge.source_id)
        {
            continue;
        }

        let (src, src_type) = if edge.source_type == "author_placeholder" {
            let idx = edge.properties["author_index"].as_u64().unwrap_or(0) as usize;
            let Some(&agent_uuid) = author_agent_map.get(&idx) else {
                continue;
            };
            (agent_uuid, "agent".to_string())
        } else {
            let mapped = id_map
                .get(&edge.source_id)
                .copied()
                .unwrap_or(edge.source_id);
            (mapped, edge.source_type.clone())
        };
        let tgt = id_map
            .get(&edge.target_id)
            .copied()
            .unwrap_or(edge.target_id);

        if src == tgt && src_type == edge.target_type {
            continue;
        }

        let (_row, _) = EdgeRepository::create_if_not_exists(
            pool,
            src,
            &src_type,
            tgt,
            &edge.target_type,
            &edge.relationship,
            Some(edge.properties.clone()),
            None,
            None,
        )
        .await
        .map_err(internal_error)?;
    }

    // ── 5. processed_by edge (idempotent; first spine call stamps the pipeline) ──
    let (_row, _) = EdgeRepository::create_if_not_exists(
        pool,
        paper_id,
        "paper",
        agent_id,
        "agent",
        "processed_by",
        Some(serde_json::json!({
            "pipeline": pipeline_version,
            "tool": "ingest_document_spine",
        })),
        None,
        None,
    )
    .await
    .map_err(internal_error)?;

    // ── 6. Detach embeddings ──
    let queued = embed_queue.len();
    if !embed_queue.is_empty() {
        let embedder = Arc::clone(&server.embedder);
        tokio::spawn(async move {
            for (id, content) in embed_queue {
                if !embedder.embed_and_store(id, &content).await {
                    tracing::warn!("background embedding failed for claim {id}");
                }
            }
        });
    }

    success_json(&IngestDocumentSpineResponse {
        paper_id: paper_id.to_string(),
        paper_title,
        synthesized_key: is_synthetic_key(&doi),
        doi,
        authors: author_responses,
        paragraphs_new: para_new_count,
        paragraphs_deduped: para_dedup_count,
        paragraphs_embedded: queued,
        new_paragraph_paths,
        already_ingested: para_new_count == 0 && para_dedup_count > 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gate returns false when the DOI is unknown, false when the paper exists
    /// but has no `processed_by` edge at this pipeline version, and true once
    /// the edge is present.
    #[sqlx::test(migrations = "../../migrations")]
    async fn paper_already_ingested_gate(pool: sqlx::PgPool) {
        let doi = "urn:test:check-gate";

        // Unknown DOI → not ingested.
        assert!(paper_already_ingested(
            &pool,
            &epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
                .await
                .expect("resolve viewer"),
            doi,
            PIPELINE_VERSION_BASE
        )
        .await
        .expect("gate query")
        .is_none());

        // Create the paper without a processed_by edge → still not ingested.
        let paper_id = PaperRepository::get_or_create(&pool, doi, Some("test"), None)
            .await
            .expect("create paper");
        assert!(paper_already_ingested(
            &pool,
            &epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
                .await
                .expect("resolve viewer"),
            doi,
            PIPELINE_VERSION_BASE
        )
        .await
        .expect("gate query")
        .is_none());

        // Insert a `processed_by` edge with a *different* pipeline → still not
        // ingested under PIPELINE_VERSION_BASE. Edges enforce target existence, so
        // create a real agent first.
        let agent_a = epigraph_core::Agent::new([7u8; 32], Some("test-agent-a".to_string()));
        let agent_a_id: Uuid = AgentRepository::create(&pool, &agent_a)
            .await
            .expect("create agent a")
            .id
            .into();
        EdgeRepository::create_if_not_exists(
            &pool,
            paper_id,
            "paper",
            agent_a_id,
            "agent",
            "processed_by",
            Some(serde_json::json!({ "pipeline": "some-other-pipeline" })),
            None,
            None,
        )
        .await
        .expect("create edge with other pipeline");
        assert!(paper_already_ingested(
            &pool,
            &epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
                .await
                .expect("resolve viewer"),
            doi,
            PIPELINE_VERSION_BASE
        )
        .await
        .expect("gate query")
        .is_none());

        // Insert a `processed_by` edge with the matching pipeline (different
        // target so it isn't deduped by the (source,target,relationship) key).
        let agent_b = epigraph_core::Agent::new([8u8; 32], Some("test-agent-b".to_string()));
        let agent_b_id: Uuid = AgentRepository::create(&pool, &agent_b)
            .await
            .expect("create agent b")
            .id
            .into();
        EdgeRepository::create_if_not_exists(
            &pool,
            paper_id,
            "paper",
            agent_b_id,
            "agent",
            "processed_by",
            Some(serde_json::json!({ "pipeline": PIPELINE_VERSION_BASE })),
            None,
            None,
        )
        .await
        .expect("create edge with matching pipeline");
        let hit = paper_already_ingested(
            &pool,
            &epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
                .await
                .expect("resolve viewer"),
            doi,
            PIPELINE_VERSION_BASE,
        )
        .await
        .expect("gate query");
        assert_eq!(hit, Some(paper_id));
    }

    #[test]
    fn doi_to_slug_replaces_slash() {
        assert_eq!(
            doi_to_slug("10.48550/arXiv.2606.04990"),
            "10.48550-arXiv.2606.04990"
        );
    }

    #[test]
    fn doi_to_slug_replaces_all_slashes() {
        assert_eq!(doi_to_slug("10.1000/xyz/123/abc"), "10.1000-xyz-123-abc");
    }

    // ── Document identity keying (issue #356) ──────────────────────────────

    fn src(title: &str) -> DocumentSource {
        DocumentSource {
            title: title.to_string(),
            doi: None,
            external_id: None,
            uri: None,
            source_type: epigraph_ingest::document::schema::SourceType::InternalDocument,
            authors: Vec::new(),
            journal: None,
            year: None,
            metadata: serde_json::Value::Null,
        }
    }

    fn extraction_of(source: DocumentSource) -> DocumentExtraction {
        DocumentExtraction {
            source,
            thesis: None,
            thesis_derivation: Default::default(),
            sections: Vec::new(),
            relationships: Vec::new(),
            source_text: None,
        }
    }

    #[test]
    fn real_doi_is_used_verbatim() {
        let mut s = src("A paper");
        s.doi = Some("10.1000/xyz123".to_string());
        let key = resolve_doi(&extraction_of(s));
        assert_eq!(key, "10.1000/xyz123");
        assert!(!is_synthetic_key(&key));
    }

    #[test]
    fn arxiv_uri_still_resolves_to_arxiv_doi() {
        let mut s = src("A preprint");
        s.uri = Some("https://arxiv.org/abs/2606.04990".to_string());
        assert_eq!(resolve_doi(&extraction_of(s)), "10.48550/arXiv.2606.04990");
    }

    /// The core of #356: two unrelated DOI-less documents must NOT share a key.
    #[test]
    fn distinct_doi_less_documents_get_distinct_keys() {
        let a = resolve_doi(&extraction_of(src("V4 pre-flight: layered 18HB joint")));
        let b = resolve_doi(&extraction_of(src("Anatomy & Physiology, Ch. 1")));
        assert!(is_synthetic_key(&a) && is_synthetic_key(&b));
        assert_ne!(a, b, "unrelated DOI-less documents collapsed onto one key");
    }

    /// Every placeholder spelling is treated as absent, not as an identity — so
    /// none of them lands on a shared bucket, and none equals another document's key.
    #[test]
    fn placeholder_dois_are_treated_as_absent() {
        let baseline = resolve_doi(&extraction_of(src("Run 3 summary")));
        for placeholder in ["unknown", "UNKNOWN", " n/a ", "", "None", "-", "TBD"] {
            let mut s = src("Run 3 summary");
            s.doi = Some(placeholder.to_string());
            let key = resolve_doi(&extraction_of(s));
            assert!(
                is_synthetic_key(&key),
                "placeholder {placeholder:?} was kept as an identity key: {key}"
            );
            // Same document metadata ⇒ same synthesized key regardless of which
            // placeholder spelling the caller used.
            assert_eq!(key, baseline);
        }
        // ...and a *different* document with the same placeholder does not collide.
        let mut other = src("Run 4 summary");
        other.doi = Some("unknown".to_string());
        assert_ne!(resolve_doi(&extraction_of(other)), baseline);
    }

    #[test]
    fn synthesized_key_is_stable_across_calls() {
        let s = src("Run 3 summary");
        assert_eq!(
            resolve_doi(&extraction_of(s.clone())),
            resolve_doi(&extraction_of(s))
        );
    }

    /// `external_id` pins identity: a re-ingest that corrects the title (the
    /// exact case that used to overwrite the shared node's title) converges on
    /// the same node instead of forking a new one.
    #[test]
    fn external_id_pins_identity_across_metadata_edits() {
        let mut a = src("ELN entry: variant V2");
        a.external_id = Some("eln-run-2026-07-23-v2".to_string());
        let mut b = src("ELN entry: variant V2 (joint_bp=84, corrected)");
        b.external_id = Some("eln-run-2026-07-23-v2".to_string());
        b.year = Some(2026);
        assert_eq!(
            resolve_doi(&extraction_of(a)),
            resolve_doi(&extraction_of(b))
        );
    }

    #[test]
    fn distinct_external_ids_do_not_collide() {
        let mut a = src("Sweep variant");
        a.external_id = Some("eln-run-v2".to_string());
        let mut b = src("Sweep variant");
        b.external_id = Some("eln-run-v3".to_string());
        assert_ne!(
            resolve_doi(&extraction_of(a)),
            resolve_doi(&extraction_of(b)),
            "two sweep variants with the same title shared one node"
        );
    }

    #[test]
    fn placeholder_external_id_falls_back_to_metadata() {
        let mut a = src("Report X");
        a.external_id = Some("unknown".to_string());
        assert_eq!(
            resolve_doi(&extraction_of(a)),
            resolve_doi(&extraction_of(src("Report X")))
        );
    }

    /// Authors participate in metadata-derived identity, so the two documents
    /// whose author lists got unioned in #356 key apart even given one title.
    #[test]
    fn authors_disambiguate_same_titled_documents() {
        let mut a = src("Overview");
        a.authors = vec![epigraph_ingest::common::schema::AuthorEntry {
            name: "Lawrence J. Gitman".to_string(),
            affiliations: Vec::new(),
            roles: Vec::new(),
        }];
        let mut b = src("Overview");
        b.authors = vec![epigraph_ingest::common::schema::AuthorEntry {
            name: "Amit Shah".to_string(),
            affiliations: Vec::new(),
            roles: Vec::new(),
        }];
        assert_ne!(
            resolve_doi(&extraction_of(a)),
            resolve_doi(&extraction_of(b))
        );
    }

    #[test]
    fn author_order_does_not_change_the_key() {
        let mk = |names: [&str; 2]| {
            let mut s = src("Joint work");
            s.authors = names
                .iter()
                .map(|n| epigraph_ingest::common::schema::AuthorEntry {
                    name: (*n).to_string(),
                    affiliations: Vec::new(),
                    roles: Vec::new(),
                })
                .collect();
            resolve_doi(&extraction_of(s))
        };
        assert_eq!(mk(["Ada", "Grace"]), mk(["Grace", "Ada"]));
    }

    #[test]
    fn synthetic_key_shape_is_urn_slug_hash() {
        let mut s = src("V4 pre-flight: layered 18HB compliant joint");
        s.external_id = Some("eln/run 42".to_string());
        let key = resolve_doi(&extraction_of(s));
        let rest = key
            .strip_prefix(SYNTHETIC_KEY_PREFIX)
            .expect("synthetic keys are URN-prefixed");
        let (slug, hash) = rest.rsplit_once('-').expect("slug-hash shape");
        assert_eq!(slug, "eln-run-42");
        assert_eq!(hash.len(), 16);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// A title of only non-alphanumerics leaves an empty slug; the key must
    /// still be a well-formed, unique URN rather than a dangling prefix.
    #[test]
    fn empty_slug_still_yields_a_valid_key() {
        let key = resolve_doi(&extraction_of(src("!!! ???")));
        let rest = key.strip_prefix(SYNTHETIC_KEY_PREFIX).expect("prefixed");
        assert_eq!(rest.len(), 16);
        assert!(rest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn key_slug_is_bounded_and_collapses_separators() {
        let long = "a".repeat(200);
        assert!(key_slug(&long).len() <= 48);
        assert_eq!(key_slug("Hello   World -- Again"), "hello-world-again");
        assert_eq!(key_slug("  leading and trailing  "), "leading-and-trailing");
    }
}
