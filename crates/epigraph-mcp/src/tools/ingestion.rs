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
    let bg = EpiGraphMcpFull::new_shared(
        server.pool.clone(),
        Arc::clone(&server.signer),
        Arc::clone(&server.embedder),
        server.read_only,
    );
    let doi_log = doi.clone();
    tokio::spawn(async move {
        if let Err(e) = do_ingest_document(&bg, &extraction).await {
            tracing::warn!(doi = doi_log, "background ingest_document failed: {e:?}");
        }
    });
    success_json(&serde_json::json!({
        "status": "queued",
        "doi": doi,
        "title": title,
        "note": "DB writes are running as a detached background task. Call check_already_ingested to confirm completion before assuming the write landed."
    }))
}

/// Inline (typed-param) counterpart to [`ingest_document`]. Takes a
/// `DocumentExtraction` directly instead of a file path and routes it through
/// the same [`do_ingest_document`] core, so an MCP client can produce the
/// hierarchy in-band — without first writing a file it then can't reference.
/// Identical graph result and idempotency gate as the file-path path.
pub async fn ingest_document_inline(
    server: &EpiGraphMcpFull,
    params: IngestDocumentInlineParams,
) -> Result<CallToolResult, McpError> {
    let extraction = params.extraction;
    let doi = resolve_doi(&extraction);
    let title = extraction.source.title.clone();
    let bg = EpiGraphMcpFull::new_shared(
        server.pool.clone(),
        Arc::clone(&server.signer),
        Arc::clone(&server.embedder),
        server.read_only,
    );
    let doi_log = doi.clone();
    tokio::spawn(async move {
        if let Err(e) = do_ingest_document(&bg, &extraction).await {
            tracing::warn!(
                doi = doi_log,
                "background ingest_document_inline failed: {e:?}"
            );
        }
    });
    success_json(&serde_json::json!({
        "status": "queued",
        "doi": doi,
        "title": title,
        "note": "DB writes are running as a detached background task. Call check_already_ingested to confirm completion before assuming the write landed."
    }))
}

/// Pool-only gate check: returns `Some(paper_id)` iff a paper with `doi`
/// exists AND has a `processed_by` edge whose `properties.pipeline` equals
/// `pipeline_version`. Mirrors the inline gate used by `do_ingest_document`.
pub async fn paper_already_ingested(
    pool: &sqlx::PgPool,
    doi: &str,
    pipeline_version: &str,
) -> Result<Option<Uuid>, McpError> {
    let Some(prior) = PaperRepository::find_by_doi(pool, doi)
        .await
        .map_err(internal_error)?
    else {
        return Ok(None);
    };
    if PaperRepository::has_processed_by_edge(pool, prior.id, pipeline_version)
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
    params: CheckAlreadyIngestedParams,
) -> Result<CallToolResult, McpError> {
    let pipeline = params
        .pipeline_version
        .unwrap_or_else(|| PIPELINE_VERSION_BASE.to_string());
    let paper_id = paper_already_ingested(&server.pool, &params.doi, &pipeline).await?;

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
/// `ingest_document_inline`. Skips atoms entirely; the full content-hash dedup
/// applies at paragraph level so re-ingesting an abstract is safe.
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
    extraction: &DocumentExtraction,
) -> Result<CallToolResult, McpError> {
    // D9 writer-side verbatim re-verification: when the extraction carries
    // `source_text`, every span-backed paragraph's stored `text` must equal the
    // bytes its span points at. Fail closed before any DB write so paraphrase
    // drift can never reach a verbatim_v2 node. No-op for Tier 2 (no source_text).
    epigraph_ingest::document::structure::verify_extraction_verbatim(extraction)
        .map_err(|e| invalid_params(format!("verbatim guard failed: {e}")))?;

    let plan = build_ingest_plan(extraction);
    let pool = &server.pool;
    let agent_id = server.agent_id().await?;
    let agent_id_typed = AgentId::from_uuid(agent_id);
    let pub_key = server.signer.public_key();

    let paper_title = extraction.source.title.clone();
    let doi = resolve_doi(extraction);
    let pipeline_version = effective_pipeline_version(extraction);

    // ── 1. Get-or-create paper node ──
    // (Pipeline-version gate removed: node-level content-hash dedup handles
    //  idempotency so re-ingesting an abstract then the full paper is safe.
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
    for (idx, author) in extraction.source.authors.iter().enumerate() {
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
        claim.content_hash = ContentHasher::hash(planned.content.as_bytes());
        claim.signature = Some(server.signer.sign(&claim.content_hash));

        // ClaimRepository::create dedupes by content_hash and returns the
        // existing row when the hash matches. Two dedup paths exist:
        //   (a) deterministic-id collision: persisted_id != planned.id
        //       (e.g. content_hash matched some other claim with a different
        //       UUID — shouldn't happen for atoms or compounds we built,
        //       but we handle it for safety).
        //   (b) atom convergence across papers: planned.id is
        //       uuid_v5(ATOM_NAMESPACE, content_hash), so the existing
        //       atom has the same id. We detect this via persisted.trace_id
        //       already being Some (the original ingestion already wrote
        //       trace + evidence; we must NOT clobber that provenance).
        let persisted = ClaimRepository::create(pool, &claim)
            .await
            .map_err(internal_error)?;
        let persisted_id: Uuid = persisted.id.into();
        let already_had_trace = persisted.trace_id.is_some();
        if persisted_id != planned.id || already_had_trace {
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
        // distinct planned UUIDs (e.g. compound paragraph and its sole
        // atom that share text) onto the same persisted claim. The
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
        match ds_auto::auto_wire_ds_batch(pool, &ds_entries, agent_id).await {
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

fn resolve_doi(extraction: &DocumentExtraction) -> String {
    if let Some(d) = &extraction.source.doi {
        return d.clone();
    }
    if let Some(uri) = &extraction.source.uri {
        // Hand-rolled arXiv pattern: \d{4}\.\d{4,5}
        if let Some(arxiv) = find_arxiv_id(uri) {
            return format!("10.48550/arXiv.{arxiv}");
        }
        return uri.clone();
    }
    "unknown".to_string()
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

    let plan = build_ingest_plan(extraction);
    let pool = &server.pool;
    let agent_id = server.agent_id().await?;
    let agent_id_typed = AgentId::from_uuid(agent_id);
    let pub_key = server.signer.public_key();

    let paper_title = extraction.source.title.clone();
    let doi = resolve_doi(extraction);
    let pipeline_version = effective_pipeline_version(extraction);

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
    for (idx, author) in extraction.source.authors.iter().enumerate() {
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
        claim.content_hash = ContentHasher::hash(planned.content.as_bytes());
        claim.signature = Some(server.signer.sign(&claim.content_hash));

        let persisted = ClaimRepository::create(pool, &claim)
            .await
            .map_err(internal_error)?;
        let persisted_id: Uuid = persisted.id.into();
        let already_had_trace = persisted.trace_id.is_some();

        if persisted_id != planned.id || already_had_trace {
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
        assert!(paper_already_ingested(&pool, doi, PIPELINE_VERSION_BASE)
            .await
            .expect("gate query")
            .is_none());

        // Create the paper without a processed_by edge → still not ingested.
        let paper_id = PaperRepository::get_or_create(&pool, doi, Some("test"), None)
            .await
            .expect("create paper");
        assert!(paper_already_ingested(&pool, doi, PIPELINE_VERSION_BASE)
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
        assert!(paper_already_ingested(&pool, doi, PIPELINE_VERSION_BASE)
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
        let hit = paper_already_ingested(&pool, doi, PIPELINE_VERSION_BASE)
            .await
            .expect("gate query");
        assert_eq!(hit, Some(paper_id));
    }
}
