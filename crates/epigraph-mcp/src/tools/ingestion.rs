#![allow(clippy::wildcard_imports)]

use std::collections::HashMap;
use std::path::Path;

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
use epigraph_ingest::schema::DocumentExtraction;

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

fn parse_author_entry(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(obj) => obj
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    }
}

fn lit_methodology(s: Option<&str>) -> Methodology {
    match s.map(str::to_lowercase).as_deref() {
        Some("statistical" | "statistical_analysis") => Methodology::Instrumental,
        Some("deductive" | "deductive_logic") => Methodology::Deductive,
        Some("inductive" | "inductive_generalization") => Methodology::Inductive,
        Some("meta_analysis") => Methodology::FormalProof,
        _ => Methodology::Extraction,
    }
}

pub async fn ingest_paper(
    server: &EpiGraphMcpFull,
    params: IngestPaperParams,
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

    let extraction: LiteratureExtraction =
        serde_json::from_str(&data).map_err(|e| invalid_params(format!("invalid JSON: {e}")))?;

    do_ingest(server, &extraction).await
}

pub async fn ingest_paper_url(
    server: &EpiGraphMcpFull,
    params: IngestPaperUrlParams,
) -> Result<CallToolResult, McpError> {
    let output_dir = params
        .output_dir
        .unwrap_or_else(|| "/tmp/epigraph-extractions".to_string());
    tokio::fs::create_dir_all(&output_dir)
        .await
        .map_err(|e| internal_error(format!("cannot create output dir: {e}")))?;

    let source = params.source.trim();

    // Determine if it's an arXiv ID, DOI, or file path
    let pdf_path = if Path::new(source).exists() {
        source.to_string()
    } else if source.starts_with("10.") {
        // DOI — try arXiv
        let arxiv_id = source.rsplit('/').next().unwrap_or(source);
        let url = format!("https://arxiv.org/pdf/{arxiv_id}");
        download_pdf(&url, &output_dir, arxiv_id).await?
    } else {
        // Assume arXiv ID
        let url = format!("https://arxiv.org/pdf/{source}");
        download_pdf(&url, &output_dir, source).await?
    };

    // Run extraction pipeline
    let output_json = format!("{output_dir}/claims.json");
    let status = tokio::process::Command::new("python3")
        .arg("scripts/extract_and_enrich.py")
        .arg(&pdf_path)
        .arg("--output")
        .arg(&output_json)
        .status()
        .await
        .map_err(|e| internal_error(format!("extraction pipeline failed: {e}")))?;

    if !status.success() {
        return Err(internal_error("extraction pipeline exited with error"));
    }

    let data = tokio::fs::read_to_string(&output_json)
        .await
        .map_err(|e| internal_error(format!("cannot read extraction output: {e}")))?;

    let extraction: LiteratureExtraction =
        serde_json::from_str(&data).map_err(|e| invalid_params(format!("invalid JSON: {e}")))?;

    do_ingest(server, &extraction).await
}

async fn download_pdf(url: &str, output_dir: &str, name: &str) -> Result<String, McpError> {
    let resp = reqwest::get(url)
        .await
        .map_err(|e| internal_error(format!("download failed: {e}")))?;

    if !resp.status().is_success() {
        return Err(internal_error(format!(
            "download returned {}",
            resp.status()
        )));
    }

    let pdf_path = format!("{output_dir}/{name}.pdf");
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| internal_error(format!("read bytes: {e}")))?;
    tokio::fs::write(&pdf_path, &bytes)
        .await
        .map_err(|e| internal_error(format!("write pdf: {e}")))?;
    Ok(pdf_path)
}

#[allow(clippy::too_many_lines)]
pub async fn do_ingest(
    server: &EpiGraphMcpFull,
    extraction: &LiteratureExtraction,
) -> Result<CallToolResult, McpError> {
    let agent_id = server.agent_id().await?;
    let agent_id_typed = AgentId::from_uuid(agent_id);
    let pub_key = server.signer.public_key();

    let doi = &extraction.source.doi;
    let title = &extraction.source.title;

    // BUG (s3a-followup): every author Agent is constructed with the same
    // hardcoded public_key=[0u8; 32]. Migration 057's
    // agents_public_key_unique constraint then rejects the second author of
    // any paper with 2+ distinct names. Pre-existing bug; not introduced by
    // S3a. Tier-2 test uses authors=vec![] to sidestep. Backlog item:
    // "ingest_paper hardcoded author key bug — assign per-author keypairs
    // or look up agents by name". Filed in EpiGraph with s3a-followup label.
    for author_val in &extraction.source.authors {
        let name = parse_author_entry(author_val);
        if name.is_empty() {
            continue;
        }
        let author_agent = epigraph_core::Agent::new([0u8; 32], Some(name.clone()));
        let _created = AgentRepository::create(&server.pool, &author_agent)
            .await
            .map_err(internal_error)?;
    }

    let mut claim_ids = Vec::new();
    let mut claims_embedded = 0;
    let mut claim_uuids = Vec::new();
    let mut ds_entries = Vec::new();

    for lit_claim in &extraction.claims {
        let confidence = lit_claim.confidence.clamp(0.0, 1.0);
        let methodology = lit_methodology(lit_claim.methodology.as_deref());
        let weight = methodology.weight_modifier();
        let raw_truth = (confidence * weight).clamp(0.01, 0.99);

        let mut claim = Claim::new(
            lit_claim.statement.clone(),
            agent_id_typed,
            pub_key,
            TruthValue::clamped(raw_truth),
        );
        claim.content_hash = ContentHasher::hash(lit_claim.statement.as_bytes());
        claim.signature = Some(server.signer.sign(&claim.content_hash));

        // Idempotent canonical claim create + AUTHORED verb-edge.
        let (claim, was_created) =
            crate::claim_helper::create_claim_idempotent(&server.pool, &claim, "ingest_paper")
                .await?;
        let claim_uuid = claim.id.as_uuid();

        // Build per-call Evidence + Trace regardless of was_created. Each
        // ingest run carries its own (possibly different) supporting passage,
        // so we preserve them as noun-claims linked via verb-edges.
        let evidence_hash = ContentHasher::hash(lit_claim.supporting_text.as_bytes());
        let mut evidence = Evidence::new(
            agent_id_typed,
            pub_key,
            evidence_hash,
            EvidenceType::Literature {
                doi: doi.clone(),
                extraction_target: lit_claim
                    .section
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                page_range: lit_claim.page.map(|p| (p, p)),
            },
            Some(lit_claim.supporting_text.clone()),
            claim.id,
        );
        evidence.signature = Some(server.signer.sign(&evidence_hash));

        let trace = ReasoningTrace::new(
            agent_id_typed,
            pub_key,
            methodology,
            vec![TraceInput::Evidence { id: evidence.id }],
            confidence,
            format!("Extracted from paper: {title} (DOI: {doi})"),
        );

        ReasoningTraceRepository::create(&server.pool, &trace, claim.id)
            .await
            .map_err(internal_error)?;
        EvidenceRepository::create(&server.pool, &evidence)
            .await
            .map_err(internal_error)?;

        // Verb-edges: every submission references its own Evidence + Trace.
        // Emitted on both branches per the architecture doc's "re-occurrence
        // = new edge" rule. Matches submit_claim's hoist (S3a Task 2). The
        // was_created marker on properties lets queries distinguish
        // first-create from resubmit edges.
        let _ = EdgeRepository::create(
            &server.pool,
            claim_uuid,
            "claim",
            evidence.id.as_uuid(),
            "evidence",
            "DERIVED_FROM",
            Some(serde_json::json!({"was_created": was_created})),
            None,
            None,
        )
        .await;
        let _ = EdgeRepository::create(
            &server.pool,
            claim_uuid,
            "claim",
            trace.id.as_uuid(),
            "trace",
            "HAS_TRACE",
            Some(serde_json::json!({"was_created": was_created})),
            None,
            None,
        )
        .await;

        if was_created {
            ClaimRepository::update_trace_id(&server.pool, claim.id, trace.id)
                .await
                .map_err(internal_error)?;

            if server
                .embedder
                .embed_and_store(claim_uuid, &lit_claim.statement)
                .await
            {
                claims_embedded += 1;
            }

            ds_entries.push(BatchDsEntry {
                claim_id: claim_uuid,
                confidence,
                weight,
            });
        }

        // Always push to claim_ids / claim_uuids — relationship edges below
        // reference these by index. Multi-emit on resubmit is intentional
        // per architecture rule 1 ("re-occurrence = new edge").
        claim_ids.push(claim_uuid.to_string());
        claim_uuids.push(claim_uuid);
    }

    let (claims_ds_wired, ds_frame_id) = if ds_entries.is_empty() {
        (None, None)
    } else {
        match ds_auto::auto_wire_ds_batch(&server.pool, &ds_entries, agent_id).await {
            Ok((fid, count)) => (Some(count), Some(fid.to_string())),
            Err(e) => {
                tracing::warn!("ds auto-wire batch failed: {e}");
                (None, None)
            }
        }
    };

    let mut relationships_created = 0;
    for rel in &extraction.relationships {
        if rel.source_index < claim_uuids.len() && rel.target_index < claim_uuids.len() {
            let source = claim_uuids[rel.source_index];
            let target = claim_uuids[rel.target_index];
            let relationship = rel.relationship.to_uppercase();

            EdgeRepository::create(
                &server.pool,
                source,
                "claim",
                target,
                "claim",
                &relationship,
                Some(serde_json::json!({
                    "strength": rel.strength.unwrap_or(0.5),
                    "source": "paper_ingestion",
                })),
                None,
                None,
            )
            .await
            .map_err(internal_error)?;
            relationships_created += 1;
        }
    }

    success_json(&IngestPaperResponse {
        paper_title: title.clone(),
        doi: doi.clone(),
        claims_ingested: claim_ids.len(),
        claims_embedded,
        relationships_created,
        claim_ids,
        claims_ds_wired,
        ds_frame_id,
    })
}
// ────────────────────────────────────────────────────────────────────────────
// ingest_document — hierarchical DocumentExtraction → graph
// ────────────────────────────────────────────────────────────────────────────

const PIPELINE_VERSION: &str = "hierarchical_extraction_v1";

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

    do_ingest_document(server, &extraction).await
}

/// Core ingestion logic factored out so integration tests can drive a parsed
/// `DocumentExtraction` without round-tripping through the file-path validation
/// in `ingest_document`.
#[allow(clippy::too_many_lines)]
pub async fn do_ingest_document(
    server: &EpiGraphMcpFull,
    extraction: &DocumentExtraction,
) -> Result<CallToolResult, McpError> {
    let plan = build_ingest_plan(extraction);
    let pool = &server.pool;
    let agent_id = server.agent_id().await?;
    let agent_id_typed = AgentId::from_uuid(agent_id);
    let pub_key = server.signer.public_key();

    let paper_title = extraction.source.title.clone();
    let doi = resolve_doi(extraction);

    // ── 1. Version gate: skip if already processed by this pipeline ──
    if let Some(prior) = PaperRepository::find_by_doi(pool, &doi)
        .await
        .map_err(internal_error)?
    {
        if PaperRepository::has_processed_by_edge(pool, prior.id, PIPELINE_VERSION)
            .await
            .map_err(internal_error)?
        {
            return success_json(&IngestDocumentResponse {
                paper_id: prior.id.to_string(),
                paper_title,
                doi,
                authors: vec![],
                claims_ingested: 0,
                claims_embedded: 0,
                claims_skipped_dedup: 0,
                relationships_created: 0,
                claims_ds_wired: None,
                ds_frame_id: None,
                already_ingested: true,
            });
        }
    }

    // ── 2. Get-or-create paper node ──
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
        EdgeRepository::create_if_not_exists(
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
    let mut embedded_count = 0_usize;
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
            EdgeRepository::create_if_not_exists(
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

        EdgeRepository::create_if_not_exists(
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

        if server
            .embedder
            .embed_and_store(persisted_id, &planned.content)
            .await
        {
            embedded_count += 1;
        }

        // Atoms (level 3) are the units we trust to carry CDST evidence.
        if planned.level == 3 {
            ds_entries.push(BatchDsEntry {
                claim_id: persisted_id,
                confidence,
                weight,
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

        EdgeRepository::create_if_not_exists(
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
        relationships_created += 1;
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

    // ── 7. Mark paper as processed by this pipeline (version gate for re-runs) ──
    // Edge target is the server's agent — paper -processed_by-> agent
    // models "this paper was processed by this agent at this pipeline
    // version". (Self-loops on paper are blocked by the edges_no_self_loop
    // check constraint, so we cannot point the edge back at the paper.)
    EdgeRepository::create_if_not_exists(
        pool,
        paper_id,
        "paper",
        agent_id,
        "agent",
        "processed_by",
        Some(serde_json::json!({
            "pipeline": PIPELINE_VERSION,
            "tool": "ingest_document",
        })),
        None,
        None,
    )
    .await
    .map_err(internal_error)?;

    success_json(&IngestDocumentResponse {
        paper_id: paper_id.to_string(),
        paper_title,
        doi,
        authors: author_responses,
        claims_ingested: claim_ids.len() - dedup_count,
        claims_embedded: embedded_count,
        claims_skipped_dedup: dedup_count,
        relationships_created,
        claims_ds_wired,
        ds_frame_id,
        already_ingested: false,
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
