#![allow(clippy::wildcard_imports)]

use std::path::Path;

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;
use crate::tools::ds_auto::{self, BatchDsEntry};
use crate::types::*;

use epigraph_core::{
    AgentId, Claim, Evidence, EvidenceType, Methodology, ReasoningTrace, TraceInput, TruthValue,
};
use epigraph_crypto::ContentHasher;
use epigraph_db::{
    AgentRepository, ClaimRepository, EdgeRepository, EvidenceRepository, ReasoningTraceRepository,
};

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
    let data = tokio::fs::read_to_string(&params.file_path)
        .await
        .map_err(|e| invalid_params(format!("cannot read {}: {e}", params.file_path)))?;

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
async fn do_ingest(
    server: &EpiGraphMcpFull,
    extraction: &LiteratureExtraction,
) -> Result<CallToolResult, McpError> {
    let agent_id = server.agent_id().await?;
    let agent_id_typed = AgentId::from_uuid(agent_id);
    let pub_key = server.signer.public_key();

    let doi = &extraction.source.doi;
    let title = &extraction.source.title;

    // Ensure author agents exist
    for author_val in &extraction.source.authors {
        let name = parse_author_entry(author_val);
        if name.is_empty() {
            continue;
        }
        // Create or get agent for author
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

        ClaimRepository::create(&server.pool, &claim)
            .await
            .map_err(internal_error)?;
        ReasoningTraceRepository::create(&server.pool, &trace, claim.id)
            .await
            .map_err(internal_error)?;
        EvidenceRepository::create(&server.pool, &evidence)
            .await
            .map_err(internal_error)?;
        ClaimRepository::update_trace_id(&server.pool, claim.id, trace.id)
            .await
            .map_err(internal_error)?;

        // Embed
        if server
            .embedder
            .embed_and_store(claim.id.as_uuid(), &lit_claim.statement)
            .await
        {
            claims_embedded += 1;
        }

        // Collect for DS batch wiring
        ds_entries.push(BatchDsEntry {
            claim_id: claim.id.as_uuid(),
            confidence,
            weight,
        });

        claim_ids.push(claim.id.as_uuid().to_string());
        claim_uuids.push(claim.id.as_uuid());
    }

    // DS batch auto-wire (best-effort)
    let (claims_ds_wired, ds_frame_id) =
        match ds_auto::auto_wire_ds_batch(&server.pool, &ds_entries, agent_id).await {
            Ok((fid, count)) => (Some(count), Some(fid.to_string())),
            Err(e) => {
                tracing::warn!("ds auto-wire batch failed: {e}");
                (None, None)
            }
        };

    // Create relationship edges
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
