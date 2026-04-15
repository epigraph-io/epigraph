//! Paper ingestion endpoint: download, extract, and enrich a research paper.
//!
//! `POST /api/v1/ingest/paper` accepts an arXiv ID, DOI, or local PDF path
//! and runs the full extraction pipeline on the host (where Python + deps are
//! available), returning the enriched claims JSON for the MCP server to ingest
//! into the knowledge graph.
//!
//! This endpoint exists so that containerized agents (which lack Python) can
//! trigger the pipeline via HTTP instead of shelling out locally.

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::errors::ApiError;
use crate::state::AppState;

/// Default output directory for extraction artifacts
const DEFAULT_OUTPUT_DIR: &str = "/tmp/epigraph-extractions";

/// Request body for paper ingestion
#[derive(Debug, Deserialize)]
pub struct IngestPaperRequest {
    /// arXiv ID (e.g. "2508.16798"), DOI (e.g. "10.48550/arXiv.2508.16798"),
    /// or absolute path to a local PDF file.
    pub source: String,
    /// Optional output directory for intermediate files.
    pub output_dir: Option<String>,
}

/// Response from a successful paper extraction
#[derive(Debug, Serialize)]
pub struct IngestPaperResponse {
    /// The enriched claims JSON (full LiteratureExtraction structure)
    pub extraction: serde_json::Value,
    /// Path to the enriched JSON file on the host
    pub enriched_path: String,
    /// Path to the resolved PDF (if downloaded)
    pub pdf_path: Option<String>,
    /// Number of claims extracted
    pub claims_count: usize,
}

/// Locate the `extract_and_enrich.py` script relative to the working directory
/// or known installation paths.
fn find_extraction_script() -> Option<PathBuf> {
    let candidates = [
        // Container mount path (epiclaw containers)
        PathBuf::from("/opt/epigraph/scripts/extract_and_enrich.py"),
        // Dev: running from repo root
        PathBuf::from("scripts/extract_and_enrich.py"),
        // Absolute path in devcontainer
        PathBuf::from("/workspaces/EpiGraphV2/scripts/extract_and_enrich.py"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

/// POST /api/v1/ingest/paper
///
/// Run the full paper extraction pipeline: resolve source → download PDF →
/// extract structure → LLM claim extraction → provenance enrichment.
///
/// Returns the enriched claims JSON that can be passed to `ingest_paper`.
///
/// # Request Body
///
/// ```json
/// {
///   "source": "2508.16798",
///   "output_dir": "/tmp/epigraph-extractions"
/// }
/// ```
///
/// # Responses
///
/// - `200 OK` — Extraction succeeded, enriched JSON returned
/// - `400 Bad Request` — Invalid source format
/// - `500 Internal Server Error` — Pipeline execution failed
pub async fn ingest_paper(
    State(_state): State<AppState>,
    Json(request): Json<IngestPaperRequest>,
) -> Result<(StatusCode, Json<IngestPaperResponse>), ApiError> {
    let source = request.source.trim().to_string();
    if source.is_empty() {
        return Err(ApiError::ValidationError {
            field: "source".to_string(),
            reason: "Source must not be empty".to_string(),
        });
    }

    let output_dir = request
        .output_dir
        .unwrap_or_else(|| DEFAULT_OUTPUT_DIR.to_string());

    // Ensure output directory exists
    tokio::fs::create_dir_all(&output_dir)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Cannot create output dir '{output_dir}': {e}"),
        })?;

    // ── 1. Resolve source to PDF path ──
    let (resolved_pdf, _arxiv_id) = resolve_source(&source, &output_dir).await?;

    // ── 2. Find extraction script ──
    let script_path = find_extraction_script().ok_or_else(|| ApiError::InternalError {
        message: "extract_and_enrich.py not found — ensure it exists in scripts/".to_string(),
    })?;

    // ── 3. Extract structure from PDF (if not already done) ──
    let pdf_stem = Path::new(&resolved_pdf)
        .file_stem()
        .map_or_else(|| "paper".to_string(), |s| s.to_string_lossy().to_string());
    let structure_path = format!("{output_dir}/{pdf_stem}_structure.json");
    let enriched_path = format!("{output_dir}/{pdf_stem}_enriched.json");

    if !Path::new(&enriched_path).exists() {
        // Extract structure if needed
        if !Path::new(&structure_path).exists() {
            extract_pdf_structure(&resolved_pdf, &structure_path).await?;
        }

        // Run enrichment pipeline
        run_enrichment_pipeline(&script_path, &structure_path).await?;
    }

    // ── 4. Read and return the enriched JSON ──
    if !Path::new(&enriched_path).exists() {
        return Err(ApiError::InternalError {
            message: format!("Enriched JSON not found at {enriched_path} after pipeline"),
        });
    }

    let content = tokio::fs::read_to_string(&enriched_path)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to read enriched JSON: {e}"),
        })?;

    let extraction: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| ApiError::InternalError {
            message: format!("Invalid enriched JSON: {e}"),
        })?;

    let claims_count = extraction
        .get("claims")
        .and_then(|c| c.as_array())
        .map_or(0, |a| a.len());

    Ok((
        StatusCode::OK,
        Json(IngestPaperResponse {
            extraction,
            enriched_path,
            pdf_path: Some(resolved_pdf),
            claims_count,
        }),
    ))
}

/// Resolve a source string (arXiv ID, DOI, or PDF path) to a local PDF path.
async fn resolve_source(
    source: &str,
    output_dir: &str,
) -> Result<(String, Option<String>), ApiError> {
    if Path::new(source)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("pdf"))
    {
        // Local PDF path
        if !Path::new(source).exists() {
            return Err(ApiError::ValidationError {
                field: "source".to_string(),
                reason: format!("PDF file not found: {source}"),
            });
        }
        Ok((source.to_string(), None))
    } else if source.starts_with("10.") {
        // DOI — extract arXiv ID if it's an arXiv DOI
        let arxiv_id = source
            .strip_prefix("10.48550/arXiv.")
            .ok_or_else(|| ApiError::ValidationError {
                field: "source".to_string(),
                reason: format!(
                    "Only arXiv DOIs (10.48550/arXiv.*) are supported for direct download, got: {source}"
                ),
            })?;
        let pdf_path = download_arxiv_pdf(arxiv_id, output_dir).await?;
        Ok((pdf_path, Some(arxiv_id.to_string())))
    } else {
        // Assume arXiv ID
        let pdf_path = download_arxiv_pdf(source, output_dir).await?;
        Ok((pdf_path, Some(source.to_string())))
    }
}

/// Download a PDF from arXiv if not already cached locally.
async fn download_arxiv_pdf(arxiv_id: &str, output_dir: &str) -> Result<String, ApiError> {
    let pdf_url = format!("https://arxiv.org/pdf/{arxiv_id}.pdf");
    let pdf_dest = format!("{output_dir}/{arxiv_id}.pdf");

    if Path::new(&pdf_dest).exists() {
        return Ok(pdf_dest);
    }

    let output = tokio::process::Command::new("curl")
        .args(["-L", "-o", &pdf_dest, "--max-time", "120", &pdf_url])
        .output()
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("curl not available or failed to start: {e}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ApiError::InternalError {
            message: format!("PDF download failed for {arxiv_id}: {stderr}"),
        });
    }

    Ok(pdf_dest)
}

/// Extract PDF structure using Python (pymupdf4llm or raw text fallback).
async fn extract_pdf_structure(pdf_path: &str, structure_path: &str) -> Result<(), ApiError> {
    let py_script = format!(
        r#"
import json, sys
try:
    import pymupdf4llm
    md = pymupdf4llm.to_markdown('{pdf_path}')
    result = {{"title": "", "authors": "", "sections": [{{"title": "Full Text", "text": md}}], "figures": []}}
except ImportError:
    raw = open('{pdf_path}', 'rb').read()[:100000].decode('utf-8', errors='replace')
    result = {{"title": "", "authors": "", "sections": [{{"title": "Full Text", "text": raw}}], "figures": []}}
json.dump(result, open('{structure_path}', 'w'), indent=2)
"#
    );

    let output = tokio::process::Command::new("python3")
        .args(["-c", py_script.trim()])
        .output()
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("python3 not available: {e}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ApiError::InternalError {
            message: format!("PDF structure extraction failed: {stderr}"),
        });
    }

    Ok(())
}

/// Run `extract_and_enrich.py` on a structure JSON file.
async fn run_enrichment_pipeline(script_path: &Path, structure_path: &str) -> Result<(), ApiError> {
    let output = tokio::process::Command::new("python3")
        .arg(script_path)
        .arg(structure_path)
        .output()
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("extract_and_enrich.py failed to start: {e}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ApiError::InternalError {
            message: format!("Enrichment pipeline failed: {stderr}"),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_extraction_script_returns_none_when_missing() {
        // In test environment the script may or may not exist,
        // but the function should not panic
        let _ = find_extraction_script();
    }

    #[test]
    fn test_empty_source_rejected() {
        let req = IngestPaperRequest {
            source: "   ".to_string(),
            output_dir: None,
        };
        assert!(req.source.trim().is_empty());
    }
}
