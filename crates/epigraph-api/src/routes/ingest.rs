//! Paper ingestion endpoint: download, extract, and enrich a research paper.
//!
//! `POST /api/v1/ingest/paper` accepts an arXiv ID or an arXiv DOI and runs
//! the full extraction pipeline on the host (where Python + deps are
//! available), returning the enriched claims JSON for the MCP server to ingest
//! into the knowledge graph.
//!
//! This endpoint exists so that containerized agents (which lack Python) can
//! trigger the pipeline via HTTP instead of shelling out locally.
//!
//! # Paths are the server's, never the caller's (backlog 0fd96e75)
//!
//! The request used to carry an `output_dir` and could name a local PDF as
//! its `source`; both reached `create_dir_all`, `curl -o` and a Python script
//! as text. The ingested id went into the download path unchecked, so `..` or
//! an absolute path wrote anywhere the server could, and the PDF and
//! structure paths were spliced into the source of a `python3 -c` script
//! inside single quotes, so a quote in either was code on the host.
//!
//! Now the body takes only `source` (unknown fields are refused), the source
//! must be an arXiv id or arXiv DOI that [`arxiv_id_from_source`] accepts
//! (ASCII digits, dots and an old-style archive name, never a path), every
//! file lives directly under [`WORK_DIR`] and [`confined`] refuses any other
//! parent after canonicalizing it, and the structure script is a constant
//! that reads its two paths from `sys.argv` ([`structure_command`]).

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::errors::ApiError;
use crate::state::AppState;

/// The server's work directory for extraction artifacts. Fixed: a request
/// cannot move it.
const WORK_DIR: &str = "/tmp/epigraph-extractions";

/// Request body for paper ingestion
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestPaperRequest {
    /// arXiv ID (e.g. "2508.16798", "hep-th/9901001v2") or arXiv DOI
    /// (e.g. "10.48550/arXiv.2508.16798").
    pub source: String,
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
/// { "source": "2508.16798" }
/// ```
///
/// # Responses
///
/// - `200 OK` — Extraction succeeded, enriched JSON returned
/// - `400 Bad Request` — The source is not an arXiv id or arXiv DOI
/// - `422 Unprocessable Entity` — The body names a field other than `source`
/// - `500 Internal Server Error` — Pipeline execution failed
pub async fn ingest_paper(
    // `claims:admin`, checked before the body is parsed (backlog f00d75ab).
    _scope: crate::middleware::bearer::RequireScopeAdmin,
    State(_state): State<AppState>,
    Json(request): Json<IngestPaperRequest>,
) -> Result<(StatusCode, Json<IngestPaperResponse>), ApiError> {
    // ── 1. Validate the source before touching the filesystem ──
    let arxiv_id = arxiv_id_from_source(request.source.trim())?;
    let stem = arxiv_id.replace('/', "_");

    // ── 2. The work directory and every path in it ──
    tokio::fs::create_dir_all(WORK_DIR)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Cannot create the extraction work dir: {e}"),
        })?;
    let root = tokio::fs::canonicalize(WORK_DIR)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Cannot resolve the extraction work dir: {e}"),
        })?;
    let pdf_path = confined(&root, &format!("{stem}.pdf"))?;
    let structure_path = confined(&root, &format!("{stem}_structure.json"))?;
    let enriched_path = confined(&root, &format!("{stem}_enriched.json"))?;

    // ── 3. Download the PDF (if not cached) ──
    download_arxiv_pdf(arxiv_id, &pdf_path).await?;

    // ── 4. Find extraction script ──
    let script_path = find_extraction_script().ok_or_else(|| ApiError::InternalError {
        message: "extract_and_enrich.py not found — ensure it exists in scripts/".to_string(),
    })?;

    // ── 5. Extract structure and enrich (if not already done) ──
    if !enriched_path.exists() {
        if !structure_path.exists() {
            extract_pdf_structure(&pdf_path, &structure_path).await?;
        }
        run_enrichment_pipeline(&script_path, &structure_path).await?;
    }

    // ── 6. Read and return the enriched JSON ──
    if !enriched_path.exists() {
        return Err(ApiError::InternalError {
            message: format!(
                "Enriched JSON not found at {} after pipeline",
                enriched_path.display()
            ),
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
            enriched_path: enriched_path.display().to_string(),
            pdf_path: Some(pdf_path.display().to_string()),
            claims_count,
        }),
    ))
}

/// The arXiv id named by `source`: an arXiv id, or an arXiv DOI
/// (`10.48550/arXiv.<id>`) whose suffix is one. Anything else, a filesystem
/// path included, is a 400.
fn arxiv_id_from_source(source: &str) -> Result<&str, ApiError> {
    let refuse = |reason: &str| ApiError::ValidationError {
        field: "source".to_string(),
        reason: reason.to_string(),
    };
    if source.is_empty() {
        return Err(refuse("Source must not be empty"));
    }
    let id = if source.starts_with("10.") {
        source.strip_prefix("10.48550/arXiv.").ok_or_else(|| {
            refuse("Only arXiv DOIs (10.48550/arXiv.<id>) are supported for direct download")
        })?
    } else {
        source
    };
    if is_arxiv_id(id) {
        Ok(id)
    } else {
        Err(refuse(
            "Source must be an arXiv id (e.g. 2508.16798 or hep-th/9901001) or an arXiv DOI",
        ))
    }
}

/// Is `id` an arXiv identifier, with an optional `vN` version?
///
/// * New style: `YYMM.NNNN` or `YYMM.NNNNN` (`2508.16798`).
/// * Old style: `archive[.XX]/YYMMNNN` (`hep-th/9901001`, `math.GT/0309136`),
///   the archive lowercase ASCII letters with at most one inner hyphen.
///
/// Every accepted id is ASCII letters, digits, `.`, `-` and at most one `/`,
/// with no `..`: it cannot name a path outside the work directory, nor carry
/// a quote or a space into any command.
fn is_arxiv_id(id: &str) -> bool {
    let all_digits = |s: &str, n: std::ops::RangeInclusive<usize>| {
        n.contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
    };
    // A trailing `vN` after the numeric part.
    let body = match id.rsplit_once('v') {
        Some((head, ver))
            if all_digits(ver, 1..=3) && head.bytes().last().is_some_and(|b| b.is_ascii_digit()) =>
        {
            head
        }
        _ => id,
    };
    if let Some((archive, number)) = body.split_once('/') {
        let (name, subject) = match archive.split_once('.') {
            Some((name, subject)) => (name, Some(subject)),
            None => (archive, None),
        };
        let name_ok = (2..=16).contains(&name.len())
            && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
            && !name.starts_with('-')
            && !name.ends_with('-')
            && name.bytes().filter(|&b| b == b'-').count() <= 1;
        let subject_ok =
            subject.is_none_or(|s| s.len() == 2 && s.bytes().all(|b| b.is_ascii_uppercase()));
        name_ok && subject_ok && all_digits(number, 7..=7)
    } else {
        match body.split_once('.') {
            Some((yymm, number)) => all_digits(yymm, 4..=4) && all_digits(number, 4..=5),
            None => false,
        }
    }
}

/// `root.join(file_name)`, refused unless its parent is exactly `root`.
///
/// `root` is the canonicalized work directory. A `file_name` with a separator,
/// a `..`, or an absolute path would land elsewhere; the ids
/// [`is_arxiv_id`] admits cannot produce one, and this is the check that does
/// not rely on that.
fn confined(root: &Path, file_name: &str) -> Result<PathBuf, ApiError> {
    let path = root.join(file_name);
    let single = Path::new(file_name).components().count() == 1
        && matches!(
            Path::new(file_name).components().next(),
            Some(std::path::Component::Normal(_))
        );
    if single && path.parent() == Some(root) {
        Ok(path)
    } else {
        Err(ApiError::ValidationError {
            field: "source".to_string(),
            reason: "Source does not name a file in the extraction work dir".to_string(),
        })
    }
}

/// Download a PDF from arXiv to `pdf_dest` if not already cached locally.
async fn download_arxiv_pdf(arxiv_id: &str, pdf_dest: &Path) -> Result<(), ApiError> {
    if pdf_dest.exists() {
        return Ok(());
    }
    let pdf_url = format!("https://arxiv.org/pdf/{arxiv_id}.pdf");

    let output = tokio::process::Command::new("curl")
        .args(["-L", "--max-time", "120", "-o"])
        .arg(pdf_dest)
        .arg(&pdf_url)
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

    Ok(())
}

/// The PDF structure extractor (pymupdf4llm, or a raw-text fallback). A
/// constant: the two paths arrive as `sys.argv[1]` and `sys.argv[2]`, never as
/// script text.
const STRUCTURE_SCRIPT: &str = r#"
import json, sys
pdf_path, structure_path = sys.argv[1], sys.argv[2]
try:
    import pymupdf4llm
    md = pymupdf4llm.to_markdown(pdf_path)
    result = {"title": "", "authors": "", "sections": [{"title": "Full Text", "text": md}], "figures": []}
except ImportError:
    with open(pdf_path, 'rb') as f:
        raw = f.read()[:100000].decode('utf-8', errors='replace')
    result = {"title": "", "authors": "", "sections": [{"title": "Full Text", "text": raw}], "figures": []}
with open(structure_path, 'w') as f:
    json.dump(result, f, indent=2)
"#;

/// `python3 -c STRUCTURE_SCRIPT <pdf_path> <structure_path>`.
fn structure_command(pdf_path: &Path, structure_path: &Path) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("python3");
    cmd.arg("-c")
        .arg(STRUCTURE_SCRIPT.trim())
        .arg(pdf_path)
        .arg(structure_path);
    cmd
}

/// Extract PDF structure using Python (pymupdf4llm or raw text fallback).
async fn extract_pdf_structure(pdf_path: &Path, structure_path: &Path) -> Result<(), ApiError> {
    let output = structure_command(pdf_path, structure_path)
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
async fn run_enrichment_pipeline(script_path: &Path, structure_path: &Path) -> Result<(), ApiError> {
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

    fn refused(source: &str) -> bool {
        matches!(
            arxiv_id_from_source(source),
            Err(ApiError::ValidationError { ref field, .. }) if field == "source"
        )
    }

    #[test]
    fn test_find_extraction_script_returns_none_when_missing() {
        // In test environment the script may or may not exist,
        // but the function should not panic
        let _ = find_extraction_script();
    }

    /// Calibration: the ids and DOIs the route exists for still pass, so the
    /// refusals below are the validator's, not a validator that refuses all.
    #[test]
    fn arxiv_ids_and_arxiv_dois_are_accepted() {
        for (source, id) in [
            ("2508.16798", "2508.16798"),
            ("2508.16798v2", "2508.16798v2"),
            ("0704.0001", "0704.0001"),
            ("hep-th/9901001", "hep-th/9901001"),
            ("hep-th/9901001v3", "hep-th/9901001v3"),
            ("math.GT/0309136", "math.GT/0309136"),
            ("solv-int/9901001", "solv-int/9901001"),
            ("10.48550/arXiv.2508.16798", "2508.16798"),
        ] {
            assert_eq!(arxiv_id_from_source(source).ok(), Some(id), "{source}");
        }
    }

    /// Backlog 0fd96e75: a traversal, an absolute path, a local PDF, a quote,
    /// or a DOI whose suffix is any of those, is refused before any file or
    /// process is touched.
    #[test]
    fn a_path_a_traversal_or_a_quote_is_not_an_arxiv_id() {
        for source in [
            "",
            "..",
            "../../etc/passwd",
            "2508.16798/../../etc/cron.d/x",
            "hep-th/../9901001",
            "hep-th/9901001/..",
            "/etc/passwd",
            "/tmp/paper.pdf",
            "paper.pdf",
            "2508.16798.pdf",
            "2508.16798'); import os; os.system('id') #",
            "2508.16798'",
            "hep-th/9901001\"",
            "2508.16798 ",
            "2508.16798\n",
            "2508.167",
            "25O8.16798",
            "HEP-TH/9901001",
            "-rf/9901001",
            "10.48550/arXiv.../../x",
            "10.48550/arXiv./etc/passwd",
            "10.48550/arXiv.2508.16798'",
            "10.1000/xyz123",
        ] {
            assert!(refused(source), "{source:?} must be refused");
        }
    }

    /// The confinement check refuses a name that leaves the work dir however
    /// it is spelled, independently of the id validator.
    #[test]
    fn confined_refuses_any_name_that_leaves_the_root() {
        let root = Path::new("/srv/work");
        assert_eq!(
            confined(root, "2508.16798.pdf").ok(),
            Some(PathBuf::from("/srv/work/2508.16798.pdf"))
        );
        for name in [
            "../x.pdf",
            "..",
            "/etc/passwd",
            "sub/x.pdf",
            "./x.pdf",
            "",
            "x/../../y",
        ] {
            assert!(confined(root, name).is_err(), "{name:?} must be refused");
        }
    }

    /// The structure script receives its paths as argv: a path with a quote
    /// in it is an argument, not script text.
    #[test]
    fn the_structure_script_takes_its_paths_as_argv() {
        let pdf = Path::new("/w/x'); __import__('os').system('id') #.pdf");
        let out = Path::new("/w/o'.json");
        let cmd = structure_command(pdf, out);
        let std = cmd.as_std();
        assert_eq!(std.get_program(), "python3");
        let args: Vec<&std::ffi::OsStr> = std.get_args().collect();
        assert_eq!(
            args,
            vec![
                std::ffi::OsStr::new("-c"),
                std::ffi::OsStr::new(STRUCTURE_SCRIPT.trim()),
                pdf.as_os_str(),
                out.as_os_str(),
            ]
        );
        assert!(!STRUCTURE_SCRIPT.contains("__import__"));
    }

    /// End to end on the host's `python3`: a PDF path that would be code if it
    /// were spliced into the script is only a (missing) file name. Under the
    /// old `format!` script the first quote closed the string literal and the
    /// `mkdir` ran.
    #[tokio::test]
    async fn a_quote_in_a_path_runs_no_python() {
        let dir = std::env::temp_dir().join(format!("ingest-argv-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let marker = dir.join("injected");
        let pdf = dir.join(format!(
            "x'+str(__import__('os').mkdir('{}'))+'.pdf",
            marker.display()
        ));
        let out = dir.join("structure.json");
        let output = match structure_command(&pdf, &out).output().await {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("python3 is not installed; skipping");
                let _ = std::fs::remove_dir_all(&dir);
                return;
            }
            Err(e) => panic!("python3 failed to start: {e}"),
        };
        let injected = marker.exists();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            !injected,
            "the PDF path was executed as Python: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !output.status.success(),
            "CALIBRATION: the script ran and failed to open the missing PDF"
        );
    }
}
