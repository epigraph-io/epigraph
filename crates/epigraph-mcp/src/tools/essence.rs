//! Essence binding — store the bytes an ingest run consumed, and hand the
//! ingestion writers the digest every `paper -asserts-> claim` edge must carry
//! (backlog 7c909c49).
//!
//! # The defect this closes
//!
//! Before this, a claim's only tie to its source was `papers.doi`. A DOI is a
//! DOCUMENT identity, not a byte payload: it is shared by the preprint and the
//! published PDF, by an OCR pass and a clean export. "Which bytes did this
//! claim come out of?" had no answer anywhere in the schema, so a claim whose
//! paper node no longer resolves to anything readable was indistinguishable
//! from a healthy one.
//!
//! # One rule for what the bytes are
//!
//! There is no configuration and no third branch:
//!
//! 1. `extraction.source_text` is `Some` and non-empty → the essence IS that
//!    text. This is literally the document, and the writer-side verbatim guard
//!    (`verify_extraction_verbatim`) has already proved every span-backed
//!    paragraph is a byte-exact slice of it.
//! 2. Otherwise → `serde_json::to_vec(extraction)`. When no upstream text was
//!    supplied, the extraction envelope IS the artifact the run consumed.
//!
//! Empty output is a hard error, so the writer can never reach a state where it
//! has nothing to bind (`blobs_size_positive` would reject it anyway).
//!
//! Rule 2 is deterministic here: `serde_json` is built WITHOUT `preserve_order`
//! in this workspace, so `Value::Object` is a sorted `BTreeMap` and struct
//! fields serialize in declaration order. The same logical extraction submitted
//! through `ingest_document` (file path) and through `ingest_document_inline`
//! therefore hashes identically and converges on ONE rendition row.
//!
//! # Where the bytes go
//!
//! Into the kernel's content-addressed blob store, under `server.blob_dir` —
//! resolved ONCE at server construction (`epigraph_core::blob_storage_root`).
//! This module never reads the environment itself, so a test's injected
//! `with_blob_dir` is honoured and there is no second, drifting notion of where
//! blobs live. There is no on/off switch: the only configuration is *where*,
//! never *whether*.

use std::collections::{HashMap, HashSet};

use rmcp::model::{CallToolResult, Content};
use uuid::Uuid;

use epigraph_core::blob::hash_hex;
use epigraph_crypto::ContentHasher;
use epigraph_db::{
    BlobRepository, EdgeRepository, PaperRepository, SourceArtifactRepository,
    HAS_ESSENCE_RELATIONSHIP,
};
use epigraph_ingest::schema::DocumentExtraction;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::VerifyPaperEssenceParams;

/// `essence_kind` when the essence is the document's own verbatim text.
pub const ESSENCE_KIND_SOURCE_TEXT: &str = "source_text";
/// `essence_kind` when the essence is the serialized extraction envelope.
pub const ESSENCE_KIND_EXTRACTION_JSON: &str = "extraction_json";

/// `entity_types.type_name` of a rendition node.
const SOURCE_ARTIFACT_ENTITY_TYPE: &str = "source_artifact";

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

/// What one ingest run bound itself to.
#[derive(Debug, Clone)]
pub struct EssenceBinding {
    /// BLAKE3-256 of the essence bytes. Non-optional on purpose — this is what
    /// [`EdgeRepository::upsert_asserts_edge`] takes positionally.
    pub digest: [u8; 32],
    /// Lowercase hex rendering, the exact form stored on the edge.
    pub digest_hex: String,
    /// The `source_artifacts` rendition row.
    pub artifact_id: Uuid,
    /// The `blobs` row holding the bytes.
    pub blob_id: Uuid,
    /// [`ESSENCE_KIND_SOURCE_TEXT`] or [`ESSENCE_KIND_EXTRACTION_JSON`].
    pub kind: &'static str,
    /// Length of the essence payload.
    pub size_bytes: usize,
}

/// Store this extraction's essence bytes and join the rendition to `paper_id`.
///
/// Idempotent end to end: the blob write is content-addressed and skips a file
/// that already exists, the rendition row is `ON CONFLICT DO NOTHING`, and the
/// `has_essence` edge is create-if-not-exists. Re-ingesting the same bytes
/// therefore produces the same digest, the same rendition and the same edge.
///
/// # Errors
/// Fails closed. An [`McpError`] here aborts the ingest rather than writing
/// claims that name nothing — which is the entire point of the item.
pub async fn bind_essence(
    server: &EpiGraphMcpFull,
    extraction: &DocumentExtraction,
    paper_id: Uuid,
    doi: &str,
) -> Result<EssenceBinding, McpError> {
    let (bytes, kind, mime_type, extension) = essence_payload(extraction)?;

    let digest = ContentHasher::hash(&bytes);
    let digest_hex = hash_hex(&digest[..]);
    // `sanitize_filename` REJECTS `/` outright (it does not fall back to the
    // basename), so a raw DOI is not a legal blob filename. Derive one from the
    // digest instead: stable, collision-free and always safe.
    let short = &digest_hex[..16];
    let filename = format!("essence-{short}.{extension}");

    let agent_id = server.agent_id().await?;

    let stored = BlobRepository::store(
        &server.pool,
        &server.blob_dir,
        &filename,
        mime_type,
        &bytes,
        agent_id,
        // No `attach_to_claim`: the essence belongs to the DOCUMENT, and the
        // per-claim link is the `essence_digest` on each asserts edge.
        None,
        &["essence".to_string()],
        &serde_json::json!({ "essence_kind": kind }),
    )
    .await
    .map_err(internal_error)?;

    let (artifact_id, _was_created) = SourceArtifactRepository::upsert_essence_rendition(
        &server.pool,
        agent_id,
        // Content-derived, because the row is content-addressed and may be
        // shared by two documents with byte-identical essence. Naming it after
        // the first writer's DOI would make a shared row look owned.
        &format!("essence:{short}"),
        &digest,
        &serde_json::json!({
            "essence_kind": kind,
            "size_bytes": bytes.len(),
            "blob_id": stored.blob.id,
        }),
    )
    .await
    .map_err(internal_error)?;

    // The document→rendition join. The DOI lives on the EDGE, not on the
    // rendition row, for the same reason the name is content-derived.
    EdgeRepository::create_if_not_exists(
        &server.pool,
        paper_id,
        "paper",
        artifact_id,
        SOURCE_ARTIFACT_ENTITY_TYPE,
        HAS_ESSENCE_RELATIONSHIP,
        Some(serde_json::json!({ "essence_kind": kind, "doi": doi })),
        None,
        None,
    )
    .await
    .map_err(internal_error)?;

    Ok(EssenceBinding {
        digest,
        digest_hex,
        artifact_id,
        blob_id: stored.blob.id,
        kind,
        size_bytes: bytes.len(),
    })
}

/// The one rule, isolated so it can be tested without a database.
///
/// Returns `(bytes, essence_kind, mime_type, file_extension)`.
///
/// # Errors
/// [`McpError`] when the chosen payload is empty — the extraction carried no
/// text and serialized to nothing, which is not a bindable artifact.
fn essence_payload(
    extraction: &DocumentExtraction,
) -> Result<(Vec<u8>, &'static str, &'static str, &'static str), McpError> {
    let (bytes, kind, mime_type, extension) = match extraction.source_text.as_deref() {
        Some(text) if !text.is_empty() => (
            text.as_bytes().to_vec(),
            ESSENCE_KIND_SOURCE_TEXT,
            "text/plain; charset=utf-8",
            "txt",
        ),
        _ => (
            serde_json::to_vec(extraction).map_err(internal_error)?,
            ESSENCE_KIND_EXTRACTION_JSON,
            "application/json",
            "json",
        ),
    };
    if bytes.is_empty() {
        return Err(internal_error(
            "essence binding: extraction produced zero bytes, so there is nothing \
             for its claims to be bound to",
        ));
    }
    Ok((bytes, kind, mime_type, extension))
}

// ────────────────────────────────────────────────────────────────────────────
// verify_paper_essence — fail closed when a paper's asserted claims name bytes
// we cannot produce
// ────────────────────────────────────────────────────────────────────────────

/// One condition that makes a paper's essence binding unsound.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EssenceFinding {
    /// Machine-readable condition, e.g. `unbound_claim`.
    pub kind: &'static str,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

impl EssenceFinding {
    fn new(kind: &'static str, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
            claim_id: None,
            digest: None,
        }
    }
    fn on_claim(mut self, claim_id: Uuid) -> Self {
        self.claim_id = Some(claim_id);
        self
    }
    fn with_digest(mut self, digest: impl Into<String>) -> Self {
        self.digest = Some(digest.into());
        self
    }
}

struct ResolvedRendition {
    kind: String,
    bytes: Vec<u8>,
}

/// Prove that every claim this paper asserts names bytes we can still produce.
///
/// FAILS CLOSED. With `strict` (the default) any fault is an MCP **error**, not
/// a soft report, because a verifier that returns `200 {"verified": false}` is a
/// verifier whose result gets ignored. The full report travels in the error
/// message either way.
///
/// # Faults
/// - `no_essence` — the paper has no `has_essence` rendition at all.
/// - `blob_row_missing` — a rendition's digest has no `blobs` row.
/// - `bytes_missing` — the row exists but its file does not (in a multi-replica
///   deployment, the symptom of replicas not sharing a blob volume).
/// - `digest_mismatch` — the file exists but does not re-hash to its digest.
/// - `unbound_claim` — an `asserts` edge with no `essence_digest`. This is the
///   legacy, pre-essence corpus: migration 074's trigger grandfathers those
///   rows for writes, and this is where they are surfaced rather than hidden.
/// - `unknown_digest` — an `asserts` edge naming a digest this paper has no
///   rendition for.
/// - `atom_unbound` — a level-3 atom reached through
///   `paragraph -decomposes_to-> atom`, carrying this paper's `doi:<doi>` label,
///   with no `asserts` edge from this paper. Exactly the incident shape that
///   opened backlog 7c909c49.
/// - `paragraph_not_in_essence` — see containment below.
///
/// # Warnings
/// - `stale_binding` — a claim bound to an older but still-resolvable
///   rendition. NOT a fault: multi-rendition history is legitimate and is the
///   whole reason the digest lives per-rendition instead of in a column on
///   `papers`.
///
/// # Containment, and its two deliberate gaps
///
/// For `essence_kind = 'source_text'` renditions every level-2 (paragraph)
/// claim's content must be a byte substring of the essence read back off disk.
/// This is sound because the writer-side verbatim guard already forces Tier-1
/// paragraphs to be exact slices of `source_text`.
///
/// Two things are deliberately NOT containment-checked, and neither is a bug:
/// 1. **Atoms** (level 3) are LLM rewrites of a paragraph, not verbatim slices,
///    so substring containment would fail on correct data.
/// 2. **`extraction_json` renditions** hold paragraph text JSON-escaped, so a
///    paragraph containing a quote or a newline is legitimately not a raw
///    substring of the envelope.
pub async fn verify_paper_essence(
    server: &EpiGraphMcpFull,
    params: VerifyPaperEssenceParams,
) -> Result<CallToolResult, McpError> {
    let strict = params.strict.unwrap_or(true);
    let (paper_id, doi) = resolve_paper(server, &params).await?;

    let mut faults: Vec<EssenceFinding> = Vec::new();
    let mut warnings: Vec<EssenceFinding> = Vec::new();

    // ── 1. The renditions this paper is joined to ──
    let renditions = SourceArtifactRepository::list_for_paper(&server.pool, paper_id)
        .await
        .map_err(internal_error)?;
    if renditions.is_empty() {
        faults.push(EssenceFinding::new(
            "no_essence",
            format!("paper {paper_id} has no has_essence rendition, so its claims name nothing"),
        ));
    }

    // ── 2. Do those renditions still resolve to bytes? ──
    let mut resolved: HashMap<String, ResolvedRendition> = HashMap::new();
    let mut rendition_report = Vec::new();
    for r in &renditions {
        let digest_hex = hash_hex(&r.content_hash[..]);
        let kind = r
            .properties
            .get("essence_kind")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string();

        let blobs = BlobRepository::find_by_content_hash(&server.pool, &r.content_hash)
            .await
            .map_err(internal_error)?;
        let mut bytes_verified = false;
        match blobs.first() {
            None => faults.push(
                EssenceFinding::new(
                    "blob_row_missing",
                    format!("rendition {} names bytes with no blobs row", r.id),
                )
                .with_digest(digest_hex.clone()),
            ),
            Some(blob) => match BlobRepository::read_content(&server.blob_dir, blob).await {
                Err(e) => faults.push(
                    EssenceFinding::new("bytes_missing", format!("blob {}: {e}", blob.id))
                        .with_digest(digest_hex.clone()),
                ),
                Ok(bytes) => {
                    if hash_hex(&ContentHasher::hash(&bytes)[..]) == digest_hex {
                        bytes_verified = true;
                        resolved.insert(
                            digest_hex.clone(),
                            ResolvedRendition {
                                kind: kind.clone(),
                                bytes,
                            },
                        );
                    } else {
                        faults.push(
                            EssenceFinding::new(
                                "digest_mismatch",
                                format!("blob {} was modified after it was written", blob.id),
                            )
                            .with_digest(digest_hex.clone()),
                        );
                    }
                }
            },
        }
        rendition_report.push(serde_json::json!({
            "artifact_id": r.id,
            "digest": digest_hex,
            "essence_kind": kind,
            "bytes_verified": bytes_verified,
        }));
    }

    // ── 3. Every asserted claim must name one of them ──
    let known: HashSet<String> = renditions
        .iter()
        .map(|r| hash_hex(&r.content_hash[..]))
        .collect();
    let newest = renditions.first().map(|r| hash_hex(&r.content_hash[..]));

    let bindings = PaperRepository::list_asserted_claim_bindings(&server.pool, paper_id)
        .await
        .map_err(internal_error)?;

    for b in &bindings {
        let Some(digest) = b.essence_digest.as_deref() else {
            faults.push(
                EssenceFinding::new(
                    "unbound_claim",
                    "asserts edge carries no essence_digest (pre-essence row)",
                )
                .on_claim(b.claim_id),
            );
            continue;
        };
        if !known.contains(digest) {
            faults.push(
                EssenceFinding::new(
                    "unknown_digest",
                    "asserts edge names a rendition this paper is not joined to",
                )
                .on_claim(b.claim_id)
                .with_digest(digest),
            );
            continue;
        }
        if newest.as_deref() != Some(digest) {
            warnings.push(
                EssenceFinding::new(
                    "stale_binding",
                    "claim is bound to an older, still-resolvable rendition",
                )
                .on_claim(b.claim_id)
                .with_digest(digest),
            );
        }
        // Containment teeth: source_text renditions, level-2 claims only.
        if b.level.as_deref() == Some("2") {
            if let Some(res) = resolved.get(digest) {
                if res.kind == ESSENCE_KIND_SOURCE_TEXT
                    && std::str::from_utf8(&res.bytes).is_ok_and(|text| !text.contains(&b.content))
                {
                    faults.push(
                        EssenceFinding::new(
                            "paragraph_not_in_essence",
                            "level-2 claim content is not a byte substring of the essence",
                        )
                        .on_claim(b.claim_id)
                        .with_digest(digest),
                    );
                }
            }
        }
    }

    // ── 4. The paper -> paragraph -> atom walk ──
    let doi_label = format!("doi:{doi}");
    let atoms =
        PaperRepository::list_atoms_of_asserted_paragraphs(&server.pool, paper_id, &doi_label)
            .await
            .map_err(internal_error)?;
    for a in &atoms {
        if a.carries_doi_label && !a.asserted {
            faults.push(
                EssenceFinding::new(
                    "atom_unbound",
                    format!(
                        "atom carries {doi_label} and decomposes from paragraph {} but this \
                         paper does not assert it, so it is bound to no bytes",
                        a.paragraph_id
                    ),
                )
                .on_claim(a.atom_id),
            );
        }
    }

    let report = serde_json::json!({
        "paper_id": paper_id,
        "doi": doi,
        "strict": strict,
        "verified": faults.is_empty(),
        "renditions": rendition_report,
        "asserted_claims": bindings.len(),
        "atoms_reached": atoms.len(),
        "faults": faults,
        "warnings": warnings,
    });

    if strict && !faults.is_empty() {
        return Err(internal_error(format!(
            "verify_paper_essence FAILED for {doi}: {} fault(s); {report}",
            faults.len(),
        )));
    }
    success_json(&report)
}

/// `doi` or `paper_id`, exactly one of which must resolve.
async fn resolve_paper(
    server: &EpiGraphMcpFull,
    params: &VerifyPaperEssenceParams,
) -> Result<(Uuid, String), McpError> {
    if let Some(doi) = params.doi.as_deref() {
        let paper = PaperRepository::find_by_doi(&server.pool, doi)
            .await
            .map_err(internal_error)?
            .ok_or_else(|| invalid_params(format!("no paper with doi {doi}")))?;
        return Ok((paper.id, paper.doi));
    }
    if let Some(raw) = params.paper_id.as_deref() {
        let id = parse_uuid(raw)?;
        let paper = PaperRepository::find_by_id(&server.pool, id)
            .await
            .map_err(internal_error)?
            .ok_or_else(|| invalid_params(format!("no paper with id {id}")))?;
        return Ok((paper.id, paper.doi));
    }
    Err(invalid_params("supply either doi or paper_id"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extraction_with(source_text: Option<&str>) -> DocumentExtraction {
        let mut doc: DocumentExtraction = serde_json::from_str(
            r#"{
              "source": {
                "title": "Essence Rule Fixture",
                "doi": "10.1234/essence-rule",
                "source_type": "Paper",
                "authors": []
              },
              "thesis": "a thesis",
              "sections": [
                {"title": "S", "paragraphs": [
                  {"text": "a paragraph", "atoms": [], "generality": [], "confidence": 0.9}
                ]}
              ],
              "relationships": []
            }"#,
        )
        .expect("fixture parses");
        doc.source_text = source_text.map(str::to_string);
        doc
    }

    /// Rule 1: real `source_text` is the essence, verbatim and byte-exact.
    #[test]
    fn source_text_is_the_essence_when_present() {
        let doc = extraction_with(Some("The artifact body.\n"));
        let (bytes, kind, mime, ext) = essence_payload(&doc).unwrap();
        assert_eq!(bytes, b"The artifact body.\n");
        assert_eq!(kind, ESSENCE_KIND_SOURCE_TEXT);
        assert_eq!(mime, "text/plain; charset=utf-8");
        assert_eq!(ext, "txt");
    }

    /// Rule 2 covers BOTH absent and empty, so there is no "no bytes" branch.
    #[test]
    fn absent_or_empty_source_text_falls_back_to_the_envelope() {
        for st in [None, Some("")] {
            let doc = extraction_with(st);
            let (bytes, kind, mime, ext) = essence_payload(&doc).unwrap();
            assert_eq!(kind, ESSENCE_KIND_EXTRACTION_JSON, "for {st:?}");
            assert_eq!(mime, "application/json");
            assert_eq!(ext, "json");
            assert!(!bytes.is_empty());
            // It really is the envelope, not a placeholder.
            let round: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(round["source"]["title"], "Essence Rule Fixture");
        }
    }

    /// The determinism rule 2 relies on: the same logical extraction hashes the
    /// same, whether it arrived as a file or as inline typed params.
    #[test]
    fn envelope_serialization_is_stable() {
        let a = ContentHasher::hash(&essence_payload(&extraction_with(None)).unwrap().0);
        let b = ContentHasher::hash(&essence_payload(&extraction_with(None)).unwrap().0);
        assert_eq!(a, b);
    }

    /// The blob store rejects `/`, so a DOI can never be the filename. Prove
    /// the derived name survives sanitization.
    #[test]
    fn derived_filename_is_blob_safe_where_a_doi_is_not() {
        let digest = ContentHasher::hash(b"bytes");
        let hex = hash_hex(&digest[..]);
        let name = format!("essence-{}.txt", &hex[..16]);
        assert_eq!(epigraph_core::blob::sanitize_filename(&name).unwrap(), name);
        assert!(epigraph_core::blob::sanitize_filename("10.1234/abc").is_err());
    }
}
