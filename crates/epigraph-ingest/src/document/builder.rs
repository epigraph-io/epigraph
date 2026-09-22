//! Document hierarchy walker. Reads a `DocumentExtraction` and produces an
//! `IngestPlan` of claims + edges + path index.

use std::collections::HashMap;

use uuid::Uuid;

use crate::common::edges::{decomposes_edge, thesis_derivation_str};
use crate::common::ids::{atom_id, compound_claim_id, compound_content_hash, content_hash};
use crate::common::paths::normalize_claim_path;
use crate::common::plan::{IngestPlan, PlannedClaim, PlannedEdge};
use crate::document::schema::{DocumentExtraction, Paragraph, SourceType};

const fn source_type_str(st: &SourceType) -> &'static str {
    match st {
        SourceType::Paper => "Paper",
        SourceType::Textbook => "Textbook",
        SourceType::InternalDocument => "InternalDocument",
        SourceType::Report => "Report",
        SourceType::Transcript => "Transcript",
        SourceType::Legal => "Legal",
        SourceType::Tabular => "Tabular",
    }
}

/// Every value [`source_type_str`] can emit — i.e. the `properties.source_type`
/// stamp that marks a persisted row as DOCUMENT ingest output.
///
/// Deliberately not "anything that is not `workflow`": `ClaimRepository::
/// evolve_step` writes `properties = {"level": n, "step_lineage_id": …}` with no
/// `source_type` at all, and those rows bind the plain content hash.
/// Spelled through [`source_type_str`] so the mapping has exactly one
/// definition; `every_source_type_stamp_is_listed` holds the other end of the
/// drift guard with an exhaustive `match` that stops compiling when a
/// [`SourceType`] variant is added.
pub const DOCUMENT_SOURCE_TYPES: [&str; 7] = [
    source_type_str(&SourceType::Paper),
    source_type_str(&SourceType::Textbook),
    source_type_str(&SourceType::InternalDocument),
    source_type_str(&SourceType::Report),
    source_type_str(&SourceType::Transcript),
    source_type_str(&SourceType::Legal),
    source_type_str(&SourceType::Tabular),
];

/// Whether a persisted claim's `properties` identify it as a row whose
/// `claims.content_hash` is a [`compound_content_hash`] — a digest that is NOT
/// `blake3(content)` and CANNOT be re-derived from the claim alone.
///
/// # Why a reader needs this
///
/// `build_ingest_plan` binds `compound_content_hash(blake3(text),
/// artifact_seed)` on every level-0/1/2 node (see the `content_hash` field doc
/// on [`PlannedClaim`](crate::common::plan::PlannedClaim)), so that migration
/// 013's `UNIQUE (content_hash, agent_id)` cannot collapse two documents'
/// "Introduction" rows. A reader that recomputes `blake3(content)` and compares
/// it to the stored digest therefore gets a disagreement on every *untampered*
/// structural row of every ingested document. That disagreement is not
/// evidence of tampering and must not be reported as such — MCP `verify_claim`
/// routes on this predicate to answer "not applicable" instead.
///
/// # What it deliberately does NOT do
///
/// It does not attempt to re-derive the stored digest. The artifact seed is
/// `"{document title}\u{1f}{path}"`, which is not carried on the claim row, so
/// recomputation would have to guess it — and a guessed seed that happened to
/// match would manufacture exactly the false confidence this predicate exists
/// to remove. The honest answer for this class is "undecided", not "verified".
///
/// # Class predicate, not a security boundary
///
/// The inputs are `claims.properties`, which a writer with UPDATE on `claims`
/// controls. Such a writer can also rewrite `content_hash` outright, so this
/// adds no attack surface; but do not read a `true` here as an attestation of
/// anything. It classifies, it does not verify.
#[must_use]
pub fn stored_content_hash_is_seed_scoped(properties: &serde_json::Value) -> bool {
    // `level` is written as a JSON number by both builders, but every query in
    // the repo reads it through `properties->>'level'` (text), so accept either
    // spelling rather than silently failing the class check on a string.
    let level = properties.get("level").and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
    });
    let is_compound_level = matches!(level, Some(0..=2));

    let is_document = properties
        .get("source_type")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|st| DOCUMENT_SOURCE_TYPES.contains(&st));

    is_compound_level && is_document
}

fn enrichment_from_paragraph(paragraph: &Paragraph) -> serde_json::Value {
    serde_json::json!({
        "instruments_used": paragraph.instruments_used,
        "reagents_involved": paragraph.reagents_involved,
        "conditions": paragraph.conditions,
    })
}

/// Tier stamp (§2). Tier 1 (`verbatim_v2`) when the extraction carries
/// `source_text` (so section/paragraph nodes are byte-exact verbatim spans);
/// else Tier 2 (`extracted_v2`, e.g. the Python HTML/CNXML emitters).
fn spine_text_kind(extraction: &DocumentExtraction) -> &'static str {
    if extraction.source_text.is_some() {
        "verbatim_v2"
    } else {
        "extracted_v2"
    }
}

/// Walk a `DocumentExtraction` tree and produce a flat list of operations.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn build_ingest_plan(extraction: &DocumentExtraction) -> IngestPlan {
    let mut claims = Vec::new();
    let mut edges = Vec::new();
    let mut path_index = HashMap::new();

    let source_type = source_type_str(&extraction.source.source_type);
    let doc_title = &extraction.source.title;

    // Step 1: Thesis (level 0)
    #[allow(clippy::option_if_let_else)]
    let thesis_id = if let Some(ref thesis_text) = extraction.thesis {
        let hash = content_hash(thesis_text);
        let seed = format!("{doc_title}\u{1f}thesis");
        let id = compound_claim_id(&hash, &seed);
        // Stored hash is scoped too, so `uq_claims_content_hash_agent` cannot
        // collapse two documents' structural rows. See `ids::compound_content_hash`.
        let stored_hash = compound_content_hash(&hash, &seed);
        path_index.insert("thesis".to_string(), id);

        claims.push(PlannedClaim {
            id,
            content: thesis_text.clone(),
            level: 0,
            properties: serde_json::json!({
                "level": 0,
                "source_type": source_type,
                "thesis_derivation": thesis_derivation_str(&extraction.thesis_derivation),
            }),
            content_hash: stored_hash,
            confidence: 1.0,
            methodology: None,
            evidence_type: None,
            axis: None,
            supporting_text: None,
            enrichment: serde_json::json!({}),
        });
        Some(id)
    } else {
        None
    };

    let mut section_ids: Vec<Uuid> = Vec::new();

    for (si, section) in extraction.sections.iter().enumerate() {
        let section_path = format!("sections[{si}]");
        let section_hash = content_hash(&section.title);
        let section_seed = format!("{doc_title}\u{1f}{section_path}");
        let section_id = compound_claim_id(&section_hash, &section_seed);
        let section_stored_hash = compound_content_hash(&section_hash, &section_seed);
        section_ids.push(section_id);
        path_index.insert(section_path.clone(), section_id);

        claims.push(PlannedClaim {
            id: section_id,
            content: section.title.clone(),
            level: 1,
            properties: serde_json::json!({
                "level": 1,
                "source_type": source_type,
                "section": section.title,
                "spine_text_kind": spine_text_kind(extraction),
            }),
            content_hash: section_stored_hash,
            confidence: 1.0,
            methodology: None,
            evidence_type: None,
            // Structural spine nodes (thesis, section) are not DS-wired, so an
            // axis on them would have nothing to place.
            axis: None,
            supporting_text: None,
            enrichment: serde_json::json!({}),
        });

        if let Some(tid) = thesis_id {
            edges.push(decomposes_edge(tid, section_id));
        }

        let mut para_ids: Vec<Uuid> = Vec::new();

        for (pi, paragraph) in section.paragraphs.iter().enumerate() {
            let para_path = format!("{section_path}.paragraphs[{pi}]");
            let para_hash = content_hash(&paragraph.text);
            let para_seed = format!("{doc_title}\u{1f}{para_path}");
            let para_id = compound_claim_id(&para_hash, &para_seed);
            let para_stored_hash = compound_content_hash(&para_hash, &para_seed);
            para_ids.push(para_id);
            path_index.insert(para_path.clone(), para_id);

            let enrichment = enrichment_from_paragraph(paragraph);
            // Normalise once per paragraph to a canonical calibration key (or
            // None); the atoms below inherit the same tag. Keeps unrecognised
            // extractor values off the BBA, where they'd hit the 0.5
            // unknown-evidence-type fallback.
            let para_evidence_type = crate::common::evidence_type::normalize_evidence_type(
                paragraph.evidence_type.as_deref(),
            );

            // Declared labeled axis (issue #222), from the paragraph or
            // inherited from its section, plus per-atom label overrides.
            //
            // `build_ingest_plan` is infallible by contract, and
            // `axis::validate_axes` is the gate that rejects a malformed
            // declaration with a path-qualified message — every write path calls
            // it first. A failure here therefore means a caller bypassed the
            // gate: assert loudly in dev/test, and in release fall back to the
            // binary default rather than panicking mid-plan.
            let resolved = crate::document::axis::resolve_paragraph_axes(paragraph, section);
            debug_assert!(
                resolved.is_ok(),
                "unvalidated axis at {para_path}: {:?} — call axis::validate_axes before \
                 build_ingest_plan",
                resolved.as_ref().err()
            );
            let (para_axis, atom_axes) =
                resolved.unwrap_or_else(|_| (None, vec![None; paragraph.atoms.len()]));

            claims.push(PlannedClaim {
                id: para_id,
                content: paragraph.text.clone(),
                level: 2,
                properties: serde_json::json!({
                    "level": 2,
                    "source_type": source_type,
                    "section": section.title,
                    "spine_text_kind": spine_text_kind(extraction),
                }),
                content_hash: para_stored_hash,
                confidence: paragraph.confidence,
                methodology: paragraph.methodology.clone(),
                evidence_type: para_evidence_type.clone(),
                axis: para_axis,
                supporting_text: Some(paragraph.text.clone()),
                enrichment: enrichment.clone(),
            });

            edges.push(decomposes_edge(section_id, para_id));

            for (ai, atom_text) in paragraph.atoms.iter().enumerate() {
                let atom_hash = content_hash(atom_text);
                let aid = atom_id(&atom_hash);
                let atom_path = format!("{para_path}.atoms[{ai}]");
                path_index.insert(atom_path, aid);

                let generality = paragraph.generality.get(ai).copied().filter(|&g| g >= 0);

                let mut props = serde_json::json!({
                    "level": 3,
                    "source_type": source_type,
                    "section": section.title,
                });
                if let Some(g) = generality {
                    props["generality"] = serde_json::json!(g);
                }

                claims.push(PlannedClaim {
                    id: aid,
                    content: atom_text.clone(),
                    level: 3,
                    properties: props,
                    content_hash: atom_hash,
                    confidence: paragraph.confidence,
                    methodology: paragraph.methodology.clone(),
                    evidence_type: para_evidence_type.clone(),
                    // Atoms are the DS-wired units, so this is the placement
                    // that actually reaches a mass function.
                    axis: atom_axes.get(ai).cloned().flatten(),
                    supporting_text: Some(paragraph.text.clone()),
                    enrichment: enrichment.clone(),
                });

                edges.push(decomposes_edge(para_id, aid));
            }
        }

        for w in para_ids.windows(2) {
            edges.push(PlannedEdge {
                source_id: w[0],
                source_type: "claim".to_string(),
                target_id: w[1],
                target_type: "claim".to_string(),
                relationship: "continues_argument".to_string(),
                properties: serde_json::json!({}),
            });
        }
    }

    for w in section_ids.windows(2) {
        edges.push(PlannedEdge {
            source_id: w[0],
            source_type: "claim".to_string(),
            target_id: w[1],
            target_type: "claim".to_string(),
            relationship: "section_follows".to_string(),
            properties: serde_json::json!({}),
        });
    }

    for rel in &extraction.relationships {
        let src_path = normalize_claim_path(&rel.source_path);
        let tgt_path = normalize_claim_path(&rel.target_path);

        let source_id = match path_index.get(&src_path) {
            Some(id) => *id,
            None => continue,
        };
        let target_id = match path_index.get(&tgt_path) {
            Some(id) => *id,
            None => continue,
        };

        let mut props = serde_json::json!({});
        if let Some(ref rationale) = rel.rationale {
            props["rationale"] = serde_json::json!(rationale);
        }
        if let Some(strength) = rel.strength {
            props["strength"] = serde_json::json!(strength);
        }

        edges.push(PlannedEdge {
            source_id,
            source_type: "claim".to_string(),
            target_id,
            target_type: "claim".to_string(),
            relationship: rel.relationship.clone(),
            properties: props,
        });
    }

    for (author_idx, _author) in extraction.source.authors.iter().enumerate() {
        for planned_claim in &claims {
            edges.push(PlannedEdge {
                source_id: Uuid::nil(),
                source_type: "author_placeholder".to_string(),
                target_id: planned_claim.id,
                target_type: "claim".to_string(),
                relationship: "asserts".to_string(),
                properties: serde_json::json!({
                    "author_index": author_idx,
                    "role": "author",
                    "source": "document_attribution",
                }),
            });
        }
    }

    IngestPlan {
        claims,
        edges,
        path_index,
    }
}

impl crate::common::walker::Walker for DocumentExtraction {
    fn build_ingest_plan(&self) -> IngestPlan {
        build_ingest_plan(self)
    }
}

#[cfg(test)]
mod source_type_guard {
    use super::{source_type_str, DOCUMENT_SOURCE_TYPES};
    use crate::document::schema::SourceType;

    /// Every `SourceType` stamp must appear in [`DOCUMENT_SOURCE_TYPES`].
    ///
    /// The list is what MCP `verify_claim` consults to tell "this digest is not
    /// `blake3(content)` by construction" from "this body was mutated". A stamp
    /// missing from it makes every thesis/section/paragraph row of that source
    /// type report a tampering mismatch.
    ///
    /// The `match` below is exhaustive on purpose: adding a `SourceType` variant
    /// is a COMPILE error here until someone decides whether its stamp belongs
    /// in the list (and adds it to `ALL` so this test still covers it).
    #[test]
    fn every_source_type_stamp_is_listed() {
        const ALL: [SourceType; 7] = [
            SourceType::Paper,
            SourceType::Textbook,
            SourceType::InternalDocument,
            SourceType::Report,
            SourceType::Transcript,
            SourceType::Legal,
            SourceType::Tabular,
        ];

        for st in &ALL {
            match st {
                SourceType::Paper
                | SourceType::Textbook
                | SourceType::InternalDocument
                | SourceType::Report
                | SourceType::Transcript
                | SourceType::Legal
                | SourceType::Tabular => {}
            }
            let stamp = source_type_str(st);
            assert!(
                DOCUMENT_SOURCE_TYPES.contains(&stamp),
                "builder stamps source_type {stamp:?} but DOCUMENT_SOURCE_TYPES omits it — \
                 verify_claim would report every structural row of this source type as tampered"
            );
        }
        assert_eq!(
            DOCUMENT_SOURCE_TYPES.len(),
            ALL.len(),
            "the stamp list and the variant list must stay the same size"
        );
        assert!(
            !DOCUMENT_SOURCE_TYPES.contains(&"workflow"),
            "the workflow builder binds the PLAIN content hash on its compound nodes; listing \
             its stamp here would excuse a tampered workflow phase/step body"
        );
    }
}
