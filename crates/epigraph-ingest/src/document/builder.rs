//! Document hierarchy walker. Reads a `DocumentExtraction` and produces an
//! `IngestPlan` of claims + edges + path index.

use std::collections::HashMap;

use uuid::Uuid;

use crate::common::ids::{atom_id, compound_claim_id, content_hash};
use crate::common::plan::{IngestPlan, PlannedClaim, PlannedEdge};
use crate::common::schema::ThesisDerivation;
use crate::document::schema::{DocumentExtraction, Paragraph, SourceType};

/// Convert slash-delimited paths from extraction ("sections/0/paragraphs/1/atoms/2")
/// to the bracket-dot notation used by path_index ("sections[0].paragraphs[1].atoms[2]").
/// Passes through paths that are already in bracket-dot format unchanged.
#[must_use]
pub fn normalize_claim_path(path: &str) -> String {
    if path.contains('[') {
        return path.to_string();
    }
    let parts: Vec<&str> = path.split('/').collect();
    let mut result = String::new();
    let mut i = 0;
    while i < parts.len() {
        if i > 0 {
            result.push('.');
        }
        result.push_str(parts[i]);
        if i + 1 < parts.len() && parts[i + 1].parse::<usize>().is_ok() {
            result.push('[');
            result.push_str(parts[i + 1]);
            result.push(']');
            i += 2;
            continue;
        }
        i += 1;
    }
    result
}

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

const fn thesis_derivation_str(td: &ThesisDerivation) -> &'static str {
    match td {
        ThesisDerivation::TopDown => "TopDown",
        ThesisDerivation::BottomUp => "BottomUp",
    }
}

fn decomposes_edge(source_id: Uuid, target_id: Uuid) -> PlannedEdge {
    PlannedEdge {
        source_id,
        source_type: "claim".to_string(),
        target_id,
        target_type: "claim".to_string(),
        relationship: "decomposes_to".to_string(),
        properties: serde_json::json!({}),
    }
}

fn enrichment_from_paragraph(paragraph: &Paragraph) -> serde_json::Value {
    serde_json::json!({
        "instruments_used": paragraph.instruments_used,
        "reagents_involved": paragraph.reagents_involved,
        "conditions": paragraph.conditions,
    })
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
        let id = compound_claim_id(&hash, doc_title);
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
            content_hash: hash,
            confidence: 1.0,
            methodology: None,
            evidence_type: None,
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
        let section_hash = content_hash(&section.summary);
        let section_id = compound_claim_id(&section_hash, doc_title);
        section_ids.push(section_id);
        path_index.insert(section_path.clone(), section_id);

        claims.push(PlannedClaim {
            id: section_id,
            content: section.summary.clone(),
            level: 1,
            properties: serde_json::json!({
                "level": 1,
                "source_type": source_type,
                "section": section.title,
            }),
            content_hash: section_hash,
            confidence: 1.0,
            methodology: None,
            evidence_type: None,
            supporting_text: None,
            enrichment: serde_json::json!({}),
        });

        if let Some(tid) = thesis_id {
            edges.push(decomposes_edge(tid, section_id));
        }

        let mut para_ids: Vec<Uuid> = Vec::new();

        for (pi, paragraph) in section.paragraphs.iter().enumerate() {
            let para_path = format!("{section_path}.paragraphs[{pi}]");
            let para_hash = content_hash(&paragraph.compound);
            let para_id = compound_claim_id(&para_hash, doc_title);
            para_ids.push(para_id);
            path_index.insert(para_path.clone(), para_id);

            let enrichment = enrichment_from_paragraph(paragraph);

            claims.push(PlannedClaim {
                id: para_id,
                content: paragraph.compound.clone(),
                level: 2,
                properties: serde_json::json!({
                    "level": 2,
                    "source_type": source_type,
                    "section": section.title,
                    "supporting_text": paragraph.supporting_text,
                }),
                content_hash: para_hash,
                confidence: paragraph.confidence,
                methodology: paragraph.methodology.clone(),
                evidence_type: paragraph.evidence_type.clone(),
                supporting_text: Some(paragraph.supporting_text.clone()),
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
                    evidence_type: paragraph.evidence_type.clone(),
                    supporting_text: Some(paragraph.supporting_text.clone()),
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
