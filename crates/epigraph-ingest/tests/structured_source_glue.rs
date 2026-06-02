use epigraph_ingest::builder::build_ingest_plan;
use epigraph_ingest::schema::{DocumentExtraction, SourceType};
use std::collections::HashSet;

/// Regression guard for backlog b5518801: every planned claim must have a
/// DISTINCT id and no `decomposes_to` edge may be a self-loop. The original
/// emitters set a section's `summary` to the verbatim text of its first
/// paragraph's `compound`; since `compound_claim_id` hashes content with no
/// level in the material, the L1 section and its first L2 paragraph collapsed
/// onto the SAME UUID — a self-loop `decomposes_to(section, section)` and a
/// duplicate-id insert. Claim/edge COUNTS are blind to this (the builder pushes
/// both colliding claims regardless), so we assert id distinctness directly.
fn assert_no_collisions(plan: &epigraph_ingest::builder::IngestPlan) {
    let ids: HashSet<uuid::Uuid> = plan.claims.iter().map(|c| c.id).collect();
    assert_eq!(
        ids.len(),
        plan.claims.len(),
        "every planned claim id must be distinct (no L1 section == L2 paragraph collision)"
    );
    for e in plan.edges.iter().filter(|e| e.relationship == "decomposes_to") {
        assert_ne!(
            e.source_id, e.target_id,
            "decomposes_to must never be a self-loop (section id == paragraph id)"
        );
    }
}

// The fixtures are the VERBATIM output of the Python preprocessors:
//   sample_arxiv_extraction.json      <- scripts/extract_html.py on sample_arxiv.html
//   sample_openstax_extraction.json   <- scripts/extract_textbook.py on sample_openstax_module.cnxml
// Regen commands are documented in the spec and in scripts/README.md. If a
// parser changes, regenerate the fixture; this test then enforces the new
// contract deliberately.

#[test]
fn arxiv_html_maps_to_valid_document_extraction_hierarchy() {
    let json = include_str!("fixtures/sample_arxiv_extraction.json");
    let doc: DocumentExtraction =
        serde_json::from_str(json).expect("arXiv fixture must be a valid DocumentExtraction");

    // Source mapping the glue is responsible for.
    assert_eq!(doc.source.source_type, SourceType::Paper);
    assert_eq!(
        doc.source.doi.as_deref(),
        Some("10.48550/arXiv.2603.04139"),
        "arXiv id must derive the 10.48550 DOI"
    );
    assert_eq!(doc.source.authors.len(), 3, "joined author blob split into 3");
    assert!(doc.thesis.is_some(), "abstract becomes the thesis");

    // Two h2 sections, each exactly one paragraph (HTML loses intra-section
    // paragraph boundaries -> Section maps to a single Paragraph).
    assert_eq!(doc.sections.len(), 2);
    for s in &doc.sections {
        assert_eq!(s.paragraphs.len(), 1, "one paragraph per HTML section");
        let p = &s.paragraphs[0];
        assert!(!p.compound.is_empty(), "compound is required + non-empty");
        assert!(
            p.atoms.is_empty(),
            "structure recovery emits NO atoms; the LLM stage fills them"
        );
    }

    // The skipped <math> content must not have leaked into the text.
    let all_text: String = doc
        .sections
        .iter()
        .flat_map(|s| s.paragraphs.iter())
        .map(|p| p.supporting_text.clone())
        .collect();
    assert!(
        !all_text.contains("E=m") && !all_text.contains("E = m"),
        "MathML inside <math> must be skipped, not extracted"
    );

    // Now the actual glue->builder contract: a thesis(L0) + 2 sections(L1) +
    // 2 paragraphs(L2), zero atoms(L3), and the structural edges.
    let plan = build_ingest_plan(&doc);
    assert_no_collisions(&plan);
    let by_level = |l: u8| plan.claims.iter().filter(|c| c.level == l).count();
    assert_eq!(by_level(0), 1, "thesis");
    assert_eq!(by_level(1), 2, "sections");
    assert_eq!(by_level(2), 2, "paragraphs");
    assert_eq!(by_level(3), 0, "no atoms yet — pre-LLM structure recovery");

    let rel = |r: &str| plan.edges.iter().filter(|e| e.relationship == r).count();
    // thesis->S1, thesis->S2, S1->P1, S2->P2 = 4 decomposes_to.
    assert_eq!(rel("decomposes_to"), 4);
    // 2 sections -> exactly 1 section_follows.
    assert_eq!(rel("section_follows"), 1);
    // 1 paragraph per section -> no continues_argument (needs >=2 paras/section).
    assert_eq!(rel("continues_argument"), 0);
}

#[test]
fn openstax_cnxml_maps_to_valid_document_extraction_hierarchy() {
    let json = include_str!("fixtures/sample_openstax_extraction.json");
    let doc: DocumentExtraction =
        serde_json::from_str(json).expect("OpenStax fixture must be a valid DocumentExtraction");

    assert_eq!(doc.source.source_type, SourceType::Textbook);
    assert_eq!(doc.source.doi.as_deref(), Some("openstax:sample-physics"));

    // One module -> one section. CNXML preserves real <para> boundaries, so the
    // surviving real paragraph + the glossary definition = 2 paragraphs; the
    // transitional para is dropped.
    assert_eq!(doc.sections.len(), 1);
    let paras = &doc.sections[0].paragraphs;
    assert_eq!(paras.len(), 2, "1 real para + 1 definition; transitional dropped");
    assert!(
        paras.iter().all(|p| p.atoms.is_empty()),
        "no atoms in structure recovery"
    );
    assert!(
        paras.iter().any(|p| p.supporting_text.contains("[equation]")),
        "inline MathML must be rendered as the [equation] placeholder"
    );
    assert!(
        doc.sections[0]
            .paragraphs
            .iter()
            .all(|p| !p.supporting_text.contains("In this section, we will explore")),
        "transitional paragraph must be filtered out"
    );

    let plan = build_ingest_plan(&doc);
    assert_no_collisions(&plan);
    let by_level = |l: u8| plan.claims.iter().filter(|c| c.level == l).count();
    assert_eq!(by_level(1), 1, "one module -> one section");
    assert_eq!(by_level(2), 2, "two surviving paragraphs");
    assert_eq!(by_level(3), 0, "no atoms yet");
    let dec = plan.edges.iter().filter(|e| e.relationship == "decomposes_to").count();
    assert_eq!(dec, 2, "section->para x2 (no thesis in this fixture)");
    // 2 paragraphs in one section -> exactly 1 continues_argument edge.
    assert_eq!(
        plan.edges.iter().filter(|e| e.relationship == "continues_argument").count(),
        1
    );
}
