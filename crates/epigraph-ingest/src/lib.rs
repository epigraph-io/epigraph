pub mod builder;
pub mod common;
pub mod errors;
pub mod schema;

#[cfg(test)]
mod tests {
    use crate::schema::{DocumentExtraction, SourceType, ThesisDerivation};

    #[test]
    fn test_parse_minimal_document_extraction() {
        let json = r#"{
            "source": {
                "title": "Test Paper",
                "source_type": "Paper",
                "authors": []
            },
            "thesis": "This is the thesis",
            "thesis_derivation": "TopDown",
            "sections": [
                {
                    "title": "Introduction",
                    "summary": "An intro",
                    "paragraphs": [
                        {
                            "compound": "A compound claim",
                            "supporting_text": "Some evidence",
                            "atoms": ["Atom one", "Atom two"],
                            "generality": [3, 2],
                            "confidence": 0.9
                        }
                    ]
                }
            ],
            "relationships": []
        }"#;

        let doc: DocumentExtraction =
            serde_json::from_str(json).expect("should parse minimal document");

        assert_eq!(doc.source.title, "Test Paper");
        assert_eq!(doc.sections.len(), 1);
        assert_eq!(doc.sections[0].paragraphs.len(), 1);
        assert_eq!(doc.sections[0].paragraphs[0].atoms.len(), 2);
        assert_eq!(doc.thesis, Some("This is the thesis".to_string()));
    }

    #[test]
    fn test_parse_bottom_up_thesis() {
        let json = r#"{
            "source": {
                "title": "Internal Report",
                "source_type": "InternalDocument",
                "uri": "ndi:internal:test",
                "authors": []
            },
            "thesis": null,
            "thesis_derivation": "BottomUp",
            "sections": [],
            "relationships": []
        }"#;

        let doc: DocumentExtraction =
            serde_json::from_str(json).expect("should parse bottom-up document");

        assert!(doc.thesis.is_none());
        assert_eq!(doc.thesis_derivation, ThesisDerivation::BottomUp);
        assert_eq!(doc.source.source_type, SourceType::InternalDocument);
        assert_eq!(doc.source.uri, Some("ndi:internal:test".to_string()));
    }

    #[test]
    fn test_parse_cross_atom_relationships() {
        let json = r#"{
            "source": {
                "title": "Relationship Test",
                "source_type": "Paper",
                "authors": []
            },
            "sections": [],
            "relationships": [
                {
                    "source_path": "sections[0].paragraphs[0].atoms[0]",
                    "target_path": "sections[0].paragraphs[1].atoms[0]",
                    "relationship": "supports"
                }
            ]
        }"#;

        let doc: DocumentExtraction =
            serde_json::from_str(json).expect("should parse relationships");

        assert_eq!(doc.relationships.len(), 1);
        assert_eq!(
            doc.relationships[0].source_path,
            "sections[0].paragraphs[0].atoms[0]"
        );
        assert_eq!(
            doc.relationships[0].target_path,
            "sections[0].paragraphs[1].atoms[0]"
        );
        assert_eq!(doc.relationships[0].relationship, "supports");
    }

    // ── IngestPlan builder tests ─────────────────────────────────────

    use super::builder::*;

    fn make_extraction(json: &str) -> DocumentExtraction {
        serde_json::from_str(json).expect("test JSON should parse")
    }

    #[test]
    fn test_build_plan_counts() {
        let json = r#"{
            "source": { "title": "T", "source_type": "Paper", "authors": [] },
            "thesis": "Main thesis",
            "thesis_derivation": "TopDown",
            "sections": [{
                "title": "S1",
                "summary": "Section summary",
                "paragraphs": [{
                    "compound": "Compound claim",
                    "supporting_text": "Evidence",
                    "atoms": ["Atom one", "Atom two"],
                    "generality": [3, 2],
                    "confidence": 0.9
                }]
            }],
            "relationships": []
        }"#;

        let plan = build_ingest_plan(&make_extraction(json));

        assert_eq!(
            plan.claims.len(),
            5,
            "1 thesis + 1 section + 1 para + 2 atoms"
        );

        let level_counts: Vec<usize> = (0..=3)
            .map(|l| plan.claims.iter().filter(|c| c.level == l).count())
            .collect();
        assert_eq!(level_counts, vec![1, 1, 1, 2]);

        let decompose_count = plan
            .edges
            .iter()
            .filter(|e| e.relationship == "decomposes_to")
            .count();
        assert_eq!(
            decompose_count, 4,
            "thesis->section, section->para, para->atom x2"
        );
    }

    #[test]
    fn test_build_plan_no_thesis() {
        let json = r#"{
            "source": { "title": "T", "source_type": "Paper", "authors": [] },
            "thesis": null,
            "thesis_derivation": "BottomUp",
            "sections": [{
                "title": "S1",
                "summary": "Section summary",
                "paragraphs": [{
                    "compound": "Compound",
                    "atoms": ["Atom"],
                    "generality": [1],
                    "confidence": 0.8
                }]
            }],
            "relationships": []
        }"#;

        let plan = build_ingest_plan(&make_extraction(json));

        assert_eq!(
            plan.claims.len(),
            3,
            "0 thesis + 1 section + 1 para + 1 atom"
        );

        let level0 = plan.claims.iter().filter(|c| c.level == 0).count();
        assert_eq!(level0, 0);

        let decompose_count = plan
            .edges
            .iter()
            .filter(|e| e.relationship == "decomposes_to")
            .count();
        assert_eq!(decompose_count, 2, "section->para, para->atom");
    }

    #[test]
    fn test_build_plan_cross_relationships() {
        let json = r#"{
            "source": { "title": "T", "source_type": "Paper", "authors": [] },
            "thesis": null,
            "sections": [{
                "title": "S1",
                "summary": "Summary",
                "paragraphs": [
                    {
                        "compound": "P1",
                        "atoms": ["A1", "A2"],
                        "generality": [1, 2],
                        "confidence": 0.9
                    },
                    {
                        "compound": "P2",
                        "atoms": ["A3"],
                        "generality": [1],
                        "confidence": 0.8
                    }
                ]
            }],
            "relationships": [{
                "source_path": "sections[0].paragraphs[0].atoms[1]",
                "target_path": "sections[0].paragraphs[1].atoms[0]",
                "relationship": "supports"
            }]
        }"#;

        let plan = build_ingest_plan(&make_extraction(json));

        let supports_edges: Vec<_> = plan
            .edges
            .iter()
            .filter(|e| e.relationship == "supports")
            .collect();
        assert_eq!(supports_edges.len(), 1, "exactly one supports edge");
    }

    #[test]
    fn test_build_plan_author_edges() {
        let json = r#"{
            "source": {
                "title": "Test",
                "source_type": "Paper",
                "authors": [
                    {"name": "Alice", "affiliations": ["MIT"]},
                    {"name": "Bob", "affiliations": ["Stanford"]}
                ],
                "metadata": {}
            },
            "thesis": "Main claim",
            "thesis_derivation": "TopDown",
            "sections": [
                {
                    "title": "Intro",
                    "summary": "Section summary",
                    "paragraphs": [
                        {
                            "compound": "Compound claim.",
                            "supporting_text": "Original.",
                            "atoms": ["Atom one.", "Atom two."],
                            "generality": [0, 1],
                            "confidence": 0.9
                        }
                    ]
                }
            ],
            "relationships": []
        }"#;

        let extraction: DocumentExtraction = serde_json::from_str(json).unwrap();
        let plan = build_ingest_plan(&extraction);

        // 5 claims × 2 authors = 10 author_asserts edges
        let author_edges: Vec<_> = plan
            .edges
            .iter()
            .filter(|e| e.relationship == "asserts" && e.source_type == "author_placeholder")
            .collect();
        assert_eq!(author_edges.len(), 10);

        let alice_edges: Vec<_> = author_edges
            .iter()
            .filter(|e| e.properties["author_index"] == 0)
            .collect();
        assert_eq!(alice_edges.len(), 5);
    }

    #[test]
    fn test_atom_deterministic_ids() {
        let json = r#"{
            "source": { "title": "T", "source_type": "Paper", "authors": [] },
            "thesis": null,
            "sections": [{
                "title": "S1",
                "summary": "Summary",
                "paragraphs": [{
                    "compound": "C",
                    "atoms": ["Deterministic atom"],
                    "generality": [1],
                    "confidence": 0.9
                }]
            }],
            "relationships": []
        }"#;

        let plan1 = build_ingest_plan(&make_extraction(json));
        let plan2 = build_ingest_plan(&make_extraction(json));

        let atoms1: Vec<_> = plan1.claims.iter().filter(|c| c.level == 3).collect();
        let atoms2: Vec<_> = plan2.claims.iter().filter(|c| c.level == 3).collect();

        assert_eq!(atoms1.len(), atoms2.len());
        for (a, b) in atoms1.iter().zip(atoms2.iter()) {
            assert_eq!(
                a.id, b.id,
                "atom IDs must be deterministic from content hash"
            );
        }
    }

    #[test]
    fn test_compound_claim_ids_deterministic() {
        let json = r#"{
            "source": {"title": "Test Paper", "source_type": "Paper", "authors": []},
            "thesis": "Thesis statement",
            "sections": [{
                "title": "Intro", "summary": "Introduction summary",
                "paragraphs": [{"compound": "P1 compound", "atoms": ["A1"], "confidence": 0.8}]
            }]
        }"#;
        let ext: DocumentExtraction = serde_json::from_str(json).unwrap();
        let plan1 = crate::builder::build_ingest_plan(&ext);
        let plan2 = crate::builder::build_ingest_plan(&ext);
        let compounds1: Vec<_> = plan1
            .claims
            .iter()
            .filter(|c| c.level < 3)
            .map(|c| c.id)
            .collect();
        let compounds2: Vec<_> = plan2
            .claims
            .iter()
            .filter(|c| c.level < 3)
            .map(|c| c.id)
            .collect();
        assert_eq!(
            compounds1, compounds2,
            "compound claim IDs must be deterministic across builds"
        );
        // Also verify they're not Uuid::nil or all the same
        assert!(compounds1.len() >= 3); // thesis + section + paragraph
        assert_ne!(
            compounds1[0], compounds1[1],
            "different claims should have different IDs"
        );
    }

    #[test]
    fn test_normalize_claim_path() {
        use crate::builder::normalize_claim_path;
        // Slash format → bracket-dot format
        assert_eq!(
            normalize_claim_path("sections/0/paragraphs/1/atoms/2"),
            "sections[0].paragraphs[1].atoms[2]"
        );
        // Already bracket-dot → pass through
        assert_eq!(
            normalize_claim_path("sections[0].paragraphs[1].atoms[2]"),
            "sections[0].paragraphs[1].atoms[2]"
        );
        // Thesis path
        assert_eq!(normalize_claim_path("thesis"), "thesis");
    }

    #[test]
    fn test_build_plan_cross_relationships_with_slash_paths() {
        let json = r#"{
            "source": {"title": "Test", "source_type": "Paper", "authors": []},
            "thesis": "Thesis",
            "sections": [{
                "title": "S1", "summary": "Summary",
                "paragraphs": [{
                    "compound": "P1",
                    "atoms": ["Atom A", "Atom B"],
                    "confidence": 0.8
                }]
            }],
            "relationships": [{
                "source_path": "sections/0/paragraphs/0/atoms/0",
                "target_path": "sections/0/paragraphs/0/atoms/1",
                "relationship": "supports"
            }]
        }"#;
        let extraction: DocumentExtraction = serde_json::from_str(json).unwrap();
        let plan = crate::builder::build_ingest_plan(&extraction);
        let cross_edges: Vec<_> = plan
            .edges
            .iter()
            .filter(|e| e.relationship == "supports")
            .collect();
        assert_eq!(
            cross_edges.len(),
            1,
            "slash-path relationship should resolve"
        );
    }
}
