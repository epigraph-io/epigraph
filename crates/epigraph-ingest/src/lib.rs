pub mod builder;
pub mod common;
pub mod document;
pub mod errors;
pub mod schema;
pub mod workflow;

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

    // ── WorkflowExtraction ingest tests ──

    use crate::workflow::schema as wf_schema;

    fn make_workflow(json: &str) -> wf_schema::WorkflowExtraction {
        serde_json::from_str(json).expect("test workflow JSON should parse")
    }

    fn minimal_workflow_json() -> &'static str {
        r#"{
            "source": {
                "canonical_name": "deploy-canary",
                "goal": "Deploy a canary release safely.",
                "generation": 0,
                "authors": []
            },
            "thesis": "Workflow for canary deployment with monitoring.",
            "phases": [{
                "title": "Pre-flight",
                "summary": "Verify prerequisites.",
                "steps": [{
                    "compound": "Confirm CI passing.",
                    "operations": ["Run `gh pr checks`."],
                    "generality": [1],
                    "confidence": 0.9
                }]
            }],
            "relationships": []
        }"#
    }

    #[test]
    fn test_workflow_build_plan_counts() {
        let wf = make_workflow(minimal_workflow_json());
        let plan = crate::workflow::build_ingest_plan(&wf);

        // 1 thesis + 1 phase + 1 step + 1 operation
        assert_eq!(plan.claims.len(), 4);

        let level_counts: Vec<usize> = (0..=3)
            .map(|l| plan.claims.iter().filter(|c| c.level == l).count())
            .collect();
        assert_eq!(level_counts, vec![1, 1, 1, 1]);

        let decompose_count = plan
            .edges
            .iter()
            .filter(|e| e.relationship == "decomposes_to")
            .count();
        assert_eq!(decompose_count, 3, "thesis->phase, phase->step, step->op");
    }

    #[test]
    fn test_workflow_uses_phase_follows_not_section_follows() {
        let json = r#"{
            "source": {"canonical_name": "two-phase", "goal": "G", "authors": []},
            "thesis": "T",
            "phases": [
                {"title": "P1", "summary": "S1", "steps": []},
                {"title": "P2", "summary": "S2", "steps": []}
            ],
            "relationships": []
        }"#;
        let plan = crate::workflow::build_ingest_plan(&make_workflow(json));
        assert!(
            plan.edges.iter().any(|e| e.relationship == "phase_follows"),
            "must emit phase_follows for adjacent phases"
        );
        assert!(
            plan.edges.iter().all(|e| e.relationship != "section_follows"),
            "must NOT emit section_follows in workflow plans"
        );
    }

    #[test]
    fn test_workflow_step_follows_within_phase() {
        let json = r#"{
            "source": {"canonical_name": "two-step", "goal": "G", "authors": []},
            "thesis": "T",
            "phases": [{
                "title": "P1", "summary": "S1",
                "steps": [
                    {"compound": "Step1", "operations": ["op1"], "generality": [1], "confidence": 0.8},
                    {"compound": "Step2", "operations": ["op2"], "generality": [1], "confidence": 0.8}
                ]
            }],
            "relationships": []
        }"#;
        let plan = crate::workflow::build_ingest_plan(&make_workflow(json));
        let step_follows: Vec<_> = plan.edges.iter().filter(|e| e.relationship == "step_follows").collect();
        assert_eq!(step_follows.len(), 1, "exactly one step_follows between two adjacent steps");
        assert!(
            plan.edges.iter().all(|e| e.relationship != "continues_argument"),
            "must NOT emit continues_argument in workflow plans"
        );
    }

    #[test]
    fn test_workflow_atom_converges_with_document_atom() {
        let doc_json = r#"{
            "source": {"title": "P", "source_type": "Paper", "authors": []},
            "sections": [{
                "title": "Body", "summary": "S",
                "paragraphs": [{
                    "compound": "C",
                    "atoms": ["text-embedding-3-large produces 3072-dimensional vectors."],
                    "generality": [1], "confidence": 0.9
                }]
            }]
        }"#;
        let wf_json = r#"{
            "source": {"canonical_name": "embed-pipeline", "goal": "G", "authors": []},
            "thesis": "T",
            "phases": [{
                "title": "Embed", "summary": "Embed step",
                "steps": [{
                    "compound": "Run embedding.",
                    "operations": ["text-embedding-3-large produces 3072-dimensional vectors."],
                    "generality": [1], "confidence": 0.9
                }]
            }]
        }"#;
        let doc: crate::document::schema::DocumentExtraction =
            serde_json::from_str(doc_json).unwrap();
        let wf: wf_schema::WorkflowExtraction = serde_json::from_str(wf_json).unwrap();

        let doc_plan = crate::document::build_ingest_plan(&doc);
        let wf_plan = crate::workflow::build_ingest_plan(&wf);

        let doc_atom = doc_plan.claims.iter().find(|c| c.level == 3).expect("doc has atom");
        let wf_op = wf_plan.claims.iter().find(|c| c.level == 3).expect("wf has operation");

        assert_eq!(
            doc_atom.id, wf_op.id,
            "operation atom in workflow must converge with document atom of same text (ATOM_NAMESPACE shared)"
        );
    }

    #[test]
    fn test_workflow_compound_ids_scoped_by_canonical_name() {
        let json_a = r#"{
            "source": {"canonical_name": "wf-a", "goal": "G", "authors": []},
            "thesis": "Same thesis text",
            "phases": [],
            "relationships": []
        }"#;
        let json_b = r#"{
            "source": {"canonical_name": "wf-b", "goal": "G", "authors": []},
            "thesis": "Same thesis text",
            "phases": [],
            "relationships": []
        }"#;
        let plan_a = crate::workflow::build_ingest_plan(&make_workflow(json_a));
        let plan_b = crate::workflow::build_ingest_plan(&make_workflow(json_b));
        let thesis_a = plan_a.claims.iter().find(|c| c.level == 0).unwrap();
        let thesis_b = plan_b.claims.iter().find(|c| c.level == 0).unwrap();
        assert_ne!(
            thesis_a.id, thesis_b.id,
            "compound nodes must NOT converge across workflows with different canonical_name"
        );
    }
}
