use epigraph_ingest::builder::build_ingest_plan;
use epigraph_ingest::schema::DocumentExtraction;

/// Paragraph `evidence_type` is normalised to a canonical key and inherited by
/// its atoms; an unrecognised value is dropped to `None` so it never reaches
/// the BBA as an unknown tag.
#[test]
fn evidence_type_normalized_and_inherited_by_atoms() {
    let json = r#"{
      "source": { "title": "T" },
      "sections": [{
        "title": "S",
        "paragraphs": [
          { "text": "c1", "evidence_type": "Empirical", "atoms": ["a1", "a2"] },
          { "text": "c2", "evidence_type": "made_up_type", "atoms": ["a3"] },
          { "text": "c3", "atoms": ["a4"] }
        ]
      }]
    }"#;
    let extraction: DocumentExtraction = serde_json::from_str(json).unwrap();
    let plan = build_ingest_plan(&extraction);

    let etype = |content: &str| {
        plan.claims
            .iter()
            .find(|c| c.content == content)
            .unwrap()
            .evidence_type
            .clone()
    };

    // Canonical (case-insensitive) value propagates to the paragraph and atoms.
    assert_eq!(etype("c1").as_deref(), Some("empirical"));
    assert_eq!(etype("a1").as_deref(), Some("empirical"));
    assert_eq!(etype("a2").as_deref(), Some("empirical"));
    // Unrecognised value is dropped.
    assert_eq!(etype("c2"), None);
    assert_eq!(etype("a3"), None);
    // Absent value stays None.
    assert_eq!(etype("a4"), None);
}

/// Workflow `Step::evidence_type` is normalised to a canonical key and
/// inherited by its operation atoms; an unrecognised value is dropped to
/// `None`. Thesis (L0) and phase (L1) claims are structural and stay untagged,
/// mirroring document thesis/section claims. Parity with #208 (document side).
#[test]
fn workflow_evidence_type_normalized_and_inherited_by_atoms() {
    use epigraph_ingest::workflow::{build_ingest_plan, WorkflowExtraction};

    let json = r#"{
      "source": { "canonical_name": "wf-evtype", "goal": "G", "generation": 0, "authors": [] },
      "thesis": "T",
      "phases": [{
        "title": "P",
        "summary": "phase summary",
        "steps": [
          { "compound": "s1", "evidence_type": "Empirical", "operations": ["op1", "op2"], "confidence": 0.9 },
          { "compound": "s2", "evidence_type": "made_up_type", "operations": ["op3"], "confidence": 0.9 },
          { "compound": "s3", "operations": ["op4"], "confidence": 0.9 }
        ]
      }]
    }"#;
    let extraction: WorkflowExtraction = serde_json::from_str(json).unwrap();
    let plan = build_ingest_plan(&extraction);

    let etype = |content: &str| {
        plan.claims
            .iter()
            .find(|c| c.content == content)
            .unwrap_or_else(|| panic!("no claim with content {content}"))
            .evidence_type
            .clone()
    };

    // Canonical (case-insensitive) value propagates to the step and its atoms.
    assert_eq!(etype("s1").as_deref(), Some("empirical"));
    assert_eq!(etype("op1").as_deref(), Some("empirical"));
    assert_eq!(etype("op2").as_deref(), Some("empirical"));
    // Unrecognised value is dropped on both the step and its atom.
    assert_eq!(etype("s2"), None);
    assert_eq!(etype("op3"), None);
    // Absent value stays None.
    assert_eq!(etype("op4"), None);
    // Structural thesis (L0) and phase (L1) claims never carry a tag.
    assert_eq!(etype("T"), None);
    assert_eq!(etype("phase summary"), None);
}

#[test]
fn test_full_extraction_from_fixture() {
    let json = include_str!("fixtures/sample_hierarchical.json");
    let extraction: DocumentExtraction = serde_json::from_str(json).unwrap();

    let plan = build_ingest_plan(&extraction);

    // 1 thesis + 2 sections + 3 paragraphs + 9 atoms = 15 claims
    assert_eq!(
        plan.claims.iter().filter(|c| c.level == 0).count(),
        1,
        "thesis"
    );
    assert_eq!(
        plan.claims.iter().filter(|c| c.level == 1).count(),
        2,
        "sections"
    );
    assert_eq!(
        plan.claims.iter().filter(|c| c.level == 2).count(),
        3,
        "paragraphs"
    );
    assert_eq!(
        plan.claims.iter().filter(|c| c.level == 3).count(),
        9,
        "atoms"
    );
    assert_eq!(plan.claims.len(), 15);

    // 14 decomposes_to + 1 supports + 30 author_asserts + 1 section_follows + 1 continues_argument = 47
    assert_eq!(
        plan.edges
            .iter()
            .filter(|e| e.relationship == "decomposes_to")
            .count(),
        14
    );
    assert_eq!(
        plan.edges
            .iter()
            .filter(|e| e.relationship == "supports")
            .count(),
        1
    );
    assert_eq!(
        plan.edges
            .iter()
            .filter(|e| e.source_type == "author_placeholder")
            .count(),
        30
    );
    assert_eq!(
        plan.edges
            .iter()
            .filter(|e| e.relationship == "section_follows")
            .count(),
        1
    );
    assert_eq!(
        plan.edges
            .iter()
            .filter(|e| e.relationship == "continues_argument")
            .count(),
        1
    );
    assert_eq!(plan.edges.len(), 47);

    // Verify thesis content
    let thesis = plan.claims.iter().find(|c| c.level == 0).unwrap();
    assert!(thesis.content.contains("Serial entrepreneurs outperform"));

    // Verify atom determinism — same text always gets same ID
    let atom_67pct: Vec<_> = plan
        .claims
        .iter()
        .filter(|c| {
            c.content == "Serial entrepreneurs achieve 67% higher sales than novice entrepreneurs."
        })
        .collect();
    assert_eq!(atom_67pct.len(), 1);

    // Verify generality is in properties
    let atom_def = plan
        .claims
        .iter()
        .find(|c| c.content.contains("defined as entrepreneurs"))
        .unwrap();
    assert_eq!(atom_def.properties["generality"], 0);
}
