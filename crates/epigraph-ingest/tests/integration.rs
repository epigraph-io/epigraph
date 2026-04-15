use epigraph_ingest::builder::build_ingest_plan;
use epigraph_ingest::schema::DocumentExtraction;

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
