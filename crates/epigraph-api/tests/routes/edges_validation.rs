//! Validation tests for edge entity types and relationship types added
//! to support the episcience paper-synthesis pipeline (Phase 0, Task 0.2).

use epigraph_api::routes::edges::is_valid_relationship;

// NOTE: `synthesis_entity_type_is_valid` moved to the `edges.rs` db_tests
// module (`is_valid_entity_type_covers_all_seeded_types`). `is_valid_entity_type`
// is no longer a pure free function — it reads the `entity_types` registry cache
// on `AppState`, so validity is asserted against a loaded cache in a DB test,
// not a hardcoded list here.

#[test]
fn prov_o_synthesis_predicates_are_valid() {
    assert!(is_valid_relationship("WAS_DERIVED_FROM"));
    assert!(is_valid_relationship("REFINES"));
    assert!(is_valid_relationship("COMPOSED_OF"));
}

#[test]
fn methodology_relation_is_valid() {
    assert!(is_valid_relationship("METHODOLOGY"));
}

/// Inverted by ruling R-132 ("supersedes = revision only"; supersede SPEC
/// K12a): this pinned the upper-case `SUPERSEDES` alias as a valid generic
/// relationship for the synthesis side. The lineage edge is written only by
/// the supersession act, in one spelling, so neither spelling is a generic
/// relationship. (The synthesis side only reads that edge.)
#[test]
fn supersedes_is_not_a_generic_relationship_in_either_spelling() {
    assert!(!is_valid_relationship("SUPERSEDES"));
    assert!(!is_valid_relationship("supersedes"));
}
