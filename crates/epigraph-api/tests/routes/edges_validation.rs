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

#[test]
fn supersedes_uppercase_alias_is_valid() {
    // Lower-case `supersedes` already exists; this test pins the upper-case alias
    // that synthesis-side code uses.
    assert!(is_valid_relationship("SUPERSEDES"));
}
