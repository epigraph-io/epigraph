//! Every relationship the reranker is allowed to emit must have a real verdict
//! (issue #388).
//!
//! The defect this guards is structural, not a one-off. `VALID_RELATIONSHIPS`
//! (`epigraph-cli`) and `map_relationship` (`epigraph-engine`) are two halves of
//! one contract maintained in two crates, with nothing tying them together:
//! `parse_validation_response` ACCEPTS a member rather than discarding it, and
//! `build_validation_prompt` advertises it to the model — yet a member with no
//! `map_relationship` arm silently falls to `_ => MatchVerdict::Distinct`, which
//! `matching::pipeline` routes to `PolicyAction::Reject`. `derives_from` sat
//! there for the whole life of the matcher: one of five answers the model was
//! invited to give was converted into a rejection, and under #382's promotion
//! rules a `distinct` row is permanently un-promotable, so the pair was retired
//! rather than merely unpromoted.
//!
//! The test lives in `epigraph-cli` because the dependency runs one way:
//! `epigraph-cli/Cargo.toml` depends on `epigraph-engine`, and the engine has
//! no dependency back, so this is the only crate from which both halves are
//! visible.
//!
//! **Precondition, stated because it is easy to misread the invariant below:**
//! `Distinct` is not categorically illegal — `REJECTED_RELATIONSHIP` maps there
//! on purpose. The invariant holds specifically for `VALID_RELATIONSHIPS`,
//! whose members are by construction the strings the model emits when it
//! ENDORSES a pair, and it only became true once explicit `valid: false`
//! rejections stopped borrowing `derives_from` to mean "no".

#![cfg(feature = "genai")]

use epigraph_cli::rerank::candidates::VALID_RELATIONSHIPS;
use epigraph_engine::matching::verifier::{map_relationship, MatchVerdict, REJECTED_RELATIONSHIP};

/// No member of the reranker's endorsement vocabulary may land on the `_` arm.
///
/// Uses `Distinct` as the observable proxy for "unmapped", which is exact as
/// long as no vocabulary member is deliberately mapped to `Distinct` — and none
/// can be, by the argument in the module doc. A vocabulary addition made
/// without an arm fails here instead of silently rejecting real matches.
#[test]
fn every_reranker_relationship_has_a_real_verdict() {
    let unmapped: Vec<&str> = VALID_RELATIONSHIPS
        .iter()
        .copied()
        .filter(|rel| map_relationship(rel, 0.7) == MatchVerdict::Distinct)
        .collect();

    assert!(
        unmapped.is_empty(),
        "these relationships are offered to the model as legal answers but have \
         no `map_relationship` arm, so an endorsement using them is converted \
         into a rejection: {unmapped:?}. Add an arm in \
         epigraph-engine::matching::verifier::map_relationship, or remove them \
         from VALID_RELATIONSHIPS and from rerank::prompt."
    );
}

/// The complement, and the precondition the test above depends on: the
/// rejection sentinel must stay outside the vocabulary. If it ever became a
/// member, the assertion above would demand a non-`Distinct` verdict for it and
/// the endorsement/rejection overload would be back.
#[test]
fn the_rejection_sentinel_is_not_a_reranker_relationship() {
    assert!(
        !VALID_RELATIONSHIPS.contains(&REJECTED_RELATIONSHIP),
        "{REJECTED_RELATIONSHIP} must not be a legal model answer — it means \
         `valid: false`, not a relationship"
    );
    assert_eq!(
        map_relationship(REJECTED_RELATIONSHIP, 0.0),
        MatchVerdict::Distinct,
        "a rejection must still reject"
    );
}

/// The specific verdict `derives_from` now carries, asserted here as well as in
/// `epigraph-engine/tests/verifier_smoke.rs`, because this is where it is
/// visible that `derives_from` is a VOCABULARY member — the fact that makes
/// `Distinct` wrong for it.
///
/// `Overlapping` mirrors `refines`: both route to `PolicyAction::Reject`, so no
/// edge is written automatically, but `MatchVerdict::Overlapping
/// .promotion_disposition()` is `Corroborate`, so a human reviewing the staged
/// candidate can still promote it. That is the whole behavioural delta.
#[test]
fn derives_from_takes_the_same_verdict_as_refines() {
    assert_eq!(
        map_relationship("derives_from", 0.7),
        map_relationship("refines", 0.7)
    );
    assert_eq!(
        map_relationship("derives_from", 0.7),
        MatchVerdict::Overlapping
    );
}
