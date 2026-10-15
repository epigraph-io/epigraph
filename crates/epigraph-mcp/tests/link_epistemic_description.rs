//! The `link_epistemic` tool description is the contract an agent reads before
//! it files an edge, so it must not promise a belief movement the engine does
//! not deliver (backlog 9e95689e, drain U028).
//!
//! The engine transmits a positive edge's source as a restricted interval
//! (`restrict_epistemic_positive`): its belief scaled by the edge factor, but
//! ALSO its disbelief (`1 - Pl`) and its open-world (frame-incompleteness)
//! mass, each scaled by the same factor. Measured through the production
//! `discount` + `combine_multiple` pipeline (supports, f = 0.80):
//!
//! - target [0.75, 1.0, ow 0] from a disbelieved source [0.0, 0.2, ow 0]:
//!   Bel 0.75 -> 0.5942, BetP 0.8750 -> 0.6932;
//! - target [0.70, 1.0, ow 0.30] from a frame-incomplete source
//!   [0.10, 1.0, ow 0.90] that carries no disbelief at all:
//!   Bel and BetP 0.70 -> 0.6320.
//!
//! So "these STRENGTHEN the target's belief" is false for Bel and for BetP.

fn link_epistemic_description() -> String {
    epigraph_mcp::server::EpiGraphMcpFull::static_tools()
        .iter()
        .find(|t| t.name == "link_epistemic")
        .and_then(|t| t.description.as_deref().map(str::to_string))
        .expect("link_epistemic is in the manifest and has a description")
}

#[test]
fn link_epistemic_description_does_not_promise_positive_edges_raise_belief() {
    let d = link_epistemic_description();
    assert!(
        !d.contains("STRENGTHEN the target's belief"),
        "the unconditional STRENGTHEN promise must be gone: {d}"
    );
    assert!(
        !d.contains("(these WEAKEN it)"),
        "the unconditional WEAKEN promise must be gone: {d}"
    );
}

#[test]
fn link_epistemic_description_states_how_a_positive_edge_can_lower_belief() {
    let d = link_epistemic_description();
    for needle in [
        // The polarity split is still stated: an agent needs it to pick a relationship.
        "positive: supports, corroborates, elaborates, generalizes, specializes",
        "negative: contradicts, refutes",
        // The mechanism: the source's doubt travels with its belief.
        "open-world (frame-incompleteness) mass",
        "scaled by the relationship's factor",
        // The consequence, for both measures the API reports.
        "a positive edge can LOWER the target's belief and pignistic_prob",
    ] {
        assert!(d.contains(needle), "description lacks {needle:?}: {d}");
    }
}

/// `contradicts` / `refutes` transfer belief by MUTUAL EXCLUSION (drain U075):
/// only the source's belief crosses the edge, as disbelief in the target; the
/// source's disbelief transfers nothing. So, unlike a positive edge, a
/// negative edge cannot move its target the "wrong" way, and the contract an
/// agent reads must say so (the smoke test
/// `contradicts_from_disbelieved_source_does_not_raise_target_belief`
/// measures it through the real write path).
#[test]
fn link_epistemic_description_states_a_negative_edge_cannot_raise_belief() {
    let d = link_epistemic_description();
    for needle in [
        "A negative edge means mutual exclusion",
        "the source's disbelief transfers nothing",
        "a negative edge puts no mass on the target being true",
        "a negative edge cannot RAISE the target's belief or pignistic_prob",
    ] {
        assert!(d.contains(needle), "description lacks {needle:?}: {d}");
    }
    // The old blanket claim covered negative edges too; it must now be scoped
    // to positive ones.
    assert!(
        !d.contains("Polarity is not a guarantee of direction: the edge carries"),
        "the unscoped 'whole interval' claim must be gone: {d}"
    );
}
