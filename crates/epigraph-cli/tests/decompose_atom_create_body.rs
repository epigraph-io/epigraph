//! The wire shape `decompose_claims::submit_atom` POSTs to `/api/v1/claims`,
//! read back through the API's OWN request type.
//!
//! Backlog 3590a2d8: atoms were born with `evidence_ids=[]`. The fix (U041) is
//! the `derived_from` field this body carries; the API records a derivation
//! evidence row from it. `CreateClaimRequest` has no `deny_unknown_fields`, so
//! a misspelt key (`derived_from`, `claim_id`, `method`) — or the parent's id
//! and author swapped — is accepted with a 200 and the atom silently loses its
//! provenance again. Every other decompose test drives a fake submit closure
//! and never sees this body, so it is pinned here: deserialized by
//! `epigraph_api::routes::claims::CreateClaimRequest`, the parse the handler
//! actually does, rather than compared against a hand-copied literal.

use epigraph_api::routes::claims::CreateClaimRequest;
use epigraph_cli::decompose::{atom_create_body, AtomParent, DECOMPOSE_DERIVATION_METHOD};
use uuid::Uuid;

#[test]
fn atom_create_body_names_the_parent_in_derived_from_as_the_api_parses_it() {
    // Distinct ids, so a claim_id/agent_id swap cannot pass.
    let parent = AtomParent {
        claim_id: Uuid::new_v4(),
        agent_id: Uuid::new_v4(),
    };
    assert_ne!(parent.claim_id, parent.agent_id);

    let body = atom_create_body("The heavier mass accelerates downward.", 2, parent);
    let req: CreateClaimRequest = serde_json::from_value(body.clone())
        .unwrap_or_else(|e| panic!("the API must accept the atom body: {e}; body={body}"));

    let derived = req.derived_from.unwrap_or_else(|| {
        panic!(
            "the API parsed NO derived_from from the atom body, so the atom would be \
             born evidence-free (3590a2d8); body={body}"
        )
    });
    assert_eq!(
        derived.claim_id, parent.claim_id,
        "derived_from.claim_id must be the PARENT CLAIM; body={body}"
    );
    assert_eq!(derived.method, "decompose_claims");
    assert_eq!(DECOMPOSE_DERIVATION_METHOD, "decompose_claims");

    assert_eq!(
        req.agent_id, parent.agent_id,
        "the atom inherits the parent's AUTHOR as agent_id; body={body}"
    );
    assert_eq!(req.content, "The heavier mass accelerates downward.");
    assert!(
        req.if_not_exists,
        "if_not_exists must be set, or a re-run 409s instead of deduping"
    );
    assert_eq!(req.initial_truth, Some(0.5), "provenance, not belief");
    assert_eq!(
        req.labels,
        vec!["atom".to_string(), "generality:2".to_string()]
    );
    let props = req.properties.expect("properties carry the methodology");
    assert_eq!(props["methodology"], "inductive_generalization");
    assert_eq!(props["evidence_type"], "logical");
}
