//! A belief read's profile identity: `{name, hash}` (addendum §3.1, SPEC §3.5
//! `BeliefView.profile`). The name is the named global profile the lens was
//! resolved over; the hash is over the RESOLVED parameters. So two lenses over
//! the same global profile share the name and differ in hash exactly when
//! their resolved parameters differ.

use epigraph_engine::belief_profile::{
    BeliefProfile, FrameTier, PerspectiveTier, DEFAULT_PROFILE_NAME,
};
use epigraph_engine::belief_query::FramedBeliefContext;

#[test]
fn a_context_reports_the_global_profiles_name_and_its_resolved_hash() {
    let global = BeliefProfile::builtin();
    let lensed = global.resolve(
        FrameTier::default(),
        PerspectiveTier {
            overrides: Some(&serde_json::json!({
                "reliability": { "intra_evidence_locality_factor": 0.9 }
            })),
            reliability: None,
        },
    );
    let restated = global.resolve(
        FrameTier::default(),
        PerspectiveTier {
            overrides: Some(&serde_json::json!({
                "reliability": {
                    "intra_evidence_locality_factor": global.reliability.intra_evidence_locality_factor
                }
            })),
            reliability: None,
        },
    );

    let plain = FramedBeliefContext::from_profile(global.clone()).profile_identity();
    let moved = FramedBeliefContext::from_profile(lensed.clone()).profile_identity();
    let same = FramedBeliefContext::from_profile(restated).profile_identity();

    assert_eq!(plain.name, DEFAULT_PROFILE_NAME);
    assert_eq!(moved.name, DEFAULT_PROFILE_NAME);
    assert_eq!(plain.hash, global.profile_hash());
    assert_eq!(moved.hash, lensed.profile_hash());
    assert_ne!(
        plain.hash, moved.hash,
        "a parameter moved, so the hash moves"
    );
    assert_eq!(
        plain, same,
        "a restated parameter moves neither name nor hash"
    );
}
