//! A compound's belief, derived per viewer from its visible leaves
//! (atom-level belief program, SPEC §3.2, §3.3, §3.6, §7.1, §8).
//!
//! Skeleton: every entry point returns an inert value.

use std::collections::HashMap;

use uuid::Uuid;

use crate::belief_query::FramedBeliefContext;
use crate::belief_view::{
    Basis, BeliefView, DerivedBelief, Envelope, InputSummary, LeafState, NotAll, DEP_RULE,
    PRODUCT_FRAME_BETP,
};

/// Each requested atom's [`LeafState`] as `viewer` sees it.
///
/// # Errors
/// A database read.
pub async fn leaf_states_batch(
    _conn: &mut sqlx::PgConnection,
    _viewer: &epigraph_db::visibility::Viewer,
    ids: &[Uuid],
    _ctx: &FramedBeliefContext,
) -> Result<HashMap<Uuid, LeafState>, String> {
    Ok(ids.iter().map(|id| (*id, LeafState::Unproven)).collect())
}

/// P2 for each requested compound, over the leaves `viewer` can see.
///
/// # Errors
/// A database read.
pub async fn compound_ready_batch(
    _conn: &mut sqlx::PgConnection,
    _viewer: &epigraph_db::visibility::Viewer,
    ids: &[Uuid],
    _ctx: &FramedBeliefContext,
) -> Result<HashMap<Uuid, bool>, String> {
    Ok(ids.iter().map(|id| (*id, true)).collect())
}

/// The derived [`BeliefView`] of each requested compound, as `viewer` sees
/// it, under the lens `ctx`.
///
/// # Errors
/// A database read, or a conjunction that cannot be evaluated.
pub async fn derive_compound_belief_batch(
    _conn: &mut sqlx::PgConnection,
    _viewer: &epigraph_db::visibility::Viewer,
    ids: &[Uuid],
    _ctx: &FramedBeliefContext,
) -> Result<HashMap<Uuid, BeliefView>, String> {
    Ok(ids
        .iter()
        .map(|id| {
            (
                *id,
                BeliefView {
                    claim_id: *id,
                    basis: Basis::Derived,
                    bel: 0.0,
                    pl: 1.0,
                    betp: 0.5,
                    nr: 1.0,
                    derived: Some(DerivedBelief {
                        rule: DEP_RULE,
                        betp_kind: PRODUCT_FRAME_BETP,
                        frechet: Envelope {
                            lo: 0.0,
                            hi: 1.0,
                            hi_nr: 1.0,
                        },
                        conflict: 0.0,
                        exact: true,
                        leaves_used: 0,
                        evidenced: 0,
                        legacy_leaves: 0,
                        internally_contested: false,
                        not_all: NotAll::NONE,
                    }),
                    profile: None,
                    rule_version: DEP_RULE,
                    inputs: InputSummary::default(),
                },
            )
        })
        .collect())
}

/// The [`BeliefView`] of each requested atom or standalone, as `viewer` sees
/// it, under the lens `ctx`.
///
/// # Errors
/// A database read.
pub async fn atom_belief_view_batch(
    _conn: &mut sqlx::PgConnection,
    _viewer: &epigraph_db::visibility::Viewer,
    _ids: &[Uuid],
    _ctx: &FramedBeliefContext,
) -> Result<HashMap<Uuid, BeliefView>, String> {
    Ok(HashMap::new())
}
