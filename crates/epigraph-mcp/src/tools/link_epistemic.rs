//! `link_epistemic` — belief-affecting epistemic edge creation between claims.
//!
//! Counterpart to the generic `POST /api/v1/edges` HTTP route's create→wire
//! path, scoped to claim↔claim epistemic relationships. Unlike the deliberately
//! inert [`link_hierarchical`](super::link_hierarchical) tool (no DS recompute,
//! no event), this tool mirrors `routes/edges.rs::create_edge`: on first
//! creation it builds a Dempster–Shafer mass function from the **source** claim's
//! belief interval and recomputes the **target** claim's combined belief, then
//! emits the `edge.added` durable event.
//!
//! Direction convention: `source -> target` means "source `relationship`
//! target" (a `supports` edge: source is evidence for / strengthens target),
//! matching `epigraph_engine::sheaf::restriction_kind_with_profile`.
//!
//! Tight contract:
//! - both endpoints are existing claims (`source_type`/`target_type` are always
//!   `"claim"`, not caller-controllable),
//! - `relationship` must be one of [`EPISTEMIC_RELATIONSHIPS`],
//!   [`STRUCTURAL_RELATIONSHIPS`] or [`TEMPORAL_RELATIONSHIPS`] (lowercase
//!   canonical strings; `supersedes` is intentionally excluded — it has
//!   dedicated semantics in `supersede_claim`). The latter two sets are kept
//!   separate because their members map to `RestrictionKind::Neutral` by
//!   design — belief-wiring already no-ops on Neutral, so accepting them
//!   here just lets citation/provenance (`cites`) and temporal-succession
//!   (`shifted_to`) edges be created MCP-natively without a doomed detour
//!   through the raw HTTP edges route. They stay two lists rather than one
//!   because they make different claims about the world and have different
//!   read sides: `shifted_to` alone feeds recall's re-ranking (via
//!   `ClaimRepository::shifted_from_batch`), while nothing reads `cites` for
//!   ranking.
//! - idempotent on `(source, target, relationship)` for the five ORDERED
//!   relations (`supports`, `elaborates`, `generalizes`, `specializes`,
//!   `refutes`) and on the UNORDERED pair for the two symmetric ones
//!   (`contradicts`, `corroborates` — see [`SYMMETRIC_RELATIONSHIPS`]). For a
//!   symmetric relation, re-asserting the REVERSE direction returns the
//!   EXISTING edge id — whose stored `source_id`/`target_id` are the opposite
//!   of the caller's params — with `was_created=false`.
//!
//!   Belief consequence of that (a genuine behavior change, not obvious from
//!   the write branch): `MassFunctionRepository::exists_for_perspective` keys
//!   solely on `perspective_id = edge_id`, so one edge id per pair means at
//!   most ONE edge-factor BBA can ever exist for that pair. A reverse
//!   re-assertion therefore short-circuits inside
//!   `auto_wire_edge_if_epistemic` and reports `belief_wired=false`; no BBA is
//!   wired onto the other endpoint. That is the correct reading for a relation
//!   whose truth is unordered, but it differs from the pre-`SYMMETRIC_RELATIONSHIPS`
//!   behavior, where `A contradicts B` then `B contradicts A` moved BOTH
//!   endpoints' belief via two edges and two BBAs.
//!
//!   A re-hit never re-creates the durable edge row or re-emits `edge.added`.
//!   Belief wiring, however, is NOT gated
//!   on `was_created` alone: a re-hit still attempts the wire, and
//!   `belief_wired=true` on that re-hit exactly when no BBA has ever been
//!   materialized for this edge_id AND the source now has a belief interval
//!   — the "factorless source wakes up later" case (backlog claim
//!   8ef5cf61-7382-43a4-85cb-565d76ba3f06). Once a BBA exists for the edge,
//!   further re-hits are stable no-ops again (`belief_wired=false`).
//!
//! Deferred vs the HTTP route (tracked as follow-ups): per-edge provenance
//! recording, 1-hop `propagate_to_dependents` (an HTTP-only concern per the
//! engine comment), and the legacy BP `factors`-table INSERT (a separate
//! subsystem from the CDST recompute that moves belief here).

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{LinkEpistemicBelief, LinkEpistemicParams, LinkEpistemicResponse};

use epigraph_core::ClaimId;
use epigraph_db::{ClaimRepository, EdgeRepository, EventRepository};
use epigraph_engine::edge_factor::{auto_wire_edge_if_epistemic, EdgeFactorOutcome};

/// Allowed epistemic relationship strings — the engine's non-neutral relations
/// **minus `supersedes`**, as lowercase canonical strings (matching the
/// `epigraph-core::relationships` constants and the engine's internal
/// `to_ascii_lowercase`).
///
/// Deliberately NOT validated against `routes/edges.rs::VALID_RELATIONSHIPS`:
/// that HTTP whitelist stores only UPPER-CASE `CONTRADICTS`/`CORROBORATES` and
/// is case-sensitive, while the engine lowercases internally. The real invariant
/// (asserted by the coverage-guard test) is that every entry maps to a
/// **non-Neutral** `RestrictionKind`, which is what actually moves belief.
///
/// `supersedes` is excluded on purpose: it has dedicated semantics
/// (`supersede_claim`, scope `claims:admin`, flips `is_current=false` + nulls
/// the superseded claim's embedding). Letting any `claims:write` agent write a
/// bare `supersedes` edge here would create an inconsistent state.
pub const EPISTEMIC_RELATIONSHIPS: &[&str] = &[
    "supports",
    "corroborates",
    "elaborates",
    "generalizes",
    "specializes",
    "contradicts",
    "refutes",
];

fn is_epistemic_relationship(s: &str) -> bool {
    EPISTEMIC_RELATIONSHIPS.contains(&s)
}

/// Structural (non-belief-affecting) relations `link_epistemic` also accepts,
/// kept deliberately SEPARATE from `EPISTEMIC_RELATIONSHIPS`.
///
/// Unlike the epistemic set, these are expected to map to
/// `RestrictionKind::Neutral` — a citation/provenance link is not an
/// epistemic claim about the relationship between two nodes, so it must not
/// move belief. Folding `cites` into `EPISTEMIC_RELATIONSHIPS` would break
/// `every_epistemic_relationship_maps_to_non_neutral`'s all-non-Neutral
/// invariant (and its hard count=7 assertion) below, so it gets its own
/// allow-list instead. `auto_wire_edge_if_epistemic` already no-ops safely on
/// `Neutral` relationships (see `epigraph_engine::edge_factor`'s
/// short-circuit), so no changes are needed to the belief-wiring path itself.
pub const STRUCTURAL_RELATIONSHIPS: &[&str] = &["cites"];

fn is_structural_relationship(s: &str) -> bool {
    STRUCTURAL_RELATIONSHIPS.contains(&s)
}

/// TEMPORAL-SUCCESSION relations `link_epistemic` also accepts — a THIRD
/// allow-list, kept separate from both sets above (backlog 52eff3ab).
///
/// `source shifted_to target` means the source is the value that held in an
/// earlier world and the target is the value that holds now: "the throughput
/// ceiling shifted from 400/s to 900/s" is `400/s -shifted_to-> 900/s`.
///
/// **Why this is not in [`EPISTEMIC_RELATIONSHIPS`], and must never be moved
/// there.** That const is *defined* as the belief-affecting set: every member
/// is asserted non-Neutral by `every_epistemic_relationship_maps_to_non_neutral`,
/// it is pinned at exactly seven, it is mirrored in
/// `epigraph_db::EPISTEMIC_RELATIONSHIPS`, and it drives
/// `ClaimRepository::in_epistemic_degree_batch`. Adding `shifted_to` there
/// would wire a Dempster–Shafer mass function onto the succession — the
/// `contradicts` treatment — and so retroactively falsify a correct historical
/// measurement. 400/s was TRUE of its own era; a later remeasurement is not
/// counter-evidence against it. That is precisely why succession is a separate
/// relationship from `contradicts` rather than a synonym for it.
///
/// **Why not fold it into [`STRUCTURAL_RELATIONSHIPS`].** Mechanically it would
/// work — both sets get the same `Neutral` (inert) treatment. But "this is a
/// citation" and "this value superseded that one in time" are different claims
/// about the world, and the read sides differ: nothing reads `cites` for
/// ranking, whereas `ClaimRepository::shifted_from_batch` turns `shifted_to`
/// into a recall re-ranking signal. A separate const keeps the doc honest and
/// keeps the partition test able to say which set a relation belongs to.
///
/// **What it DOES license: retrieval, not belief.** Inertness here is the
/// default rather than something this module arranges —
/// `restriction_kind_with_profile` falls through to `Neutral` for any unknown
/// relationship, `auto_wire_ds_for_edge` short-circuits to `NonEpistemic` on
/// Neutral before it queries anything, and the migration-001
/// `edge_to_factor_type` table has no `shifted_to` row, so the
/// `auto_create_factor_from_edge` trigger mints no BP factor. Inertness being
/// the default is exactly why it is fragile: it breaks the moment someone adds
/// `shifted_to` to `EPISTEMIC_RELATIONSHIPS`, so
/// `shifted_to_is_temporal_and_maps_to_neutral` below pins it.
///
/// Routes through the DIRECTIONAL writer (`create_if_not_exists`), not the
/// symmetric one: succession is ORDERED. The schema backs that with
/// `edges_shifted_to_pair_uniq` (migration 060), which rejects the REVERSED
/// assertion as well as the exact duplicate — `A shifted_to B` and
/// `B shifted_to A` are a temporal contradiction, not two facts.
pub const TEMPORAL_RELATIONSHIPS: &[&str] = &[epigraph_db::TEMPORAL_SUCCESSION_RELATIONSHIP];

fn is_temporal_relationship(s: &str) -> bool {
    TEMPORAL_RELATIONSHIPS.contains(&s)
}

/// Epistemic relations whose truth is UNORDERED: `A contradicts B` and
/// `B contradicts A` assert the same fact about the pair, so the graph must
/// hold ONE edge for them, not two.
///
/// Members route through `EdgeRepository::create_symmetric_if_absent_returning`
/// (bidirectional `WHERE NOT EXISTS`) instead of
/// `EdgeRepository::create_if_not_exists`, whose predicate
/// (`source_id = $1 AND target_id = $2 AND relationship = $3`) is directional.
/// This aligns `link_epistemic` with the cross-source matcher, which already
/// writes the SAME lowercase `contradicts` byte string through the symmetric
/// writer (`epigraph_engine::matching::verifier::CONTRADICTS_RELATIONSHIP` +
/// `matching::policy::write_edge`) — before this, the two writers disagreed
/// about whether a reversed pair was the same edge, so a matcher-written A→B
/// and an MCP-written B→A coexisted as duplicates. (`corroborates` unifies
/// only MCP-vs-MCP writes: the matcher emits UPPERCASE `CORROBORATES` and
/// dedup compares the relationship string byte-for-byte.)
///
/// Everything else in [`EPISTEMIC_RELATIONSHIPS`] is genuinely ordered
/// (`A supports B` != `B supports A`) and keeps the directional writer. The
/// row still stores the CALLER's `source -> target` ordering — we do NOT
/// canonicalize — so the read side must meet the writer halfway:
/// `ClaimRepository::in_epistemic_degree_batch` counts edges on BOTH endpoints
/// for these relations, and `ClaimRepository::dispute_batch` mirrors the
/// `contradicts` leg (only that one — `refutes` is ordered and stays
/// target-only). Without that, asserting the reverse direction of a
/// contradiction would return the existing edge and then read back as no
/// dispute signal at all on the asserter's own endpoint.
///
/// Defined once in `epigraph-db` alongside the batch readers that consume it
/// and re-exported here, so the writer's notion of "symmetric" and the
/// readers' cannot drift apart.
pub use epigraph_db::SYMMETRIC_RELATIONSHIPS;

fn is_symmetric_relationship(s: &str) -> bool {
    SYMMETRIC_RELATIONSHIPS.contains(&s)
}

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

pub async fn link_epistemic(
    server: &EpiGraphMcpFull,
    params: LinkEpistemicParams,
) -> Result<CallToolResult, McpError> {
    do_link_epistemic(server, params).await
}

/// Core logic factored out so integration tests can call it directly without
/// round-tripping through the rmcp dispatch layer (mirrors
/// `do_link_hierarchical`).
pub async fn do_link_epistemic(
    server: &EpiGraphMcpFull,
    params: LinkEpistemicParams,
) -> Result<CallToolResult, McpError> {
    let source_id = parse_uuid(&params.source_claim_id)?;
    let target_id = parse_uuid(&params.target_claim_id)?;

    // Tight allow-list — lowercase canonical epistemic relations, plus the two
    // separate inert sets: structural (currently just `cites`) and temporal
    // (currently just `shifted_to`). See each const's doc comment for why
    // neither is folded into EPISTEMIC_RELATIONSHIPS.
    if !is_epistemic_relationship(&params.relationship)
        && !is_structural_relationship(&params.relationship)
        && !is_temporal_relationship(&params.relationship)
    {
        return Err(invalid_params(format!(
            "invalid relationship '{}'. Valid epistemic types: {}. Valid structural types: {}. \
             Valid temporal types: {}",
            params.relationship,
            EPISTEMIC_RELATIONSHIPS.join(", "),
            STRUCTURAL_RELATIONSHIPS.join(", "),
            TEMPORAL_RELATIONSHIPS.join(", "),
        )));
    }

    // No self-loops — both endpoints are claims so equal UUIDs always loop.
    if source_id == target_id {
        return Err(invalid_params(
            "self-loops are not allowed (source and target are the same claim)",
        ));
    }

    let pool = &server.pool;

    // Verify both claims exist via the repo layer (SQL stays in epigraph-db).
    // Disambiguate which side is missing.
    if ClaimRepository::get_by_id(pool, ClaimId::from_uuid(source_id))
        .await
        .map_err(internal_error)?
        .is_none()
    {
        return Err(invalid_params(format!(
            "source_claim_id {source_id} not found"
        )));
    }
    if ClaimRepository::get_by_id(pool, ClaimId::from_uuid(target_id))
        .await
        .map_err(internal_error)?
        .is_none()
    {
        return Err(invalid_params(format!(
            "target_claim_id {target_id} not found"
        )));
    }

    // Symmetric relations dedup in BOTH directions (see SYMMETRIC_RELATIONSHIPS);
    // ordered relations keep the (source, target, relationship) triple.
    // The two writers differ in their `properties` shape: `create_if_not_exists`
    // takes `Option<Value>` and defaults internally, the symmetric one takes a
    // bare `Value`. Neither takes valid_from/valid_to — link_epistemic passes
    // `None, None` on the directional path anyway, so nothing is lost.
    let (edge_id, was_created) = if is_symmetric_relationship(&params.relationship) {
        EdgeRepository::create_symmetric_if_absent_returning(
            pool,
            source_id,
            target_id,
            &params.relationship,
            params
                .properties
                .clone()
                .unwrap_or_else(|| serde_json::json!({})),
        )
        .await
        .map_err(internal_error)?
    } else {
        let written = EdgeRepository::create_if_not_exists(
            pool,
            source_id,
            "claim",
            target_id,
            "claim",
            &params.relationship,
            params.properties.clone(),
            None,
            None,
        )
        .await;
        let (row, created) = match written {
            Ok(pair) => pair,
            // A direction-agnostic partial unique index rejected the INSERT
            // (`epigraph_db::PAIR_UNIQUE_RELATIONSHIPS` — `alternative_of`,
            // migration 042; `shifted_to`, migration 060). The directional
            // `WHERE NOT EXISTS` inside `create_if_not_exists` only sees the
            // caller's own orientation, so the reversed row slips past it and
            // the index is what stops the write. That is a caller mistake, not
            // a server fault: report it as `invalid_params` rather than
            // surfacing a raw constraint violation as an internal error.
            Err(epigraph_db::DbError::DuplicateKey { .. })
                if epigraph_db::PAIR_UNIQUE_RELATIONSHIPS
                    .contains(&params.relationship.as_str()) =>
            {
                return Err(invalid_params(format!(
                    "'{}' already relates {} and {} in the opposite direction. This pair is \
                     unique regardless of direction, so the reversal is not a second fact — \
                     for `shifted_to` it asserts that each value succeeded the other in time. \
                     Retract the existing edge if the direction recorded is wrong.",
                    params.relationship, source_id, target_id,
                )));
            }
            Err(e) => return Err(internal_error(e)),
        };
        (row.id, created)
    };

    // Belief wiring fires whenever no BBA has ever been materialized for this
    // edge yet — NOT simply on first creation. An edge can be written durably
    // while its source is "factorless" (no belief interval); if the source
    // later acquires belief and the SAME edge is re-asserted, `was_created`
    // is `false` on that call but the wake-up must still fire (backlog claim
    // 8ef5cf61-7382-43a4-85cb-565d76ba3f06). `auto_wire_edge_if_epistemic`
    // itself resolves the "already wired?" check (via
    // `MassFunctionRepository::exists_for_perspective`) and is a no-op once a
    // BBA exists for this edge_id, so it's safe to attempt on every call.
    //
    // The BBA is attributed to the SOURCE claim's agent_id ("A's author asserts
    // A SUPPORTS B"), NOT the caller — exactly as the HTTP wrapper
    // `trigger_edge_ds_recomputation` does. Resolved here via a runtime query
    // (no `query!` macro → zero .sqlx offline-data churn).
    let mut belief_wired = false;
    let source_agent_id: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
            .bind(source_id)
            .fetch_optional(pool)
            .await
            .map_err(internal_error)?;

    if let Some(agent_id) = source_agent_id {
        // Best-effort: a recompute error must not lose the durable edge.
        // `belief_wired` is true ONLY when the engine actually materialized
        // a BBA and recomputed the target (`Wired`). The other outcomes
        // (SourceFactorless / Vacuous / NonEpistemic / already-wired / None-on-error)
        // move no belief, so we honestly report `belief_wired=false`.
        // Direction caveat for SYMMETRIC relations in the factorless wake-up
        // case: the dedup may have returned the edge id of the OPPOSITE-
        // direction row, so a BBA materialized here under
        // `perspective_id = edge_id` can be derived from an interval on the
        // stored row's target rather than its source. Defensible for a relation
        // whose truth is unordered; recovering the stored direction would mean
        // widening `create_symmetric_if_absent_returning`'s return type.
        let outcome = auto_wire_edge_if_epistemic(
            pool,
            was_created,
            edge_id,
            source_id,
            "claim",
            target_id,
            "claim",
            &params.relationship,
            agent_id,
        )
        .await;
        belief_wired = matches!(outcome, Some(EdgeFactorOutcome::Wired));
    }

    if was_created {
        // Emit the durable `edge.added` event (best-effort; never fail the call
        // on a publish error). Actor = the MCP signer agent, mirroring
        // `emit_tool_invoked`'s actor resolution. Scoped to genuine creation
        // only — a re-assertion of an existing edge (including a wake-up
        // wire) must not re-emit `edge.added`.
        let actor_id = server.agent_id().await.ok();
        let _ = EventRepository::publish_or_log(
            pool,
            "edge.added",
            actor_id,
            &serde_json::json!({
                "edge_id": edge_id,
                "source_type": "claim",
                "source_id": source_id,
                "target_type": "claim",
                "target_id": target_id,
                "relationship": params.relationship,
            }),
        )
        .await;
    }

    // Best-effort readback of the target's cached DS columns — the ones the
    // recompute wrote (belief / plausibility / pignistic_prob). NOT the unframed
    // `belief_query::get_belief`, which reads `truth_value` and so would NOT
    // reflect the wire.
    let target_belief =
        match ClaimRepository::get_belief_columns(pool, ClaimId::from_uuid(target_id)).await {
            Ok(Some(cols)) => match (cols.belief, cols.plausibility, cols.pignistic_prob) {
                (Some(belief), Some(plausibility), Some(pignistic_prob)) => {
                    Some(LinkEpistemicBelief {
                        belief,
                        plausibility,
                        pignistic_prob,
                    })
                }
                // Claim with no BBA yet → NULL DS columns → belief not reportable.
                _ => None,
            },
            // Missing row: belief not reportable.
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(
                    target = %target_id,
                    error = ?e,
                    "link_epistemic: target belief readback failed (non-fatal)"
                );
                None
            }
        };

    success_json(&LinkEpistemicResponse {
        edge_id: edge_id.to_string(),
        was_created,
        relationship: params.relationship,
        belief_wired,
        target_belief,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_engine::sheaf::{
        restriction_kind_with_profile, RestrictionKind, RestrictionProfile,
    };

    /// Coverage guard (the most important test): EVERY exposed epistemic
    /// relationship must map to a NON-Neutral `RestrictionKind` under the
    /// default scientific profile — otherwise the tool would advertise a
    /// belief-affecting edge that is actually inert. Also catches drift if the
    /// engine's `restriction_kind_with_profile` mapping changes.
    ///
    /// We assert the engine mapping ONLY (not membership in
    /// `routes/edges.rs::VALID_RELATIONSHIPS`): that HTTP whitelist is
    /// UPPER-CASE and case-sensitive, so a membership check would spuriously
    /// fail on our lowercase canonical strings. The engine mapping is the real
    /// invariant that governs belief.
    #[test]
    fn every_epistemic_relationship_maps_to_non_neutral() {
        let profile = RestrictionProfile::scientific();
        for rel in EPISTEMIC_RELATIONSHIPS {
            let kind = restriction_kind_with_profile(rel, &profile);
            assert!(
                !matches!(kind, RestrictionKind::Neutral),
                "epistemic relationship '{rel}' maps to RestrictionKind::Neutral \
                 (inert) — it would not move belief; remove it from \
                 EPISTEMIC_RELATIONSHIPS or fix the engine mapping. Got: {kind:?}"
            );
        }
    }

    /// `cites` is a citation/provenance link, not an epistemic claim about the
    /// relationship between two nodes — it is DELIBERATELY `Neutral` (does not
    /// move belief). This is the mirror image of the coverage guard above:
    /// `cites` must NOT be added to `EPISTEMIC_RELATIONSHIPS` (that would break
    /// `every_epistemic_relationship_maps_to_non_neutral`'s all-non-Neutral
    /// invariant and its hard count=7 assertion), but `link_epistemic` must
    /// still accept it via the separate `STRUCTURAL_RELATIONSHIPS` allow-list
    /// so the conflict-resolution workflow's cites-edge pinning step can run
    /// MCP-natively (backlog 47afad2e).
    #[test]
    fn cites_is_structural_and_maps_to_neutral() {
        let profile = RestrictionProfile::scientific();
        assert!(
            is_structural_relationship("cites"),
            "'cites' must be accepted via STRUCTURAL_RELATIONSHIPS"
        );
        assert!(
            !is_epistemic_relationship("cites"),
            "'cites' must NOT be in EPISTEMIC_RELATIONSHIPS (it is Neutral by design, which \
             would break the all-non-Neutral coverage guard)"
        );
        assert!(
            matches!(
                restriction_kind_with_profile("cites", &profile),
                RestrictionKind::Neutral
            ),
            "'cites' must map to RestrictionKind::Neutral — a citation link is not an \
             epistemic claim and must not move belief"
        );
    }

    /// THE FORK, pinned as a unit test so it fails at `cargo test --lib` speed
    /// rather than only in the DB-backed fixture: `shifted_to` maps to
    /// `RestrictionKind::Neutral`, i.e. it moves NO belief (backlog 52eff3ab).
    ///
    /// "The throughput ceiling shifted from 400/s to 900/s" is not evidence
    /// that 400/s was ever false — it was true of an earlier world. A
    /// `Negative` mapping (the `contradicts` treatment) would retroactively
    /// falsify a correct historical measurement, which is exactly why
    /// succession is a separate relationship from contradiction.
    ///
    /// Neutral is the ENGINE DEFAULT for an unmapped string, so what this test
    /// really guards is the mirror of
    /// `every_epistemic_relationship_maps_to_non_neutral`: it fails the moment
    /// someone "fixes" the allow-list by appending `shifted_to` to
    /// `EPISTEMIC_RELATIONSHIPS` or teaches the engine a polarity for it.
    #[test]
    fn shifted_to_is_temporal_and_maps_to_neutral() {
        let profile = RestrictionProfile::scientific();
        assert!(
            is_temporal_relationship("shifted_to"),
            "'shifted_to' must be accepted via TEMPORAL_RELATIONSHIPS"
        );
        assert!(
            !is_epistemic_relationship("shifted_to"),
            "'shifted_to' must NOT be in EPISTEMIC_RELATIONSHIPS — succession is not \
             counter-evidence, and membership there would wire a mass function that \
             retroactively falsifies a correct historical measurement"
        );
        assert!(
            matches!(
                restriction_kind_with_profile("shifted_to", &profile),
                RestrictionKind::Neutral
            ),
            "'shifted_to' must map to RestrictionKind::Neutral — it licenses a retrieval \
             preference, not a belief update"
        );
    }

    /// The three allow-lists are pairwise DISJOINT, and every temporal relation
    /// is inert. A relation that appeared in two lists would have an ambiguous
    /// belief contract; one that appeared in the temporal list while mapping
    /// non-Neutral would move belief behind the caller's back.
    #[test]
    fn temporal_set_is_disjoint_and_inert() {
        let profile = RestrictionProfile::scientific();
        for rel in TEMPORAL_RELATIONSHIPS {
            assert!(
                !is_epistemic_relationship(rel),
                "'{rel}' is temporal and must not also be epistemic (the epistemic set is \
                 defined as the belief-affecting one)"
            );
            assert!(
                !is_structural_relationship(rel),
                "'{rel}' must belong to exactly one allow-list; temporal and structural are \
                 different claims about the world even though both are inert"
            );
            assert!(
                matches!(
                    restriction_kind_with_profile(rel, &profile),
                    RestrictionKind::Neutral
                ),
                "temporal relationship '{rel}' must be Neutral (inert) — it re-ranks \
                 retrieval, it does not move belief"
            );
        }
        for rel in STRUCTURAL_RELATIONSHIPS {
            assert!(
                !is_temporal_relationship(rel),
                "'{rel}' is structural and must not also be temporal"
            );
        }
    }

    /// Pin the polarity split from the spec §4 table: the five positive
    /// relationships strengthen the target (`Positive`), the two negative ones
    /// weaken it (`Negative`). This catches an accidental sign flip in the
    /// engine mapping that the bare non-Neutral guard would miss.
    #[test]
    fn epistemic_relationship_polarities_match_spec() {
        let profile = RestrictionProfile::scientific();
        for rel in [
            "supports",
            "corroborates",
            "elaborates",
            "generalizes",
            "specializes",
        ] {
            assert!(
                matches!(
                    restriction_kind_with_profile(rel, &profile),
                    RestrictionKind::Positive(_)
                ),
                "'{rel}' must be a Positive (strengthening) restriction"
            );
        }
        for rel in ["contradicts", "refutes"] {
            assert!(
                matches!(
                    restriction_kind_with_profile(rel, &profile),
                    RestrictionKind::Negative(_)
                ),
                "'{rel}' must be a Negative (weakening) restriction"
            );
        }
    }

    /// The 7-entry set is exactly the documented surface: no `supersedes`, no
    /// structural relationships, no duplicates.
    #[test]
    fn epistemic_set_is_the_documented_seven() {
        assert_eq!(
            EPISTEMIC_RELATIONSHIPS.len(),
            7,
            "EPISTEMIC_RELATIONSHIPS must be exactly the 7 documented relations"
        );
        assert!(
            !is_epistemic_relationship("supersedes"),
            "supersedes must NOT be exposed — it belongs to supersede_claim"
        );
        for structural in ["decomposes_to", "section_follows", "continues_argument"] {
            assert!(
                !is_epistemic_relationship(structural),
                "structural relationship '{structural}' must not be in the epistemic set"
            );
        }
        assert!(!is_epistemic_relationship("relates_to"));
        assert!(!is_epistemic_relationship(""));
        assert!(
            !is_epistemic_relationship("SUPPORTS"),
            "matcher is case-sensitive on the lowercase canonical form"
        );
    }

    /// The symmetric subset is exactly `{contradicts, corroborates}` — the two
    /// relations whose truth is unordered. Everything else stays on the
    /// directional writer, so widening this set silently changes dedup shape
    /// on the write path AND which endpoints the read path counts. A pure
    /// const-vs-const drift guard: it pins the shared definition, it does not
    /// exercise either path (that coverage is DB-backed, in
    /// `epigraph-db/tests/dispute_batch_test.rs`).
    #[test]
    fn symmetric_set_is_exactly_contradicts_and_corroborates() {
        assert_eq!(
            SYMMETRIC_RELATIONSHIPS.len(),
            2,
            "SYMMETRIC_RELATIONSHIPS must be exactly {{contradicts, corroborates}}"
        );
        assert!(is_symmetric_relationship("contradicts"));
        assert!(is_symmetric_relationship("corroborates"));
        for ordered in [
            "supports",
            "refutes",
            "elaborates",
            "generalizes",
            "specializes",
            "cites",
            "supersedes",
            "",
        ] {
            assert!(
                !is_symmetric_relationship(ordered),
                "'{ordered}' is ordered (or not epistemic) and must keep the directional writer"
            );
        }
        assert!(
            !is_symmetric_relationship("CONTRADICTS"),
            "both dedup predicates compare the relationship string byte-for-byte, so casing is \
             identity: the UPPERCASE DS variant is a DIFFERENT relationship. Mirrors the \
             lowercase-on-purpose note on `verifier::CONTRADICTS_RELATIONSHIP`."
        );
    }

    /// Drift guard: the symmetric and ordered subsets PARTITION the seven
    /// epistemic relations. Adding an eighth relationship without deciding its
    /// symmetry fails here rather than silently defaulting to directional —
    /// which now also decides whether the READ side counts it on one endpoint
    /// or both (`ClaimRepository::in_epistemic_degree_batch`).
    ///
    /// Subsumes the subset property too: every symmetric member must clear the
    /// epistemic allow-list gate in `do_link_epistemic` (and must not be a
    /// structural relation, which is Neutral by design), or it could never
    /// reach the write branch at all.
    #[test]
    fn directional_relationships_partition_the_epistemic_set() {
        const ORDERED: &[&str] = &[
            "supports",
            "elaborates",
            "generalizes",
            "specializes",
            "refutes",
        ];

        for rel in ORDERED {
            assert!(
                is_epistemic_relationship(rel),
                "ordered relation '{rel}' must be in EPISTEMIC_RELATIONSHIPS"
            );
            assert!(
                !is_symmetric_relationship(rel),
                "ordered relation '{rel}' must not also be symmetric (subsets must be disjoint)"
            );
        }
        for rel in EPISTEMIC_RELATIONSHIPS {
            assert!(
                is_symmetric_relationship(rel) || ORDERED.contains(rel),
                "'{rel}' is in EPISTEMIC_RELATIONSHIPS but is neither symmetric nor listed as \
                 ordered — decide its dedup shape before exposing it"
            );
        }
        for rel in SYMMETRIC_RELATIONSHIPS {
            assert!(
                is_epistemic_relationship(rel),
                "'{rel}' routes through the symmetric writer but is not in \
                 EPISTEMIC_RELATIONSHIPS — it could never reach the write branch"
            );
            assert!(
                !is_structural_relationship(rel),
                "'{rel}' must not also be structural (structural relations are Neutral)"
            );
            assert!(
                !is_temporal_relationship(rel),
                "'{rel}' must not also be temporal: succession is ORDERED and keeps the \
                 DIRECTIONAL writer, backed by the anti-symmetric pair index \
                 `edges_shifted_to_pair_uniq` (migration 060). Routing it through the \
                 symmetric writer would silently accept the REVERSED assertion as the same \
                 fact, when it is that fact's temporal contradiction."
            );
        }
        assert_eq!(
            SYMMETRIC_RELATIONSHIPS.len() + ORDERED.len(),
            EPISTEMIC_RELATIONSHIPS.len(),
            "the two subsets must exactly cover the epistemic set with no overlap"
        );
    }
}
