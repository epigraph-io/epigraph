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
//! - `relationship` must be one of [`EPISTEMIC_RELATIONSHIPS`] or
//!   [`STRUCTURAL_RELATIONSHIPS`] (lowercase canonical strings; `supersedes`
//!   is intentionally excluded — it has dedicated semantics in
//!   `supersede_claim`). The structural set (currently just `cites`) is kept
//!   separate because its members map to `RestrictionKind::Neutral` by
//!   design — belief-wiring already no-ops on Neutral, so accepting them
//!   here just lets citation/provenance edges be created MCP-natively
//!   without a doomed detour through the raw HTTP edges route.
//! - idempotent on `(source, target, relationship)` — and for the SYMMETRIC
//!   relationships (`contradicts`, `corroborates`, see
//!   [`SYMMETRIC_RELATIONSHIPS`]) on the UNORDERED pair, so filing one in both
//!   directions yields one row rather than two descriptions of one fact. A
//!   re-hit returns the existing edge with `was_created=false` and never
//!   re-creates the durable edge row or re-emits `edge.added`. On a symmetric
//!   re-hit against the reverse direction the response's
//!   `belief_target_claim_id` is the caller's SOURCE, because both the wire and
//!   the belief readback follow the row's stored orientation rather than the
//!   caller's argument order. Belief wiring, however, is NOT gated
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

/// The subset of [`EPISTEMIC_RELATIONSHIPS`] that is SEMANTICALLY SYMMETRIC:
/// "A contradicts B" and "B contradicts A" are the same fact about the same
/// pair, as are the two orderings of `corroborates`. Edges for these are
/// deduped in BOTH directions via
/// [`EdgeRepository::create_symmetric_if_absent_oriented`]; everything else
/// keeps the directional `create_if_not_exists` path.
///
/// Why it matters (backlog 9a0bd3e2): `link_epistemic` wrote every
/// relationship through the directional repo, so an agent filing `contradicts`
/// in both orders produced two `edges` rows for one disagreement. Every
/// conflict-density measure counts rows — `silence_alarm`'s
/// `check_conflict_density` included — so one dispute read as two.
///
/// The five excluded epistemic relations are genuinely directional and MUST
/// NOT be added here: `supports`, `elaborates`, `generalizes`, `specializes`
/// and `refutes` all assert something about `source` that is false of
/// `target` (A generalizes B is not B generalizes A), and collapsing their
/// orderings would erase real information rather than a duplicate.
///
/// **Casing caveat.** Dedup is a byte-exact `relationship = $3` comparison.
/// The cross-source matcher writes `CORROBORATES` (upper) and `contradicts`
/// (lower) — see `epigraph_engine::matching::verifier`'s two relationship
/// constants. So listing lowercase `corroborates` here collapses the two call
/// ORDERS of `link_epistemic`'s own `corroborates`; it does NOT unify a
/// `link_epistemic` `corroborates` with a matcher-written `CORROBORATES`.
/// That casing split is pre-existing and out of scope here.
pub const SYMMETRIC_RELATIONSHIPS: &[&str] = &["contradicts", "corroborates"];

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
    viewer: &epigraph_db::visibility::Viewer,
    params: LinkEpistemicParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    do_link_epistemic(server, viewer, params, auth).await
}

/// Core logic factored out so integration tests can call it directly without
/// round-tripping through the rmcp dispatch layer (mirrors
/// `do_link_hierarchical`).
pub async fn do_link_epistemic(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: LinkEpistemicParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let source_id = parse_uuid(&params.source_claim_id)?;
    let target_id = parse_uuid(&params.target_claim_id)?;

    // Tight allow-list — lowercase canonical epistemic relations, plus the
    // separate structural set (currently just `cites`; see
    // STRUCTURAL_RELATIONSHIPS doc comment for why it isn't folded into
    // EPISTEMIC_RELATIONSHIPS).
    if !is_epistemic_relationship(&params.relationship)
        && !is_structural_relationship(&params.relationship)
    {
        return Err(invalid_params(format!(
            "invalid relationship '{}'. Valid epistemic types: {}. Valid structural types: {}",
            params.relationship,
            EPISTEMIC_RELATIONSHIPS.join(", "),
            STRUCTURAL_RELATIONSHIPS.join(", "),
        )));
    }

    // No self-loops — both endpoints are claims so equal UUIDs always loop.
    if source_id == target_id {
        return Err(invalid_params(
            "self-loops are not allowed (source and target are the same claim)",
        ));
    }

    // ONE TRANSACTION, STAMPED FROM THE WRITE IDENTITY (the caller over HTTP, the server's own agent on stdio; batch H-b D1). The existence
    // reads, the edge, the belief wiring, the `edge.added` event and the belief
    // readback all run on it, and it commits once.
    //
    // It used to be three units: the edge INSERT on the unstamped pool, the
    // belief wiring on its own stamped transaction, and the event on the pool
    // again. The edge on the unstamped pool was admitted only when world-owned
    // (two PUBLIC endpoints, which 070's BEFORE trigger makes world-owned). An
    // edge touching a group-private claim is owned by that claim's group and was
    // refused on a cleanly-migrated schema. Production admitted it only through
    // the orphan `edges_privacy` policy that R3 drops. The existence reads on the
    // pool could not see a group-private endpoint at all, so that population never
    // reached the INSERT. Both halves move.
    //
    // THE BELIEF WIRING STAYS BEST-EFFORT, and it does so inside a SAVEPOINT, not
    // by swallowing an error in this transaction. `claim_frames` and
    // `mass_functions` take their tenancy from the TARGET claim, so an epistemic
    // edge into a claim this agent's group cannot write is refused at the wiring.
    // Unsavepointed, that refusal would abort the edge's transaction and turn
    // COMMIT into a silent ROLLBACK. The edge lands on the production schema
    // today, so that would be a regression there. The savepoint is committed only
    // when a BBA was actually materialized (`Wired`) and rolled back on every
    // other outcome. That keeps the old contract: `belief_wired` and the committed
    // state cannot disagree.
    //
    // THE STAMP IS THE WRITE IDENTITY's (`EpiGraphMcpFull::write_identity`), as for every other MCP write. An
    // endpoint in another agent's private group is refused loudly by the edge's
    // WITH CHECK, or for a co-owned edge by RETURNING's intersection read, and
    // nothing is written. Whether a caller should carry write authority into a
    // group this process cannot write is the cross-agent ownership question
    // (#374), not a stamping one.
    let actor = server.write_identity(auth, viewer).await?;
    let actor_id = actor.agent_id();
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, actor, "link_epistemic").await?;

    // Verify both claims exist via the repo layer (SQL stays in epigraph-db).
    // Disambiguate which side is missing.
    if ClaimRepository::get_by_id(&mut *tx, viewer, ClaimId::from_uuid(source_id))
        .await
        .map_err(internal_error)?
        .is_none()
    {
        return Err(invalid_params(format!(
            "source_claim_id {source_id} not found"
        )));
    }
    if ClaimRepository::get_by_id(&mut *tx, viewer, ClaimId::from_uuid(target_id))
        .await
        .map_err(internal_error)?
        .is_none()
    {
        return Err(invalid_params(format!(
            "target_claim_id {target_id} not found"
        )));
    }

    // Symmetric relationships (`contradicts`, `corroborates`) dedup in BOTH
    // directions, so the two call orders collapse to ONE row; everything else
    // keeps the directional `(source, target, relationship)` idempotency.
    // See `SYMMETRIC_RELATIONSHIPS`.
    //
    // `wire_source` / `wire_target` are the endpoints AS STORED on the
    // surviving row. They differ from the caller's `(source_id, target_id)`
    // in exactly one case — a symmetric dedup hit against the reverse
    // direction — and the belief wiring below must follow the row, not the
    // caller: the BBA is keyed on `edge_id`, so materializing the caller's
    // direction onto a row recording the opposite one would attach a factor
    // the row does not describe.
    let (edge_id, was_created, wire_source, wire_target) =
        if is_symmetric_relationship(&params.relationship) {
            let upsert = EdgeRepository::create_symmetric_if_absent_oriented_conn(
                &mut tx,
                source_id,
                target_id,
                &params.relationship,
                params.properties.clone().unwrap_or(serde_json::json!({})),
            )
            .await
            .map_err(internal_error)?;
            (
                upsert.edge_id,
                upsert.was_created,
                upsert.source_id,
                upsert.target_id,
            )
        } else {
            let (edge_row, was_created) = EdgeRepository::create_if_not_exists_conn(
                &mut tx,
                source_id,
                "claim",
                target_id,
                "claim",
                &params.relationship,
                params.properties.clone(),
                None,
                None,
            )
            .await
            .map_err(internal_error)?;
            (edge_row.id, was_created, source_id, target_id)
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
    let source_agent_id: Option<uuid::Uuid> = {
        // PR-09: an authorship oracle over a uuid that derives from caller
        // input — it names the `agents.id` behind any claim. Filtered rather
        // than exempted; `fetch_optional` already handles "no row", so an
        // invisible source simply skips the best-effort belief recompute.
        //
        // Bound on `wire_source`, NOT the caller's `source_id`: after a
        // symmetric dedup hit the surviving row records the reverse
        // orientation, and the BBA is keyed on that row's `edge_id`. Attributing
        // it to the caller's direction would name an author the row does not
        // describe. Both endpoints were viewer-checked above, so following the
        // row cannot widen what this read can see.
        let sql = viewer.splice(
            "SELECT c.agent_id FROM claims c \
                 WHERE c.id = $1 /* {VISIBILITY:c} */",
            2,
        );
        let mut q = sqlx::query_scalar(&sql).bind(wire_source);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        q.fetch_optional(&mut *tx).await.map_err(internal_error)?
    };

    if let Some(agent_id) = source_agent_id {
        // Best-effort: a wiring error must not lose the durable edge.
        // `belief_wired` is true ONLY when the engine actually materialized
        // a BBA and recomputed the target (`Wired`). The other outcomes
        // (SourceFactorless / Vacuous / NonEpistemic / already-wired / None-on-error)
        // move no belief, so we honestly report `belief_wired=false`.
        //
        // The wiring writes `claim_frames`, `mass_functions` and an
        // `UPDATE claims` on the TARGET. Those tables are CLAIM-DERIVED, so
        // migration 074/070 fill their tenancy from the TARGET claim and the
        // `WITH CHECK` asks about the target's group, not the caller's and not
        // the source author's (which is what the BBA is ATTRIBUTED to, a
        // different question). An epistemic edge into another group's claim
        // therefore moves no belief. `tools/ds.rs` and `tools/claims.rs`
        // (`update_with_evidence`) carry the same residual, and
        // `epigraph-db/tests/tool_write_tables_require_a_stamp.rs` pins the pair.
        use sqlx::Acquire as _;
        let mut sp = tx.begin().await.map_err(internal_error)?;
        let outcome = auto_wire_edge_if_epistemic(
            &mut sp,
            viewer,
            was_created,
            edge_id,
            wire_source,
            "claim",
            wire_target,
            "claim",
            &params.relationship,
            agent_id,
        )
        .await;
        // Release the savepoint only when a BBA was actually materialized. On
        // every other outcome it is rolled back, so a partial wiring is never
        // left behind and the `Wired` verdict and the committed state cannot
        // disagree.
        if matches!(outcome, Some(EdgeFactorOutcome::Wired)) {
            sp.commit().await.map_err(internal_error)?;
            belief_wired = true;
        } else {
            sp.rollback().await.map_err(internal_error)?;
        }
    }

    if was_created {
        // Emit the durable `edge.added` event on the SAME transaction. It is
        // SAVEPOINT-wrapped inside `publish_or_log_conn`, so a refused event
        // cannot abort the edge, and it shares the edge's fate: there is no
        // `edge.added` for an edge that was rolled back. Actor = the MCP
        // signer agent, mirroring `emit_tool_invoked`'s actor resolution.
        // Scoped to genuine creation only — a re-assertion of an existing edge
        // (including a wake-up wire) must not re-emit `edge.added`.
        let _ = EventRepository::publish_or_log_conn(
            &mut tx,
            "edge.added",
            Some(actor_id),
            &serde_json::json!({
                "edge_id": edge_id,
                "source_type": "claim",
                "source_id": wire_source,
                "target_type": "claim",
                "target_id": wire_target,
                "relationship": params.relationship,
            }),
        )
        .await;
    }

    // Best-effort readback of the target's cached DS columns — the ones the
    // recompute wrote (belief / plausibility / pignistic_prob). NOT the unframed
    // `belief_query::get_belief`, which reads `truth_value` and so would NOT
    // reflect the wire.
    //
    // Keyed on `wire_target`, the claim the recompute actually touched, which
    // on a reverse symmetric dedup hit is the caller's SOURCE. The response
    // echoes it as `belief_target_claim_id` so the caller never has to guess
    // which claim the interval belongs to.
    //
    // Inside the transaction, before COMMIT, and under a SAVEPOINT because the
    // failure is swallowed: this read sees exactly what the wiring above wrote,
    // and a failed read cannot abort the edge.
    let target_belief = {
        use sqlx::Acquire as _;
        let mut sp = tx.begin().await.map_err(internal_error)?;
        let read =
            ClaimRepository::get_belief_columns(&mut *sp, viewer, ClaimId::from_uuid(wire_target))
                .await;
        sp.rollback().await.map_err(internal_error)?;
        match read {
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
                    target = %wire_target,
                    error = ?e,
                    "link_epistemic: target belief readback failed (non-fatal)"
                );
                None
            }
        }
    };

    tx.commit().await.map_err(internal_error)?;

    success_json(&LinkEpistemicResponse {
        edge_id: edge_id.to_string(),
        was_created,
        relationship: params.relationship,
        belief_wired,
        belief_target_claim_id: wire_target.to_string(),
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
}
