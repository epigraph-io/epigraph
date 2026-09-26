#![allow(clippy::wildcard_imports)]

use std::collections::BTreeSet;

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

use epigraph_db::{
    DivergenceRepository, FrameRepository, MassFunctionRepository, ScopedBeliefRepository,
};
use epigraph_ds::{combination, CombinationMethod, FocalElement, FrameOfDiscernment, MassFunction};

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

fn parse_combination_method(s: &str) -> Result<CombinationMethod, String> {
    match s.to_lowercase().as_str() {
        "dempster" => Ok(CombinationMethod::Dempster),
        "conjunctive" | "tbm" => Ok(CombinationMethod::Conjunctive),
        "yageropen" | "yager_open" => Ok(CombinationMethod::YagerOpen),
        "yagerclosed" | "yager_closed" => Ok(CombinationMethod::YagerClosed),
        "duboisprade" | "dubois_prade" => Ok(CombinationMethod::DuboisPrade),
        "inagaki" => Ok(CombinationMethod::Inagaki),
        other => Err(format!("unknown combination method: {other}. Options: Dempster, Conjunctive, YagerOpen, YagerClosed, DuboisPrade, Inagaki")),
    }
}

/// Parse mass JSON into a `MassFunction` using epigraph-ds's built-in parser.
fn parse_masses_json(
    frame: &FrameOfDiscernment,
    masses_json: &serde_json::Value,
) -> Result<MassFunction, McpError> {
    MassFunction::from_json_masses(frame.clone(), masses_json)
        .map_err(|e| invalid_params(format!("invalid mass function: {e}")))
}

/// Apply combination method to two mass functions via `redistribute()`.
fn combine_two(
    m1: &MassFunction,
    m2: &MassFunction,
    method: CombinationMethod,
    gamma: Option<f64>,
) -> Result<MassFunction, McpError> {
    combination::redistribute(m1, m2, method, gamma).map_err(internal_error)
}

pub async fn create_frame(
    server: &EpiGraphMcpFull,
    params: CreateFrameParams,
) -> Result<CallToolResult, McpError> {
    if params.hypotheses.len() < 2 {
        return Err(invalid_params("frame requires at least 2 hypotheses"));
    }

    // Check if parent is specified and valid
    if let Some(ref parent_id_str) = params.parent_frame_id {
        let parent_id = parse_uuid(parent_id_str)?;
        let frame = FrameRepository::create_refinement(
            &server.pool,
            parent_id,
            &params.name,
            params.description.as_deref(),
            &params.hypotheses,
        )
        .await
        .map_err(internal_error)?;

        return success_json(&CreateFrameResponse {
            frame_id: frame.id.to_string(),
            name: frame.name,
            hypotheses: frame.hypotheses,
            version: frame.version,
        });
    }

    let frame = FrameRepository::create(
        &server.pool,
        &params.name,
        params.description.as_deref(),
        &params.hypotheses,
    )
    .await
    .map_err(internal_error)?;

    success_json(&CreateFrameResponse {
        frame_id: frame.id.to_string(),
        name: frame.name,
        hypotheses: frame.hypotheses,
        version: frame.version,
    })
}

pub async fn submit_ds_evidence(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: SubmitDsEvidenceParams,
) -> Result<CallToolResult, McpError> {
    let claim_id = parse_uuid(&params.claim_id)?;
    let frame_id = parse_uuid(&params.frame_id)?;
    let perspective_id = match &params.perspective_id {
        Some(s) => Some(parse_uuid(s)?),
        None => None,
    };

    let method = params
        .combination_method
        .as_deref()
        .map(parse_combination_method)
        .transpose()
        .map_err(invalid_params)?
        .unwrap_or(CombinationMethod::Dempster);
    let method_name = format!("{method:?}");

    // Backlog 82dcff9d (G5): both parameters are deprecated — accepted, and
    // `combination_method` stored, but neither reaches the belief (see the
    // recompute below). A caller who sends a non-default value believes it
    // does something, so the response says it did not.
    let mut warnings = deprecated_parameter_warnings(method, params.gamma);

    // Get frame from DB
    let frame_row = FrameRepository::get_by_id(&server.pool, viewer, frame_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("frame {frame_id} not found")))?;

    let frame = FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone())
        .map_err(internal_error)?;

    // Backlog 45cbaef4 (G6): an index that names none of the frame's
    // hypotheses is stored as given (the column is an unconstrained integer, and
    // refusing would change a call that used to succeed), but every belief
    // reader resolves it to 0 through `edge_factor::resolve_hypothesis_index`.
    // Say so rather than let the caller believe it addressed that hypothesis.
    let resolved_index = epigraph_engine::edge_factor::resolve_hypothesis_index(
        Some(params.hypothesis_index),
        frame.hypothesis_count(),
    );
    if usize::try_from(params.hypothesis_index).ok() != Some(resolved_index) {
        warnings.push(format!(
            "hypothesis_index={} names none of this frame's {} hypotheses (valid: 0..={}); it \
             was stored as given, but every belief read, including the belief returned here, \
             is about hypothesis 0 ({:?}).",
            params.hypothesis_index,
            frame.hypothesis_count(),
            frame.hypothesis_count().saturating_sub(1),
            frame_row
                .hypotheses
                .first()
                .map(String::as_str)
                .unwrap_or_default(),
        ));
    }

    // Parse the mass function. Reliability handling forks on whether the
    // caller opted into calibrated per-source-class discounting:
    //
    // - `evidence_type` supplied: store the RAW (undiscounted) masses plus
    //   the resolved `evidence_type`/`locality_tag` metadata, and let the
    //   existing shared recompute path below
    //   (`recompute_claim_belief_on_frame` -> `recompute_combined_belief` ->
    //   `epigraph_engine::edge_factor::effective_source_strength`) derive
    //   the calibrated discount from that metadata + `calibration.toml`
    //   ([evidence_type_weights], locality composition) at combine time —
    //   the same discount authority `auto_wire_ds_update` already uses
    //   (issue #197 Phase 2/4). We must NOT also pre-discount here: this
    //   function already reads its returned belief back from the `claims`
    //   row *after* delegating to that same recompute path (backlog
    //   2bffdfdc), so a pre-discount would double-apply the calibrated
    //   weight (e.g. testimonial 0.6 x 0.6 = 0.36) while `params.reliability`
    //   is simply ignored in favor of the calibrated prior.
    // - `evidence_type` omitted (default): EXACT pre-change behavior —
    //   pre-discount the stored masses by the raw `params.reliability`
    //   float and store `evidence_type = NULL`, `locality_tag = "unknown"`,
    //   so `effective_source_strength` falls through to its legacy/unknown
    //   tiers exactly as it did before this change. `locality_tag` alone
    //   (without `evidence_type`) is a no-op for the same reason: step (1)
    //   of `effective_source_strength` fires whenever `evidence_type` is
    //   `None` and never reaches locality composition, so we fold that case
    //   into the legacy branch too rather than silently accepting a
    //   parameter that couldn't affect anything.
    let mut mass_fn = parse_masses_json(&frame, &params.masses)?;
    let calibrated_evidence_type = params.evidence_type.as_deref().filter(|s| !s.is_empty());

    // Backlog 86ee2d30 (G12): an `evidence_type` outside the vocabulary the
    // recompute resolves is ACCEPTED and silently combined at the 0.5
    // unknown-type weight (`effective_source_strength`'s last tier: this path
    // stores no `source_strength`). Report it, never refuse it — the vocabulary
    // is operator-extensible and a new key may be deliberate.
    let unknown_keys = match calibrated_evidence_type {
        Some(et) if !evidence_type_resolves(server, frame_id, et).await => {
            warnings.push(format!(
                "evidence_type={et:?} is not in the calibration vocabulary \
                 (calibration.toml [evidence_type_weights] keys or [evidence_type_aliases]) and \
                 has no entry in this frame's evidence_type_weights override, so this BBA is \
                 combined at the 0.5 unknown-type reliability. Known keys: {}.",
                known_evidence_type_keys().join(", ")
            ));
            vec![et.to_string()]
        }
        _ => Vec::new(),
    };
    let stored_locality_tag = if calibrated_evidence_type.is_some() {
        params.locality_tag.as_deref().unwrap_or("unknown")
    } else {
        "unknown"
    };
    if calibrated_evidence_type.is_none() {
        let reliability = params.reliability.unwrap_or(1.0).clamp(0.0, 1.0);
        if reliability < 1.0 {
            mass_fn = epigraph_ds::combination::discount(&mass_fn, reliability)
                .map_err(internal_error)?;
        }
    }

    let agent_id = server.agent_id().await?;

    let masses_json = serde_json::to_value(
        mass_fn
            .masses()
            .iter()
            .map(|(fe, m)| (focal_to_key(fe), *m))
            .collect::<std::collections::HashMap<String, f64>>(),
    )
    .map_err(internal_error)?;

    // ── THE TWO TIER-A WRITES AND THE RECOMPUTE, IN ONE STAMPED TRANSACTION ──
    //
    // `claim_frames` and `mass_functions` both carry migration 077's strict
    // `WITH CHECK (owner_group_id = ANY(epigraph_writable_groups()))` and neither
    // has an orphan `*_privacy` policy to fall back on, so on the unstamped pool
    // this tool was refused with `42501` on its FIRST write — MEASURED on both
    // schema configurations, `new row violates row-level security policy for
    // table "claim_frames"`. That is also why `mass_functions` stayed 0 through
    // every e2e run.
    //
    // The two belong together: a `claim_frames` assignment with no BBA is a frame
    // membership that moves no belief, and a BBA whose claim is not assigned to
    // the frame is unreachable from `recompute_claim_belief_on_frame`'s own
    // enumeration. Before this they were two pool checkouts and therefore two
    // tenancy contexts.
    //
    // THE RECOMPUTE BELOW IS IN THE SAME TRANSACTION, and so is the commit. That
    // makes the whole tool one unit: `claim_frames`, `mass_functions` and the
    // claim's cached `belief`/`plausibility`/`pignistic_prob` either all land or
    // none do (see the note at the recompute call for where it used to stop).
    //
    // HISTORY, kept short. An earlier revision of this block converted only the
    // two writes above and left the recompute on `epigraph_engine::edge_factor`'s
    // pool-bound DS machinery. On a cleanly-migrated schema the tool then
    // committed `claim_frames` + `mass_functions` and failed afterwards at the
    // recompute's `UPDATE claims`, leaving the cached belief stale behind an error
    // response. The only repair for that window was out-of-band
    // (`epigraph-cli recompute_claim_belief` on `MaintenancePool::connect`),
    // because the in-band `recompute_beliefs` tool was then hard-disabled (it now
    // runs on the maintenance connection, batch H1). D2 moved the recompute onto
    // this connection, so that window no longer exists and there is nothing to
    // repair.
    //
    // Retry-safety is still worth recording, though it no longer carries a
    // committed-partial argument. `assign_claim` is `ON CONFLICT … DO UPDATE` and
    // `store_with_perspective` upserts on
    // `(claim_id, frame_id, source_agent_id, perspective_id)`, so a repeat call
    // re-states the same BBA rather than combining its mass twice.
    //
    // AND IT SUCCEEDS ONLY FOR CLAIMS THIS SERVER'S GROUP OWNS. Stated here because
    // "the whole tool is one unit that lands" is true only of that case, and the
    // reported e2e arm was run on the agent's own claim. `claim_frames` and
    // `mass_functions` are CLAIM-DERIVED: migration 074's
    // `epigraph_derived_require_tenancy` fills `(visibility, owner_group_id)` from
    // the parent claim and 070 arm (c) re-stamps it, so the `WITH CHECK` asks about
    // the CLAIM's group, not the evidence author's. The stamp here carries
    // `server.agent_id()`'s writable set, so a BBA against ANOTHER group's claim is
    // still refused on a cleanly-migrated schema. `tools/challenges.rs` states the
    // same residual for `challenge_claim` in its doc header, and
    // `epigraph-db/tests/tool_write_tables_require_a_stamp.rs::
    // a_challenge_against_a_foreign_groups_claim_is_still_refused` pins it on the
    // non-bypassing role. `tools/claims.rs::update_with_evidence` has the same shape
    // for the same reason. Whether an admin scope should carry write authority into
    // a group it is not a member of is a tenancy-model decision, not a bug here.
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, agent_id, "submit_ds_evidence")
            .await?;

    FrameRepository::assign_claim(&mut *tx, claim_id, frame_id, Some(params.hypothesis_index))
        .await
        .map_err(internal_error)?;

    // source_strength stays NULL either way: the calibrated path derives
    // reliability dynamically from evidence_type at recompute time
    // (effective_source_strength), and the legacy path already baked the
    // raw `reliability` float into the pre-discounted masses above rather
    // than caching it here — unchanged from pre-change behavior.
    let mf_id = MassFunctionRepository::store_with_perspective(
        &mut *tx,
        claim_id,
        frame_id,
        Some(agent_id),
        perspective_id,
        &masses_json,
        None,
        Some(&method_name),
        None,
        calibrated_evidence_type, // NULL unless caller opted in (backlog a2b71568)
        stored_locality_tag,      // "unknown" unless evidence_type was also supplied
        None, // manual DS submission has no evidence row in scope (issue #197 Phase 3)
    )
    .await
    .map_err(internal_error)?;

    // Count stored BBAs for the response (bba_count is informational only).
    // Read INSIDE the transaction so it counts the row just stored rather than
    // whatever a sibling connection can see.
    let bba_count =
        MassFunctionRepository::get_for_claim_frame(&mut *tx, viewer, claim_id, frame_id)
            .await
            .map_err(internal_error)?
            .len();

    // Combine + persist the claim's cached belief via the SAME code path
    // `recompute_beliefs` uses (`recompute_claim_belief_on_frame` ->
    // `recompute_combined_belief`), instead of re-deriving it here with a
    // second, divergent implementation. Backlog 2bffdfdc: the old inline
    // combine here used raw stored masses with no dynamic reliability
    // discount and a fixed-method pairwise loop, while `recompute_beliefs`
    // applies the issue-197 discount chain and adaptive rule selection —
    // same BBA rows, two different answers. Delegating here makes the two
    // tools compute identically by construction.
    //
    // `params.combination_method` and `params.gamma` do not influence the
    // stored/returned belief: the shared recompute always resolves the method
    // adaptively (via `combine_multiple`). This is the accepted consequence of
    // unification; both are deprecated and warned about (backlog 82dcff9d).
    //
    // `params.hypothesis_index` DOES: it is stored in `claim_frames` just above,
    // and the recompute's `edge_factor::resolve_hypothesis_index` reads it back,
    // as every framed belief read does (backlog 45cbaef4). A value outside the
    // frame is stored as given but read as 0 by all of them; see the warning
    // pushed where the frame is loaded. (This comment used to say the recompute
    // always targets index 0. It has not since the cache writer started reading
    // the stored index.)
    //
    // IT RUNS INSIDE THE SAME TRANSACTION, and the commit moved below it. Its
    // `UPDATE claims SET belief/plausibility/pignistic_prob` is where
    // `submit_ds_evidence` STOPPED on a cleanly-migrated schema: the statement
    // ran on the unstamped pool, where `claims_tenancy`'s `WITH CHECK` refuses
    // it. Errors here are propagated (DS is the primary belief authority on this
    // path), so on the old shape a refusal returned an error with the BBA already
    // committed and the claim's cached belief still describing the evidence
    // before it — success-shaped state behind a failure-shaped response. Now the
    // BBA and the belief it implies are one unit.
    epigraph_engine::edge_factor::recompute_claim_belief_on_frame(
        &mut tx, viewer, claim_id, frame_id,
    )
    .await
    .map_err(internal_error)?;

    // Read back exactly what the shared recompute path just wrote, so the
    // response can never drift from what a later `recompute_beliefs` call
    // (with no new evidence) would produce.
    //
    // ON THE WRITE TRANSACTION, BEFORE THE COMMIT (backlog F3, `15c00c7a`).
    // This read used to run after `tx.commit()`, on `server.pool`, so every way
    // it could fail — the claim invisible to the request viewer below, or
    // invisible to the pool's UNSTAMPED `epigraph_app` connection, which hides
    // every `group`-visibility row — returned an error for a frame assignment,
    // BBA and recomputed belief that had already committed. The description's
    // contract is "a refusal … writes nothing", so the read that can refuse now
    // runs where a refusal still rolls everything back: `?` below drops `tx`
    // uncommitted. MEASURED before the move
    // (`tests/ds_evidence_no_error_after_commit.rs`): the server agent's OWN
    // group-private claim on an `epigraph_app` pool answered "claim … not
    // found" with 1 BBA and 1 `claim_frames` row committed, and so did a
    // request viewer that cannot read the claim. On the transaction the read
    // sees what the author's stamp sees, which is the row it just updated.
    let (belief, plausibility, mass_on_empty, pignistic_prob, mass_on_missing): (
        f64,
        f64,
        f64,
        Option<f64>,
        f64,
    ) = {
        // PR-09: this is a per-id belief oracle over a caller-supplied uuid —
        // it returns the BetP and mass distribution of any claim in the corpus.
        // Filtered rather than exempted: the id comes from the request, so an
        // unfiltered read here answers "what does this private claim believe?"
        // for anyone who can guess an id. `fetch_optional` + the not-found
        // branch below make an invisible claim indistinguishable from a
        // nonexistent one (plan §8.5).
        //
        // NOTE that this refusal is DIFFERENT IN KIND from the other three
        // per-id oracles PR-09 hardened. `ds_auto.rs`, `link_epistemic.rs` and
        // `workflows.rs` all DEGRADE when the row is invisible (no prior, skip
        // the best-effort recompute, skip the cascade child) and leave the
        // write-half question to PR-16. This one aborts the whole call, so it
        // DOES decide the write half for `submit_ds_evidence`: a viewer that
        // cannot read the claim cannot submit evidence against it. That is the
        // right answer under D3 — you may not assert about what you may not
        // read — but it is a decision, not a side effect, and the ledger's
        // D-PR16-per-id-claim-oracles-write-half is scoped to the other three
        // for that reason.
        //
        // Reachable today, independently of PR-12: a caller passing a
        // NONEXISTENT claim_id now gets `invalid_request` where the previous
        // `fetch_one` gave `RowNotFound` -> internal_error. Strictly better,
        // and recorded in the PR-09 ledger's behaviour_changes.
        let sql = viewer.splice(
            "SELECT belief, plausibility, mass_on_empty, pignistic_prob, mass_on_missing
             FROM claims c WHERE c.id = $1 /* {VISIBILITY:c} */",
            2,
        );
        let mut q = sqlx::query_as(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        q.fetch_optional(&mut *tx)
            .await
            .map_err(internal_error)?
            .ok_or_else(|| {
                rmcp::model::ErrorData::invalid_request(format!("claim {claim_id} not found"), None)
            })?
    };

    tx.commit().await.map_err(internal_error)?;

    let betp = pignistic_prob.unwrap_or(0.0);
    let ign = plausibility - belief;

    success_json(&DsEvidenceResponse {
        mass_function_id: mf_id.to_string(),
        claim_id: claim_id.to_string(),
        frame_id: frame_id.to_string(),
        belief,
        plausibility,
        ignorance: ign,
        pignistic_prob: betp,
        mass_on_conflict: mass_on_empty,
        mass_on_missing,
        bba_count: bba_count as i64,
        method_used: method_name,
        warnings,
        unknown_keys,
    })
}

/// The calibration the belief recompute itself uses — same loader, same
/// fallback as `edge_factor::compute_combined_belief` — so a vocabulary
/// verdict here agrees with what the combine will actually do.
fn recompute_calibration() -> epigraph_engine::calibration::CalibrationConfig {
    epigraph_engine::calibration::CalibrationConfig::from_workspace_root().unwrap_or_else(|_| {
        epigraph_engine::calibration::CalibrationConfig::default_for_phase2_fallback()
    })
}

/// Every evidence-type key the calibration resolves (canonical keys and
/// aliases), sorted — what a caller told its key is unknown needs to see.
pub(crate) fn known_evidence_type_keys() -> Vec<String> {
    let c = recompute_calibration();
    let mut keys: Vec<String> = c
        .evidence_type_weights
        .keys()
        .chain(c.evidence_type_aliases.keys())
        .cloned()
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// Would the recompute resolve `evidence_type` to a real weight for a BBA on
/// `frame_id` rather than the 0.5 unknown-type fallback? True when it is in the
/// engine's vocabulary ([`epigraph_engine::edge_factor::is_known_evidence_type_key`])
/// or the frame's own strict-key `evidence_type_weights` override names it
/// (Tier 1 of `effective_source_strength`).
///
/// The override read is `VISIBILITY-EXEMPT` at the repo; it is spent here only
/// on a frame this caller already read through its viewer, and only as a
/// yes/no about the caller's own key. A failed read counts as "no override",
/// matching the recompute's own `.ok().flatten()`.
async fn evidence_type_resolves(server: &EpiGraphMcpFull, frame_id: uuid::Uuid, et: &str) -> bool {
    if epigraph_engine::edge_factor::is_known_evidence_type_key(et, &recompute_calibration()) {
        return true;
    }
    FrameRepository::get_per_frame_evidence_type_weights(&server.pool, frame_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|m| m.contains_key(&et.to_lowercase()))
}

/// The `warnings` a `submit_ds_evidence` call earns by sending a deprecated
/// parameter a non-default value (backlog 82dcff9d, G5).
///
/// Dempster is the default and is what an omitted `combination_method` parses
/// to, so it earns nothing; `gamma` has no default at all, so ANY value does.
fn deprecated_parameter_warnings(method: CombinationMethod, gamma: Option<f64>) -> Vec<String> {
    let mut out = Vec::new();
    if !matches!(method, CombinationMethod::Dempster) {
        out.push(format!(
            "combination_method={method:?} is deprecated: it was stored on the BBA and is \
             echoed as method_used, but it did not change the returned belief. The claim's \
             belief is always recomputed by the shared adaptive combine (the one \
             recompute_beliefs uses)."
        ));
    }
    if let Some(g) = gamma {
        out.push(format!(
            "gamma={g} is deprecated: it was neither stored nor used, and did not change the \
             returned belief."
        ));
    }
    out
}

pub async fn get_belief(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: GetBeliefParams,
) -> Result<CallToolResult, McpError> {
    let claim_id = parse_uuid(&params.claim_id)?;
    let frame_id = params.frame_id.as_deref().map(parse_uuid).transpose()?;

    // Optional (frame, perspective) lens. For get_belief the rule is one-sided:
    // frame_id may legitimately appear alone (the existing framed-but-unlensed
    // path); only perspective_id present requires frame_id. Validate + check
    // existence up front so a bad lens fails fast.
    let lens = crate::tools::lens::resolve_lens_get_belief(
        params.frame_id.as_deref(),
        params.perspective_id.as_deref(),
    )?;
    if let Some((lens_frame, lens_perspective)) = lens {
        crate::tools::lens::validate_lens_exists(
            &server.pool,
            viewer,
            lens_frame,
            lens_perspective,
        )
        .await?;
    }

    let interval =
        epigraph_engine::belief_query::get_belief(&server.pool, viewer, claim_id, frame_id)
            .await
            .map_err(|e| match e {
                epigraph_engine::BeliefQueryError::FrameNotFound(id) => {
                    invalid_params(format!("frame {id} not found"))
                }
                epigraph_engine::BeliefQueryError::ClaimNotFound(id) => {
                    invalid_params(format!("claim {id} not found"))
                }
                epigraph_engine::BeliefQueryError::ParseMasses(msg) => {
                    invalid_params(format!("invalid mass function: {msg}"))
                }
                other => internal_error(other),
            })?;

    // Additive lensed interval, computed under the chosen (frame, perspective).
    // The top-level belief/plausibility/etc above stay the global (unlensed)
    // values. Existence already validated → a compute failure is internal.
    let lensed_belief = match lens {
        Some((lens_frame, lens_perspective)) => {
            let lensed = epigraph_engine::belief_query::get_perspective_belief(
                &server.pool,
                viewer,
                claim_id,
                lens_frame,
                lens_perspective,
            )
            .await
            .map_err(|e| match e {
                epigraph_engine::BeliefQueryError::FrameNotFound(id) => {
                    invalid_params(format!("frame {id} not found"))
                }
                epigraph_engine::BeliefQueryError::ClaimNotFound(id) => {
                    invalid_params(format!("claim {id} not found"))
                }
                epigraph_engine::BeliefQueryError::ParseMasses(msg) => {
                    invalid_params(format!("invalid mass function: {msg}"))
                }
                other => internal_error(other),
            })?;
            Some(LensedBelief::from_interval(
                lens_frame,
                lens_perspective,
                &lensed,
            ))
        }
        None => None,
    };

    let ignorance = interval.plausibility - interval.belief;
    success_json(&BeliefResponse {
        claim_id: claim_id.to_string(),
        belief: interval.belief,
        plausibility: interval.plausibility,
        ignorance,
        pignistic_prob: interval.pignistic_prob,
        mass_on_conflict: interval.mass_on_conflict,
        mass_on_missing: interval.mass_on_missing,
        source: interval.source,
        lensed_belief,
    })
}

pub async fn list_frames(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ListFramesParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let frames = FrameRepository::list(&server.pool, viewer, limit, 0)
        .await
        .map_err(internal_error)?;

    let entries: Vec<FrameEntry> = frames
        .into_iter()
        .map(|f| FrameEntry {
            frame_id: f.id.to_string(),
            name: f.name,
            description: f.description,
            hypotheses: f.hypotheses,
            version: f.version,
            parent_frame_id: f.parent_frame_id.map(|p| p.to_string()),
            is_refinable: f.is_refinable,
        })
        .collect();

    success_json(&entries)
}

pub async fn compare_methods(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: CompareMethodsParams,
) -> Result<CallToolResult, McpError> {
    let claim_id = parse_uuid(&params.claim_id)?;
    let frame_id = parse_uuid(&params.frame_id)?;

    let frame_row = FrameRepository::get_by_id(&server.pool, viewer, frame_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("frame {frame_id} not found")))?;

    let frame = FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone())
        .map_err(internal_error)?;

    let all_bbas =
        MassFunctionRepository::get_for_claim_frame(&server.pool, viewer, claim_id, frame_id)
            .await
            .map_err(internal_error)?;

    if all_bbas.is_empty() {
        return Err(invalid_params("no BBAs stored for this claim/frame"));
    }

    let mut mass_fns = Vec::new();
    for row in &all_bbas {
        mass_fns.push(parse_masses_json(&frame, &row.masses)?);
    }

    let hypothesis_index = params.hypothesis_index as usize;
    let target = FocalElement::positive(BTreeSet::from([hypothesis_index]));

    let methods = [
        CombinationMethod::Conjunctive,
        CombinationMethod::Dempster,
        CombinationMethod::YagerOpen,
        CombinationMethod::YagerClosed,
        CombinationMethod::DuboisPrade,
        CombinationMethod::Inagaki,
    ];

    let mut results = Vec::new();
    for method in methods {
        if mass_fns.len() == 1 {
            let mf = &mass_fns[0];
            let bel = epigraph_ds::measures::belief(mf, &target);
            let pl = epigraph_ds::measures::plausibility(mf, &target);
            let betp = epigraph_ds::measures::pignistic_probability(mf, hypothesis_index);
            results.push(CompareMethodResult {
                method: format!("{method:?}"),
                belief: bel,
                plausibility: pl,
                pignistic_prob: betp,
                mass_on_conflict: mf.mass_of_conflict(),
                mass_on_missing: mf.mass_of_missing(),
            });
        } else {
            match (|| -> Result<_, McpError> {
                let mut result = mass_fns[0].clone();
                for mf in &mass_fns[1..] {
                    result = combine_two(&result, mf, method, None)?;
                }
                let bel = epigraph_ds::measures::belief(&result, &target);
                let pl = epigraph_ds::measures::plausibility(&result, &target);
                let betp = epigraph_ds::measures::pignistic_probability(&result, hypothesis_index);
                Ok(CompareMethodResult {
                    method: format!("{method:?}"),
                    belief: bel,
                    plausibility: pl,
                    pignistic_prob: betp,
                    mass_on_conflict: result.mass_of_conflict(),
                    mass_on_missing: result.mass_of_missing(),
                })
            })() {
                Ok(r) => results.push(r),
                Err(_) => {
                    results.push(CompareMethodResult {
                        method: format!("{method:?}"),
                        belief: 0.0,
                        plausibility: 0.0,
                        pignistic_prob: 0.0,
                        mass_on_conflict: 0.0,
                        mass_on_missing: 0.0,
                    });
                }
            }
        }
    }

    success_json(&CompareMethodsResponse {
        claim_id: claim_id.to_string(),
        frame_id: frame_id.to_string(),
        hypothesis_index: params.hypothesis_index,
        results,
    })
}

pub async fn scoped_belief(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ScopedBeliefParams,
) -> Result<CallToolResult, McpError> {
    let claim_id = parse_uuid(&params.claim_id)?;
    let scope_id = parse_uuid(&params.scope_id)?;

    let scope_type = match params.scope_type.to_lowercase().as_str() {
        "perspective" => "perspective",
        "community" => "community",
        other => {
            return Err(invalid_params(format!(
                "scope_type must be 'perspective' or 'community', got '{other}'"
            )));
        }
    };

    // Frame function: when a frame is given for a perspective scope, compute the
    // belief live from the claim's labelled BBAs — each discounted by this
    // perspective's source-reliability map — rather than reading the cache. This
    // reflects current evidence no matter how it was ingested.
    if scope_type == "perspective" {
        if let Some(frame_id_str) = params.frame_id.as_deref() {
            let frame_id = parse_uuid(frame_id_str)?;
            let interval = epigraph_engine::belief_query::get_perspective_belief(
                &server.pool,
                viewer,
                claim_id,
                frame_id,
                scope_id,
            )
            .await
            .map_err(|e| match e {
                epigraph_engine::BeliefQueryError::FrameNotFound(id) => {
                    invalid_params(format!("frame {id} not found"))
                }
                // Without this arm the engine's new not-found signal would fall
                // through to `internal_error` and turn a precise diagnostic
                // into a 500.
                epigraph_engine::BeliefQueryError::ClaimNotFound(id) => {
                    invalid_params(format!("claim {id} not found"))
                }
                epigraph_engine::BeliefQueryError::ParseMasses(msg) => {
                    invalid_params(format!("invalid mass function: {msg}"))
                }
                other => internal_error(other),
            })?;
            return success_json(&ScopedBeliefResponse {
                claim_id: claim_id.to_string(),
                scope_type: scope_type.to_string(),
                scope_id: scope_id.to_string(),
                belief: interval.belief,
                plausibility: interval.plausibility,
                mass_on_conflict: interval.mass_on_conflict,
                mass_on_missing: interval.mass_on_missing,
                pignistic_prob: Some(interval.pignistic_prob),
            });
        }
    }

    let row =
        ScopedBeliefRepository::get(&server.pool, viewer, claim_id, scope_type, Some(scope_id))
            .await
            .map_err(internal_error)?
            .ok_or_else(|| {
                invalid_params(format!(
                    "no scoped belief for claim {claim_id} with {scope_type} {scope_id}"
                ))
            })?;

    success_json(&ScopedBeliefResponse {
        claim_id: claim_id.to_string(),
        scope_type: scope_type.to_string(),
        scope_id: scope_id.to_string(),
        belief: row.belief,
        plausibility: row.plausibility,
        mass_on_conflict: row.mass_on_empty,
        mass_on_missing: row.mass_on_missing,
        pignistic_prob: row.pignistic_prob,
    })
}

pub async fn get_divergence(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: GetDivergenceParams,
) -> Result<CallToolResult, McpError> {
    let claim_id = parse_uuid(&params.claim_id)?;

    let row = DivergenceRepository::get_latest(&server.pool, viewer, claim_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("no divergence data for claim {claim_id}")))?;

    success_json(&DivergenceResponse {
        claim_id: claim_id.to_string(),
        pignistic_prob: row.pignistic_prob,
        bayesian_posterior: row.bayesian_posterior,
        kl_divergence: row.kl_divergence,
        computed_at: row.computed_at.to_rfc3339(),
    })
}

/// Convert a FocalElement to a string key for JSON serialization.
fn focal_to_key(fe: &FocalElement) -> String {
    if fe.is_conflict() {
        return String::new();
    }
    let indices: Vec<String> = fe
        .subset
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    if fe.complement {
        format!("~{}", indices.join(","))
    } else {
        indices.join(",")
    }
}
