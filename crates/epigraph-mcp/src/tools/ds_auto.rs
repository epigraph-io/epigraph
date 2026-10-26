//! Auto-wiring of CDST (Calibrated Dempster-Shafer) evidence for claims.
//!
//! Every claim-creating or claim-updating tool calls into this module after
//! persisting the claim. DS is the primary belief authority — `update_with_evidence`
//! propagates errors, and so do `submit_claim` and `memorize`: their new-claim
//! wiring runs inside the submission's own author-stamped transaction, before
//! COMMIT, and a wiring failure rolls the whole submission back
//! (`claim_helper::wire_ds_for_new_claim_in_tx`). It used to be best-effort and
//! post-commit, which reported success over a committed claim with no BBA.
//!
//! Each BBA is Shafer-discounted by its `source_strength` before combination to
//! prevent runaway confirmation (C2) and dilution attacks (C3).

use std::collections::BTreeSet;

use sqlx::Acquire;

use uuid::Uuid;

use epigraph_db::{FrameRepository, MassFunctionRepository, PerspectiveRepository};
use epigraph_ds::{combination, measures, FocalElement, FrameOfDiscernment, MassFunction};

// Edge-factor auto-wire moved to `epigraph_engine::edge_factor` so the HTTP
// route layer can share a single algorithm. Re-export keeps the existing
// MCP call sites (`tools::ingestion`, `tools::workflows`) working unchanged.
//
// Phase 2 (issue #197) re-exports `effective_source_strength` so the local
// `auto_wire_ds_update` combine loop below can call it without an extra
// `use` and so external integration tests can import via the MCP crate.
pub use epigraph_engine::edge_factor::{
    auto_wire_ds_for_edge, auto_wire_edge_if_epistemic, effective_source_strength,
    effective_source_strength_profiled, EdgeFactorOutcome,
};

/// Probability value in [0.0, 1.0]. Currently f64 for codebase consistency.
/// Future: may migrate to f32 or bounded newtype for memory optimization.
/// Changing this alias + recompiling will flag every callsite.
pub type Prob = f64;

/// Result of auto-wiring DS evidence for a single claim.
#[derive(Debug)]
#[allow(dead_code)] // mass_on_conflict/missing retained for diagnostics
pub struct DsAutoResult {
    pub belief: Prob,
    pub plausibility: Prob,
    pub pignistic_prob: Prob,
    pub mass_on_conflict: Prob,
    pub mass_on_missing: Prob,
    pub frame_id: Uuid,
    /// Whether the claim's cached DS columns were written with the values
    /// above. `false` when the caller is a non-owner of a public claim whose
    /// cache it may not write on this frame (migration 114: a non-owner
    /// refreshes a cache only on the frame it already carries, and seeds one
    /// only on `binary_truth` when the claim has no cache at all). The BBA is
    /// stored either way; the values above are then this call's combination,
    /// NOT what the claim's cache holds.
    pub cache_written: bool,
}

/// Entry for batch DS wiring (used by `do_ingest_document`).
pub struct BatchDsEntry {
    pub claim_id: Uuid,
    pub confidence: f64,
    pub weight: f64,
    /// Canonical evidence-type tag from the extraction plan, stored on the BBA
    /// so `effective_source_strength` (global) and the frame function
    /// (per-perspective) can key reliability on it. `None` → untagged BBA
    /// (falls back to the stored `source_strength` / α = 1.0).
    pub evidence_type: Option<String>,
    /// Declared labeled axis to place this claim on (issue #222). `None` → the
    /// canonical binary `{TRUE, FALSE}` frame, i.e. today's behaviour.
    pub axis: Option<epigraph_ingest::common::plan::PlannedAxis>,
}

/// Canonical binary frame name.
const BINARY_FRAME_NAME: &str = "binary_truth";
/// Hypotheses for the canonical binary frame.
// belief-profile: allow-literal (array length of a fixed hypothesis list)
const BINARY_HYPOTHESES: [&str; 2] = ["TRUE", "FALSE"];

/// `mass_functions.combination_method` of the BBA [`auto_wire_ds_update`] seeds
/// from a claim's `truth_value` (backlog fc55465b).
pub const TRUTH_VALUE_SEED_METHOD: &str = "truth_value_seed";

/// The range a `truth_value` is capped to before it is seeded: the served
/// belief profile's `construction.truth_seed_min` / `truth_seed_max`
/// (defaults 0.005 / 0.995), so the seed's committed mass stays within the cap
/// `build_bba_on_index` puts on evidence. An uncapped t = 1.0 (or 0.0) would
/// seed a categorical BBA, and under Dempster's rule a categorical BBA absorbs
/// every later one: the claim could never be moved by evidence again.
fn seed_truth_bounds() -> (f64, f64) {
    let c = &epigraph_engine::belief_profile::BeliefProfile::served().construction;
    (c.truth_seed_min, c.truth_seed_max)
}

/// Get-or-create the canonical `binary_truth` frame.
///
/// Handles race conditions: get → create → fallback get.
pub async fn ensure_binary_frame(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
) -> Result<Uuid, String> {
    let hyps: Vec<String> = BINARY_HYPOTHESES.iter().map(|s| (*s).to_string()).collect();
    ensure_axis_frame(
        &mut *conn,
        viewer,
        BINARY_FRAME_NAME,
        &hyps,
        Some("Canonical binary frame: {TRUE, FALSE}"),
    )
    .await
}

/// Get-or-create a frame by name over `hypotheses` — the generalization of
/// [`ensure_binary_frame`] to any declared labeled axis (issue #222).
///
/// Frames dedupe by NAME (the DB has a unique index on it), so an existing frame
/// under this name is reused. Its stored hypotheses must match `hypotheses`
/// exactly, including order: the index a label resolves to is positional, so
/// reusing a same-named frame with a different list would silently place claims
/// on a different hypothesis than the caller declared. That mismatch is an error.
///
/// Handles the create race the same way as before: get → create → fallback get.
pub async fn ensure_axis_frame(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    name: &str,
    hypotheses: &[String],
    description: Option<&str>,
) -> Result<Uuid, String> {
    // Fast path: frame already exists — verify the axis agrees before reuse.
    if let Some(row) = FrameRepository::get_by_name(&mut *conn, viewer, name)
        .await
        .map_err(|e| format!("get_by_name: {e}"))?
    {
        if row.hypotheses != hypotheses {
            return Err(format!(
                "frame {name:?} already exists over {:?}, but this claim declares {hypotheses:?}; \
                 a frame name denotes one ordered axis (issue #222)",
                row.hypotheses
            ));
        }
        return Ok(row.id);
    }

    // The create runs under its OWN savepoint, and that is not hygiene. Its
    // failure is SWALLOWED — the arm below falls back to a re-read — and a
    // swallowed failure inside a caller's transaction aborts that transaction:
    // the fallback read then fails with `25P02`, every later statement fails,
    // and the caller's `COMMIT` is answered with `ROLLBACK` and NO error (brief
    // hard constraint #6). MEASURED by review on `ingest_document`'s post-commit
    // DS transaction: a declared axis whose frame name exists but is invisible
    // to the ingesting agent took the document from 3 atom BBAs to 0 — the
    // binary atoms' BBAs, wired earlier in the same transaction, vanished at
    // COMMIT — with one WARN and no error. The same abort happens on the race
    // this fallback was written for (two first creations of one name; the loser
    // gets `23505`).
    //
    // `Connection::begin` on a connection already in a transaction is a
    // SAVEPOINT; on an autocommit checkout it is a plain transaction. Both are
    // correct here.
    let mut sp = conn
        .begin()
        .await
        .map_err(|e| format!("frame {name:?}: could not open a savepoint for the create: {e}"))?;
    let created = FrameRepository::create(&mut *sp, name, description, hypotheses).await;
    match created {
        Ok(row) => {
            sp.commit().await.map_err(|e| {
                format!("frame {name:?}: could not release the create savepoint: {e}")
            })?;
            Ok(row.id)
        }
        Err(_) => {
            sp.rollback().await.map_err(|e| {
                format!("frame {name:?}: could not roll back the failed create: {e}")
            })?;
            // Race: another connection created it first — re-fetch and re-verify.
            let row = FrameRepository::get_by_name(&mut *conn, viewer, name)
                .await
                .map_err(|e| format!("fallback get_by_name: {e}"))?
                .ok_or_else(|| format!("frame {name:?} missing after create attempt"))?;
            if row.hypotheses != hypotheses {
                return Err(format!(
                    "frame {name:?} was concurrently created over {:?}, but this claim declares \
                     {hypotheses:?}",
                    row.hypotheses
                ));
            }
            Ok(row.id)
        }
    }
}

/// Build a simple-support BBA for a binary frame: `m({primary}) =
/// (confidence*weight).clamp(0.01, 0.99)`, with the remainder on Θ.
///
/// NOTE (backlog b3d12e2a): an earlier Fix(2) added a fixed `base_against`
/// opposing-singleton mass to make `Pl(primary) < 1.0`. That was reverted —
/// it flipped weakly-supported claims (where `confidence*weight < base_against`)
/// to `contradicted` (regression in `classify_test::high_ignorance_*`), and
/// nothing consumes the plausibility headroom today. The reported BetP-drop bug
/// is fixed by the writer discount-authority unification (Fix(1)), not by this
/// shape change. Reintroduce a directed shape only with a bound that keeps the
/// opposing mass strictly below the primary mass, and only when a real consumer
/// of `Pl(primary) < 1.0` exists.
fn build_binary_bba(
    frame: &FrameOfDiscernment,
    confidence: f64,
    weight: f64,
    supports: bool,
) -> Result<MassFunction, String> {
    let idx = usize::from(!supports); // 0=TRUE, 1=FALSE
    build_bba_on_index(frame, confidence, weight, idx)
}

/// Simple-support BBA placing `m({idx}) = confidence*weight`, clamped to the
/// served belief profile's `construction.simple_support_mass_min` /
/// `simple_support_mass_max` (defaults 0.01 / 0.99), with the remainder on Θ — [`build_binary_bba`] generalized to any hypothesis
/// index on any frame (issue #222).
///
/// Same mass SHAPE as the binary case, just aimed at the declared label instead
/// of TRUE/FALSE, so all the discounting and combination behaviour downstream is
/// unchanged.
fn build_bba_on_index(
    frame: &FrameOfDiscernment,
    confidence: f64,
    weight: f64,
    idx: usize,
) -> Result<MassFunction, String> {
    let bounds = &epigraph_engine::belief_profile::BeliefProfile::served().construction;
    let mass = (confidence * weight).clamp(
        bounds.simple_support_mass_min,
        bounds.simple_support_mass_max,
    );
    MassFunction::simple(frame.clone(), BTreeSet::from([idx]), mass)
        .map_err(|e| format!("build BBA: {e}"))
}

/// Serialize a `MassFunction` to JSON for DB storage.
fn mass_to_json(mf: &MassFunction) -> Result<serde_json::Value, String> {
    let map: std::collections::HashMap<String, f64> = mf
        .masses()
        .iter()
        .map(|(fe, m)| (focal_to_key(fe), *m))
        .collect();
    serde_json::to_value(map).map_err(|e| format!("serialize BBA: {e}"))
}

/// Convert a `FocalElement` to a string key for JSON serialization.
fn focal_to_key(fe: &FocalElement) -> String {
    if fe.is_conflict() {
        return String::new();
    }
    let indices: Vec<String> = fe.subset.iter().map(ToString::to_string).collect();
    if fe.complement {
        format!("~{}", indices.join(","))
    } else {
        indices.join(",")
    }
}

/// Construct a `FrameOfDiscernment` for the binary frame.
fn binary_frame() -> Result<FrameOfDiscernment, String> {
    let hyps: Vec<String> = BINARY_HYPOTHESES.iter().map(|s| (*s).to_string()).collect();
    FrameOfDiscernment::new(BINARY_FRAME_NAME.to_string(), hyps)
        .map_err(|e| format!("binary frame: {e}"))
}

/// Construct a `FrameOfDiscernment` for a declared axis (issue #222).
fn axis_frame(name: &str, hypotheses: &[String]) -> Result<FrameOfDiscernment, String> {
    FrameOfDiscernment::new(name.to_string(), hypotheses.to_vec())
        .map_err(|e| format!("axis frame {name:?}: {e}"))
}

/// Compute Bel/Pl/BetP for hypothesis 0 (TRUE) from a combined mass function.
fn compute_measures(combined: &MassFunction) -> (Prob, Prob, Prob, Prob, Prob) {
    compute_measures_on_index(combined, 0)
}

/// Compute Bel/Pl/BetP for an arbitrary hypothesis index (issue #222).
///
/// On the binary frame `idx` is 0 and this is exactly [`compute_measures`]. On a
/// declared axis it must be the index the claim asserts — reporting Bel(index 0)
/// for a claim placed on `moderate` would cache a belief about `ineffective`.
/// This matches how the read side already behaves:
/// `epigraph_engine::belief_query` targets the claim's stored
/// `claim_frames.hypothesis_index`.
fn compute_measures_on_index(
    combined: &MassFunction,
    idx: usize,
) -> (Prob, Prob, Prob, Prob, Prob) {
    let target = FocalElement::positive(BTreeSet::from([idx]));
    let bel = measures::belief(combined, &target);
    let pl = measures::plausibility(combined, &target);
    let betp = measures::pignistic_probability(combined, idx);
    let conflict = combined.mass_of_conflict();
    let missing = combined.mass_of_missing();
    (bel, pl, betp, conflict, missing)
}

/// Parse a stored BBA row back into a `MassFunction`.
fn parse_stored_bba(
    frame: &FrameOfDiscernment,
    masses_json: &serde_json::Value,
) -> Result<MassFunction, String> {
    MassFunction::from_json_masses(frame.clone(), masses_json)
        .map_err(|e| format!("parse stored BBA: {e}"))
}

/// The evidential content of one auto-wire call.
///
/// Bundled rather than passed positionally because `confidence` and `weight`
/// are adjacent bare `f64`s: `(.., confidence, 0.6, true, None)` compiles just
/// as happily with the two transposed, and the result is a silently
/// mis-weighted BBA rather than an error. Named fields make that a compile
/// error. (Adding `viewer` for tenancy also pushed this to 8 arguments and
/// tripped `clippy::too_many_arguments`, but the count is the symptom.)
#[derive(Debug, Clone, Copy)]
pub struct DsAutoInput<'a> {
    /// Belief mass for the supported hypothesis, in `[0, 1]`.
    pub confidence: f64,
    /// Source-reliability discount applied to the BBA, in `[0, 1]`.
    pub weight: f64,
    /// Whether the evidence supports (`true`) or opposes (`false`) the claim.
    pub supports: bool,
    /// Evidence classification tag, when the caller has one.
    pub evidence_type: Option<&'a str>,
    /// The evidence row this BBA came from, when the caller wrote one in the
    /// same transaction. Stored as `mass_functions.evidence_id`, it is what
    /// gives the BBA a source identity
    /// (`epigraph_engine::source_dependence::SourceKey`), so a later
    /// re-observation of the same `source_url` by the same agent is folded as
    /// a repeat rather than as independent corroboration (backlog 4c42c0bf).
    pub evidence_id: Option<Uuid>,
}

/// The future an [`optional_read_under_savepoint`] read returns: it borrows the
/// savepoint's connection for `'c`.
pub type OptionalRead<'c, T, E> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<T>, E>> + Send + 'c>>;

/// Run an OPTIONAL read (one whose failure the caller treats as "no value")
/// under a SAVEPOINT, so its failure cannot abort the enclosing transaction.
///
/// # Why this exists
///
/// Several calibration reads in this module were written `.await.ok()`, and
/// their comments promise that a database error "falls through to None". That
/// was true while they ran on their own pooled checkout. Since the new-claim
/// wiring moved INSIDE the submission transaction (15f35c6b), a failed
/// statement ABORTS that transaction: the `.ok()` hides the error, and the NEXT
/// statement fails with `current transaction is aborted`, so `submit_claim`,
/// `memorize` and `resolve_backlog_item` would fail with an error that names the
/// wrong statement (review finding, atomicity-authz). Under a savepoint the
/// failed read is rolled back alone and the promise holds again.
///
/// Returns `Ok(None)` when the read fails (logged at WARN). Only a failure of
/// the savepoint itself (`SAVEPOINT` / `RELEASE` / `ROLLBACK TO`) is an `Err`:
/// that means the connection is unusable and the caller must not go on.
///
/// # Errors
/// A string naming the savepoint statement that failed.
pub async fn optional_read_under_savepoint<T, E, F>(
    conn: &mut sqlx::PgConnection,
    what: &'static str,
    read: F,
) -> Result<Option<T>, String>
where
    E: std::fmt::Display,
    F: for<'c> FnOnce(&'c mut sqlx::PgConnection) -> OptionalRead<'c, T, E>,
{
    let mut sp = conn
        .begin()
        .await
        .map_err(|e| format!("{what}: could not open a savepoint: {e}"))?;
    let outcome = read(&mut sp).await;
    match outcome {
        Ok(value) => {
            sp.commit()
                .await
                .map_err(|e| format!("{what}: could not release the savepoint: {e}"))?;
            Ok(value)
        }
        Err(e) => {
            tracing::warn!(read = what, error = %e, "optional read failed; treated as absent");
            sp.rollback()
                .await
                .map_err(|e| format!("{what}: could not roll back to the savepoint: {e}"))?;
            Ok(None)
        }
    }
}

/// The frame's `belief_profile` override object (`frames.properties`), read
/// under a savepoint for the same reason as [`optional_read_under_savepoint`]:
/// it is optional, and a failure must not abort the caller's transaction.
async fn frame_profile_overrides(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    frame_id: Uuid,
) -> Result<Option<serde_json::Value>, String> {
    let what = "belief_profile";
    let mut sp = conn
        .begin()
        .await
        .map_err(|e| format!("{what}: could not open a savepoint: {e}"))?;
    match FrameRepository::get_by_id(&mut *sp, viewer, frame_id).await {
        Ok(row) => {
            sp.commit()
                .await
                .map_err(|e| format!("{what}: could not release the savepoint: {e}"))?;
            Ok(row.and_then(|f| {
                epigraph_engine::belief_profile::overrides_in(&f.properties).cloned()
            }))
        }
        Err(e) => {
            tracing::warn!(read = what, error = %e, "optional read failed; treated as absent");
            sp.rollback()
                .await
                .map_err(|e| format!("{what}: could not roll back to the savepoint: {e}"))?;
            Ok(None)
        }
    }
}

/// The belief profile a DS write folds under: the served profile with this
/// frame's tier, exactly what `edge_factor::compute_combined_belief` resolves,
/// so the cached value this write leaves is the value a recompute reproduces.
fn resolve_frame_profile(
    frame_overrides: Option<&serde_json::Value>,
    per_frame_intra: Option<f64>,
    per_frame_evidence_weights: Option<&std::collections::HashMap<String, f64>>,
) -> epigraph_engine::belief_profile::BeliefProfile {
    epigraph_engine::belief_profile::BeliefProfile::served().resolve(
        epigraph_engine::belief_profile::FrameTier {
            overrides: frame_overrides,
            intra_evidence_locality_factor: per_frame_intra,
            evidence_type_weights: per_frame_evidence_weights,
        },
        epigraph_engine::belief_profile::PerspectiveTier::default(),
    )
}

/// Auto-wire DS for a **new** claim.
///
/// Creates a BBA, assigns the claim to the binary frame, computes Bel/Pl/BetP,
/// and updates the claim's DS columns.
pub async fn auto_wire_ds_for_claim(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    agent_id: Uuid,
    input: DsAutoInput<'_>,
) -> Result<DsAutoResult, String> {
    let DsAutoInput {
        confidence,
        weight,
        supports,
        evidence_type,
        evidence_id,
    } = input;
    let frame_id = ensure_binary_frame(&mut *conn, viewer).await?;
    let frame = binary_frame()?;

    // Build BBA
    let bba = build_binary_bba(&frame, confidence, weight, supports)?;
    let masses_json = mass_to_json(&bba)?;

    // Assign claim to binary frame (hypothesis_index=0 → TRUE)
    FrameRepository::assign_claim(&mut *conn, claim_id, frame_id, Some(0))
        .await
        .map_err(|e| format!("assign_claim: {e}"))?;

    // The canonical key, not the caller's spelling or DB-vocab tag (bc06ec6f).
    let evidence_type = epigraph_engine::calibration::canonical_evidence_type(evidence_type);

    // Store BBA (perspective_id=NULL for auto-wired). source_strength is the
    // evidence-type reliability weight (used as Shafer's reliability discount
    // at combination time). Agent confidence is already encoded in the BBA's
    // mass shape (mass = confidence * weight, clamped); using `confidence`
    // here would double-discount.
    MassFunctionRepository::store_with_perspective(
        &mut *conn,
        claim_id,
        frame_id,
        Some(agent_id),
        None, // no perspective
        &masses_json,
        None,
        Some("auto_wire"),
        Some(weight),             // source_strength = evidence-type reliability
        evidence_type.as_deref(), // evidence_type (canonical key)
        "unknown", // ds_auto single-evidence path; locality lives on edge_factor (issue #197)
        // The creation's evidence row, when the caller wrote one (issue #197
        // Phase 3). perspective_id stays NULL: this is the claim's one
        // creation BBA, not a per-evidence row.
        evidence_id,
    )
    .await
    .map_err(|e| format!("store BBA: {e}"))?;

    // BetP-drop fix (backlog b3d12e2a): previously this path discounted by
    // `confidence`, while the batch writer applied NO discount and the
    // update/recompute paths discount by `effective_source_strength` — three
    // writers, three answers for the same stored BBA. Unify onto the SAME
    // discount authority (`effective_source_strength`) so the new-claim initial
    // cache matches the first `update_with_evidence` and `recompute_beliefs`.
    //
    // We re-read the row we just stored and compute its discounted single-BBA
    // measures inline, mirroring the `all_rows.len() <= 1` branch of
    // `auto_wire_ds_update` below. (Honest cost: this duplicates the
    // calibration-load block rather than calling the engine `recombine` fn —
    // `recompute_claim_belief_on_frame` returns `bool`, not the measures, so it
    // cannot hand back the scalars this fn must return in DsAutoResult. The
    // shared invariant is the discount AUTHORITY, not a single code path.)
    //
    // NOTE: because submit_claim persists `truth_value = clamped(ds.pignistic_prob)`,
    // this also shifts the new-claim persisted truth_value from a confidence-based
    // value to the evidence-type-discounted BetP — a deliberate, correctness-positive
    // change in persisted truth, not only in cached BetP.
    // All optional: a failure means "no per-frame override", and each runs under
    // its own savepoint because this function runs inside the submission's
    // transaction (see `optional_read_under_savepoint`).
    let per_frame_intra =
        optional_read_under_savepoint(&mut *conn, "intra_evidence_locality_factor", |c| {
            Box::pin(FrameRepository::get_intra_evidence_locality_factor(
                c, frame_id,
            ))
        })
        .await?;
    let per_frame_evidence_weights =
        optional_read_under_savepoint(&mut *conn, "evidence_type_weights", |c| {
            Box::pin(FrameRepository::get_per_frame_evidence_type_weights(
                c, frame_id,
            ))
        })
        .await?;

    let all_rows =
        MassFunctionRepository::get_for_claim_frame(&mut *conn, viewer, claim_id, frame_id)
            .await
            .map_err(|e| format!("get_for_claim_frame: {e}"))?;
    let row = all_rows
        .first()
        .ok_or_else(|| "no BBA row after store_with_perspective".to_string())?;
    let frame_overrides = frame_profile_overrides(&mut *conn, viewer, frame_id).await?;
    let profile = resolve_frame_profile(
        frame_overrides.as_ref(),
        per_frame_intra,
        per_frame_evidence_weights.as_ref(),
    );
    let reliability = effective_source_strength_profiled(row, &profile);
    let mf = parse_stored_bba(&frame, &row.masses)?;
    let discounted =
        combination::discount(&mf, reliability).map_err(|e| format!("discount: {e}"))?;
    let (bel, pl, betp, conflict, missing) = compute_measures(&discounted);

    // Update claim DS columns
    let cache_written = MassFunctionRepository::update_claim_belief(
        &mut *conn,
        claim_id,
        epigraph_db::CachedBelief {
            belief: bel,
            plausibility: pl,
            mass_on_empty: conflict,
            pignistic_prob: Some(betp),
            mass_on_missing: missing,
            belief_frame_id: Some(frame_id),
        },
    )
    .await
    .map_err(|e| format!("update_claim_belief: {e}"))?;

    Ok(DsAutoResult {
        belief: bel,
        plausibility: pl,
        pignistic_prob: betp,
        mass_on_conflict: conflict,
        mass_on_missing: missing,
        frame_id,
        cache_written,
    })
}

/// Auto-wire DS for an **evidence update** on an existing claim.
///
/// Stores a new BBA, retrieves all BBAs, discounts each by its source_strength
/// (Shafer's reliability discounting), combines via `combine_multiple()`,
/// and updates the claim's DS columns.
///
/// `evidence_id` is passed as `perspective_id` so that each evidence submission
/// gets its own BBA row rather than upsert-overwriting the previous one on the
/// unique constraint (claim_id, frame_id, agent_id, perspective_id=NULL).
///
/// # The claim's scalar prior (backlog fc55465b)
///
/// A claim whose `truth_value` came from a path that wrote no BBA (ingest-time
/// `calculate_initial_truth`, REST create) has nothing for the new evidence to
/// combine with, and its `pignistic_prob` cache is NULL. Two guards keep the
/// first update from discarding that prior:
///
/// - **Seed** (`seed_truth_prior = true`, and the claim has NO BBA on any
///   two-hypothesis frame): before the evidence BBA is stored, the claim gets a
///   [`TRUTH_VALUE_SEED_METHOD`] row built by
///   [`MassFunction::from_pignistic_prior`], whose BetP is exactly the
///   `truth_value` (capped to the profile's truth-seed bounds), so the seed alone moves
///   nothing. It is attributed to the claim's author (the authored scalar is
///   the author's opinion), stored undiscounted (`source_strength = 1.0`,
///   `evidence_type = NULL`: `effective_source_strength`'s exempt arm), with no
///   perspective and no evidence row. It is written at most once: afterwards
///   the claim has BBAs. A caller that seeds must pass an `evidence_id`, or its
///   own evidence BBA would upsert over a seed it authored.
/// - **Clamp prior**: the supports=true monotonicity clamp reads
///   `COALESCE(pignistic_prob, truth_value)`, so a caller that does not seed
///   (a non-owner attaching to a public claim, `backfill_factors`) still has a
///   prior to clamp to.
#[allow(clippy::too_many_arguments)]
pub async fn auto_wire_ds_update(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    agent_id: Uuid,
    confidence: f64,
    weight: f64,
    supports: bool,
    evidence_type_str: Option<&str>, // NEW: evidence classification tag
    evidence_id: Option<Uuid>,       // C-1: used as perspective_id to separate BBAs
    seed_truth_prior: bool,
) -> Result<DsAutoResult, String> {
    auto_wire_ds_update_filed_on(
        conn,
        viewer,
        claim_id,
        agent_id,
        confidence,
        weight,
        supports,
        evidence_type_str,
        evidence_id,
        seed_truth_prior,
        None,
    )
    .await
}

/// [`auto_wire_ds_update`], with the evidence BBA filed on `file_on` instead
/// of `binary_truth` when it is `Some`: a two-hypothesis frame the claim's
/// readers read (a promoted hypothesis's `research_validity`, operator ruling
/// R-17; `epigraph_engine::promotion::promoted_hypothesis_filing_frame`), whose
/// index 0 is the claim's own hypothesis, as on `binary_truth`. The claim is
/// bound to it at index 0. Only the row's frame changes: the truth_value seed,
/// the frame-scoped calibration and the cache (`belief_frame_id`) stay on
/// `binary_truth`, and the fold below reads every two-hypothesis frame, so the
/// evidence is combined exactly once either way.
#[allow(clippy::too_many_arguments)]
pub async fn auto_wire_ds_update_filed_on(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    agent_id: Uuid,
    confidence: f64,
    weight: f64,
    supports: bool,
    evidence_type_str: Option<&str>,
    evidence_id: Option<Uuid>,
    seed_truth_prior: bool,
    file_on: Option<Uuid>,
) -> Result<DsAutoResult, String> {
    let frame_id = ensure_binary_frame(&mut *conn, viewer).await?;
    let frame = binary_frame()?;
    let store_frame_id = file_on.unwrap_or(frame_id);

    // Build BBA for this evidence
    let bba = build_binary_bba(&frame, confidence, weight, supports)?;
    let masses_json = mass_to_json(&bba)?;

    // Ensure assignment exists
    FrameRepository::assign_claim(&mut *conn, claim_id, frame_id, Some(0))
        .await
        .map_err(|e| format!("assign_claim: {e}"))?;
    if store_frame_id != frame_id {
        FrameRepository::assign_claim(&mut *conn, claim_id, store_frame_id, Some(0))
            .await
            .map_err(|e| format!("assign_claim: {e}"))?;
    }

    // Materialize a synthetic perspective with id=evidence_id so the
    // mass_functions.perspective_id FK is satisfied. Without this, every
    // multi-evidence update path (report_workflow_outcome, update_with_evidence)
    // failed with mass_functions_perspective_id_fkey since C-1 (355cf4f).
    if let Some(persp_id) = evidence_id {
        PerspectiveRepository::ensure_evidence_perspective(&mut *conn, persp_id, Some(agent_id))
            .await
            .map_err(|e| format!("ensure_evidence_perspective: {e}"))?;
    }

    // The canonical key: callers pass a DB-vocab tag of the evidence row they
    // wrote or linked (`observation`, `reference`, ...) or a caller-cased
    // canonical key; both resolve through the calibration alias map (bc06ec6f).
    let evidence_type_str =
        epigraph_engine::calibration::canonical_evidence_type(evidence_type_str);

    // The claim's scalar prior, read ONCE, before anything below writes: the
    // cached `pignistic_prob` (the clamp's prior), the authored `truth_value`
    // (the seed, and the clamp's prior when the cache is NULL), and the author
    // (the seed's source). PR-09: a per-id read over a caller-supplied uuid, so
    // it is filtered rather than exempted; an invisible claim reads as "no
    // prior", the same answer a nonexistent one gives.
    let claim_prior: Option<(Option<f64>, f64, Uuid)> = {
        let sql = viewer.splice(
            "SELECT c.pignistic_prob, c.truth_value, c.agent_id FROM claims c \
                 WHERE c.id = $1 /* {VISIBILITY:c} */",
            // belief-profile: allow-literal (the SQL bind slot the visibility splice uses)
            2,
        );
        // Owned, so the boxed read borrows only the savepoint's connection.
        let group: Option<Vec<Uuid>> = viewer.group_bind().map(<[Uuid]>::to_vec);
        optional_read_under_savepoint(&mut *conn, "claim prior", move |c| {
            Box::pin(async move {
                let mut q = sqlx::query_as::<_, (Option<f64>, f64, Uuid)>(&sql).bind(claim_id);
                if let Some(g) = group {
                    q = q.bind(g);
                }
                q.fetch_optional(c).await
            })
        })
        .await?
    };

    // The truth_value seed (see the doc comment). Decided on BBA PRESENCE over
    // every two-hypothesis frame, not on `pignistic_prob IS NULL`: a claim can
    // carry a cache from another frame (`assess_claim`, an other-frame
    // recompute) and no binary BBA, and a claim whose BBAs sit on a legacy
    // binary frame already has its prior in the combine below.
    if seed_truth_prior {
        if let Some((_, truth, author)) = claim_prior {
            let existing =
                MassFunctionRepository::get_for_claim_binary_frames(&mut *conn, viewer, claim_id)
                    .await
                    .map_err(|e| format!("get_for_claim_binary_frames: {e}"))?;
            let (seed_min, seed_max) = seed_truth_bounds();
            let t = truth.clamp(seed_min, seed_max);
            let seed = if existing.is_empty() {
                MassFunction::from_pignistic_prior(frame.clone(), 0, t)
                    .map_err(|e| format!("truth_value seed: {e}"))?
            } else {
                None
            };
            if let Some(seed) = seed {
                MassFunctionRepository::store_with_perspective(
                    &mut *conn,
                    claim_id,
                    frame_id,
                    Some(author), // the authored scalar is the author's opinion
                    None,         // no perspective
                    &mass_to_json(&seed)?,
                    None,
                    Some(TRUTH_VALUE_SEED_METHOD),
                    Some(1.0), // exempt reliability: read undiscounted, so BetP stays t
                    None,      // no evidence_type (the exempt arm keys on its absence)
                    "unknown",
                    None, // no evidence row produced it
                )
                .await
                .map_err(|e| format!("store truth_value seed: {e}"))?;
            }
        }
    }

    // Store BBA — use evidence_id as perspective_id so each evidence submission
    // gets its own row instead of upsert-overwriting on (claim, frame, agent, NULL).
    // source_strength = evidence-type reliability weight (used for Shafer
    // discount at combination time); agent confidence is already in the
    // BBA mass shape, storing it here too would double-discount.
    MassFunctionRepository::store_with_perspective(
        &mut *conn,
        claim_id,
        store_frame_id, // binary_truth, or the frame the caller files on (R-17)
        Some(agent_id),
        evidence_id, // C-1: unique perspective per evidence prevents overwrite
        &masses_json,
        None,
        Some("auto_wire"),
        Some(weight),                 // source_strength = evidence-type reliability
        evidence_type_str.as_deref(), // evidence_type (canonical key)
        "unknown",   // ds_auto evidence path; locality not derived here (issue #197)
        evidence_id, // Phase 3: the FK to the evidence row that produced this BBA (issue #197)
    )
    .await
    .map_err(|e| format!("store BBA: {e}"))?;

    // Retrieve BBAs from ALL 2-hypothesis frames for this claim. The DB JOIN
    // on frames ensures we only include frames with exactly 2 hypotheses —
    // a BBA from a 3+-hypothesis frame whose focal elements happen to use only
    // indices 0 and 1 would be semantically wrong when parsed as binary_frame()
    // ({0,1} in a ternary frame ≠ Theta on binary). Cross-frame retrieval
    // prevents frame-fragmentation loss: BBAs written to legacy binary frames
    // (e.g. "research_validity") are included so update_with_evidence combines
    // the full evidence history rather than starting fresh from just the new
    // BBA — the root cause of the BetP drop in backlog 30bfbb19
    // (claims c98b6dec, adf396a8: 0.883→0.725, 0.834→0.733).
    let all_rows =
        MassFunctionRepository::get_for_claim_binary_frames(&mut *conn, viewer, claim_id)
            .await
            .map_err(|e| format!("get_for_claim_binary_frames: {e}"))?;

    // Phase 2 (issue #197): the combine path no longer trusts the
    // stored `source_strength` as the authority. Reliability is derived
    // dynamically from (`evidence_type`, `locality_tag`) under the belief
    // profile the recompute path resolves: the served profile (calibration,
    // or its load-failure fallback) with this frame's overrides. See
    // `epigraph_engine::edge_factor::effective_source_strength_profiled`.
    let per_frame_intra =
        optional_read_under_savepoint(&mut *conn, "intra_evidence_locality_factor", |c| {
            Box::pin(FrameRepository::get_intra_evidence_locality_factor(
                c, frame_id,
            ))
        })
        .await?;

    // Phase 4 (issue #197): per-frame evidence-type weight override map.
    // When set, its keyed entries win over the global calibration table
    // at Tier 1 of `effective_source_strength`. Loaded once above the
    // combine loop. On any DB error we fall through to `None`, under a
    // savepoint so the error cannot abort a caller's transaction.
    let per_frame_evidence_weights =
        optional_read_under_savepoint(&mut *conn, "evidence_type_weights", |c| {
            Box::pin(FrameRepository::get_per_frame_evidence_type_weights(
                c, frame_id,
            ))
        })
        .await?;

    // The monotonicity clamp's prior. Supporting evidence must never lower
    // BetP: high-conflict K between legacy mixed-format BBAs (m({0})>0 AND
    // m({1})>0) and a new pure-support BBA can reduce pignistic_prob even when
    // supports=true, so the result is bounded from below by the pre-addition
    // value: the cached `pignistic_prob`, or the authored `truth_value` when the
    // claim has no cache (backlog fc55465b: with no fallback the clamp never
    // fired on exactly the claims whose prior was otherwise discarded).
    let prior_betp: Option<f64> = claim_prior.map(|(cached, truth, _)| cached.unwrap_or(truth));

    // The second value is the conflict the fold SAW. Since U025 every
    // `combine_multiple` step is Dempster, which normalises conflict out of
    // the combined mass, so the multi-BBA arm reads it from the per-step
    // reports (`aggregate_conflict`), exactly as the recompute path
    // (`edge_factor::compute_combined_belief`) does; otherwise this write and
    // the next recompute would disagree on `claims.mass_on_empty`.
    //
    // Discount each BBA via the helper, then combine through the SAME
    // function the recompute path uses (`edge_factor::compute_combined_belief`):
    // BBAs from one agent re-reading one `source_url` are folded cautiously into
    // one before the Dempster fold, so a re-worded re-observation of an
    // unchanged source no longer counts as corroboration (backlog 4c42c0bf).
    // Rows with no source identity fold exactly as before.
    let source_keys =
        epigraph_engine::source_dependence::source_keys_for_rows(&mut *conn, viewer, &all_rows)
            .await
            .map_err(|e| format!("evidence source_url read: {e}"))?;
    let mut items = Vec::with_capacity(all_rows.len());
    let frame_overrides = frame_profile_overrides(&mut *conn, viewer, frame_id).await?;
    let profile = resolve_frame_profile(
        frame_overrides.as_ref(),
        per_frame_intra,
        per_frame_evidence_weights.as_ref(),
    );
    for (row, key) in all_rows.iter().zip(source_keys) {
        let mf = parse_stored_bba(&frame, &row.masses)?;
        let reliability = effective_source_strength_profiled(row, &profile);
        let discounted =
            combination::discount(&mf, reliability).map_err(|e| format!("discount: {e}"))?;
        items.push((key, discounted));
    }
    let (combined, fold_conflict) =
        epigraph_engine::source_dependence::combine_with_source_dependence(
            items,
            profile.combination.conflict_threshold,
        )
        .map_err(|e| format!("combine_multiple: {e}"))?;

    let (bel, pl, mut betp, _, missing) = compute_measures(&combined);
    let conflict = fold_conflict;

    // Monotonicity clamp: supports=true evidence must not lower pignistic_prob.
    //
    // Bounded by plausibility (backlog 0183a294). The prior is read from
    // `claims.pignistic_prob`, which may itself be an inflated value left by an
    // earlier write, so raising `betp` to it unconditionally persisted
    // `pignistic_prob > plausibility` — a triple no mass function can represent,
    // and one Postgres accepts because `claims_plausibility_bounds` is a [0,1]
    // range check with no Bel <= BetP <= Pl ordering constraint.
    //
    // Where monotonicity and the DS bound conflict, the bound wins: a BetP above
    // plausibility is not a weaker guarantee, it is an impossible one. Clamping
    // to `prior.min(pl)` keeps 30bfbb19's intent wherever the prior is
    // representable, and yields to `pl` only when it is not.
    if supports {
        if let Some(prior) = prior_betp {
            let bounded_prior = prior.min(pl);
            if betp < bounded_prior {
                betp = bounded_prior;
            }
        }
    }

    let cache_written = MassFunctionRepository::update_claim_belief(
        &mut *conn,
        claim_id,
        epigraph_db::CachedBelief {
            belief: bel,
            plausibility: pl,
            mass_on_empty: conflict,
            pignistic_prob: Some(betp),
            mass_on_missing: missing,
            belief_frame_id: Some(frame_id),
        },
    )
    .await
    .map_err(|e| format!("update_claim_belief: {e}"))?;

    Ok(DsAutoResult {
        belief: bel,
        plausibility: pl,
        pignistic_prob: betp,
        mass_on_conflict: conflict,
        mass_on_missing: missing,
        frame_id,
        cache_written,
    })
}

/// Auto-wire DS for a **batch** of new claims (used by ingestion).
///
/// Resolves the binary frame once and each declared axis frame once (cached by
/// name), then wires each claim sequentially. Individual failures are logged and
/// skipped.
///
/// The returned `Uuid` is the `binary_truth` frame — the batch's default frame,
/// and what `ds_frame_id` on the ingest response has always meant. Claims placed
/// on a declared axis (issue #222) are wired on their own frame; read those back
/// per claim via `claim_frames` rather than from this single id.
pub async fn auto_wire_ds_batch(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    entries: &[BatchDsEntry],
    agent_id: Uuid,
) -> Result<(Uuid, usize), String> {
    if entries.is_empty() {
        return Err("empty batch".to_string());
    }

    let binary_frame_id = ensure_binary_frame(&mut *conn, viewer).await?;
    let binary = binary_frame()?;
    // Axis frames resolved on first use, keyed by frame name. Keeps a sweep of N
    // atoms on one axis to a single get-or-create round trip, as the binary path
    // has always had.
    let mut axis_frames: std::collections::HashMap<String, (Uuid, FrameOfDiscernment)> =
        std::collections::HashMap::new();
    let mut wired = 0_usize;

    for entry in entries {
        let resolved = match &entry.axis {
            None => Ok((binary_frame_id, binary.clone(), 0_usize)),
            Some(axis) => match axis_frames.get(&axis.frame) {
                Some((id, frame)) => Ok((*id, frame.clone(), axis.hypothesis_index)),
                None => {
                    match ensure_axis_frame(&mut *conn, viewer, &axis.frame, &axis.hypotheses, None)
                        .await
                    {
                        Err(e) => Err(e),
                        Ok(id) => match axis_frame(&axis.frame, &axis.hypotheses) {
                            Err(e) => Err(e),
                            Ok(frame) => {
                                axis_frames.insert(axis.frame.clone(), (id, frame.clone()));
                                Ok((id, frame, axis.hypothesis_index))
                            }
                        },
                    }
                }
            },
        };
        let (frame_id, frame, idx) = match resolved {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    claim_id = %entry.claim_id,
                    "ds_auto batch skip (axis frame): {e}"
                );
                continue;
            }
        };

        // SAVEPOINT PER ENTRY, and it is not hygiene. This loop's contract is
        // "individual failures are logged and skipped", which was expressible as a
        // swallowed error only while every statement ran on its own pool checkout.
        // Now that the caller can hand us a TRANSACTION, a swallowed failure does
        // not skip the entry — it aborts the whole transaction, so every later
        // entry fails with `25P02 current transaction is aborted` and the eventual
        // COMMIT is answered with ROLLBACK and NO ERROR. The tool would report a
        // wired count having written nothing. A savepoint keeps the documented
        // behaviour: the failing entry is rolled back alone and the rest proceed.
        let mut sp = match conn.begin().await {
            Ok(sp) => sp,
            Err(e) => {
                tracing::warn!(
                    claim_id = %entry.claim_id,
                    "ds_auto batch skip (no savepoint; the caller's transaction is already \
                     unusable): {e}"
                );
                break;
            }
        };
        match wire_single_batch_entry(&mut sp, viewer, &frame, frame_id, idx, entry, agent_id).await
        {
            Ok(()) => match sp.commit().await {
                Ok(()) => wired += 1,
                Err(e) => tracing::warn!(
                    claim_id = %entry.claim_id,
                    "ds_auto batch entry computed but its savepoint could not be released: {e}"
                ),
            },
            Err(e) => {
                tracing::warn!(
                    claim_id = %entry.claim_id,
                    "ds_auto batch skip: {e}"
                );
                if let Err(e) = sp.rollback().await {
                    tracing::warn!("ds_auto batch: savepoint rollback failed: {e}");
                    break;
                }
            }
        }
    }

    Ok((binary_frame_id, wired))
}

/// Wire a single claim in a batch context (frame already resolved).
///
/// `hypothesis_index` is the hypothesis the claim asserts — 0 (TRUE) on the
/// binary frame, or the declared label's index on an axis (issue #222). It is
/// both the BBA's focal element and the `claim_frames.hypothesis_index` the
/// belief readers target.
async fn wire_single_batch_entry(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    frame: &FrameOfDiscernment,
    frame_id: Uuid,
    hypothesis_index: usize,
    entry: &BatchDsEntry,
    agent_id: Uuid,
) -> Result<(), String> {
    let bba = build_bba_on_index(frame, entry.confidence, entry.weight, hypothesis_index)?;
    let masses_json = mass_to_json(&bba)?;

    let idx_i32 = i32::try_from(hypothesis_index)
        .map_err(|_| format!("hypothesis_index {hypothesis_index} out of range"))?;
    FrameRepository::assign_claim(&mut *conn, entry.claim_id, frame_id, Some(idx_i32))
        .await
        .map_err(|e| format!("assign_claim: {e}"))?;

    // Ingest normalizes its tags already; canonicalize anyway so no batch
    // caller can store a non-canonical spelling (bc06ec6f).
    let evidence_type =
        epigraph_engine::calibration::canonical_evidence_type(entry.evidence_type.as_deref());
    MassFunctionRepository::store_with_perspective(
        &mut *conn,
        entry.claim_id,
        frame_id,
        Some(agent_id),
        None,
        &masses_json,
        None,
        Some("auto_wire"),
        Some(entry.weight), // source_strength = methodology weight (legacy fallback when evidence_type is None)
        evidence_type.as_deref(), // evidence_type → effective_source_strength / frame function
        "unknown",          // batch ds_auto path; no per-entry locality (issue #197)
        None,               // batch path predates per-claim evidence rows (issue #197 Phase 3)
    )
    .await
    .map_err(|e| format!("store BBA: {e}"))?;

    // BetP-drop fix (backlog b3d12e2a): the initial cache MUST be written
    // through the same discount authority every other writer uses. Calling
    // compute_measures(&bba) on the raw, UNDISCOUNTED BBA here recorded an
    // inflated m({TRUE})/BetP; the first `update_with_evidence` then re-read
    // all rows, re-discounted this one by `effective_source_strength`
    // (e.g. statistical=0.9, circumstantial=0.4, unknown=0.5) and recombined
    // from scratch, dropping the cached BetP even though a SUPPORTING source
    // was just added (observed 0.848 -> 0.716). Routing through the canonical
    // recombine makes the initial cache agree with auto_wire_ds_update and
    // recompute_beliefs. `recompute_claim_belief_on_frame` re-reads the row we
    // just stored, applies `effective_source_strength`, and writes Bel/Pl/BetP
    // (and, on the binary frame, classification) via update_claim_belief.
    epigraph_engine::edge_factor::recompute_claim_belief_on_frame(
        &mut *conn,
        viewer,
        entry.claim_id,
        frame_id,
    )
    .await
    .map_err(|e| format!("recompute initial cache: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn potency_frame() -> FrameOfDiscernment {
        axis_frame(
            "anxiolytic_potency",
            &[
                "ineffective".to_string(),
                "mild".to_string(),
                "moderate".to_string(),
                "strong".to_string(),
            ],
        )
        .expect("4-hypothesis frame")
    }

    /// The generalized builder must reproduce the binary builder exactly on the
    /// binary frame — the backward-compatibility guarantee for issue #222.
    #[test]
    fn binary_builder_is_the_index_builder_at_0_and_1() {
        let frame = binary_frame().expect("binary frame");
        for (supports, idx) in [(true, 0_usize), (false, 1_usize)] {
            let via_binary = build_binary_bba(&frame, 0.8, 0.9, supports).expect("binary BBA");
            let via_index = build_bba_on_index(&frame, 0.8, 0.9, idx).expect("indexed BBA");
            assert_eq!(
                mass_to_json(&via_binary).expect("json"),
                mass_to_json(&via_index).expect("json"),
                "supports={supports} must equal index {idx}"
            );
        }
    }

    /// Mass lands on the DECLARED hypothesis, with the remainder on Θ — the same
    /// simple-support shape the binary path uses, just aimed elsewhere.
    #[test]
    fn axis_bba_places_mass_on_the_declared_index() {
        let frame = potency_frame();
        let bba = build_bba_on_index(&frame, 0.8, 0.9, 2).expect("BBA on 'moderate'");
        let expected = (0.8_f64 * 0.9).clamp(0.01, 0.99);

        let on_moderate = bba.mass_of(&FocalElement::positive(BTreeSet::from([2_usize])));
        assert!(
            (on_moderate - expected).abs() < 1e-12,
            "m({{moderate}}) = {on_moderate}, want {expected}"
        );
        // Nothing on the sibling hypotheses: a claim placed on `moderate` asserts
        // nothing about `mild` or `strong` beyond the shared ignorance mass.
        for other in [0_usize, 1, 3] {
            let m = bba.mass_of(&FocalElement::positive(BTreeSet::from([other])));
            assert!(m.abs() < 1e-12, "unexpected mass {m} on hypothesis {other}");
        }
        let theta = bba.mass_of(&FocalElement::theta(&frame));
        assert!(
            (theta - (1.0 - expected)).abs() < 1e-12,
            "remainder must sit on Theta, got {theta}"
        );
    }

    /// The crux of the correctness argument: measures must be read at the
    /// declared index. Reading index 0 for a claim placed on `moderate` reports
    /// belief in `ineffective`.
    #[test]
    fn measures_at_the_declared_index_differ_from_index_zero() {
        let frame = potency_frame();
        let bba = build_bba_on_index(&frame, 0.9, 1.0, 2).expect("BBA on 'moderate'");

        let (bel_at_2, _, betp_at_2, _, _) = compute_measures_on_index(&bba, 2);
        let (bel_at_0, _, betp_at_0, _, _) = compute_measures_on_index(&bba, 0);

        assert!(
            (bel_at_2 - 0.9).abs() < 1e-12,
            "Bel(moderate) should be the asserted mass, got {bel_at_2}"
        );
        assert!(
            bel_at_0.abs() < 1e-12,
            "Bel(ineffective) must be 0 — nothing was asserted about it, got {bel_at_0}"
        );
        assert!(
            betp_at_2 > betp_at_0,
            "BetP(moderate)={betp_at_2} must exceed BetP(ineffective)={betp_at_0}"
        );
    }

    /// `compute_measures` (the binary entry point) must stay identical to the
    /// generalized form at index 0, so no existing caller changes behaviour.
    #[test]
    fn compute_measures_is_index_zero() {
        let frame = binary_frame().expect("binary frame");
        let bba = build_binary_bba(&frame, 0.7, 0.8, true).expect("BBA");
        assert_eq!(compute_measures(&bba), compute_measures_on_index(&bba, 0));
    }

    /// Every hypothesis on the axis is reachable, including the last index —
    /// guards an off-by-one in the label→index resolution.
    #[test]
    fn every_hypothesis_index_is_addressable() {
        let frame = potency_frame();
        for idx in 0..4_usize {
            let bba = build_bba_on_index(&frame, 0.6, 1.0, idx).expect("BBA");
            let (bel, _, _, _, _) = compute_measures_on_index(&bba, idx);
            assert!((bel - 0.6).abs() < 1e-12, "index {idx} gave Bel {bel}");
        }
    }

    /// An index outside the frame is a construction error, not a silent
    /// placement on some other hypothesis.
    #[test]
    fn out_of_range_index_is_an_error() {
        let frame = potency_frame();
        assert!(build_bba_on_index(&frame, 0.5, 1.0, 4).is_err());
    }

    /// Division of responsibility: `FrameOfDiscernment::new` only rejects an
    /// EMPTY frame (and silently dedupes), so the "at least 2 distinct
    /// hypotheses" contract is enforced upstream by
    /// `epigraph_ingest::document::axis` validation, not here. This pins that
    /// split so a future reader does not assume the DS layer guards it.
    #[test]
    fn axis_frame_rejects_only_the_empty_frame() {
        assert!(axis_frame("empty", &[]).is_err());
        // A degenerate 1-hypothesis frame is accepted at this layer...
        assert!(axis_frame("solo", &["only".to_string()]).is_ok());
        // ...and rejected by the ingest-side validator that callers go through.
        let decl = epigraph_ingest::document::schema::AxisDeclaration {
            frame: "solo".to_string(),
            hypotheses: vec!["only".to_string()],
            label: "only".to_string(),
        };
        let para = epigraph_ingest::document::schema::Paragraph {
            text: "p".to_string(),
            span: None,
            atoms: vec!["a".to_string()],
            generality: Vec::new(),
            confidence: 0.8,
            methodology: None,
            evidence_type: None,
            axis: Some(decl),
            axis_labels: Vec::new(),
            page: None,
            instruments_used: Vec::new(),
            reagents_involved: Vec::new(),
            conditions: Vec::new(),
        };
        let section = epigraph_ingest::document::schema::Section {
            title: "s".to_string(),
            heading_span: None,
            axis: None,
            paragraphs: vec![],
        };
        assert!(
            epigraph_ingest::document::axis::resolve_paragraph_axes(&para, &section).is_err(),
            "the ingest-side validator must reject a 1-hypothesis axis"
        );
    }

    /// Mass is clamped into [0.01, 0.99] on an axis exactly as on the binary
    /// frame, so a 0-confidence or 1.0-confidence claim stays combinable.
    #[test]
    fn axis_mass_is_clamped_like_the_binary_path() {
        let frame = potency_frame();
        let lo = build_bba_on_index(&frame, 0.0, 1.0, 1).expect("BBA");
        let hi = build_bba_on_index(&frame, 1.0, 1.0, 1).expect("BBA");
        let m = |b: &MassFunction| b.mass_of(&FocalElement::positive(BTreeSet::from([1_usize])));
        assert!((m(&lo) - 0.01).abs() < 1e-12, "got {}", m(&lo));
        assert!((m(&hi) - 0.99).abs() < 1e-12, "got {}", m(&hi));
    }
}
