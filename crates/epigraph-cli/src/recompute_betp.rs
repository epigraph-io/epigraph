//! Backfill stale cached `claims.pignistic_prob` (and `belief`,
//! `plausibility`, `conflict_k`, `mass_on_missing`) on the cohort of claims
//! whose combined belief was last written under the superseded
//! raw-`source_strength` model, before issue #197's dynamic
//! `effective_source_strength` derivation (evidence_type + locality +
//! per-frame override + calibration) existed.
//!
//! Backlog claim f2521c53-86bb-4b3b-96b4-a5cc963f8015.
//!
//! Reuses the canonical recompute entry point
//! (`epigraph_engine::edge_factor::recompute_claim_belief_on_frame` /
//! `preview_claim_belief_on_frame`) rather than re-deriving discount+combine
//! logic — see `crates/epigraph-cli/src/bin/recompute_claim_belief.rs` for
//! the established per-claim, per-frame pattern this module mirrors.

use sqlx::PgPool;
use uuid::Uuid;

/// Cohort SQL: claims whose cached BetP is due for a refresh under the
/// current (dynamic reliability) combine pipeline.
///
/// Two disjoint populations, unioned:
///
/// (a) **Multi-BBA hub claims** — claims with more than one BBA on the same
///     2-hypothesis ("binary") frame. `frames.hypotheses` array-length
///     scoping matches `MassFunctionRepository::get_for_claim_binary_frames`
///     (the established "is this a binary frame" query in this codebase).
///     These need a fresh Dempster combination across sources because the
///     per-BBA reliability weight feeding the combine changed model
///     (issue #197 Phase 2/4) since the cached value was last written.
///
/// (b) **Single-BBA non-simple-shape claims** — claims with exactly one BBA
///     on a binary frame whose `masses` JSONB contains a focal-element key
///     of `"1"` (mass on the non-supported hypothesis alone) or `"~"`
///     (open-world/complement mass on the empty set). Both are focal-element
///     shapes beyond the simple `{"0", "0,1"}` case a raw single-source
///     discount was originally calibrated against.
///
/// `UNION` (not `UNION ALL`) so a claim that happens to satisfy both (a) and
/// (b) — a hub claim where one of its BBAs also has a "~" key — is not
/// double-counted or double-processed by the caller.
pub async fn select_cohort(pool: &PgPool) -> Result<Vec<Uuid>, sqlx::Error> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT claim_id FROM (
            -- (a) multi-BBA hub claims: >1 BBA on the same binary frame.
            SELECT mf.claim_id
              FROM mass_functions mf
              JOIN frames f ON f.id = mf.frame_id
             WHERE array_length(f.hypotheses, 1) = 2
             GROUP BY mf.claim_id, mf.frame_id
            HAVING COUNT(*) > 1

            UNION

            -- (b) single-BBA claims on a binary frame whose stored masses
            -- contain a non-simple focal-element key: a lone "1" (mass on
            -- the non-supported hypothesis by itself) or "~" (open-world /
            -- complement mass on the empty set). The `?` operator is exact
            -- top-level-key containment, so `masses ? '~'` matches only the
            -- bare "~" key, not "~0" / "~0,1" / "~1".
            SELECT mf.claim_id
              FROM mass_functions mf
              JOIN frames f ON f.id = mf.frame_id
             WHERE array_length(f.hypotheses, 1) = 2
               AND (mf.masses ? '1' OR mf.masses ? '~')
             GROUP BY mf.claim_id, mf.frame_id
            HAVING COUNT(*) = 1
        ) cohort
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Discover every distinct `frame_id` a claim has BBAs on, ordered by the
/// frame's name. Identical query to
/// `recompute_claim_belief.rs::recompute_one_claim_all_frames`'s frame
/// discovery — kept in lock-step so both operator binaries process a
/// claim's frames in the same deterministic order (matters because
/// `claims.{belief, pl, betp, ...}` are frame-agnostic scalars — last
/// writer wins across frames).
async fn claim_frames(pool: &PgPool, claim_id: Uuid) -> Result<Vec<Uuid>, String> {
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT DISTINCT mf.frame_id, f.name \
           FROM mass_functions mf \
           JOIN frames f ON f.id = mf.frame_id \
          WHERE mf.claim_id = $1 \
          ORDER BY f.name",
    )
    .bind(claim_id)
    .fetch_all(pool)
    .await
    .map_err(|e| format!("list frames for claim: {e}"))?;
    Ok(rows.into_iter().map(|(frame_id, _name)| frame_id).collect())
}

/// Dry-run half: preview the recomputed belief for every frame this claim
/// has BBAs on, without writing anything. Returns `(frame_id, preview)`
/// pairs in the same frame-name order `run_claim` would write them, so a
/// caller can print "last one wins" alongside each candidate.
///
/// # Errors
/// Propagates any error from the frame-discovery query or from
/// `epigraph_engine::edge_factor::preview_claim_belief_on_frame`.
pub async fn preview_claim(
    pool: &PgPool,
    claim_id: Uuid,
) -> Result<Vec<(Uuid, epigraph_engine::edge_factor::CombinedBeliefPreview)>, String> {
    let frames = claim_frames(pool, claim_id).await?;
    let mut out = Vec::with_capacity(frames.len());
    for frame_id in frames {
        if let Some(preview) =
            epigraph_engine::edge_factor::preview_claim_belief_on_frame(pool, claim_id, frame_id)
                .await?
        {
            out.push((frame_id, preview));
        }
    }
    Ok(out)
}

/// Real-write half: recompute and persist the belief for every frame this
/// claim has BBAs on, via the canonical
/// `epigraph_engine::edge_factor::recompute_claim_belief_on_frame` write
/// path (the same one `recompute_claim_belief.rs` uses). Returns the number
/// of (claim, frame) pairs that produced a write.
///
/// # Errors
/// Propagates any error from the frame-discovery query or from the engine's
/// recompute-and-write call.
pub async fn run_claim(pool: &PgPool, claim_id: Uuid) -> Result<usize, String> {
    let frames = claim_frames(pool, claim_id).await?;
    let mut written = 0usize;
    for frame_id in frames {
        let did =
            epigraph_engine::edge_factor::recompute_claim_belief_on_frame(pool, claim_id, frame_id)
                .await?;
        if did {
            written += 1;
        }
    }
    Ok(written)
}
