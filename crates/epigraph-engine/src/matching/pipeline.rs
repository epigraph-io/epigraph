//! Pipeline orchestrator for the cross-source matcher.
//!
//! Wires blocker → scorer → band classification → verifier → policy.
//! See `docs/superpowers/specs/2026-05-21-cross-source-matching-design.md` §3.
//!
//! Two entry points share the blocking and scoring stages:
//!
//! - [`run_pipeline`] — the full sweep, driven by the `cross_source_sweep` CLI.
//!   Every mid-or-above pair goes through the LLM verifier and the resulting
//!   verdict decides promote / contradicts / reject.
//! - [`stage_candidates`] — blocking + scoring ONLY. It writes `status='pending'`
//!   rows with `verifier_verdict IS NULL`, writes NO edges, spends NO LLM
//!   tokens, and does NOT stamp `claims.last_match_scan_at` (stamping would
//!   hide unverified seeds from the nightly verifying sweep for 7 days). It
//!   exists so an agent over MCP can fill the human-review queue
//!   (`list_match_candidates` / `decide_match_candidate`) without a verifier
//!   client, which only `epigraph-cli` can construct.
//!
//! Both call [`default_blockers`] and [`stage_decision`] so the blocker set and
//! the mid-band boundary cannot drift between them.

use crate::matching::blocker::{
    compound_nbhd::CompoundNbhdBlocker, content_hash_prefix::ContentHashBlocker,
    embedding_ann::EmbeddingAnnBlocker, shared_triple::SharedTripleBlocker,
    theme_cluster::ThemeClusterBlocker, union_block, Blocker, CandidatePair,
};
use crate::matching::calibration::MatcherConfig;
use crate::matching::policy::{Policy, PolicyAction};
use crate::matching::scorer::{score_pair, MatchFeatures};
use crate::matching::verifier::{map_relationship, MatchVerdict, VerifierClient};
use epigraph_db::repos::match_candidate::MatchCandidateRepo;
use sqlx::PgPool;
use uuid::Uuid;

pub struct RunInputs {
    pub seeds: Vec<Uuid>,
    pub cfg: MatcherConfig,
    pub verifier: Box<dyn VerifierClient>,
    pub auto_promote: bool,
}

#[derive(Debug, Clone)]
pub struct RunReport {
    pub run_id: Uuid,
    pub scanned_pairs: usize,
    pub promoted: usize,
    /// Candidates staged as `pending` for human review (`auto_promote=false`).
    pub staged: usize,
    pub mid_band: usize,
    pub rejected: usize,
    /// Verdict writes the `decided_at` gate refused because a human had
    /// already ruled on the pair. Nonzero means the verifier is re-scoring
    /// decided candidates — see [`Policy::verdict_writes_suppressed`].
    pub verdict_writes_suppressed: usize,
    /// Pairs the verifier had **no answer** for (`verify` returned `None`).
    /// These are skipped outright — no candidate row, no verdict, no edge — so
    /// they are neither promoted, staged, nor rejected, and the other counters
    /// alone cannot account for them.
    ///
    /// **This is not an outage alarm.** A large, routine baseline is expected:
    /// the production verifier's pre-LLM candidate query filters out every pair
    /// already connected by an edge in either direction, while this pipeline
    /// applies no such filter, so on any re-run over an edge-dense corpus the
    /// structural `decomposes_to` / `section_follows` pairs land here as a
    /// matter of course. A rise here means "fewer pairs got a fresh answer",
    /// which is consistent with both a verifier problem and an already-linked
    /// corpus; this counter cannot tell them apart. Total verifier silence is
    /// alarmed at the seam that *can* tell them apart — see
    /// `epigraph_cli::matching_client::is_total_verifier_outage`.
    pub skipped_no_verdict: usize,
}

/// The blocker set every entry point runs. Factored out so the staging tool
/// and the nightly sweep cannot drift on which blockers generate candidates —
/// a divergence there would make the two paths disagree about what a "pair"
/// even is, silently.
fn default_blockers(fan_out: usize) -> Vec<Box<dyn Blocker>> {
    vec![
        Box::new(EmbeddingAnnBlocker::new(fan_out)),
        Box::new(ThemeClusterBlocker::new(fan_out)),
        Box::new(CompoundNbhdBlocker::new(fan_out)),
        Box::new(SharedTripleBlocker::new(fan_out)),
        Box::new(ContentHashBlocker),
    ]
}

/// What [`stage_candidates`] does with a scored pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageDecision {
    /// At or above the mid band — write a `pending` candidate row.
    Stage,
    /// Below the mid band — dropped entirely, exactly as [`run_pipeline`] drops
    /// its low band (spec §6 state machine: `[dropped]`).
    BelowBand,
}

/// Classify a scored pair against the mid band.
///
/// Pinned to the identical `>=` comparison [`run_pipeline`] uses when it routes
/// pairs to the verifier, so the two entry points classify the boundary the
/// same way. A NaN score falls to [`StageDecision::BelowBand`] because
/// `f32::NAN >= mid` is false — a degenerate `renormalized_score` must not
/// reach the review queue.
#[must_use]
pub fn stage_decision(score: f32, mid: f32) -> StageDecision {
    if score >= mid {
        StageDecision::Stage
    } else {
        StageDecision::BelowBand
    }
}

/// Truncate `pairs` to `max_pairs`, returning the kept pairs and how many were
/// dropped. `max_pairs == 0` means uncapped.
///
/// This is a COST GUARD, not a ranking. `union_block` returns pairs in sorted
/// canonical-uuid order, so truncation drops an ARBITRARY subset — not the
/// lowest-scoring one; scores do not exist yet at this point. Each surviving
/// pair costs 5 DB round-trips in `score_pair`, which is the whole reason the
/// cap exists. The drop count is returned so a partial scan is never silent:
/// callers must surface it.
fn cap_pairs(pairs: Vec<CandidatePair>, max_pairs: usize) -> (Vec<CandidatePair>, usize) {
    if max_pairs == 0 || pairs.len() <= max_pairs {
        return (pairs, 0);
    }
    let dropped = pairs.len() - max_pairs;
    let mut kept = pairs;
    kept.truncate(max_pairs);
    (kept, dropped)
}

pub async fn run_pipeline(pool: &PgPool, inputs: RunInputs) -> anyhow::Result<RunReport> {
    let run_id = Uuid::new_v4();
    let blockers = default_blockers(inputs.cfg.fan_out.max_per_claim);
    let pairs = union_block(
        pool,
        &blockers,
        &inputs.seeds,
        inputs.cfg.filter,
        &inputs.cfg.eligibility,
    )
    .await?;

    let mut promoted = 0usize;
    let mut mid_band = 0usize;
    let mut rejected = 0usize;
    let mut skipped_no_verdict = 0usize;
    let repo = MatchCandidateRepo::new(pool.clone());
    let policy = Policy::new(pool.clone(), repo, run_id, inputs.auto_promote);

    // First pass: score every pair, route by band. Mid-band goes to a queue
    // for the verifier so we batch its LLM call once.
    let mut mid_pairs: Vec<(Uuid, Uuid)> = Vec::new();
    let mut mid_features: Vec<MatchFeatures> = Vec::new();
    for (a, b) in &pairs {
        let f = score_pair(pool, *a, *b, &inputs.cfg.weights).await?;
        // Route BOTH high- and mid-band pairs through the verifier. The former
        // high-band fast path (`score >= bands.high`) auto-promoted to
        // CORROBORATES with NO verification, which silently corroborated
        // strongly-cosine but opposite-stance pairs — and missing-mass pairs
        // whose `belief_alignment` fell back to the neutral 0.5 — because the
        // contradiction check lives only in the verifier. Verifying the high
        // band closes that hole; the second-pass dispatch below promotes only
        // on Same/Paraphrase, writes `contradicts` on Contradicts, and rejects
        // otherwise. Cost: high-band pairs now incur one verifier call;
        // acceptable since `auto_promote` defaults off and a future
        // `belief_alignment`-gated fast-path can re-optimize the clear cases.
        if stage_decision(f.score, inputs.cfg.bands.mid) == StageDecision::Stage {
            mid_pairs.push((*a, *b));
            mid_features.push(f);
        } else {
            // Low band — not even recorded as a candidate (see spec §6 state
            // machine: [dropped]). Keep the rejected counter for telemetry.
            let _ = f;
            rejected += 1;
        }
    }

    // Second pass: verifier batch + policy dispatch for mid-band.
    if !mid_pairs.is_empty() {
        let verdicts = inputs.verifier.verify(&mid_pairs).await?;
        if verdicts.len() != mid_pairs.len() {
            anyhow::bail!(
                "verifier returned {} verdict slots for {} pairs — alignment violated",
                verdicts.len(),
                mid_pairs.len()
            );
        }
        for ((pair, slot), features) in mid_pairs.into_iter().zip(verdicts).zip(mid_features) {
            // `mid_band` counts pairs ROUTED to the verifier, including the
            // ones it had no answer for — it is the band-distribution
            // telemetry and must not move because verification failed.
            mid_band += 1;
            // No answer is not a verdict. Skip the pair completely: no upsert,
            // no `patch_verdict`, no edge. Whatever a previous run stored stays
            // stored. Writing anything here is the defect — the placeholder
            // that used to arrive in this slot mapped to `Distinct` and
            // overwrote real verdicts with `distinct`, which #382 then makes
            // permanently un-promotable.
            let Some(verdict) = slot else {
                skipped_no_verdict += 1;
                continue;
            };
            let mv = map_relationship(&verdict.relationship, verdict.strength);
            let (a, b) = pair;
            match mv {
                MatchVerdict::Same | MatchVerdict::Paraphrase => {
                    policy
                        .act(PolicyAction::AutoPromote, a, b, &features, Some(verdict))
                        .await?;
                    promoted += 1;
                }
                MatchVerdict::Contradicts => {
                    policy
                        .act(
                            PolicyAction::WriteContradicts,
                            a,
                            b,
                            &features,
                            Some(verdict),
                        )
                        .await?;
                    promoted += 1;
                }
                MatchVerdict::Overlapping | MatchVerdict::Distinct => {
                    policy
                        .act(PolicyAction::Reject, a, b, &features, Some(verdict))
                        .await?;
                    rejected += 1;
                }
            }
        }
    }

    // When not auto-promoting, every AutoPromote/WriteContradicts decision
    // above actually STAGED a `pending` candidate for human review (Policy
    // wrote `status='pending'` under the same `auto_promote` flag), so report
    // it honestly as `staged` rather than `promoted`.
    let (promoted, staged) = if inputs.auto_promote {
        (promoted, 0usize)
    } else {
        (0usize, promoted)
    };

    Ok(RunReport {
        run_id,
        scanned_pairs: pairs.len(),
        promoted,
        staged,
        mid_band,
        rejected,
        verdict_writes_suppressed: policy.verdict_writes_suppressed(),
        skipped_no_verdict,
    })
}

/// Inputs for [`stage_candidates`].
pub struct StageInputs {
    pub seeds: Vec<Uuid>,
    pub cfg: MatcherConfig,
    /// Cap on scored pairs; `0` means uncapped. See [`cap_pairs`] — truncation
    /// is arbitrary, not by score.
    pub max_pairs: usize,
    /// `false` performs the full blocking + scoring pass and reports what it
    /// *would* stage without writing any row.
    pub write: bool,
}

/// Outcome of [`stage_candidates`].
///
/// `blocked_pairs` = `truncated_pairs` + `already_present` + `scanned_pairs`,
/// and `scanned_pairs` = `staged` + `below_band` + `write_conflicts`.
#[derive(Debug, Clone)]
pub struct StageReport {
    pub run_id: Uuid,
    /// Pairs `union_block` produced, before the `max_pairs` cap.
    pub blocked_pairs: usize,
    /// Pairs actually sent through `score_pair`.
    pub scanned_pairs: usize,
    /// Pairs dropped by the `max_pairs` cap. Nonzero means a PARTIAL scan.
    pub truncated_pairs: usize,
    /// Rows this run created (in a dry run: would have created).
    pub staged: usize,
    pub below_band: usize,
    /// Pairs skipped before scoring because they already had a
    /// `match_candidates` row, in any status. See
    /// [`MatchCandidateRepo::existing_pairs`].
    pub already_present: usize,
    /// Pairs that cleared the band but whose insert found a row anyway — a
    /// concurrent writer created it between the `existing_pairs` read and the
    /// insert. Nonzero means two staging runs overlapped; nothing was
    /// overwritten either way. Always 0 in a dry run.
    pub write_conflicts: usize,
    /// Whether rows were actually written (`StageInputs::write`).
    pub wrote_rows: bool,
}

/// Run the blocking + scoring stages over `seeds` and stage the survivors as
/// `status='pending'` match candidates for human review.
///
/// **No verification happens here.** No `VerifierClient` is constructed, no LLM
/// token is spent, and the rows this writes carry `verifier_verdict IS NULL`
/// and `verifier_rationale IS NULL`. Never synthesise a `Verdict` or a
/// rationale string on this path: a rationale written by a path that asked no
/// model anything is the exact fabrication that produced the 12,006 bogus
/// `status='rejected'` rows documented at
/// `epigraph-cli/src/bin/cross_source_sweep.rs`.
///
/// It also does NOT stamp `claims.last_match_scan_at`. Staged rows carry no
/// verdict, so advancing the sweep window would hide unverified seeds from the
/// nightly verifying sweep for 7 days. Staging is therefore a *supplement* to
/// `cross_source_sweep`, never a substitute for it.
///
/// Staging is strictly ADDITIVE: a pair that already has a `match_candidates`
/// row is left byte-identical, in two layers. Pairs with an existing row are
/// filtered out before scoring ([`MatchCandidateRepo::existing_pairs`]), and
/// the write itself goes through `insert_if_absent` rather than `upsert`. Both
/// layers exist because overwriting a row here corrupts the review queue three
/// different ways — see that method's doc, and
/// [`PolicyAction::write_mode`] for the promotion inversion in particular. Do
/// not relax either one.
pub async fn stage_candidates(pool: &PgPool, inputs: StageInputs) -> anyhow::Result<StageReport> {
    let run_id = Uuid::new_v4();
    let blockers = default_blockers(inputs.cfg.fan_out.max_per_claim);
    let blocked = union_block(
        pool,
        &blockers,
        &inputs.seeds,
        inputs.cfg.filter,
        &inputs.cfg.eligibility,
    )
    .await?;
    let blocked_pairs = blocked.len();
    let (pairs, truncated_pairs) = cap_pairs(blocked, inputs.max_pairs);

    // One batched read for the whole capped list — not per-pair, which would
    // double this path's query count.
    let repo = MatchCandidateRepo::new(pool.clone());
    let existing = repo.existing_pairs(&pairs).await?;

    // `auto_promote = false` defensively: `PolicyAction::Stage` ignores the
    // flag, but a Policy built for a staging run should not be one flipped bit
    // away from committing edges.
    let policy = Policy::new(pool.clone(), repo, run_id, false);

    let mut scanned_pairs = 0usize;
    let mut staged = 0usize;
    let mut below_band = 0usize;
    let mut already_present = 0usize;
    let mut write_conflicts = 0usize;
    for (a, b) in pairs {
        if existing.contains(&(a, b)) {
            already_present += 1;
            continue;
        }
        let f = score_pair(pool, a, b, &inputs.cfg.weights).await?;
        scanned_pairs += 1;
        match stage_decision(f.score, inputs.cfg.bands.mid) {
            StageDecision::Stage => {
                if !inputs.write {
                    staged += 1;
                } else if policy.act(PolicyAction::Stage, a, b, &f, None).await? {
                    // `verdict: None` — nothing was asked, so nothing is
                    // reported.
                    staged += 1;
                } else {
                    // A concurrent writer got there first. `act` routes Stage
                    // through `insert_if_absent`, so that row is untouched.
                    write_conflicts += 1;
                }
            }
            StageDecision::BelowBand => below_band += 1,
        }
    }

    Ok(StageReport {
        run_id,
        blocked_pairs,
        scanned_pairs,
        truncated_pairs,
        staged,
        below_band,
        already_present,
        write_conflicts,
        wrote_rows: inputs.write,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(n: u128) -> CandidatePair {
        (Uuid::from_u128(n), Uuid::from_u128(n + 1_000))
    }

    /// Pins the `>=` boundary `run_pipeline` uses to route the mid band, so the
    /// staging entry point and the nightly sweep cannot drift on it.
    #[test]
    fn stage_decision_is_inclusive_at_the_mid_band() {
        assert_eq!(stage_decision(0.80, 0.80), StageDecision::Stage);
    }

    #[test]
    fn stage_decision_drops_scores_below_the_mid_band() {
        assert_eq!(stage_decision(0.7999, 0.80), StageDecision::BelowBand);
    }

    /// A degenerate `renormalized_score` must never reach the review queue.
    #[test]
    fn stage_decision_drops_nan_scores() {
        assert_eq!(stage_decision(f32::NAN, 0.80), StageDecision::BelowBand);
        assert_eq!(stage_decision(f32::NAN, 0.0), StageDecision::BelowBand);
    }

    #[test]
    fn cap_pairs_truncates_and_reports_the_drop_count() {
        let pairs: Vec<CandidatePair> = (0..10).map(pair).collect();
        let (kept, dropped) = cap_pairs(pairs, 4);
        assert_eq!(kept.len(), 4);
        assert_eq!(dropped, 6);
    }

    #[test]
    fn cap_pairs_is_a_noop_at_or_below_the_cap() {
        let exactly: Vec<CandidatePair> = (0..4).map(pair).collect();
        let (kept, dropped) = cap_pairs(exactly.clone(), 4);
        assert_eq!(kept, exactly);
        assert_eq!(dropped, 0);

        let under: Vec<CandidatePair> = (0..2).map(pair).collect();
        let (kept, dropped) = cap_pairs(under.clone(), 4);
        assert_eq!(kept, under);
        assert_eq!(dropped, 0);
    }

    #[test]
    fn cap_pairs_zero_means_uncapped() {
        let pairs: Vec<CandidatePair> = (0..10).map(pair).collect();
        let (kept, dropped) = cap_pairs(pairs.clone(), 0);
        assert_eq!(kept, pairs);
        assert_eq!(dropped, 0);
    }
}
