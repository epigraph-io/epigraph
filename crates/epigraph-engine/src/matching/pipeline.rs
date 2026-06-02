//! Pipeline orchestrator for the cross-source matcher.
//!
//! Wires blocker → scorer → band classification → verifier → policy.
//! See `docs/superpowers/specs/2026-05-21-cross-source-matching-design.md` §3.

use crate::matching::blocker::{
    compound_nbhd::CompoundNbhdBlocker, content_hash_prefix::ContentHashBlocker,
    embedding_ann::EmbeddingAnnBlocker, shared_triple::SharedTripleBlocker,
    theme_cluster::ThemeClusterBlocker, union_block, Blocker,
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
}

pub async fn run_pipeline(pool: &PgPool, inputs: RunInputs) -> anyhow::Result<RunReport> {
    let run_id = Uuid::new_v4();
    let fan_out = inputs.cfg.fan_out.max_per_claim;
    let blockers: Vec<Box<dyn Blocker>> = vec![
        Box::new(EmbeddingAnnBlocker::new(fan_out)),
        Box::new(ThemeClusterBlocker::new(fan_out)),
        Box::new(CompoundNbhdBlocker::new(fan_out)),
        Box::new(SharedTripleBlocker::new(fan_out)),
        Box::new(ContentHashBlocker),
    ];
    let pairs = union_block(pool, &blockers, &inputs.seeds, inputs.cfg.filter).await?;

    let mut promoted = 0usize;
    let mut mid_band = 0usize;
    let mut rejected = 0usize;
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
        if f.score >= inputs.cfg.bands.mid {
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
                "verifier returned {} verdicts for {} pairs — alignment violated",
                verdicts.len(),
                mid_pairs.len()
            );
        }
        for ((pair, verdict), features) in mid_pairs.into_iter().zip(verdicts).zip(mid_features) {
            mid_band += 1;
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
    })
}
