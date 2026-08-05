//! Policy layer: turn a scored/verified pair into rows + edges.
//!
//! See `docs/superpowers/specs/2026-05-21-cross-source-matching-design.md` §6
//! (state machine) and §7 (CORROBORATES edges). The pipeline classifies each
//! pair into [`PolicyAction`] and hands it off here; this module is the
//! single point where match_candidate rows and edge inserts happen so the
//! state machine stays auditable.

use crate::matching::scorer::MatchFeatures;
use crate::matching::verifier::{
    map_relationship, Verdict, CONTRADICTS_RELATIONSHIP, CORROBORATES_RELATIONSHIP,
};
use epigraph_db::repos::match_candidate::MatchCandidateRepo;
use epigraph_db::EdgeRepository;
use sqlx::PgPool;
use std::sync::atomic::{AtomicUsize, Ordering};
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub enum PolicyAction {
    AutoPromote,
    WriteContradicts,
    Reject,
}

pub struct Policy {
    pool: PgPool,
    repo: MatchCandidateRepo,
    run_id: Uuid,
    auto_promote: bool,
    /// Count of verdict writes the `decided_at` gate refused. See
    /// [`Policy::verdict_writes_suppressed`].
    suppressed: AtomicUsize,
}

impl Policy {
    pub fn new(pool: PgPool, repo: MatchCandidateRepo, run_id: Uuid, auto_promote: bool) -> Self {
        Self {
            pool,
            repo,
            run_id,
            auto_promote,
            suppressed: AtomicUsize::new(0),
        }
    }

    /// How many times this run tried to rewrite the verdict of an
    /// already-decided candidate and was refused.
    ///
    /// This is deliberately surfaced rather than silently dropped. Before the
    /// gate, every such overwrite left a trace in `verifier_rationale` — which
    /// is how the 123 corrupted prod rows were found at all. Gating the
    /// rationale destroys that detector, so this counter is its replacement,
    /// not a nicety: a nonzero value means the verifier is re-scoring pairs a
    /// human has already ruled on.
    pub fn verdict_writes_suppressed(&self) -> usize {
        self.suppressed.load(Ordering::Relaxed)
    }

    /// Upsert the candidate row, recording a suppressed verdict write.
    async fn upsert_candidate(
        &self,
        lo: Uuid,
        hi: Uuid,
        f: &MatchFeatures,
        features_json: serde_json::Value,
        status: &str,
        verdict: Option<&Verdict>,
    ) -> anyhow::Result<Uuid> {
        // Persist the matcher-level vocabulary (`same|paraphrase|overlapping|
        // contradicts|distinct`) per spec §5, NOT the raw reranker relationship
        // string. The raw string is preserved in edge properties for debug.
        let column_verdict =
            verdict.map(|v| map_relationship(&v.relationship, v.strength).as_column_str());
        let outcome = self
            .repo
            .upsert(
                lo,
                hi,
                f.score,
                features_json,
                status,
                Some(self.run_id),
                column_verdict,
                verdict.map(|v| v.rationale.as_str()),
            )
            .await?;
        if outcome.verdict_write_suppressed(column_verdict) {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                candidate_id = %outcome.id,
                run_id = %self.run_id,
                attempted = column_verdict.unwrap_or("-"),
                retained = outcome.verifier_verdict.as_deref().unwrap_or("-"),
                "verdict write suppressed: candidate already decided",
            );
        }
        Ok(outcome.id)
    }

    pub async fn act(
        &self,
        action: PolicyAction,
        a: Uuid,
        b: Uuid,
        f: &MatchFeatures,
        verdict: Option<Verdict>,
    ) -> anyhow::Result<()> {
        // Canonicalize: match_candidates has a CHECK (claim_a < claim_b).
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };

        // Verifier verdict + rationale are persisted on the row so we don't
        // re-ask the LLM (spec §4, "Verdict and rationale stored on the match-
        // candidate row; never re-asked"). They go through
        // `MatchCandidateRepo::upsert` in the SAME statement as `status`, so
        // the `decided_at` guard covers the decision as a whole. Do not
        // reintroduce a follow-up UPDATE here: an out-of-band verdict write is
        // exactly the defect this replaced.
        let features_json = serde_json::to_value(f)?;

        // `auto_promote` gates BOTH the edge write (below) AND whether the
        // candidate is committed (`promoted`) or staged for human review
        // (`pending`). Before this, `auto_promote=false` left the row as
        // `promoted` with no edge — a half-state — and the `pending` review
        // queue (`decide_match_candidate`, `MatchCandidateRepo::list_pending`,
        // the API `pending[]` array) had no producer at all, so the whole
        // human-review surface was dead in normal operation.
        let promote_status = if self.auto_promote {
            "promoted"
        } else {
            "pending"
        };

        match action {
            PolicyAction::AutoPromote => {
                let id = self
                    .upsert_candidate(lo, hi, f, features_json, promote_status, verdict.as_ref())
                    .await?;
                if self.auto_promote {
                    self.write_edge(a, b, CORROBORATES_RELATIONSHIP, f, id, verdict.as_ref())
                        .await?;
                }
            }
            PolicyAction::WriteContradicts => {
                let id = self
                    .upsert_candidate(lo, hi, f, features_json, promote_status, verdict.as_ref())
                    .await?;
                if self.auto_promote {
                    // Lowercase 'contradicts' — the directional factor graph
                    // maps it to mutual_exclusion with strength 0. Shared with
                    // the human-decide path (`decide_candidate` /
                    // `decide_match_candidate`) via the constant so the two
                    // producers of this edge cannot drift on casing; edge dedup
                    // compares the relationship string exactly.
                    self.write_edge(a, b, CONTRADICTS_RELATIONSHIP, f, id, verdict.as_ref())
                        .await?;
                }
            }
            PolicyAction::Reject => {
                self.upsert_candidate(lo, hi, f, features_json, "rejected", verdict.as_ref())
                    .await?;
            }
        }
        Ok(())
    }

    /// Insert a claim→claim edge, skipping if the same relationship already
    /// connects the two claims in either direction. Delegates the dedup SQL to
    /// [`EdgeRepository::create_symmetric_if_absent`] so the bidirectional
    /// `WHERE NOT EXISTS` form lives in one place. Migrations 017/018 dropped
    /// the unique triple index, so the explicit existence check (not
    /// `ON CONFLICT`) is what prevents duplicates on re-run.
    async fn write_edge(
        &self,
        a: Uuid,
        b: Uuid,
        relationship: &str,
        f: &MatchFeatures,
        candidate_id: Uuid,
        v: Option<&Verdict>,
    ) -> anyhow::Result<()> {
        let props = serde_json::json!({
            "matcher_run_id":     self.run_id,
            "score":              f.score,
            "features":           f,
            "candidate_id":       candidate_id,
            "verifier_verdict":   v.map(|x| &x.relationship),
            "verifier_rationale": v.map(|x| &x.rationale),
            "source":             "cross_source_matcher",
        });
        EdgeRepository::create_symmetric_if_absent(&self.pool, a, b, relationship, props).await?;
        Ok(())
    }
}
