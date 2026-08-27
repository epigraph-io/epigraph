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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    AutoPromote,
    WriteContradicts,
    Reject,
    /// Record the pair as `pending` for human review; never writes an edge,
    /// never carries a verdict, and ignores `auto_promote`.
    ///
    /// This is the verifier-free entry point
    /// ([`crate::matching::pipeline::stage_candidates`]): blocking + scoring
    /// happened, no model was asked anything, so there is nothing to promote
    /// and nothing to reject. Anything stronger than "queue it for a human"
    /// would be a finding the pipeline did not make.
    Stage,
}

impl PolicyAction {
    /// The `match_candidates.status` this action writes.
    ///
    /// `auto_promote` gates BOTH the edge write ([`Self::edge_relationship`])
    /// AND whether the candidate is committed (`promoted`) or staged for human
    /// review (`pending`). Before this, `auto_promote=false` left the row as
    /// `promoted` with no edge — a half-state — and the `pending` review queue
    /// (`decide_match_candidate`, `MatchCandidateRepo::list_pending`, the API
    /// `pending[]` array) had no producer at all, so the whole human-review
    /// surface was dead in normal operation.
    ///
    /// [`PolicyAction::Stage`] ignores the flag: a pair nobody verified is
    /// never committed, however the run was configured.
    #[must_use]
    pub fn candidate_status(self, auto_promote: bool) -> &'static str {
        match self {
            PolicyAction::AutoPromote | PolicyAction::WriteContradicts => {
                if auto_promote {
                    "promoted"
                } else {
                    "pending"
                }
            }
            PolicyAction::Stage => "pending",
            PolicyAction::Reject => "rejected",
        }
    }

    /// The edge relationship this action commits, or `None` when it writes no
    /// edge at all.
    ///
    /// Lowercase `contradicts` — the directional factor graph maps it to
    /// mutual_exclusion with strength 0. Shared with the human-decide path
    /// (`decide_candidate` / `decide_match_candidate`) via the constant so the
    /// two producers of this edge cannot drift on casing; edge dedup compares
    /// the relationship string exactly.
    #[must_use]
    pub fn edge_relationship(self, auto_promote: bool) -> Option<&'static str> {
        match self {
            PolicyAction::AutoPromote if auto_promote => Some(CORROBORATES_RELATIONSHIP),
            PolicyAction::WriteContradicts if auto_promote => Some(CONTRADICTS_RELATIONSHIP),
            _ => None,
        }
    }
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

        // The row/edge decision is a pure function of (action, auto_promote) —
        // see [`PolicyAction::candidate_status`] and
        // [`PolicyAction::edge_relationship`]. Keeping it out of this async
        // body is what makes "Stage never writes an edge" assertable in a unit
        // test with no database.
        let status = action.candidate_status(self.auto_promote);
        let id = self
            .upsert_candidate(lo, hi, f, features_json, status, verdict.as_ref())
            .await?;
        if let Some(rel) = action.edge_relationship(self.auto_promote) {
            self.write_edge(a, b, rel, f, id, verdict.as_ref()).await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole safety claim of `stage_cross_source_matches`, asserted with no
    /// database: a staged pair is always queued for review and never commits an
    /// edge, whatever `auto_promote` says.
    #[test]
    fn stage_action_always_pends_and_never_writes_an_edge() {
        for auto_promote in [false, true] {
            assert_eq!(
                PolicyAction::Stage.candidate_status(auto_promote),
                "pending",
                "Stage must queue for review (auto_promote={auto_promote})"
            );
            assert_eq!(
                PolicyAction::Stage.edge_relationship(auto_promote),
                None,
                "Stage must never commit an edge (auto_promote={auto_promote})"
            );
        }
    }

    /// Regression net for the `Policy::act` refactor: this table is exactly the
    /// matrix the three pre-refactor `match` arms produced. `act` shares the
    /// nightly sweep's write path, so a mistake here changes what cron writes
    /// to prod.
    #[test]
    fn existing_actions_keep_their_pre_refactor_status_and_edge() {
        let table: &[(PolicyAction, bool, &str, Option<&str>)] = &[
            (
                PolicyAction::AutoPromote,
                true,
                "promoted",
                Some(CORROBORATES_RELATIONSHIP),
            ),
            (PolicyAction::AutoPromote, false, "pending", None),
            (
                PolicyAction::WriteContradicts,
                true,
                "promoted",
                Some(CONTRADICTS_RELATIONSHIP),
            ),
            (PolicyAction::WriteContradicts, false, "pending", None),
            (PolicyAction::Reject, true, "rejected", None),
            (PolicyAction::Reject, false, "rejected", None),
        ];
        for &(action, auto_promote, status, edge) in table {
            assert_eq!(
                action.candidate_status(auto_promote),
                status,
                "{action:?} / auto_promote={auto_promote}"
            );
            assert_eq!(
                action.edge_relationship(auto_promote),
                edge,
                "{action:?} / auto_promote={auto_promote}"
            );
        }
    }

    /// Casing is identity for edge dedup (see the `CONTRADICTS_RELATIONSHIP`
    /// doc), so the contradicts edge must stay lowercase — and must never be
    /// confused with CORROBORATES, which is its exact inverse.
    #[test]
    fn contradicts_edge_stays_lowercase_through_the_action_table() {
        let rel = PolicyAction::WriteContradicts.edge_relationship(true);
        assert_eq!(rel, Some("contradicts"));
        assert_ne!(rel, Some(CORROBORATES_RELATIONSHIP));
    }
}
