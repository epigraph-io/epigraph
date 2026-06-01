//! Policy layer: turn a scored/verified pair into rows + edges.
//!
//! See `docs/superpowers/specs/2026-05-21-cross-source-matching-design.md` §6
//! (state machine) and §7 (CORROBORATES edges). The pipeline classifies each
//! pair into [`PolicyAction`] and hands it off here; this module is the
//! single point where match_candidate rows and edge inserts happen so the
//! state machine stays auditable.

use crate::matching::scorer::MatchFeatures;
use crate::matching::verifier::{map_relationship, Verdict};
use epigraph_db::repos::match_candidate::MatchCandidateRepo;
use epigraph_db::EdgeRepository;
use sqlx::PgPool;
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
}

impl Policy {
    pub fn new(pool: PgPool, repo: MatchCandidateRepo, run_id: Uuid, auto_promote: bool) -> Self {
        Self {
            pool,
            repo,
            run_id,
            auto_promote,
        }
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

        // Persist verifier verdict + rationale on the row so we don't re-ask
        // the LLM (spec §4, "Verdict and rationale stored on the match-
        // candidate row; never re-asked"). Today MatchCandidateRepo::upsert
        // doesn't accept these as args yet; we patch them in below.
        let features_json = serde_json::to_value(f)?;

        match action {
            PolicyAction::AutoPromote => {
                let id = self
                    .repo
                    .upsert(
                        lo,
                        hi,
                        f.score,
                        features_json,
                        "promoted",
                        Some(self.run_id),
                    )
                    .await?;
                if let Some(v) = verdict.as_ref() {
                    self.patch_verdict(id, v).await?;
                }
                if self.auto_promote {
                    self.write_edge(a, b, "CORROBORATES", f, id, verdict.as_ref())
                        .await?;
                }
            }
            PolicyAction::WriteContradicts => {
                let id = self
                    .repo
                    .upsert(
                        lo,
                        hi,
                        f.score,
                        features_json,
                        "promoted",
                        Some(self.run_id),
                    )
                    .await?;
                if let Some(v) = verdict.as_ref() {
                    self.patch_verdict(id, v).await?;
                }
                if self.auto_promote {
                    // Use the lowercase 'contradicts' factor mapping (migration
                    // 090 / 049) — the directional factor graph maps it to
                    // mutual_exclusion with strength 0.
                    self.write_edge(a, b, "contradicts", f, id, verdict.as_ref())
                        .await?;
                }
            }
            PolicyAction::Reject => {
                let id = self
                    .repo
                    .upsert(
                        lo,
                        hi,
                        f.score,
                        features_json,
                        "rejected",
                        Some(self.run_id),
                    )
                    .await?;
                if let Some(v) = verdict.as_ref() {
                    self.patch_verdict(id, v).await?;
                }
            }
        }
        Ok(())
    }

    async fn patch_verdict(&self, id: Uuid, v: &Verdict) -> anyhow::Result<()> {
        // Persist the matcher-level vocabulary (`same|paraphrase|overlapping|
        // contradicts|distinct`) per spec §5, NOT the raw reranker relationship
        // string. The raw string is preserved in edge properties for debug.
        let column_verdict = map_relationship(&v.relationship, v.strength).as_column_str();
        sqlx::query(
            "UPDATE match_candidates
             SET verifier_verdict = $2, verifier_rationale = $3
             WHERE id = $1",
        )
        .bind(id)
        .bind(column_verdict)
        .bind(&v.rationale)
        .execute(&self.pool)
        .await?;
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
