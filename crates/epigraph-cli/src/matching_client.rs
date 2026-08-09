//! Production [`VerifierClient`] for the cross-source matcher.
//!
//! The engine crate (`epigraph-engine::matching::verifier`) defines the trait;
//! we cannot define this impl there because `epigraph-cli` already depends on
//! `epigraph-engine`. This module wraps [`crate::rerank::rerank_candidates_table`]
//! and harvests per-pair verdicts from the extended [`RerankSummary::per_pair_verdicts`]
//! channel (no edges written — dry-run only).
//!
//! [`VerifierClient`]: epigraph_engine::matching::verifier::VerifierClient
//! [`RerankSummary::per_pair_verdicts`]: crate::rerank::RerankSummary::per_pair_verdicts

use std::collections::HashMap;

use async_trait::async_trait;
use epigraph_engine::matching::verifier::{Verdict, VerifierClient};
use sqlx::PgPool;
use uuid::Uuid;

use crate::rerank::{rerank_candidates_table, PerPairVerdict, RerankConfig, RerankSummary};

/// Wraps the Phase 7 reranker as a [`VerifierClient`].
///
/// Each `verify()` call:
/// 1. Creates a transient temp table named `matcher_verify_<uuid>` (safe
///    identifier characters only).
/// 2. Inserts the pairs, deduplicated to canonical `(min, max)` order so the
///    reranker doesn't bill us twice for `(A,B)` and `(B,A)`.
/// 3. Calls `rerank_candidates_table` with `dry_run=true`. Edges are NOT
///    written by the reranker — the matcher policy layer owns that.
/// 4. Joins the per-pair verdicts back to the input order via
///    [`align_verdicts`]. Pairs the reranker returned no row for yield `None`
///    ("no answer"), which the pipeline skips; the LLM's own `valid: false`
///    rejections are a real answer and still map to `derives_from`.
pub struct RerankBridgesClient {
    pool: PgPool,
    config: RerankConfig,
}

impl RerankBridgesClient {
    /// New client with default rerank config (dry-run forced, batch=10).
    pub fn new(pool: PgPool) -> Self {
        let config = RerankConfig {
            dry_run: true,
            ..RerankConfig::default()
        };
        Self { pool, config }
    }

    /// Override the rerank config; `dry_run` is forced to `true` regardless of
    /// what the caller passes, since edge-writing is the matcher policy's job.
    pub fn with_config(pool: PgPool, mut config: RerankConfig) -> Self {
        config.dry_run = true;
        Self { pool, config }
    }
}

/// Join the reranker's per-pair output back onto the caller's pair list,
/// preserving order and the one-slot-per-input-pair contract.
///
/// `None` is returned for any pair the reranker produced **no row** for, *for
/// any reason whatsoever*. That is the verifier saying *"I have no answer"*, and
/// it must stay distinct from every verdict value. The known upstream paths, as
/// of writing, are these five — and none of them is a finding about the pair:
///
/// 1. the model answered the batch but omitted this pair,
/// 2. the batch's LLM call failed outright — `rerank::core::rerank_inner`'s
///    `call_llm_with_retry` `Err` arm bumps `summary.errors` and `continue`s, so
///    every pair in that batch is absent,
/// 3. the pair never reached the model at all —
///    `rerank::core::find_candidates_from_table` filters out pairs already
///    connected by any edge in either direction (and anything without an
///    embedding), while the matcher pipeline applies no such filter, so on a
///    re-run the highest-scoring pairs are systematically absent,
/// 4. [`crate::rerank::RerankConfig::limit`] truncated the candidate set before
///    the batch loop,
/// 5. [`crate::rerank::prompt::parse_validation_response`] dropped the model's
///    answer — an unparseable item, a `pair_index` out of bounds, or a
///    `valid: true` answer whose `relationship` is outside `VALID_RELATIONSHIPS`
///    or whose `strength` is outside `[0.3, 1.0]`.
///
/// The list is deliberately *not* load-bearing: this function keys on the
/// absence of a row, so a sixth path added tomorrow lands on `None` too. That
/// matters, since PR #381 tried to tell such paths apart inside a rationale
/// string, enumerated only some of them, and shipped a literal that asserted
/// "the model returned no entry" for pairs the model was demonstrably never
/// asked about. Because a `None` causes the pipeline to write nothing, no
/// string asserts anything and none can be false.
///
/// `valid: false` is the opposite case: the model *did* answer and said the
/// pair is not a real bridge. That keeps the `derives_from` mapping (→
/// `MatchVerdict::Distinct` → Reject) it has always had.
pub fn align_verdicts(
    pairs: &[(Uuid, Uuid)],
    per_pair_verdicts: Vec<PerPairVerdict>,
) -> Vec<Option<Verdict>> {
    // Index verdicts by canonical pair so we can re-align to caller order.
    let mut by_pair: HashMap<(Uuid, Uuid), PerPairVerdict> = HashMap::new();
    for v in per_pair_verdicts {
        let key = if v.source_id < v.target_id {
            (v.source_id, v.target_id)
        } else {
            (v.target_id, v.source_id)
        };
        by_pair.insert(key, v);
    }

    pairs
        .iter()
        .map(|(a, b)| {
            let key = if a < b { (*a, *b) } else { (*b, *a) };
            // No row from the reranker => no answer. Do NOT fabricate one.
            let per_pair = by_pair.get(&key)?;
            if !per_pair.valid {
                return Some(Verdict {
                    source_id: *a,
                    target_id: *b,
                    relationship: "derives_from".to_string(),
                    strength: per_pair.strength.unwrap_or(0.0) as f32,
                    rationale: per_pair.rationale.clone(),
                });
            }
            Some(Verdict {
                source_id: *a,
                target_id: *b,
                relationship: per_pair
                    .relationship
                    .clone()
                    .unwrap_or_else(|| "analogous".to_string()),
                strength: per_pair.strength.unwrap_or(0.5) as f32,
                rationale: per_pair.rationale.clone(),
            })
        })
        .collect()
}

/// Did this rerank call reach the model for at least one pair and come back
/// with a usable answer for **none** of them?
///
/// That is an outage, not a finding, and it must not be reported as a run of
/// `None`s. `rerank_inner`'s LLM-failure arm does `continue`, not `return Err`,
/// so a total provider failure returns `Ok` with an empty `per_pair_verdicts` —
/// which post-fix means every pair is skipped, nothing is written, the pipeline
/// returns `Ok`, and `cross_source_sweep` would go on to stamp
/// `last_match_scan_at` on every seed and exit 0. Seven days of seeds
/// black-holed by a successful-looking sweep. This has already been observed in
/// prod as `401 Unauthorized` on every verifier call while the process still
/// exited 0 with well-formed JSON — `cross-source-sweep-nightly.sh` currently
/// greps stderr for auth strings to catch it, a heuristic this check replaces
/// structurally.
///
/// `candidates_evaluated` is the count that survived
/// `find_candidates_from_table`, so pairs dropped **before** the model — already
/// edged (the routine, high-volume case on a re-run), no embedding, or
/// `limit`-truncated — are not counted here. A fully already-linked corpus
/// therefore yields `candidates_evaluated == 0` and is *not* flagged: the sweep
/// legitimately had nothing to ask, and must still stamp its seeds or it would
/// re-scan the same window forever. The predicate fires only when the model was
/// genuinely asked and genuinely said nothing usable.
///
/// A *partial* failure is deliberately not flagged: some real answers came back,
/// those are findings, and the unanswered remainder is reported through
/// `RunReport::skipped_no_verdict`. An honest batch of `valid: false` answers is
/// likewise not flagged — `rerank_inner` pushes rejections into
/// `per_pair_verdicts` too, so "the model said no to everything" is a result,
/// not an outage.
///
/// **Known wedge, accepted deliberately.** A *persistent* malformed-response
/// mode — every answer dropped by
/// [`crate::rerank::prompt::parse_validation_response`] because the
/// `relationship` is out of vocabulary or the `strength` is outside
/// `[0.3, 1.0]` — also leaves `per_pair_verdicts` empty and so fires this
/// predicate. That is intended: a model emitting only unusable answers is
/// malfunctioning. But because the error aborts the run *upstream* of the
/// `last_match_scan_at` stamp, the sweep will retry the same seed window every
/// night until an operator intervenes. Loud-and-stuck is the deliberate choice
/// over silent-and-advancing; the alternative — telling a transport failure
/// apart from a parse failure — is not derivable from `RerankSummary::errors`
/// (the whole-batch arm adds `batch.len()` at once, the parse-drop path adds one
/// per unanswered index) and would need a new field on the summary.
pub fn is_total_verifier_outage(summary: &RerankSummary) -> bool {
    summary.candidates_evaluated > 0 && summary.per_pair_verdicts.is_empty()
}

#[async_trait]
impl VerifierClient for RerankBridgesClient {
    async fn verify(&self, pairs: &[(Uuid, Uuid)]) -> anyhow::Result<Vec<Option<Verdict>>> {
        if pairs.is_empty() {
            return Ok(Vec::new());
        }

        // Canonical-order dedup before insertion: the reranker's internal
        // similarity-DESC sort is stable, but it would otherwise see (a,b)
        // and (b,a) as two distinct rows and burn tokens twice.
        let mut canon: Vec<(Uuid, Uuid)> = pairs
            .iter()
            .map(|(a, b)| if a < b { (*a, *b) } else { (*b, *a) })
            .collect();
        canon.sort_unstable();
        canon.dedup();

        let table = format!("matcher_verify_{}", Uuid::new_v4().simple());
        // CREATE TEMP TABLE is per-session, but sqlx's pool routes successive
        // .execute(&pool) calls to different connections — the temp table
        // wouldn't be visible from the connection that later runs the
        // rerank query. Use a regular table with a UUID-suffixed name
        // (still safe-identifier per find_candidates_from_table) and drop
        // it explicitly at the end.
        sqlx::query(&format!(
            "CREATE TABLE {table}
             (source_id uuid NOT NULL, target_id uuid NOT NULL)"
        ))
        .execute(&self.pool)
        .await?;

        // Always attempt to clean up the table, even if subsequent work
        // errors. Defer via a guard wouldn't help across an early-return
        // through `?`; explicit cleanup after the body is simpler.
        let result = async {
            for (a, b) in &canon {
                sqlx::query(&format!(
                    "INSERT INTO {table} (source_id, target_id) VALUES ($1, $2)"
                ))
                .bind(a)
                .bind(b)
                .execute(&self.pool)
                .await?;
            }

            rerank_candidates_table(&self.pool, &table, &self.config)
                .await
                .map_err(|e| anyhow::anyhow!(e))
        }
        .await;

        let _ = sqlx::query(&format!("DROP TABLE IF EXISTS {table}"))
            .execute(&self.pool)
            .await;

        let summary = result?;

        // Fail loudly BEFORE handing the pipeline a vector of `None`s it would
        // (correctly) skip and the sweep would (incorrectly) read as "the
        // corpus stopped matching". See `is_total_verifier_outage`.
        if is_total_verifier_outage(&summary) {
            anyhow::bail!(
                "verifier outage: the reranker sent {} candidate pair(s) to the model \
                 and got a usable answer for none of them ({} error(s) recorded). \
                 Refusing to report this as \"no matches\" — a run of no-answers here \
                 would skip every pair, write nothing, and still stamp every seed as \
                 scanned.",
                summary.candidates_evaluated,
                summary.errors
            );
        }

        Ok(align_verdicts(pairs, summary.per_pair_verdicts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn per_pair(a: Uuid, b: Uuid, valid: bool) -> PerPairVerdict {
        PerPairVerdict {
            source_id: a,
            target_id: b,
            valid,
            relationship: valid.then(|| "supports".to_string()),
            strength: Some(0.9),
            rationale: "model spoke".to_string(),
        }
    }

    /// THE regression guard for defect B: a pair the reranker produced no row
    /// for must come back as `None`, not as a synthetic verdict. Before this,
    /// the miss returned `derives_from`/0.0, which `map_relationship` sends to
    /// `MatchVerdict::Distinct` → Reject → `patch_verdict('distinct')`.
    #[test]
    fn a_pair_the_reranker_did_not_answer_on_yields_no_verdict() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let out = align_verdicts(&[(a, b)], Vec::new());
        assert_eq!(out.len(), 1, "one slot per input pair");
        assert!(
            out[0].is_none(),
            "silence must not be laundered into a verdict, got {:?}",
            out[0]
        );
    }

    /// The complement: an explicit `valid: false` IS an answer — the model was
    /// asked and said no. Skipping those too would throw away real rejections.
    #[test]
    fn an_explicit_llm_rejection_is_still_a_verdict() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let out = align_verdicts(&[(a, b)], vec![per_pair(a, b, false)]);
        let v = out[0]
            .as_ref()
            .expect("valid:false is an answer, not silence");
        assert_eq!(v.relationship, "derives_from");
        assert_eq!(v.rationale, "model spoke");
    }

    /// A total LLM failure must NOT be laundered into "the corpus stopped
    /// matching". `rerank_inner`'s failure arm `continue`s, so the summary comes
    /// back `Ok` with pairs sent and zero verdicts; post-fix that would skip
    /// every pair, write nothing, and let the sweep stamp every seed as scanned
    /// while exiting 0.
    #[test]
    fn pairs_sent_to_the_model_with_zero_answers_is_an_outage() {
        let summary = RerankSummary {
            candidates_evaluated: 10,
            errors: 10,
            per_pair_verdicts: Vec::new(),
            ..Default::default()
        };
        assert!(
            is_total_verifier_outage(&summary),
            "10 pairs asked, 0 answered is an outage, not a corpus signal"
        );
    }

    /// The routine case this must NOT fire on: every pair was filtered out
    /// before the model (already edged / no embedding / `limit`), so nothing was
    /// asked and nothing could be answered. Flagging it would fail the sweep
    /// every night on an already-linked corpus AND wedge it re-scanning the same
    /// seed window forever, because the `last_match_scan_at` stamp is downstream
    /// of the error.
    #[test]
    fn a_corpus_with_nothing_left_to_ask_is_not_an_outage() {
        let summary = RerankSummary {
            candidates_evaluated: 0,
            errors: 0,
            per_pair_verdicts: Vec::new(),
            ..Default::default()
        };
        assert!(
            !is_total_verifier_outage(&summary),
            "no pair reached the model, so there is no verifier failure to report"
        );
    }

    /// A partial failure is a real result plus a shortfall, not an outage: the
    /// answers that did arrive are findings and must be acted on. The
    /// unanswered remainder is reported via `RunReport::skipped_no_verdict`.
    #[test]
    fn a_partial_batch_failure_is_not_an_outage() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let summary = RerankSummary {
            candidates_evaluated: 10,
            errors: 9,
            per_pair_verdicts: vec![per_pair(a, b, true)],
            ..Default::default()
        };
        assert!(
            !is_total_verifier_outage(&summary),
            "one real answer means the model was reachable; do not fail the run"
        );
    }

    /// Alignment is by canonical pair, so a verdict reported in the opposite
    /// orientation still matches — and every input slot is filled, silent or
    /// not, so the pipeline's length check cannot be tripped by a `None`.
    #[test]
    fn alignment_is_orientation_independent_and_positional() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        // Answer only for the (a,b) pair, reported as (b,a).
        let out = align_verdicts(&[(a, c), (a, b)], vec![per_pair(b, a, true)]);
        assert_eq!(out.len(), 2);
        assert!(out[0].is_none(), "unanswered pair keeps its slot as None");
        let v = out[1]
            .as_ref()
            .expect("reversed-orientation answer must match");
        assert_eq!(v.relationship, "supports");
        assert_eq!(
            (v.source_id, v.target_id),
            (a, b),
            "caller's orientation is preserved"
        );
    }
}
