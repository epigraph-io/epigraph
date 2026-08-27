//! Write-time contradiction scan for `submit_claim` / `memorize`
//! (backlog `6ed02d04`).
//!
//! # Scope caveat — this DETECTS and ENQUEUES, it never DECIDES
//!
//! Everything in this module is a cheap lexical *suspicion*. It stages a
//! `match_candidates` row with `status = 'pending'` and `verifier_verdict =
//! NULL` and stops there. No `contradicts` edge is ever written by the write
//! path, and no verdict is ever recorded. Adjudication still requires
//! `cross_source_sweep`'s LLM verifier or a human operator.
//!
//! That boundary is forced, not chosen: a real verdict needs an LLM, and the
//! shipped `epigraph-mcp` binary registers no `LlmProvider` — see the KNOWN
//! LIMITATION at `crate::tools::recall` (the `groundedness_gate` branch).
//! `epigraph-cli`'s `AnthropicClient` cannot be reused here because
//! `epigraph-cli` depends on `epigraph-mcp`, so importing it would close a
//! crate cycle.
//!
//! # Why lexical, and why free
//!
//! [`crate::tools::novelty_gate::decide`] already fetches `NEAREST_K = 5`
//! neighbours and previously discarded four of them. This scan runs over that
//! exact same vector: zero extra embedding calls, zero extra queries on the
//! common path. The only added cost is the neighbours' `left(content, 2000)`
//! text, which now rides along on the ANN round-trip.
//!
//! The detector is deliberately precision-first and purely surface-lexical.
//! Embeddings are famously blind to negation — "X is safe" and "X is not safe"
//! are near-neighbours — which is exactly why a *close* neighbour plus a
//! *polarity flip* is the highest-yield cheap signal available here, and why
//! the novelty gate's own `0.05` / `0.15` distance geometry cannot express it
//! no matter how it is retuned.
//!
//! A signal fires only when, inside a distance band, either
//! (a) the two texts differ in NEGATION PARITY, or (b) they hit opposite sides
//! of a fixed ANTONYM table — and, in both cases, only when polarity-stripped
//! token Jaccard clears a floor. Every fired signal costs an operator a triage,
//! so the brakes matter more than the recall.

use std::collections::BTreeSet;

use epigraph_db::{MatchCandidateRepo, NearestClaimHit};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use epigraph_engine::matching::verifier::WRITE_TIME_SCAN_SOURCE;

/// Maximum cosine distance for a neighbour to count as "about the same thing".
///
/// Wider than [`crate::tools::novelty_gate::NEAR_DUPLICATE_BAND`] (`0.15`) on
/// purpose: inserting a negation barely moves an embedding, but an
/// opposite-polarity *paraphrase* ("throughput improves" vs "throughput
/// regresses under load") can drift a good deal further while still being a
/// direct conflict. `0.15` would miss those.
///
/// This is the tuning surface and the biggest unknown in the feature — see the
/// note on [`MIN_LEXICAL_OVERLAP`].
pub const CONTRADICTION_BAND: f64 = 0.30;

/// Jaccard floor over polarity-stripped tokens. Below this the two texts do not
/// share enough subject matter for a polarity difference to mean anything, and
/// the signal is dropped.
///
/// This is the false-positive brake. Every fired signal creates a pending row a
/// human has to triage, so the cost of a loose floor is a flooded review queue,
/// not merely wasted CPU. Neither this nor [`CONTRADICTION_BAND`] can be
/// measured without a corpus; both are named constants precisely so the first
/// production week can retune them in one place.
pub const MIN_LEXICAL_OVERLAP: f64 = 0.35;

/// Why the detector thinks a pair may conflict. Serialized into the staged
/// row's `features` so an operator can see the heuristic's actual reasoning
/// rather than just a score.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum ContradictionCue {
    /// One text carries a negation cue and the other does not.
    NegationParity,
    /// The two texts sit on opposite sides of an [`ANTONYMS`] entry.
    Antonym { positive: String, negative: String },
}

/// One neighbour the scan fired on.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ContradictionSignal {
    pub neighbor_id: Uuid,
    pub distance: f64,
    pub lexical_overlap: f64,
    pub cues: Vec<ContradictionCue>,
}

/// Negation markers. Stored apostrophe-free because [`tokenize`] splits on
/// every non-alphanumeric character, so `"doesn't"` arrives as `doesn` + `t`
/// — an entry spelled `"doesn't"` could never match.
const NEGATION_CUES: &[&str] = &[
    "not", "no", "never", "cannot", "cant", "dont", "doesnt", "didnt", "isnt", "arent", "wasnt",
    "werent", "wont", "without", "neither", "nor", "none", "unable", "fails", "failed", "absent",
    "lacks",
];

/// Fixed antonym table, `(positive, negative)`.
///
/// Deliberately small and conservative. This is not meant to be a thesaurus:
/// every entry added is a new way to generate a false positive on a human's
/// review queue, and the table has no way to know that "the test *fails* to
/// reproduce" is not the opposite of "the test *passes* review". Grow it only
/// against observed misses.
const ANTONYMS: &[(&str, &str)] = &[
    ("increase", "decrease"),
    ("increases", "decreases"),
    ("higher", "lower"),
    ("faster", "slower"),
    ("safe", "unsafe"),
    ("enabled", "disabled"),
    ("present", "absent"),
    ("supports", "refutes"),
    ("true", "false"),
    ("always", "never"),
    ("succeeds", "fails"),
    ("succeeded", "failed"),
    ("passes", "fails"),
    ("passed", "failed"),
    ("possible", "impossible"),
    ("correct", "incorrect"),
    ("valid", "invalid"),
    ("secure", "insecure"),
    ("required", "optional"),
];

/// Function words carrying no subject matter. Removed before the overlap score
/// so two texts are compared on what they are ABOUT, not on their grammar.
const STOPWORDS: &[&str] = &[
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being", "do", "does", "did", "of",
    "to", "in", "on", "for", "and", "or", "that", "this", "it", "as", "at", "by", "with",
];

/// Lowercase, split on every non-alphanumeric character, drop empties.
#[must_use]
pub fn tokenize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

/// Does this token set assert a negation?
///
/// Parity, not a count: "not" appearing twice is still one polarity, and
/// counting cues would make "no evidence that X does not hold" look doubly
/// negative when it is barely negative at all.
#[must_use]
pub fn has_negation(tokens: &BTreeSet<String>) -> bool {
    NEGATION_CUES.iter().any(|cue| tokens.contains(*cue))
}

/// Antonym-table hits between two token sets.
///
/// Fires only when one side holds EXACTLY one member of a pair and the other
/// side holds EXACTLY the other. A side containing BOTH members is suppressed:
/// text that mentions "increases" and "decreases" together is discussing both
/// directions ("batching increases throughput but decreases tail latency"),
/// not asserting one, and pairing it against either polarity is noise.
#[must_use]
pub fn antonym_cues(a: &BTreeSet<String>, b: &BTreeSet<String>) -> Vec<ContradictionCue> {
    let mut cues = Vec::new();
    for (positive, negative) in ANTONYMS {
        let a_pos = a.contains(*positive);
        let a_neg = a.contains(*negative);
        let b_pos = b.contains(*positive);
        let b_neg = b.contains(*negative);
        // Either side holding both members is discussing the axis, not
        // asserting a direction on it.
        if (a_pos && a_neg) || (b_pos && b_neg) {
            continue;
        }
        if (a_pos && b_neg) || (a_neg && b_pos) {
            cues.push(ContradictionCue::Antonym {
                positive: (*positive).to_string(),
                negative: (*negative).to_string(),
            });
        }
    }
    cues
}

/// Is this token a polarity marker rather than subject matter?
fn is_polarity_token(token: &str) -> bool {
    NEGATION_CUES.contains(&token)
        || ANTONYMS
            .iter()
            .any(|(positive, negative)| *positive == token || *negative == token)
}

/// Jaccard similarity over token sets with negation cues, every antonym-table
/// word, and [`STOPWORDS`] removed.
///
/// Stripping FIRST is load-bearing, not a tidying step. The very tokens that
/// carry the contradiction are the ones that differ between the two texts, so
/// leaving them in depresses the overlap by exactly the amount the cue raised
/// the suspicion — on short claims that is enough to push a true hit below
/// [`MIN_LEXICAL_OVERLAP`] and mask it. Compare the subjects, gate on the
/// polarity separately.
///
/// Two texts that strip down to nothing at all score `0.0`: an empty
/// intersection is no evidence of a shared subject, and the conservative answer
/// suppresses.
#[must_use]
pub fn polarity_stripped_jaccard(a: &BTreeSet<String>, b: &BTreeSet<String>) -> f64 {
    let strip = |set: &BTreeSet<String>| -> BTreeSet<String> {
        set.iter()
            .filter(|t| !is_polarity_token(t) && !STOPWORDS.contains(&t.as_str()))
            .cloned()
            .collect()
    };
    let a = strip(a);
    let b = strip(b);
    let union = a.union(&b).count();
    if union == 0 {
        return 0.0;
    }
    let intersection = a.intersection(&b).count();
    intersection as f64 / union as f64
}

/// Scan `incoming` against the ANN neighbours the novelty gate already fetched.
///
/// Pure: no I/O, no clock, no randomness. Neighbours are examined in the order
/// given (closest-first, as `ClaimRepository::nearest_by_embedding` returns
/// them) and the output preserves that order.
///
/// Order of the three filters is deliberate — distance gates BEFORE cue
/// detection so a far-away neighbour never even gets tokenized, and the
/// (more expensive) overlap score is computed only for neighbours that already
/// produced a cue.
#[must_use]
pub fn scan(incoming: &str, nearest: &[NearestClaimHit]) -> Vec<ContradictionSignal> {
    let incoming_tokens: BTreeSet<String> = tokenize(incoming).into_iter().collect();
    if incoming_tokens.is_empty() {
        return Vec::new();
    }
    let incoming_negated = has_negation(&incoming_tokens);

    let mut signals = Vec::new();
    for hit in nearest {
        if hit.distance > CONTRADICTION_BAND {
            continue;
        }
        let neighbor_tokens: BTreeSet<String> = tokenize(&hit.content).into_iter().collect();

        let mut cues = Vec::new();
        if has_negation(&neighbor_tokens) != incoming_negated {
            cues.push(ContradictionCue::NegationParity);
        }
        cues.extend(antonym_cues(&incoming_tokens, &neighbor_tokens));
        if cues.is_empty() {
            continue;
        }

        let lexical_overlap = polarity_stripped_jaccard(&incoming_tokens, &neighbor_tokens);
        if lexical_overlap < MIN_LEXICAL_OVERLAP {
            continue;
        }

        signals.push(ContradictionSignal {
            neighbor_id: hit.claim_id,
            distance: hit.distance,
            lexical_overlap,
            cues,
        });
    }
    signals
}

/// `features` payload for the staged `match_candidates` row.
///
/// `source` comes from [`WRITE_TIME_SCAN_SOURCE`] rather than a re-typed
/// literal: both promote guards compare against that exact byte string, and
/// `features->>'source'` is the only reliable way to tell a scan row from a
/// matcher row (their `score` columns are on incomparable scales).
#[must_use]
pub fn features_json(incoming: Uuid, sig: &ContradictionSignal) -> serde_json::Value {
    serde_json::json!({
        "source":          WRITE_TIME_SCAN_SOURCE,
        "detector":        "lexical_polarity_v1",
        "embed_distance":  sig.distance,
        "embed_cosine":    1.0 - sig.distance,
        "lexical_overlap": sig.lexical_overlap,
        "cues":            &sig.cues,
        "incoming_claim":  incoming,
        "neighbor_claim":  sig.neighbor_id,
    })
}

/// Stage each signal as a pending `match_candidates` row and return the
/// neighbour ids the scan fired on.
///
/// **Best-effort, never fails.** A `submit_claim` must not error because the
/// review queue is unavailable — the same discipline CLAUDE.md mandates for
/// post-commit embedding. Every failure is a `tracing::warn!` and nothing
/// propagates. That is a real observability gap (a DB hiccup drops the signal
/// with no caller-visible trace beyond the log line) and it is the correct
/// trade: a suspicion is not worth failing a write over.
///
/// Returns ALL fired neighbour ids, including pairs that were already queued —
/// the caller reports what the scan found, not what it managed to insert.
///
/// Callers MUST invoke this only AFTER the claim row exists:
/// `match_candidates.claim_a` / `claim_b` are foreign keys into `claims(id)`.
pub async fn enqueue(pool: &PgPool, new_claim: Uuid, signals: &[ContradictionSignal]) -> Vec<Uuid> {
    let repo = MatchCandidateRepo::new(pool.clone());
    let mut fired = Vec::with_capacity(signals.len());

    for sig in signals {
        // `match_candidates_canonical_order` is a CHECK (claim_a < claim_b)
        // that neither the compiler nor any test in this workspace can enforce
        // for us — sort here, at the only call site that builds the pair.
        let (lo, hi) = if new_claim < sig.neighbor_id {
            (new_claim, sig.neighbor_id)
        } else {
            (sig.neighbor_id, new_claim)
        };
        if lo == hi {
            // A claim matching itself would violate the same CHECK. Reachable
            // only if the ANN result somehow contains the row we just wrote.
            tracing::debug!(claim_id = %new_claim, "contradiction scan: skipping self-pair");
            continue;
        }

        fired.push(sig.neighbor_id);

        let score = (1.0 - sig.distance).clamp(0.0, 1.0) as f32;
        match repo
            // `run_id: None` — a submission is not a matcher run.
            .insert_if_absent(
                lo,
                hi,
                score,
                features_json(new_claim, sig),
                "pending",
                None,
            )
            .await
        {
            Ok(Some(id)) => {
                tracing::debug!(candidate_id = %id, claim_a = %lo, claim_b = %hi,
                    "contradiction scan: staged candidate for review");
            }
            Ok(None) => {
                tracing::debug!(claim_a = %lo, claim_b = %hi,
                    "contradiction scan: pair already queued, leaving the existing row untouched");
            }
            Err(e) => {
                tracing::warn!(claim_a = %lo, claim_b = %hi,
                    "contradiction scan: staging candidate failed: {e}");
            }
        }
    }
    fired
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(distance: f64, content: &str) -> NearestClaimHit {
        NearestClaimHit {
            claim_id: Uuid::new_v4(),
            content: content.to_string(),
            distance,
        }
    }

    #[test]
    fn no_neighbors_yields_no_signals() {
        assert!(scan("anything", &[]).is_empty());
    }

    /// Distance gates BEFORE cue detection: a blatant negation flip outside the
    /// band must not fire, no matter how obvious the lexical signal is.
    #[test]
    fn neighbor_beyond_contradiction_band_is_ignored() {
        let nearest = [hit(
            0.45,
            "the retry loop is not safe under concurrent writes",
        )];
        assert!(scan("the retry loop is safe under concurrent writes", &nearest).is_empty());
    }

    /// `distance == CONTRADICTION_BAND` fires — the comparison is `>`, not
    /// `>=`. Pinned the way novelty_gate pins its own band boundaries.
    #[test]
    fn boundary_distance_equal_to_contradiction_band_is_inclusive() {
        let nearest = [hit(
            CONTRADICTION_BAND,
            "the retry loop is not safe under concurrent writes",
        )];
        let signals = scan("the retry loop is safe under concurrent writes", &nearest);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].distance, CONTRADICTION_BAND);
    }

    /// The canonical case the whole feature exists for: an embedding cannot
    /// separate these two, a single token can.
    #[test]
    fn negation_parity_flip_on_near_identical_text_fires() {
        let nearest = [hit(
            0.04,
            "the retry loop is not safe under concurrent writes",
        )];
        let signals = scan("the retry loop is safe under concurrent writes", &nearest);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].cues, vec![ContradictionCue::NegationParity]);
    }

    /// Parity, not presence: two texts that are both negated agree about
    /// polarity and must not fire.
    #[test]
    fn matching_negation_on_both_sides_does_not_fire() {
        let nearest = [hit(0.04, "the deploy script does not remove temp files")];
        assert!(scan("the deploy script does not clean temp files", &nearest).is_empty());
    }

    #[test]
    fn antonym_pair_fires_without_any_negation_word() {
        let nearest = [hit(0.10, "batching decreases throughput")];
        let signals = scan("batching increases throughput", &nearest);
        assert_eq!(signals.len(), 1);
        assert_eq!(
            signals[0].cues,
            vec![ContradictionCue::Antonym {
                positive: "increases".to_string(),
                negative: "decreases".to_string(),
            }]
        );
        assert!(!signals[0].cues.contains(&ContradictionCue::NegationParity));
    }

    /// A neighbour naming both directions is describing a trade-off, not
    /// asserting the opposite of the incoming claim.
    #[test]
    fn antonym_present_on_both_sides_does_not_fire() {
        let nearest = [hit(
            0.10,
            "batching increases throughput but decreases throughput at high load",
        )];
        assert!(scan("batching increases throughput", &nearest).is_empty());
    }

    /// The false-positive brake: a close embedding plus a polarity flip is not
    /// enough when the two texts are not about the same thing.
    #[test]
    fn low_lexical_overlap_suppresses_signal_despite_close_embedding() {
        let nearest = [hit(0.05, "the mitochondrion cannot synthesize ribosomes")];
        assert!(scan(
            "quantum annealing accelerates protein folding simulations",
            &nearest
        )
        .is_empty());
    }

    /// Jaccard is computed AFTER stripping polarity words. "throughput
    /// increases" vs "throughput decreases" shares 1 of 3 raw tokens
    /// (0.333 — below the floor), but the two tokens that differ are exactly
    /// the ones carrying the contradiction. Stripping them leaves a perfect
    /// subject match, so a true hit is not masked by its own evidence.
    #[test]
    fn polarity_words_are_excluded_from_the_overlap_score() {
        let a: BTreeSet<String> = tokenize("throughput increases").into_iter().collect();
        let b: BTreeSet<String> = tokenize("throughput decreases").into_iter().collect();

        // Unstripped, this fixture scores 1/3 — below the floor. The test only
        // proves something while that stays true.
        let raw = a.intersection(&b).count() as f64 / a.union(&b).count() as f64;
        assert!(
            raw < MIN_LEXICAL_OVERLAP,
            "raw Jaccard {raw} already clears the floor; this fixture no longer \
             distinguishes stripped from unstripped"
        );
        assert!((polarity_stripped_jaccard(&a, &b) - 1.0).abs() < f64::EPSILON);

        let nearest = [hit(0.08, "throughput decreases")];
        let signals = scan("throughput increases", &nearest);
        assert_eq!(signals.len(), 1);
        assert!((signals[0].lexical_overlap - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn case_and_punctuation_do_not_affect_cue_detection() {
        assert_eq!(tokenize("Is NOT safe."), tokenize("is not safe"));
        let nearest = [hit(0.04, "the retry loop is not safe")];
        let signals = scan("The Retry Loop IS SAFE!!!", &nearest);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].cues, vec![ContradictionCue::NegationParity]);
    }

    /// The ANN result is closest-first and the output must stay in that order,
    /// so the operator queue reflects the ranking the index produced.
    #[test]
    fn signals_preserve_closest_first_order_from_the_ann_result() {
        let near = hit(0.03, "the retry loop is not safe under concurrent writes");
        let far = hit(0.22, "the retry loop is not safe under concurrent writes");
        let (near_id, far_id) = (near.claim_id, far.claim_id);
        let signals = scan(
            "the retry loop is safe under concurrent writes",
            &[near, far],
        );
        assert_eq!(signals.len(), 2);
        assert_eq!(signals[0].neighbor_id, near_id);
        assert_eq!(signals[1].neighbor_id, far_id);
    }

    /// Guards a copy-paste indexing bug: attributing every signal to the first
    /// hit would enqueue the WRONG pair, and no compile-time check would catch
    /// it.
    #[test]
    fn every_firing_neighbor_reports_its_own_id_and_distance() {
        let first = hit(0.03, "the cache is not enabled for cold reads");
        let second = hit(0.19, "the cache is not enabled for cold reads");
        let (first_id, second_id) = (first.claim_id, second.claim_id);
        let signals = scan("the cache is enabled for cold reads", &[first, second]);
        assert_eq!(signals.len(), 2);
        assert_eq!(signals[0].neighbor_id, first_id);
        assert!((signals[0].distance - 0.03).abs() < f64::EPSILON);
        assert_eq!(signals[1].neighbor_id, second_id);
        assert!((signals[1].distance - 0.19).abs() < f64::EPSILON);
        assert_ne!(signals[0].neighbor_id, signals[1].neighbor_id);
    }

    /// Both promote guards key on this exact string; a re-typed literal here
    /// would silently disable them.
    #[test]
    fn features_json_carries_the_write_time_scan_source_marker() {
        let incoming = Uuid::new_v4();
        let sig = ContradictionSignal {
            neighbor_id: Uuid::new_v4(),
            distance: 0.1,
            lexical_overlap: 0.9,
            cues: vec![ContradictionCue::NegationParity],
        };
        let features = features_json(incoming, &sig);
        assert_eq!(
            features["source"].as_str(),
            Some(epigraph_engine::matching::verifier::WRITE_TIME_SCAN_SOURCE)
        );
        assert_eq!(
            features["neighbor_claim"].as_str(),
            Some(sig.neighbor_id.to_string().as_str())
        );
        assert_eq!(
            features["incoming_claim"].as_str(),
            Some(incoming.to_string().as_str())
        );
    }
}
