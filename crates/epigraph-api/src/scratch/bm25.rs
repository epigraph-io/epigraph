//! A small Okapi BM25 over atom text (DESIGN §4.3), with no new crate.
//!
//! The scratch graph holds one chat (a few thousand atoms at most), so the
//! index is rebuilt for every query: that keeps it trivially consistent with
//! supersession and costs well under a millisecond at that size.

use std::collections::{BTreeMap, BTreeSet};

/// Term-frequency saturation.
pub const K1: f64 = 1.2;
/// Length normalisation.
pub const B: f64 = 0.75;

/// Common English function words, dropped from documents and queries.
const STOPWORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "for", "from", "has", "have", "he",
    "her", "his", "i", "if", "in", "into", "is", "it", "its", "me", "my", "of", "on", "or", "our",
    "she", "so", "that", "the", "their", "them", "then", "there", "these", "they", "this", "to",
    "was", "we", "were", "what", "when", "which", "who", "will", "with", "you", "your",
];

/// Lower-cased alphanumeric runs; single letters and stopwords are dropped,
/// single digits are kept (numbers carry meaning in a chat: "batch 7").
pub fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(str::to_lowercase)
        .filter(|t| {
            let single = t.chars().count() == 1;
            let numeric = t.chars().all(|c| c.is_ascii_digit());
            (numeric || !single) && !STOPWORDS.contains(&t.as_str())
        })
        .collect()
}

/// Rank `docs` against `query` and return up to `limit` `(index, score)`
/// pairs with a positive score, best first. Ties keep `docs` order, so a
/// caller that lists newer documents first breaks ties toward them.
///
/// Each distinct query term counts once: a long query that repeats a word is
/// not allowed to weight that word up.
pub fn rank(docs: &[&str], query: &str, limit: usize) -> Vec<(usize, f64)> {
    if docs.is_empty() || limit == 0 {
        return Vec::new();
    }
    let terms: BTreeSet<String> = tokenize(query).into_iter().collect();
    if terms.is_empty() {
        return Vec::new();
    }
    let tokenized: Vec<Vec<String>> = docs.iter().map(|d| tokenize(d)).collect();
    let n = tokenized.len() as f64;
    let avg_len = tokenized.iter().map(Vec::len).sum::<usize>() as f64 / n;

    let mut df: BTreeMap<&str, usize> = BTreeMap::new();
    for doc in &tokenized {
        let seen: BTreeSet<&str> = doc.iter().map(String::as_str).collect();
        for term in seen {
            if terms.contains(term) {
                *df.entry(term).or_default() += 1;
            }
        }
    }

    let mut scored: Vec<(usize, f64)> = tokenized
        .iter()
        .enumerate()
        .filter_map(|(i, doc)| {
            let len = doc.len() as f64;
            let norm = if avg_len > 0.0 {
                1.0 - B + B * len / avg_len
            } else {
                1.0
            };
            let score: f64 = terms
                .iter()
                .filter_map(|term| {
                    let tf = doc.iter().filter(|t| *t == term).count() as f64;
                    if tf == 0.0 {
                        return None;
                    }
                    let d = df.get(term.as_str()).copied().unwrap_or(0) as f64;
                    let idf = (1.0 + (n - d + 0.5) / (d + 0.5)).ln();
                    Some(idf * tf * (K1 + 1.0) / (tf + K1 * norm))
                })
                .sum();
            (score > 0.0).then_some((i, score))
        })
        .collect();
    // Stable sort: equal scores keep document order.
    scored.sort_by(|a, b| b.1.total_cmp(&a.1));
    scored.truncate(limit);
    scored
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_lowercases_splits_and_drops_stopwords_and_single_letters() {
        assert_eq!(
            tokenize("The Operator's v2 probes: batch 7, B-17!"),
            vec!["operator", "v2", "probes", "batch", "7", "17"]
        );
        assert_eq!(tokenize("Größe über"), vec!["größe", "über"]);
        assert!(tokenize("a the of ... !").is_empty());
    }

    #[test]
    fn rarer_term_outranks_common_term() {
        // "probe" is in every document, "firmware" in one.
        let docs = [
            "probe reading normal",
            "probe firmware updated",
            "probe dropped offline",
        ];
        let ranked = rank(&docs, "probe firmware", 3);
        assert_eq!(ranked.first().map(|r| r.0), Some(1));
        // The common term alone still scores every document, but lower.
        let common = rank(&docs, "probe", 3);
        assert_eq!(common.len(), 3);
        assert!(ranked[0].1 > common[0].1);
    }

    #[test]
    fn shorter_document_wins_at_equal_term_frequency() {
        let docs = [
            "greenhouse sensor rollout uses many other unrelated words here",
            "greenhouse sensor",
        ];
        let ranked = rank(&docs, "greenhouse", 2);
        assert_eq!(ranked.iter().map(|r| r.0).collect::<Vec<_>>(), vec![1, 0]);
    }

    #[test]
    fn no_overlap_and_empty_inputs_rank_nothing() {
        let docs = ["alpha beta", "gamma delta"];
        assert!(rank(&docs, "epsilon", 5).is_empty());
        assert!(rank(&docs, "the of a", 5).is_empty());
        assert!(rank(&[], "alpha", 5).is_empty());
        assert!(rank(&docs, "alpha", 0).is_empty());
    }

    #[test]
    fn ties_keep_document_order_and_limit_truncates() {
        let docs = ["batch shipped", "batch shipped", "batch shipped"];
        let ranked = rank(&docs, "batch", 2);
        assert_eq!(ranked.iter().map(|r| r.0).collect::<Vec<_>>(), vec![0, 1]);
    }

    #[test]
    fn repeated_query_terms_count_once() {
        let docs = ["batch shipped", "firmware updated"];
        let once = rank(&docs, "batch firmware", 2);
        let repeated = rank(&docs, "batch batch batch batch firmware", 2);
        assert_eq!(once, repeated);
    }
}
