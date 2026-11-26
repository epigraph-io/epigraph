//! Stance-seeking probe blocker (a04248cf).
//!
//! The other blockers retrieve neighbours of the SEED: its embedding, theme,
//! triples, hash. A claim that contradicts the seed can sit outside every one of
//! those neighbourhoods. Corroborations restate a finding and land among its
//! nearest neighbours; a contradiction asserts the opposite and can rank below
//! `top_k` restatements and paraphrases. This blocker aims the retrieval query at
//! the disagreement instead. It rewrites each seed into one or more probe texts
//! that invert or negate its assertion (see [`stance_probes`]), embeds them, and
//! takes the probe vectors' nearest neighbours as candidates for the seed.
//!
//! v1 builds the probes from templates; no LLM is called. Embedding is network
//! I/O and can fail, so it happens in [`StanceProbeBlocker::prepare`], before
//! blocking. [`Blocker::candidates`] then runs only SQL, like the other blockers.

use super::{canonical, Blocker, CandidatePair};
use async_trait::async_trait;
use epigraph_embeddings::EmbeddingService;
use regex::{Captures, Regex};
use sqlx::PgPool;
use std::collections::HashSet;
use std::sync::OnceLock;
use uuid::Uuid;

/// Probe texts per seed, at most: one directional inversion and one negation.
pub const MAX_PROBES_PER_SEED: usize = 2;

/// Texts per `batch_generate` call. Below the provider's batch ceiling, and
/// small enough that one request stays well inside its per-request token budget.
const EMBED_CHUNK: usize = 64;

/// Directional words and the word that inverts each one. The map is not
/// required to be an involution (`reduces` → `increases` while `increases` →
/// `decreases`); each entry only has to name an opposite direction.
const INVERSIONS: &[(&str, &str)] = &[
    ("increase", "decrease"),
    ("increases", "decreases"),
    ("increased", "decreased"),
    ("increasing", "decreasing"),
    ("decrease", "increase"),
    ("decreases", "increases"),
    ("decreased", "increased"),
    ("decreasing", "increasing"),
    ("reduce", "increase"),
    ("reduces", "increases"),
    ("reduced", "increased"),
    ("reducing", "increasing"),
    ("enhance", "reduce"),
    ("enhances", "reduces"),
    ("enhanced", "reduced"),
    ("improve", "worsen"),
    ("improves", "worsens"),
    ("improved", "worsened"),
    ("worsen", "improve"),
    ("worsens", "improves"),
    ("worsened", "improved"),
    ("outperform", "underperform"),
    ("outperforms", "underperforms"),
    ("outperformed", "underperformed"),
    ("underperform", "outperform"),
    ("underperforms", "outperforms"),
    ("underperformed", "outperformed"),
    ("raise", "lower"),
    ("raises", "lowers"),
    ("raised", "lowered"),
    ("rise", "fall"),
    ("rises", "falls"),
    ("fall", "rise"),
    ("falls", "rises"),
    ("higher", "lower"),
    ("lower", "higher"),
    ("lowers", "raises"),
    ("lowered", "raised"),
    ("more", "less"),
    ("less", "more"),
    ("greater", "smaller"),
    ("larger", "smaller"),
    ("smaller", "larger"),
    ("faster", "slower"),
    ("slower", "faster"),
    ("stronger", "weaker"),
    ("weaker", "stronger"),
    ("positive", "negative"),
    ("negative", "positive"),
    ("positively", "negatively"),
    ("negatively", "positively"),
    ("above", "below"),
    ("below", "above"),
    ("promotes", "inhibits"),
    ("inhibits", "promotes"),
    ("activates", "inhibits"),
];

/// A negated auxiliary and its affirmative form, longest spellings first so
/// `can not` wins over `can`.
const NEGATIONS: &[(&str, &str)] = &[
    ("does not", "does"),
    ("do not", "do"),
    ("did not", "did"),
    ("is not", "is"),
    ("are not", "are"),
    ("was not", "was"),
    ("were not", "were"),
    ("can not", "can"),
    ("cannot", "can"),
    ("will not", "will"),
    ("has not", "has"),
    ("have not", "have"),
    ("had not", "had"),
    ("should not", "should"),
    ("could not", "could"),
    ("would not", "would"),
    ("may not", "may"),
    ("might not", "might"),
    ("must not", "must"),
    ("doesn't", "does"),
    ("don't", "do"),
    ("didn't", "did"),
    ("isn't", "is"),
    ("aren't", "are"),
    ("wasn't", "was"),
    ("weren't", "were"),
    ("can't", "can"),
    ("won't", "will"),
    ("hasn't", "has"),
    ("haven't", "have"),
    ("shouldn't", "should"),
    ("couldn't", "could"),
    ("wouldn't", "would"),
    ("no longer", "still"),
];

/// Auxiliaries after which a bare `not` negates the clause.
const AUXILIARIES: &[&str] = &[
    "is", "are", "was", "were", "can", "will", "does", "do", "did", "has", "have", "had", "should",
    "could", "would", "may", "might", "must",
];

fn word_alternation<'a>(words: impl Iterator<Item = &'a str>) -> String {
    words.map(regex::escape).collect::<Vec<_>>().join("|")
}

fn inversion_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let alt = word_alternation(INVERSIONS.iter().map(|(w, _)| *w));
        Regex::new(&format!(r"(?i)\b(?:{alt})\b")).expect("inversion regex")
    })
}

fn negation_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // `\s+` between the words of a two-word negation; the apostrophe forms
        // match ASCII `'` only.
        let alt = NEGATIONS
            .iter()
            .map(|(n, _)| regex::escape(n).replace(' ', r"\s+"))
            .collect::<Vec<_>>()
            .join("|");
        Regex::new(&format!(r"(?i)\b(?:{alt})\b")).expect("negation regex")
    })
}

fn auxiliary_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let alt = word_alternation(AUXILIARIES.iter().copied());
        Regex::new(&format!(r"(?i)\b(?:{alt})\b")).expect("auxiliary regex")
    })
}

/// `replacement` in the case shape of `original`: all-caps stays all-caps, an
/// initial capital stays an initial capital, anything else is lower case.
fn match_case(original: &str, replacement: &str) -> String {
    let letters: Vec<char> = original.chars().filter(|c| c.is_alphabetic()).collect();
    if letters.len() > 1 && letters.iter().all(|c| c.is_uppercase()) {
        return replacement.to_uppercase();
    }
    if original.chars().next().is_some_and(char::is_uppercase) {
        let mut chars = replacement.chars();
        return match chars.next() {
            Some(first) => first.to_uppercase().chain(chars).collect(),
            None => String::new(),
        };
    }
    replacement.to_string()
}

fn lookup<'a>(table: &'a [(&'a str, &'a str)], key: &str) -> Option<&'a str> {
    let key = key.split_whitespace().collect::<Vec<_>>().join(" ");
    table
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(&key))
        .map(|(_, v)| *v)
}

/// Every directional word swapped for its opposite, or `None` when the text
/// carries no directional word.
fn invert_direction(text: &str) -> Option<String> {
    let re = inversion_re();
    if !re.is_match(text) {
        return None;
    }
    Some(
        re.replace_all(text, |caps: &Captures| {
            let word = &caps[0];
            lookup(INVERSIONS, word).map_or_else(|| word.to_string(), |r| match_case(word, r))
        })
        .into_owned(),
    )
}

/// The clause's polarity flipped: the first negation removed if there is one,
/// else `not` inserted after the first auxiliary, else the whole assertion
/// wrapped in "It is not the case that".
fn flip_negation(text: &str) -> String {
    if let Some(m) = negation_re().find(text) {
        let affirmative = lookup(NEGATIONS, m.as_str()).unwrap_or(m.as_str());
        return format!(
            "{}{}{}",
            &text[..m.start()],
            match_case(m.as_str(), affirmative),
            &text[m.end()..]
        );
    }
    if let Some(m) = auxiliary_re().find(text) {
        return format!("{} not{}", &text[..m.end()], &text[m.end()..]);
    }
    // Lower-case the first letter unless the first word is an acronym or a
    // proper-looking token with more capitals (e.g. "DNA", "McKinsey").
    let mut chars = text.chars();
    let body = match chars.next() {
        Some(first)
            if first.is_uppercase()
                && !text
                    .split_whitespace()
                    .next()
                    .is_some_and(|w| w.chars().skip(1).any(char::is_uppercase)) =>
        {
            first.to_lowercase().chain(chars).collect()
        }
        _ => text.to_string(),
    };
    format!("It is not the case that {body}")
}

/// Probe texts that argue against `content`: a directional inversion (when the
/// text has a directional word) and a negation flip, deduplicated, never equal
/// to the input, at most [`MAX_PROBES_PER_SEED`]. Empty for blank input.
#[must_use]
pub fn stance_probes(content: &str) -> Vec<String> {
    let text = content.trim();
    if text.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<String> = Vec::new();
    for probe in invert_direction(text)
        .into_iter()
        .chain(std::iter::once(flip_negation(text)))
    {
        let probe = probe.trim().to_string();
        if probe.is_empty()
            || probe.eq_ignore_ascii_case(text)
            || out.iter().any(|p| p.eq_ignore_ascii_case(&probe))
        {
            continue;
        }
        out.push(probe);
        if out.len() == MAX_PROBES_PER_SEED {
            break;
        }
    }
    out
}

/// What [`StanceProbeBlocker::prepare`] did with the seed set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StanceProbeStats {
    /// Seeds that got at least one probe vector.
    pub seeds_probed: usize,
    /// Probe texts embedded (and ANN-searched) across all seeds.
    pub probe_texts: usize,
    /// Seeds not probed: no stored embedding (so the vector space cannot be
    /// confirmed), blank content, or every probe vector had a dimension that
    /// differs from the seed's stored embedding.
    pub seeds_skipped: usize,
}

/// Candidate generator that ANN-searches stance-inverted probe vectors.
pub struct StanceProbeBlocker {
    top_k: usize,
    probes: Vec<(Uuid, Vec<f32>)>,
}

impl StanceProbeBlocker {
    /// A blocker over already-computed probe vectors, each tagged with the seed
    /// it argues against.
    #[must_use]
    pub fn from_probe_vectors(top_k: usize, probes: Vec<(Uuid, Vec<f32>)>) -> Self {
        Self { top_k, probes }
    }

    /// Build the probe texts for every seed and embed them with `embedder`.
    ///
    /// `embedder` must produce vectors in the same space as `claims.embedding`
    /// (the stored model); a vector whose length differs from the seed's stored
    /// embedding is dropped rather than searched, since pgvector refuses to
    /// compare vectors of different dimensions. A seed with no stored embedding
    /// is not probed.
    ///
    /// # Errors
    /// A database read failure, or any embedding call failure. An embedding
    /// failure is an error rather than a silent skip: the caller stamps the
    /// seeds as scanned on success, so a skipped probe stage would hide those
    /// seeds' contradictions until their next scan.
    pub async fn prepare(
        pool: &PgPool,
        embedder: &dyn EmbeddingService,
        seeds: &[Uuid],
        top_k: usize,
    ) -> anyhow::Result<(Self, StanceProbeStats)> {
        let mut stats = StanceProbeStats::default();
        if seeds.is_empty() {
            return Ok((Self::from_probe_vectors(top_k, Vec::new()), stats));
        }
        let rows: Vec<(Uuid, String, Option<i32>)> = sqlx::query_as(
            "SELECT id, content, vector_dims(embedding) FROM claims WHERE id = ANY($1)",
        )
        .bind(seeds)
        .fetch_all(pool)
        .await?;

        // (seed, seed's stored dimension, probe text)
        let mut texts: Vec<(Uuid, usize, String)> = Vec::new();
        let mut seen: HashSet<Uuid> = HashSet::new();
        for (id, content, dims) in rows {
            if !seen.insert(id) {
                continue;
            }
            let probes = stance_probes(&content);
            match (dims, probes.is_empty()) {
                (Some(d), false) if d > 0 => {
                    let d = usize::try_from(d).unwrap_or(0);
                    texts.extend(probes.into_iter().map(|p| (id, d, p)));
                }
                _ => stats.seeds_skipped += 1,
            }
        }

        let mut probes: Vec<(Uuid, Vec<f32>)> = Vec::with_capacity(texts.len());
        for chunk in texts.chunks(EMBED_CHUNK) {
            let batch: Vec<&str> = chunk.iter().map(|(_, _, t)| t.as_str()).collect();
            let vectors = embedder
                .batch_generate(&batch)
                .await
                .map_err(|e| anyhow::anyhow!("stance probe embedding failed: {e}"))?;
            if vectors.len() != chunk.len() {
                anyhow::bail!(
                    "stance probe embedding returned {} vectors for {} texts",
                    vectors.len(),
                    chunk.len()
                );
            }
            for ((seed, dims, _), v) in chunk.iter().zip(vectors) {
                if v.len() == *dims {
                    probes.push((*seed, v));
                }
            }
        }

        let probed: HashSet<Uuid> = probes.iter().map(|(s, _)| *s).collect();
        let with_texts: HashSet<Uuid> = texts.iter().map(|(s, _, _)| *s).collect();
        stats.seeds_probed = probed.len();
        stats.probe_texts = probes.len();
        stats.seeds_skipped += with_texts.difference(&probed).count();
        Ok((Self::from_probe_vectors(top_k, probes), stats))
    }
}

#[async_trait]
impl Blocker for StanceProbeBlocker {
    async fn candidates(
        &self,
        pool: &PgPool,
        seeds: &[Uuid],
    ) -> Result<Vec<CandidatePair>, sqlx::Error> {
        let wanted: HashSet<Uuid> = seeds.iter().copied().collect();
        let mut out: Vec<CandidatePair> = Vec::new();
        for (seed, vector) in &self.probes {
            if !wanted.contains(seed) {
                continue;
            }
            // Same shape as `EmbeddingAnnBlocker`: a constant operand against
            // `embedding` so the planner can use the HNSW cosine index.
            let neighbors: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT id FROM claims
                 WHERE id <> $1
                   AND embedding IS NOT NULL
                 ORDER BY embedding <=> $2::vector
                 LIMIT $3",
            )
            .bind(seed)
            .bind(epigraph_db::pgvector_literal(vector))
            .bind(i64::try_from(self.top_k).unwrap_or(i64::MAX))
            .fetch_all(pool)
            .await?;
            for (nbr,) in neighbors {
                if let Some(p) = canonical(*seed, nbr) {
                    out.push(p);
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    fn is_probe(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverts_directional_verb() {
        let p = stance_probes("Drug X increases survival in mice");
        assert_eq!(p[0], "Drug X decreases survival in mice");
    }

    #[test]
    fn inversion_preserves_case_and_swaps_every_direction_word() {
        assert_eq!(
            invert_direction("Higher doses improve recall").as_deref(),
            Some("Lower doses worsen recall")
        );
        assert_eq!(
            invert_direction("MORE is better").as_deref(),
            Some("LESS is better")
        );
    }

    #[test]
    fn inversion_matches_whole_words_only() {
        // "increasingly" and "Lowell" are not directional words.
        assert_eq!(invert_direction("Lowell is increasingly cited"), None);
    }

    #[test]
    fn negation_inserted_after_first_auxiliary() {
        assert_eq!(
            flip_negation("The effect is significant at p<0.05"),
            "The effect is not significant at p<0.05"
        );
    }

    #[test]
    fn existing_negation_is_removed() {
        assert_eq!(
            flip_negation("Caffeine does not improve endurance"),
            "Caffeine does improve endurance"
        );
        assert_eq!(
            flip_negation("The model can't generalise"),
            "The model can generalise"
        );
        assert_eq!(
            flip_negation("Doses   cannot exceed 5 mg"),
            "Doses   can exceed 5 mg"
        );
    }

    #[test]
    fn no_auxiliary_falls_back_to_not_the_case() {
        assert_eq!(
            flip_negation("Aspirin prevents strokes"),
            "It is not the case that aspirin prevents strokes"
        );
        assert_eq!(
            flip_negation("DNA origami folds in minutes"),
            "It is not the case that DNA origami folds in minutes"
        );
    }

    #[test]
    fn probes_are_distinct_non_identity_and_capped() {
        let input = "Higher temperature increases yield";
        let p = stance_probes(input);
        assert_eq!(
            p,
            vec![
                "Lower temperature decreases yield".to_string(),
                "It is not the case that higher temperature increases yield".to_string(),
            ]
        );
        assert!(p.len() <= MAX_PROBES_PER_SEED);
        assert!(p.iter().all(|x| x != input));
    }

    #[test]
    fn blank_content_has_no_probes() {
        assert!(stance_probes("   ").is_empty());
        assert!(stance_probes("").is_empty());
    }
}
