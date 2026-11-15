//! The atomicity heuristic: is a claim already one atomic proposition?
//!
//! `decompose_claims` (epigraph-cli) skips claims this accepts, so they never
//! get a `decomposes_to` edge and stay in the undecomposed population. The
//! operator ruled (2026-10-14, backlog `5e1debbc`) that such claims are
//! TERMINAL by policy: not a backlog and not a defect. The MCP tool
//! `query_undecomposed_claims` flags them with the same function, so the two
//! surfaces cannot disagree about which rows are atomic.

/// Longest claim, in Unicode scalar values, that [`looks_atomic`] may call
/// atomic. Chosen by the operator brief (2026-09-24): "one sentence and ≤ 160
/// chars".
pub const ATOMIC_MAX_CHARS: usize = 160;

/// Number of sentences in `text`, by a deliberately simple rule.
///
/// A boundary is either
/// * a run of `.` `!` `?` (plus any closing quote/bracket), followed by
///   whitespace, followed by an uppercase letter, a digit, or an opening
///   quote/bracket; or
/// * a line break between two non-blank lines (bullet lists, pasted notes).
///
/// It errs toward COUNTING a boundary: `"Dr. Smith"` and `"e.g. The"` read as
/// two sentences. That direction only sends a claim to the LLM that could have
/// been skipped; the opposite error would silently skip a compound claim.
/// Decimals (`3.5`) and dotted identifiers (`epigraph.io`) never count, because
/// no whitespace follows the dot.
pub fn sentence_count(text: &str) -> usize {
    let chars: Vec<char> = text.trim().chars().collect();
    if chars.is_empty() {
        return 0;
    }
    let closing = |c: char| matches!(c, '"' | '\'' | ')' | ']' | '\u{201d}' | '\u{2019}');
    let opening = |c: char| matches!(c, '"' | '\'' | '(' | '[' | '\u{201c}' | '\u{2018}');
    let mut n = 1;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if matches!(c, '.' | '!' | '?') {
            let mut j = i + 1;
            while j < chars.len() && (matches!(chars[j], '.' | '!' | '?') || closing(chars[j])) {
                j += 1;
            }
            let mut k = j;
            while k < chars.len() && chars[k].is_whitespace() {
                k += 1;
            }
            if k > j && k < chars.len() {
                let next = chars[k];
                if next.is_uppercase() || next.is_ascii_digit() || opening(next) {
                    n += 1;
                    // The whitespace run is consumed: a newline inside it must
                    // not count the same boundary twice.
                    i = k;
                    continue;
                }
            }
            i = j;
        } else if c == '\n' {
            // A line break between non-blank lines is a boundary.
            let mut k = i + 1;
            while k < chars.len() && chars[k].is_whitespace() {
                k += 1;
            }
            if k < chars.len() {
                n += 1;
            }
            i = k;
        } else {
            i += 1;
        }
    }
    n
}

/// Whether `content` is already atomic enough that decomposing it would spend
/// an LLM call to get the claim back unchanged: exactly one sentence (see
/// [`sentence_count`]) and at most [`ATOMIC_MAX_CHARS`] characters.
///
/// This is the ONE definition of the heuristic; `decompose_claims`' eligibility
/// filter and its report (`epigraph_cli::decompose`, via a re-export) and the
/// `looks_atomic` flag on `query_undecomposed_claims` all call it.
pub fn looks_atomic(content: &str) -> bool {
    sentence_count(content) <= 1 && content.trim().chars().count() <= ATOMIC_MAX_CHARS
}

// =============================================================================
// CONJUNCT ESTIMATE: how many independent assertions does a claim carry?
// =============================================================================

/// Signal name: the text has more than one sentence ([`sentence_count`]'s
/// boundaries).
pub const SIGNAL_SENTENCES: &str = "sentences";
/// Signal name: a sentence has `;` outside parentheses.
pub const SIGNAL_SEMICOLON: &str = "semicolon";
/// Signal name: `and` / `but` / `whereas` / `while` joins two parts that each
/// have a finite verb.
pub const SIGNAL_COORDINATION: &str = "coordination";
/// Signal name: an inline enumeration, `(1) … (2) …`, `1) … 2) …`,
/// `(a) … (b) …` or `(i) … (ii) …`.
pub const SIGNAL_ENUMERATION: &str = "enumeration";
/// Signal name: `respectively`, which binds several values to several
/// referents in one clause.
pub const SIGNAL_RESPECTIVELY: &str = "respectively";

/// An estimated count of at least this many makes a claim compound-suspect.
pub const COMPOUND_SUSPECT_MIN_CONJUNCTS: usize = 2;

/// What [`conjunct_estimate`] found in one claim.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConjunctEstimate {
    /// Estimated number of independently assertable statements. 0 for blank
    /// text, otherwise at least 1.
    pub count: usize,
    /// The rules that raised `count` above 1, each at most once, in the fixed
    /// order sentences, semicolon, coordination, enumeration, respectively.
    /// Empty when `count <= 1`.
    pub signals: Vec<&'static str>,
}

impl ConjunctEstimate {
    /// Whether the claim probably asserts several independent conjuncts
    /// (`count >= COMPOUND_SUSPECT_MIN_CONJUNCTS`).
    pub fn compound_suspect(&self) -> bool {
        self.count >= COMPOUND_SUSPECT_MIN_CONJUNCTS
    }
}

/// Estimate how many independent assertions `text` makes (backlog `72850d43`).
///
/// A COUNT with the rules that produced it, not a verdict: narrative protocol
/// and postmortem claims are legitimately long, so nothing should reject on
/// it. It is advisory and separate from [`looks_atomic`], which stays the one
/// rule `decompose_claims` skips on. The two can disagree: a short single
/// sentence such as `"The test passed and the build failed."` is
/// `looks_atomic` (terminal by the 2026-10-14 ruling) and has an estimate
/// of 2.
///
/// Deterministic, no model, no lexicon beyond the closed word lists in this
/// file. Per sentence (the boundaries are [`sentence_count`]'s) the estimate
/// is the largest of:
///
/// * the clauses: the sentence is cut at every `;` outside parentheses, and
///   each piece counts once, or once per part when `and` / `but` / `whereas` /
///   `while` separates parts that EACH hold a finite verb and at least two
///   words (`"A binds B and C"` is one; `"A binds B and inhibits C"` is two);
/// * the items of an inline enumeration (`(1) … (2) … (3) …`);
/// * 2, when the sentence says `respectively`.
///
/// The sentence estimates are summed.
///
/// Unlike [`sentence_count`], the coordination rule errs toward NOT counting:
/// finite verbs are recognised from a closed list plus `-ed` forms (not after
/// a determiner or preposition, not before a participial preposition), so
/// `"Yields rose and costs fell"` counts 2 but a sentence whose verbs are
/// outside the list counts 1. A hit is meant to be labelled and sent for
/// re-decomposition, and a wrong label on an atomic claim is noise on every
/// later read, so precision is preferred. Known false positives: parenthesised
/// citation numbers `(1) … (2)` read as an enumeration, and a participle used
/// as an adjective right after a conjunction (`"The kit contains buffer and
/// prepared slides."` counts 2).
/// Several numeric quantities bound to different referents are NOT detected
/// except through `;` and `respectively`.
pub fn conjunct_estimate(text: &str) -> ConjunctEstimate {
    let sentences = split_sentences(text);
    if sentences.is_empty() {
        return ConjunctEstimate::default();
    }
    let mut count = 0;
    let (mut semicolon, mut coordination, mut enumeration, mut respectively) =
        (false, false, false, false);
    for sentence in &sentences {
        let flat = strip_parenthesised(sentence);
        let mut clauses = 0;
        let mut pieces = 0;
        for piece in flat.split(';') {
            let tokens = tokenize(piece);
            if tokens.is_empty() {
                continue;
            }
            pieces += 1;
            let parts = coordinated_clauses(&tokens);
            if parts > 1 {
                coordination = true;
            }
            clauses += parts;
        }
        if pieces > 1 {
            semicolon = true;
        }
        let mut best = clauses.max(1);
        let items = inline_enumeration_items(sentence);
        if items > best {
            best = items;
            enumeration = true;
        }
        if best < 2 && tokenize(&flat).iter().any(|t| t == "respectively") {
            best = 2;
            respectively = true;
        }
        count += best;
    }
    let mut signals = Vec::new();
    if count > 1 {
        for (on, name) in [
            (sentences.len() > 1, SIGNAL_SENTENCES),
            (semicolon, SIGNAL_SEMICOLON),
            (coordination, SIGNAL_COORDINATION),
            (enumeration, SIGNAL_ENUMERATION),
            (respectively, SIGNAL_RESPECTIVELY),
        ] {
            if on {
                signals.push(name);
            }
        }
    }
    ConjunctEstimate { count, signals }
}

/// `text` cut at [`sentence_count`]'s boundaries. The loop is that function's,
/// collecting the pieces instead of counting them; `split_matches_count` in
/// the tests holds the two together.
fn split_sentences(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.trim().chars().collect();
    let mut out = Vec::new();
    if chars.is_empty() {
        return out;
    }
    let closing = |c: char| matches!(c, '"' | '\'' | ')' | ']' | '\u{201d}' | '\u{2019}');
    let opening = |c: char| matches!(c, '"' | '\'' | '(' | '[' | '\u{201c}' | '\u{2018}');
    let mut start = 0;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if matches!(c, '.' | '!' | '?') {
            let mut j = i + 1;
            while j < chars.len() && (matches!(chars[j], '.' | '!' | '?') || closing(chars[j])) {
                j += 1;
            }
            let mut k = j;
            while k < chars.len() && chars[k].is_whitespace() {
                k += 1;
            }
            if k > j && k < chars.len() {
                let next = chars[k];
                if next.is_uppercase() || next.is_ascii_digit() || opening(next) {
                    out.push(chars[start..j].iter().collect());
                    start = k;
                    i = k;
                    continue;
                }
            }
            i = j;
        } else if c == '\n' {
            let mut k = i + 1;
            while k < chars.len() && chars[k].is_whitespace() {
                k += 1;
            }
            if k < chars.len() {
                out.push(chars[start..i].iter().collect());
                start = k;
            }
            i = k;
        } else {
            i += 1;
        }
    }
    out.push(chars[start..].iter().collect());
    out
}

/// `text` without anything inside `(…)` or `[…]`, so `(p < 0.05; n = 12)` and
/// `(mean and SD)` cut nothing. An unmatched closer is dropped.
fn strip_parenthesised(text: &str) -> String {
    let mut depth = 0usize;
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// Lower-cased whitespace-separated words, with punctuation trimmed from both
/// ends (an inner apostrophe or hyphen stays). Words that were only
/// punctuation are dropped.
fn tokenize(text: &str) -> Vec<String> {
    text.split_whitespace()
        .map(|w| {
            w.trim_matches(|c: char| !c.is_alphanumeric())
                .to_lowercase()
        })
        .filter(|w| !w.is_empty())
        .collect()
}

/// The conjunctions the coordination rule cuts at. `or` is absent: a
/// disjunction asserts neither side.
const COORDINATORS: [&str; 4] = ["and", "but", "whereas", "while"];

/// Auxiliaries, copulas and modals.
const AUXILIARIES: [&str; 33] = [
    "is", "are", "was", "were", "has", "have", "had", "does", "do", "did", "can", "could", "will",
    "would", "shall", "should", "may", "might", "must", "cannot", "isn't", "aren't", "wasn't",
    "weren't", "hasn't", "haven't", "hadn't", "doesn't", "don't", "didn't", "can't", "won't",
    "couldn't",
];

/// Frequent finite verbs of the corpus that the `-ed` rule cannot see: third
/// person singular presents and irregular pasts.
const FINITE_VERBS: [&str; 64] = [
    "increases",
    "decreases",
    "shows",
    "binds",
    "causes",
    "reduces",
    "requires",
    "uses",
    "returns",
    "fails",
    "passes",
    "holds",
    "gives",
    "takes",
    "makes",
    "yields",
    "produces",
    "contains",
    "remains",
    "becomes",
    "became",
    "exists",
    "needs",
    "runs",
    "ran",
    "writes",
    "wrote",
    "reads",
    "rose",
    "fell",
    "grew",
    "found",
    "led",
    "leads",
    "means",
    "works",
    "breaks",
    "broke",
    "keeps",
    "kept",
    "went",
    "goes",
    "gets",
    "got",
    "depends",
    "supports",
    "contradicts",
    "refutes",
    "implies",
    "predicts",
    "matches",
    "differs",
    "exceeds",
    "drops",
    "rises",
    "falls",
    "appears",
    "occurs",
    "lacks",
    "allows",
    "prevents",
    "enables",
    "skips",
    "stores",
];

/// Words after which an `-ed` form is a modifier, not a finite verb
/// (`the filtered rows`, `of retired edges`).
const MODIFIER_LEADS: [&str; 20] = [
    "the", "a", "an", "this", "that", "these", "those", "its", "their", "each", "every", "any",
    "no", "of", "in", "by", "with", "for", "to", "from",
];

/// Prepositions that, right after an `-ed` form, mark it as a participial
/// modifier (`the arm, measured under two buffers, turns`). `by` and `to` are
/// left out: `increased by 20%` and `dropped to zero` are finite far more
/// often than not.
const PARTICIPLE_TAILS: [&str; 17] = [
    "under", "from", "on", "in", "with", "at", "for", "as", "during", "using", "via", "across",
    "over", "through", "into", "within", "against",
];

/// `-ed` words that are not past forms.
const NOT_PAST_FORMS: [&str; 5] = ["embed", "hundred", "sacred", "naked", "wicked"];

/// Whether `tokens[i]` reads as a finite verb. `first_part` is true for the
/// part before the first coordinator, which must carry its own subject: there
/// an `-ed` form in first position is a modifier (`Retired edges …`), while a
/// later part may open with one (`… and decreased C`, subject shared).
fn is_finite_verb(tokens: &[String], i: usize, first_part: bool) -> bool {
    let t = tokens[i].as_str();
    if AUXILIARIES.contains(&t) || FINITE_VERBS.contains(&t) {
        return true;
    }
    if t.len() < 4 || !t.ends_with("ed") || t.ends_with("eed") || NOT_PAST_FORMS.contains(&t) {
        return false;
    }
    if tokens
        .get(i + 1)
        .is_some_and(|next| PARTICIPLE_TAILS.contains(&next.as_str()))
    {
        return false;
    }
    if i == 0 {
        return !first_part;
    }
    !MODIFIER_LEADS.contains(&tokens[i - 1].as_str())
}

/// Number of coordinated clauses in one `;`-free piece: its parts between
/// coordinators that hold a finite verb and at least two words, and never
/// less than 1. A coordinator between two numbers (`between 3 and 5`) does not
/// cut.
fn coordinated_clauses(tokens: &[String]) -> usize {
    let starts_with_digit = |t: &String| t.chars().next().is_some_and(|c| c.is_ascii_digit());
    let mut clauses = 0;
    let mut part: Vec<String> = Vec::new();
    let mut first_part = true;
    let mut close = |part: &mut Vec<String>, first_part: &mut bool| {
        if part.len() >= 2 && (0..part.len()).any(|i| is_finite_verb(part, i, *first_part)) {
            clauses += 1;
        }
        part.clear();
        *first_part = false;
    };
    for (i, t) in tokens.iter().enumerate() {
        let numeric_range = i > 0
            && i + 1 < tokens.len()
            && starts_with_digit(&tokens[i - 1])
            && starts_with_digit(&tokens[i + 1]);
        if COORDINATORS.contains(&t.as_str()) && !numeric_range {
            close(&mut part, &mut first_part);
        } else {
            part.push(t.clone());
        }
    }
    close(&mut part, &mut first_part);
    clauses.max(1)
}

/// Items of an inline enumeration in `sentence`: the longest of the runs
/// `(1) (2) …` / `1) 2) …`, `(a) (b) …` and `(i) (ii) …` that starts at its
/// first label and keeps order. 0 when no run reaches two items.
fn inline_enumeration_items(sentence: &str) -> usize {
    const ROMAN: [&str; 8] = ["i", "ii", "iii", "iv", "v", "vi", "vii", "viii"];
    let (mut number, mut letter, mut roman) = (0usize, 0u8, 0usize);
    for word in sentence.split_whitespace() {
        let word = word.trim_end_matches([',', ';', ':', '.']);
        let Some(body) = word.strip_suffix(')') else {
            continue;
        };
        let (label, parenthesised) = match body.strip_prefix('(') {
            Some(inner) => (inner, true),
            None => (body, false),
        };
        if label.is_empty() || label.len() > 4 {
            continue;
        }
        if label.chars().all(|c| c.is_ascii_digit()) {
            if label.parse::<usize>().ok() == Some(number + 1) {
                number += 1;
            }
            continue;
        }
        // A bare `a)` is too often the tail of a parenthetical; letters and
        // roman numerals need both brackets.
        if !parenthesised {
            continue;
        }
        if roman < ROMAN.len() && label == ROMAN[roman] {
            roman += 1;
        }
        if label.len() == 1 && label.as_bytes()[0] == b'a' + letter && letter < 26 {
            letter += 1;
        }
    }
    let items = number.max(letter as usize).max(roman);
    if items >= 2 {
        items
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_short_sentence_looks_atomic() {
        assert_eq!(sentence_count("Water boils at 100 C at sea level."), 1);
        assert!(looks_atomic("Water boils at 100 C at sea level."));
        // No terminal punctuation at all is still one sentence.
        assert!(looks_atomic("Gravity bends light"));
    }

    #[test]
    fn two_sentences_are_not_atomic_even_when_short() {
        let t = "Gravity bends light. Time dilates near mass.";
        assert_eq!(sentence_count(t), 2);
        assert!(
            !looks_atomic(t),
            "two sentences are compound regardless of length"
        );
        assert_eq!(sentence_count("Is it true? Yes! It is."), 3);
    }

    #[test]
    fn one_long_sentence_is_not_atomic() {
        let long = format!("The system {} works.", "really ".repeat(30));
        assert_eq!(sentence_count(&long), 1);
        assert!(long.chars().count() > ATOMIC_MAX_CHARS);
        assert!(
            !looks_atomic(&long),
            "over the char cap is compound-suspect"
        );
    }

    #[test]
    fn the_char_cap_is_inclusive_and_counts_chars_not_bytes() {
        let exact = "a".repeat(ATOMIC_MAX_CHARS);
        assert!(looks_atomic(&exact), "exactly the cap is still atomic");
        let over = "a".repeat(ATOMIC_MAX_CHARS + 1);
        assert!(!looks_atomic(&over));
        // 160 two-byte chars: 320 bytes, 160 chars -> atomic.
        let multibyte = "é".repeat(ATOMIC_MAX_CHARS);
        assert!(multibyte.len() > ATOMIC_MAX_CHARS);
        assert!(looks_atomic(&multibyte), "cap is in chars, not bytes");
    }

    #[test]
    fn decimals_and_dotted_names_are_not_boundaries() {
        assert_eq!(sentence_count("Version 3.5 of epigraph.io ships in Q3."), 1);
        assert_eq!(sentence_count("pH was 7.4 in the sample"), 1);
    }

    #[test]
    fn lowercase_after_a_period_is_not_a_boundary() {
        // Conservative in the other direction would be wrong here: "etc. and"
        // continues the sentence.
        assert_eq!(sentence_count("apples, pears, etc. are fruit"), 1);
    }

    #[test]
    fn line_breaks_between_non_blank_lines_are_boundaries() {
        assert_eq!(sentence_count("- first point\n- second point"), 2);
        assert_eq!(sentence_count("First line.\nSecond line."), 2);
        // A trailing newline adds nothing.
        assert_eq!(sentence_count("Only line.\n\n"), 1);
    }

    #[test]
    fn empty_text_has_no_sentences() {
        assert_eq!(sentence_count(""), 0);
        assert_eq!(sentence_count("   "), 0);
    }

    // ── conjunct_estimate ────────────────────────────────────────────────────

    fn est(text: &str) -> (usize, Vec<&'static str>) {
        let e = conjunct_estimate(text);
        (e.count, e.signals)
    }

    #[test]
    fn split_matches_count() {
        for t in [
            "",
            "   ",
            "Gravity bends light",
            "Gravity bends light. Time dilates near mass.",
            "Is it true? Yes! It is.",
            "Version 3.5 of epigraph.io ships in Q3.",
            "apples, pears, etc. are fruit",
            "- first point\n- second point",
            "First line.\nSecond line.",
            "Only line.\n\n",
            "He said \"stop.\" Then it stopped.\n\nlast line",
        ] {
            assert_eq!(
                split_sentences(t).len(),
                sentence_count(t),
                "split_sentences and sentence_count disagree on {t:?}"
            );
        }
        assert_eq!(
            split_sentences("First line.\nSecond one. Third."),
            vec!["First line.", "Second one.", "Third."]
        );
    }

    #[test]
    fn a_single_assertion_estimates_one_with_no_signal() {
        for t in [
            "Water boils at 100 C at sea level.",
            "The rotor arm friction coefficient is about 4e-22 N m s.",
            // Coordinated NOUN phrases, one predicate.
            "Claims and edges are tenanted by owner group.",
            "Protein A binds B and C.",
            // Coordinated adjectives.
            "The scaffold is longer and stiffer than the staple strands.",
            // A numeric range.
            "The yield was between 3 and 5 percent when the buffer was fresh.",
            // Modifiers ending in -ed are not finite verbs.
            "Retired edges and deprecated claims are hidden from recall.",
            // A disjunction asserts neither side.
            "The run fails or the token is refused.",
            // Punctuation inside parentheses cuts nothing.
            "The effect was significant (p < 0.05; n = 12 and 14).",
            // An imperative protocol step with a compound object.
            "Mix the scaffold and the staples in folding buffer.",
        ] {
            assert_eq!(est(t), (1, vec![]), "{t:?}");
            assert!(!conjunct_estimate(t).compound_suspect(), "{t:?}");
        }
    }

    #[test]
    fn blank_text_estimates_zero() {
        assert_eq!(est(""), (0, vec![]));
        assert_eq!(est("  \n "), (0, vec![]));
    }

    #[test]
    fn sentences_are_summed() {
        assert_eq!(
            est("Gravity bends light. Time dilates near mass."),
            (2, vec![SIGNAL_SENTENCES])
        );
        assert_eq!(
            est("- the sweep is read-only\n- labels are written by the caller\n- nothing is superseded"),
            (3, vec![SIGNAL_SENTENCES])
        );
    }

    #[test]
    fn semicolons_outside_parentheses_cut() {
        assert_eq!(
            est("Folding buffer: Tris 50 mM; NaCl 100 mM; MgCl2 12.5 mM."),
            (3, vec![SIGNAL_SEMICOLON])
        );
        assert_eq!(
            est("The migration adds the column; the backfill fills it."),
            (2, vec![SIGNAL_SEMICOLON])
        );
        // A trailing semicolon adds no empty piece.
        assert_eq!(est("The migration adds the column;"), (1, vec![]));
    }

    #[test]
    fn coordination_counts_only_parts_with_a_finite_verb() {
        // Two full clauses.
        assert_eq!(
            est("The test passed and the build failed."),
            (2, vec![SIGNAL_COORDINATION])
        );
        // Shared subject, two predicates.
        assert_eq!(
            est("The inhibitor increased the folding yield and decreased aggregation."),
            (2, vec![SIGNAL_COORDINATION])
        );
        assert_eq!(
            est("Magnesium stabilises the lattice but EDTA is required for release."),
            // `stabilises` is outside the closed list: one part counts.
            (1, vec![])
        );
        assert_eq!(
            est("Magnesium is needed for folding but EDTA is required for release."),
            (2, vec![SIGNAL_COORDINATION])
        );
        assert_eq!(
            est("Salt and pepper are spices and sugar is sweet, whereas vinegar is sour."),
            (3, vec![SIGNAL_COORDINATION])
        );
        // The estimate and `looks_atomic` are independent rules.
        assert!(looks_atomic("The test passed and the build failed."));
        assert!(conjunct_estimate("The test passed and the build failed.").compound_suspect());
    }

    #[test]
    fn inline_enumerations_count_their_items() {
        assert_eq!(
            est("The screen reports (1) the sentence count, (2) the clause count and (3) the signals."),
            (3, vec![SIGNAL_ENUMERATION])
        );
        assert_eq!(
            est("Three failure modes: (a) no token, (b) wrong scope, (c) expired grant."),
            (3, vec![SIGNAL_ENUMERATION])
        );
        assert_eq!(
            est("Two phases: (i) spine ingest, (ii) atom extraction."),
            (2, vec![SIGNAL_ENUMERATION])
        );
        // One label is a reference, not a list; and a run must start at 1.
        assert_eq!(est("The result of step (2) is reused."), (1, vec![]));
        assert_eq!(est("See equation (1) for the definition."), (1, vec![]));
    }

    /// A participial phrase is not a clause: `measured under …` modifies the
    /// subject, and the coordinated nouns inside it cut nothing.
    #[test]
    fn a_participial_phrase_is_not_a_clause() {
        assert_eq!(
            est(
                "The rotor arm, measured under several buffer conditions and temperatures, \
                 turns with a friction coefficient of about 4e-22 N m s."
            ),
            (1, vec![])
        );
        // `by` stays finite: the common quantitative phrasing must count.
        assert_eq!(
            est("The folding yield increased by 20% and aggregation decreased by half."),
            (2, vec![SIGNAL_COORDINATION])
        );
    }

    /// The documented false positive, pinned so a change to the `-ed` rule
    /// has to update the doc comment with it.
    #[test]
    fn a_participle_after_a_conjunction_is_a_known_false_positive() {
        assert_eq!(
            est("The kit contains buffer and prepared slides."),
            (2, vec![SIGNAL_COORDINATION])
        );
    }

    #[test]
    fn respectively_binds_two_referents() {
        assert_eq!(
            est("The melting points of the two designs were 52 C and 58 C, respectively."),
            (2, vec![SIGNAL_RESPECTIVELY])
        );
    }

    #[test]
    fn signals_combine_in_fixed_order() {
        let e = conjunct_estimate(
            "The first run passed and the second run failed; the cause was a stale token. \
             Retries were disabled.",
        );
        assert_eq!(e.count, 4);
        assert_eq!(
            e.signals,
            vec![SIGNAL_SENTENCES, SIGNAL_SEMICOLON, SIGNAL_COORDINATION]
        );
        assert!(e.compound_suspect());
    }
}
