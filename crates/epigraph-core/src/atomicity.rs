//! The atomicity heuristic: is a claim already one atomic proposition?
//!
//! `decompose_claims` (epigraph-cli) skips claims this accepts, so they never
//! get a `decomposes_to` edge and stay in the undecomposed population. The
//! operator ruled (2026-10-14, backlog `5e1debbc`) that such claims are
//! TERMINAL by policy: not a backlog and not a defect. The MCP tool
//! `query_undecomposed_claims` flags them with the same function, so the two
//! surfaces cannot disagree about which rows are atomic.
//!
//! [`conjunct_screen`] is the finer, warn-only measure: an estimated count of
//! independent assertions per claim. `looks_atomic` decides what
//! `decompose_claims` skips by default; the screen decides what is reported as
//! compound (the `submit_claim` and `ingest_document` warnings, the
//! `screen_claim_atomicity` and `query_compound_claims` MCP tools, the
//! `atomicity_sweep` label and `decompose_claims --redecompose`). A claim can
//! look atomic and still screen compound ("X rose, but Y fell.").

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

/// The label the compound-atom sweep (`epigraph-cli`'s `atomicity_sweep`)
/// puts on a current atom (the target of a `decomposes_to` edge, with no
/// in-force `decomposes_to` children of its own) that [`conjunct_screen`]
/// calls compound, and takes off one that no longer qualifies.
pub const COMPOUND_ATOM_LABEL: &str = "compound-atom";

/// The [`ConjunctScreen::conjunct_count`] at which a claim screens compound.
pub const COMPOUND_MIN_CONJUNCTS: usize = 2;

/// What [`conjunct_screen`] counted in one claim's text.
///
/// The components are reported, not only the total, so a caller can see WHY a
/// claim screened compound: a narrative protocol or postmortem claim is
/// legitimately long, and the screen is a warning and a discovery key, never a
/// rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ConjunctScreen {
    /// [`sentence_count`] of the text.
    pub sentences: usize,
    /// Joins inside a sentence that start another independent clause: a `;`,
    /// or a comma followed by `and`, `but`, `yet`, `so`, `while`, `whereas`,
    /// `although`, `though` or `which`, or `whereas` alone. A `, and` that
    /// closes a comma list (`A, B, and C`) is not a join.
    pub clause_joins: usize,
    /// Distinct numeric quantities. A range written with a dash (`3-5 nm`) is
    /// one; a number glued to a letter (`CO2`, `Q3`, `v1.2`, `COVID-19`) and a
    /// bare four-digit year (1800 to 2199) are none.
    pub quantities: usize,
    /// The estimated number of independent assertions:
    /// `max(sentences + clause_joins, ceil(quantities / 2))`. Never below
    /// [`ConjunctScreen::sentences`].
    pub conjunct_count: usize,
}

impl ConjunctScreen {
    /// `conjunct_count >= COMPOUND_MIN_CONJUNCTS`.
    pub fn is_compound(&self) -> bool {
        self.conjunct_count >= COMPOUND_MIN_CONJUNCTS
    }
}

/// Words that, after a comma, start an independent clause.
const CLAUSE_CONNECTORS: [&str; 9] = [
    "and", "but", "yet", "so", "while", "whereas", "although", "though", "which",
];

/// Estimate how many logically independent assertions `text` makes.
///
/// A heuristic with no parser and no database, so the MCP server and the CLI
/// share it. Three signals, each documented on [`ConjunctScreen`]:
///
/// * sentences ([`sentence_count`]);
/// * clause joins inside a sentence;
/// * distinct numeric quantities, halved and rounded up: one fact often
///   carries two numbers (a change from one value to another, a value and its
///   uncertainty, a range written in words), so two quantities alone do not
///   make a claim compound, and three do.
///
/// Its errors run in both directions and are accepted because nothing is
/// refused on it. A noun-phrase `and` ("apples and pears are fruit") is not
/// counted, so "X rose and Y fell" without a comma is missed; a comma list
/// opened by an introductory phrase ("In May, X rose, and Y fell") reads as a
/// list and its join is missed; a non-restrictive `, which` that only
/// describes ("the lab, which is in Oslo") is counted.
pub fn conjunct_screen(text: &str) -> ConjunctScreen {
    let sentences = sentence_count(text);
    let clause_joins = clause_join_count(text);
    let quantities = quantity_count(text);
    ConjunctScreen {
        sentences,
        clause_joins,
        quantities,
        conjunct_count: (sentences + clause_joins).max(quantities.div_ceil(2)),
    }
}

/// [`ConjunctScreen::clause_joins`] of `text`.
fn clause_join_count(text: &str) -> usize {
    let chars: Vec<char> = text.trim().chars().collect();
    // The word starting at `i` (letters only, lower-cased) and where it ends.
    let word_at = |i: usize| -> (String, usize) {
        let mut j = i;
        while j < chars.len() && chars[j].is_alphabetic() {
            j += 1;
        }
        (chars[i..j].iter().collect::<String>().to_lowercase(), j)
    };
    let mut joins = 0;
    // Commas since the last sentence or clause boundary: a `, and` after one
    // closes a list rather than joining a clause.
    let mut commas = 0usize;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '.' | '!' | '?' | '\n' => commas = 0,
            ';' => {
                // A semicolon with more text after it joins two clauses.
                if chars[i + 1..].iter().any(|c| c.is_alphanumeric()) {
                    joins += 1;
                }
                commas = 0;
            }
            ',' if chars.get(i + 1).is_some_and(|c| c.is_whitespace()) => {
                let mut k = i + 1;
                while k < chars.len() && chars[k].is_whitespace() {
                    k += 1;
                }
                let (word, end) = word_at(k);
                let followed = chars.get(end).is_some_and(|c| c.is_whitespace());
                if followed && CLAUSE_CONNECTORS.contains(&word.as_str()) {
                    if word == "and" && commas > 0 {
                        // `A, B, and C`: a list tail.
                    } else {
                        joins += 1;
                        commas = 0;
                    }
                    i = end;
                    continue;
                }
                commas += 1;
            }
            _ if c.is_alphabetic() && (i == 0 || !chars[i - 1].is_alphanumeric()) => {
                let (word, end) = word_at(i);
                // `whereas` joins two clauses with or without a comma; the
                // comma form was counted (and skipped past) above.
                if word == "whereas" {
                    joins += 1;
                    commas = 0;
                }
                i = end;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    joins
}

/// [`ConjunctScreen::quantities`] of `text`.
fn quantity_count(text: &str) -> usize {
    let chars: Vec<char> = text.chars().collect();
    let dash = |c: char| matches!(c, '-' | '\u{2013}' | '\u{2014}');
    let mut seen = std::collections::BTreeSet::new();
    let mut i = 0;
    while i < chars.len() {
        if !chars[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        // Glued to a word on the left: `CO2`, `Q3`, `v1.2`, `COVID-19`.
        let glued = i > 0
            && (chars[i - 1].is_alphabetic()
                || chars[i - 1] == '_'
                || (dash(chars[i - 1]) && i > 1 && chars[i - 2].is_alphabetic()));
        let start = i;
        let mut j = i;
        loop {
            while j < chars.len() && chars[j].is_ascii_digit() {
                j += 1;
            }
            // A decimal point or thousands separator inside the number.
            if j + 1 < chars.len() && matches!(chars[j], '.' | ',') && chars[j + 1].is_ascii_digit()
            {
                j += 1;
                continue;
            }
            // A dash range (`3-5`, `3–5`) is one quantity.
            if j + 1 < chars.len() && dash(chars[j]) && chars[j + 1].is_ascii_digit() {
                j += 1;
                continue;
            }
            break;
        }
        let literal: String = chars[start..j].iter().collect();
        i = j;
        if glued {
            continue;
        }
        let year = literal.len() == 4
            && literal
                .parse::<u32>()
                .is_ok_and(|y| (1800..=2199).contains(&y));
        if !year {
            seen.insert(literal);
        }
    }
    seen.len()
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

    // --- conjunct screen ---

    fn screen(t: &str) -> ConjunctScreen {
        conjunct_screen(t)
    }

    #[test]
    fn a_single_assertion_screens_atomic() {
        let s = screen("Water boils at 100 C at sea level.");
        assert_eq!(
            s,
            ConjunctScreen {
                sentences: 1,
                clause_joins: 0,
                quantities: 1,
                conjunct_count: 1
            }
        );
        assert!(!s.is_compound());
    }

    #[test]
    fn a_noun_phrase_and_is_not_a_conjunct() {
        let s = screen("Apples and pears are fruit.");
        assert_eq!(s.clause_joins, 0);
        assert_eq!(s.conjunct_count, 1);
        assert!(!s.is_compound());
    }

    #[test]
    fn a_comma_list_tail_is_not_a_join() {
        let s = screen("Apples, pears, and plums are fruit.");
        assert_eq!(s.clause_joins, 0, "{s:?}");
        assert!(!s.is_compound());
    }

    #[test]
    fn one_sentence_joining_two_clauses_screens_compound() {
        // `looks_atomic` accepts this: one sentence, under the char cap. The
        // screen is what catches it.
        let t = "The catalyst raised the yield, but it shortened the column life.";
        assert!(looks_atomic(t));
        let s = screen(t);
        assert_eq!(s.sentences, 1);
        assert_eq!(s.clause_joins, 1);
        assert_eq!(s.conjunct_count, 2);
        assert!(s.is_compound());
        let semi = screen("The pump failed; the backup took over within seconds.");
        assert_eq!(semi.clause_joins, 1);
        assert!(semi.is_compound());
        let whereas = screen("Group A improved whereas group B declined.");
        assert_eq!(whereas.clause_joins, 1);
        assert!(whereas.is_compound());
        let comma_whereas = screen("Group A improved, whereas group B declined.");
        assert_eq!(comma_whereas.clause_joins, 1, "counted once, not twice");
    }

    #[test]
    fn a_trailing_semicolon_joins_nothing() {
        assert_eq!(screen("The pump failed;").clause_joins, 0);
    }

    #[test]
    fn several_sentences_screen_compound() {
        let s = screen("Gravity bends light. Time dilates near mass.");
        assert_eq!(s.sentences, 2);
        assert_eq!(s.conjunct_count, 2);
        assert!(s.is_compound());
    }

    #[test]
    fn quantities_count_distinct_numbers_not_identifiers_or_years() {
        // A decimal is one quantity; Q3 and epigraph.io are not quantities.
        assert_eq!(
            screen("Version 3.5 of epigraph.io ships in Q3.").quantities,
            1
        );
        assert_eq!(
            screen("CO2 and H2O levels rose in COVID-19 wards").quantities,
            0
        );
        assert_eq!(
            screen("In 2020 the yield was 40%.").quantities,
            1,
            "a year is context"
        );
        assert_eq!(
            screen("Particles were 3-5 nm wide.").quantities,
            1,
            "a range is one"
        );
        assert_eq!(screen("Particles were 3\u{2013}5 nm wide.").quantities, 1);
        assert_eq!(screen("The run took 1,200 seconds.").quantities, 1);
        assert_eq!(
            screen("Both arms took 12 days and 12 days.").quantities,
            1,
            "distinct"
        );
    }

    #[test]
    fn two_quantities_are_one_fact_three_are_several() {
        let change = screen("Throughput rose from 40 to 55 requests per second.");
        assert_eq!(change.quantities, 2);
        assert_eq!(change.conjunct_count, 1);
        assert!(!change.is_compound(), "a change from one value to another");
        let three = screen("The sample held 12 mg iron with 3 mg zinc at 7.4 pH");
        assert_eq!(three.quantities, 3);
        assert_eq!(three.sentences, 1);
        assert_eq!(three.conjunct_count, 2);
        assert!(
            three.is_compound(),
            "three numbers bound to different referents"
        );
    }

    #[test]
    fn the_count_is_never_below_the_sentence_count() {
        for t in [
            "",
            "One.",
            "One. Two. Three.",
            "- a\n- b\n- c",
            "A rose, and B fell; C held at 3, 4, 5 and 6.",
        ] {
            let s = screen(t);
            assert!(s.conjunct_count >= s.sentences, "{t:?}: {s:?}");
        }
        assert_eq!(screen(""), ConjunctScreen::default());
    }
}
