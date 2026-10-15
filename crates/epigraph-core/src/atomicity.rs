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
}
