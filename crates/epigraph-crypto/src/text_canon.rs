//! Text canonicalization for *hash inputs* (backlog e09986c2).
//!
//! # What problem this solves
//!
//! A content address computed as BLAKE3 over the raw UTF-8 bytes of a string
//! is a function of BYTES, not of TEXT-AS-PERCEIVED. Three classes of
//! difference are invisible to a human reader yet fork the digest:
//!
//! 1. **Unicode normalization form.** `"café"` is `caf\u{00e9}` in NFC and
//!    `cafe\u{0301}` in NFD. macOS filesystems hand out NFD, most editors and
//!    web forms hand out NFC, and both render identically.
//! 2. **Invisible characters.** A zero-width space pasted out of a word
//!    processor or a BOM prepended by a Windows editor survives into the text
//!    and is unrenderable.
//! 3. **Whitespace runs.** A trailing newline, a double space after a full
//!    stop, a tab where a space was — the difference between text typed by
//!    hand and the same text round-tripped through a template.
//!
//! # What this module is NOT for
//!
//! This canonicalizes the **input to a hash**, never the stored text. The
//! submitter's bytes are preserved verbatim in the database; only the digest
//! used to *find* an equivalent row is computed over the canonical form. Do
//! not use [`canonicalize_for_hash`] to rewrite content before storing it —
//! the whole point of the split is that the graph keeps exactly what the agent
//! wrote.
//!
//! Nor is it a security boundary. It is not a homoglyph or confusable
//! defence (`а` U+0430 CYRILLIC A still differs from `a` U+0061, by design —
//! collapsing scripts would let one agent's claim silently absorb another's),
//! and it is not a Unicode-security profile such as UTS #39. It is a
//! dedup-recall aid, nothing more.

use unicode_normalization::UnicodeNormalization;

/// Format-control characters that carry no rendered width.
///
/// Deliberately a small, enumerated set rather than the whole `Cf` general
/// category: `Cf` also contains bidi controls (U+202A..U+202E, U+2066..U+2069)
/// whose removal can change the *visual order* of the surrounding text, so
/// stripping them would make two differently-reading strings hash alike.
///
/// - `U+200B` ZERO WIDTH SPACE
/// - `U+200C` ZERO WIDTH NON-JOINER
/// - `U+200D` ZERO WIDTH JOINER
/// - `U+2060` WORD JOINER
/// - `U+FEFF` ZERO WIDTH NO-BREAK SPACE (byte-order mark)
const ZERO_WIDTH: [char; 5] = ['\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}', '\u{FEFF}'];

#[inline]
fn is_zero_width(c: char) -> bool {
    ZERO_WIDTH.contains(&c)
}

/// Canonicalize `s` for use as a **hash input**.
///
/// Applies, in this exact order:
///
/// 1. **Strip zero-width format controls** (see [`ZERO_WIDTH`]).
/// 2. **NFC-normalize** the result.
/// 3. **Collapse** every run of [`char::is_whitespace`] to one ASCII space and
///    **trim** leading and trailing whitespace.
///
/// # Why the strip must precede the normalization
///
/// Zero-width joiners have combining class 0, so an interposed `U+200B` BLOCKS
/// canonical composition: `"e\u{200b}\u{0301}"` NFC-normalizes to itself, and
/// stripping afterwards would leave `"e\u{0301}"` — the decomposed form.
/// Running the function a second time would then compose it to `"é"`, giving
/// `canon(canon(x)) != canon(x)`. Stripping first makes the composition
/// visible to NFC and restores idempotency, which
/// `canonicalize_is_idempotent_over_adversarial_inputs` pins.
///
/// # Idempotency
///
/// `canonicalize_for_hash(&canonicalize_for_hash(x)) == canonicalize_for_hash(x)`
/// for every `x`. The output holds no zero-width controls, is in NFC, and
/// contains no whitespace other than single interior ASCII spaces — so a
/// second pass is a no-op. This matters because the digest is a persisted
/// lookup key: a non-idempotent canonicalizer would make a re-canonicalized
/// backfill disagree with the write path.
#[must_use]
pub fn canonicalize_for_hash(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_space = false;

    for ch in s.chars().filter(|c| !is_zero_width(*c)).nfc() {
        if ch.is_whitespace() {
            // Leading whitespace is dropped outright (nothing to separate);
            // an unflushed trailing `pending_space` is the trim.
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(ch);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three pairs from the backlog e09986c2 reproduction. Each renders
    /// identically on screen and must therefore share a canonical form.
    #[test]
    fn repro_pairs_collapse_to_one_canonical_form() {
        let cases: [(&str, &str); 3] = [
            // NFC vs NFD.
            (
                "The caf\u{00e9} protocol raises yield.",
                "The cafe\u{0301} protocol raises yield.",
            ),
            // Zero-width space and BOM.
            (
                "Ribosome profiling resolves translation rates.",
                "Ribosome\u{200b} profiling resolves translation\u{feff} rates.",
            ),
            // Double space and trailing newline.
            (
                "CRISPR knockouts reduce tumour volume.",
                "CRISPR  knockouts reduce tumour volume.\n",
            ),
        ];

        for (a, b) in cases {
            assert_ne!(a, b, "fixture: the pair must be byte-distinct");
            assert_eq!(
                canonicalize_for_hash(a),
                canonicalize_for_hash(b),
                "cosmetic variants must share a canonical form: {a:?} vs {b:?}"
            );
        }
    }

    #[test]
    fn canonicalize_is_idempotent_over_adversarial_inputs() {
        let inputs = [
            "",
            " ",
            "\u{feff}",
            "  \t\n  ",
            "plain text",
            "  leading and trailing  ",
            "cafe\u{0301}",
            // The blocked-composition case that forces strip-before-NFC.
            "e\u{200b}\u{0301}",
            "a\u{200d}\u{200c}b",
            "line one\nline two\r\nline three",
            "\u{2060}\u{200b}only invisibles\u{feff}",
            "tabs\tand\u{00a0}nbsp",
            "\u{0301}leading combining mark",
            "  \u{feff} \u{0301}x  ",
            "mixed   \u{200b}  spacing\u{feff}\t\tand\nnewlines  ",
        ];

        for input in inputs {
            let once = canonicalize_for_hash(input);
            let twice = canonicalize_for_hash(&once);
            assert_eq!(once, twice, "canon must be idempotent for {input:?}");
        }
    }

    #[test]
    fn output_carries_no_zero_width_and_only_single_ascii_spaces() {
        let canon = canonicalize_for_hash("a\u{200b}b \t\n c\u{feff}  d  ");
        assert_eq!(canon, "ab c d");
        assert!(!canon.chars().any(is_zero_width));
        assert!(!canon.contains("  "));
        assert_eq!(canon.trim(), canon);
    }

    #[test]
    fn nbsp_and_other_unicode_whitespace_collapse_to_ascii_space() {
        // U+00A0 NBSP, U+2009 THIN SPACE, U+3000 IDEOGRAPHIC SPACE all satisfy
        // char::is_whitespace and must not survive as distinct separators.
        assert_eq!(canonicalize_for_hash("a\u{00a0}b"), "a b");
        assert_eq!(canonicalize_for_hash("a\u{2009}b"), "a b");
        assert_eq!(canonicalize_for_hash("a\u{3000}b"), "a b");
        assert_eq!(canonicalize_for_hash("a\u{00a0}\u{2009}b"), "a b");
    }

    #[test]
    fn whitespace_only_input_canonicalizes_to_empty() {
        for input in ["", " ", "\t", "\n", "  \r\n\t ", "\u{200b}", "\u{feff} "] {
            assert_eq!(canonicalize_for_hash(input), "");
        }
    }

    /// Canonicalization must not collapse text that genuinely differs. If it
    /// did, one agent's claim would silently absorb another's.
    #[test]
    fn semantically_distinct_text_stays_distinct() {
        let distinct = [
            ("yield rises", "yield falls"),
            // Word boundaries are load-bearing: collapsing a space entirely
            // (rather than to one space) would merge these.
            ("the rapist", "therapist"),
            // Homoglyphs are deliberately NOT folded (Cyrillic а vs Latin a).
            ("\u{0430}pple", "apple"),
            // Case is not folded either.
            ("Yield", "yield"),
        ];

        for (a, b) in distinct {
            assert_ne!(
                canonicalize_for_hash(a),
                canonicalize_for_hash(b),
                "distinct text must not be folded together: {a:?} vs {b:?}"
            );
        }
    }

    #[test]
    fn already_canonical_text_is_returned_unchanged() {
        let text = "Mitochondrial density predicts endurance capacity.";
        assert_eq!(canonicalize_for_hash(text), text);
    }
}
