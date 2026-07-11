//! Conservative author-byline recovery from raw document body text.
//!
//! Hierarchical extraction occasionally drops `source.authors` (empty array),
//! leaving `ingest_document` with no real authors to attribute a paper to.
//! [`parse_byline_authors`] is a defensive backstop: it scans the *top* of the
//! source text for the author byline that typically sits between the title and
//! the abstract, and returns the parsed names.
//!
//! The parser is deliberately **conservative** — it must never turn title
//! words into fake author agents. When it is not confident it returns an empty
//! `Vec`, which is exactly the existing behavior (the Rust write path inserts
//! no placeholder author). False negatives are safe; false positives are the
//! enemy, because each fake name mints a deterministic author agent that then
//! pollutes co-authorship edges across every paper that shares the phrase.

use crate::common::schema::AuthorEntry;

/// Number of leading lines to consider — the byline of an arXiv/journal paper
/// sits within the first handful of lines, above the abstract.
const MAX_SCAN_LINES: usize = 15;

/// Attempt to recover author names from the byline near the top of `source_text`.
///
/// Returns the parsed authors, or an empty `Vec` when no confident byline is
/// found. Conservative by construction: a candidate line only qualifies when
/// *every* comma / `and`-separated segment is name-shaped (see
/// [`segment_is_name_shaped`]).
#[must_use]
pub fn parse_byline_authors(source_text: &str) -> Vec<AuthorEntry> {
    // Scan the leading lines, stopping at the abstract (the byline is always
    // above it). Skip the very first non-empty line: that is the title, and a
    // title can incidentally be name-shaped ("Firstname Lastname" as a subject).
    let mut seen_first_content = false;
    for raw_line in source_text.lines().take(MAX_SCAN_LINES) {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if is_abstract_marker(line) {
            break;
        }
        if !seen_first_content {
            // This is the title line; never mine it for authors.
            seen_first_content = true;
            continue;
        }
        if let Some(authors) = parse_byline_line(line) {
            return authors;
        }
    }
    Vec::new()
}

/// A line is the abstract boundary if it begins with "abstract" (case-insensitive),
/// optionally followed by a colon. Once we reach it, the byline is behind us.
fn is_abstract_marker(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower == "abstract" || lower.starts_with("abstract:") || lower.starts_with("abstract ")
}

/// Parse a single candidate byline line into authors, or `None` if the line is
/// not a confident, all-name-shaped byline.
fn parse_byline_line(line: &str) -> Option<Vec<AuthorEntry>> {
    let segments = split_author_segments(line);
    if segments.is_empty() {
        return None;
    }
    let mut authors = Vec::with_capacity(segments.len());
    for seg in &segments {
        if !segment_is_name_shaped(seg) {
            // Any non-name segment disqualifies the whole line: a real byline is
            // uniformly name-shaped, so a mixed line is almost certainly prose.
            return None;
        }
        authors.push(AuthorEntry {
            name: (*seg).to_string(),
            affiliations: Vec::new(),
            roles: Vec::new(),
        });
    }
    Some(authors)
}

/// Split a byline line on commas and the conjunction "and" / "&", trimming
/// whitespace and dropping empty segments. Handles the common
/// "A, B, and C" / "A and B" / "A, B & C" shapes.
fn split_author_segments(line: &str) -> Vec<&str> {
    line.split(',')
        .flat_map(|piece| {
            piece
                .split(" and ")
                .flat_map(|p| p.split(" & "))
                .collect::<Vec<_>>()
        })
        .map(str::trim)
        // A trailing "and C" arrives here as the segment "and C" only when there
        // was no comma before it; the `split(" and ")` above already handles the
        // spaced form. Guard against a bare leading/trailing "and" token.
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("and"))
        .collect()
}

/// A segment is name-shaped when it is 2–4 whitespace tokens, each token being
/// an initial (`J.`) or a Capitalized word, with no digits and no all-caps
/// acronyms. This rejects title fragments ("Attention Is All You Need" is 5
/// tokens with no comma → one over-long segment) while accepting real names
/// ("Jane Q. Smith", "A. Turing").
fn segment_is_name_shaped(seg: &str) -> bool {
    let tokens: Vec<&str> = seg.split_whitespace().collect();
    if tokens.len() < 2 || tokens.len() > 4 {
        return false;
    }
    tokens.iter().all(|t| token_is_name_shaped(t))
}

/// A token qualifies as a name token when it is either an initial (`J.` / `J`
/// single uppercase letter, optionally dotted / hyphenated initials) or a
/// Capitalized word: leading uppercase, at least one following lowercase, no
/// digits, and not ALL-CAPS.
fn token_is_name_shaped(token: &str) -> bool {
    // Strip a trailing name particle punctuation we allow inside names.
    let t = token.trim_matches(|c: char| c == '.');
    if t.is_empty() {
        // token was just dots
        return false;
    }
    let cleaned = t.replace(['-', '\''], "");
    if cleaned.is_empty() {
        return false;
    }
    // No digits anywhere.
    if cleaned.chars().any(|c| c.is_ascii_digit()) {
        return false;
    }
    // Every char must be alphabetic (after removing the particle punctuation).
    if !cleaned.chars().all(char::is_alphabetic) {
        return false;
    }
    let first = cleaned.chars().next().unwrap();
    if !first.is_uppercase() {
        return false;
    }
    // Single-letter initial (with or without the stripped dot) is fine.
    if cleaned.chars().count() == 1 {
        return true;
    }
    // Multi-letter word: must not be ALL-CAPS (rejects acronyms like "NASA",
    // "IEEE"), i.e. it must contain at least one lowercase letter.
    cleaned.chars().any(char::is_lowercase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_only_authors_are_recovered() {
        // Realistic shape: title, blank, byline, blank, abstract, body.
        // No structured source.authors exist — the names live ONLY in the body.
        let text = "\
Deep Residual Learning for Image Recognition

Kaiming He, Xiangyu Zhang, Shaoqing Ren, and Jian Sun

Abstract
We present a residual learning framework to ease the training of networks.
";
        let authors = parse_byline_authors(text);
        let names: Vec<&str> = authors.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["Kaiming He", "Xiangyu Zhang", "Shaoqing Ren", "Jian Sun"]
        );
    }

    #[test]
    fn normal_comma_and_byline_yields_three_entries() {
        let text = "\
A Study of Something

Ada Lovelace, Grace Hopper, and Barbara Liskov

Abstract
Body text here.
";
        let authors = parse_byline_authors(text);
        assert_eq!(authors.len(), 3);
        assert_eq!(authors[0].name, "Ada Lovelace");
        assert_eq!(authors[1].name, "Grace Hopper");
        assert_eq!(authors[2].name, "Barbara Liskov");
    }

    #[test]
    fn no_recognizable_byline_yields_empty() {
        // A title-only document with prose — no name-shaped byline line.
        let text = "\
Attention Is All You Need

The dominant sequence transduction models are based on complex recurrent or
convolutional neural networks that include an encoder and a decoder.
";
        let authors = parse_byline_authors(text);
        assert!(authors.is_empty(), "expected no authors, got {authors:?}");
    }

    #[test]
    fn all_caps_acronym_line_is_rejected() {
        // Adversarial: an org line under the title must not be parsed as authors.
        let text = "\
Some Technical Report

NASA JPL CALTECH

Abstract
Contents.
";
        assert!(parse_byline_authors(text).is_empty());
    }

    #[test]
    fn single_author_with_initial_is_recovered() {
        let text = "\
On Computable Numbers

Alan M. Turing

Abstract
Body.
";
        let authors = parse_byline_authors(text);
        assert_eq!(authors.len(), 1);
        assert_eq!(authors[0].name, "Alan M. Turing");
    }

    #[test]
    fn ampersand_separator_is_supported() {
        let text = "\
Structure and Interpretation

Harold Abelson & Gerald Sussman

Abstract
Body.
";
        let authors = parse_byline_authors(text);
        let names: Vec<&str> = authors.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["Harold Abelson", "Gerald Sussman"]);
    }

    #[test]
    fn empty_input_yields_empty() {
        assert!(parse_byline_authors("").is_empty());
    }

    #[test]
    fn prose_sentence_after_title_is_not_mined() {
        // A short capitalized prose line that is not a byline must be rejected
        // because its segments are not uniformly name-shaped.
        let text = "\
Introduction to Widgets

This Paper Describes a New Approach to widget fabrication.

Abstract
Body.
";
        assert!(parse_byline_authors(text).is_empty());
    }
}
