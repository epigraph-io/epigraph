//! Character-safe text shortening for response summaries and labels.

/// Shorten `s` for display: when it has MORE than `limit` characters, return
/// its first `keep` characters followed by `"..."`; otherwise return it whole.
///
/// RED-PHASE STUB: returns `s` unchanged.
pub(crate) fn ellipsize(s: &str, limit: usize, keep: usize) -> String {
    let _ = (limit, keep);
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::ellipsize;

    #[test]
    fn cuts_on_a_character_boundary_when_the_byte_cut_would_split_one() {
        let s = format!("a{}", "é".repeat(200));
        assert!(
            !s.is_char_boundary(120),
            "fixture must put byte 120 inside a character"
        );
        let out = ellipsize(&s, 120, 120);
        let expected: String = s.chars().take(120).collect::<String>() + "...";
        assert_eq!(out, expected);
        assert_eq!(out.chars().count(), 123, "120 characters plus the ellipsis");
    }

    #[test]
    fn ascii_output_is_what_the_byte_slice_produced() {
        // ASCII is one byte per character, so the old `&s[..120]` and the new
        // character cut must agree exactly.
        let s = "x".repeat(130);
        assert_eq!(ellipsize(&s, 120, 120), format!("{}...", &s[..120]));
    }

    #[test]
    fn the_threshold_counts_characters_not_bytes() {
        // 120 four-byte characters is 480 bytes but only 120 characters: not
        // over the limit, so nothing is cut and no ellipsis is added.
        let exactly = "🦀".repeat(120);
        assert_eq!(ellipsize(&exactly, 120, 120), exactly);

        // One more character is over the limit.
        let over = "🦀".repeat(121);
        assert_eq!(
            ellipsize(&over, 120, 120),
            format!("{}...", "🦀".repeat(120))
        );
    }

    #[test]
    fn short_text_is_returned_whole() {
        assert_eq!(ellipsize("short", 120, 120), "short");
        assert_eq!(ellipsize("", 60, 57), "");
    }

    #[test]
    fn keep_shorter_than_limit_reproduces_the_provenance_label_rule() {
        // `claim_provenance` labels: over 60 characters → first 57 + "...",
        // so the label never exceeds 60 characters.
        let at_limit = "é".repeat(60);
        assert_eq!(ellipsize(&at_limit, 60, 57), at_limit, "60 is not over 60");

        let over = "é".repeat(100);
        assert!(!over.is_char_boundary(57), "byte 57 is mid-character");
        let out = ellipsize(&over, 60, 57);
        assert_eq!(out, format!("{}...", "é".repeat(57)));
        assert_eq!(out.chars().count(), 60);
    }
}
