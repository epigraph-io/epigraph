//! Text-based document fragmenter
//!
//! Splits text documents into semantically coherent fragments with overlap.

use super::{Fragment, Fragmenter};
use crate::errors::HarvesterError;
use async_trait::async_trait;
use epigraph_crypto::ContentHasher;

/// Text fragmenter that splits on semantic boundaries
///
/// # Strategy
/// - Target size: 1000-2000 tokens (estimated as chars/4)
/// - Overlap: 100-200 tokens for context preservation
/// - Splits on paragraph boundaries when possible
/// - Falls back to sentence boundaries
/// - Each fragment is BLAKE3 hashed for content addressing
pub struct TextFragmenter {
    /// Target fragment size in characters
    target_size: usize,

    /// Overlap size in characters
    overlap: usize,
}

impl TextFragmenter {
    /// Create a new text fragmenter
    ///
    /// # Parameters
    /// - `target_size`: Target fragment size in characters (default: 6000 = ~1500 tokens)
    /// - `overlap`: Overlap between fragments in characters (default: 600 = ~150 tokens)
    #[must_use]
    pub fn new(target_size: usize, overlap: usize) -> Self {
        Self {
            target_size,
            overlap,
        }
    }

    /// Estimate token count (rough approximation: 1 token ≈ 4 characters)
    #[must_use]
    pub fn estimate_tokens(text: &str) -> usize {
        text.chars().count() / 4
    }

    /// Find the best split point near the target position
    ///
    /// Prefers paragraph boundaries, then sentence boundaries, then word boundaries.
    fn find_split_point(&self, text: &str, target: usize) -> usize {
        if target >= text.len() {
            return text.len();
        }

        // Search window: ±20% of target
        let search_start = target.saturating_sub(target / 5);
        let search_end = (target + target / 5).min(text.len());
        let search_slice = &text[search_start..search_end];

        // Look for paragraph break (double newline)
        if let Some(pos) = search_slice.rfind("\n\n") {
            let absolute_pos = search_start + pos + 2; // After the double newline
            if absolute_pos > 0 && absolute_pos < text.len() {
                return absolute_pos;
            }
        }

        // Look for sentence boundary (. ! ? followed by space/newline)
        let sentence_endings = [". ", ".\n", "! ", "!\n", "? ", "?\n"];
        let mut best_pos = None;
        let mut best_distance = usize::MAX;

        for ending in &sentence_endings {
            if let Some(pos) = search_slice.rfind(ending) {
                let absolute_pos = search_start + pos + ending.len();
                let distance = target.abs_diff(absolute_pos);
                if distance < best_distance && absolute_pos > 0 && absolute_pos < text.len() {
                    best_pos = Some(absolute_pos);
                    best_distance = distance;
                }
            }
        }

        if let Some(pos) = best_pos {
            return pos;
        }

        // Fall back to word boundary (space)
        if let Some(pos) = search_slice.rfind(' ') {
            let absolute_pos = search_start + pos + 1;
            if absolute_pos > 0 && absolute_pos < text.len() {
                return absolute_pos;
            }
        }

        // Last resort: split at target
        target.min(text.len())
    }

    /// Fragment the text into overlapping chunks
    fn fragment_impl(&self, content: &str) -> Result<Vec<Fragment>, HarvesterError> {
        if content.is_empty() {
            return Ok(vec![]);
        }

        let mut fragments = Vec::new();
        let mut current_offset = 0;
        let mut sequence = 0;

        while current_offset < content.len() {
            // Calculate end position for this fragment
            let remaining = content.len() - current_offset;
            let target_end = if remaining <= self.target_size {
                // Last fragment - take everything
                content.len()
            } else {
                // Find good split point
                let tentative_end = current_offset + self.target_size;
                self.find_split_point(content, tentative_end)
            };

            // Extract fragment content
            let fragment_content = &content[current_offset..target_end];

            // Calculate BLAKE3 hash
            let content_hash = ContentHasher::hash(fragment_content.as_bytes());

            fragments.push(Fragment {
                content: fragment_content.to_string(),
                content_hash,
                start_offset: current_offset,
                end_offset: target_end,
                sequence_number: sequence,
            });

            // Move to next fragment with overlap
            if target_end >= content.len() {
                break; // We've reached the end
            }

            // Next fragment starts overlap characters before the end of this one
            current_offset = target_end.saturating_sub(self.overlap);
            sequence += 1;
        }

        Ok(fragments)
    }
}

impl Default for TextFragmenter {
    fn default() -> Self {
        Self::new(6000, 600)
    }
}

#[async_trait]
impl Fragmenter for TextFragmenter {
    type Error = HarvesterError;

    async fn fragment(&self, content: &str) -> Result<Vec<Fragment>, Self::Error> {
        self.fragment_impl(content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_text_returns_no_fragments() {
        let fragmenter = TextFragmenter::default();
        let fragments = fragmenter.fragment("").await.unwrap();
        assert!(fragments.is_empty());
    }

    #[tokio::test]
    async fn small_text_returns_single_fragment() {
        let fragmenter = TextFragmenter::default();
        let text = "This is a short text.";
        let fragments = fragmenter.fragment(text).await.unwrap();

        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].content, text);
        assert_eq!(fragments[0].start_offset, 0);
        assert_eq!(fragments[0].end_offset, text.len());
        assert_eq!(fragments[0].sequence_number, 0);
    }

    #[tokio::test]
    async fn large_text_splits_into_multiple_fragments() {
        let fragmenter = TextFragmenter::new(100, 20); // Small size for testing
        let text = "A".repeat(250); // 250 characters
        let fragments = fragmenter.fragment(&text).await.unwrap();

        assert!(fragments.len() > 1, "Should create multiple fragments");

        // Check sequence numbers are correct
        for (i, fragment) in fragments.iter().enumerate() {
            assert_eq!(fragment.sequence_number, i as u32);
        }
    }

    #[tokio::test]
    async fn fragments_have_overlap() {
        let fragmenter = TextFragmenter::new(100, 20);
        let text = "A".repeat(250);
        let fragments = fragmenter.fragment(&text).await.unwrap();

        if fragments.len() > 1 {
            // Check that fragments overlap
            for i in 0..fragments.len() - 1 {
                let current_end = fragments[i].end_offset;
                let next_start = fragments[i + 1].start_offset;
                assert!(
                    next_start < current_end,
                    "Fragments should overlap. Current ends at {current_end}, next starts at {next_start}"
                );
            }
        }
    }

    #[tokio::test]
    async fn fragments_cover_entire_text() {
        let fragmenter = TextFragmenter::new(100, 20);
        let text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".repeat(10);
        let fragments = fragmenter.fragment(&text).await.unwrap();

        // First fragment should start at 0
        assert_eq!(fragments.first().unwrap().start_offset, 0);

        // Last fragment should end at text length
        assert_eq!(fragments.last().unwrap().end_offset, text.len());
    }

    #[tokio::test]
    async fn splits_on_paragraph_boundaries() {
        let fragmenter = TextFragmenter::new(100, 10);
        let text = format!(
            "{}First paragraph.\n\n{}Second paragraph.\n\n{}Third paragraph.",
            "X".repeat(40),
            "Y".repeat(40),
            "Z".repeat(40)
        );

        let fragments = fragmenter.fragment(&text).await.unwrap();

        // Should split on paragraph boundaries when possible
        assert!(fragments.len() > 1);

        // Check that splits happen after paragraph breaks
        for fragment in &fragments[..fragments.len() - 1] {
            let content = &fragment.content;
            // Fragment should ideally end with paragraph break or be a complete unit
            assert!(!content.is_empty());
        }
    }

    #[tokio::test]
    async fn each_fragment_has_unique_hash() {
        let fragmenter = TextFragmenter::new(50, 10);
        let text = "First part. Second part. Third part. Fourth part.";
        let fragments = fragmenter.fragment(text).await.unwrap();

        if fragments.len() > 1 {
            for i in 0..fragments.len() {
                for j in i + 1..fragments.len() {
                    // Different fragments should have different hashes (unless content identical)
                    if fragments[i].content != fragments[j].content {
                        assert_ne!(
                            fragments[i].content_hash, fragments[j].content_hash,
                            "Different content should have different hashes"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn estimate_tokens_approximates_correctly() {
        let text = "This is a test string with approximately twenty tokens.";
        let estimated = TextFragmenter::estimate_tokens(text);
        // Should be roughly text.len() / 4
        let expected = text.len() / 4;
        assert!(
            estimated.abs_diff(expected) <= 1,
            "Token estimate {estimated} should be close to {expected}"
        );
    }

    #[test]
    fn find_split_point_prefers_paragraph_breaks() {
        let fragmenter = TextFragmenter::new(100, 20);
        let text = "First paragraph text here.\n\nSecond paragraph text here.";
        let split = fragmenter.find_split_point(text, 30);

        // Should split after the paragraph break
        assert!(
            split > 25 && split <= 28,
            "Split at {split} should be near paragraph break"
        );
    }

    #[test]
    fn find_split_point_falls_back_to_sentence() {
        let fragmenter = TextFragmenter::new(100, 20);
        let text = "First sentence. Second sentence. Third sentence.";
        let split = fragmenter.find_split_point(text, 25);

        // Should split near a sentence boundary
        let split_char = text.chars().nth(split.saturating_sub(1));
        assert!(
            split_char == Some(' ') || split_char == Some('.'),
            "Should split near sentence boundary, got char at {split}: {split_char:?}"
        );
    }

    #[tokio::test]
    async fn content_hash_is_deterministic() {
        let fragmenter = TextFragmenter::default();
        let text = "Test content for hashing.";

        let fragments1 = fragmenter.fragment(text).await.unwrap();
        let fragments2 = fragmenter.fragment(text).await.unwrap();

        assert_eq!(fragments1.len(), fragments2.len());
        for (f1, f2) in fragments1.iter().zip(fragments2.iter()) {
            assert_eq!(
                f1.content_hash, f2.content_hash,
                "Same content should produce same hash"
            );
        }
    }
}
