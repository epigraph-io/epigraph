//! Text tokenization utilities
//!
//! Provides token counting and text truncation for embedding APIs.

use crate::errors::EmbeddingError;

// =============================================================================
// TOKENIZATION CONSTANTS
// =============================================================================

/// Default maximum tokens for `OpenAI` embedding models (text-embedding-ada-002).
/// `OpenAI`'s embedding models have a context limit of 8191 tokens.
pub const DEFAULT_OPENAI_MAX_TOKENS: usize = 8191;

/// Estimated number of characters per token for English text.
/// This is a rough approximation; actual tokenization varies by model and language.
/// Used for fallback token counting when precise tokenizers are not available.
const CHARS_PER_TOKEN_ESTIMATE: usize = 4;

/// Tokenizer for counting and truncating text
pub struct Tokenizer {
    /// Maximum tokens allowed
    max_tokens: usize,
}

impl Tokenizer {
    /// Create a new tokenizer with the given max tokens
    #[must_use]
    pub const fn new(max_tokens: usize) -> Self {
        Self { max_tokens }
    }

    /// Estimate the number of tokens in a text
    ///
    /// This is an approximation using character count / 4.
    /// For accurate counting, use the `tiktoken-rs` feature.
    ///
    /// # Arguments
    /// * `text` - The text to count
    ///
    /// # Returns
    /// Estimated token count
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn count_tokens(&self, text: &str) -> usize {
        // Use tiktoken for accurate counting when openai feature is enabled
        #[cfg(feature = "openai")]
        {
            if let Ok(bpe) = tiktoken_rs::cl100k_base() {
                return bpe.encode_with_special_tokens(text).len();
            }
        }

        // Fallback to character-based estimation (~4 chars per token for English)
        text.len().div_ceil(CHARS_PER_TOKEN_ESTIMATE)
    }

    /// Check if text exceeds the token limit
    ///
    /// # Arguments
    /// * `text` - The text to check
    ///
    /// # Returns
    /// * `Ok(token_count)` - If within limit
    /// * `Err(EmbeddingError::TextTooLong)` - If exceeds limit
    #[allow(clippy::missing_const_for_fn)]
    pub fn validate(&self, text: &str) -> Result<usize, EmbeddingError> {
        let token_count = self.count_tokens(text);
        if token_count > self.max_tokens {
            return Err(EmbeddingError::TextTooLong {
                actual: token_count,
                max: self.max_tokens,
            });
        }
        Ok(token_count)
    }

    /// Truncate text to fit within the token limit
    ///
    /// The result is a prefix of `text` whose [`count_tokens`](Self::count_tokens)
    /// is at most `max_tokens`. The first cut is the "about 4 characters per
    /// token" estimate, at a word boundary where there is one; on dense text
    /// (CJK, code, long digit runs) that estimate lands over the limit, so the
    /// prefix is then shrunk in proportion to the overshoot until it fits.
    ///
    /// # Arguments
    /// * `text` - The text to truncate
    ///
    /// # Returns
    /// The truncated text (or original if already within limit)
    #[must_use]
    pub fn truncate(&self, text: &str) -> String {
        self.truncate_counted(text).0
    }

    /// [`truncate`](Self::truncate), also returning the token count of the
    /// result, so a caller that needs both counts the text once rather than
    /// twice (with the `openai` feature every count is a BPE encode).
    #[must_use]
    pub fn truncate_counted(&self, text: &str) -> (String, usize) {
        let mut tokens = self.count_tokens(text);
        if tokens <= self.max_tokens {
            return (text.to_string(), tokens);
        }

        // Estimate character limit from token limit
        let estimated_char_limit = self.max_tokens * CHARS_PER_TOKEN_ESTIMATE;

        // Truncate at word boundary if possible, fall back to character truncation
        let mut out = Self::truncate_at_word_boundary(text, estimated_char_limit)
            .unwrap_or_else(|| text.chars().take(estimated_char_limit).collect());

        // Converge: shrink by the overshoot ratio, always by at least one char,
        // so the loop ends (an empty string counts zero tokens).
        loop {
            tokens = self.count_tokens(&out);
            if tokens <= self.max_tokens {
                return (out, tokens);
            }
            let chars = out.chars().count();
            let keep = (chars.saturating_mul(self.max_tokens) / tokens).min(chars - 1);
            out = out.chars().take(keep).collect();
        }
    }

    /// Truncate at a word boundary
    fn truncate_at_word_boundary(text: &str, max_chars: usize) -> Option<String> {
        if text.len() <= max_chars {
            return Some(text.to_string());
        }

        // Find the last space before the limit
        let truncated: String = text.chars().take(max_chars).collect();
        truncated
            .rfind(' ')
            .map(|last_space| truncated[..last_space].to_string())
    }

    /// Get the maximum token limit
    #[must_use]
    pub const fn max_tokens(&self) -> usize {
        self.max_tokens
    }
}

impl Default for Tokenizer {
    fn default() -> Self {
        Self::new(DEFAULT_OPENAI_MAX_TOKENS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_count_estimate() {
        let tokenizer = Tokenizer::new(100);
        // "hello" has 5 characters, estimate ~2 tokens
        let count = tokenizer.count_tokens("hello");
        assert!((1..=5).contains(&count));
    }

    #[test]
    fn test_validate_within_limit() {
        let tokenizer = Tokenizer::new(100);
        let result = tokenizer.validate("short text");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_exceeds_limit() {
        let tokenizer = Tokenizer::new(2);
        let long_text = "This is a very long text that exceeds the limit";
        let result = tokenizer.validate(long_text);
        assert!(matches!(result, Err(EmbeddingError::TextTooLong { .. })));
    }

    #[test]
    fn test_truncate_long_text() {
        let tokenizer = Tokenizer::new(5);
        let long_text = "This is a very long text that needs truncation";
        let truncated = tokenizer.truncate(long_text);
        // Should be shorter than original
        assert!(truncated.len() < long_text.len());
    }

    /// `truncate` must return text that FITS: its output is what gets sent to a
    /// provider whose hard limit is `max_tokens`. A cut made by "about 4 chars per
    /// token" lands far over the limit on dense text (CJK, code, digits), and the
    /// provider answers 400 (backlog ef32cdeb).
    #[test]
    fn truncate_always_fits_the_limit_on_dense_text() {
        let tokenizer = Tokenizer::new(50);
        let text = "漢字のテストは密度が高い".repeat(120);
        let out = tokenizer.truncate(&text);
        assert!(!out.is_empty(), "truncation must keep a prefix");
        assert!(text.starts_with(&out), "truncation must keep a prefix");
        let tokens = tokenizer.count_tokens(&out);
        assert!(
            tokens <= 50,
            "truncated text is {tokens} tokens against a limit of 50"
        );
    }
}
