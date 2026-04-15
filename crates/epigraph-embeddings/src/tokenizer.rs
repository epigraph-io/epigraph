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
    /// # Arguments
    /// * `text` - The text to truncate
    ///
    /// # Returns
    /// The truncated text (or original if already within limit)
    #[must_use]
    pub fn truncate(&self, text: &str) -> String {
        let token_count = self.count_tokens(text);
        if token_count <= self.max_tokens {
            return text.to_string();
        }

        // Estimate character limit from token limit
        let estimated_char_limit = self.max_tokens * CHARS_PER_TOKEN_ESTIMATE;

        // Truncate at word boundary if possible, fall back to character truncation
        Self::truncate_at_word_boundary(text, estimated_char_limit)
            .unwrap_or_else(|| text.chars().take(estimated_char_limit).collect())
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
}
