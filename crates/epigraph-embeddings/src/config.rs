//! Configuration for the embedding service
//!
//! Provides flexible configuration for embedding dimensions, providers,
//! caching, and rate limiting.

use serde::{Deserialize, Serialize};

/// Default embedding dimension for `OpenAI` text-embedding-3-small
pub const DEFAULT_OPENAI_DIMENSION: usize = 1536;

/// Default embedding dimension for local models
pub const DEFAULT_LOCAL_DIMENSION: usize = 384;

/// Default maximum tokens for `OpenAI` embeddings
pub const DEFAULT_MAX_TOKENS: usize = 8191;

/// Default rate limit (requests per minute)
pub const DEFAULT_RATE_LIMIT_RPM: u32 = 3000;

/// Default rate limit (tokens per minute)
pub const DEFAULT_RATE_LIMIT_TPM: u32 = 1_000_000;

/// Configuration for the embedding service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingConfig {
    /// Dimension of the embedding vectors
    pub dimension: usize,

    /// Maximum tokens allowed per text input
    pub max_tokens: usize,

    /// Whether to normalize embeddings to unit vectors
    pub normalize: bool,

    /// Whether to cache embeddings
    pub cache_enabled: bool,

    /// Cache TTL in seconds (0 = no expiration)
    pub cache_ttl_secs: u64,

    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,

    /// Provider-specific configuration
    pub provider: ProviderConfig,
}

impl EmbeddingConfig {
    /// Create configuration for `OpenAI` embeddings
    #[must_use]
    pub fn openai(dimension: usize) -> Self {
        Self {
            dimension,
            max_tokens: DEFAULT_MAX_TOKENS,
            normalize: true,
            cache_enabled: true,
            cache_ttl_secs: 3600,
            rate_limit: RateLimitConfig::default(),
            provider: ProviderConfig::OpenAi {
                model: "text-embedding-3-small".to_string(),
                api_base_url: None,
            },
        }
    }

    /// Create configuration for local model embeddings
    #[must_use]
    pub const fn local(dimension: usize) -> Self {
        Self {
            dimension,
            max_tokens: 512,
            normalize: true,
            cache_enabled: true,
            cache_ttl_secs: 3600,
            rate_limit: RateLimitConfig::disabled(),
            provider: ProviderConfig::Local { model_path: None },
        }
    }

    /// Create configuration for Jina multimodal embeddings
    #[must_use]
    pub fn jina(dimension: usize) -> Self {
        Self {
            dimension,
            max_tokens: 32_768,
            normalize: true,
            cache_enabled: true,
            cache_ttl_secs: 3600,
            rate_limit: RateLimitConfig::disabled(),
            provider: ProviderConfig::Jina {
                model: "jina-embeddings-v4".to_string(),
                api_base_url: None,
                task: Some("retrieval.passage".to_string()),
            },
        }
    }

    /// Create configuration with custom dimension
    #[must_use]
    pub const fn with_dimension(mut self, dimension: usize) -> Self {
        self.dimension = dimension;
        self
    }

    /// Enable or disable caching
    #[must_use]
    pub const fn with_cache(mut self, enabled: bool) -> Self {
        self.cache_enabled = enabled;
        self
    }

    /// Enable or disable normalization
    #[must_use]
    pub const fn with_normalization(mut self, enabled: bool) -> Self {
        self.normalize = enabled;
        self
    }

    /// Set maximum tokens
    #[must_use]
    pub const fn with_max_tokens(mut self, max_tokens: usize) -> Self {
        self.max_tokens = max_tokens;
        self
    }
}

impl Default for EmbeddingConfig {
    fn default() -> Self {
        Self::openai(DEFAULT_OPENAI_DIMENSION)
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Whether rate limiting is enabled
    pub enabled: bool,

    /// Maximum requests per minute
    pub requests_per_minute: u32,

    /// Maximum tokens per minute
    pub tokens_per_minute: u32,
}

impl RateLimitConfig {
    /// Create disabled rate limiting
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            requests_per_minute: 0,
            tokens_per_minute: 0,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: DEFAULT_RATE_LIMIT_RPM,
            tokens_per_minute: DEFAULT_RATE_LIMIT_TPM,
        }
    }
}

/// Provider-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProviderConfig {
    /// `OpenAI` API configuration
    OpenAi {
        /// Model name (e.g., "text-embedding-3-small")
        model: String,
        /// Optional custom API base URL
        api_base_url: Option<String>,
    },

    /// Local model configuration
    Local {
        /// Path to the model file (optional)
        model_path: Option<String>,
    },

    /// Mock provider for testing
    Mock {
        /// Whether to simulate failures
        simulate_failures: bool,
        /// Fixed dimension for mock embeddings
        dimension: usize,
    },

    /// Jina AI API configuration (supports multimodal text+image embedding)
    Jina {
        /// Model name (e.g., "jina-embeddings-v4")
        model: String,
        /// Optional custom API base URL (default: <https://api.jina.ai>)
        api_base_url: Option<String>,
        /// Task adapter: "retrieval", "text-matching", or "code"
        task: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jina_config_creation() {
        let config = EmbeddingConfig::jina(1536);
        assert_eq!(config.dimension, 1536);
        assert_eq!(config.max_tokens, 32_768);
        assert!(config.normalize);
        assert!(config.cache_enabled);

        if let ProviderConfig::Jina {
            model,
            task,
            api_base_url,
        } = &config.provider
        {
            assert_eq!(model, "jina-embeddings-v4");
            assert_eq!(task, &Some("retrieval.passage".to_string()));
            assert!(api_base_url.is_none());
        } else {
            panic!("Expected Jina provider config");
        }
    }

    #[test]
    fn test_jina_config_serialization() {
        let config = EmbeddingConfig::jina(1536);
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: EmbeddingConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.dimension, 1536);
        assert_eq!(deserialized.max_tokens, 32_768);

        if let ProviderConfig::Jina { model, .. } = &deserialized.provider {
            assert_eq!(model, "jina-embeddings-v4");
        } else {
            panic!("Expected Jina provider config after round-trip");
        }
    }
}
