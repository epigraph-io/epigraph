//! Which LLM provider `POST /api/v1/analyze/unconstrained` uses, read once at
//! boot (backlog e8e14178).
//!
//! The handler read `EPIGRAPH_LLM_PROVIDER` with `std::env::var` on every
//! request: invisible to the binary's startup, and settable by a test only by
//! mutating the process environment. It now reads
//! [`AppState::llm_provider`](crate::state::AppState::llm_provider), which
//! `bin/server.rs` sets from [`LlmProviderSetting::from_env`] at startup (the
//! settings pattern of `serving.rs`; see `tests/no_library_env_reads.rs`).
//!
//! The value is a selector for `epigraph_cli`'s `create_llm_client`:
//! `anthropic`, `epigraph` (the first active registered provider), `mock`, or a
//! registered extension's name. It is not validated here: which names exist
//! depends on what the build registers, and an unknown name is the handler's
//! 503, as before.

/// The variable that names the provider.
pub const LLM_PROVIDER_ENV: &str = "EPIGRAPH_LLM_PROVIDER";

/// The provider when the variable is unset or blank.
pub const DEFAULT_LLM_PROVIDER: &str = "anthropic";

/// The configured LLM provider selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmProviderSetting(String);

impl Default for LlmProviderSetting {
    fn default() -> Self {
        Self(DEFAULT_LLM_PROVIDER.to_string())
    }
}

impl LlmProviderSetting {
    /// Parse the raw variable value: unset, empty or blank is
    /// [`DEFAULT_LLM_PROVIDER`]; anything else is that name, trimmed.
    #[must_use]
    pub fn parse(raw: Option<&str>) -> Self {
        match raw.map(str::trim).filter(|v| !v.is_empty()) {
            Some(name) => Self(name.to_string()),
            None => Self::default(),
        }
    }

    /// [`Self::parse`] of [`LLM_PROVIDER_ENV`]. Called once, by
    /// `bin/server.rs`.
    #[must_use]
    pub fn from_env() -> Self {
        Self::parse(std::env::var(LLM_PROVIDER_ENV).ok().as_deref())
    }

    /// The selector, as `create_llm_client` takes it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_defaults_unset_and_blank_to_anthropic_and_keeps_a_name() {
        assert_eq!(LlmProviderSetting::parse(None).as_str(), "anthropic");
        assert_eq!(LlmProviderSetting::parse(Some("")).as_str(), "anthropic");
        assert_eq!(LlmProviderSetting::parse(Some("  ")).as_str(), "anthropic");
        assert_eq!(LlmProviderSetting::parse(Some("mock")).as_str(), "mock");
        assert_eq!(
            LlmProviderSetting::parse(Some("anthropic")).as_str(),
            "anthropic"
        );
        assert_eq!(LlmProviderSetting::parse(Some(" mock\n")).as_str(), "mock");
        assert_eq!(LlmProviderSetting::default().as_str(), DEFAULT_LLM_PROVIDER);
    }
}
