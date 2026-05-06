//! `LlmProvider` — pluggable language-model backend for the `EpiGraph` kernel.
//!
//! The kernel ships with [`NoOpLlmProvider`], which fails every request with
//! [`LlmError::NotAvailable`]. Concrete built-ins (Anthropic API, mock) plus
//! any private/enterprise extensions register themselves at process startup
//! via [`register_llm_provider`]; the [`default_llm_provider`] helper walks
//! the registry and returns the first provider whose
//! [`LlmProvider::is_active`] returns `true`.
//!
//! # Extension point contract
//!
//! - [`LlmProvider::is_active`] must be cheap (env-var check, file existence,
//!   etc.) and may return different answers across calls if the environment
//!   changes. The `default_llm_provider` walk skips inactive providers but
//!   does not unregister them.
//! - [`LlmProvider::complete_json`] is the canonical inference call. Errors
//!   are wrapped in [`LlmError`]; HTTP-like rate limits get
//!   [`LlmError::RateLimited`] so callers can implement backoff.
//! - Names are unique. Registering a second provider with the same `name()`
//!   replaces the existing entry (last write wins).
//! - Insertion order matters: the most-recently-registered provider is
//!   preferred by [`default_llm_provider`], so private/enterprise extensions
//!   always outrank built-ins.

use async_trait::async_trait;
use std::sync::{Arc, OnceLock, RwLock};
use thiserror::Error;

/// Errors returned by [`LlmProvider`] implementations.
#[derive(Error, Debug)]
pub enum LlmError {
    /// No active provider is registered (typical when callers forgot to
    /// install built-ins or extensions, or when env credentials are absent).
    #[error("no active LLM provider: {0}")]
    NotAvailable(String),

    /// The provider was reachable but the request failed.
    #[error("LLM API request failed: {message}")]
    RequestFailed { message: String },

    /// The provider returned a response that did not parse as expected JSON.
    #[error("LLM returned malformed JSON: {message}")]
    MalformedResponse { message: String },

    /// The provider rate-limited the request.
    #[error("LLM rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    /// The provider was selected but its credentials are missing.
    #[error("LLM API key not configured for provider: {provider}")]
    MissingApiKey { provider: String },
}

/// Pluggable language-model backend.
///
/// Implementors live in built-in crates (Anthropic, Mock) or in private /
/// enterprise extension crates. Each kernel-side caller resolves an
/// [`Arc<dyn LlmProvider>`] via [`default_llm_provider`] or
/// [`llm_provider_by_name`] and uses the same async API regardless of
/// backend.
#[async_trait]
pub trait LlmProvider: Send + Sync + 'static {
    /// Stable selector name. Must be unique within the registry. The
    /// `--provider <NAME>` CLI flag matches against this.
    fn name(&self) -> &str;

    /// Human-readable model identifier (e.g. `"claude-sonnet-4-5-20250929"`).
    /// Surfaced in logs / status output. May be `"<provider>-not-configured"`
    /// when [`is_active`](Self::is_active) is `false`.
    fn model_name(&self) -> &str;

    /// Returns `true` if this provider can serve a request right now.
    ///
    /// Implementations check for credentials, external binaries, network
    /// reachability, etc. The result may change across calls (e.g. an env
    /// var becomes set), so callers should not cache it.
    ///
    /// `default_llm_provider` skips providers whose `is_active` is `false`.
    fn is_active(&self) -> bool;

    /// Send a prompt; receive a parsed JSON value.
    ///
    /// The JSON shape is caller-defined; providers extract it from the
    /// model's text output (typically by stripping markdown code fences and
    /// running `serde_json::from_str`).
    async fn complete_json(&self, prompt: &str) -> Result<serde_json::Value, LlmError>;
}

// =============================================================================
// KERNEL-DEFAULT NO-OP PROVIDER
// =============================================================================

/// Kernel-default no-op LLM provider.
///
/// Every call returns [`LlmError::NotAvailable`]. Use it when a caller wants
/// a non-`Option<Arc<dyn LlmProvider>>` API but no real backend has been
/// configured — the resulting error message tells the operator what to fix.
#[derive(Debug, Default, Clone)]
pub struct NoOpLlmProvider;

impl NoOpLlmProvider {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl LlmProvider for NoOpLlmProvider {
    fn name(&self) -> &str {
        "noop"
    }

    fn model_name(&self) -> &str {
        "noop"
    }

    fn is_active(&self) -> bool {
        false
    }

    async fn complete_json(&self, _prompt: &str) -> Result<serde_json::Value, LlmError> {
        Err(LlmError::NotAvailable(
            "no LLM provider registered. Call \
             `epigraph_cli::enrichment::register_builtin_llm_providers()` \
             from `main`, or register a private provider via \
             `epigraph_interfaces::register_llm_provider`."
                .into(),
        ))
    }
}

// =============================================================================
// PROCESS-WIDE REGISTRY
// =============================================================================

type ProviderList = RwLock<Vec<Arc<dyn LlmProvider>>>;
static REGISTRY: OnceLock<ProviderList> = OnceLock::new();

fn registry() -> &'static ProviderList {
    REGISTRY.get_or_init(|| RwLock::new(Vec::new()))
}

/// Register a provider. New registrations are tried FIRST by
/// [`default_llm_provider`], so private extensions outrank built-ins.
/// Re-registering a provider with the same `name()` replaces the existing
/// entry (last write wins).
pub fn register_llm_provider(provider: Arc<dyn LlmProvider>) {
    let r = registry();
    let mut w = r.write().expect("LLM provider registry poisoned");
    let name = provider.name().to_string();
    w.retain(|p| p.name() != name);
    w.insert(0, provider);
}

/// Names of currently registered providers, in priority (newest-first) order.
pub fn registered_llm_providers() -> Vec<String> {
    let r = registry();
    let g = r.read().expect("LLM provider registry poisoned");
    g.iter().map(|p| p.name().to_string()).collect()
}

/// Look up a registered provider by exact name.
pub fn llm_provider_by_name(name: &str) -> Option<Arc<dyn LlmProvider>> {
    let r = registry();
    let g = r.read().expect("LLM provider registry poisoned");
    g.iter().find(|p| p.name() == name).map(Arc::clone)
}

/// Return the first registered provider whose [`LlmProvider::is_active`] is
/// `true`. Falls back to a fresh [`NoOpLlmProvider`] when no provider is
/// active — call sites using the returned `Arc` will surface a clear
/// `NotAvailable` error on first request, rather than panicking at lookup.
///
/// The `mock` built-in (registered by callers that opt into testing) is
/// intentionally skipped by auto-detect; use [`llm_provider_by_name`] for
/// explicit selection of `mock`.
pub fn default_llm_provider() -> Arc<dyn LlmProvider> {
    let r = registry();
    let g = r.read().expect("LLM provider registry poisoned");
    for p in g.iter() {
        if p.name() == "mock" {
            continue;
        }
        if p.is_active() {
            return Arc::clone(p);
        }
    }
    Arc::new(NoOpLlmProvider::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test provider that reports a configurable `is_active` and returns a
    /// fixed JSON value from `complete_json`. Used to exercise registry
    /// semantics without env-var coupling.
    #[derive(Debug)]
    struct TestProvider {
        name: &'static str,
        active: bool,
    }

    #[async_trait]
    impl LlmProvider for TestProvider {
        fn name(&self) -> &str {
            self.name
        }
        fn model_name(&self) -> &str {
            "test"
        }
        fn is_active(&self) -> bool {
            self.active
        }
        async fn complete_json(&self, _prompt: &str) -> Result<serde_json::Value, LlmError> {
            Ok(serde_json::json!({ "from": self.name }))
        }
    }

    #[test]
    fn noop_provider_is_inactive_and_errors_clearly() {
        let p = NoOpLlmProvider::new();
        assert_eq!(p.name(), "noop");
        assert!(!p.is_active());
    }

    #[tokio::test]
    async fn noop_complete_json_errors_with_not_available() {
        let p = NoOpLlmProvider::new();
        let err = p.complete_json("prompt").await.unwrap_err();
        assert!(matches!(err, LlmError::NotAvailable(_)));
    }

    #[test]
    fn register_provider_appears_in_registry() {
        register_llm_provider(Arc::new(TestProvider {
            name: "iface_test_appears",
            active: true,
        }));
        assert!(registered_llm_providers()
            .iter()
            .any(|n| n == "iface_test_appears"));
    }

    #[test]
    fn register_provider_dedups_by_name() {
        register_llm_provider(Arc::new(TestProvider {
            name: "iface_test_dedup",
            active: false,
        }));
        register_llm_provider(Arc::new(TestProvider {
            name: "iface_test_dedup",
            active: false,
        }));
        let count = registered_llm_providers()
            .into_iter()
            .filter(|n| n == "iface_test_dedup")
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn register_provider_outranks_earlier_registrations() {
        register_llm_provider(Arc::new(TestProvider {
            name: "iface_test_first",
            active: false,
        }));
        register_llm_provider(Arc::new(TestProvider {
            name: "iface_test_second",
            active: false,
        }));
        let names = registered_llm_providers();
        let first = names.iter().position(|n| n == "iface_test_first");
        let second = names.iter().position(|n| n == "iface_test_second");
        if let (Some(f), Some(s)) = (first, second) {
            assert!(
                s < f,
                "later registration must come first; full list: {names:?}"
            );
        } else {
            panic!("both names must be present; full list: {names:?}");
        }
    }

    #[tokio::test]
    async fn default_llm_provider_returns_first_active() {
        register_llm_provider(Arc::new(TestProvider {
            name: "iface_test_default_active",
            active: true,
        }));
        let p = default_llm_provider();
        // We can't assert `p.name() == "iface_test_default_active"` because
        // other tests register their own active providers in parallel. Verify
        // the contract behaviorally instead: the returned provider must be
        // active.
        assert!(
            p.is_active(),
            "default_llm_provider must return an active provider when one is registered"
        );
    }

    #[tokio::test]
    async fn default_llm_provider_skips_mock() {
        // mock should NEVER be auto-selected (it's opt-in via name lookup).
        register_llm_provider(Arc::new(TestProvider {
            name: "mock",
            active: true,
        }));
        let p = default_llm_provider();
        assert_ne!(
            p.name(),
            "mock",
            "default_llm_provider must skip the `mock` provider"
        );
    }

    #[test]
    fn llm_provider_by_name_finds_registered() {
        register_llm_provider(Arc::new(TestProvider {
            name: "iface_test_by_name",
            active: true,
        }));
        let p = llm_provider_by_name("iface_test_by_name").expect("present");
        assert_eq!(p.name(), "iface_test_by_name");
    }

    #[test]
    fn llm_provider_by_name_misses_return_none() {
        assert!(llm_provider_by_name("iface_test_nonexistent_provider").is_none());
    }
}
