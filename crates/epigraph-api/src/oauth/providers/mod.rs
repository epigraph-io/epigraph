//! Multi-provider external identity registry.
//!
//! See `docs/superpowers/specs/2026-04-26-multi-provider-identity-design.md`.

// Submodules are wired in subsequent tasks as their contents land.
pub mod cloudflare_access;
pub mod config;
pub mod google;
pub mod jwks;
pub mod provision;
mod registry;
pub use registry::ProviderRegistry;
mod traits;
pub use provision::provision_external_user;
pub use traits::{ExternalIdentity, ExternalIdentityProvider, OidcRedirectFlow, ProviderError};

use std::path::Path;
use std::sync::Arc;

use self::cloudflare_access::CloudflareAccessProvider;
use self::config::{ProviderFlow, ProvidersConfig};
use self::google::GoogleProvider;
use self::jwks::JwksCache;

/// Build a registry from a `providers.toml` path.
///
/// Currently dispatches `flow=redirect` to GoogleProvider and `flow=assertion` to CloudflareAccessProvider.
/// When adding more redirect providers, switch on `name` here.
pub fn build_registry(path: &Path) -> Result<Arc<ProviderRegistry>, String> {
    let mut registry = ProviderRegistry::empty();
    if !path.exists() {
        return Err(format!(
            "providers.toml not found at {path:?}; copy from providers.toml at repo root or set EPIGRAPH_PROVIDERS_CONFIG"
        ));
    }

    let cfg = ProvidersConfig::load_from_path(path).map_err(|e| e.to_string())?;
    cfg.validate().map_err(|e| e.to_string())?;
    let jwks = JwksCache::new();

    for p in cfg.providers {
        match p.flow {
            ProviderFlow::Redirect => {
                let google =
                    GoogleProvider::from_config(&p, jwks.clone()).map_err(|e| e.to_string())?;
                let arc = Arc::new(google);
                registry
                    .register(
                        arc.clone() as Arc<dyn ExternalIdentityProvider>,
                        Some(arc as Arc<dyn OidcRedirectFlow>),
                    )
                    .map_err(|e| e.to_string())?;
            }
            ProviderFlow::Assertion => {
                let cf = CloudflareAccessProvider::from_config(&p, jwks.clone())
                    .map_err(|e| e.to_string())?;
                registry
                    .register(Arc::new(cf) as Arc<dyn ExternalIdentityProvider>, None)
                    .map_err(|e| e.to_string())?;
            }
        }
    }
    tracing::info!(count = registry.names().count(), "Loaded provider registry");
    Ok(Arc::new(registry))
}
