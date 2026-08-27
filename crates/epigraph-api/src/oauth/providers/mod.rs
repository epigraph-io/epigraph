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
pub use provision::{provision_external_user, provision_external_user_client};
pub use traits::{ExternalIdentity, ExternalIdentityProvider, OidcRedirectFlow, ProviderError};

use std::path::Path;
use std::sync::Arc;

use self::cloudflare_access::CloudflareAccessProvider;
use self::config::{ProviderFlow, ProvidersConfig};
use self::google::GoogleProvider;
use self::jwks::JwksCache;

/// The deployment environments that are NOT production.
///
/// Deliberately an allowlist of known-safe names, so the DEFAULT — and, in
/// particular, an **unset** `EPIGRAPH_ENV` — is production. `EPIGRAPH_ENV` is
/// introduced by PR-02 and is therefore unset in every deployment that exists
/// today, which is exactly the population the boot assertion is for. Keying the
/// assertion on `env == "production"` would have made it fire only in the one
/// configuration nobody has yet: an operator who upgraded without also setting
/// the new variable would get a `tracing::warn!` and a clean boot, then a silent
/// authentication outage as `refresh_allowed` and `provision_external_user_client`
/// — both now deny-by-default — 403'd every already-provisioned identity. That
/// is the failure mode the assertion exists to convert into a loud one, and
/// standing decision Q4 (fail closed, explicit opt-in) settles which way an
/// unknown value goes.
const NON_PRODUCTION_ENVS: &[&str] = &["development", "dev", "test", "testing", "local", "ci"];

/// Does this `EPIGRAPH_ENV` value name a non-production environment?
///
/// Case- and whitespace-insensitive. Anything unrecognised — including the empty
/// string an unset variable yields — is production.
#[must_use]
pub fn env_is_production(env: &str) -> bool {
    !NON_PRODUCTION_ENVS.contains(&env.trim().to_ascii_lowercase().as_str())
}

/// Is this provider's identity-provisioning posture safe to serve?
///
/// The unsafe posture is exactly one shape: `auto_provision` on, NO identity
/// allowlist at all, and no explicit `allow_all_identities` opt-out. Before
/// PR-02 that shape meant "provision a `human` client for ANY identity this IdP
/// authenticates" and was documented as intended. It now means "provision
/// nobody" — and outside an explicitly-declared non-production `EPIGRAPH_ENV`
/// it means "do not boot", so an operator upgrading into the fail-closed default
/// discovers it at deploy time rather than through a silent authentication
/// outage. See [`env_is_production`] for why the default is the strict side.
///
/// Factored out of [`build_registry`] so all four corners are unit-testable
/// without writing a TOML file.
///
/// # Errors
/// Returns `Err(message)` only for the production case; every other
/// combination is `Ok(())` and the caller warns where appropriate.
pub fn provisioning_posture_is_safe(
    allowed_emails: &[String],
    allowed_domains: &[String],
    auto_provision: bool,
    allow_all_identities: bool,
    env: &str,
) -> Result<(), String> {
    let no_allowlist = allowed_emails.is_empty() && allowed_domains.is_empty();
    if !auto_provision || !no_allowlist || allow_all_identities {
        return Ok(());
    }
    if env_is_production(env) {
        return Err(format!(
            "auto_provision is enabled with no allowed_emails/allowed_domains and \
             EPIGRAPH_ALLOW_ALL_IDENTITIES is not \"true\". Populate the provider's \
             allowlist in providers.toml, or set EPIGRAPH_ALLOW_ALL_IDENTITIES=true \
             to declare that any identity this IdP authenticates may provision. \
             (EPIGRAPH_ENV={env:?} is treated as production; set it to one of \
             {NON_PRODUCTION_ENVS:?} to downgrade this to a warning.)"
        ));
    }
    Ok(())
}

/// Build a registry from a `providers.toml` path.
///
/// Currently dispatches `flow=redirect` to GoogleProvider and `flow=assertion` to CloudflareAccessProvider.
/// When adding more redirect providers, switch on `name` here.
///
/// `allow_all_identities` comes from [`crate::state::ApiConfig`]. This is the
/// only place in the process that sees the parsed provider configs before the
/// registry becomes an opaque `Arc`, so it is where PR-02's production boot
/// assertion lives — `AppState::with_db` is a sync constructor that installs
/// `ProviderRegistry::empty()` and structurally never sees an allowlist.
///
/// `env` is the raw `EPIGRAPH_ENV` value, read ONCE in `bin/server.rs` and
/// threaded in the same way `allow_all_identities` already is. It used to be a
/// bare `std::env::var` inside the provider loop; a hidden environment read in a
/// library function is untestable without mutating process state, which is why
/// the boot-assertion test could only reach the extracted predicate and never
/// `build_registry` itself.
///
/// # Errors
/// Returns `Err` when the file is missing or unparseable, when a provider's
/// config is invalid, or when any provider's provisioning posture is unsafe for
/// `env` (see [`provisioning_posture_is_safe`]).
pub fn build_registry(
    path: &Path,
    allow_all_identities: bool,
    env: &str,
) -> Result<Arc<ProviderRegistry>, String> {
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
        // Security gate: an auto-provisioning provider with no identity
        // allowlist. Before PR-02 this minted a `human` client for ANY identity
        // the IdP authenticated; it now provisions nobody. Refuse to boot in
        // production so the operator fixes it deliberately; warn everywhere else
        // so dev and CI still run.
        provisioning_posture_is_safe(
            &p.allowed_emails,
            &p.allowed_domains,
            p.auto_provision,
            allow_all_identities,
            env,
        )
        .map_err(|e| format!("provider '{}': {e}", p.name))?;

        if p.auto_provision && p.allowed_emails.is_empty() && p.allowed_domains.is_empty() {
            if allow_all_identities {
                tracing::warn!(
                    provider = %p.name,
                    "auto_provision enabled with no identity allowlist AND \
                     allow_all_identities=true — ALL authenticated identities will be provisioned"
                );
            } else {
                tracing::warn!(
                    provider = %p.name,
                    "auto_provision enabled with no identity allowlist and \
                     allow_all_identities=false — NO identity can provision through this \
                     provider. Populate allowed_emails/allowed_domains in providers.toml. \
                     (This is a hard startup failure unless EPIGRAPH_ENV names a \
                     non-production environment.)"
                );
            }
        }
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

#[cfg(test)]
mod posture_tests {
    use super::provisioning_posture_is_safe;

    fn list(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn empty_allowlist_in_production_without_opt_out_refuses_to_boot() {
        let err = provisioning_posture_is_safe(&[], &[], true, false, "production")
            .expect_err("must refuse");
        assert!(
            err.contains("EPIGRAPH_ALLOW_ALL_IDENTITIES"),
            "the error must name the escape hatch, got: {err}"
        );
    }

    #[test]
    fn empty_allowlist_in_production_with_opt_out_boots() {
        // Explicit operator declaration: allow-all is back, and they said so.
        assert!(provisioning_posture_is_safe(&[], &[], true, true, "production").is_ok());
    }

    #[test]
    fn empty_allowlist_outside_production_boots() {
        // Dev/CI keep running; the caller logs a warning instead. Each name has
        // to be DECLARED — this is an allowlist, not "anything but production".
        for env in [
            "development",
            "dev",
            "test",
            "testing",
            "local",
            "ci",
            "  CI  ",
        ] {
            assert!(
                provisioning_posture_is_safe(&[], &[], true, false, env).is_ok(),
                "{env:?} must be recognised as non-production"
            );
        }
    }

    /// The default side of the gate, and the whole reason the assertion is worth
    /// having: `EPIGRAPH_ENV` is introduced by PR-02, so it is UNSET in every
    /// deployment that exists today. An `env == "production"` test would fire
    /// only where someone had already set the new variable — i.e. nowhere — and
    /// the fail-closed `refresh_allowed` / `provision_external_user_client`
    /// changes shipping alongside it would surface as a silent auth outage
    /// instead. Unset, and anything unrecognised, is production.
    #[test]
    fn an_unset_or_unknown_env_is_treated_as_production() {
        for env in [
            "",
            "   ",
            "staging",
            "prod",
            "production",
            "Production",
            "qa",
        ] {
            assert!(
                provisioning_posture_is_safe(&[], &[], true, false, env).is_err(),
                "{env:?} must be treated as production"
            );
        }
    }

    #[test]
    fn a_configured_allowlist_boots_everywhere() {
        assert!(
            provisioning_posture_is_safe(&list(&["a@b.test"]), &[], true, false, "production")
                .is_ok()
        );
        assert!(
            provisioning_posture_is_safe(&[], &list(&["b.test"]), true, false, "production")
                .is_ok()
        );
    }

    #[test]
    fn auto_provision_off_boots_with_an_empty_allowlist() {
        // Nothing can provision through it at all, so the allowlist is moot.
        assert!(provisioning_posture_is_safe(&[], &[], false, false, "production").is_ok());
    }
}
