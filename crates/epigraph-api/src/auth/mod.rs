//! Kernel-side authentication helpers: `IdentityResolver`, default-scope catalogues.

#[cfg(feature = "db")]
pub mod identity_resolver;

#[cfg(feature = "db")]
pub use identity_resolver::IdentityResolver;

/// Default scope set granted to auto-provisioned humans (Google, CF Access, …).
///
/// Mirrors the inline list previously in `oauth/token.rs` (`provision_google_user`
/// at lines 481-501). Exposed publicly so overlay providers can reuse it without
/// duplicating.
#[must_use]
pub fn human_default_scopes() -> Vec<String> {
    vec![
        "claims:read".to_string(),
        "claims:write".to_string(),
        "claims:challenge".to_string(),
        "evidence:read".to_string(),
        "evidence:submit".to_string(),
        "edges:read".to_string(),
        "edges:write".to_string(),
        "agents:read".to_string(),
        "agents:write".to_string(),
        "groups:read".to_string(),
        "groups:manage".to_string(),
        "analysis:belief".to_string(),
        "analysis:propagation".to_string(),
        "analysis:reasoning".to_string(),
        "analysis:gaps".to_string(),
        "analysis:structural".to_string(),
        "analysis:hypothesis".to_string(),
        "analysis:political".to_string(),
        "clients:register".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_default_scopes_count_is_19() {
        assert_eq!(human_default_scopes().len(), 19);
    }

    #[test]
    fn human_default_scopes_includes_clients_register() {
        assert!(human_default_scopes().iter().any(|s| s == "clients:register"));
    }
}
