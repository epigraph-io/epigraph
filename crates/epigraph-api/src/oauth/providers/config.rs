//! TOML schema for `providers.toml` and validation.
//!
//! Sample:
//!
//! ```toml
//! [[provider]]
//! name = "google"
//! flow = "redirect"
//! grant_type = "google_id_token"
//! issuer = "https://accounts.google.com"
//! extra_issuers = ["accounts.google.com"]
//! jwks_url = "https://www.googleapis.com/oauth2/v3/certs"
//! audience_env = "GOOGLE_CLIENT_ID"
//! client_id_env = "GOOGLE_CLIENT_ID"
//! client_secret_env = "GOOGLE_CLIENT_SECRET"
//! auth_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
//! token_endpoint = "https://oauth2.googleapis.com/token"
//! redirect_uri_env = "EPIGRAPH_REDIRECT_URI"
//! auto_provision = true
//! default_scopes = ["claims:read", "claims:write"]
//! ```

use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProviderConfigError {
    #[error("io: {0}")]
    Io(String),
    #[error("toml parse: {0}")]
    Parse(String),
    #[error("missing env var {0}")]
    MissingEnv(String),
    #[error("invalid provider name {0:?}: must match [a-z0-9-]+")]
    InvalidName(String),
    #[error("duplicate provider name: {0}")]
    DuplicateName(String),
    #[error("duplicate grant_type: {0}")]
    DuplicateGrantType(String),
    #[error("provider {name}: missing required field {field} for flow={flow}")]
    MissingField {
        name: String,
        flow: String,
        field: String,
    },
}

#[derive(Debug, Deserialize)]
pub struct ProvidersConfig {
    #[serde(rename = "provider", default)]
    pub providers: Vec<ProviderConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProviderConfig {
    pub name: String,
    pub flow: ProviderFlow,
    pub grant_type: String,
    pub issuer: String,
    #[serde(default)]
    pub extra_issuers: Vec<String>,
    pub jwks_url: String,
    pub audience: Option<String>,
    pub audience_env: Option<String>,
    pub client_id_env: Option<String>,
    pub client_secret_env: Option<String>,
    pub auth_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    /// Optional literal redirect URI; takes precedence over `redirect_uri_env`.
    pub redirect_uri: Option<String>,
    /// Optional env-var name to read the redirect URI from. Lower priority than `redirect_uri`.
    pub redirect_uri_env: Option<String>,
    #[serde(default = "default_true")]
    pub auto_provision: bool,
    #[serde(default)]
    pub default_scopes: Vec<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProviderFlow {
    Redirect,
    Assertion,
}

impl ProvidersConfig {
    /// Read TOML from disk and parse. Does not resolve env vars or validate.
    pub fn load_from_path(path: &Path) -> Result<Self, ProviderConfigError> {
        let text =
            std::fs::read_to_string(path).map_err(|e| ProviderConfigError::Io(e.to_string()))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ProviderConfigError> {
        toml::from_str(text).map_err(|e| ProviderConfigError::Parse(e.to_string()))
    }

    /// Validate cross-cutting invariants: unique names/grant_types, name format,
    /// required fields per flow.
    pub fn validate(&self) -> Result<(), ProviderConfigError> {
        let mut seen_names = std::collections::HashSet::new();
        let mut seen_grants = std::collections::HashSet::new();
        for p in &self.providers {
            validate_name(&p.name)?;
            if !seen_names.insert(&p.name) {
                return Err(ProviderConfigError::DuplicateName(p.name.clone()));
            }
            if !seen_grants.insert(&p.grant_type) {
                return Err(ProviderConfigError::DuplicateGrantType(
                    p.grant_type.clone(),
                ));
            }
            match p.flow {
                ProviderFlow::Redirect => {
                    require(&p.name, "redirect", "auth_endpoint", &p.auth_endpoint)?;
                    require(&p.name, "redirect", "token_endpoint", &p.token_endpoint)?;
                    require(&p.name, "redirect", "client_id_env", &p.client_id_env)?;
                    require(
                        &p.name,
                        "redirect",
                        "client_secret_env",
                        &p.client_secret_env,
                    )?;
                }
                ProviderFlow::Assertion => {
                    if p.audience.is_none() && p.audience_env.is_none() {
                        return Err(ProviderConfigError::MissingField {
                            name: p.name.clone(),
                            flow: "assertion".into(),
                            field: "audience or audience_env".into(),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

fn require<T>(
    name: &str,
    flow: &str,
    field: &str,
    val: &Option<T>,
) -> Result<(), ProviderConfigError> {
    if val.is_none() {
        Err(ProviderConfigError::MissingField {
            name: name.into(),
            flow: flow.into(),
            field: field.into(),
        })
    } else {
        Ok(())
    }
}

fn validate_name(name: &str) -> Result<(), ProviderConfigError> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(ProviderConfigError::InvalidName(name.to_string()));
    }
    Ok(())
}

/// Resolve an env-var reference; returns the value or `MissingEnv`.
pub fn resolve_env(var_name: &str) -> Result<String, ProviderConfigError> {
    std::env::var(var_name).map_err(|_| ProviderConfigError::MissingEnv(var_name.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_redirect() -> &'static str {
        r#"
[[provider]]
name = "google"
flow = "redirect"
grant_type = "google_id_token"
issuer = "https://accounts.google.com"
jwks_url = "https://www.googleapis.com/oauth2/v3/certs"
audience_env = "GOOGLE_CLIENT_ID"
client_id_env = "GOOGLE_CLIENT_ID"
client_secret_env = "GOOGLE_CLIENT_SECRET"
auth_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
token_endpoint = "https://oauth2.googleapis.com/token"
default_scopes = ["claims:read"]
"#
    }

    #[test]
    fn parses_redirect_provider() {
        let cfg = ProvidersConfig::parse(sample_redirect()).unwrap();
        assert_eq!(cfg.providers.len(), 1);
        assert_eq!(cfg.providers[0].name, "google");
        assert_eq!(cfg.providers[0].flow, ProviderFlow::Redirect);
        cfg.validate().unwrap();
    }

    #[test]
    fn missing_redirect_field_rejected() {
        let mut cfg = ProvidersConfig::parse(sample_redirect()).unwrap();
        cfg.providers[0].auth_endpoint = None;
        let err = cfg.validate().unwrap_err();
        match err {
            ProviderConfigError::MissingField { field, .. } => {
                assert_eq!(field, "auth_endpoint")
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn duplicate_name_rejected() {
        let text = format!("{}{}", sample_redirect(), sample_redirect());
        let cfg = ProvidersConfig::parse(&text).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ProviderConfigError::DuplicateName(_)));
    }

    #[test]
    fn invalid_name_format_rejected() {
        let mut cfg = ProvidersConfig::parse(sample_redirect()).unwrap();
        cfg.providers[0].name = "Google".into();
        assert!(matches!(
            cfg.validate(),
            Err(ProviderConfigError::InvalidName(_))
        ));
    }

    #[test]
    fn assertion_flow_requires_audience() {
        let text = r#"
[[provider]]
name = "cf"
flow = "assertion"
grant_type = "cf_jwt"
issuer = "https://team.cloudflareaccess.com"
jwks_url = "https://team.cloudflareaccess.com/cdn-cgi/access/certs"
"#;
        let cfg = ProvidersConfig::parse(text).unwrap();
        assert!(matches!(
            cfg.validate(),
            Err(ProviderConfigError::MissingField { .. })
        ));
    }
}
