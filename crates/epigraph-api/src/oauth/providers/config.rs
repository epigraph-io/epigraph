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
// Reject unknown keys so a misspelled allowlist key (e.g. `allowed_email`
// singular, or wrong nesting) fails the parse LOUDLY rather than silently
// deserializing to an empty Vec via `#[serde(default)]` — which the allow-all
// default in `email_is_allowed` would then treat as "permit everyone",
// re-opening the exact over-broad default this allowlist exists to close.
#[serde(deny_unknown_fields)]
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
    /// Allowlist of exact email addresses permitted to auto-provision.
    /// Empty (the serde default) together with `allowed_domains` empty means
    /// allow-all (backward compatible). See [`email_is_allowed`].
    #[serde(default)]
    pub allowed_emails: Vec<String>,
    /// Allowlist of email domains (the part after the last `@`) permitted to
    /// auto-provision. Empty together with `allowed_emails` empty means allow-all.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

fn default_true() -> bool {
    true
}

/// Decide whether `email` is permitted by the configured allowlists.
///
/// Semantics (deliberately conservative — this gate is security-sensitive):
/// * Both lists empty -> `true` (allow-all; the gate is opt-in and backward
///   compatible with the serde-default-empty config).
/// * Otherwise -> `true` iff the trimmed, lowercased email EXACTLY matches some
///   `allowed_emails` entry (compared case-insensitively after trimming the
///   entry too) OR its domain (the substring after the LAST `@`, lowercased)
///   matches some `allowed_domains` entry.
/// * An empty email while an allowlist IS configured -> `false` (deny). This
///   prevents an absent/`""` email (provision uses `unwrap_or_default()`) from
///   slipping past a malformed empty allowlist entry.
///
/// `email_verified` is intentionally NOT a parameter: it is a call-site concern
/// (provision checks it only when an allowlist is configured, and only for
/// providers that don't already hardcode verification). Keeping it out keeps
/// this helper a pure, total string predicate that is trivial to unit-test.
pub fn email_is_allowed(
    email: &str,
    allowed_emails: &[String],
    allowed_domains: &[String],
) -> bool {
    // Both empty => allow-all (opt-in gate, backward compatible).
    if allowed_emails.is_empty() && allowed_domains.is_empty() {
        return true;
    }

    let email = email.trim().to_ascii_lowercase();
    // An allowlist is configured but the email is empty/absent => deny.
    if email.is_empty() {
        return false;
    }

    // Exact-address match (case-insensitive; trim the configured entries too so
    // stray whitespace in TOML doesn't create a never-matching entry, and an
    // empty/blank entry can never match the already-non-empty email).
    if allowed_emails
        .iter()
        .any(|e| e.trim().to_ascii_lowercase() == email)
    {
        return true;
    }

    // Domain match on the substring after the LAST '@'. Without an '@' there is
    // no domain to compare, so domain rules cannot match.
    if let Some(idx) = email.rfind('@') {
        let domain = &email[idx + 1..];
        if !domain.is_empty()
            && allowed_domains
                .iter()
                .any(|d| d.trim().to_ascii_lowercase() == domain)
        {
            return true;
        }
    }

    false
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
    fn allowlist_keys_parse_and_default_empty() {
        // Absent keys default to empty (allow-all).
        let cfg = ProvidersConfig::parse(sample_redirect()).unwrap();
        assert!(cfg.providers[0].allowed_emails.is_empty());
        assert!(cfg.providers[0].allowed_domains.is_empty());

        // Present keys parse into the vecs.
        let text = format!(
            "{sample}allowed_emails = [\"jeremy.barton@gmail.com\"]\nallowed_domains = [\"baros.associates\"]\n",
            sample = sample_redirect()
        );
        let cfg = ProvidersConfig::parse(&text).unwrap();
        assert_eq!(
            cfg.providers[0].allowed_emails,
            vec!["jeremy.barton@gmail.com".to_string()]
        );
        assert_eq!(
            cfg.providers[0].allowed_domains,
            vec!["baros.associates".to_string()]
        );
    }

    fn emails(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn both_lists_empty_allows_all() {
        // Allow-all is the opt-in default; even an empty email is permitted when
        // no allowlist is configured (matches pre-gate provisioning behavior).
        assert!(email_is_allowed("anyone@example.com", &[], &[]));
        assert!(email_is_allowed("", &[], &[]));
    }

    #[test]
    fn exact_email_match_is_case_insensitive() {
        let allowed = emails(&["jeremy.barton@gmail.com"]);
        assert!(email_is_allowed("Jeremy.Barton@GMAIL.com", &allowed, &[]));
    }

    #[test]
    fn email_whitespace_is_trimmed_before_match() {
        let allowed = emails(&["jeremy.barton@gmail.com"]);
        assert!(email_is_allowed(
            "  jeremy.barton@gmail.com\t",
            &allowed,
            &[]
        ));
    }

    #[test]
    fn unlisted_email_is_denied_when_allowlist_present() {
        let allowed = emails(&["jeremy.barton@gmail.com"]);
        assert!(!email_is_allowed("evil@attacker.com", &allowed, &[]));
    }

    #[test]
    fn domain_allow_permits_any_address_in_domain() {
        let domains = emails(&["baros.associates"]);
        assert!(email_is_allowed("anyone@baros.associates", &[], &domains));
        assert!(email_is_allowed("Someone@Baros.Associates", &[], &domains));
    }

    #[test]
    fn domain_allow_does_not_permit_other_domains() {
        // Allowed only via domain, not exact: an address in a DIFFERENT domain
        // whose exact form is not listed must be denied.
        let domains = emails(&["baros.associates"]);
        assert!(!email_is_allowed("jeremy@gmail.com", &[], &domains));
        // And a substring/suffix attack must not match: "evilbaros.associates"
        // and "baros.associates.attacker.com" are different domains.
        assert!(!email_is_allowed("x@evilbaros.associates", &[], &domains));
        assert!(!email_is_allowed(
            "x@baros.associates.attacker.com",
            &[],
            &domains
        ));
    }

    #[test]
    fn empty_email_denied_when_allowlist_configured() {
        let allowed = emails(&["jeremy.barton@gmail.com"]);
        assert!(!email_is_allowed("", &allowed, &[]));
        assert!(!email_is_allowed("   ", &allowed, &[]));
        // Also when only a domain allowlist is configured.
        let domains = emails(&["baros.associates"]);
        assert!(!email_is_allowed("", &[], &domains));
    }

    #[test]
    fn domain_split_uses_last_at_sign() {
        // Plus-addressing / multiple '@' (quoted local parts): the domain is the
        // part after the LAST '@', so this resolves to "gmail.com".
        let domains = emails(&["gmail.com"]);
        assert!(email_is_allowed("weird@local@gmail.com", &[], &domains));
        // And exact-match must NOT be fooled into treating a malformed address
        // with no domain as allowed by a domain rule.
        assert!(!email_is_allowed("nodomain", &[], &domains));
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
