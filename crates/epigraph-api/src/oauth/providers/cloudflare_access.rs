//! Cloudflare Access provider — assertion-only (no redirect dance).
//!
//! Validates `Cf-Access-Jwt-Assertion` JWTs against Cloudflare Access's JWKS.

use async_trait::async_trait;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use super::config::ProviderConfig;
use super::jwks::JwksCache;
use super::traits::{ExternalIdentity, ExternalIdentityProvider, ProviderError};

#[derive(Debug, Deserialize)]
struct CfClaims {
    sub: String,
    email: Option<String>,
    name: Option<String>,
    /// CF Access emits `aud` as an array (one element typically).
    /// jsonwebtoken's `Validation::set_audience` handles either string or array shape.
    iss: String,
    iat: u64,
    exp: u64,
}

pub struct CloudflareAccessProvider {
    name: String,
    grant_type: String,
    issuer: String,
    jwks_url: String,
    audience: String,
    auto_provision: bool,
    default_scopes: Vec<String>,
    jwks: JwksCache,
}

impl CloudflareAccessProvider {
    pub fn from_config(cfg: &ProviderConfig, jwks: JwksCache) -> Result<Self, ProviderError> {
        let resolve_env = |var: &str| -> Result<String, ProviderError> {
            std::env::var(var).map_err(|_| ProviderError::Config(format!("env var {var} not set")))
        };
        let audience = match (&cfg.audience, &cfg.audience_env) {
            (Some(a), _) => a.clone(),
            (_, Some(env)) => resolve_env(env)?,
            _ => {
                return Err(ProviderError::Config(
                    "audience/audience_env required".into(),
                ))
            }
        };
        Ok(Self {
            name: cfg.name.clone(),
            grant_type: cfg.grant_type.clone(),
            issuer: cfg.issuer.clone(),
            jwks_url: cfg.jwks_url.clone(),
            audience,
            auto_provision: cfg.auto_provision,
            default_scopes: cfg.default_scopes.clone(),
            jwks,
        })
    }

    async fn validate_with_kid(
        &self,
        assertion: &str,
        refetch: bool,
    ) -> Result<ExternalIdentity, ProviderError> {
        let header = decode_header(assertion)
            .map_err(|e| ProviderError::InvalidAssertion(format!("bad header: {e}")))?;
        let kid = header
            .kid
            .ok_or_else(|| ProviderError::InvalidAssertion("missing kid".into()))?;
        let keys = if refetch {
            self.jwks.refetch(&self.jwks_url).await?
        } else {
            self.jwks.get(&self.jwks_url).await?
        };
        let arr = keys
            .as_array()
            .ok_or_else(|| ProviderError::JwksFetch("keys not an array".into()))?;
        let key = arr.iter().find(|k| k["kid"].as_str() == Some(&kid));
        let key = match key {
            Some(k) => k,
            None if !refetch => return Box::pin(self.validate_with_kid(assertion, true)).await,
            None => {
                return Err(ProviderError::InvalidAssertion(format!(
                    "kid {kid} not in JWKS"
                )))
            }
        };
        let n = key["n"]
            .as_str()
            .ok_or_else(|| ProviderError::JwksFetch("missing 'n'".into()))?;
        let e = key["e"]
            .as_str()
            .ok_or_else(|| ProviderError::JwksFetch("missing 'e'".into()))?;
        let decoding = DecodingKey::from_rsa_components(n, e)
            .map_err(|err| ProviderError::JwksFetch(format!("bad RSA key: {err}")))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.audience]);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.leeway = 60;

        let data = decode::<CfClaims>(assertion, &decoding, &validation)
            .map_err(|e| ProviderError::InvalidAssertion(format!("validation failed: {e}")))?;

        let raw = serde_json::json!({
            "sub": data.claims.sub,
            "email": data.claims.email,
            "name": data.claims.name,
            "iss": data.claims.iss,
            "iat": data.claims.iat,
            "exp": data.claims.exp,
        });

        Ok(ExternalIdentity {
            subject: data.claims.sub,
            email: data.claims.email,
            email_verified: true, // CF gates by IdP — treat as verified
            name: data.claims.name,
            raw_claims: raw,
        })
    }
}

#[async_trait]
impl ExternalIdentityProvider for CloudflareAccessProvider {
    fn name(&self) -> &str {
        &self.name
    }
    fn grant_type(&self) -> &str {
        &self.grant_type
    }
    async fn validate(&self, assertion: &str) -> Result<ExternalIdentity, ProviderError> {
        self.validate_with_kid(assertion, false).await
    }
    fn auto_provision(&self) -> bool {
        self.auto_provision
    }
    fn default_scopes(&self) -> &[String] {
        &self.default_scopes
    }
}
