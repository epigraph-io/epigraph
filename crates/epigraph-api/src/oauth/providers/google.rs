//! Google identity provider — implements both ExternalIdentityProvider and OidcRedirectFlow.

use async_trait::async_trait;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use super::config::ProviderConfig;
use super::jwks::JwksCache;
use super::traits::{ExternalIdentity, ExternalIdentityProvider, OidcRedirectFlow, ProviderError};

/// Percent-encode a query-string value per RFC 3986 unreserved set.
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[derive(Debug, Deserialize)]
struct GoogleClaims {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    iat: u64,
    exp: u64,
}

pub struct GoogleProvider {
    name: String,
    grant_type: String,
    issuer_primary: String,
    extra_issuers: Vec<String>,
    jwks_url: String,
    audience: String,
    client_id: String,
    client_secret: String,
    auth_endpoint: String,
    token_endpoint: String,
    default_redirect_uri: Option<String>,
    auto_provision: bool,
    default_scopes: Vec<String>,
    jwks: JwksCache,
}

impl GoogleProvider {
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
        let client_id = resolve_env(
            cfg.client_id_env
                .as_deref()
                .ok_or_else(|| ProviderError::Config("client_id_env required".into()))?,
        )?;
        let client_secret = resolve_env(
            cfg.client_secret_env
                .as_deref()
                .ok_or_else(|| ProviderError::Config("client_secret_env required".into()))?,
        )?;
        let auth_endpoint = cfg
            .auth_endpoint
            .clone()
            .ok_or_else(|| ProviderError::Config("auth_endpoint required".into()))?;
        let token_endpoint = cfg
            .token_endpoint
            .clone()
            .ok_or_else(|| ProviderError::Config("token_endpoint required".into()))?;

        let default_redirect_uri = match (&cfg.redirect_uri, &cfg.redirect_uri_env) {
            (Some(u), _) => Some(u.clone()),
            (_, Some(env)) => Some(resolve_env(env)?),
            _ => None,
        };

        Ok(Self {
            name: cfg.name.clone(),
            grant_type: cfg.grant_type.clone(),
            issuer_primary: cfg.issuer.clone(),
            extra_issuers: cfg.extra_issuers.clone(),
            jwks_url: cfg.jwks_url.clone(),
            audience,
            client_id,
            client_secret,
            auth_endpoint,
            token_endpoint,
            default_redirect_uri,
            auto_provision: cfg.auto_provision,
            default_scopes: cfg.default_scopes.clone(),
            jwks,
        })
    }

    fn issuers(&self) -> Vec<&str> {
        let mut v = vec![self.issuer_primary.as_str()];
        v.extend(self.extra_issuers.iter().map(|s| s.as_str()));
        v
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
            None if !refetch => {
                // One forced refetch on kid miss.
                return Box::pin(self.validate_with_kid(assertion, true)).await;
            }
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
        validation.set_issuer(&self.issuers());
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.leeway = 60;

        let data = decode::<GoogleClaims>(assertion, &decoding, &validation)
            .map_err(|e| ProviderError::InvalidAssertion(format!("validation failed: {e}")))?;
        let raw = serde_json::json!({
            "sub": data.claims.sub,
            "email": data.claims.email,
            "email_verified": data.claims.email_verified,
            "name": data.claims.name,
            "iat": data.claims.iat,
            "exp": data.claims.exp,
        });
        Ok(ExternalIdentity {
            subject: data.claims.sub,
            email: data.claims.email,
            email_verified: data.claims.email_verified.unwrap_or(false),
            name: data.claims.name,
            raw_claims: raw,
        })
    }
}

#[async_trait]
impl ExternalIdentityProvider for GoogleProvider {
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

#[async_trait]
impl OidcRedirectFlow for GoogleProvider {
    fn build_auth_url(&self, state: &str, pkce_challenge: &str, redirect_uri: &str) -> String {
        format!(
            "{}?client_id={}&redirect_uri={}&response_type=code\
             &scope=openid+email+profile&code_challenge={}&code_challenge_method=S256\
             &access_type=offline&state={}",
            self.auth_endpoint,
            pct_encode(&self.client_id),
            pct_encode(redirect_uri),
            pct_encode(pkce_challenge),
            pct_encode(state),
        )
    }

    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        pkce_verifier: &str,
    ) -> Result<String, ProviderError> {
        let params = [
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("code", code),
            ("code_verifier", pkce_verifier),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect_uri),
        ];
        let resp = reqwest::Client::new()
            .post(&self.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| ProviderError::Upstream(format!("token POST failed: {e}")))?;
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ProviderError::Upstream(format!("bad token response: {e}")))?;
        if let Some(err) = body.get("error").and_then(|v| v.as_str()) {
            return Err(ProviderError::Upstream(format!(
                "idp returned error: {err}"
            )));
        }
        body.get("id_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| ProviderError::Upstream("response missing id_token".into()))
    }

    fn default_redirect_uri(&self) -> Option<&str> {
        self.default_redirect_uri.as_deref()
    }
}
