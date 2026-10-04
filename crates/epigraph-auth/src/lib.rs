//! Shared OAuth2-style auth primitives for the EpiGraph workspace.
//!
//! Both `epigraph-api` (HTTP) and `epigraph-mcp` (MCP HTTP transport) validate
//! tokens against the same `JwtConfig`, so audience and algorithm must move in
//! lockstep.
//!
//! ## Audience
//!
//! Tokens use audience `"epigraph-api"` regardless of which server validates
//! them. MCP intentionally accepts API-minted tokens — there is no separate
//! `epigraph-mcp` audience. Adding one would double minting work for clients
//! that talk to both servers, and the threat model does not distinguish them.

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod claim_act;

/// The committed development JWT secret. NEVER acceptable in production.
/// Single source of truth — every consumer must reference this const, not a
/// copy of the literal.
pub const DEV_JWT_SECRET: &[u8] = b"epigraph-dev-secret-change-in-production!!";

/// Minimum acceptable HMAC secret length, in bytes.
pub const MIN_SECRET_LEN: usize = 32;

/// Fail-closed production secret gate. Returns `Err(reason)` if the secret is
/// empty, shorter than [`MIN_SECRET_LEN`] bytes, or equal to [`DEV_JWT_SECRET`].
///
/// Call this ONLY at binary boot, gated behind an opt-out env var for dev/CI.
/// Do NOT call it inside `JwtConfig::from_secret` or any state/builder
/// constructor — those are exercised by the test suite with the dev fallback.
pub fn assert_production_secret(secret: &[u8]) -> Result<(), String> {
    if secret.is_empty() {
        return Err("EPIGRAPH_JWT_SECRET is empty".to_string());
    }
    if secret.len() < MIN_SECRET_LEN {
        return Err(format!(
            "EPIGRAPH_JWT_SECRET is {} bytes; minimum is {MIN_SECRET_LEN}",
            secret.len()
        ));
    }
    if secret == DEV_JWT_SECRET {
        return Err(
            "EPIGRAPH_JWT_SECRET is the committed dev literal; refusing to start in production"
                .to_string(),
        );
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct EpiGraphClaims {
    pub sub: Uuid,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
    pub jti: Uuid,
    pub scopes: Vec<String>,
    pub client_type: String,
    pub owner_id: Option<Uuid>,
    pub agent_id: Option<Uuid>,
    /// The refresh-token family this access token was minted with: the
    /// `COALESCE(family_id, id)` of the refresh token issued or rotated in the
    /// same response. Present only on human tokens minted alongside a refresh
    /// token. A CLAIM, not authority: nothing grants anything on it alone.
    ///
    /// Optional both ways for N-1: a token without it decodes as `None`, and
    /// it is omitted from the payload when `None`, so a binary that predates it
    /// reads this binary's tokens (no `deny_unknown_fields` on this struct).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fam: Option<Uuid>,
    /// The elevation session this token claims. Nothing mints it yet; when
    /// something does, it is resolved against a live database row before it
    /// means anything. Same N-1 shape as [`Self::fam`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elv: Option<Uuid>,
}

/// What an access token is bound to beyond its client: the refresh family it
/// was minted with and the elevation session it claims. Every mint site passes
/// one, so a site that should carry a family cannot drop it by omission.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AccessTokenBinding {
    /// Becomes the `fam` claim.
    pub family_id: Option<Uuid>,
    /// Becomes the `elv` claim.
    pub elevation_id: Option<Uuid>,
}

impl AccessTokenBinding {
    /// No family, no elevation: the token's payload carries neither key.
    pub const NONE: Self = Self {
        family_id: None,
        elevation_id: None,
    };

    /// Bound to one refresh family, with no elevation.
    #[must_use]
    pub const fn family(family_id: Uuid) -> Self {
        Self {
            family_id: Some(family_id),
            elevation_id: None,
        }
    }
}

/// The scope ONLY an elevated access token carries (elevation plan EL-5):
/// `epigraph_core::canonical_scopes::PLATFORM_ADMIN_SCOPE`, spelled here
/// because this crate does not depend on `epigraph-core` (a test in
/// `epigraph-api` pins the two equal).
pub const ELEVATED_ONLY_SCOPE: &str = "platform:admin";

/// `scopes` without [`ELEVATED_ONLY_SCOPE`]: what any grant but the elevate
/// grant may mint, whatever a client's `granted_scopes` hold. The token
/// endpoint's grants build their response's `scope` with it, so the response
/// names exactly what [`JwtConfig::issue_access_token`] puts in the token.
#[must_use]
pub fn without_elevated_only_scope(mut scopes: Vec<String>) -> Vec<String> {
    scopes.retain(|s| s != ELEVATED_ONLY_SCOPE);
    scopes
}

pub struct JwtConfig {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtConfig {
    pub fn from_secret(secret: &[u8]) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the binding is the one options struct; folding the client's own \
                  claims into it too would touch every mint site for no gain"
    )]
    pub fn issue_access_token(
        &self,
        client_id: Uuid,
        scopes: Vec<String>,
        client_type: &str,
        owner_id: Option<Uuid>,
        agent_id: Option<Uuid>,
        ttl: Duration,
        binding: AccessTokenBinding,
    ) -> Result<(String, Uuid), jsonwebtoken::errors::Error> {
        // THE MINT CHOKEPOINT for the elevation scope: only a token that
        // names an elevation (the elevate grant's) may carry it, whatever the
        // caller asked for.
        let scopes = if binding.elevation_id.is_some() {
            scopes
        } else {
            without_elevated_only_scope(scopes)
        };
        let now = Utc::now();
        let jti = Uuid::new_v4();
        let claims = EpiGraphClaims {
            sub: client_id,
            iss: "epigraph".to_string(),
            aud: "epigraph-api".to_string(),
            exp: (now + ttl).timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            jti,
            scopes,
            client_type: client_type.to_string(),
            owner_id,
            agent_id,
            fam: binding.family_id,
            elv: binding.elevation_id,
        };
        let token = encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key)?;
        Ok((token, jti))
    }

    pub fn validate_token(
        &self,
        token: &str,
    ) -> Result<EpiGraphClaims, jsonwebtoken::errors::Error> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["epigraph"]);
        validation.set_audience(&["epigraph-api"]);
        validation.leeway = 0;
        let data = decode::<EpiGraphClaims>(token, &self.decoding_key, &validation)?;
        Ok(data.claims)
    }
}

/// Authorization context attached to a request after Bearer validation.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub client_id: Uuid,
    pub agent_id: Option<Uuid>,
    pub owner_id: Option<Uuid>,
    pub client_type: ClientType,
    pub scopes: Vec<String>,
    pub jti: Uuid,
    /// The token's `fam` claim: the refresh family it was minted with.
    pub family_id: Option<Uuid>,
    /// The token's `elv` claim, AS CLAIMED. Not authority: a request is
    /// elevated only once this is resolved against a live elevation session
    /// bound to this principal and family. Nothing resolves it yet.
    pub elevation_claim: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClientType {
    Agent,
    Human,
    Service,
}

impl AuthContext {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// Convert validated JWT claims into an `AuthContext`.
impl From<EpiGraphClaims> for AuthContext {
    fn from(claims: EpiGraphClaims) -> Self {
        let client_type = match claims.client_type.as_str() {
            "agent" => ClientType::Agent,
            "human" => ClientType::Human,
            _ => ClientType::Service,
        };
        Self {
            client_id: claims.sub,
            agent_id: claims.agent_id,
            owner_id: claims.owner_id,
            client_type,
            scopes: claims.scopes,
            jti: claims.jti,
            family_id: claims.fam,
            elevation_claim: claims.elv,
        }
    }
}

/// Returns Err with a 403-shaped message if any required scope is missing.
pub fn check_scopes(auth: &AuthContext, required: &[&str]) -> Result<(), String> {
    for scope in required {
        if !auth.has_scope(scope) {
            return Err(format!("Missing required scope: {scope}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `platform:admin` reaches a token ONLY with an elevation claim: a token
    /// minted without `elv` loses it whatever scopes it was asked for (so no
    /// client whose `granted_scopes` holds it can pre-arm a later check of
    /// it), and a token minted with `elv` keeps it. Other scopes pass
    /// through in order. Mutation: the strip dropped from
    /// `issue_access_token` -> the unelevated token carries it.
    #[test]
    fn only_an_elevated_token_carries_the_elevation_scope() {
        let cfg = JwtConfig::from_secret(b"test-secret-at-least-32-bytes!!");
        let asked = vec![
            "claims:read".to_string(),
            ELEVATED_ONLY_SCOPE.to_string(),
            "claims:write".to_string(),
        ];
        let mint = |binding: AccessTokenBinding| {
            let (token, _) = cfg
                .issue_access_token(
                    Uuid::new_v4(),
                    asked.clone(),
                    "human",
                    None,
                    Some(Uuid::new_v4()),
                    Duration::minutes(5),
                    binding,
                )
                .unwrap();
            cfg.validate_token(&token).unwrap().scopes
        };
        let fam = Uuid::new_v4();
        for binding in [AccessTokenBinding::NONE, AccessTokenBinding::family(fam)] {
            assert_eq!(mint(binding), vec!["claims:read", "claims:write"]);
        }
        let elevated = AccessTokenBinding {
            family_id: Some(fam),
            elevation_id: Some(Uuid::new_v4()),
        };
        assert_eq!(mint(elevated), asked);
        assert_eq!(
            without_elevated_only_scope(asked.clone()),
            vec!["claims:read", "claims:write"]
        );
    }

    #[test]
    fn jwt_roundtrip() {
        let cfg = JwtConfig::from_secret(b"test-secret-at-least-32-bytes!!");
        let (token, jti) = cfg
            .issue_access_token(
                Uuid::new_v4(),
                vec!["claims:read".into(), "claims:write".into()],
                "agent",
                None,
                None,
                Duration::minutes(5),
                AccessTokenBinding::NONE,
            )
            .unwrap();
        let claims = cfg.validate_token(&token).unwrap();
        assert_eq!(claims.jti, jti);
        assert_eq!(claims.aud, "epigraph-api");
    }

    #[test]
    fn expired_rejected() {
        let cfg = JwtConfig::from_secret(b"test-secret-at-least-32-bytes!!");
        let (token, _) = cfg
            .issue_access_token(
                Uuid::new_v4(),
                vec![],
                "agent",
                None,
                None,
                Duration::seconds(-10),
                AccessTokenBinding::NONE,
            )
            .unwrap();
        assert!(cfg.validate_token(&token).is_err());
    }

    #[test]
    fn wrong_secret_rejected() {
        let a = JwtConfig::from_secret(b"secret-one-at-least-32-bytes!!!");
        let b = JwtConfig::from_secret(b"secret-two-at-least-32-bytes!!!");
        let (token, _) = a
            .issue_access_token(
                Uuid::new_v4(),
                vec![],
                "agent",
                None,
                None,
                Duration::minutes(5),
                AccessTokenBinding::NONE,
            )
            .unwrap();
        assert!(b.validate_token(&token).is_err());
    }

    #[test]
    fn check_scopes_pass_and_fail() {
        let auth = AuthContext {
            client_id: Uuid::new_v4(),
            agent_id: None,
            owner_id: None,
            client_type: ClientType::Service,
            scopes: vec!["claims:read".into()],
            jti: Uuid::new_v4(),
            family_id: None,
            elevation_claim: None,
        };
        assert!(check_scopes(&auth, &["claims:read"]).is_ok());
        assert!(check_scopes(&auth, &["claims:write"]).is_err());
    }

    #[test]
    fn assert_production_secret_rejects_empty() {
        assert!(assert_production_secret(b"").is_err());
    }

    #[test]
    fn assert_production_secret_rejects_short() {
        // 31 bytes — one below the 32-byte floor.
        assert!(assert_production_secret(b"0123456789012345678901234567890").is_err());
    }

    #[test]
    fn assert_production_secret_rejects_dev_literal() {
        assert!(
            assert_production_secret(DEV_JWT_SECRET).is_err(),
            "the committed dev literal must never pass the production gate"
        );
    }

    #[test]
    fn assert_production_secret_accepts_real_secret() {
        // 40 random-looking bytes, not the dev literal.
        let secret = b"R7p2-Xq9_kL4vN8wErTy6uIoP1aSdFgHjKlZ0cVb";
        assert!(assert_production_secret(secret).is_ok());
    }
}
