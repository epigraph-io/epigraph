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

    pub fn issue_access_token(
        &self,
        client_id: Uuid,
        scopes: Vec<String>,
        client_type: &str,
        owner_id: Option<Uuid>,
        agent_id: Option<Uuid>,
        ttl: Duration,
    ) -> Result<(String, Uuid), jsonwebtoken::errors::Error> {
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
        };
        assert!(check_scopes(&auth, &["claims:read"]).is_ok());
        assert!(check_scopes(&auth, &["claims:write"]).is_err());
    }
}
