//! JWT creation and validation using HMAC-SHA256.
//!
//! The server has its own secret key used exclusively for signing/verifying JWTs.
//! Uses HMAC-SHA256 as a placeholder until EdDSA support in jsonwebtoken stabilises.
//! The token format is identical — only the signing algorithm changes.

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// JWT claims for EpiGraph access tokens.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct EpiGraphClaims {
    /// Subject: oauth_clients.id
    pub sub: Uuid,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
    /// Expiration (unix timestamp)
    pub exp: i64,
    /// Issued at (unix timestamp)
    pub iat: i64,
    /// Not before (unix timestamp)
    pub nbf: i64,
    /// JWT ID (unique per token, referenced by provenance_log)
    pub jti: Uuid,
    /// OAuth2 scopes
    pub scopes: Vec<String>,
    /// Client type: agent, human, service
    pub client_type: String,
    /// Human owner's oauth_clients.id (None for humans themselves)
    pub owner_id: Option<Uuid>,
    /// Agent ID in the knowledge graph (None for non-agent clients)
    pub agent_id: Option<Uuid>,
}

/// Server-side JWT signing configuration.
pub struct JwtConfig {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtConfig {
    /// Create from a shared secret (HMAC-SHA256).
    pub fn from_secret(secret: &[u8]) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
        }
    }

    /// Issue an access token JWT.
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

    /// Validate and decode an access token JWT.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_roundtrip() {
        let config = JwtConfig::from_secret(b"test-secret-at-least-32-bytes!!");
        let client_id = Uuid::new_v4();
        let scopes = vec!["claims:read".to_string(), "analysis:belief".to_string()];

        let (token, jti) = config
            .issue_access_token(
                client_id,
                scopes.clone(),
                "agent",
                Some(Uuid::new_v4()),
                Some(Uuid::new_v4()),
                Duration::minutes(15),
            )
            .unwrap();

        let claims = config.validate_token(&token).unwrap();
        assert_eq!(claims.sub, client_id);
        assert_eq!(claims.scopes, scopes);
        assert_eq!(claims.client_type, "agent");
        assert_eq!(claims.jti, jti);
        assert_eq!(claims.iss, "epigraph");
        assert_eq!(claims.aud, "epigraph-api");
    }

    #[test]
    fn test_expired_token_rejected() {
        let config = JwtConfig::from_secret(b"test-secret-at-least-32-bytes!!");
        let (token, _) = config
            .issue_access_token(
                Uuid::new_v4(),
                vec![],
                "agent",
                None,
                None,
                Duration::seconds(-10), // already expired
            )
            .unwrap();
        assert!(config.validate_token(&token).is_err());
    }

    #[test]
    fn test_wrong_secret_rejected() {
        let config1 = JwtConfig::from_secret(b"secret-one-at-least-32-bytes!!!");
        let config2 = JwtConfig::from_secret(b"secret-two-at-least-32-bytes!!!");
        let (token, _) = config1
            .issue_access_token(
                Uuid::new_v4(),
                vec![],
                "agent",
                None,
                None,
                Duration::minutes(15),
            )
            .unwrap();
        assert!(config2.validate_token(&token).is_err());
    }
}
