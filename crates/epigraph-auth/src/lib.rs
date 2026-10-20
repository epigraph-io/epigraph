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
    /// The DELEGATOR of a delegated run token: the agent of the OAuth client
    /// that asked for this token on `agent_id`'s behalf (`sub` is that
    /// client's row). A CLAIM, not authority: every site that admits it checks,
    /// per request, that the delegation is still live
    /// (`epigraph_db::AgentRepository::delegated_principal_pool`), and a site
    /// that does not know it treats the token as an ordinary token for
    /// `agent_id`, which is refused when that agent is operated (fails
    /// closed). Same N-1 shape as [`Self::fam`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dlg: Option<Uuid>,
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
    /// Becomes the `dlg` claim.
    pub delegated_by: Option<Uuid>,
}

impl AccessTokenBinding {
    /// No family, no elevation: the token's payload carries neither key.
    pub const NONE: Self = Self {
        family_id: None,
        elevation_id: None,
        delegated_by: None,
    };

    /// Bound to one refresh family, with no elevation.
    #[must_use]
    pub const fn family(family_id: Uuid) -> Self {
        Self {
            family_id: Some(family_id),
            elevation_id: None,
            delegated_by: None,
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

/// The admin-only scopes (`epigraph_core::canonical_scopes::ADMIN_ONLY_SCOPES`,
/// spelled here because this crate does not depend on `epigraph-core`; a test
/// in `epigraph-api` pins the two equal). THE CHECK CHOKEPOINT
/// ([`AuthContext::has_scope`]) treats them as ABSENT on a request that is
/// not elevated once the database's admin-scope switch is armed (elevation
/// plan EL-10, DESIGN 6.5).
pub const ADMIN_ONLY_SCOPES: &[&str] = &[
    "claims:admin",
    "clients:admin",
    "entity-types:write",
    "groups:admin",
    "instance:admin",
];

/// The ONLY scopes a DELEGATED run token (an access token carrying `dlg`) may
/// hold: claim, evidence and edge reads and writes, challenges, and agent
/// reads. Never group or agent management, webhooks, clients, or any
/// admin-only or elevated scope. The bearer layers refuse a delegated token
/// that carries anything else ([`outside_delegated_ceiling`]), and
/// [`AuthContext::has_scope`] never answers `true` outside it for a delegated
/// context, so no out-of-ceiling gate (a `claims:admin` arm included) runs for
/// one even where admission was skipped.
pub const DELEGATED_SCOPE_CEILING: &[&str] = &[
    "claims:read",
    "claims:write",
    "claims:challenge",
    "evidence:read",
    "evidence:submit",
    "edges:read",
    "edges:write",
    "agents:read",
];

/// The scopes of `scopes` outside [`DELEGATED_SCOPE_CEILING`], in order.
#[must_use]
pub fn outside_delegated_ceiling(scopes: &[String]) -> Vec<&str> {
    scopes
        .iter()
        .map(String::as_str)
        .filter(|s| !DELEGATED_SCOPE_CEILING.contains(s))
        .collect()
}

/// Whether `scope` is one of [`ADMIN_ONLY_SCOPES`].
#[must_use]
pub fn is_admin_only_scope(scope: &str) -> bool {
    ADMIN_ONLY_SCOPES.contains(&scope)
}

/// Whether the admin-only scopes are STANDING authority on a request: what the
/// database's admin-scope switch (migration 128) said when the request's auth
/// layer read it (through a short cache).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminScopePosture {
    /// The switch is unarmed (or absent): an admin-only scope a token carries
    /// is authority, as before the switch.
    Unarmed,
    /// The switch is armed, or could not be read (fail closed): an admin-only
    /// scope is authority only on an ELEVATED request.
    Armed,
}

/// A live elevation the request's auth layer CHECKED against the database (the
/// session is live for this principal on this family). Never built from a
/// token claim alone: [`AuthContext::elevation_claim`] is the claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElevationRef {
    /// The live elevation session (`elevation_sessions.id`).
    pub session_id: Uuid,
    /// Its refresh family.
    pub family_id: Uuid,
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
            dlg: binding.delegated_by,
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

    /// Verify a token for RFC 7009 revocation ONLY: signature, issuer and
    /// audience, but NOT expiry. Never use this to admit a request; admission
    /// is [`JwtConfig::validate_token`].
    ///
    /// Expiry is left to the revocation store, which applies one clock-skew
    /// margin on one clock (migration 141's definer: 24 hours on the database
    /// clock). Checking `exp` here, on the revoking host's own clock, would
    /// let a host running ahead answer a revocation 200 and record nothing
    /// while a host lagging it still admits the token.
    pub fn verify_for_revocation(
        &self,
        token: &str,
    ) -> Result<EpiGraphClaims, jsonwebtoken::errors::Error> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["epigraph"]);
        validation.set_audience(&["epigraph-api"]);
        // `exp` must still be present (`required_spec_claims`); only its
        // comparison with this host's clock is skipped.
        validation.validate_exp = false;
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
    /// bound to this principal and family ([`Self::elevation`]).
    pub elevation_claim: Option<Uuid>,
    /// The live elevation this request carries, set ONLY by the auth layer
    /// after the database said the session is live (the API's recorder layer,
    /// the MCP server's dispatch). `None` on every other request.
    pub elevation: Option<ElevationRef>,
    /// The token's `dlg` claim, AS CLAIMED: the delegator agent of a
    /// delegated run token. Not authority: a site admits such a token only
    /// after the database says the delegation is live
    /// (`epigraph_db::AgentRepository::delegated_principal_pool`), on every
    /// request.
    pub delegated_by: Option<Uuid>,
    /// The admin-scope switch as the auth layer read it for this request.
    /// [`From<EpiGraphClaims>`] sets [`AdminScopePosture::Armed`] (fail
    /// closed): an auth layer that forgets to read the switch loses admin
    /// authority rather than keeping it.
    pub admin_scopes: AdminScopePosture,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClientType {
    Agent,
    Human,
    Service,
}

impl AuthContext {
    /// Whether the token carries a scope whose meaning the admin-scope switch
    /// decides (an [`ADMIN_ONLY_SCOPES`] entry or [`ELEVATED_ONLY_SCOPE`]).
    /// Only then does an auth layer need to read the switch: for any other
    /// token [`Self::admin_scopes`] changes no answer of [`Self::has_scope`],
    /// and it stays at the fail-closed default.
    #[must_use]
    pub fn carries_switch_decided_scope(&self) -> bool {
        self.scopes
            .iter()
            .any(|s| is_admin_only_scope(s) || s == ELEVATED_ONLY_SCOPE)
    }

    /// THE CHECK CHOKEPOINT (elevation plan EL-10): whether this request holds
    /// `scope`. Every scope check (`check_scopes`, the API's `RequireScope*`
    /// extractors, the MCP server's `SCOPE_MAP` gate) goes through here; a
    /// direct read of [`Self::scopes`] outside this crate is forbidden by the
    /// API's `admin_scope_literals` ratchet.
    ///
    /// * [`ELEVATED_ONLY_SCOPE`] (`platform:admin`) counts only on an ELEVATED
    ///   request ([`Self::elevation`]): a token whose session ended holds it
    ///   for nothing.
    /// * An [`ADMIN_ONLY_SCOPES`] entry, on an ELEVATED request: held when the
    ///   token carries `platform:admin` (the elevate grant's), so elevation
    ///   stands in for the standing admin scopes it strips, whatever the
    ///   switch says. A WRITE-named entry (`entity-types:write`) is never
    ///   implied: elevation is sudo READ.
    /// * An [`ADMIN_ONLY_SCOPES`] entry, on a request that is NOT elevated:
    ///   held as the token says while [`Self::admin_scopes`] is
    ///   [`AdminScopePosture::Unarmed`], ABSENT while it is
    ///   [`AdminScopePosture::Armed`].
    /// * Every other scope: as the token says.
    ///
    /// Before all of these: a DELEGATED context ([`Self::delegated_by`]) holds
    /// nothing outside [`DELEGATED_SCOPE_CEILING`], whatever its token carries.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        if self.delegated_by.is_some() && !DELEGATED_SCOPE_CEILING.contains(&scope) {
            return false;
        }
        let carried = self.scopes.iter().any(|s| s == scope);
        let elevated = self.elevation.is_some();
        if scope == ELEVATED_ONLY_SCOPE {
            return carried && elevated;
        }
        if !is_admin_only_scope(scope) {
            return carried;
        }
        if elevated {
            return carried
                || (!scope.ends_with(":write")
                    && self.scopes.iter().any(|s| s == ELEVATED_ONLY_SCOPE));
        }
        carried && self.admin_scopes == AdminScopePosture::Unarmed
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
            elevation: None,
            delegated_by: claims.dlg,
            admin_scopes: AdminScopePosture::Armed,
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
            delegated_by: None,
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

    fn ctx(scopes: &[&str], posture: AdminScopePosture, elevated: bool) -> AuthContext {
        AuthContext {
            client_id: Uuid::new_v4(),
            agent_id: Some(Uuid::new_v4()),
            owner_id: None,
            client_type: ClientType::Human,
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            jti: Uuid::new_v4(),
            family_id: None,
            elevation_claim: None,
            elevation: elevated.then(|| ElevationRef {
                session_id: Uuid::new_v4(),
                family_id: Uuid::new_v4(),
            }),
            admin_scopes: posture,
            delegated_by: None,
        }
    }

    /// THE CHECK CHOKEPOINT (elevation plan EL-10). Unarmed and unelevated:
    /// every scope as the token says (today's behaviour). Armed and
    /// unelevated: every admin-only scope ABSENT, every other scope as the
    /// token says. Elevated (with `platform:admin`, the elevate grant's
    /// token): the admin-only READ scopes held whatever the switch says, a
    /// write-named one (`entity-types:write`) never implied, and
    /// `platform:admin` itself held only while elevated. A context built from
    /// claims is ARMED until an auth layer reads the switch (fail closed).
    #[test]
    fn the_check_chokepoint_follows_the_switch_and_the_elevation() {
        let standing = [
            "claims:read",
            "claims:admin",
            "clients:admin",
            "entity-types:write",
            "groups:admin",
            "instance:admin",
        ];
        let unarmed = ctx(&standing, AdminScopePosture::Unarmed, false);
        for s in standing {
            assert!(unarmed.has_scope(s), "unarmed holds {s}");
        }
        let armed = ctx(&standing, AdminScopePosture::Armed, false);
        assert!(
            armed.has_scope("claims:read"),
            "armed keeps ordinary scopes"
        );
        for s in ADMIN_ONLY_SCOPES {
            assert!(!armed.has_scope(s), "armed, unelevated: {s} is absent");
        }
        assert!(check_scopes(&armed, &["claims:admin"]).is_err());
        assert!(check_scopes(&unarmed, &["claims:admin"]).is_ok());

        let elevated_token = ["claims:read", ELEVATED_ONLY_SCOPE];
        for posture in [AdminScopePosture::Unarmed, AdminScopePosture::Armed] {
            let elevated = ctx(&elevated_token, posture, true);
            for s in [
                "claims:admin",
                "clients:admin",
                "groups:admin",
                "instance:admin",
            ] {
                assert!(elevated.has_scope(s), "{posture:?} elevated holds {s}");
            }
            assert!(
                !elevated.has_scope("entity-types:write"),
                "elevation implies no write-named admin scope"
            );
            assert!(elevated.has_scope(ELEVATED_ONLY_SCOPE));
            let ended = ctx(&elevated_token, posture, false);
            assert!(
                !ended.has_scope(ELEVATED_ONLY_SCOPE),
                "{posture:?}: platform:admin counts only while elevated"
            );
            assert!(
                !ended.has_scope("claims:admin"),
                "{posture:?}: an ended elevation implies nothing"
            );
            let no_platform = ctx(&["claims:read"], posture, true);
            assert!(
                !no_platform.has_scope("claims:admin"),
                "elevation implies the admin scopes only with platform:admin"
            );
        }

        let cfg = JwtConfig::from_secret(b"test-secret-at-least-32-bytes!!");
        let (token, _) = cfg
            .issue_access_token(
                Uuid::new_v4(),
                vec!["claims:admin".into()],
                "service",
                None,
                None,
                Duration::minutes(5),
                AccessTokenBinding::NONE,
            )
            .unwrap();
        let from_claims: AuthContext = cfg.validate_token(&token).unwrap().into();
        assert!(from_claims.carries_switch_decided_scope());
        assert!(!ctx(
            &["claims:read", "claims:write"],
            AdminScopePosture::Armed,
            false
        )
        .carries_switch_decided_scope());
        assert!(ctx(&[ELEVATED_ONLY_SCOPE], AdminScopePosture::Armed, false)
            .carries_switch_decided_scope());
        assert_eq!(from_claims.admin_scopes, AdminScopePosture::Armed);
        assert_eq!(from_claims.elevation, None);
        assert!(
            !from_claims.has_scope("claims:admin"),
            "a context no auth layer stamped holds no admin scope"
        );
    }

    fn mint(cfg: &JwtConfig, ttl: Duration) -> (String, Uuid) {
        cfg.issue_access_token(
            Uuid::new_v4(),
            vec![],
            "agent",
            None,
            None,
            ttl,
            AccessTokenBinding::NONE,
        )
        .unwrap()
    }

    #[test]
    fn revocation_accepts_a_genuine_token_past_its_expiry() {
        let cfg = JwtConfig::from_secret(b"test-secret-at-least-32-bytes!!");
        let (token, jti) = mint(&cfg, Duration::hours(-2));
        assert!(
            cfg.validate_token(&token).is_err(),
            "precondition: admission refuses it"
        );
        let claims = cfg
            .verify_for_revocation(&token)
            .expect("a genuine token past exp is still verifiable for revocation");
        assert_eq!(claims.jti, jti);
    }

    #[test]
    fn revocation_still_verifies_signature_issuer_and_audience() {
        let cfg = JwtConfig::from_secret(b"secret-one-at-least-32-bytes!!!");
        let forger = JwtConfig::from_secret(b"secret-two-at-least-32-bytes!!!");
        // CONTROL: the genuine, expired token passes, so each refusal below is
        // the altered field's, not expiry's.
        let (genuine, _) = mint(&cfg, Duration::hours(-2));
        assert!(cfg.verify_for_revocation(&genuine).is_ok());

        let (forged, _) = mint(&forger, Duration::hours(-2));
        assert!(
            cfg.verify_for_revocation(&forged).is_err(),
            "another secret's token is refused"
        );

        let base = cfg.verify_for_revocation(&genuine).unwrap();
        for (iss, aud) in [
            ("not-epigraph", "epigraph-api"),
            ("epigraph", "not-epigraph-api"),
        ] {
            let altered = EpiGraphClaims {
                iss: iss.to_string(),
                aud: aud.to_string(),
                ..base.clone()
            };
            let token =
                encode(&Header::new(Algorithm::HS256), &altered, &cfg.encoding_key).unwrap();
            assert!(
                cfg.verify_for_revocation(&token).is_err(),
                "iss {iss:?} / aud {aud:?} is refused"
            );
        }
    }

    /// The `dlg` claim is N-1 safe in both directions. A binary that predates
    /// it (modelled by the claim set it decoded, which has no `dlg` and no
    /// `deny_unknown_fields`) decodes a delegated token as an ordinary token
    /// for the same agent, so it refuses that agent if it is operated (fail
    /// closed). A token minted without a delegator carries no `dlg` key at
    /// all, so this binary's tokens are byte-compatible with the old shape.
    /// Mutations caught: `dlg` serialised when `None` (the key appears),
    /// `dlg` not mapped into `AuthContext::delegated_by`, and
    /// `deny_unknown_fields` on the old shape.
    #[test]
    fn a_token_without_dlg_decodes_and_a_dlg_token_decodes_in_the_n_minus_1_struct() {
        #[derive(Deserialize)]
        #[allow(
            dead_code,
            reason = "decoded only to prove the old shape accepts the token"
        )]
        struct PreDelegationClaims {
            sub: Uuid,
            iss: String,
            aud: String,
            exp: i64,
            iat: i64,
            nbf: i64,
            jti: Uuid,
            scopes: Vec<String>,
            client_type: String,
            owner_id: Option<Uuid>,
            agent_id: Option<Uuid>,
            #[serde(default)]
            fam: Option<Uuid>,
            #[serde(default)]
            elv: Option<Uuid>,
        }
        let cfg = JwtConfig::from_secret(b"test-secret-at-least-32-bytes!!");
        let agent = Uuid::new_v4();
        let delegator = Uuid::new_v4();
        let mint = |delegated_by: Option<Uuid>| {
            cfg.issue_access_token(
                Uuid::new_v4(),
                vec!["claims:read".to_string()],
                "agent",
                None,
                Some(agent),
                Duration::minutes(5),
                AccessTokenBinding {
                    delegated_by,
                    ..AccessTokenBinding::NONE
                },
            )
            .unwrap()
            .0
        };
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["epigraph"]);
        validation.set_audience(&["epigraph-api"]);
        let keys = |token: &str| -> std::collections::HashMap<String, serde::de::IgnoredAny> {
            decode(token, &cfg.decoding_key, &validation)
                .expect("payload keys")
                .claims
        };

        let plain = mint(None);
        assert!(
            !keys(&plain).contains_key("dlg"),
            "a token with no delegator must not carry the key"
        );
        let ctx: AuthContext = cfg.validate_token(&plain).unwrap().into();
        assert_eq!(ctx.delegated_by, None);

        let delegated = mint(Some(delegator));
        assert!(keys(&delegated).contains_key("dlg"));
        assert_eq!(cfg.validate_token(&delegated).unwrap().dlg, Some(delegator));
        let ctx: AuthContext = cfg.validate_token(&delegated).unwrap().into();
        assert_eq!(ctx.delegated_by, Some(delegator));
        assert_eq!(ctx.agent_id, Some(agent));

        let old = decode::<PreDelegationClaims>(&delegated, &cfg.decoding_key, &validation)
            .expect("a binary that predates `dlg` must still decode a delegated token");
        assert_eq!(
            old.claims.agent_id,
            Some(agent),
            "the old shape reads the token as one for the same agent, which it refuses if \
             that agent is operated"
        );
    }

    /// A DELEGATED context (one carrying `dlg`) holds no scope outside the
    /// delegated ceiling, whatever its token carries and whatever the
    /// admin-scope switch says, so no `claims:admin` arm (or any other
    /// out-of-ceiling gate) can run for it even where the bearer layer's
    /// admission refusal was skipped. Calibration: the same context without
    /// `dlg`, switch unarmed, holds every scope it carries.
    #[test]
    fn a_delegated_context_holds_no_scope_outside_the_ceiling() {
        let carried = [
            "claims:read",
            "claims:write",
            "claims:admin",
            "webhooks:write",
            "groups:write",
            "groups:admin",
            "agents:write",
            "clients:admin",
        ];
        let ctx = |delegated_by: Option<Uuid>| AuthContext {
            client_id: Uuid::new_v4(),
            agent_id: Some(Uuid::new_v4()),
            owner_id: None,
            client_type: ClientType::Agent,
            scopes: carried.iter().map(|s| (*s).to_string()).collect(),
            jti: Uuid::new_v4(),
            family_id: None,
            elevation_claim: None,
            elevation: None,
            admin_scopes: AdminScopePosture::Unarmed,
            delegated_by,
        };
        let plain = ctx(None);
        for scope in carried {
            assert!(plain.has_scope(scope), "CALIBRATION: {scope}");
        }
        let delegated = ctx(Some(Uuid::new_v4()));
        assert!(delegated.has_scope("claims:read"));
        assert!(delegated.has_scope("claims:write"));
        for scope in [
            "claims:admin",
            "webhooks:write",
            "groups:write",
            "groups:admin",
            "agents:write",
            "clients:admin",
        ] {
            assert!(
                !delegated.has_scope(scope),
                "a delegated context must not hold {scope}"
            );
        }
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
            elevation: None,
            admin_scopes: AdminScopePosture::Unarmed,
            delegated_by: None,
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
