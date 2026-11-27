//! Shared OAuth2-style auth primitives for the EpiGraph workspace.
//!
//! Both `epigraph-api` (HTTP) and `epigraph-mcp` (MCP HTTP transport) validate
//! tokens against the same `JwtConfig`, so audience and algorithm must move in
//! lockstep.
//!
//! ## Audience
//!
//! Kernel tokens use audience [`KERNEL_AUDIENCE`] (`"epigraph-api"`)
//! regardless of which kernel server validates them. MCP intentionally
//! accepts API-minted tokens — there is no separate `epigraph-mcp` audience.
//! Adding one would double minting work for clients that talk to both
//! servers, and the threat model does not distinguish them.
//!
//! Every token the kernel has ever minted carries `aud` (the field is a
//! required `String` on [`EpiGraphClaims`] and has been since the first
//! public release), so [`JwtConfig::validate_token`] has no "missing `aud`"
//! case to tolerate: a token without one fails to decode.
//!
//! The one other audience is a mounted federation EXTENSION's, minted only by
//! the RFC 8693 token-exchange grant ([`JwtConfig::exchange_token`]): a
//! short-lived token the gateway forwards downstream instead of the caller's
//! kernel bearer. [`JwtConfig::validate_token`] refuses it (its `aud` is not
//! the kernel's), so a forwarded token replayed at the kernel acts as no one.
//! An extension validates its own with
//! [`JwtConfig::validate_token_for_audience`].
//!
//! ## Signing keys
//!
//! An extension must be able to VERIFY kernel tokens without being able to
//! MINT them. With one shared HMAC secret (HS256, [`JwtConfig::from_secret`])
//! that is impossible: whoever verifies can sign any kernel token. So the
//! kernel signs EdDSA with an Ed25519 key only it holds
//! ([`JWT_SIGNING_KEY_VAR`], [`JwtConfig::from_ed25519_seed`]), publishes the
//! public half as a JWK Set ([`JwtConfig::jwks`], served at
//! `/.well-known/jwks.json`), and an extension verifies with
//! [`JwtConfig::verifier_from_jwks`], which cannot mint. HS256 stays as the
//! unset-key default and, beside a signing key, as an accept-only migration
//! window ([`JwtConfig::with_hs256_accept`]) the operator closes by removing
//! the shared secret everywhere.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{Duration, Utc};
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm,
    OctetKeyPairParameters, OctetKeyPairType, PublicKeyUse, ThumbprintHash,
};
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod claim_act;
pub mod relationships;

/// The committed development JWT secret. NEVER acceptable in production.
/// Single source of truth — every consumer must reference this const, not a
/// copy of the literal.
pub const DEV_JWT_SECRET: &[u8] = b"epigraph-dev-secret-change-in-production!!";

/// The environment variable holding the kernel's Ed25519 JWT signing key
/// (64 hex characters, the 32-byte seed). Set, the kernel signs every token
/// EdDSA and `EPIGRAPH_JWT_SECRET` becomes only the HS256 accept window.
pub const JWT_SIGNING_KEY_VAR: &str = "EPIGRAPH_JWT_SIGNING_KEY";

/// Minimum acceptable HMAC secret length, in bytes.
pub const MIN_SECRET_LEN: usize = 32;

/// The audience of every token the kernel admits on its own routes (the HTTP
/// API and the MCP server alike). See the crate doc.
pub const KERNEL_AUDIENCE: &str = "epigraph-api";

/// The issuer of every kernel-minted token.
pub const KERNEL_ISSUER: &str = "epigraph";

/// RFC 8693 section 2.1 `grant_type` of the token-exchange grant.
pub const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// RFC 8693 section 3 token type identifier for an OAuth access token: the
/// only `subject_token_type` the exchange accepts, the only
/// `requested_token_type` it issues, and its `issued_token_type`.
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// The longest an exchanged (extension-audience) token lives: 5 minutes, and
/// never past its subject token's own `exp`. The gateway exchanges once per
/// federated call, so the bound is revocation latency, not a usability limit.
pub const EXCHANGED_TOKEN_MAX_SECS: i64 = 300;

/// Why [`JwtConfig::exchange_token`] refused. Each maps to one RFC 6749
/// section 5.2 / RFC 8693 section 2.2.2 `error` code ([`Self::oauth_error`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExchangeRefusal {
    /// The requested `audience` is the kernel's own, or not a configured
    /// extension (`invalid_target`).
    InvalidTarget(String),
    /// The subject token does not validate as a kernel token, or is one this
    /// grant never exchanges (delegated or elevated) (`invalid_grant`).
    InvalidGrant(String),
    /// A requested scope the subject token does not carry (`invalid_scope`).
    InvalidScope(String),
    /// A malformed request (`invalid_request`).
    InvalidRequest(String),
}

impl ExchangeRefusal {
    /// The RFC `error` code.
    #[must_use]
    pub fn oauth_error(&self) -> &'static str {
        match self {
            Self::InvalidTarget(_) => "invalid_target",
            Self::InvalidGrant(_) => "invalid_grant",
            Self::InvalidScope(_) => "invalid_scope",
            Self::InvalidRequest(_) => "invalid_request",
        }
    }

    /// The human-readable `error_description`.
    #[must_use]
    pub fn description(&self) -> &str {
        match self {
            Self::InvalidTarget(d)
            | Self::InvalidGrant(d)
            | Self::InvalidScope(d)
            | Self::InvalidRequest(d) => d,
        }
    }
}

/// A token minted by [`JwtConfig::exchange_token`].
#[derive(Debug, Clone)]
pub struct ExchangedToken {
    /// The signed extension-audience token.
    pub token: String,
    /// Its claims (`aud` = the extension).
    pub claims: EpiGraphClaims,
    /// The subject token's validated claims: the caller checks liveness on
    /// them (revocation of its `jti`, its client's status) before answering.
    pub subject: EpiGraphClaims,
}

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

/// RFC 8410 PKCS#8 v1 prefix of an Ed25519 private key: `OneAsymmetricKey`
/// with algorithm `id-Ed25519` (1.3.101.112) wrapping a 32-byte
/// `CurvePrivateKey`. The 32-byte seed follows. `EncodingKey::from_ed_der`
/// takes exactly this encoding.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// Parse the kernel's Ed25519 JWT signing key: 64 hex characters (the 32-byte
/// seed), the same format as the kernel's other Ed25519 keys. The error never
/// echoes the value.
pub fn parse_ed25519_seed(hex_seed: &str) -> Result<[u8; 32], String> {
    let bytes =
        hex::decode(hex_seed.trim()).map_err(|_| format!("{JWT_SIGNING_KEY_VAR} is not hex"))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        format!(
            "{JWT_SIGNING_KEY_VAR} is {} bytes; an Ed25519 seed is 32 (64 hex characters)",
            bytes.len()
        )
    })
}

/// The kernel's boot check for its JWT keys. Pure, so every arm is testable
/// without a process.
///
/// * A set [`JWT_SIGNING_KEY_VAR`] must parse ([`parse_ed25519_seed`]),
///   whatever `allow_insecure` says: a typo must refuse boot, never fall back
///   to signing with the shared secret.
/// * A set `EPIGRAPH_JWT_SECRET` must pass [`assert_production_secret`]
///   (unless `allow_insecure`), whether it signs (no signing key) or is only
///   the HS256 accept window (signing key set).
/// * Neither set: refused unless `allow_insecure` (the dev fallback).
pub fn check_kernel_jwt_keys(
    signing_key: Option<&str>,
    secret: Option<&str>,
    allow_insecure: bool,
) -> Result<(), String> {
    let signing_key = signing_key.map(str::trim).filter(|s| !s.is_empty());
    let secret = secret.filter(|s| !s.is_empty());
    if let Some(key) = signing_key {
        parse_ed25519_seed(key)?;
    }
    if allow_insecure {
        return Ok(());
    }
    match (signing_key, secret) {
        (_, Some(secret)) => assert_production_secret(secret.as_bytes()),
        (Some(_), None) => Ok(()),
        (None, None) => assert_production_secret(b""),
    }
}

/// How a [`JwtConfig`] signs, if it signs at all.
enum Signer {
    /// The legacy shared HMAC secret. Anyone who can VERIFY can also sign,
    /// which is why an extension must never be handed this config.
    Hs256(EncodingKey),
    /// The kernel's Ed25519 key. Every token carries `kid`.
    EdDsa { key: EncodingKey, kid: String },
    /// A verify-only config ([`JwtConfig::verifier_from_jwks`]): every mint
    /// refuses.
    None,
}

/// One Ed25519 public key a [`JwtConfig`] verifies with.
struct EdVerifyingKey {
    /// RFC 7638 thumbprint of the key's JWK: the `kid` its tokens carry.
    kid: String,
    /// base64url of the 32-byte public key (the JWK `x`).
    x: String,
    key: DecodingKey,
}

impl EdVerifyingKey {
    fn from_public(public: &[u8; 32]) -> Self {
        let x = URL_SAFE_NO_PAD.encode(public);
        let kid = Self::jwk_for(&x, None).thumbprint(ThumbprintHash::SHA256);
        Self {
            kid,
            x,
            key: DecodingKey::from_ed_der(public),
        }
    }

    fn jwk_for(x: &str, kid: Option<&str>) -> Jwk {
        Jwk {
            common: CommonParameters {
                public_key_use: Some(PublicKeyUse::Signature),
                key_algorithm: Some(KeyAlgorithm::EdDSA),
                key_id: kid.map(str::to_string),
                ..CommonParameters::default()
            },
            algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                key_type: OctetKeyPairType::OctetKeyPair,
                curve: EllipticCurve::Ed25519,
                x: x.to_string(),
            }),
        }
    }

    fn jwk(&self) -> Jwk {
        Self::jwk_for(&self.x, Some(&self.kid))
    }
}

/// The kernel's token keys.
///
/// * [`Self::from_secret`]: HS256 with one shared secret, signing and
///   verifying (the legacy and dev configuration, unchanged).
/// * [`Self::from_ed25519_seed`]: the kernel signs EdDSA with its private key
///   and publishes the public half ([`Self::jwks`], served at
///   `/.well-known/jwks.json`). [`Self::with_hs256_accept`] keeps accepting
///   HS256 tokens from the shared secret during a migration window; it never
///   signs with it.
/// * [`Self::verifier_from_jwks`]: a resource server that is NOT the kernel
///   (a federation extension) verifies by public key and cannot mint any
///   token, kernel or extension audience.
///
/// Every verification goes through one dispatcher that pins the algorithm to
/// the key that verifies it: an EdDSA token needs a `kid` this config holds,
/// an HS256 token needs the accept window, and nothing else verifies. So an
/// HS256 token MACed with a public key's bytes (algorithm confusion) is
/// refused like any other HS256 token outside the window.
pub struct JwtConfig {
    signer: Signer,
    hs256: Option<DecodingKey>,
    ed25519: Vec<EdVerifyingKey>,
}

impl JwtConfig {
    /// HS256 with one shared secret, signing and verifying.
    pub fn from_secret(secret: &[u8]) -> Self {
        Self {
            signer: Signer::Hs256(EncodingKey::from_secret(secret)),
            hs256: Some(DecodingKey::from_secret(secret)),
            ed25519: Vec::new(),
        }
    }

    /// The kernel signing EdDSA with the Ed25519 key whose 32-byte seed this
    /// is, and verifying only its own tokens (add the legacy window with
    /// [`Self::with_hs256_accept`]).
    pub fn from_ed25519_seed(seed: &[u8; 32]) -> Self {
        let public = ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes();
        let verifying = EdVerifyingKey::from_public(&public);
        let mut pkcs8 = Vec::with_capacity(48);
        pkcs8.extend_from_slice(&ED25519_PKCS8_PREFIX);
        pkcs8.extend_from_slice(seed);
        Self {
            signer: Signer::EdDsa {
                key: EncodingKey::from_ed_der(&pkcs8),
                kid: verifying.kid.clone(),
            },
            hs256: None,
            ed25519: vec![verifying],
        }
    }

    /// A verify-only config from a JWK Set (the kernel's
    /// `/.well-known/jwks.json`). Every key must be an Ed25519 (`OKP`) key;
    /// any other key, or an empty set, is refused rather than skipped. The
    /// `kid` is recomputed from the key, so a published `kid` that does not
    /// match its key is refused too. [`Self::issue_access_token`] and
    /// [`Self::exchange_token`] refuse on this config.
    ///
    /// # Errors
    /// A description of the first key or document problem.
    pub fn verifier_from_jwks(jwks: &str) -> Result<Self, String> {
        let set: JwkSet =
            serde_json::from_str(jwks).map_err(|e| format!("JWKS is not a JWK Set: {e}"))?;
        if set.keys.is_empty() {
            return Err("JWKS holds no keys".to_string());
        }
        let mut ed25519 = Vec::with_capacity(set.keys.len());
        for jwk in &set.keys {
            let AlgorithmParameters::OctetKeyPair(params) = &jwk.algorithm else {
                return Err("JWKS holds a key that is not an Ed25519 (OKP) key".to_string());
            };
            if params.curve != EllipticCurve::Ed25519 {
                return Err("JWKS holds an OKP key whose curve is not Ed25519".to_string());
            }
            if !matches!(jwk.common.key_algorithm, None | Some(KeyAlgorithm::EdDSA)) {
                return Err("JWKS holds an Ed25519 key whose alg is not EdDSA".to_string());
            }
            let public = URL_SAFE_NO_PAD
                .decode(&params.x)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .ok_or_else(|| "JWKS holds an Ed25519 key whose x is not 32 bytes".to_string())?;
            ed25519_dalek::VerifyingKey::from_bytes(&public)
                .map_err(|_| "JWKS holds an invalid Ed25519 public key".to_string())?;
            let key = EdVerifyingKey::from_public(&public);
            if let Some(kid) = jwk.common.key_id.as_deref() {
                if kid != key.kid {
                    return Err(format!(
                        "JWKS key `{kid}` is not its key's RFC 7638 thumbprint"
                    ));
                }
            }
            if !ed25519.iter().any(|k: &EdVerifyingKey| k.kid == key.kid) {
                ed25519.push(key);
            }
        }
        Ok(Self {
            signer: Signer::None,
            hs256: None,
            ed25519,
        })
    }

    /// Also ACCEPT HS256 tokens MACed with `secret`: the migration window
    /// while tokens minted before the switch to EdDSA are still live. Never
    /// signs with it. Close the window by dropping the secret, because while
    /// it is open anyone holding the secret can still mint a token this
    /// config admits.
    #[must_use]
    pub fn with_hs256_accept(mut self, secret: &[u8]) -> Self {
        self.hs256 = Some(DecodingKey::from_secret(secret));
        self
    }

    /// The kernel's config from its environment values: with a signing key,
    /// EdDSA (and the HS256 accept window only if `secret` is set); without
    /// one, HS256 from `secret`, or [`DEV_JWT_SECRET`] when that is unset too
    /// (the dev fallback; production refuses it at boot,
    /// [`check_kernel_jwt_keys`]). The dev literal is NEVER the accept window
    /// of a config that signs EdDSA.
    ///
    /// # Errors
    /// The signing key does not parse ([`parse_ed25519_seed`]).
    pub fn from_kernel_env(
        signing_key: Option<&str>,
        secret: Option<&str>,
    ) -> Result<Self, String> {
        let secret = secret.filter(|s| !s.is_empty());
        match signing_key.map(str::trim).filter(|s| !s.is_empty()) {
            Some(key) => {
                let cfg = Self::from_ed25519_seed(&parse_ed25519_seed(key)?);
                Ok(match secret {
                    Some(secret) => cfg.with_hs256_accept(secret.as_bytes()),
                    None => cfg,
                })
            }
            None => Ok(Self::from_secret(
                secret.map_or(DEV_JWT_SECRET, str::as_bytes),
            )),
        }
    }

    /// The algorithm this config mints with, `None` for a verify-only one.
    #[must_use]
    pub fn signing_algorithm(&self) -> Option<Algorithm> {
        match self.signer {
            Signer::Hs256(_) => Some(Algorithm::HS256),
            Signer::EdDsa { .. } => Some(Algorithm::EdDSA),
            Signer::None => None,
        }
    }

    /// Whether this config admits HS256 tokens (the shared-secret window).
    #[must_use]
    pub fn accepts_hs256(&self) -> bool {
        self.hs256.is_some()
    }

    /// The public keys this config verifies EdDSA tokens with, as the JWK Set
    /// `/.well-known/jwks.json` serves. Empty for an HS256-only config: a
    /// shared secret is never published.
    #[must_use]
    pub fn jwks(&self) -> JwkSet {
        JwkSet {
            keys: self.ed25519.iter().map(EdVerifyingKey::jwk).collect(),
        }
    }

    /// THE SIGNING CHOKEPOINT: every token this config mints.
    fn sign(&self, claims: &EpiGraphClaims) -> Result<String, jsonwebtoken::errors::Error> {
        match &self.signer {
            Signer::Hs256(key) => encode(&Header::new(Algorithm::HS256), claims, key),
            Signer::EdDsa { key, kid } => {
                let mut header = Header::new(Algorithm::EdDSA);
                header.kid = Some(kid.clone());
                encode(&header, claims, key)
            }
            Signer::None => Err(jsonwebtoken::errors::ErrorKind::InvalidKeyFormat.into()),
        }
    }

    /// THE VERIFICATION CHOKEPOINT: issuer, `aud` = `audience`, signature by a
    /// key this config holds for the token's algorithm, and `exp` with no
    /// leeway unless `check_exp` is false (revocation only).
    fn verify(
        &self,
        token: &str,
        audience: &str,
        check_exp: bool,
    ) -> Result<EpiGraphClaims, jsonwebtoken::errors::Error> {
        use jsonwebtoken::errors::ErrorKind;
        let header = decode_header(token)?;
        let key = match header.alg {
            Algorithm::EdDSA => {
                let kid = header.kid.as_deref().ok_or(ErrorKind::InvalidSignature)?;
                &self
                    .ed25519
                    .iter()
                    .find(|k| k.kid == kid)
                    .ok_or(ErrorKind::InvalidSignature)?
                    .key
            }
            Algorithm::HS256 => self.hs256.as_ref().ok_or(ErrorKind::InvalidAlgorithm)?,
            _ => return Err(ErrorKind::InvalidAlgorithm.into()),
        };
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[KERNEL_ISSUER]);
        validation.set_audience(&[audience]);
        if check_exp {
            validation.leeway = 0;
        } else {
            // `exp` must still be present (`required_spec_claims`); only its
            // comparison with this host's clock is skipped.
            validation.validate_exp = false;
        }
        let data = decode::<EpiGraphClaims>(token, key, &validation)?;
        Ok(data.claims)
    }

    /// Mint a kernel-audience access token.
    ///
    /// # Errors
    /// Signing fails; a verify-only config ([`Self::verifier_from_jwks`])
    /// always refuses (`InvalidKeyFormat`).
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
            iss: KERNEL_ISSUER.to_string(),
            aud: KERNEL_AUDIENCE.to_string(),
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
        let token = self.sign(&claims)?;
        Ok((token, jti))
    }

    /// Admit a token on a KERNEL route: signature, issuer, `exp` (no leeway)
    /// and `aud` = [`KERNEL_AUDIENCE`]. An extension-audience token minted by
    /// [`Self::exchange_token`] is refused here (`InvalidAudience`).
    pub fn validate_token(
        &self,
        token: &str,
    ) -> Result<EpiGraphClaims, jsonwebtoken::errors::Error> {
        self.validate_token_for_audience(token, KERNEL_AUDIENCE)
    }

    /// [`Self::validate_token`] for another resource server: `aud` must equal
    /// `audience` exactly (an array audience fails to decode). For a mounted
    /// federation extension validating the exchanged token the gateway
    /// forwards; the kernel's own routes use [`Self::validate_token`].
    pub fn validate_token_for_audience(
        &self,
        token: &str,
        audience: &str,
    ) -> Result<EpiGraphClaims, jsonwebtoken::errors::Error> {
        self.verify(token, audience, true)
    }

    /// RFC 8693 token exchange, the pure half: validate `subject_token` as a
    /// KERNEL token and mint a token for `audience` naming the same principal
    /// (`sub`, `agent_id`, `owner_id`, `client_type`), with scopes no wider
    /// than the subject's, living at most [`EXCHANGED_TOKEN_MAX_SECS`] and
    /// never past the subject's `exp`.
    ///
    /// Refused:
    /// * an `audience` that is [`KERNEL_AUDIENCE`] or not in
    ///   `allowed_audiences` (the configured extensions);
    /// * a subject token that does not validate on a kernel route, including
    ///   one that is itself an exchanged token (so an extension cannot turn
    ///   the token it was handed into one for another extension);
    /// * a DELEGATED (`dlg`) or ELEVATED (`elv`) subject: neither reaches a
    ///   federated tool, and the minted token carries neither claim, nor a
    ///   refresh family (`fam`);
    /// * a `requested_scopes` entry the subject does not carry. `None` or an
    ///   empty list means the subject's own scopes.
    ///
    /// The caller (the token endpoint) still checks liveness on
    /// [`ExchangedToken::subject`] (revoked `jti`, client status) before it
    /// answers; this function reads no state.
    ///
    /// # Errors
    /// [`ExchangeRefusal`] as listed; `InvalidRequest` if signing fails.
    pub fn exchange_token(
        &self,
        subject_token: &str,
        audience: &str,
        allowed_audiences: &[String],
        requested_scopes: Option<&[String]>,
    ) -> Result<ExchangedToken, ExchangeRefusal> {
        let audience = audience.trim();
        if audience.is_empty() {
            return Err(ExchangeRefusal::InvalidRequest(
                "audience is required".to_string(),
            ));
        }
        if audience == KERNEL_AUDIENCE || !allowed_audiences.iter().any(|a| a == audience) {
            return Err(ExchangeRefusal::InvalidTarget(format!(
                "audience `{audience}` is not a configured federation extension"
            )));
        }
        let subject = self.validate_token(subject_token).map_err(|_| {
            ExchangeRefusal::InvalidGrant(
                "subject_token is not a valid, unexpired kernel access token".to_string(),
            )
        })?;
        if subject.dlg.is_some() || subject.elv.is_some() {
            return Err(ExchangeRefusal::InvalidGrant(
                "a delegated or elevated token is not exchangeable".to_string(),
            ));
        }
        let scopes = match requested_scopes.filter(|r| !r.is_empty()) {
            None => subject.scopes.clone(),
            Some(requested) => {
                let mut out: Vec<String> = Vec::with_capacity(requested.len());
                for scope in requested {
                    if !subject.scopes.iter().any(|s| s == scope) {
                        return Err(ExchangeRefusal::InvalidScope(format!(
                            "scope `{scope}` is not carried by the subject token"
                        )));
                    }
                    if !out.contains(scope) {
                        out.push(scope.clone());
                    }
                }
                out
            }
        };
        // Belt and braces: the elevation scope never leaves an elevated token,
        // and an elevated subject was refused above.
        let scopes = without_elevated_only_scope(scopes);
        let now = Utc::now().timestamp();
        let exp = (now + EXCHANGED_TOKEN_MAX_SECS).min(subject.exp);
        let claims = EpiGraphClaims {
            sub: subject.sub,
            iss: KERNEL_ISSUER.to_string(),
            aud: audience.to_string(),
            exp,
            iat: now,
            nbf: now,
            jti: Uuid::new_v4(),
            scopes,
            client_type: subject.client_type.clone(),
            owner_id: subject.owner_id,
            agent_id: subject.agent_id,
            fam: None,
            elv: None,
            dlg: None,
        };
        let token = self
            .sign(&claims)
            .map_err(|e| ExchangeRefusal::InvalidRequest(format!("signing failed: {e}")))?;
        Ok(ExchangedToken {
            token,
            claims,
            subject,
        })
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
        self.verify(token, KERNEL_AUDIENCE, false)
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
            let token = cfg.sign(&altered).unwrap();
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
            decode(token, cfg.hs256.as_ref().unwrap(), &validation)
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

        let old =
            decode::<PreDelegationClaims>(&delegated, cfg.hs256.as_ref().unwrap(), &validation)
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

    // ── RFC 8693 token exchange (backlog c9b82fae) ─────────────────────────

    const EXT: &str = "episcience";

    fn allowed() -> Vec<String> {
        vec![EXT.to_string(), "other-ext".to_string()]
    }

    fn subject(
        cfg: &JwtConfig,
        scopes: &[&str],
        ttl: Duration,
        binding: AccessTokenBinding,
    ) -> String {
        cfg.issue_access_token(
            Uuid::new_v4(),
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "human",
            Some(Uuid::new_v4()),
            Some(Uuid::new_v4()),
            ttl,
            binding,
        )
        .unwrap()
        .0
    }

    /// The exchanged token names the SAME principal as its subject, carries
    /// the extension's audience and no `fam`/`elv`/`dlg`, lives at most five
    /// minutes, and is REFUSED by the kernel's own validator (and by another
    /// extension's), while the named extension admits it. Mutations caught:
    /// minting with the kernel audience (the kernel would admit it), copying
    /// the subject's `fam`, dropping the 5-minute cap.
    #[test]
    fn an_exchanged_token_is_for_the_extension_only_and_names_the_same_principal() {
        let cfg = JwtConfig::from_secret(b"test-secret-at-least-32-bytes!!");
        let fam = Uuid::new_v4();
        let raw = subject(
            &cfg,
            &["claims:read", "episcience:tools"],
            Duration::hours(1),
            AccessTokenBinding::family(fam),
        );
        let subj = cfg.validate_token(&raw).unwrap();
        let before = Utc::now().timestamp();
        let ex = cfg.exchange_token(&raw, EXT, &allowed(), None).unwrap();

        assert_ne!(ex.token, raw, "the exchange must mint a NEW token");
        let kernel = cfg.validate_token(&ex.token).unwrap_err();
        assert_eq!(
            *kernel.kind(),
            jsonwebtoken::errors::ErrorKind::InvalidAudience,
            "a kernel route must refuse an extension-audience token"
        );
        assert!(
            cfg.validate_token_for_audience(&ex.token, "other-ext")
                .is_err(),
            "another extension must refuse it too"
        );
        let got = cfg.validate_token_for_audience(&ex.token, EXT).unwrap();
        assert_eq!(got, ex.claims);
        assert_eq!(got.aud, EXT);
        assert_eq!(got.sub, subj.sub);
        assert_eq!(got.agent_id, subj.agent_id);
        assert_eq!(got.owner_id, subj.owner_id);
        assert_eq!(got.client_type, subj.client_type);
        assert_eq!(got.scopes, subj.scopes);
        assert_ne!(got.jti, subj.jti);
        assert_eq!((got.fam, got.elv, got.dlg), (None, None, None));
        assert!(got.exp <= before + EXCHANGED_TOKEN_MAX_SECS + 1);
        assert!(got.exp > before, "it must be usable now");
        assert_eq!(ex.subject, subj);
    }

    /// The exchanged token never outlives its subject: a subject with one
    /// minute left yields a token expiring with it, not five minutes later.
    #[test]
    fn an_exchanged_token_never_outlives_its_subject() {
        let cfg = JwtConfig::from_secret(b"test-secret-at-least-32-bytes!!");
        let raw = subject(
            &cfg,
            &["claims:read"],
            Duration::seconds(60),
            AccessTokenBinding::NONE,
        );
        let subj_exp = cfg.validate_token(&raw).unwrap().exp;
        let ex = cfg.exchange_token(&raw, EXT, &allowed(), None).unwrap();
        assert_eq!(ex.claims.exp, subj_exp);
    }

    /// Scopes: a request may NARROW (kept in request order, deduplicated) and
    /// may never WIDEN: one scope the subject lacks refuses the whole
    /// exchange with `invalid_scope`, even beside scopes it holds.
    #[test]
    fn an_exchange_narrows_scopes_and_refuses_a_wider_one() {
        let cfg = JwtConfig::from_secret(b"test-secret-at-least-32-bytes!!");
        let raw = subject(
            &cfg,
            &["claims:read", "claims:write", "episcience:tools"],
            Duration::hours(1),
            AccessTokenBinding::NONE,
        );
        let narrow = vec![
            "episcience:tools".to_string(),
            "claims:read".to_string(),
            "episcience:tools".to_string(),
        ];
        let ex = cfg
            .exchange_token(&raw, EXT, &allowed(), Some(&narrow))
            .unwrap();
        assert_eq!(ex.claims.scopes, vec!["episcience:tools", "claims:read"]);

        for wider in [
            vec!["claims:admin".to_string()],
            vec!["claims:read".to_string(), "groups:manage".to_string()],
            vec![ELEVATED_ONLY_SCOPE.to_string()],
        ] {
            let err = cfg
                .exchange_token(&raw, EXT, &allowed(), Some(&wider))
                .unwrap_err();
            assert_eq!(err.oauth_error(), "invalid_scope", "{wider:?}: {err:?}");
        }
    }

    /// Audience: only a CONFIGURED extension. The kernel's own audience, an
    /// unknown name, a blank one, and any name under an empty allowlist are
    /// refused, the first three before the subject is even looked at.
    #[test]
    fn an_exchange_refuses_an_audience_that_is_not_a_configured_extension() {
        let cfg = JwtConfig::from_secret(b"test-secret-at-least-32-bytes!!");
        let raw = subject(
            &cfg,
            &["claims:read"],
            Duration::hours(1),
            AccessTokenBinding::NONE,
        );
        for aud in [KERNEL_AUDIENCE, "evil-ext", "EPISCIENCE"] {
            let err = cfg.exchange_token(&raw, aud, &allowed(), None).unwrap_err();
            assert_eq!(err.oauth_error(), "invalid_target", "{aud}");
        }
        let mut with_kernel = allowed();
        with_kernel.push(KERNEL_AUDIENCE.to_string());
        assert_eq!(
            cfg.exchange_token(&raw, KERNEL_AUDIENCE, &with_kernel, None)
                .unwrap_err()
                .oauth_error(),
            "invalid_target",
            "the kernel audience is never a target, even if misconfigured into the list"
        );
        assert_eq!(
            cfg.exchange_token(&raw, EXT, &[], None)
                .unwrap_err()
                .oauth_error(),
            "invalid_target"
        );
        assert_eq!(
            cfg.exchange_token(&raw, "  ", &allowed(), None)
                .unwrap_err()
                .oauth_error(),
            "invalid_request"
        );
    }

    /// Subject: only a live KERNEL token that is neither delegated nor
    /// elevated. An exchanged token (so an extension cannot re-exchange what
    /// it was handed into another extension's), an expired one, another
    /// secret's, a delegated one and an elevated one are all `invalid_grant`.
    #[test]
    fn an_exchange_refuses_a_subject_that_is_not_a_plain_live_kernel_token() {
        let cfg = JwtConfig::from_secret(b"test-secret-at-least-32-bytes!!");
        let forger = JwtConfig::from_secret(b"another-secret-at-least-32-bytes");
        let good = subject(
            &cfg,
            &["claims:read"],
            Duration::hours(1),
            AccessTokenBinding::NONE,
        );
        let exchanged = cfg
            .exchange_token(&good, EXT, &allowed(), None)
            .unwrap()
            .token;
        let delegated = subject(
            &cfg,
            &["claims:read"],
            Duration::hours(1),
            AccessTokenBinding {
                delegated_by: Some(Uuid::new_v4()),
                ..AccessTokenBinding::NONE
            },
        );
        let elevated = subject(
            &cfg,
            &["claims:read"],
            Duration::hours(1),
            AccessTokenBinding {
                family_id: Some(Uuid::new_v4()),
                elevation_id: Some(Uuid::new_v4()),
                delegated_by: None,
            },
        );
        let cases = [
            ("exchanged", exchanged),
            (
                "expired",
                subject(
                    &cfg,
                    &["claims:read"],
                    Duration::seconds(-5),
                    AccessTokenBinding::NONE,
                ),
            ),
            (
                "forged",
                subject(
                    &forger,
                    &["claims:read"],
                    Duration::hours(1),
                    AccessTokenBinding::NONE,
                ),
            ),
            ("delegated", delegated),
            ("elevated", elevated),
            ("garbage", "not-a-jwt".to_string()),
        ];
        for (what, token) in cases {
            let err = cfg
                .exchange_token(&token, "other-ext", &allowed(), None)
                .unwrap_err();
            assert_eq!(err.oauth_error(), "invalid_grant", "{what}: {err:?}");
        }
        // CONTROL: the plain token is exchangeable for the same audience, so
        // each refusal above is the subject's, not the audience's.
        assert!(cfg
            .exchange_token(&good, "other-ext", &allowed(), None)
            .is_ok());
    }
}

/// Backlog 7b834860: an extension that verifies kernel tokens must not be able
/// to mint them. Each negative test names the mutation it catches.
#[cfg(test)]
mod asymmetric_signing_tests {
    use super::*;
    use jsonwebtoken::errors::ErrorKind;

    /// RFC 8037 appendix A.1: the Ed25519 private key `d`.
    const RFC8037_SEED_HEX: &str =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    /// The shared HMAC secret an extension held before this change.
    const SHARED: &[u8] = b"the-shared-hmac-secret-of-32-bytes!!";

    fn seed(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn mint(cfg: &JwtConfig, ttl: Duration) -> Result<String, jsonwebtoken::errors::Error> {
        cfg.issue_access_token(
            Uuid::new_v4(),
            vec!["claims:read".to_string(), "claims:write".to_string()],
            "agent",
            None,
            Some(Uuid::new_v4()),
            ttl,
            AccessTokenBinding::NONE,
        )
        .map(|(token, _)| token)
    }

    fn claims_now() -> EpiGraphClaims {
        let now = Utc::now().timestamp();
        EpiGraphClaims {
            sub: Uuid::new_v4(),
            iss: KERNEL_ISSUER.to_string(),
            aud: KERNEL_AUDIENCE.to_string(),
            exp: now + 300,
            iat: now,
            nbf: now,
            jti: Uuid::new_v4(),
            scopes: vec!["claims:admin".to_string()],
            client_type: "service".to_string(),
            owner_id: None,
            agent_id: None,
            fam: None,
            elv: None,
            dlg: None,
        }
    }

    fn jwks_json(cfg: &JwtConfig) -> String {
        serde_json::to_string(&cfg.jwks()).unwrap()
    }

    /// Known answer (RFC 8037 A.2 and A.3): the published `x` and the `kid`
    /// derived from the RFC's private key are the RFC's. Proves the PKCS#8
    /// wrapping and the public-key derivation, not just self-consistency.
    #[test]
    fn the_published_key_and_kid_match_rfc_8037() {
        let cfg = JwtConfig::from_ed25519_seed(&parse_ed25519_seed(RFC8037_SEED_HEX).unwrap());
        let doc: serde_json::Value = serde_json::to_value(cfg.jwks()).unwrap();
        let key = &doc["keys"][0];
        assert_eq!(key["kty"], "OKP");
        assert_eq!(key["crv"], "Ed25519");
        assert_eq!(key["alg"], "EdDSA");
        assert_eq!(key["use"], "sig");
        assert_eq!(key["x"], "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        assert_eq!(key["kid"], "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
        assert_eq!(doc["keys"].as_array().unwrap().len(), 1);
        // The token it mints names that key and verifies.
        let token = mint(&cfg, Duration::minutes(5)).unwrap();
        let header = decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::EdDSA);
        assert_eq!(
            header.kid.as_deref(),
            Some("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k")
        );
        assert!(cfg.validate_token(&token).is_ok());
    }

    /// THE DEFECT: an extension holding what it needs to verify kernel tokens
    /// could mint any of them. With the kernel's JWKS it verifies a kernel
    /// token and the exchanged token the gateway forwards, and refuses to
    /// mint either (no kernel token, no extension token). The JWKS carries no
    /// private material. Mutation caught: a verify-only config that can sign
    /// (`Signer::None` encoding with any key).
    #[test]
    fn an_extension_verifies_kernel_tokens_by_public_key_and_cannot_mint_one() {
        let kernel = JwtConfig::from_ed25519_seed(&seed(7));
        let published = jwks_json(&kernel);
        for private_field in ["\"d\"", "\"k\"", "\"p\"", "\"q\""] {
            assert!(
                !published.contains(private_field),
                "JWKS leaks {private_field}"
            );
        }
        let extension = JwtConfig::verifier_from_jwks(&published).unwrap();
        assert_eq!(extension.signing_algorithm(), None);
        assert!(!extension.accepts_hs256());

        let kernel_token = mint(&kernel, Duration::minutes(5)).unwrap();
        assert!(extension.validate_token(&kernel_token).is_ok());
        let exchanged = kernel
            .exchange_token(
                &kernel_token,
                "episcience",
                &["episcience".to_string()],
                None,
            )
            .unwrap();
        let claims = extension
            .validate_token_for_audience(&exchanged.token, "episcience")
            .expect("the extension verifies the token the gateway forwards");
        assert_eq!(claims.sub, exchanged.subject.sub);

        let refused = mint(&extension, Duration::minutes(5)).unwrap_err();
        assert_eq!(refused.kind(), &ErrorKind::InvalidKeyFormat);
        assert!(extension.sign(&claims_now()).is_err());
        assert!(matches!(
            extension.exchange_token(
                &kernel_token,
                "episcience",
                &["episcience".to_string()],
                None
            ),
            Err(ExchangeRefusal::InvalidRequest(_))
        ));
    }

    /// With a signing key and NO accept window, an HS256 token is refused
    /// whoever MACed it: the old shared secret, or the committed dev literal
    /// (the kernel's dev fallback must never become the window). Calibration:
    /// the same forged token IS admitted while the window holds the secret,
    /// and a token the kernel mints in the window is still EdDSA. Mutations
    /// caught: HS256 verified without a configured window (e.g. falling back
    /// to `DEV_JWT_SECRET`), and `from_kernel_env` opening the window with
    /// the dev literal when the secret is unset.
    #[test]
    fn an_eddsa_kernel_admits_no_hs256_token_outside_the_window() {
        let key_hex = hex::encode(seed(9));
        let forged_with = |secret: &[u8]| {
            let mut claims = claims_now();
            claims.scopes = vec!["claims:admin".to_string(), "claims:write".to_string()];
            encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(secret),
            )
            .unwrap()
        };
        let closed = JwtConfig::from_kernel_env(Some(&key_hex), None).unwrap();
        assert!(!closed.accepts_hs256());
        for secret in [SHARED, DEV_JWT_SECRET] {
            let err = closed.validate_token(&forged_with(secret)).unwrap_err();
            assert_eq!(err.kind(), &ErrorKind::InvalidAlgorithm);
            assert!(closed.verify_for_revocation(&forged_with(secret)).is_err());
        }
        let empty_secret = JwtConfig::from_kernel_env(Some(&key_hex), Some("")).unwrap();
        assert!(empty_secret.validate_token(&forged_with(b"")).is_err());

        let window =
            JwtConfig::from_kernel_env(Some(&key_hex), Some(std::str::from_utf8(SHARED).unwrap()))
                .unwrap();
        assert!(window.accepts_hs256());
        assert!(window.validate_token(&forged_with(SHARED)).is_ok());
        assert!(window.validate_token(&forged_with(DEV_JWT_SECRET)).is_err());
        let minted = mint(&window, Duration::minutes(5)).unwrap();
        assert_eq!(decode_header(&minted).unwrap().alg, Algorithm::EdDSA);
        assert_eq!(window.signing_algorithm(), Some(Algorithm::EdDSA));
        // Closing the window is dropping the secret: the same kernel key still
        // verifies everything it minted.
        assert!(closed.validate_token(&minted).is_ok());
    }

    /// Algorithm confusion: an HS256 token MACed with the PUBLIC key (its raw
    /// bytes, or the published `x` string) is refused by the extension and by
    /// a kernel whose window holds a different secret. Mutation caught: the
    /// HS256 arm verifying with a key derived from a configured Ed25519 key.
    #[test]
    fn an_hs256_token_macd_with_the_public_key_is_refused() {
        let kernel = JwtConfig::from_ed25519_seed(&seed(3)).with_hs256_accept(SHARED);
        let extension = JwtConfig::verifier_from_jwks(&jwks_json(&kernel)).unwrap();
        let x = kernel.ed25519[0].x.clone();
        let raw = URL_SAFE_NO_PAD.decode(&x).unwrap();
        for mac_key in [raw.as_slice(), x.as_bytes()] {
            let token = encode(
                &Header::new(Algorithm::HS256),
                &claims_now(),
                &EncodingKey::from_secret(mac_key),
            )
            .unwrap();
            assert!(extension.validate_token(&token).is_err());
            assert!(kernel.validate_token(&token).is_err());
        }
        // Nor does any algorithm outside the two the kernel uses verify.
        let hs512 = encode(
            &Header::new(Algorithm::HS512),
            &claims_now(),
            &EncodingKey::from_secret(SHARED),
        )
        .unwrap();
        assert_eq!(
            kernel.validate_token(&hs512).unwrap_err().kind(),
            &ErrorKind::InvalidAlgorithm
        );
    }

    /// An EdDSA token verifies only under the `kid` it names, and only if this
    /// config holds that `kid`: a token from another Ed25519 key is refused,
    /// and so is a genuine token whose `kid` was stripped or swapped.
    /// Mutation caught: the `kid` lookup replaced by "the first key".
    #[test]
    fn an_eddsa_token_needs_a_kid_this_config_holds() {
        let kernel = JwtConfig::from_ed25519_seed(&seed(1));
        let other = JwtConfig::from_ed25519_seed(&seed(2));
        let extension = JwtConfig::verifier_from_jwks(&jwks_json(&kernel)).unwrap();
        let foreign = mint(&other, Duration::minutes(5)).unwrap();
        assert!(kernel.validate_token(&foreign).is_err());
        assert!(extension.validate_token(&foreign).is_err());

        let Signer::EdDsa { key, .. } = &kernel.signer else {
            panic!("an Ed25519 kernel signs EdDSA");
        };
        let claims = claims_now();
        let no_kid = encode(&Header::new(Algorithm::EdDSA), &claims, key).unwrap();
        let mut swapped = Header::new(Algorithm::EdDSA);
        swapped.kid = Some(other.ed25519[0].kid.clone());
        let swapped = encode(&swapped, &claims, key).unwrap();
        for token in [&no_kid, &swapped] {
            for cfg in [&kernel, &extension] {
                assert_eq!(
                    cfg.validate_token(token).unwrap_err().kind(),
                    &ErrorKind::InvalidSignature
                );
            }
        }
        // CONTROL: the same claims under the right kid verify.
        assert!(extension
            .validate_token(&kernel.sign(&claims).unwrap())
            .is_ok());
    }

    /// Revocation verifies an EdDSA token past its expiry (else EdDSA tokens
    /// are unrevocable) and still refuses another key's. Mutation caught:
    /// `verify_for_revocation` left pinned to HS256.
    #[test]
    fn revocation_verifies_an_expired_eddsa_token_and_refuses_a_foreign_one() {
        let kernel = JwtConfig::from_ed25519_seed(&seed(5));
        let expired = mint(&kernel, Duration::hours(-2)).unwrap();
        assert_eq!(
            kernel.validate_token(&expired).unwrap_err().kind(),
            &ErrorKind::ExpiredSignature
        );
        assert!(kernel.verify_for_revocation(&expired).is_ok());
        let foreign = mint(&JwtConfig::from_ed25519_seed(&seed(6)), Duration::hours(-2)).unwrap();
        assert!(kernel.verify_for_revocation(&foreign).is_err());
    }

    /// A JWKS is all Ed25519 or refused: a symmetric (`oct`) key beside a
    /// good one, an empty set, a `kid` that is not its key's thumbprint, a
    /// short `x`, or a non-EdDSA `alg` refuses the whole document. Mutation
    /// caught: skipping a non-Ed25519 key instead of refusing.
    #[test]
    fn verifier_from_jwks_refuses_anything_but_ed25519_keys() {
        let kernel = JwtConfig::from_ed25519_seed(&seed(4));
        let good: serde_json::Value = serde_json::to_value(kernel.jwks()).unwrap();
        let good_key = good["keys"][0].clone();
        let with = |key: serde_json::Value| {
            serde_json::json!({ "keys": [key, good_key.clone()] }).to_string()
        };
        let mut wrong_kid = good_key.clone();
        wrong_kid["kid"] = serde_json::json!("not-the-thumbprint");
        let mut short_x = good_key.clone();
        short_x["x"] = serde_json::json!("AAAA");
        let mut wrong_alg = good_key.clone();
        wrong_alg["alg"] = serde_json::json!("ES256");
        for bad in [
            with(serde_json::json!({ "kty": "oct", "k": "c2VjcmV0" })),
            r#"{"keys":[]}"#.to_string(),
            "not json".to_string(),
            with(wrong_kid),
            with(short_x),
            with(wrong_alg),
        ] {
            assert!(
                JwtConfig::verifier_from_jwks(&bad).is_err(),
                "{bad} must be refused"
            );
        }
        // CONTROL: the good key alone, and without a `kid`, are accepted.
        assert!(JwtConfig::verifier_from_jwks(&good.to_string()).is_ok());
        let mut kidless = good_key.clone();
        kidless.as_object_mut().unwrap().remove("kid");
        let extension =
            JwtConfig::verifier_from_jwks(&serde_json::json!({ "keys": [kidless] }).to_string())
                .unwrap();
        assert!(extension
            .validate_token(&mint(&kernel, Duration::minutes(5)).unwrap())
            .is_ok());
    }

    /// With no signing key the kernel is exactly the HS256 kernel it was: the
    /// secret (or the dev literal when unset) signs, tokens carry no `kid`,
    /// a peer still on `from_secret` verifies them, and nothing is published.
    #[test]
    fn with_no_signing_key_the_kernel_is_unchanged() {
        let secret = std::str::from_utf8(SHARED).unwrap();
        for (env_secret, peer_secret) in [(Some(secret), SHARED), (None, DEV_JWT_SECRET)] {
            for key in [None, Some(""), Some("  ")] {
                let cfg = JwtConfig::from_kernel_env(key, env_secret).unwrap();
                assert_eq!(cfg.signing_algorithm(), Some(Algorithm::HS256));
                assert!(cfg.jwks().keys.is_empty());
                let token = mint(&cfg, Duration::minutes(5)).unwrap();
                let header = decode_header(&token).unwrap();
                assert_eq!(header.alg, Algorithm::HS256);
                assert_eq!(header.kid, None);
                assert!(JwtConfig::from_secret(peer_secret)
                    .validate_token(&token)
                    .is_ok());
            }
        }
    }

    /// The boot check: a malformed signing key refuses boot even under the
    /// insecure opt-out (never a silent fall back to HS256 signing), without
    /// echoing the key; a key alone is a production configuration; a set
    /// secret is still held to the production bar while it is the window.
    #[test]
    fn the_kernel_boot_check_covers_every_arm() {
        let key = hex::encode(seed(8));
        let real = "r".repeat(MIN_SECRET_LEN);
        let dev = std::str::from_utf8(DEV_JWT_SECRET).unwrap();
        let typo = format!("{}zz", &key[..62]);
        for allow_insecure in [false, true] {
            let err = check_kernel_jwt_keys(Some(&typo), Some(&real), allow_insecure).unwrap_err();
            assert!(
                !err.contains(&typo[..20]),
                "the error echoes the key: {err}"
            );
            assert!(check_kernel_jwt_keys(Some(&key[..62]), None, allow_insecure).is_err());
            assert!(JwtConfig::from_kernel_env(Some(&typo), Some(&real)).is_err());
        }
        assert!(check_kernel_jwt_keys(Some(&key), None, false).is_ok());
        assert!(check_kernel_jwt_keys(Some(&key), Some(&real), false).is_ok());
        assert!(check_kernel_jwt_keys(Some(&key), Some(dev), false).is_err());
        assert!(check_kernel_jwt_keys(Some(&key), Some(dev), true).is_ok());
        assert!(check_kernel_jwt_keys(None, Some(&real), false).is_ok());
        assert!(check_kernel_jwt_keys(None, Some(dev), false).is_err());
        assert!(check_kernel_jwt_keys(None, None, false).is_err());
        assert!(check_kernel_jwt_keys(Some(""), Some(""), false).is_err());
        assert!(check_kernel_jwt_keys(None, None, true).is_ok());
    }
}
