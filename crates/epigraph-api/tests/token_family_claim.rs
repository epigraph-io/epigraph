#![cfg(feature = "db")]
//! Access tokens carry their refresh family (`fam`) and an elevation slot
//! (`elv`).
//!
//! The elevation stack binds an elevation session to the refresh-token family
//! of the human session that asked for it. That needs the family on the
//! ACCESS token, which until now carried only `{sub, iss, aud, exp, iat, nbf,
//! jti, scopes, client_type, owner_id, agent_id}`. Both new claims are
//! optional: a token minted by a binary that predates them must still decode,
//! and a token minted by this binary must still decode under the previous
//! struct, because API and MCP binaries roll one at a time (N-1, both ways).
//!
//! The claims are not authority. `elv` is not minted by anything yet, and
//! nothing reads `fam` or `elv` as a grant of anything: a later batch
//! resolves them against a live database row.
//!
//! Each test names the mutation it is there to catch.

use base64::Engine as _;
use chrono::Duration;
use epigraph_auth::{AccessTokenBinding, AuthContext, JwtConfig};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const SECRET: &[u8] = b"token-family-claim-test-secret-of-adequate-length";

/// A FROZEN copy of `epigraph_auth::EpiGraphClaims` as it was before `fam`
/// and `elv` existed (branch head before this batch). Never edit it to track
/// the live struct: it stands for the binary one release back.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct PreviousClaims {
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
}

fn validation() -> Validation {
    let mut v = Validation::new(Algorithm::HS256);
    v.set_issuer(&["epigraph"]);
    v.set_audience(&["epigraph-api"]);
    v.leeway = 0;
    v
}

/// The payload segment of a compact JWS, as JSON.
fn payload(token: &str) -> serde_json::Value {
    let seg = token
        .split('.')
        .nth(1)
        .expect("a compact JWS has a payload");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(seg)
        .expect("base64url payload");
    serde_json::from_slice(&bytes).expect("JSON payload")
}

fn previous_claims_now() -> PreviousClaims {
    let now = chrono::Utc::now().timestamp();
    PreviousClaims {
        sub: Uuid::new_v4(),
        iss: "epigraph".into(),
        aud: "epigraph-api".into(),
        exp: now + 300,
        iat: now,
        nbf: now,
        jti: Uuid::new_v4(),
        scopes: vec!["claims:read".into()],
        client_type: "human".into(),
        owner_id: None,
        agent_id: Some(Uuid::new_v4()),
    }
}

// =============================================================================
// N-1, both ways, and the claim shape
// =============================================================================

/// An OLD binary decodes a NEW token carrying both claims, and reads every
/// claim it knows exactly as the new binary wrote it.
///
/// Catches: renaming or retyping an existing claim while adding the new ones
/// (e.g. `#[serde(rename = "scope")]` on `scopes`): the old struct then fails
/// to decode, or decodes a different value.
#[test]
fn a_token_with_fam_and_elv_decodes_under_the_previous_claims_struct() {
    let cfg = JwtConfig::from_secret(SECRET);
    let client = Uuid::new_v4();
    let agent = Uuid::new_v4();
    let fam = Uuid::new_v4();
    let elv = Uuid::new_v4();
    let binding = AccessTokenBinding {
        family_id: Some(fam),
        elevation_id: Some(elv),
    };
    let (token, jti) = cfg
        .issue_access_token(
            client,
            vec!["claims:read".into()],
            "human",
            Some(agent),
            Some(agent),
            Duration::minutes(5),
            binding,
        )
        .expect("mint");

    let old = decode::<PreviousClaims>(&token, &DecodingKey::from_secret(SECRET), &validation())
        .expect("the previous claims struct must decode a token carrying fam and elv")
        .claims;
    assert_eq!(old.sub, client);
    assert_eq!(old.jti, jti);
    assert_eq!(old.agent_id, Some(agent));
    assert_eq!(old.owner_id, Some(agent));
    assert_eq!(old.scopes, vec!["claims:read".to_string()]);
    assert_eq!(old.client_type, "human");

    // And the new binary reads the new claims back.
    let new = cfg.validate_token(&token).expect("current struct decodes");
    assert_eq!(new.fam, Some(fam));
    assert_eq!(new.elv, Some(elv));
}

/// A NEW binary decodes an OLD token (no `fam`, no `elv`): both read `None`.
///
/// Catches: a claim that demands its key, which would log out every live
/// session at deploy. Serde reads a missing plain `Option` as `None` on its
/// own, so the realistic way to get there is giving the claim a custom
/// `deserialize_with` and losing the `default` beside it (the mutation run
/// for this test), or retyping it to a bare `Uuid`.
#[test]
fn a_token_without_the_new_claims_decodes_under_the_current_struct() {
    let old = previous_claims_now();
    let token = encode(
        &Header::new(Algorithm::HS256),
        &old,
        &EncodingKey::from_secret(SECRET),
    )
    .expect("encode previous claims");

    let claims = JwtConfig::from_secret(SECRET)
        .validate_token(&token)
        .expect("the current struct must decode a token minted before fam/elv existed");
    assert_eq!(claims.fam, None);
    assert_eq!(claims.elv, None);
    assert_eq!(claims.agent_id, old.agent_id);
    assert_eq!(claims.jti, old.jti);
}

/// A claim this binary does not know is ignored, not refused. The next
/// binary (N+1) may add one, and this binary must keep serving its tokens.
///
/// Catches: `#[serde(deny_unknown_fields)]` on `EpiGraphClaims`.
#[test]
fn an_unknown_claim_is_ignored_by_the_current_struct() {
    let mut body = serde_json::to_value(previous_claims_now()).expect("to JSON");
    body["fam"] = serde_json::json!(Uuid::new_v4());
    body["a_claim_from_a_later_release"] = serde_json::json!({"anything": [1, 2, 3]});
    let token = encode(
        &Header::new(Algorithm::HS256),
        &body,
        &EncodingKey::from_secret(SECRET),
    )
    .expect("encode");

    JwtConfig::from_secret(SECRET)
        .validate_token(&token)
        .expect("an unknown claim must not make the token invalid");
}

/// A token with no family and no elevation does not carry the keys at all:
/// the wire shape of every token that does not need them is unchanged.
///
/// Catches: dropping `skip_serializing_if = "Option::is_none"` (the payload
/// would then carry `"fam": null` / `"elv": null`).
#[test]
fn a_token_with_no_binding_carries_neither_key() {
    let (token, _) = JwtConfig::from_secret(SECRET)
        .issue_access_token(
            Uuid::new_v4(),
            vec![],
            "agent",
            None,
            Some(Uuid::new_v4()),
            Duration::minutes(5),
            AccessTokenBinding::NONE,
        )
        .expect("mint");
    let body = payload(&token);
    let obj = body.as_object().expect("payload object");
    assert!(!obj.contains_key("fam"), "no family, no key: {body}");
    assert!(!obj.contains_key("elv"), "no elevation, no key: {body}");
}

/// The validated claims reach the request's `AuthContext` as CLAIMS:
/// `family_id` and `elevation_claim`.
///
/// Catches: a `From<EpiGraphClaims> for AuthContext` that drops either claim
/// (`family_id: None`), which would leave the later elevation resolution
/// with nothing to resolve.
#[test]
fn fam_and_elv_reach_the_auth_context() {
    let cfg = JwtConfig::from_secret(SECRET);
    let fam = Uuid::new_v4();
    let elv = Uuid::new_v4();
    let (token, _) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            vec![],
            "human",
            None,
            Some(Uuid::new_v4()),
            Duration::minutes(5),
            AccessTokenBinding {
                family_id: Some(fam),
                elevation_id: Some(elv),
            },
        )
        .expect("mint");
    let ctx: AuthContext = cfg.validate_token(&token).expect("valid").into();
    assert_eq!(ctx.family_id, Some(fam));
    assert_eq!(ctx.elevation_claim, Some(elv));

    let (token, _) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            vec![],
            "human",
            None,
            Some(Uuid::new_v4()),
            Duration::minutes(5),
            AccessTokenBinding::NONE,
        )
        .expect("mint");
    let ctx: AuthContext = cfg.validate_token(&token).expect("valid").into();
    assert_eq!(ctx.family_id, None);
    assert_eq!(ctx.elevation_claim, None);
}
