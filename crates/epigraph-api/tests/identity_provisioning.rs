#![cfg(feature = "db")]
//! PR-02 — every authenticated principal has an `agents.id`, and the two
//! registration gates are closed.
//!
//! Covers the acceptance lines `group_lifecycle.rs` does not:
//! * `AuthContext.agent_id` is non-null for every grant that mints through
//!   `POST /oauth/token`;
//! * `ensure_for_client` is idempotent and bootstraps exactly one personal
//!   group;
//! * the `key_kind='derived'` placeholder key is refused by the packet
//!   verifier;
//! * a freshly registered `client_type:"agent"` client is `pending` with zero
//!   granted scopes and cannot obtain a token at all.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use epigraph_api::{create_router, ApiConfig, AppState};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

// =============================================================================
// FIXTURES
// =============================================================================

fn app(pool: PgPool) -> axum::Router {
    create_router(AppState::with_db(pool, ApiConfig::default()))
}

async fn post_json(app: axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Seed a `service` OAuth client with a known secret, `status='active'`, and
/// `agent_id = NULL` — the shape every client created by `/oauth/register` or
/// by external provisioning has today. Returns `(row_id, client_id, secret)`.
async fn seed_service_client(pool: &PgPool, name: &str) -> (Uuid, String, String) {
    let secret_bytes: [u8; 32] = *blake3::hash(name.as_bytes()).as_bytes();
    let secret = hex::encode(secret_bytes);
    let hash = blake3::hash(&secret_bytes);
    let client_id = format!("epigraph_{}", hex::encode(&secret_bytes[..16]));

    // `services_must_have_legal_entity` requires both legal fields on a
    // client_type='service' row.
    let row: (Uuid,) = sqlx::query_as(
        r#"INSERT INTO oauth_clients
            (client_id, client_secret_hash, client_name, client_type,
             allowed_scopes, granted_scopes, status, agent_id,
             legal_entity_name, legal_contact_email)
           VALUES ($1, $2, $3, 'service', $4, $4, 'active', NULL, $3, 'ops@example.test')
           RETURNING id"#,
    )
    .bind(&client_id)
    .bind(hash.as_bytes().as_slice())
    .bind(name)
    .bind(vec!["claims:read".to_string(), "claims:write".to_string()])
    .fetch_one(pool)
    .await
    .expect("seed oauth client");

    (row.0, client_id, secret)
}

/// Decode a JWT payload without verifying (we only need the claims).
fn jwt_claims(token: &str) -> Value {
    use base64::Engine as _;
    let payload = token.split('.').nth(1).expect("jwt has a payload segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("jwt payload is base64url");
    serde_json::from_slice(&bytes).expect("jwt payload is JSON")
}

// =============================================================================
// 1. agent_id IS POPULATED ON EVERY GRANT
// =============================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn client_credentials_mints_a_token_carrying_an_agent_id(pool: PgPool) {
    let (row_id, client_id, secret) = seed_service_client(&pool, "cc-client").await;

    // Precondition: this is exactly the "agent_id is never populated" shape.
    let before: (Option<Uuid>,) =
        sqlx::query_as("SELECT agent_id FROM oauth_clients WHERE id = $1")
            .bind(row_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(before.0.is_none());

    let (status, body) = post_json(
        app(pool.clone()),
        "/oauth/token",
        json!({
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": secret,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let claims = jwt_claims(body["access_token"].as_str().unwrap());
    let agent_id = claims["agent_id"]
        .as_str()
        .expect("agent_id claim must be present and non-null");
    let agent_id: Uuid = agent_id.parse().unwrap();

    // And it was persisted, so the NEXT mint reuses it.
    let after: (Option<Uuid>,) = sqlx::query_as("SELECT agent_id FROM oauth_clients WHERE id = $1")
        .bind(row_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(after.0, Some(agent_id));
}

#[sqlx::test(migrations = "../../migrations")]
async fn refresh_token_grant_also_carries_the_agent_id(pool: PgPool) {
    let (_row_id, client_id, secret) = seed_service_client(&pool, "refresh-client").await;

    let (_, first) = post_json(
        app(pool.clone()),
        "/oauth/token",
        json!({
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": secret,
        }),
    )
    .await;
    let first_agent = jwt_claims(first["access_token"].as_str().unwrap())["agent_id"]
        .as_str()
        .unwrap()
        .to_string();
    let refresh = first["refresh_token"].as_str().unwrap().to_string();

    let (status, body) = post_json(
        app(pool.clone()),
        "/oauth/token",
        json!({ "grant_type": "refresh_token", "refresh_token": refresh }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let claims = jwt_claims(body["access_token"].as_str().unwrap());
    assert_eq!(
        claims["agent_id"].as_str(),
        Some(first_agent.as_str()),
        "the refresh grant must resolve the SAME principal, not a second one"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn ensure_for_client_is_idempotent(pool: PgPool) {
    let (row_id, client_id, secret) = seed_service_client(&pool, "idem-client").await;

    for _ in 0..3 {
        let (status, body) = post_json(
            app(pool.clone()),
            "/oauth/token",
            json!({
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": secret,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    let agent_id: (Uuid,) = sqlx::query_as("SELECT agent_id FROM oauth_clients WHERE id = $1")
        .bind(row_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    // Exactly one agent, one personal group, one live membership.
    let agents: (i64,) = sqlx::query_as("SELECT count(*) FROM agents WHERE id = $1")
        .bind(agent_id.0)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(agents.0, 1);

    let groups: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM groups WHERE created_by_agent_id = $1 AND kind = 'personal'",
    )
    .bind(agent_id.0)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(groups.0, 1, "exactly one personal group per principal");

    let memberships: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM group_memberships WHERE agent_id = $1 AND revoked_at IS NULL",
    )
    .bind(agent_id.0)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(memberships.0, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn every_principal_has_a_personal_group_from_its_first_token(pool: PgPool) {
    let (row_id, client_id, secret) = seed_service_client(&pool, "personal-client").await;

    let (status, _) = post_json(
        app(pool.clone()),
        "/oauth/token",
        json!({
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": secret,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let agent_id: (Uuid,) = sqlx::query_as("SELECT agent_id FROM oauth_clients WHERE id = $1")
        .bind(row_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    let g: (String, String, i32, i64) = sqlx::query_as(
        "SELECT did_key, kind, octet_length(public_key), \
                (SELECT count(*) FROM group_key_epochs e WHERE e.group_id = g.id) \
         FROM groups g WHERE created_by_agent_id = $1",
    )
    .bind(agent_id.0)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        g.0,
        format!("did:epigraph:personal:{}", agent_id.0),
        "the deterministic did_key is what makes ensure_personal_group idempotent"
    );
    assert_eq!(g.1, "personal");
    // groups_public_key_shape (migration 060) requires a 0-byte key for any
    // kind <> 'team'. A personal group holds no key material at all...
    assert_eq!(g.2, 0);
    // ...so it also has no key epoch.
    assert_eq!(g.3, 0, "a personal group must carry no key epochs");

    // The principal is the admin of its own personal group.
    let role: (String, i32) = sqlx::query_as(
        "SELECT role, octet_length(wrapped_key_share) FROM group_memberships \
         WHERE agent_id = $1 AND revoked_at IS NULL",
    )
    .bind(agent_id.0)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(role.0, "admin");
    assert_eq!(role.1, 0, "nothing to wrap for a keyless personal group");
}

// =============================================================================
// 2. THE DERIVED KEY IS NOT A SIGNATURE VERIFIER
// =============================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn a_derived_key_is_refused_by_the_packet_verifier(pool: PgPool) {
    let (row_id, client_id, secret) = seed_service_client(&pool, "derived-client").await;

    // Mint once so the placeholder principal exists.
    let (status, _) = post_json(
        app(pool.clone()),
        "/oauth/token",
        json!({
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": secret,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let agent: (Uuid,) = sqlx::query_as("SELECT agent_id FROM oauth_clients WHERE id = $1")
        .bind(row_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    // It really is a 32-byte placeholder, flagged as such.
    let kind: (String, i32) =
        sqlx::query_as("SELECT key_kind, octet_length(public_key) FROM agents WHERE id = $1")
            .bind(agent.0)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(kind.0, "derived");
    assert_eq!(kind.1, 32, "it must satisfy agents_public_key_length");

    // Now submit a packet claiming to be signed by that agent, with signatures
    // REQUIRED. `AgentRepository::public_key_if_signer` filters
    // key_kind='ed25519', so the placeholder is invisible to the verifier and
    // the request is refused as an unregistered signer — never accepted, and
    // never a 500 from feeding a hash output to an Ed25519 verifier.
    let signing_app = create_router(AppState::with_db(
        pool.clone(),
        ApiConfig {
            require_packet_signatures: true,
            ..ApiConfig::default()
        },
    ));

    let packet = json!({
        "claim": {
            "content": "a claim signed by nobody",
            "initial_truth": 0.9,
            "agent_id": agent.0,
        },
        "evidence": [],
        "reasoning_trace": {
            "methodology": "inductive",
            "inputs": [],
            "confidence": 0.8,
            "explanation": "derived-key rejection test",
        },
        "signature": "0".repeat(128),
    });

    // /api/v1/submit/packet is on the protected router, so it needs a token.
    let bearer = {
        let cfg = epigraph_api::oauth::JwtConfig::from_secret(
            std::env::var("EPIGRAPH_JWT_SECRET")
                .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string())
                .as_bytes(),
        );
        cfg.issue_access_token(
            row_id,
            vec!["claims:write".to_string()],
            "service",
            None,
            Some(agent.0),
            chrono::Duration::minutes(60),
        )
        .unwrap()
        .0
    };

    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/submit/packet")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::from(packet.to_string()))
        .unwrap();
    let resp = signing_app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a derived placeholder key must never satisfy the signature path: {body}"
    );
    assert_eq!(body["error"], "SignatureError", "{body}");
    // The SPECIFIC message, not just the error class. `submit.rs` returns the
    // same "SignatureError" class for an ordinary failed verification, and a
    // BLAKE3 output decompresses to a valid Edwards point about half the time —
    // so `error == "SignatureError"` alone passes on UNFIXED code roughly half
    // the runs (the other half takes the `Err(e)` 500 arm). This string is
    // produced only by the `public_key_if_signer` miss, i.e. only by the
    // key_kind filter actually being there.
    assert_eq!(
        body["message"], "Agent not registered, or is not an Ed25519 signer",
        "the derived key must be rejected by the key_kind filter, not merely fail \
         verification: {body}"
    );

    // Nothing was written.
    let claims: (i64,) = sqlx::query_as("SELECT count(*) FROM claims WHERE agent_id = $1")
        .bind(agent.0)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(claims.0, 0);
}

// =============================================================================
// 3. THE AUTO-ACTIVATION KILL
// =============================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn a_freshly_registered_agent_client_cannot_read_a_claim(pool: PgPool) {
    // `client_type:"agent"` requires at least one active human client to own it
    // (the `agents_must_have_owner` CHECK on oauth_clients).
    sqlx::query(
        r#"INSERT INTO oauth_clients
            (client_id, client_name, client_type, allowed_scopes, granted_scopes, status)
           VALUES ('epigraph_owner_human', 'Owner', 'human', '{}', '{}', 'active')"#,
    )
    .execute(&pool)
    .await
    .expect("seed owner human client");

    let agent_pubkey = hex::encode(blake3::hash(b"drive-by-agent").as_bytes());

    let (status, body) = post_json(
        app(pool.clone()),
        "/oauth/register",
        json!({
            "client_name": "Drive-by Harvester",
            "client_type": "agent",
            "client_id": agent_pubkey,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // THE GATE. This arm used to return status="active" with eleven scopes
    // including claims:write and ingest:write — an unauthenticated POST yielded
    // a usable write credential.
    assert_eq!(
        body["status"], "pending",
        "an agent registration must NOT be auto-activated: {body}"
    );

    let row: (String, Vec<String>, Vec<String>) = sqlx::query_as(
        "SELECT status, allowed_scopes, granted_scopes FROM oauth_clients WHERE client_id = $1",
    )
    .bind(&agent_pubkey)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, "pending");
    assert!(
        row.2.is_empty(),
        "granted_scopes must be EMPTY until an admin approves; got {:?}",
        row.2
    );
    // allowed_scopes records what an admin MAY approve, and must not include
    // anything an approval should have to think about twice.
    assert!(
        !row.1.is_empty(),
        "allowed_scopes records the approvable set"
    );
    for forbidden in [
        "instance:admin",
        "claims:admin",
        "ingest:write",
        "agents:write",
    ] {
        assert!(
            !row.1.contains(&forbidden.to_string()),
            "allowed_scopes must not propose {forbidden}"
        );
    }

    // And no token can be obtained: get_by_client_id filters status='active',
    // so there is no credential with which to read a claim.
    let (status, _) = post_json(
        app(pool.clone()),
        "/oauth/token",
        json!({
            "grant_type": "client_credentials",
            "client_id": agent_pubkey,
            "client_secret": "irrelevant",
        }),
    )
    .await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "a pending client must not obtain a token, got {status}"
    );
}

// =============================================================================
// 4. THE INVARIANT RATCHET
// =============================================================================

/// PR-02's headline acceptance is "`AuthContext.agent_id` is non-null for every
/// authenticated request". Nothing in the type system enforces it:
/// `issue_access_token` takes `Option<Uuid>`, and a FIFTH mint site added by a
/// later PR would reintroduce `None` silently — the runtime tests all mint
/// through the four sites that already pass `Some(..)`, so none of them would
/// fail.
///
/// So: source inspection over the whole `src/` tree. Every `issue_access_token`
/// call outside a `#[cfg(test)]` module must pass `Some(...)`, never a literal
/// `None`, for the `agent_id` argument.
///
/// PR-03's `ViewerExtractor` resolves a `Viewer` from that claim, so a `None`
/// here becomes a 401 on every protected content route there. Catching it as a
/// failing assertion in PR-02 is cheaper than as an outage in PR-03.
#[test]
fn every_production_token_mint_carries_an_agent_id() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk(&src, &mut files);

    let mut sites = 0usize;
    for file in files {
        let text = std::fs::read_to_string(&file).expect("read source");

        // Drop `#[cfg(test)] mod tests { .. }` bodies by brace depth. The test
        // helpers inside them legitimately mint `None`-principal tokens to
        // exercise the rejection paths.
        let mut code = String::new();
        let mut skip_depth: Option<i32> = None;
        let mut pending_cfg_test = false;
        for line in text.lines() {
            match skip_depth {
                Some(depth) => {
                    let d =
                        depth + line.matches('{').count() as i32 - line.matches('}').count() as i32;
                    skip_depth = if d <= 0 { None } else { Some(d) };
                }
                None => {
                    if pending_cfg_test && line.contains("mod ") && line.contains('{') {
                        pending_cfg_test = false;
                        skip_depth = Some(1);
                        continue;
                    }
                    if line.trim_start().starts_with("#[cfg(test)]") {
                        pending_cfg_test = true;
                        continue;
                    }
                    pending_cfg_test = false;
                    code.push_str(line);
                    code.push('\n');
                }
            }
        }

        // Normalise whitespace so a rustfmt-wrapped argument list is one string.
        let flat = code.split_whitespace().collect::<Vec<_>>().join(" ");
        let mut rest = flat.as_str();
        while let Some(i) = rest.find(".issue_access_token(") {
            rest = &rest[i + ".issue_access_token(".len()..];
            // The argument list ends at the matching ')'.
            let mut depth = 1i32;
            let mut end = rest.len();
            for (j, c) in rest.char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = j;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let args = &rest[..end];
            sites += 1;
            assert!(
                !args.contains("None,"),
                "{}: issue_access_token must pass Some(agent_id), never None — \
                 PR-02 acceptance: AuthContext.agent_id is non-null for every \
                 authenticated request. Args: {args}",
                file.display()
            );
            assert!(
                args.contains("Some("),
                "{}: issue_access_token argument list carries no Some(agent_id): {args}",
                file.display()
            );
            rest = &rest[end..];
        }
    }

    // Guard against the walk silently finding nothing (a refactor that renames
    // the method, or moves the mint sites out of `src/`, must fail loudly here
    // rather than pass vacuously).
    assert_eq!(
        sites, 4,
        "expected exactly 4 production token-mint sites (3 in oauth/token.rs, 1 in \
         oauth/providers/provision.rs); found {sites}. A new one must pass \
         Some(agent_id) and this count must be updated deliberately."
    );
}

// =============================================================================
// 5. ensure_for_client — WHICH agents ROW A CLIENT SPEAKS AS
// =============================================================================

/// An `agent` client's `client_id` IS its hex Ed25519 public key
/// (`oauth/register.rs` requires it; `oauth/token.rs` decodes it to verify the
/// client assertion). So such a client already HAS a signing identity, and the
/// kernel resolves that identity elsewhere by `agents.public_key`
/// (`routes/policies.rs`, `routes/workflows.rs`).
///
/// `ensure_for_client` used to derive a placeholder unconditionally, so the
/// token's `agent_id` named a `key_kind='derived'` row while the agent's own
/// claims were authored under a different one. Under PR-03/PR-07, where the JWT
/// principal becomes the viewer identity, an agent's own claims would then be
/// invisible to its own token.
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_client_speaks_as_its_own_ed25519_agent_row(pool: PgPool) {
    let pubkey: [u8; 32] = *blake3::hash(b"real-signer").as_bytes();
    let pubkey_hex = hex::encode(pubkey);

    let real: (Uuid,) = sqlx::query_as(
        "INSERT INTO agents (public_key, display_name, key_kind) \
         VALUES ($1, 'real signer', 'ed25519') RETURNING id",
    )
    .bind(pubkey.as_slice())
    .fetch_one(&pool)
    .await
    .expect("seed ed25519 agent");

    sqlx::query(
        r#"INSERT INTO oauth_clients
            (client_id, client_name, client_type, allowed_scopes, granted_scopes, status)
           VALUES ('epigraph_owner_h', 'Owner', 'human', '{}', '{}', 'active')"#,
    )
    .execute(&pool)
    .await
    .unwrap();

    let owner: (Uuid,) =
        sqlx::query_as("SELECT id FROM oauth_clients WHERE client_id = 'epigraph_owner_h'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let client: (Uuid,) = sqlx::query_as(
        r#"INSERT INTO oauth_clients
            (client_id, client_name, client_type, allowed_scopes, granted_scopes, status, owner_id)
           VALUES ($1, 'agent', 'agent', '{}', '{}', 'active', $2) RETURNING id"#,
    )
    .bind(&pubkey_hex)
    .bind(owner.0)
    .fetch_one(&pool)
    .await
    .expect("seed agent client");

    let mut conn = pool.acquire().await.unwrap();
    let resolved =
        epigraph_db::repos::agent::AgentRepository::ensure_for_client(&mut conn, client.0)
            .await
            .expect("ensure_for_client");

    assert_eq!(
        resolved.as_uuid(),
        real.0,
        "an agent client must speak as the ed25519 agents row holding its client_id, \
         not as a second derived placeholder"
    );

    // And no derived twin was minted alongside it.
    let derived: (i64,) = sqlx::query_as("SELECT count(*) FROM agents WHERE key_kind = 'derived'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(derived.0, 0, "no placeholder should exist for this client");
}

/// The `ON CONFLICT (public_key) DO UPDATE` in `ensure_for_client` must NOT
/// adopt a pre-existing row that is a real signer.
///
/// `POST /api/v1/agents` accepts an arbitrary 32-byte `public_key` from any
/// `agents:write` holder, and `oauth_clients.id` is exposed as the JWT `sub`, so
/// pre-creating an agent at
/// `blake3::derive_key("epigraph-oauth-client", <victim client uuid>)` with a key
/// you hold the private half of would otherwise make you that client's
/// principal — WITH a real verifier, defeating `public_key_if_signer` entirely.
#[sqlx::test(migrations = "../../migrations")]
async fn ensure_for_client_refuses_to_adopt_an_ed25519_squatter(pool: PgPool) {
    let (row_id, _client_id, _secret) = seed_service_client(&pool, "squatted-client").await;

    // The attacker pre-creates the row at exactly the derived key, as a signer.
    let derived = blake3::derive_key("epigraph-oauth-client", row_id.as_bytes());
    sqlx::query(
        "INSERT INTO agents (public_key, display_name, key_kind) \
         VALUES ($1, 'squatter', 'ed25519')",
    )
    .bind(derived.as_slice())
    .execute(&pool)
    .await
    .expect("seed squatter");

    let mut conn = pool.acquire().await.unwrap();
    let err = epigraph_db::repos::agent::AgentRepository::ensure_for_client(&mut conn, row_id)
        .await
        .expect_err("must refuse to adopt a non-derived row");
    assert!(
        matches!(err, epigraph_db::DbError::DuplicateKey { .. }),
        "expected DuplicateKey, got {err:?}"
    );

    // The client is left UNLINKED — a hard failure, not a silent adoption.
    let after: (Option<Uuid>,) = sqlx::query_as("SELECT agent_id FROM oauth_clients WHERE id = $1")
        .bind(row_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(after.0.is_none());
}

/// `ensure_personal_group` must REVIVE a revoked epoch-0 membership.
///
/// The untargeted `ON CONFLICT DO NOTHING` it used to carry did not conflict on
/// the partial index `group_memberships_one_live` (there is no live row) but did
/// conflict on the composite `(group_id, agent_id, epoch)` UNIQUE — so the
/// insert silently no-op'd and the agent had NO live membership in its own
/// personal group, permanently, because every later mint hit the same conflict.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_personal_group_membership_is_revived(pool: PgPool) {
    let key: [u8; 32] = *blake3::hash(b"personal-revive").as_bytes();
    let agent: (Uuid,) = sqlx::query_as(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, 'p') RETURNING id",
    )
    .bind(key.as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let group_id =
        epigraph_db::repos::agent::AgentRepository::ensure_personal_group(&mut conn, agent.0)
            .await
            .expect("first call");

    sqlx::query("UPDATE group_memberships SET revoked_at = now() WHERE group_id = $1")
        .bind(group_id)
        .execute(&pool)
        .await
        .unwrap();

    let again =
        epigraph_db::repos::agent::AgentRepository::ensure_personal_group(&mut conn, agent.0)
            .await
            .expect("second call");
    assert_eq!(again, group_id, "the personal group id is deterministic");

    let role = epigraph_db::GroupMembershipRepository::get_member_role(&pool, group_id, agent.0)
        .await
        .unwrap();
    assert_eq!(
        role.as_deref(),
        Some("admin"),
        "the agent must hold a LIVE role='admin' membership in its own personal group"
    );

    // Exactly one row: revived, not duplicated.
    let n: (i64,) = sqlx::query_as("SELECT count(*) FROM group_memberships WHERE group_id = $1")
        .bind(group_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n.0, 1);
}
