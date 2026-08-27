#![cfg(feature = "db")]
//! PR-02 — group lifecycle end to end.
//!
//! The headline acceptance: create-group → add-member → get-member-role
//! round-trips. On `main` the second leg is impossible — `create_group` writes
//! no membership row at all, so `require_group_admin` 403s the creator on their
//! own brand-new group.
//!
//! Everything here drives the real router (`create_router`), so the extractor
//! ordering, the scope gates and `bearer_auth_middleware` are all in the path.
//! `get_member_role` has no HTTP route (there is no
//! `GET /groups/:id/members/:agent_id` and `GET /groups/:id` returns only
//! `member_count`), so the third leg of the round-trip is asserted at the
//! repository layer.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_db::GroupMembershipRepository;
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

/// Insert a real `agents` row. `group_memberships.agent_id` and
/// `groups.created_by_agent_id` both carry FKs to it, so a token whose
/// `agent_id` claim names no row cannot create a group.
async fn seed_agent(pool: &PgPool, name: &str) -> Uuid {
    let key: [u8; 32] = *blake3::hash(name.as_bytes()).as_bytes();
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id",
    )
    .bind(key.as_slice())
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("seed agent");
    row.0
}

/// Mint a JWT carrying `agent_id` and `scopes`. Mirrors
/// `tests/common/mod.rs::mint_token_with_agent`; inlined so this file does not
/// pull in the whole shared fixture module for one function.
fn token(scopes: &[&str], agent_id: Uuid) -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (t, _jti) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "agent",
            None,
            Some(agent_id),
            chrono::Duration::minutes(60),
        )
        .expect("test JWT issued");
    t
}

async fn send(
    app: axum::Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(t) = bearer {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let req = match body {
        Some(b) => req
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(b.to_string()))
            .unwrap(),
        None => req.body(Body::empty()).unwrap(),
    };
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

/// A distinct 32-byte GROUP public key, hex-encoded. `did_key` is derived from
/// it and `groups.did_key` is UNIQUE, so two groups need two keys.
fn group_key(seed: &str) -> String {
    hex::encode(blake3::hash(seed.as_bytes()).as_bytes())
}

/// A structurally valid wrapped key share: 60 bytes, being a 12-byte nonce, a
/// 32-byte wrapped key and a 16-byte GCM tag. The contents are opaque to the
/// server (it never unwraps), but the SHAPE is now enforced at the boundary.
fn wrapped_share(seed: &str) -> String {
    let mut bytes = Vec::with_capacity(60);
    bytes.extend_from_slice(blake3::hash(seed.as_bytes()).as_bytes()); // 32
    bytes.extend_from_slice(&blake3::hash(seed.as_bytes()).as_bytes()[..28]); // 28
    assert_eq!(bytes.len(), 60);
    hex::encode(bytes)
}

async fn create_group(pool: &PgPool, tok: &str, name: &str, key_seed: &str) -> (StatusCode, Value) {
    send(
        app(pool.clone()),
        Method::POST,
        "/api/v1/groups",
        Some(tok),
        Some(json!({ "name": name, "group_public_key": group_key(key_seed) })),
    )
    .await
}

// =============================================================================
// 1. THE HEADLINE ACCEPTANCE
// =============================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn create_group_then_add_member_then_get_member_role_round_trips(pool: PgPool) {
    let creator = seed_agent(&pool, "creator").await;
    let newcomer = seed_agent(&pool, "newcomer").await;

    // --- leg 1: create ---------------------------------------------------
    let writer = token(&["groups:write"], creator);
    let (status, body) = create_group(&pool, &writer, "Test Group", "grp-a").await;
    assert_eq!(status, StatusCode::CREATED, "create_group: {body}");
    let group_id: Uuid = body["group_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(body["epoch"], 0);

    // The creator must be a LIVE admin of their own group. This row is what
    // PR-02 adds; without it leg 2 is unreachable.
    let role = GroupMembershipRepository::get_member_role(&pool, group_id, creator)
        .await
        .unwrap();
    assert_eq!(
        role.as_deref(),
        Some("admin"),
        "the creator must be stored as a live admin of their own group"
    );

    // Epoch 0 must exist in the same transaction, else add_member 409s.
    let epochs: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM group_key_epochs WHERE group_id = $1 AND status = 'active'",
    )
    .bind(group_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        epochs.0, 1,
        "create_group must write exactly one active epoch"
    );

    // The group is a team group carrying real key material.
    let kind: (String,) = sqlx::query_as("SELECT kind FROM groups WHERE id = $1")
        .bind(group_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(kind.0, "team");

    // --- leg 2: add member ------------------------------------------------
    // THIS is the assertion that fails on main: require_group_admin finds no
    // membership row for the creator and returns 403.
    let admin = token(&["groups:admin"], creator);
    let (status, body) = send(
        app(pool.clone()),
        Method::POST,
        &format!("/api/v1/groups/{group_id}/members"),
        Some(&admin),
        Some(json!({
            "agent_id": newcomer,
            "wrapped_key_share": wrapped_share("share-1"),
            "role": "writer",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "add_member: {body}");
    assert_eq!(body["role"], "writer");
    assert_eq!(body["epoch"], 0);

    // --- leg 3: get_member_role -------------------------------------------
    let role = GroupMembershipRepository::get_member_role(&pool, group_id, newcomer)
        .await
        .unwrap();
    assert_eq!(role.as_deref(), Some("writer"));
}

// =============================================================================
// 2. did_key UNIQUENESS AND SHAPE
// =============================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn second_group_by_same_creator_succeeds(pool: PgPool) {
    let creator = seed_agent(&pool, "serial-creator").await;
    let tok = token(&["groups:write"], creator);

    let (s1, b1) = create_group(&pool, &tok, "First", "grp-1").await;
    assert_eq!(s1, StatusCode::CREATED, "{b1}");
    let (s2, b2) = create_group(&pool, &tok, "Second", "grp-2").await;
    assert_eq!(
        s2,
        StatusCode::CREATED,
        "a second group by the same creator must succeed: {b2}"
    );

    assert_ne!(
        b1["did_key"], b2["did_key"],
        "two groups with different public keys must get different dids"
    );
    for b in [&b1, &b2] {
        assert!(
            b["did_key"].as_str().unwrap().starts_with("did:key:z"),
            "did must be multibase, got {}",
            b["did_key"]
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn reusing_the_same_group_key_is_409_not_500(pool: PgPool) {
    let creator = seed_agent(&pool, "dupe-creator").await;
    let tok = token(&["groups:write"], creator);

    let (s1, _) = create_group(&pool, &tok, "First", "same-key").await;
    assert_eq!(s1, StatusCode::CREATED);

    // groups_did_key_key is UNIQUE. A repeat submission is a client error.
    let (s2, b2) = create_group(&pool, &tok, "Again", "same-key").await;
    assert_eq!(
        s2,
        StatusCode::CONFLICT,
        "a duplicate group public key must be a clean 409, not a 23505 -> 500: {b2}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn did_key_is_parseable_by_the_kernel_parser(pool: PgPool) {
    let creator = seed_agent(&pool, "did-creator").await;
    let tok = token(&["groups:write"], creator);
    let key_hex = group_key("grp-did");

    let (status, body) = send(
        app(pool.clone()),
        Method::POST,
        "/api/v1/groups",
        Some(&tok),
        Some(json!({ "name": "DID Group", "group_public_key": key_hex })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // The route used to emit `did:key:<hex>`, which DidKey::to_public_key
    // rejects outright — no did this route produced could be read back by the
    // code that consumes it.
    // DidKey's inner String is private, so round-trip through its transparent
    // Deserialize rather than constructing it.
    let did: epigraph_crypto::DidKey =
        serde_json::from_value(body["did_key"].clone()).expect("did_key is a string");
    let round_tripped = did
        .to_public_key()
        .expect("the kernel's own parser must accept the did this route emits");
    assert_eq!(hex::encode(round_tripped), key_hex);
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_group_accepts_the_legacy_creator_public_key_field_name(pool: PgPool) {
    // The field was renamed group_public_key (it is the GROUP's key, not the
    // creator's) with a serde alias, so existing clients keep working.
    let creator = seed_agent(&pool, "legacy-creator").await;
    let tok = token(&["groups:write"], creator);
    let (status, body) = send(
        app(pool.clone()),
        Method::POST,
        "/api/v1/groups",
        Some(&tok),
        Some(json!({ "name": "Legacy", "creator_public_key": group_key("legacy") })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

// =============================================================================
// 3. THE ROLE VOCABULARY
// =============================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn role_omitted_defaults_to_reader_and_does_not_500(pool: PgPool) {
    // NOTE: `reader`, not `writer`. PR-01 shipped `default_role() -> "reader"`
    // and migration 060 sets the column DEFAULT to 'reader', both with an
    // explicit least-privilege rationale. The plan text says `writer`; the code
    // is the authority.
    let creator = seed_agent(&pool, "role-creator").await;
    let newcomer = seed_agent(&pool, "role-newcomer").await;
    let (status, body) = create_group(
        &pool,
        &token(&["groups:write"], creator),
        "Role Group",
        "grp-role",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let group_id: Uuid = body["group_id"].as_str().unwrap().parse().unwrap();

    let (status, body) = send(
        app(pool.clone()),
        Method::POST,
        &format!("/api/v1/groups/{group_id}/members"),
        Some(&token(&["groups:admin"], creator)),
        Some(json!({
            "agent_id": newcomer,
            "wrapped_key_share": wrapped_share("share-role"),
            // role deliberately omitted
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["role"], "reader");
}

#[sqlx::test(migrations = "../../migrations")]
async fn role_member_is_rejected_with_400(pool: PgPool) {
    // "member" was the pre-PR-01 default. It VIOLATES
    // group_memberships_role_check, so it used to be a 23514 -> HTTP 500.
    let creator = seed_agent(&pool, "member-creator").await;
    let newcomer = seed_agent(&pool, "member-newcomer").await;
    let (_, body) = create_group(
        &pool,
        &token(&["groups:write"], creator),
        "Member Group",
        "grp-member",
    )
    .await;
    let group_id: Uuid = body["group_id"].as_str().unwrap().parse().unwrap();

    let (status, _) = send(
        app(pool.clone()),
        Method::POST,
        &format!("/api/v1/groups/{group_id}/members"),
        Some(&token(&["groups:admin"], creator)),
        Some(json!({
            "agent_id": newcomer,
            "wrapped_key_share": wrapped_share("share-member"),
            "role": "member",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_four_role_vocabularies_agree(pool: PgPool) {
    // 1. The CHECK constraint.
    let def: (String,) = sqlx::query_as(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
         WHERE conname = 'group_memberships_role_check'",
    )
    .fetch_one(&pool)
    .await
    .expect("group_memberships_role_check must exist");
    for role in ["admin", "writer", "reader"] {
        assert!(
            def.0.contains(role),
            "CHECK must admit {role}; got {}",
            def.0
        );
    }
    assert!(
        !def.0.contains("creator") && !def.0.contains("member"),
        "CHECK must NOT admit creator/member; got {}",
        def.0
    );

    // 2. The column DEFAULT — least privilege.
    let dflt: (Option<String>,) = sqlx::query_as(
        "SELECT column_default FROM information_schema.columns \
         WHERE table_name = 'group_memberships' AND column_name = 'role'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        dflt.0.as_deref().unwrap_or("").contains("'reader'"),
        "column DEFAULT must be 'reader'; got {:?}",
        dflt.0
    );

    // 3. routes/groups.rs::valid_roles and its serde default.
    //
    // Anchored on the WHOLE `default_role` body, not a bare `"reader".to_string()`
    // substring: that literal appears anywhere in the file and would keep this
    // leg green after someone changed the default itself.
    let routes =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/routes/groups.rs"))
            .unwrap();
    assert!(
        routes.contains(r#"let valid_roles = ["admin", "writer", "reader"];"#),
        "routes/groups.rs::valid_roles must be exactly admin|writer|reader"
    );
    assert!(
        routes.contains("fn default_role() -> String {\n    \"reader\".to_string()\n}"),
        "routes/groups.rs::default_role must be exactly `\"reader\".to_string()`"
    );

    // 4. middleware/group_authz.rs accepts exactly "admin". Source inspection,
    //    because the branch it used to carry — `role_str != "creator"` — was
    //    unreachable and could not be caught by any runtime test.
    //
    //    Comments are STRIPPED before the negative check. The file's own doc
    //    comment already says "The group creator is stored as role=admin"; the
    //    unquoted form passed by luck, and one reviewer writing the word in
    //    quotes in a comment would have failed a test about executable code.
    let authz_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/middleware/group_authz.rs"
    ))
    .unwrap();
    let authz: String = authz_src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !authz.contains(r#""creator""#),
        "group_authz.rs code must not mention the unstorable role \"creator\""
    );
    assert!(
        !authz.contains(r#""writer""#) && !authz.contains(r#""reader""#),
        "group_authz.rs must gate on \"admin\" ALONE — a second accepted role here \
         would silently widen group administration"
    );
    assert!(
        authz.contains(r#"role_str != "admin""#),
        "group_authz.rs must gate on role == \"admin\""
    );
}

// =============================================================================
// 4. MEMBER REMOVAL
// =============================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn last_admin_cannot_be_removed(pool: PgPool) {
    let creator = seed_agent(&pool, "solo-admin").await;
    let (_, body) = create_group(
        &pool,
        &token(&["groups:write"], creator),
        "Solo",
        "grp-solo",
    )
    .await;
    let group_id: Uuid = body["group_id"].as_str().unwrap().parse().unwrap();

    // The creator is the group's ONLY admin. Removing them would leave the
    // group permanently unadministrable — require_group_admin is the only way
    // in and there is no break-glass path.
    let (status, _) = send(
        app(pool.clone()),
        Method::DELETE,
        &format!("/api/v1/groups/{group_id}/members/{creator}"),
        Some(&token(&["groups:admin"], creator)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Still a live admin.
    assert_eq!(
        GroupMembershipRepository::get_member_role(&pool, group_id, creator)
            .await
            .unwrap()
            .as_deref(),
        Some("admin")
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_admin_can_be_removed_once_a_second_admin_exists(pool: PgPool) {
    let creator = seed_agent(&pool, "first-admin").await;
    let second = seed_agent(&pool, "second-admin").await;
    let (_, body) = create_group(&pool, &token(&["groups:write"], creator), "Duo", "grp-duo").await;
    let group_id: Uuid = body["group_id"].as_str().unwrap().parse().unwrap();

    let admin = token(&["groups:admin"], creator);
    let (status, body) = send(
        app(pool.clone()),
        Method::POST,
        &format!("/api/v1/groups/{group_id}/members"),
        Some(&admin),
        Some(json!({
            "agent_id": second,
            "wrapped_key_share": wrapped_share("share-duo"),
            "role": "admin",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, _) = send(
        app(pool.clone()),
        Method::DELETE,
        &format!("/api/v1/groups/{group_id}/members/{creator}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[sqlx::test(migrations = "../../migrations")]
async fn removing_a_non_member_is_404(pool: PgPool) {
    let creator = seed_agent(&pool, "nm-creator").await;
    let stranger = seed_agent(&pool, "nm-stranger").await;
    let (_, body) = create_group(&pool, &token(&["groups:write"], creator), "NM", "grp-nm").await;
    let group_id: Uuid = body["group_id"].as_str().unwrap().parse().unwrap();

    // Previously a silent 204: remove_member discarded rows_affected().
    let (status, _) = send(
        app(pool.clone()),
        Method::DELETE,
        &format!("/api/v1/groups/{group_id}/members/{stranger}"),
        Some(&token(&["groups:admin"], creator)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// =============================================================================
// 5. READ AUTHORIZATION
// =============================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn get_group_is_401_anonymously_and_403_for_a_non_member(pool: PgPool) {
    let creator = seed_agent(&pool, "gg-creator").await;
    let stranger = seed_agent(&pool, "gg-stranger").await;
    let (_, body) = create_group(&pool, &token(&["groups:write"], creator), "GG", "grp-gg").await;
    let group_id: Uuid = body["group_id"].as_str().unwrap().parse().unwrap();
    let uri = format!("/api/v1/groups/{group_id}");

    // Anonymous: the route left the public router in PR-02.
    let (status, _) = send(app(pool.clone()), Method::GET, &uri, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Authenticated non-member: membership is the tenancy boundary.
    let (status, _) = send(
        app(pool.clone()),
        Method::GET,
        &uri,
        Some(&token(&["groups:read"], stranger)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Authenticated member without groups:read.
    let (status, _) = send(
        app(pool.clone()),
        Method::GET,
        &uri,
        Some(&token(&["claims:read"], creator)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The member, correctly scoped.
    let (status, body) = send(
        app(pool.clone()),
        Method::GET,
        &uri,
        Some(&token(&["groups:read"], creator)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["member_count"], 1);
    assert_eq!(body["current_epoch"], 0);
}

// =============================================================================
// 6. SCOPE GATES AND INPUT VALIDATION
// =============================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn group_writes_require_their_scopes(pool: PgPool) {
    let creator = seed_agent(&pool, "scope-creator").await;

    // create_group without groups:write — 403, and (issue #128) NOT a 422 from
    // Json parsing, because the scope extractor runs first.
    let (status, _) = send(
        app(pool.clone()),
        Method::POST,
        "/api/v1/groups",
        Some(&token(&["claims:read"], creator)),
        Some(json!({ "name": "Nope", "group_public_key": group_key("nope") })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (_, body) = create_group(
        &pool,
        &token(&["groups:write"], creator),
        "Scoped",
        "grp-scope",
    )
    .await;
    let group_id: Uuid = body["group_id"].as_str().unwrap().parse().unwrap();

    // add_member with groups:write but not groups:admin — scope AND membership.
    let other = seed_agent(&pool, "scope-other").await;
    let (status, _) = send(
        app(pool.clone()),
        Method::POST,
        &format!("/api/v1/groups/{group_id}/members"),
        Some(&token(&["groups:write"], creator)),
        Some(json!({
            "agent_id": other,
            "wrapped_key_share": wrapped_share("share-scope"),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // groups:admin but NOT a member of this group — the membership half.
    let (status, _) = send(
        app(pool.clone()),
        Method::POST,
        &format!("/api/v1/groups/{group_id}/members"),
        Some(&token(&["groups:admin"], other)),
        Some(json!({
            "agent_id": other,
            "wrapped_key_share": wrapped_share("share-scope2"),
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "groups:admin alone must not be enough — membership is also required"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn add_member_rejects_a_wrapped_share_that_is_not_60_bytes(pool: PgPool) {
    let creator = seed_agent(&pool, "ws-creator").await;
    let newcomer = seed_agent(&pool, "ws-newcomer").await;
    let (_, body) = create_group(&pool, &token(&["groups:write"], creator), "WS", "grp-ws").await;
    let group_id: Uuid = body["group_id"].as_str().unwrap().parse().unwrap();
    let admin = token(&["groups:admin"], creator);
    let uri = format!("/api/v1/groups/{group_id}/members");

    // A wrapped group key is exactly 12 (nonce) + 32 (key) + 16 (GCM tag).
    // EncryptedPayload::from_bytes alone only enforces >= 28, so 40 bytes would
    // have been stored and then failed to unwrap on the MEMBER's machine.
    for (label, share) in [
        (
            "too short (40 bytes, but parses as a payload)",
            hex::encode([7u8; 40]),
        ),
        ("too long (72 bytes)", hex::encode([7u8; 72])),
        (
            "below the payload minimum (16 bytes)",
            hex::encode([7u8; 16]),
        ),
        ("empty", String::new()),
    ] {
        let (status, _) = send(
            app(pool.clone()),
            Method::POST,
            &uri,
            Some(&admin),
            Some(json!({ "agent_id": newcomer, "wrapped_key_share": share })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "wrapped_key_share {label}");
    }

    // Non-hex is also a 400, not a 500.
    let (status, _) = send(
        app(pool.clone()),
        Method::POST,
        &uri,
        Some(&admin),
        Some(json!({ "agent_id": newcomer, "wrapped_key_share": "zzzz" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// =============================================================================
// 6. add_member CLIENT ERRORS ARE NOT 500s
// =============================================================================

/// Adding an agent who is already a live member violates the partial unique
/// index `group_memberships_one_live` (23505). That is a client error.
///
/// This is the same defect class `add_member`'s own `valid_roles` comment exists
/// to prevent — "anything this list admits and the CHECK rejects becomes a 23514
/// -> HTTP 500 instead of a 400" — and which `create_group` and `remove_member`
/// already handled while this handler mapped every `DbError` to a 500.
#[sqlx::test(migrations = "../../migrations")]
async fn adding_an_existing_member_twice_is_409_not_500(pool: PgPool) {
    let creator = seed_agent(&pool, "dup-creator").await;
    let newcomer = seed_agent(&pool, "dup-newcomer").await;
    let (_, body) = create_group(&pool, &token(&["groups:write"], creator), "Dup", "grp-dup").await;
    let group_id: Uuid = body["group_id"].as_str().unwrap().parse().unwrap();

    let admin = token(&["groups:admin"], creator);
    let payload = json!({
        "agent_id": newcomer,
        "wrapped_key_share": wrapped_share("share-dup"),
        "role": "reader",
    });

    let (status, body) = send(
        app(pool.clone()),
        Method::POST,
        &format!("/api/v1/groups/{group_id}/members"),
        Some(&admin),
        Some(payload.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = send(
        app(pool.clone()),
        Method::POST,
        &format!("/api/v1/groups/{group_id}/members"),
        Some(&admin),
        Some(payload),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

/// Naming an agent that does not exist violates
/// `group_memberships_agent_id_fkey` (23503) — a 404, not a 500.
#[sqlx::test(migrations = "../../migrations")]
async fn adding_an_unknown_agent_is_404_not_500(pool: PgPool) {
    let creator = seed_agent(&pool, "fk-creator").await;
    let (_, body) = create_group(&pool, &token(&["groups:write"], creator), "FK", "grp-fk").await;
    let group_id: Uuid = body["group_id"].as_str().unwrap().parse().unwrap();

    let (status, body) = send(
        app(pool.clone()),
        Method::POST,
        &format!("/api/v1/groups/{group_id}/members"),
        Some(&token(&["groups:admin"], creator)),
        Some(json!({
            "agent_id": Uuid::new_v4(),
            "wrapped_key_share": wrapped_share("share-fk"),
            "role": "reader",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

/// `groups.created_by_agent_id` FKs to `agents`, and the creator comes straight
/// from the token. A hand-minted token naming no agent row raised 23503 -> 500;
/// it is a 403, the same answer the `agent_id: None` guard already gives.
#[sqlx::test(migrations = "../../migrations")]
async fn creating_a_group_with_an_unknown_agent_principal_is_403_not_500(pool: PgPool) {
    let (status, body) = send(
        app(pool.clone()),
        Method::POST,
        "/api/v1/groups",
        Some(&token(&["groups:write"], Uuid::new_v4())),
        Some(json!({
            "name": "Ghost",
            "group_public_key": hex::encode(*blake3::hash(b"grp-ghost").as_bytes()),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

// =============================================================================
// 7. THE LAST-ADMIN GUARD IS ONE STATEMENT
// =============================================================================

/// Two concurrent removals of the group's only two admins must not both
/// succeed.
///
/// The guard used to be `get_member_role` -> `count_live_admins_excluding` ->
/// `remove_member`: three round-trips on the pool, no transaction. With admins A
/// and B, each request saw ONE other admin, both passed, and both revoked —
/// leaving zero admins and a permanently unadministrable group, which is exactly
/// what the guard exists to prevent. The in-code comment claimed the two
/// removals bounded each other; they do not, precisely because each sees the
/// other.
///
/// `revoke_member_unless_last_admin` folds the count into the writing `UPDATE`,
/// so the loser re-evaluates its subquery against the winner's committed state
/// under READ COMMITTED and finds no other live admin.
#[sqlx::test(migrations = "../../migrations")]
async fn two_concurrent_admin_removals_cannot_strand_a_group(pool: PgPool) {
    let a = seed_agent(&pool, "race-admin-a").await;
    let b = seed_agent(&pool, "race-admin-b").await;
    let (_, body) = create_group(&pool, &token(&["groups:write"], a), "Race", "grp-race").await;
    let group_id: Uuid = body["group_id"].as_str().unwrap().parse().unwrap();

    let admin = token(&["groups:admin"], a);
    let (status, body) = send(
        app(pool.clone()),
        Method::POST,
        &format!("/api/v1/groups/{group_id}/members"),
        Some(&admin),
        Some(json!({
            "agent_id": b,
            "wrapped_key_share": wrapped_share("share-race"),
            "role": "admin",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // A removes B while B removes A.
    let (ra, rb) = tokio::join!(
        epigraph_db::GroupMembershipRepository::revoke_member_unless_last_admin(&pool, group_id, b),
        epigraph_db::GroupMembershipRepository::revoke_member_unless_last_admin(&pool, group_id, a),
    );
    let ra = ra.expect("revoke a->b");
    let rb = rb.expect("revoke b->a");

    assert!(
        !(ra == epigraph_db::RevokeOutcome::Revoked && rb == epigraph_db::RevokeOutcome::Revoked),
        "both removals succeeded: the group now has zero admins ({ra:?} / {rb:?})"
    );

    let survivors = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM group_memberships \
         WHERE group_id = $1 AND role = 'admin' AND revoked_at IS NULL",
    )
    .bind(group_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(survivors, 1, "exactly one admin must survive");
}

/// `count_live_admins_excluding` is no longer used by the removal guard (a
/// second snapshot is what made the guard racy) but survives for PR-18's
/// privatization approver check, which needs "≥ 2 live admins other than the
/// plan author" as a read-only precondition. Pinned so the next reader does not
/// find it callerless and delete it.
#[sqlx::test(migrations = "../../migrations")]
async fn count_live_admins_excluding_ignores_the_excluded_and_the_revoked(pool: PgPool) {
    let a = seed_agent(&pool, "count-a").await;
    let b = seed_agent(&pool, "count-b").await;
    let c = seed_agent(&pool, "count-c").await;
    let (_, body) = create_group(&pool, &token(&["groups:write"], a), "Count", "grp-count").await;
    let group_id: Uuid = body["group_id"].as_str().unwrap().parse().unwrap();

    let admin = token(&["groups:admin"], a);
    for (agent, role, seed) in [(b, "admin", "s-b"), (c, "reader", "s-c")] {
        let (status, body) = send(
            app(pool.clone()),
            Method::POST,
            &format!("/api/v1/groups/{group_id}/members"),
            Some(&admin),
            Some(json!({
                "agent_id": agent,
                "wrapped_key_share": wrapped_share(seed),
                "role": role,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    // Excluding A leaves B (admin); C is a reader and does not count.
    assert_eq!(
        GroupMembershipRepository::count_live_admins_excluding(&pool, group_id, a)
            .await
            .unwrap(),
        1
    );

    // Revoking B leaves none.
    sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(group_id)
    .bind(b)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        GroupMembershipRepository::count_live_admins_excluding(&pool, group_id, a)
            .await
            .unwrap(),
        0
    );
}
