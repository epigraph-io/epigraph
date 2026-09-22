#![cfg(feature = "db")]
//! PR-20 — atomic key rotation, and the obligation a member removal leaves.
//!
//! Everything here drives the real router (`create_router`), so the extractor
//! ordering, the scope gates, `bearer_auth_middleware` and the group-admin
//! membership check are all in the path.
//!
//! # Why the state is built from a `ScopedPool`
//!
//! `POST /api/v1/groups/:id/rotate` runs its whole body on
//! `ScopedPool::begin_as`, which `AppState::with_db` cannot supply — `scoped`
//! is `None` there and the handler REFUSES rather than falling back to the raw
//! pool. `with_scoped_pool` sets `db_pool = scoped.inner()` over the same
//! `#[sqlx::test]` database, so the other four group routes and the raw seeding
//! below are unaffected.
//!
//! # Why these fixtures are duplicated from `group_lifecycle.rs`
//!
//! Deliberately, and it is the in-tree precedent: that file's own `token()`
//! says it was inlined rather than pull in the shared fixture module for one
//! function. Extracting the six helpers into `tests/common/mod.rs` would put
//! this PR's diff on top of `two_concurrent_admin_removals_cannot_strand_a_group`,
//! the highest-risk existing test on the surface PR-20 changes.
//!
//! # The split with `epigraph-privacy`
//!
//! The acceptance clause "a revoked member's retained share still decrypts
//! pre-rotation ciphertext" is asserted in
//! `crates/epigraph-privacy/src/encryptor.rs`, inline, because reaching those
//! primitives from here would need an `epigraph-privacy` dev-dependency and the
//! deferred obligation `D-PR19-B` proposes a ratchet requiring `epigraph-api` to
//! exclude that crate from its closure. This file carries the HTTP and
//! transactional half, none of which needs the crypto.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use epigraph_api::tenancy_disclosure::ROTATION_DOES_NOT_REVOKE_PAST_ACCESS;
use epigraph_api::{create_router, ApiConfig, AppState};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

mod viewer_fixture;

// =============================================================================
// FIXTURES
// =============================================================================

async fn app(pool: &PgPool) -> axum::Router {
    create_router(AppState::with_scoped_pool(
        viewer_fixture::scoped_pool(pool).await,
        ApiConfig::default(),
    ))
}

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

fn group_key(seed: &str) -> String {
    hex::encode(blake3::hash(seed.as_bytes()).as_bytes())
}

/// A structurally valid wrapped key share: 60 bytes (12-byte nonce + 32-byte
/// wrapped key + 16-byte GCM tag). Opaque to the server, which never unwraps —
/// but the SHAPE is enforced at the boundary, by `add_member` and now by
/// `rotate_key`.
fn wrapped_share(seed: &str) -> String {
    let mut bytes = Vec::with_capacity(60);
    bytes.extend_from_slice(blake3::hash(seed.as_bytes()).as_bytes());
    bytes.extend_from_slice(&blake3::hash(seed.as_bytes()).as_bytes()[..28]);
    assert_eq!(bytes.len(), 60);
    hex::encode(bytes)
}

/// Create a group and add one non-admin member. Returns
/// `(group_id, creator_agent, member_agent, admin_token)`.
///
/// The creator's own membership row carries `wrapped_key_share = ''::bytea` by
/// construction (`GroupRepository::create_with_admin` — they generated the base
/// key and had nothing to wrap), which is exactly why the rotation assertions
/// below check the creator's row too.
async fn group_with_two_members(pool: &PgPool, seed: &str) -> (Uuid, Uuid, Uuid, String) {
    let creator = seed_agent(pool, &format!("{seed}-creator")).await;
    let member = seed_agent(pool, &format!("{seed}-member")).await;

    let writer = token(&["groups:write", "groups:admin", "groups:read"], creator);
    let (status, body) = send(
        app(pool).await,
        Method::POST,
        "/api/v1/groups",
        Some(&writer),
        Some(json!({ "name": seed, "group_public_key": group_key(seed) })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create_group: {body}");
    let group_id: Uuid = body["group_id"].as_str().unwrap().parse().unwrap();

    let (status, body) = send(
        app(pool).await,
        Method::POST,
        &format!("/api/v1/groups/{group_id}/members"),
        Some(&writer),
        Some(json!({
            "agent_id": member,
            "wrapped_key_share": wrapped_share(&format!("{seed}-member-share")),
            "role": "writer",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "add_member: {body}");

    (group_id, creator, member, writer)
}

/// A rotation body that re-wraps every live member. `shares` must cover the
/// roster exactly or the route refuses.
///
/// The body carries shares and NOTHING else: the request has no escrow field.
/// The recoverability gate is satisfied out of band — by a `wrapped_key` already
/// on the epoch row ([`escrow_epoch`]) or by a `kms_key_ref` on the group
/// ([`make_recoverable`]) — because a gate a caller can satisfy with a value the
/// server cannot check is not a gate.
fn rotation_for(members: &[Uuid], seed: &str) -> Value {
    let shares: Vec<Value> = members
        .iter()
        .enumerate()
        .map(|(i, agent_id)| {
            json!({
                "agent_id": agent_id,
                "wrapped_key_share": wrapped_share(&format!("{seed}-rotated-{i}")),
            })
        })
        .collect();
    json!({ "shares": shares })
}

/// Satisfy the gate's SECOND disjunct: an external escrow reference on the
/// group. Merged into `properties` rather than replacing it, so a group that
/// carries other properties is not silently stripped of them by a fixture.
async fn make_recoverable(pool: &PgPool, group_id: Uuid) {
    sqlx::query(
        "UPDATE groups
            SET properties = COALESCE(properties, '{}'::jsonb)
                             || jsonb_build_object('kms_key_ref', $2::text)
          WHERE id = $1",
    )
    .bind(group_id)
    .bind("arn:example:key/epoch-escrow")
    .execute(pool)
    .await
    .expect("seed kms_key_ref");
}

/// Satisfy the gate's FIRST disjunct: a `wrapped_key` already present on the
/// epoch row that is about to be retired.
///
/// Seeded by raw SQL, and that is the point rather than a shortcut. Nothing in
/// the tree writes this column — `create_with_admin` leaves it NULL and the
/// rotate route takes no key material — so a group under FINAL-PLAN §5.4's
/// custody model (1) or (2) reaches this state through its KMS/HSM provisioning
/// and not through the API. The disjunct is still specified and still enforced,
/// so it is still tested.
async fn escrow_epoch(pool: &PgPool, group_id: Uuid, epoch: i32, key: &[u8]) {
    let n = sqlx::query(
        "UPDATE group_key_epochs SET wrapped_key = $3 WHERE group_id = $1 AND epoch = $2",
    )
    .bind(group_id)
    .bind(epoch)
    .bind(key)
    .execute(pool)
    .await
    .expect("seed epoch escrow")
    .rows_affected();
    assert_eq!(
        n, 1,
        "the fixture must find the epoch row it claims to seed"
    );
}

async fn epoch_statuses(pool: &PgPool, group_id: Uuid) -> Vec<(i32, String)> {
    sqlx::query_as("SELECT epoch, status FROM group_key_epochs WHERE group_id = $1 ORDER BY epoch")
        .bind(group_id)
        .fetch_all(pool)
        .await
        .expect("read epoch rows")
}

async fn live_shares(pool: &PgPool, group_id: Uuid) -> Vec<(Uuid, i32, i32)> {
    sqlx::query_as(
        "SELECT agent_id, epoch, octet_length(wrapped_key_share)::int
         FROM group_memberships
         WHERE group_id = $1 AND revoked_at IS NULL
         ORDER BY agent_id",
    )
    .bind(group_id)
    .fetch_all(pool)
    .await
    .expect("read live memberships")
}

// =============================================================================
// 1. THE GATE — both disjuncts and the refusal
// =============================================================================

/// A group created through the normal path escrows nothing: `create_with_admin`
/// writes `wrapped_key = NULL` on epoch 0 because the server holds no key
/// material. Retiring that epoch would leave everything sealed under it
/// permanently unreadable, so the rotation refuses.
#[sqlx::test(migrations = "../../migrations")]
async fn rotation_is_refused_when_the_retiring_epochs_key_is_not_recoverable(pool: PgPool) {
    let (group_id, creator, member, admin) = group_with_two_members(&pool, "gate-refusal").await;

    let (status, body) = send(
        app(&pool).await,
        Method::POST,
        &format!("/api/v1/groups/{group_id}/rotate"),
        Some(&admin),
        Some(rotation_for(&[creator, member], "gate-refusal")),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "an unrecoverable retiring epoch must be refused, not rotated: {body}"
    );

    assert_eq!(
        epoch_statuses(&pool, group_id).await,
        vec![(0, "active".to_string())],
        "the refusal must leave the epoch state exactly as it was — no retired row, no N+1"
    );
}

/// First disjunct: `wrapped_key IS NOT NULL` on the retiring epoch.
///
/// The rotation neither reads nor writes that value — it only asks whether it is
/// there. The assertions below pin both halves of that: the escrow on the
/// RETIRED row survives the rotation byte for byte, and the incoming epoch is
/// created with none.
#[sqlx::test(migrations = "../../migrations")]
async fn an_epoch_that_already_carries_a_wrapped_key_satisfies_the_gate(pool: PgPool) {
    let (group_id, creator, member, admin) = group_with_two_members(&pool, "gate-escrow").await;
    escrow_epoch(&pool, group_id, 0, &[0xABu8; 48]).await;

    let (status, body) = send(
        app(&pool).await,
        Method::POST,
        &format!("/api/v1/groups/{group_id}/rotate"),
        Some(&admin),
        Some(rotation_for(&[creator, member], "gate-escrow")),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "rotate: {body}");
    assert_eq!(body["previous_epoch"], 0);
    assert_eq!(body["new_epoch"], 1);
    assert_eq!(body["members_rewrapped"], 2);

    // EXACTLY ONE ACTIVE EPOCH. `group_key_epochs_one_active` is a partial
    // unique index, so the schema enforces "at most one" and never "at least
    // one"; the `= 1` half is this assertion's job and it is what catches a
    // rotation that retired N without creating N+1.
    assert_eq!(
        epoch_statuses(&pool, group_id).await,
        vec![(0, "retired".to_string()), (1, "active".to_string())],
        "retire N, create N+1, and nothing else"
    );

    let escrowed: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT wrapped_key FROM group_key_epochs WHERE group_id = $1 AND epoch = 0",
    )
    .bind(group_id)
    .fetch_one(&pool)
    .await
    .expect("read retired epoch");
    assert_eq!(
        escrowed,
        Some(vec![0xABu8; 48]),
        "the escrow on the retired row is what the gate READ; the rotation must leave it \
         untouched rather than moving, clearing or overwriting it"
    );

    let incoming: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT wrapped_key FROM group_key_epochs WHERE group_id = $1 AND epoch = 1",
    )
    .bind(group_id)
    .fetch_one(&pool)
    .await
    .expect("read new epoch");
    assert!(
        incoming.is_none(),
        "the server holds no key material for the epoch it just created"
    );

    // EVERY live member carries a real share at N+1 — including the creator,
    // whose epoch-0 row was `''::bytea` because they minted the base key and
    // had nothing to wrap. At N+1 there IS something to wrap.
    let rows = live_shares(&pool, group_id).await;
    assert_eq!(rows.len(), 2, "both members are still live");
    for (agent_id, epoch, share_len) in rows {
        assert_eq!(epoch, 1, "{agent_id} was not advanced to the new epoch");
        assert_eq!(
            share_len, 60,
            "{agent_id} must hold a full 60-byte wrapped share at the new epoch; the creator's \
             empty epoch-0 share is normalised by the rotation rather than carried forward"
        );
    }
}

/// Second disjunct: `groups.properties->>'kms_key_ref'`. Seeded by raw SQL —
/// nothing in the tree writes that key yet, which is itself worth recording.
///
/// This is the production satisfier. FINAL-PLAN §5.4 says
/// `group_key_epochs.wrapped_key` stays NULL under both production custody
/// models by design, so for a real group this disjunct, and not the first one,
/// is what opens the gate.
#[sqlx::test(migrations = "../../migrations")]
async fn a_kms_key_ref_satisfies_the_gate_with_no_escrow_on_the_epoch(pool: PgPool) {
    let (group_id, creator, member, admin) = group_with_two_members(&pool, "gate-kms").await;

    make_recoverable(&pool, group_id).await;

    let (status, body) = send(
        app(&pool).await,
        Method::POST,
        &format!("/api/v1/groups/{group_id}/rotate"),
        Some(&admin),
        Some(rotation_for(&[creator, member], "gate-kms")),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "an external escrow reference makes the retiring epoch recoverable: {body}"
    );
    assert_eq!(
        epoch_statuses(&pool, group_id).await,
        vec![(0, "retired".to_string()), (1, "active".to_string())]
    );
}

// =============================================================================
// 2. THE ROSTER CONTRACT
// =============================================================================

/// An epoch advance that skipped a live member would leave them holding a share
/// for a retired epoch — an accidental removal dressed as a key change. The
/// refusal is whole: the transaction rolls back and the epoch state is
/// untouched.
#[sqlx::test(migrations = "../../migrations")]
async fn a_rotation_that_misses_a_live_member_is_refused_and_changes_nothing(pool: PgPool) {
    let (group_id, creator, _member, admin) = group_with_two_members(&pool, "roster-short").await;
    // The gate is opened first, so the 400 below is the ROSTER refusing and not
    // the gate refusing earlier for an unrelated reason.
    make_recoverable(&pool, group_id).await;

    let (status, body) = send(
        app(&pool).await,
        Method::POST,
        &format!("/api/v1/groups/{group_id}/rotate"),
        Some(&admin),
        Some(rotation_for(&[creator], "roster-short")),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a partial roster must be refused, not partially applied: {body}"
    );
    assert_eq!(
        epoch_statuses(&pool, group_id).await,
        vec![(0, "active".to_string())],
        "the rolled-back transaction leaves exactly one active epoch — not zero, not two"
    );
    for (agent_id, epoch, _) in live_shares(&pool, group_id).await {
        assert_eq!(epoch, 0, "{agent_id} must not have been advanced");
    }
}

/// A share naming somebody who is not a live member is refused too. The
/// symmetric direction matters: without it, "covers the roster" could be
/// satisfied by a superset and the operator would never learn they had wrapped
/// the new key for the person they just removed.
#[sqlx::test(migrations = "../../migrations")]
async fn a_rotation_naming_a_non_member_is_refused(pool: PgPool) {
    let (group_id, creator, member, admin) = group_with_two_members(&pool, "roster-extra").await;
    let outsider = seed_agent(&pool, "roster-extra-outsider").await;
    make_recoverable(&pool, group_id).await;

    let (status, body) = send(
        app(&pool).await,
        Method::POST,
        &format!("/api/v1/groups/{group_id}/rotate"),
        Some(&admin),
        Some(rotation_for(&[creator, member, outsider], "roster-extra")),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a share for a non-member must be refused: {body}"
    );
    assert_eq!(
        epoch_statuses(&pool, group_id).await,
        vec![(0, "active".to_string())]
    );
}

/// The roster check is a SET difference, and a set is exactly what hides a
/// duplicate: `[A, A, B]` against a live roster of `{A, B}` collapses to
/// `{A, B}` and satisfies "covers the roster exactly". Two contradictory shares
/// for one member would then both be written, the last one silently winning, and
/// the reported re-wrap count would exceed the roster.
///
/// Two DIFFERENT shares for the duplicated agent, deliberately: a test that sent
/// the same bytes twice would pass even if the server picked one arbitrarily,
/// and so would not measure the ambiguity.
#[sqlx::test(migrations = "../../migrations")]
async fn a_rotation_naming_one_member_twice_is_refused(pool: PgPool) {
    let (group_id, creator, member, admin) = group_with_two_members(&pool, "dup").await;
    make_recoverable(&pool, group_id).await;

    let body = json!({
        "shares": [
            { "agent_id": creator, "wrapped_key_share": wrapped_share("dup-creator") },
            { "agent_id": member,  "wrapped_key_share": wrapped_share("dup-member-a") },
            { "agent_id": member,  "wrapped_key_share": wrapped_share("dup-member-b") },
        ]
    });

    let (status, resp) = send(
        app(&pool).await,
        Method::POST,
        &format!("/api/v1/groups/{group_id}/rotate"),
        Some(&admin),
        Some(body),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a duplicated agent is two answers to one question, not a submission to disambiguate: \
         {resp}"
    );
    assert_eq!(
        epoch_statuses(&pool, group_id).await,
        vec![(0, "active".to_string())],
        "the refusal must leave the epoch state exactly as it was"
    );
    for (agent_id, epoch, _) in live_shares(&pool, group_id).await {
        assert_eq!(epoch, 0, "{agent_id} must not have been advanced");
    }
}

/// Scope AND membership, never OR — the invariant the whole module header
/// states. A `groups:admin` token that is not an admin of THIS group is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn a_groups_admin_token_cannot_rotate_a_group_it_does_not_administer(pool: PgPool) {
    let (group_id, creator, member, _admin) = group_with_two_members(&pool, "authz").await;
    let stranger = seed_agent(&pool, "authz-stranger").await;
    let stranger_token = token(&["groups:admin", "groups:read", "groups:write"], stranger);
    make_recoverable(&pool, group_id).await;

    let (status, body) = send(
        app(&pool).await,
        Method::POST,
        &format!("/api/v1/groups/{group_id}/rotate"),
        Some(&stranger_token),
        Some(rotation_for(&[creator, member], "authz")),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the scope says the token class may manage groups; the membership says which ones: {body}"
    );
    assert_eq!(
        epoch_statuses(&pool, group_id).await,
        vec![(0, "active".to_string())]
    );
}

// =============================================================================
// 3. WHAT A MEMBER REMOVAL MARKS
// =============================================================================

/// FINAL-PLAN §6.7 point 2, end to end: the removal sets
/// `groups.reseal_required_at`, moves the epoch to `rotating`, and
/// `GET /groups/:id` surfaces the obligation.
///
/// It also pins the consequence of the `rotating` mark that the plan does not
/// state: the group stays USABLE. `get_current_epoch` treats `rotating` as
/// current, so `current_epoch` is still reported and `add_member` still works.
/// A removal records a debt; it does not brick the group until someone rotates.
#[sqlx::test(migrations = "../../migrations")]
async fn removing_a_member_marks_the_reseal_obligation_without_disabling_the_group(pool: PgPool) {
    let (group_id, creator, member, admin) = group_with_two_members(&pool, "removal-mark").await;

    let (status, body) = send(
        app(&pool).await,
        Method::GET,
        &format!("/api/v1/groups/{group_id}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get_group: {body}");
    assert_eq!(
        body["reseal_required_at"],
        Value::Null,
        "CALIBRATION: nothing is owed before the removal, or the assertion below measures nothing"
    );
    assert_eq!(body["current_epoch"], 0);

    let (status, _) = send(
        app(&pool).await,
        Method::DELETE,
        &format!("/api/v1/groups/{group_id}/members/{member}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, body) = send(
        app(&pool).await,
        Method::GET,
        &format!("/api/v1/groups/{group_id}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get_group: {body}");
    assert!(
        body["reseal_required_at"].is_string(),
        "the removal must surface a re-key obligation on GET /groups/:id: {body}"
    );
    assert_eq!(
        body["current_epoch"], 0,
        "the group keeps a current epoch while the obligation is outstanding; a removal that \
         emptied it would make the group refuse new members and new encrypted claims"
    );
    assert_eq!(body["member_count"], 1);

    assert_eq!(
        epoch_statuses(&pool, group_id).await,
        vec![(0, "rotating".to_string())],
        "the mark goes on the EPOCH row: groups_status_check admits only \
         active|suspended|deprovisioned, group_key_epochs_status_check admits rotating"
    );

    // The group is still usable: a new member can be added at the current
    // epoch even though a rotation is owed.
    let newcomer = seed_agent(&pool, "removal-mark-newcomer").await;
    let (status, body) = send(
        app(&pool).await,
        Method::POST,
        &format!("/api/v1/groups/{group_id}/members"),
        Some(&admin),
        Some(json!({
            "agent_id": newcomer,
            "wrapped_key_share": wrapped_share("removal-mark-newcomer-share"),
            "role": "reader",
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a pending rotation is a debt, not an outage: {body}"
    );

    // And the rotation that discharges the re-key still works from `rotating`.
    make_recoverable(&pool, group_id).await;
    let (status, body) = send(
        app(&pool).await,
        Method::POST,
        &format!("/api/v1/groups/{group_id}/rotate"),
        Some(&admin),
        Some(rotation_for(&[creator, newcomer], "removal-mark")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rotate from `rotating`: {body}");
    assert_eq!(
        epoch_statuses(&pool, group_id).await,
        vec![(0, "retired".to_string()), (1, "active".to_string())]
    );
}

/// Rotation does NOT clear `reseal_required_at`, and that is deliberate: the
/// claims sealed under the retired epoch are still sealed under it. FINAL-PLAN
/// §6.7 point 3 gives the clearing to the re-seal handler, when the last
/// `claim_encryption` row has actually moved.
///
/// Written as an assertion rather than a comment because "the rotation finished,
/// so the obligation is discharged" is exactly the simplification a later change
/// would make.
#[sqlx::test(migrations = "../../migrations")]
async fn rotation_does_not_clear_the_reseal_obligation(pool: PgPool) {
    let (group_id, creator, member, admin) = group_with_two_members(&pool, "not-cleared").await;

    let (status, _) = send(
        app(&pool).await,
        Method::DELETE,
        &format!("/api/v1/groups/{group_id}/members/{member}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let marked_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT reseal_required_at FROM groups WHERE id = $1")
            .bind(group_id)
            .fetch_one(&pool)
            .await
            .expect("read mark");
    let marked_at = marked_at.expect("the removal marks the group");

    make_recoverable(&pool, group_id).await;
    let (status, body) = send(
        app(&pool).await,
        Method::POST,
        &format!("/api/v1/groups/{group_id}/rotate"),
        Some(&admin),
        Some(rotation_for(&[creator], "not-cleared")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rotate: {body}");

    let after: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT reseal_required_at FROM groups WHERE id = $1")
            .bind(group_id)
            .fetch_one(&pool)
            .await
            .expect("read mark");
    assert_eq!(
        after,
        Some(marked_at),
        "rotation gates future ciphertext only; the re-seal obligation survives it, unchanged"
    );
}

/// The mark dates from the FIRST unrotated removal. A bare `now()` would restart
/// the clock on every subsequent removal, so a group with steady membership
/// churn could never age past the seven days the
/// `epigraph_groups_reseal_required` gauge measures — the groups most in need of
/// the alert would be the ones excluded from it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_second_removal_does_not_restart_the_obligations_clock(pool: PgPool) {
    let (group_id, _creator, member, admin) = group_with_two_members(&pool, "clock").await;
    let second = seed_agent(&pool, "clock-second").await;

    let (status, body) = send(
        app(&pool).await,
        Method::POST,
        &format!("/api/v1/groups/{group_id}/members"),
        Some(&admin),
        Some(json!({
            "agent_id": second,
            "wrapped_key_share": wrapped_share("clock-second-share"),
            "role": "reader",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "add second member: {body}");

    let (status, _) = send(
        app(&pool).await,
        Method::DELETE,
        &format!("/api/v1/groups/{group_id}/members/{member}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let first: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT reseal_required_at FROM groups WHERE id = $1")
            .bind(group_id)
            .fetch_one(&pool)
            .await
            .expect("read mark");

    // Backdate, so a preserved timestamp is distinguishable from a refreshed
    // one without depending on clock resolution between two fast requests.
    sqlx::query("UPDATE groups SET reseal_required_at = now() - interval '30 days' WHERE id = $1")
        .bind(group_id)
        .execute(&pool)
        .await
        .expect("backdate mark");

    let (status, _) = send(
        app(&pool).await,
        Method::DELETE,
        &format!("/api/v1/groups/{group_id}/members/{second}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let after: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT reseal_required_at FROM groups WHERE id = $1")
            .bind(group_id)
            .fetch_one(&pool)
            .await
            .expect("read mark");
    let after = after.expect("still marked");
    assert!(
        after < chrono::Utc::now() - chrono::Duration::days(29),
        "the second removal restarted the clock: {first:?} -> {after:?}"
    );
}

/// The gauge query behind `epigraph_groups_reseal_required`. The age clause is
/// an explicit acceptance item and is the easiest thing in this PR to drop, so
/// it is asserted in both directions.
#[sqlx::test(migrations = "../../migrations")]
async fn the_reseal_gauge_counts_only_obligations_older_than_its_window(pool: PgPool) {
    let (group_id, _creator, member, admin) = group_with_two_members(&pool, "gauge").await;

    assert_eq!(
        epigraph_db::GroupRepository::count_reseal_required_older_than(&pool, 7)
            .await
            .expect("count"),
        0,
        "CALIBRATION: nothing is owed yet"
    );

    let (status, _) = send(
        app(&pool).await,
        Method::DELETE,
        &format!("/api/v1/groups/{group_id}/members/{member}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert_eq!(
        epigraph_db::GroupRepository::count_reseal_required_older_than(&pool, 7)
            .await
            .expect("count"),
        0,
        "a FRESH obligation is a normal operational state and must not be counted; a gauge that \
         fires on every removal is a gauge somebody mutes"
    );

    sqlx::query("UPDATE groups SET reseal_required_at = now() - interval '8 days' WHERE id = $1")
        .bind(group_id)
        .execute(&pool)
        .await
        .expect("age the mark");

    assert_eq!(
        epigraph_db::GroupRepository::count_reseal_required_older_than(&pool, 7)
            .await
            .expect("count"),
        1,
        "an obligation past the window is what the gauge exists to report"
    );
}

// =============================================================================
// 4. THE DISCLOSURE — one constant, three readers
// =============================================================================

/// FINAL-PLAN §6.7 point 1 requires the sentence VERBATIM in three places, and
/// nothing in the tree previously stopped three copies from drifting. This is
/// the positive twin of `no_redaction_sentinel.rs`: that file asserts a spelling
/// must never appear, this one asserts a spelling must always appear.
///
/// Two of the three are the constant by construction (the response types hold
/// `&'static str`), so those are asserted on the wire. The third lives in prose
/// and is asserted against the file on disk.
#[sqlx::test(migrations = "../../migrations")]
async fn the_revocation_disclosure_is_verbatim_in_all_three_places(pool: PgPool) {
    // 1. The rotate response body.
    let (group_id, creator, member, admin) = group_with_two_members(&pool, "disclosure").await;
    make_recoverable(&pool, group_id).await;
    let (status, body) = send(
        app(&pool).await,
        Method::POST,
        &format!("/api/v1/groups/{group_id}/rotate"),
        Some(&admin),
        Some(rotation_for(&[creator, member], "disclosure")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rotate: {body}");
    assert_eq!(
        body["revocation"].as_str(),
        Some(ROTATION_DOES_NOT_REVOKE_PAST_ACCESS),
        "the caller most likely to believe they have just revoked something is told, in the same \
         response, that they have not"
    );

    // 2. `docs/tenancy.md`, read from disk.
    let doc = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/tenancy.md"),
    )
    .expect("docs/tenancy.md is readable");
    assert!(
        doc.contains(ROTATION_DOES_NOT_REVOKE_PAST_ACCESS),
        "docs/tenancy.md must carry the sentence VERBATIM — not paraphrased, not re-worded for \
         flow. A disclosure that drifts is a disclosure that stops being read."
    );

    // 3. The privatization preview's `side_effects.revocation`, asserted here on
    //    the SOURCE and, separately, on the SERIALIZED preview by
    //    `privatization_routes.rs::a_preview_counts_what_the_actor_cannot_read_and_names_only_what_it_can`,
    //    which already builds the D4 selection this needs.
    //
    //    Both, because they fail on different things. This one catches a fourth
    //    literal copy of the sentence — a copy that drifts is the failure mode
    //    the shared constant exists to prevent, and a wire assertion cannot see
    //    the difference between the constant and a literal equal to it. The
    //    serialization assertion catches the field ceasing to REACH the wire: a
    //    rename, a `#[serde(skip)]`, or `side_effects` dropping out of the
    //    response would leave this source line intact and green.
    //
    //    An earlier revision of this comment justified asserting only the
    //    source on the grounds that driving `create_plan` was too expensive a
    //    fixture. That was false — the fixture already existed — and it is
    //    recorded here rather than quietly deleted.
    let preview_src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/routes/privatization.rs"),
    )
    .expect("routes/privatization.rs is readable");
    assert!(
        preview_src.contains(
            "revocation: crate::tenancy_disclosure::ROTATION_DOES_NOT_REVOKE_PAST_ACCESS"
        ),
        "the preview's side_effects.revocation must be the shared constant, not a fourth copy \
         of the sentence"
    );
}
