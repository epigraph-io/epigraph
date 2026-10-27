#![cfg(feature = "db")]
//! The group management routes on the APPLICATION ROLE (backlog 323773fe).
//!
//! `group_lifecycle.rs` and `group_rotation.rs` drive these routes on the test
//! superuser, which bypasses row security, so they prove the handlers' own
//! checks and nothing about the database. Here both pools of the `AppState`
//! are `epigraph_app` (no BYPASSRLS, the group tables' `*_tenancy` policies
//! FORCEd), as in production. A route that still reads or writes on the raw,
//! unstamped pool sees no group row and no membership there, so:
//!
//! * `POST /api/v1/groups` is refused by `groups_tenancy`'s `WITH CHECK`
//!   (500), and
//! * `POST /api/v1/groups/:id/members`, `DELETE
//!   /api/v1/groups/:id/members/:agent_id` and `GET /api/v1/groups/:id` answer
//!   a real admin or member 403 "Not a member of this group".
//!
//! Every success arm below fails on that shape, and the refusals pin that the
//! stamped routes still refuse the callers they must. The success arms cover
//! callers who did NOT create the group (a second admin, a plain reader) as
//! well as the creator, because `groups_tenancy` has creator-only arms that a
//! creator-only test would pass through. A non-creator admin's removal marks
//! the re-key obligation through migration 181's narrow definer (ruling R-56 on
//! backlog 323773fe), and every refusal the database makes on that route is a
//! clean 403, not a 500.
//!
//! Fixtures are seeded and read back on the superuser `#[sqlx::test]` pool.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_db::{GroupRepository, ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

mod viewer_fixture;

async fn app_role_router(pool: &PgPool) -> axum::Router {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    // The table owner is not the application role, but row security is still
    // pinned ENABLED and FORCED on the three tables these routes touch, so an
    // arm cannot pass because a policy was switched off.
    for table in ["groups", "group_memberships", "group_key_epochs"] {
        let (enabled, forced): (bool, bool) = sqlx::query_as(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class \
              WHERE relnamespace = 'public'::regnamespace AND relname = $1",
        )
        .bind(table)
        .fetch_one(pool)
        .await
        .expect("read row security flags");
        assert!(
            enabled && forced,
            "{table}: row security enabled={enabled} forced={forced}; every arm here is vacuous"
        );
    }
    let url = viewer_fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = viewer_fixture::downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    create_router(state)
}

async fn seed_agent(pool: &PgPool, name: &str) -> Uuid {
    let key: [u8; 32] = *blake3::hash(name.as_bytes()).as_bytes();
    sqlx::query_scalar("INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id")
        .bind(key.as_slice())
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("seed agent")
}

fn token(agent_id: Uuid) -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (t, _jti) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            vec![
                "groups:write".to_string(),
                "groups:admin".to_string(),
                "groups:read".to_string(),
            ],
            "agent",
            None,
            Some(agent_id),
            chrono::Duration::minutes(60),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("test JWT issued");
    t
}

async fn send(
    app: axum::Router,
    method: Method,
    uri: &str,
    as_agent: Uuid,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {}", token(as_agent)));
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
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn group_key(seed: &str) -> String {
    hex::encode(blake3::hash(seed.as_bytes()).as_bytes())
}

/// A structurally valid 60-byte wrapped share (opaque to the server).
fn wrapped_share(seed: &str) -> String {
    let mut bytes = Vec::with_capacity(60);
    bytes.extend_from_slice(blake3::hash(seed.as_bytes()).as_bytes());
    bytes.extend_from_slice(&blake3::hash(seed.as_bytes()).as_bytes()[..28]);
    hex::encode(bytes)
}

/// A keyed team group created on the SUPERUSER pool, exactly as
/// `POST /api/v1/groups` would create it, so the member and read routes can be
/// measured independently of the create route.
async fn seeded_group(pool: &PgPool, admin: Uuid, seed: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key = blake3::hash(seed.as_bytes());
    let did = epigraph_crypto::DidKey::from_public_key(key.as_bytes())
        .as_str()
        .to_string();
    GroupRepository::create_with_admin(pool, id, Some(seed), &did, key.as_bytes(), None, admin)
        .await
        .expect("seed group");
    id
}

/// Live `(agent_id, role, epoch)` rows of `group`, read on the superuser pool.
async fn live_roster(pool: &PgPool, group: Uuid) -> Vec<(Uuid, String, i32)> {
    let mut rows: Vec<(Uuid, String, i32)> = sqlx::query_as(
        "SELECT agent_id, role, epoch FROM group_memberships \
          WHERE group_id = $1 AND revoked_at IS NULL",
    )
    .bind(group)
    .fetch_all(pool)
    .await
    .expect("roster");
    rows.sort();
    rows
}

/// A live membership seeded on the SUPERUSER pool at epoch 0.
async fn seed_member(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    epigraph_db::GroupMembershipRepository::add_member(
        pool,
        group,
        agent,
        &hex::decode(wrapped_share(&format!("{group}-{agent}"))).unwrap(),
        0,
        role,
    )
    .await
    .expect("seed member");
}

fn member_body(agent: Uuid, role: &str, seed: &str) -> Value {
    json!({
        "agent_id": agent,
        "wrapped_key_share": wrapped_share(seed),
        "role": role,
    })
}

/// The creator creates a group and adds a member, both on the application
/// role, and every row the two routes write is committed.
#[sqlx::test(migrations = "../../migrations")]
async fn a_creator_creates_a_group_and_adds_a_member_on_the_application_role(pool: PgPool) {
    let creator = seed_agent(&pool, "323773fe-creator").await;
    let member = seed_agent(&pool, "323773fe-member").await;

    let (status, body) = send(
        app_role_router(&pool).await,
        Method::POST,
        "/api/v1/groups",
        creator,
        Some(json!({ "name": "323773fe app role", "group_public_key": group_key("323773fe-a") })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create_group on the app role: {body}"
    );
    let group: Uuid = body["group_id"].as_str().unwrap().parse().unwrap();

    let created_by: Uuid =
        sqlx::query_scalar("SELECT created_by_agent_id FROM groups WHERE id = $1")
            .bind(group)
            .fetch_one(&pool)
            .await
            .expect("the group row committed");
    assert_eq!(created_by, creator);
    let epochs: Vec<(i32, String)> =
        sqlx::query_as("SELECT epoch, status FROM group_key_epochs WHERE group_id = $1")
            .bind(group)
            .fetch_all(&pool)
            .await
            .expect("epochs");
    assert_eq!(epochs, vec![(0, "active".to_string())], "epoch 0 committed");
    assert_eq!(
        live_roster(&pool, group).await,
        vec![(creator, "admin".to_string(), 0)],
        "the creator's admin row committed"
    );

    let (status, body) = send(
        app_role_router(&pool).await,
        Method::POST,
        &format!("/api/v1/groups/{group}/members"),
        creator,
        Some(member_body(member, "writer", "323773fe-a-share")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "add_member on the app role: {body}"
    );
    let mut want = vec![
        (creator, "admin".to_string(), 0),
        (member, "writer".to_string(), 0),
    ];
    want.sort();
    assert_eq!(live_roster(&pool, group).await, want);
}

/// The member route on its own, for an admin whose group was created out of
/// band: the admin check must see the caller's membership.
#[sqlx::test(migrations = "../../migrations")]
async fn an_admin_adds_a_member_on_the_application_role(pool: PgPool) {
    let admin = seed_agent(&pool, "323773fe-admin").await;
    let member = seed_agent(&pool, "323773fe-new").await;
    let group = seeded_group(&pool, admin, "323773fe-b").await;

    let (status, body) = send(
        app_role_router(&pool).await,
        Method::POST,
        &format!("/api/v1/groups/{group}/members"),
        admin,
        Some(member_body(member, "reader", "323773fe-b-share")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "add_member on the app role: {body}"
    );
    assert!(
        live_roster(&pool, group)
            .await
            .contains(&(member, "reader".to_string(), 0)),
        "the new member's row committed"
    );
}

/// The stamped member route still refuses a non-admin member and a stranger,
/// and writes nothing for either.
#[sqlx::test(migrations = "../../migrations")]
async fn the_member_route_refuses_a_non_admin_and_a_stranger_on_the_application_role(pool: PgPool) {
    let admin = seed_agent(&pool, "323773fe-c-admin").await;
    let writer = seed_agent(&pool, "323773fe-c-writer").await;
    let stranger = seed_agent(&pool, "323773fe-c-stranger").await;
    let target = seed_agent(&pool, "323773fe-c-target").await;
    let group = seeded_group(&pool, admin, "323773fe-c").await;
    epigraph_db::GroupMembershipRepository::add_member(
        &pool,
        group,
        writer,
        &hex::decode(wrapped_share("323773fe-c-writer")).unwrap(),
        0,
        "writer",
    )
    .await
    .expect("seed writer");
    let before = live_roster(&pool, group).await;

    let (status, body) = send(
        app_role_router(&pool).await,
        Method::POST,
        &format!("/api/v1/groups/{group}/members"),
        writer,
        Some(member_body(target, "reader", "323773fe-c-1")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a writer is not an admin: {body}"
    );
    assert!(
        body.to_string().contains("Admin role required"),
        "the writer is refused as a non-admin member, not as a non-member: {body}"
    );

    let (status, body) = send(
        app_role_router(&pool).await,
        Method::POST,
        &format!("/api/v1/groups/{group}/members"),
        stranger,
        Some(member_body(target, "reader", "323773fe-c-2")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a stranger: {body}");
    assert!(
        body.to_string().contains("Not a member of this group"),
        "{body}"
    );

    assert_eq!(
        live_roster(&pool, group).await,
        before,
        "nothing was written"
    );
}

/// The member route for an admin who did NOT create the group, which is the
/// common case on a deployment whose groups were made out of band. Every
/// creator-only arm of `groups_tenancy` is out of reach for this caller, so the
/// admin check, the group read and the INSERT must all pass on the admin's own
/// membership.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_creator_admin_adds_a_member_on_the_application_role(pool: PgPool) {
    let creator = seed_agent(&pool, "323773fe-f-creator").await;
    let admin = seed_agent(&pool, "323773fe-f-admin").await;
    let member = seed_agent(&pool, "323773fe-f-new").await;
    let group = seeded_group(&pool, creator, "323773fe-f").await;
    seed_member(&pool, group, admin, "admin").await;

    let (status, body) = send(
        app_role_router(&pool).await,
        Method::POST,
        &format!("/api/v1/groups/{group}/members"),
        admin,
        Some(member_body(member, "writer", "323773fe-f-share")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "add_member by a non-creator admin on the app role: {body}"
    );
    let mut want = vec![
        (creator, "admin".to_string(), 0),
        (admin, "admin".to_string(), 0),
        (member, "writer".to_string(), 0),
    ];
    want.sort();
    assert_eq!(
        live_roster(&pool, group).await,
        want,
        "the new member's row committed"
    );
}

/// `GET /api/v1/groups/:id` by a READER who neither created the group nor
/// administers it, on a four-member group. `member_count` must be the whole
/// live roster: the stamped read has to see every member's row through the
/// caller's group membership, not only the caller's own row (which a
/// one-member group could not tell apart).
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_creator_reader_sees_the_whole_roster_on_the_application_role(pool: PgPool) {
    let creator = seed_agent(&pool, "323773fe-g-creator").await;
    let admin = seed_agent(&pool, "323773fe-g-admin").await;
    let writer = seed_agent(&pool, "323773fe-g-writer").await;
    let reader = seed_agent(&pool, "323773fe-g-reader").await;
    let group = seeded_group(&pool, creator, "323773fe-g").await;
    seed_member(&pool, group, admin, "admin").await;
    seed_member(&pool, group, writer, "writer").await;
    seed_member(&pool, group, reader, "reader").await;
    let roster = live_roster(&pool, group).await;
    assert_eq!(roster.len(), 4, "fixture: four live members");

    let (status, body) = send(
        app_role_router(&pool).await,
        Method::GET,
        &format!("/api/v1/groups/{group}"),
        reader,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "get_group by a non-creator reader on the app role: {body}"
    );
    assert_eq!(body["id"].as_str(), Some(group.to_string().as_str()));
    assert_eq!(
        body["member_count"],
        json!(roster.len()),
        "member_count is the whole live roster, not the caller's own row: {body}"
    );
    assert_eq!(body["current_epoch"], json!(0));
}

/// `GET /api/v1/groups/:id` answers a live member, and still refuses a
/// stranger, on the application role.
#[sqlx::test(migrations = "../../migrations")]
async fn a_member_reads_the_group_on_the_application_role(pool: PgPool) {
    let admin = seed_agent(&pool, "323773fe-d-admin").await;
    let stranger = seed_agent(&pool, "323773fe-d-stranger").await;
    let group = seeded_group(&pool, admin, "323773fe-d").await;

    let (status, body) = send(
        app_role_router(&pool).await,
        Method::GET,
        &format!("/api/v1/groups/{group}"),
        admin,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get_group on the app role: {body}");
    assert_eq!(body["id"].as_str(), Some(group.to_string().as_str()));
    assert_eq!(body["member_count"], json!(1));
    assert_eq!(body["current_epoch"], json!(0));

    let (status, body) = send(
        app_role_router(&pool).await,
        Method::GET,
        &format!("/api/v1/groups/{group}"),
        stranger,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a stranger: {body}");
}

/// `revoked_at IS NOT NULL` for `agent`'s row, `reseal_required_at IS NOT
/// NULL` on the group, and the current epoch's status, on the superuser pool.
async fn removal_state(pool: &PgPool, group: Uuid, agent: Uuid) -> (bool, bool, String) {
    let revoked: bool = sqlx::query_scalar(
        "SELECT revoked_at IS NOT NULL FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(group)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("membership");
    let marked: bool =
        sqlx::query_scalar("SELECT reseal_required_at IS NOT NULL FROM groups WHERE id = $1")
            .bind(group)
            .fetch_one(pool)
            .await
            .expect("group");
    let status: String =
        sqlx::query_scalar("SELECT status FROM group_key_epochs WHERE group_id = $1 AND epoch = 0")
            .bind(group)
            .fetch_one(pool)
            .await
            .expect("epoch");
    (revoked, marked, status)
}

/// `DELETE /api/v1/groups/:id/members/:agent_id` on the application role, by
/// the group's creator. The removal revokes the row and marks the re-key
/// obligation in the same transaction, and the last-admin guard still refuses.
///
/// The creator is one admin among others here: the re-key mark goes through
/// migration 181's definer, which admits any live admin of the group, so the
/// creator-only `WITH CHECK` of `groups_tenancy` (migration 077) is not what
/// admits it. `a_non_creator_admin_removes_a_member_on_the_application_role`
/// is the case that arm could not reach.
#[sqlx::test(migrations = "../../migrations")]
async fn the_creator_removes_members_on_the_application_role(pool: PgPool) {
    let creator = seed_agent(&pool, "323773fe-e-creator").await;
    let second = seed_agent(&pool, "323773fe-e-second").await;
    let reader = seed_agent(&pool, "323773fe-e-reader").await;
    let group = seeded_group(&pool, creator, "323773fe-e").await;
    for (agent, role) in [(second, "admin"), (reader, "reader")] {
        epigraph_db::GroupMembershipRepository::add_member(
            &pool,
            group,
            agent,
            &hex::decode(wrapped_share(&format!("323773fe-e-{agent}"))).unwrap(),
            0,
            role,
        )
        .await
        .expect("seed member");
    }

    let (status, body) = send(
        app_role_router(&pool).await,
        Method::DELETE,
        &format!("/api/v1/groups/{group}/members/{reader}"),
        creator,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the creator removes a reader: {body}"
    );
    assert_eq!(
        removal_state(&pool, group, reader).await,
        (true, true, "rotating".to_string()),
        "revoked, and the re-key obligation marked in the same transaction"
    );

    let (status, body) = send(
        app_role_router(&pool).await,
        Method::DELETE,
        &format!("/api/v1/groups/{group}/members/{second}"),
        creator,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the creator removes an admin: {body}"
    );
    assert!(removal_state(&pool, group, second).await.0);

    let (status, body) = send(
        app_role_router(&pool).await,
        Method::DELETE,
        &format!("/api/v1/groups/{group}/members/{creator}"),
        creator,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "the last admin stays: {body}");
    assert!(!removal_state(&pool, group, creator).await.0);
}

/// `DELETE /api/v1/groups/:id/members/:agent_id` by an admin who did NOT
/// create the group, on the application role (ruling R-56, backlog 323773fe).
///
/// The revoke and the epoch's `rotating` mark pass row security on the admin's
/// own membership; the `groups.reseal_required_at` mark cannot, because
/// `groups_tenancy`'s `WITH CHECK` admits only the creator. Migration 181's
/// definer writes that one column for any live admin of the group, so the
/// removal now commits whole: revoked, obligation marked, epoch rotating.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_creator_admin_removes_a_member_on_the_application_role(pool: PgPool) {
    let creator = seed_agent(&pool, "323773fe-h-creator").await;
    let admin = seed_agent(&pool, "323773fe-h-admin").await;
    let reader = seed_agent(&pool, "323773fe-h-reader").await;
    let group = seeded_group(&pool, creator, "323773fe-h").await;
    seed_member(&pool, group, admin, "admin").await;
    seed_member(&pool, group, reader, "reader").await;
    assert_eq!(
        removal_state(&pool, group, reader).await,
        (false, false, "active".to_string()),
        "fixture: live reader, no re-key obligation, epoch 0 active"
    );

    let (status, body) = send(
        app_role_router(&pool).await,
        Method::DELETE,
        &format!("/api/v1/groups/{group}/members/{reader}"),
        admin,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "a non-creator admin removes a reader: {body}"
    );
    assert_eq!(
        removal_state(&pool, group, reader).await,
        (true, true, "rotating".to_string()),
        "revoked, and the re-key obligation marked in the same transaction"
    );
    assert_eq!(
        live_roster(&pool, group).await,
        {
            let mut v = vec![
                (creator, "admin".to_string(), 0),
                (admin, "admin".to_string(), 0),
            ];
            v.sort();
            v
        },
        "only the reader left the roster"
    );
}

/// A non-creator admin removes ITSELF while another admin remains. The re-key
/// mark is decided on the caller's admin membership, so it must be taken
/// before the caller's own row is revoked in the same transaction; marked
/// after, the caller would no longer be an admin and the removal would be
/// refused whole.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_creator_admin_leaves_the_group_on_the_application_role(pool: PgPool) {
    let creator = seed_agent(&pool, "323773fe-i-creator").await;
    let admin = seed_agent(&pool, "323773fe-i-admin").await;
    let group = seeded_group(&pool, creator, "323773fe-i").await;
    seed_member(&pool, group, admin, "admin").await;

    let (status, body) = send(
        app_role_router(&pool).await,
        Method::DELETE,
        &format!("/api/v1/groups/{group}/members/{admin}"),
        admin,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "an admin removes itself while the creator stays admin: {body}"
    );
    assert_eq!(
        removal_state(&pool, group, admin).await,
        (true, true, "rotating".to_string()),
        "revoked, and the re-key obligation marked"
    );
    assert_eq!(
        live_roster(&pool, group).await,
        vec![(creator, "admin".to_string(), 0)]
    );
}

/// The removal route refuses a member who is not an admin and a stranger, on
/// the application role, with a 403 and no change: no revoke, no re-key mark,
/// no epoch move. (A pin: the route's admin check refused both before
/// migration 181 as well.)
#[sqlx::test(migrations = "../../migrations")]
async fn the_removal_route_refuses_a_non_admin_and_a_stranger_on_the_application_role(
    pool: PgPool,
) {
    let creator = seed_agent(&pool, "323773fe-j-creator").await;
    let writer = seed_agent(&pool, "323773fe-j-writer").await;
    let reader = seed_agent(&pool, "323773fe-j-reader").await;
    let stranger = seed_agent(&pool, "323773fe-j-stranger").await;
    let group = seeded_group(&pool, creator, "323773fe-j").await;
    seed_member(&pool, group, writer, "writer").await;
    seed_member(&pool, group, reader, "reader").await;
    let roster_before = live_roster(&pool, group).await;
    let state_before = removal_state(&pool, group, reader).await;

    for (caller, who, needle) in [
        (writer, "a writer", "Admin role required"),
        (stranger, "a stranger", "Not a member of this group"),
    ] {
        let (status, body) = send(
            app_role_router(&pool).await,
            Method::DELETE,
            &format!("/api/v1/groups/{group}/members/{reader}"),
            caller,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{who}: {body}");
        assert!(body.to_string().contains(needle), "{who}: {body}");
    }
    assert_eq!(live_roster(&pool, group).await, roster_before);
    assert_eq!(
        removal_state(&pool, group, reader).await,
        state_before,
        "no revoke, no re-key mark and no epoch change committed"
    );
}

/// A keyless team group made by migration 164's verbs, seeded on the
/// SUPERUSER pool (a privileged session, which those verbs' triggers admit)
/// exactly as `epigraph_create_team_group` shapes it, with `creator` as its
/// admin and `member` as a reader.
async fn seeded_verb_made_group(pool: &PgPool, creator: Uuid, member: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, $2, 'did:epigraph:group:' || $1::text, ''::bytea, 'team', $3)",
    )
    .bind(id)
    .bind(format!("323773fe verb-made {id}"))
    .bind(creator)
    .execute(pool)
    .await
    .expect("seed a verb-made team group");
    for (agent, role) in [(creator, "admin"), (member, "reader")] {
        sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, $3)",
        )
        .bind(id)
        .bind(agent)
        .bind(role)
        .execute(pool)
        .await
        .expect("seed a verb-made roster row");
    }
    id
}

/// When the DATABASE refuses the removal (SQLSTATE 42501), the route answers a
/// clean 403 and commits nothing. A verb-made team group's roster and group row
/// are written only by migration 164's maintenance verbs, so its own admin's
/// REST removal is refused by the database itself; that refusal used to
/// surface as a 500.
#[sqlx::test(migrations = "../../migrations")]
async fn a_database_refusal_of_the_removal_is_a_403_on_the_application_role(pool: PgPool) {
    let creator = seed_agent(&pool, "323773fe-k-creator").await;
    let reader = seed_agent(&pool, "323773fe-k-reader").await;
    let group = seeded_verb_made_group(&pool, creator, reader).await;
    let roster_before = live_roster(&pool, group).await;

    let (status, body) = send(
        app_role_router(&pool).await,
        Method::DELETE,
        &format!("/api/v1/groups/{group}/members/{reader}"),
        creator,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a removal the database refuses is a 403, not a 500: {body}"
    );
    assert_eq!(
        live_roster(&pool, group).await,
        roster_before,
        "the reader is still a live member"
    );
    let marked: bool =
        sqlx::query_scalar("SELECT reseal_required_at IS NOT NULL FROM groups WHERE id = $1")
            .bind(group)
            .fetch_one(&pool)
            .await
            .expect("group");
    assert!(!marked, "no re-key mark committed");
}

/// `(reseal_required_at IS NOT NULL, epoch 0 status)` of `group`, read on the
/// superuser pool; usable when the target has no membership row at all. A
/// keyless (verb-made) group has no epoch row: `None`.
async fn group_mark_and_epoch(pool: &PgPool, group: Uuid) -> (bool, Option<String>) {
    let marked: bool =
        sqlx::query_scalar("SELECT reseal_required_at IS NOT NULL FROM groups WHERE id = $1")
            .bind(group)
            .fetch_one(pool)
            .await
            .expect("group");
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM group_key_epochs WHERE group_id = $1 AND epoch = 0")
            .bind(group)
            .fetch_optional(pool)
            .await
            .expect("epoch");
    (marked, status)
}

/// A removal that revokes nothing marks nothing, on the application role and
/// on a group with NO prior mark (the mark is COALESCEd and no rotation clears
/// it, so a stray one would be a permanent false re-key obligation).
///
/// The removal takes the re-key mark BEFORE the guarded revoke (so an admin
/// removing itself is still an admin when the mark is decided) and undoes it
/// with a rollback to a savepoint when the guard revokes nothing. The route
/// commits its transaction before it maps the outcome to 409 / 404, so that
/// rollback is the only thing keeping the mark out of the committed state:
/// here the sole admin removing itself is refused 409 (`LastAdmin`);
/// [`a_non_member_removal_marks_nothing_on_the_application_role`] is the 404
/// (`NotAMember`) half.
#[sqlx::test(migrations = "../../migrations")]
async fn a_last_admin_refusal_marks_nothing_on_the_application_role(pool: PgPool) {
    let creator = seed_agent(&pool, "323773fe-l-creator").await;
    let sole = seeded_group(&pool, creator, "323773fe-l-sole").await;
    assert_eq!(
        removal_state(&pool, sole, creator).await,
        (false, false, "active".to_string()),
        "fixture: a live sole admin, no re-key obligation, epoch 0 active"
    );
    let (status, body) = send(
        app_role_router(&pool).await,
        Method::DELETE,
        &format!("/api/v1/groups/{sole}/members/{creator}"),
        creator,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "the last admin stays: {body}");
    assert_eq!(
        removal_state(&pool, sole, creator).await,
        (false, false, "active".to_string()),
        "LastAdmin: still live, no re-key mark, epoch still active"
    );
}

/// The `NotAMember` half of
/// [`a_last_admin_refusal_marks_nothing_on_the_application_role`]: an admin
/// removing an agent with no membership gets 404, and the rollback to the
/// savepoint keeps the mark the removal took out of the committed state.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_removal_marks_nothing_on_the_application_role(pool: PgPool) {
    let admin = seed_agent(&pool, "323773fe-l-admin").await;
    let stranger = seed_agent(&pool, "323773fe-l-stranger").await;
    let group = seeded_group(&pool, admin, "323773fe-l-other").await;
    let roster_before = live_roster(&pool, group).await;
    assert_eq!(
        group_mark_and_epoch(&pool, group).await,
        (false, Some("active".to_string())),
        "fixture: no re-key obligation, epoch 0 active"
    );
    let (status, body) = send(
        app_role_router(&pool).await,
        Method::DELETE,
        &format!("/api/v1/groups/{group}/members/{stranger}"),
        admin,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "not a member: {body}");
    assert_eq!(live_roster(&pool, group).await, roster_before);
    assert_eq!(
        group_mark_and_epoch(&pool, group).await,
        (false, Some("active".to_string())),
        "NotAMember: no re-key mark, epoch still active"
    );
}
