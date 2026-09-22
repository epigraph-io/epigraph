#![cfg(feature = "db")]

//! The community writes require a group scope: `groups:write` to create one,
//! `groups:admin` to manage an existing one's membership.
//!
//! The split is `routes/groups.rs`'s, and it is deliberate — see
//! `routes/community.rs`'s module doc. Both tiers are tested here because
//! raising only the membership pair would have left the route that CREATES a
//! projected group, and installs its caller as that group's administrator,
//! cheaper than the two routes that merely modify one.
//!
//! # Why this file exists at all
//!
//! There was no route-level community test binary of any kind. All authorization
//! coverage for these two writes was repo-layer, in
//! `epigraph-db/tests/community_projection.rs`, which tests the MEMBERSHIP rule
//! and cannot observe a scope gate at all.
//!
//! # Assertion ORDER is load-bearing here
//!
//! The repo layer answers `MembershipOutcome::DeniedNotAMember` with a 403, and so
//! does a missing scope. A test that pointed a scope-less token at a community the
//! caller is not a member of would get 403 either way and would pass with no scope
//! gate present at all.
//!
//! So the scope tests use a caller who **is** a live member of the community (via
//! `common::seed_community_with_member`, which seeds the projection too) and whose
//! only defect is the missing scope. That token reaches 204 once the scope is
//! added — asserted in `add_member_with_groups_admin_succeeds_for_a_live_member` —
//! so the 403 in the test above it can only be the scope.

mod common;

async fn spawn() -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    common::spawn_app(&url).await
}

async fn pool() -> sqlx::PgPool {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect test pool")
}

/// A community whose only member is `agent`, plus a second perspective owned by
/// `agent` that it may try to add.
async fn member_of_a_community(pool: &sqlx::PgPool) -> (uuid::Uuid, uuid::Uuid, uuid::Uuid) {
    let agent = uuid::Uuid::new_v4();
    let community = common::seed_community_with_member(pool, agent).await;
    let perspective: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(format!("scope-test-{}", uuid::Uuid::new_v4()))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed a second perspective for the member to add");
    (agent, community, perspective)
}

// ===========================================================================
// POST /api/v1/communities  —  the CREATE tier
// ===========================================================================

/// A read-write principal without `groups:write` may not create a community.
///
/// The effect, not the status code: `CommunityRepository::create` inserts a
/// `communities` row, a projected `groups` row and a `role='admin'`
/// `group_memberships` row for the caller. A refusal must leave all three
/// absent, so the assertion counts the rows rather than trusting the 403.
#[tokio::test(flavor = "multi_thread")]
async fn create_community_without_groups_write_returns_403_and_creates_nothing() {
    let (addr, _shutdown) = spawn().await;
    let p = pool().await;
    let agent = uuid::Uuid::new_v4();
    let token = common::mint_token_with_agent(&["claims:write", "claims:read"], agent);
    let name = format!("unscoped-create-{}", uuid::Uuid::new_v4());

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/communities"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "name": name,
            "governance_type": "consensus",
            "ownership_type": "collective",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "creating a community creates a projected group and makes the caller its \
         administrator, so it costs the same scope `POST /api/v1/groups` costs; \
         got {}",
        resp.status()
    );

    let created: i64 = sqlx::query_scalar("SELECT count(*) FROM communities WHERE name = $1")
        .bind(&name)
        .fetch_one(&p)
        .await
        .unwrap();
    assert_eq!(
        created, 0,
        "a refused create must create nothing — no community, and therefore no \
         projected group and no self-granted admin membership"
    );
}

/// THE POSITIVE CONTROL. `groups:write` is in the read-write role, so this is
/// the ordinary caller and it must still succeed — an over-suppressing gate
/// would pass the test above on its own.
#[tokio::test(flavor = "multi_thread")]
async fn create_community_with_groups_write_still_succeeds() {
    let (addr, _shutdown) = spawn().await;
    let p = pool().await;
    // A real `agents` row: `CommunityRepository::create` grants the creator a
    // `group_memberships` row, whose `agent_id` is an FK, so a synthetic
    // principal would make the success path a 500 rather than a 201.
    let agent = common::seed_system_agent(&p).await;
    let token = common::mint_token_with_agent(&["groups:write", "claims:read"], agent);
    let name = format!("scoped-create-{}", uuid::Uuid::new_v4());

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/communities"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "name": name,
            "governance_type": "consensus",
            "ownership_type": "collective",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        201,
        "a read-write principal holding `groups:write` is the legitimate caller \
         and must not be locked out; got {}",
        resp.status()
    );

    let created: i64 = sqlx::query_scalar("SELECT count(*) FROM communities WHERE name = $1")
        .bind(&name)
        .fetch_one(&p)
        .await
        .unwrap();
    assert_eq!(created, 1, "and the community really exists");
}

#[tokio::test(flavor = "multi_thread")]
async fn create_community_no_token_returns_401() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/communities"))
        .json(&serde_json::json!({
            "name": "no-token",
            "governance_type": "consensus",
            "ownership_type": "collective",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "got {}", resp.status());
}

// ===========================================================================
// POST /api/v1/communities/:id/members
// ===========================================================================

/// A LIVE MEMBER of the community, holding an ordinary read-write scope, is
/// refused. The membership rule would have let this caller through, so the 403
/// is the scope and nothing else.
#[tokio::test(flavor = "multi_thread")]
async fn add_member_without_groups_admin_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let p = pool().await;
    let (agent, community, perspective) = member_of_a_community(&p).await;
    let token = common::mint_token_with_agent(&["claims:write", "groups:write"], agent);

    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/communities/{community}/members"
        ))
        .bearer_auth(token)
        .json(&serde_json::json!({ "perspective_id": perspective }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "a token without `groups:admin` may not grant a projected group \
         membership, even when its holder is a member; got {}",
        resp.status()
    );
    let remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM community_members WHERE community_id = $1 AND perspective_id = $2",
    )
    .bind(community)
    .bind(perspective)
    .fetch_one(&p)
    .await
    .unwrap();
    assert_eq!(
        remaining, 0,
        "and the refusal must leave no row behind: the effect, not the status code"
    );
}

/// THE POSITIVE CONTROL, and the thing that makes the test above meaningful.
/// Same caller, same community, same perspective — plus the scope.
#[tokio::test(flavor = "multi_thread")]
async fn add_member_with_groups_admin_succeeds_for_a_live_member() {
    let (addr, _shutdown) = spawn().await;
    let p = pool().await;
    let (agent, community, perspective) = member_of_a_community(&p).await;
    let token = common::mint_token_with_agent(&["groups:admin", "claims:read"], agent);

    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/communities/{community}/members"
        ))
        .bearer_auth(token)
        .json(&serde_json::json!({ "perspective_id": perspective }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        204,
        "a live member holding `groups:admin` is the legitimate caller and must \
         still succeed; got {}",
        resp.status()
    );
    let added: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM community_members WHERE community_id = $1 AND perspective_id = $2",
    )
    .bind(community)
    .bind(perspective)
    .fetch_one(&p)
    .await
    .unwrap();
    assert_eq!(added, 1, "and the membership row exists");
}

#[tokio::test(flavor = "multi_thread")]
async fn add_member_no_token_returns_401() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/communities/{}/members",
            uuid::Uuid::new_v4()
        ))
        .json(&serde_json::json!({ "perspective_id": uuid::Uuid::new_v4() }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "got {}", resp.status());
}

// ===========================================================================
// DELETE /api/v1/communities/:id/members/:perspective_id
// ===========================================================================

/// The eviction twin. The caller here owns the perspective it is removing, which
/// the repo layer permits unconditionally — so, again, the 403 can only be the
/// scope, and the row must survive it.
#[tokio::test(flavor = "multi_thread")]
async fn remove_member_without_groups_admin_returns_403_and_leaves_the_row() {
    let (addr, _shutdown) = spawn().await;
    let p = pool().await;
    let agent = uuid::Uuid::new_v4();
    let community = common::seed_community_with_member(&p, agent).await;
    let perspective: uuid::Uuid =
        sqlx::query_scalar("SELECT perspective_id FROM community_members WHERE community_id = $1")
            .bind(community)
            .fetch_one(&p)
            .await
            .expect("the fixture's own membership");
    let token = common::mint_token_with_agent(&["claims:write", "groups:write"], agent);

    let resp = reqwest::Client::new()
        .delete(format!(
            "http://{addr}/api/v1/communities/{community}/members/{perspective}"
        ))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "removing a projected group membership needs `groups:admin` too; got {}",
        resp.status()
    );
    let still_there: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM community_members WHERE community_id = $1 AND perspective_id = $2",
    )
    .bind(community)
    .bind(perspective)
    .fetch_one(&p)
    .await
    .unwrap();
    assert_eq!(
        still_there, 1,
        "a refused eviction must not evict: the effect, not the status code"
    );
}

/// THE POSITIVE CONTROL for the DELETE. Same caller, plus the scope.
#[tokio::test(flavor = "multi_thread")]
async fn remove_member_with_groups_admin_removes_its_own_perspective() {
    let (addr, _shutdown) = spawn().await;
    let p = pool().await;
    let agent = uuid::Uuid::new_v4();
    let community = common::seed_community_with_member(&p, agent).await;
    let perspective: uuid::Uuid =
        sqlx::query_scalar("SELECT perspective_id FROM community_members WHERE community_id = $1")
            .bind(community)
            .fetch_one(&p)
            .await
            .expect("the fixture's own membership");
    let token = common::mint_token_with_agent(&["groups:admin", "claims:read"], agent);

    let resp = reqwest::Client::new()
        .delete(format!(
            "http://{addr}/api/v1/communities/{community}/members/{perspective}"
        ))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "got {}", resp.status());
    let gone: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM community_members WHERE community_id = $1 AND perspective_id = $2",
    )
    .bind(community)
    .bind(perspective)
    .fetch_one(&p)
    .await
    .unwrap();
    assert_eq!(gone, 0, "and the membership is really gone");
}

#[tokio::test(flavor = "multi_thread")]
async fn remove_member_no_token_returns_401() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .delete(format!(
            "http://{addr}/api/v1/communities/{}/members/{}",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "got {}", resp.status());
}
