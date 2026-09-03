//! PR-11's acceptance criterion, proved against a real membership row.
//!
//! > *a `reader`-role member cannot write to their group*
//!
//! # Why this test is DB-backed rather than a unit test
//!
//! The crate's unit tests already cover the decision function over a
//! hand-built [`Principal`]. What they cannot cover is the step before it: that
//! a `reader` membership actually fails to reach `writable_groups()`. That
//! filter lives in `epigraph_db::visibility::Viewer::resolve`
//! (`matches!(role.as_str(), "admin" | "writer")`), reading a row whose legal
//! values are pinned by `group_memberships_role_check` in migration 060. A unit
//! test that constructed `Principal::new(id, vec![])` and asserted a denial
//! would be asserting its own setup.
//!
//! `Viewer::test_scoped` cannot be used either, and says so itself: *"The
//! writable set is taken to equal the group set, which is the permissive
//! choice — a test that wants to prove a **reader** cannot write must build its
//! fixture through `resolve`."* It is also `#[cfg(test)]` on its definition, so
//! it is invisible from an integration test in another crate.
//!
//! # Why the fixture is local rather than a sixth `viewer_fixture.rs`
//!
//! `crates/{api,cli,db,engine,mcp}/tests/viewer_fixture.rs` are five
//! byte-identical copies. A sixth would be more drift surface for the one
//! helper this file needs and does not have: **`seed_agent_with_group`
//! hardcodes `role = 'admin'`**, so it cannot produce the principal this test
//! exists to examine. [`seed_agent_in_group`] below takes the role as a
//! parameter, which is the whole difference.

use epigraph_authz::{GroupPolicyGate, GRANT_GROUP_WRITER};
use epigraph_db::visibility::Viewer;
use epigraph_interfaces::{Action, Decision, PolicyGate, Principal, ResourceKind, ResourceRef};
use sqlx::PgPool;
use uuid::Uuid;

/// Insert an agent, a group, and a live membership at `role`.
///
/// Same shape as `AgentRepository::ensure_personal_group` (PR-02) except that
/// the role is the caller's choice. `kind = 'personal'` carries an empty
/// `public_key` — only `kind = 'team'` may carry 32 bytes, per
/// `groups_public_key_shape`.
async fn seed_agent_in_group(pool: &PgPool, label: &str, role: &str) -> (Uuid, Uuid) {
    let agent = Uuid::new_v4();
    let pk: Vec<u8> = agent.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");

    let group: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, $2, ''::bytea, 'personal', $3) RETURNING id",
    )
    .bind(format!("{label}:{agent}"))
    .bind(format!("did:epigraph:authz:{label}:{agent}"))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed group");

    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed membership");

    (agent, group)
}

/// Build the gate's [`Principal`] the way a request path does: from a resolved
/// [`Viewer`]'s write-capable group set.
async fn principal_for(pool: &PgPool, agent: Uuid) -> Principal {
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve");
    Principal::new(
        viewer.principal().expect("a resolved viewer is Scoped"),
        viewer.writable_groups().to_vec(),
    )
}

/// **The acceptance criterion.**
#[sqlx::test(migrations = "../../migrations")]
async fn a_reader_role_member_cannot_write_to_their_own_group(pool: PgPool) {
    let (agent, group) = seed_agent_in_group(&pool, "reader", "reader").await;

    // The membership is live and the viewer sees the group — this is a member,
    // not a stranger. If this assertion ever fails, the test below is passing
    // for the wrong reason.
    let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");
    assert_eq!(
        viewer.group_bind(),
        Some(&[group][..]),
        "the reader IS a member of the group"
    );
    assert!(
        viewer.writable_groups().is_empty(),
        "`reader` must not appear in the writable set"
    );

    let decision = GroupPolicyGate::new()
        .authorize(
            &principal_for(&pool, agent).await,
            &Action::Create,
            &ResourceRef::new(ResourceKind::Claim, Uuid::new_v4()).owned_by_group(group),
        )
        .await;

    assert!(
        !decision.is_allowed(),
        "a reader-role member wrote to their own group: {decision:?}"
    );
    assert!(decision
        .denial_reason()
        .expect("a denial carries a reason")
        .contains("no write role"));
}

/// The positive control. Without it the test above passes on a gate that denies
/// everything, which would prove nothing about roles.
#[sqlx::test(migrations = "../../migrations")]
async fn a_writer_role_member_can_write_to_their_own_group(pool: PgPool) {
    let (agent, group) = seed_agent_in_group(&pool, "writer", "writer").await;

    let decision = GroupPolicyGate::new()
        .authorize(
            &principal_for(&pool, agent).await,
            &Action::Create,
            &ResourceRef::new(ResourceKind::Claim, Uuid::new_v4()).owned_by_group(group),
        )
        .await;

    assert_eq!(decision, Decision::allow(GRANT_GROUP_WRITER));
}

/// `admin` is the other write-capable role in `group_memberships_role_check`,
/// and it is what `ensure_personal_group` writes for every OAuth-minted
/// principal — so this is the case that keeps production working.
#[sqlx::test(migrations = "../../migrations")]
async fn an_admin_role_member_can_write_to_their_own_group(pool: PgPool) {
    let (agent, group) = seed_agent_in_group(&pool, "admin", "admin").await;

    let decision = GroupPolicyGate::new()
        .authorize(
            &principal_for(&pool, agent).await,
            &Action::Declassify,
            &ResourceRef::new(ResourceKind::Ownership, Uuid::new_v4()).owned_by_group(group),
        )
        .await;

    assert_eq!(decision, Decision::allow(GRANT_GROUP_WRITER));
}

/// A revoked membership buys nothing. `Viewer::resolve` reads
/// `revoked_at IS NULL`, so the group leaves both sets and the gate sees a
/// principal with no authority — not a principal whose authority merely failed
/// to load.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_writer_cannot_write(pool: PgPool) {
    let (agent, group) = seed_agent_in_group(&pool, "revoked", "writer").await;
    sqlx::query("UPDATE group_memberships SET revoked_at = now() WHERE agent_id = $1")
        .bind(agent)
        .execute(&pool)
        .await
        .expect("revoke");

    let decision = GroupPolicyGate::new()
        .authorize(
            &principal_for(&pool, agent).await,
            &Action::Create,
            &ResourceRef::new(ResourceKind::Claim, Uuid::new_v4()).owned_by_group(group),
        )
        .await;

    assert!(!decision.is_allowed(), "got {decision:?}");
}

/// An agent with no membership at all resolves to an empty writable set and is
/// refused — it does not fall through to "unowned, therefore fine".
///
/// This is the population `progress.json`'s
/// `F-PR10-agentless-principal-resolves-to-public-only` describes on the read
/// side: `Viewer::resolve` demotes rather than refusing, and the demoted viewer
/// must then be *denied* by the write gate rather than quietly permitted.
#[sqlx::test(migrations = "../../migrations")]
async fn a_principal_with_no_membership_is_denied(pool: PgPool) {
    let agent = Uuid::new_v4();
    let pk: Vec<u8> = agent.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(&pk)
        .execute(&pool)
        .await
        .expect("seed agent");

    let principal = principal_for(&pool, agent).await;
    assert!(principal.writable_groups().is_empty());

    let decision = GroupPolicyGate::new()
        .authorize(
            &principal,
            &Action::Create,
            &ResourceRef::new(ResourceKind::Claim, Uuid::new_v4()).owned_by_group(Uuid::new_v4()),
        )
        .await;
    assert!(!decision.is_allowed(), "got {decision:?}");
}
