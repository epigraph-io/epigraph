//! `Viewer::resolve` answers the same on a downgraded pool as on the harness
//! pool, for every role `viewer_fixture::downgraded_pool` is used with.
//!
//! # Why this exists
//!
//! `downgraded_pool` is reachable from five crates' test trees. A test that
//! seeds on the harness pool and then resolves its viewer on a downgraded,
//! UNSTAMPED pool is only sound if the resolve sees the same memberships the
//! harness does. If it saw fewer, every assertion of the form "this viewer
//! cannot read that row" would pass for the wrong reason, and stay green.
//!
//! The resolve is sound today because `GroupMembershipRepository::
//! list_live_for_agent` reads through migration 077's SECURITY DEFINER
//! `epigraph_live_memberships(uuid)` (re-stated by 164), owned by
//! `epigraph_maintenance` and granted to `epigraph_app`, rather than through a
//! direct, policed `SELECT ... FROM group_memberships`. This file is the control
//! that keeps it that way: a change that routed the resolve through a policed
//! read, or narrowed the definer's grants, turns it red here rather than
//! silently weakening every downstream test that pairs the two.
//!
//! `author_stamped_write_loop.rs::viewer_resolve_reaches_the_authors_
//! memberships_on_an_unstamped_app_session` already pins one point of this
//! (one admin membership reaching `writable` on the app role). What is added
//! here is the maintenance role, the `reader` role, a revoked membership, and
//! equality of the WHOLE resolved shape against the harness pool, rather than
//! containment of one id.
//!
//! What this does NOT make safe is a DIRECT read of `group_memberships` or
//! `groups` on a downgraded `epigraph_app` pool: those tables are policed, and
//! on an unstamped app session they return nothing. The calibration below
//! measures that too, so the app arm is a measurement of the definer path and
//! not of an unpoliced table. (`epigraph_maintenance` is a bypass session, so
//! its direct read sees everything and its arm is a plain equality.)

mod viewer_fixture;

use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture as fixture;

use epigraph_db::visibility::Viewer;

/// The roles `downgraded_pool` is called with anywhere in the workspace, each
/// with how many of the agent's live memberships a DIRECT read sees on an
/// unstamped session of it: none on `epigraph_app` (the table is policed, so
/// only the definer reaches the rows), all three on `epigraph_maintenance`
/// (`epigraph_bypass()` keys on that `session_user`).
const DOWNGRADED_ROLES: &[(&str, i64)] = &[("epigraph_app", 0), ("epigraph_maintenance", 3)];

async fn add_membership(pool: &PgPool, group: Uuid, agent: Uuid, role: &str, revoked: bool) {
    sqlx::query(
        "INSERT INTO group_memberships \
             (group_id, agent_id, wrapped_key_share, epoch, role, revoked_at) \
         VALUES ($1, $2, ''::bytea, 0, $3, CASE WHEN $4 THEN now() END)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .bind(revoked)
    .execute(pool)
    .await
    .expect("seed a membership");
}

/// `(group_bind, writable_groups)` of a resolved viewer, as owned vectors.
fn shape(viewer: &Viewer) -> (Vec<Uuid>, Vec<Uuid>) {
    (
        viewer
            .group_bind()
            .expect("Viewer::resolve yields a scoped viewer")
            .to_vec(),
        viewer.writable_groups().to_vec(),
    )
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_viewer_resolved_on_a_downgraded_pool_matches_the_harness_pool(pool: PgPool) {
    // One agent holding every membership shape `Viewer::resolve` distinguishes:
    // admin (its own personal group), writer, reader, and a revoked row that
    // must be absent from both sets.
    let (agent, own) = fixture::seed_agent_with_group(&pool, "dpr-agent").await;
    let (_, written) = fixture::seed_agent_with_group(&pool, "dpr-writer-host").await;
    let (_, read_only) = fixture::seed_agent_with_group(&pool, "dpr-reader-host").await;
    let (_, gone) = fixture::seed_agent_with_group(&pool, "dpr-revoked-host").await;
    add_membership(&pool, written, agent, "writer", false).await;
    add_membership(&pool, read_only, agent, "reader", false).await;
    add_membership(&pool, gone, agent, "writer", true).await;

    let harness = Viewer::resolve(&pool, agent)
        .await
        .expect("resolve on the harness pool");
    let (groups, writable) = shape(&harness);

    // CALIBRATION of the harness side: every live shape is present and the
    // revoked one is not. Without it, equality below holds between two empty
    // viewers.
    let mut want_groups = vec![own, written, read_only];
    want_groups.sort_unstable();
    let mut want_writable = vec![own, written];
    want_writable.sort_unstable();
    assert_eq!(
        groups, want_groups,
        "CALIBRATION: the harness resolve must see the admin, writer and reader memberships and \
         not the revoked one"
    );
    assert_eq!(
        writable, want_writable,
        "CALIBRATION: only admin and writer memberships are writable"
    );

    for &(role, direct_rows) in DOWNGRADED_ROLES {
        let downgraded = fixture::downgraded_pool(&pool, role).await;

        // CALIBRATION of the downgraded side: the connection really is the
        // role, holds no BYPASSRLS, and a DIRECT read of the same memberships
        // sees what that role's policy arm admits. On `epigraph_app` that is
        // nothing, which is what makes the resolve below a measurement of the
        // definer path rather than of an unpoliced table.
        let (session_user, bypassrls, direct): (String, bool, i64) = sqlx::query_as(
            "SELECT session_user::text, \
                    (SELECT r.rolbypassrls FROM pg_roles r WHERE r.rolname = session_user), \
                    (SELECT count(*) FROM group_memberships \
                      WHERE agent_id = $1 AND revoked_at IS NULL)",
        )
        .bind(agent)
        .fetch_one(&downgraded)
        .await
        .expect("session probe on the downgraded pool");
        assert_eq!(session_user, role, "the pool must really be downgraded");
        assert!(!bypassrls, "{role} must not hold BYPASSRLS");
        assert_eq!(
            direct, direct_rows,
            "CALIBRATION: a direct membership read on an unstamped {role} session must see \
             {direct_rows} rows; otherwise this arm is not measuring the path it names"
        );

        let resolved = Viewer::resolve(&downgraded, agent)
            .await
            .unwrap_or_else(|e| panic!("resolve on a downgraded {role} pool: {e}"));
        assert_eq!(
            shape(&resolved),
            (groups.clone(), writable.clone()),
            "Viewer::resolve on a downgraded, unstamped {role} pool must see exactly the \
             memberships the harness pool sees. A narrower result makes every test that resolves \
             on such a pool assert against a viewer that belongs to nobody"
        );
    }
}
