//! The loop the MCP write-path fix rests on, link by link.
//!
//! The fix is: resolve the AUTHOR's viewer on an unstamped `epigraph_app`
//! connection, hand it to `ScopedPool::begin_as`, and let migration 077's tier-A
//! `WITH CHECK` admit the submission's rows. Three links, and a reviewer was
//! right that no single test drives all three. Two were already pinned; this file
//! adds the third and names the composition so the chain is legible.
//!
//! * **resolve → the author's real memberships, on a NON-BYPASSING app session.**
//!   `Viewer::resolve` is the one membership read in the system that provably runs
//!   with no tenancy GUC — it is computing the very context a stamp would carry —
//!   so it goes through `epigraph_live_memberships(uuid)`, which migration 077
//!   declares `SECURITY DEFINER`, owns as `epigraph_maintenance` and grants to
//!   `epigraph_app`. THIS FILE, arm 1, with the calibration that the direct read
//!   on the same connection returns nothing.
//! * **stamp → `epigraph_writable_groups()`.** THIS FILE, arm 2, under
//!   `begin_as` — the primitive the MCP path uses, with `is_local = true`.
//!   `qual_guc_coherence.rs::writable_gucs_match_the_viewers_writable_set` and
//!   `the_personal_group_reaches_the_session_gucs` pin the same property under
//!   `acquire_as`, which is the sibling primitive, not this one.
//! * **that GUC triple → the write is admitted, under a role that RLS filters.**
//!   `rls_enforcement.rs::an_unstamped_app_connection_cannot_write_a_claim_derived_row`,
//!   arms 3 and 4: admitted when the writable set names the parent's owner group,
//!   refused when it names a different real group.
//!
//! # Why arm 2 is not a restatement of the type
//!
//! `apply_session_gucs` is private with exactly two callers and cannot be called
//! directly, so the only way to observe what `begin_as` wrote is to ask the
//! database the same question the policies ask — `SELECT
//! epigraph_writable_groups()` — inside the transaction it opened. A test that
//! read `current_setting('epigraph.writable_group_ids')` instead would assert the
//! GUC's NAME and not the function's answer, and the function is what every
//! `WITH CHECK` in migration 077 calls.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use sqlx::PgPool;
use uuid::Uuid;

fn sorted(mut v: Vec<Uuid>) -> Vec<Uuid> {
    v.sort_unstable();
    v
}

/// ARM 1. `Viewer::resolve` on a genuinely non-bypassing, UNSTAMPED
/// `epigraph_app` session returns the author's live memberships — including the
/// `admin` membership in its personal group that makes the set WRITABLE.
///
/// This is the bootstrap the whole fix stands on, and it is the one link nothing
/// ran. If it did not hold, the write path would stamp `{}` for every author and
/// the conversion would have replaced a half-landed orphan with a total refusal.
///
/// The calibration is the second half and it is what makes this
/// non-circularity rather than a restatement: the SAME connection's direct
/// `SELECT … FROM group_memberships` sees nothing, because `group_memberships` is
/// policed against exactly this session shape. So the rows reach the viewer
/// through the definer frame or not at all.
#[sqlx::test(migrations = "../../migrations")]
async fn viewer_resolve_reaches_the_authors_memberships_on_an_unstamped_app_session(pool: PgPool) {
    let (author, author_group) = fixture::seed_agent_with_group(&pool, "loopauthor").await;

    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(&pool)
            .await
            .expect("read epigraph_app's rolbypassrls");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS, so nothing below is filtered and both halves of this arm \
         are vacuous. Fix the role, not this test."
    );

    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;

    // CALIBRATION, on the same role and the same absence of GUCs the resolve
    // runs under: the direct read is empty. This is migration 077's own recorded
    // measurement for `epigraph_live_memberships` ("as epigraph_app with no
    // GUCs: the direct read returns 0 rows and this call returns 1").
    let direct: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM group_memberships WHERE agent_id = $1 AND revoked_at IS NULL",
    )
    .bind(author)
    .fetch_one(&app)
    .await
    .expect("the direct membership read must not ERROR — it must return nothing");
    assert_eq!(
        direct, 0,
        "the direct read returned rows, so this arm cannot tell the SECURITY DEFINER frame from \
         an unpoliced table and proves nothing about the bootstrap"
    );

    let viewer = Viewer::resolve(&app, author).await.expect(
        "resolve the author's viewer on the unstamped app connection, as the write path does",
    );

    assert!(
        viewer.writable_groups().contains(&author_group),
        "the author's `admin` membership in its own personal group must reach `writable` even \
         though the session that read it is unstamped and non-bypassing. An empty set here is \
         the failure mode the whole conversion would silently inherit: every submission stamped \
         `{{}}`, every tier-A WITH CHECK refusing it. Got: {:?}",
        viewer.writable_groups()
    );
}

/// ARM 2. What `begin_as` stamps is what the policies read.
///
/// `epigraph_writable_groups()` is the function every tier-A `WITH CHECK` in
/// migration 077 calls, and this asks it inside the transaction `begin_as`
/// opened, comparing its answer to the viewer that was handed in. The
/// `is_local = true` stamp `begin_as` uses is a silent no-op outside a
/// transaction block, so a readback as a SECOND statement is also a genuine test
/// that the handle is inside one.
#[sqlx::test(migrations = "../../migrations")]
async fn begin_as_stamps_the_writable_groups_the_policies_read(pool: PgPool) {
    let (author, author_group) = fixture::seed_agent_with_group(&pool, "loopstamp").await;
    let scoped = fixture::scoped_pool(&pool).await;

    // Resolved on the superuser pool, which is what the MCP server's
    // `server.pool` is on a maintained DSN; arm 1 covers the downgraded case.
    let viewer = Viewer::resolve(&pool, author).await.expect("resolve");
    let expected = sorted(viewer.writable_groups().to_vec());
    assert_eq!(
        expected,
        vec![author_group],
        "CALIBRATION: the author has exactly one writable group, its personal one"
    );

    let mut tx = scoped.begin_as(&viewer).await.expect("begin_as");

    let (writable,): (Vec<Uuid>,) = sqlx::query_as("SELECT epigraph_writable_groups()")
        .fetch_one(&mut *tx)
        .await
        .expect("epigraph_writable_groups()");
    assert_eq!(
        sorted(writable),
        expected,
        "the transaction-scoped stamp must make the function every WITH CHECK calls return the \
         AUTHOR's writable set. A mismatch here means the rows the submission writes are \
         judged against a set nobody chose."
    );

    let (principal,): (Option<Uuid>,) = sqlx::query_as("SELECT epigraph_principal_id()")
        .fetch_one(&mut *tx)
        .await
        .expect("epigraph_principal_id()");
    assert_eq!(
        principal,
        Some(author),
        "the principal GUC must name the AUTHOR — the creator arm on `groups_tenancy` and the \
         audit trail both key on it"
    );

    tx.rollback().await.expect("rollback");
}
