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
//!   Arm 1b is the sibling measurement that keeps a write path from "helpfully"
//!   ensuring the author's group on that same connection: the `groups` lookup is
//!   blind there too, so an ensure would take its membership-REVIVING mint path
//!   on every submission.
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

/// ARM 1b. THE READ THAT LOOKS SAFE AND IS BLIND: `personal_group_of`'s
/// `SELECT id FROM groups WHERE did_key = …` sees NOTHING on the same unstamped
/// app session, so on that session it always takes its MINT path — and the mint
/// revives a revoked membership.
///
/// # Why this arm exists at all
///
/// `epigraph-mcp`'s `begin_author_stamped_tx` briefly called
/// `ClaimRepository::personal_group_of_pool` on `server.pool` as belt-and-braces
/// before resolving the author's viewer. That call was removed, and this arm is
/// the measurement that says why rather than leaving it to a comment nobody can
/// check.
///
/// `personal_group_of`'s doc stated its read-first order as a SECURITY property:
/// migration 077's `epigraph_ensure_personal_group` membership statement was
/// `ON CONFLICT (group_id, agent_id, epoch) DO UPDATE SET revoked_at = NULL,
/// role = 'admin'`, so the mint path REVIVED a revoked membership, and the
/// lookup was what kept a write path from reaching it. Migration 105 makes the
/// mint refuse a revoked row instead; the second half below now pins that. That property holds only
/// if the lookup can see the row. On an unstamped `epigraph_app` session it
/// cannot: `groups_tenancy`'s USING is `bypass OR definer_bypass OR id =
/// ANY(session_groups) OR created_by_agent_id = principal_id` (migration 077
/// §6), and every arm is false there.
///
/// So a write path that called it on `server.pool` would re-mint on EVERY
/// submission, silently restoring memberships somebody revoked — and it would
/// have passed every `#[sqlx::test]` arm, because the superuser harness reads
/// `groups` fine and therefore never reaches the mint.
#[sqlx::test(migrations = "../../migrations")]
async fn the_personal_group_lookup_is_blind_on_an_unstamped_app_session(pool: PgPool) {
    let (author, author_group) = fixture::seed_agent_with_group(&pool, "loopblind").await;
    let did_key = format!("did:epigraph:personal:{author}");

    // CALIBRATION: the superuser harness sees the row, so the 0 below is the
    // POLICY and not a missing fixture.
    let seen_as_superuser: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM groups WHERE did_key = $1")
            .bind(&did_key)
            .fetch_one(&pool)
            .await
            .expect("read groups as the harness role");
    assert_eq!(
        seen_as_superuser, 1,
        "the fixture must have seeded the personal group under the deterministic did_key"
    );

    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let seen_as_app: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM groups WHERE did_key = $1")
        .bind(&did_key)
        .fetch_one(&app)
        .await
        .expect("the read must not ERROR — it must return nothing");
    assert_eq!(
        seen_as_app, 0,
        "if the unstamped app session CAN see the group, `personal_group_of` is a real \
         read-first lookup on the MCP write path and the belt-and-braces pre-ensure that was \
         removed from `begin_author_stamped_tx` can be restored. Until then it is a blind read \
         that always mints."
    );

    // The second half: what the mint does to a revoked membership. Measured on
    // the harness role, because the hazard is the STATEMENT's `ON CONFLICT`, not
    // who calls it.
    sqlx::query("UPDATE group_memberships SET revoked_at = now() WHERE agent_id = $1")
        .bind(author)
        .execute(&pool)
        .await
        .expect("revoke the author's membership");
    let live_before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM group_memberships \
          WHERE agent_id = $1 AND group_id = $2 AND revoked_at IS NULL",
    )
    .bind(author)
    .bind(author_group)
    .fetch_one(&pool)
    .await
    .expect("count live memberships");
    assert_eq!(live_before, 0, "CALIBRATION: the revoke took effect");

    // Since migration 105 the mint REFUSES a revoked row (SQLSTATE RVK01)
    // instead of reviving it. Before 105 this call succeeded and `live_after`
    // below was 1 — the revival this arm used to pin as the reason the blind
    // read must not reach a write path. The blind read is still blind (first
    // half); what it can reach is no longer a revival.
    let err =
        sqlx::query_scalar::<_, uuid::Uuid>("SELECT public.epigraph_ensure_personal_group($1)")
            .bind(author)
            .fetch_one(&pool)
            .await
            .expect_err("the blind read's fallback must now be refused, not revive");
    assert_eq!(
        err.as_database_error()
            .and_then(|d| d.code().map(|c| c.to_string()))
            .as_deref(),
        Some(epigraph_db::PERSONAL_MEMBERSHIP_REVOKED)
    );
    let live_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM group_memberships \
          WHERE agent_id = $1 AND group_id = $2 AND revoked_at IS NULL",
    )
    .bind(author)
    .bind(author_group)
    .fetch_one(&pool)
    .await
    .expect("count live memberships");
    assert_eq!(
        live_after, 0,
        "the mint path must NOT revive the revoked membership (migration 105). If this ever \
         returns 1 again the refusal was undone, and a blind read on a write path is once more \
         a privilege restoration — see `epigraph-mcp/src/claim_helper.rs::begin_author_stamped_tx`."
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
