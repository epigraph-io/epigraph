//! The tables the loudly-refused MCP tools write — `challenges` (challenge_claim)
//! — are tier-A, and on an UNSTAMPED application session their INSERT is refused.
//!
//! # Why these arms exist separately from the tools
//!
//! An MCP-level test cannot assert this. `#[sqlx::test]` connects as `epigraph`:
//! superuser, `BYPASSRLS`, owner of every protected table, so an arm shaped "the
//! tool now succeeds" passes identically on the unconverted tree — the vacuity
//! three reviewers of PR #494 raised. So these arms run as the real
//! non-bypassing `epigraph_app` role, each asserts `rolbypassrls = false` first,
//! and each pair differs in exactly ONE thing: whether the three session GUCs
//! `ScopedPool::begin_as` sets are set.
//!
//! # The group the stamp must carry is the CLAIM's, not the writer's
//!
//! `challenges` is claim-derived, so migration 074's
//! `epigraph_derived_require_tenancy` (BEFORE INSERT ROW) fills
//! `(visibility, owner_group_id)` from the parent claim and 070 arm (c) re-stamps
//! it unconditionally on AFTER INSERT STATEMENT. The `WITH CHECK` is therefore
//! about the CLAIM's owning group. The arms below pin both directions of that,
//! because it is the property that decides which challenges a converted
//! `challenge_claim` can still not write — and a test that only stamped "the
//! author's group" over a self-owned claim would hide it.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::repos::ChallengeRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn assert_app_role_does_not_bypass(pool: &PgPool) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app's rolbypassrls");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS, so no policy filters it and every arm in this file is \
         vacuous. Fix the role, not this test."
    );
}

/// Bind the three session GUCs the 077 policies read, exactly as
/// `ScopedPool::begin_as` does (`epigraph-db/src/pool.rs::SET_SESSION_GUCS`).
/// `begin_as` cannot be used directly: it takes a `ScopedPool`, and
/// `ScopedPoolOptions` exposes no `after_connect`, so there is no way to build
/// one whose connections have been switched to `epigraph_app`.
async fn set_gucs(conn: &mut sqlx::PgConnection, groups: &str, writable: &str, principal: &str) {
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(groups)
    .bind(writable)
    .bind(principal)
    .execute(&mut *conn)
    .await
    .expect("set session gucs");
}

/// A claim in the shape the MCP write path produces:
/// `('public', personal_group_of(author))`.
async fn seed_author_owned_public_claim(
    pool: &PgPool,
    author: Uuid,
    author_group: Uuid,
    content: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             is_current, visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.8, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(author)
    .bind(author_group)
    .execute(pool)
    .await
    .expect("seed an author-owned public claim on the superuser harness connection");
    id
}

async fn challenge_count(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM challenges WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("count challenges")
}

/// **The refusal `challenge_claim` produced on every call.** The unstamped
/// steady state of the MCP request path: three empty GUCs, so
/// `epigraph_writable_groups()` is `{}` and no row can satisfy the tier-A
/// `WITH CHECK`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_challenge_insert_is_refused_on_an_unstamped_app_session(pool: PgPool) {
    let (author, author_group) = fixture::seed_agent_with_group(&pool, "chal-unstamped").await;
    let claim =
        seed_author_owned_public_claim(&pool, author, author_group, "challenge gate: unstamped")
            .await;
    assert_app_role_does_not_bypass(&pool).await;

    let out = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        set_gucs(&mut conn, "", "", "").await;
        let out = ChallengeRepository::create(
            &mut *conn,
            claim,
            Some(author),
            "insufficient_evidence",
            "unstamped arm",
        )
        .await;
        (conn, out)
    })
    .await;

    let err = out.expect_err("an unstamped app session must not be able to write a challenge");
    let msg = err.to_string();
    assert!(
        msg.contains("42501") || msg.to_lowercase().contains("row-level security"),
        "the refusal must be the row-level security one, not an unrelated failure: {msg}"
    );
    assert_eq!(
        challenge_count(&pool, claim).await,
        0,
        "nothing may be written on the refused path"
    );
}

/// **The converted shape.** Same role, same function, same row — with the
/// session stamped from a viewer that can write the CHALLENGED CLAIM's group,
/// the INSERT lands. The only difference from the arm above is the stamp.
#[sqlx::test(migrations = "../../migrations")]
async fn a_challenge_insert_lands_when_the_session_carries_the_claims_group(pool: PgPool) {
    let (author, author_group) = fixture::seed_agent_with_group(&pool, "chal-stamped").await;
    let claim =
        seed_author_owned_public_claim(&pool, author, author_group, "challenge gate: stamped")
            .await;
    assert_app_role_does_not_bypass(&pool).await;

    let out = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        set_gucs(
            &mut conn,
            &author_group.to_string(),
            &author_group.to_string(),
            &author.to_string(),
        )
        .await;
        let out = ChallengeRepository::create(
            &mut *conn,
            claim,
            Some(author),
            "insufficient_evidence",
            "stamped arm",
        )
        .await;
        (conn, out)
    })
    .await;

    assert!(
        out.is_ok(),
        "a session stamped with the claim's owning group must be able to write the challenge: \
         {out:?}"
    );
    assert_eq!(challenge_count(&pool, claim).await, 1);
}

/// **The residual, pinned so it cannot be mistaken for a regression later.** A
/// challenger stamped with its OWN group, objecting to a claim owned by a
/// different group, is still refused — because the row inherits the CLAIM's
/// tenancy and the `WITH CHECK` asks about that group.
///
/// This is the one thing the conversion does not fix, and it is a tenancy-model
/// question (should an objection be owned by the objector?) rather than a
/// stamping bug. Asserting it here means a future change to the derived-tenancy
/// triggers has to come and edit this arm deliberately.
#[sqlx::test(migrations = "../../migrations")]
async fn a_challenge_against_a_foreign_groups_claim_is_still_refused(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "chal-owner").await;
    let (challenger, challenger_group) =
        fixture::seed_agent_with_group(&pool, "chal-challenger").await;
    let claim =
        seed_author_owned_public_claim(&pool, owner, owner_group, "challenge gate: foreign group")
            .await;
    assert_app_role_does_not_bypass(&pool).await;

    let out = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        set_gucs(
            &mut conn,
            &challenger_group.to_string(),
            &challenger_group.to_string(),
            &challenger.to_string(),
        )
        .await;
        let out = ChallengeRepository::create(
            &mut *conn,
            claim,
            Some(challenger),
            "factual_error",
            "foreign-group arm",
        )
        .await;
        (conn, out)
    })
    .await;

    assert!(
        out.is_err(),
        "a challenge inherits the CHALLENGED claim's owner_group_id, so a challenger with write \
         authority only in its own group cannot write it. If this now succeeds, the \
         derived-tenancy triggers changed and `challenge_claim`'s doc must be revisited: {out:?}"
    );
    assert_eq!(challenge_count(&pool, claim).await, 0);
}
