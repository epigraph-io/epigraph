//! The tables the loudly-refused MCP tools write — `challenges`
//! (challenge_claim), `claim_frames` and `mass_functions` (submit_ds_evidence) —
//! are tier-A, and on an UNSTAMPED application session their INSERT is refused.
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
//! All three tables are claim-derived, so migration 074's
//! `epigraph_derived_require_tenancy` (BEFORE INSERT ROW) fills
//! `(visibility, owner_group_id)` from the parent claim and 070 arm (c) re-stamps
//! it unconditionally on AFTER INSERT STATEMENT. The `WITH CHECK` is therefore
//! about the CLAIM's owning group. The arms below pin both directions of that,
//! because it is the property that decides which challenges a converted
//! `challenge_claim` can still not write — and a test that only stamped "the
//! author's group" over a self-owned claim would hide it.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::repos::{ChallengeRepository, FrameRepository, MassFunctionRepository};
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

// ===========================================================================
// submit_ds_evidence's two tables: `claim_frames` and `mass_functions`.
//
// `mass_functions` is the one whose emptiness was the original symptom — its
// last successful production write was 2026-09-22 and it stayed 0 through every
// e2e run, which is why every `supports` / `refutes` edge created since the DSN
// moved to `epigraph_app` has moved NO belief mass.
// ===========================================================================

/// A frame to hang the BBA on. `frames` is one of migration 077 §2b's four
/// instance-wide registries, so it has a STATIC widening arm and is NOT part of
/// what these arms measure — it is fixture, seeded on the superuser connection.
async fn seed_frame(pool: &PgPool, name: &str) -> Uuid {
    FrameRepository::create(
        pool,
        name,
        Some("fixture frame for the stamped-write arms"),
        &["true".to_string(), "false".to_string()],
    )
    .await
    .expect("seed frame")
    .id
}

async fn claim_frame_count(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM claim_frames WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("count claim_frames")
}

async fn mass_function_count(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM mass_functions WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("count mass_functions")
}

/// `submit_ds_evidence`'s FIRST write, refused on the unstamped session — the
/// `42501` the tool returned verbatim on both schema configurations.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_frame_assignment_is_refused_on_an_unstamped_app_session(pool: PgPool) {
    let (author, author_group) = fixture::seed_agent_with_group(&pool, "cf-unstamped").await;
    let claim =
        seed_author_owned_public_claim(&pool, author, author_group, "claim_frames gate: unstamped")
            .await;
    let frame = seed_frame(&pool, "cf-unstamped-frame").await;
    assert_app_role_does_not_bypass(&pool).await;

    let out = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        set_gucs(&mut conn, "", "", "").await;
        let out = FrameRepository::assign_claim(&mut *conn, claim, frame, Some(0)).await;
        (conn, out)
    })
    .await;

    let msg = out
        .expect_err("an unstamped app session must not be able to assign a claim to a frame")
        .to_string();
    assert!(
        msg.contains("42501") || msg.to_lowercase().contains("row-level security"),
        "the refusal must be the row-level security one: {msg}"
    );
    assert_eq!(claim_frame_count(&pool, claim).await, 0);
}

/// The converted shape: same role, same function, same row, GUCs stamped from a
/// viewer that can write the claim's group. The ONLY difference is the stamp.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_frame_assignment_lands_when_the_session_carries_the_claims_group(pool: PgPool) {
    let (author, author_group) = fixture::seed_agent_with_group(&pool, "cf-stamped").await;
    let claim =
        seed_author_owned_public_claim(&pool, author, author_group, "claim_frames gate: stamped")
            .await;
    let frame = seed_frame(&pool, "cf-stamped-frame").await;
    assert_app_role_does_not_bypass(&pool).await;

    let out = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        set_gucs(
            &mut conn,
            &author_group.to_string(),
            &author_group.to_string(),
            &author.to_string(),
        )
        .await;
        let out = FrameRepository::assign_claim(&mut *conn, claim, frame, Some(0)).await;
        (conn, out)
    })
    .await;

    assert!(out.is_ok(), "stamped assign_claim must land: {out:?}");
    assert_eq!(claim_frame_count(&pool, claim).await, 1);
}

/// `mass_functions` — the table that stayed 0 — refused on the unstamped session.
#[sqlx::test(migrations = "../../migrations")]
async fn a_mass_function_insert_is_refused_on_an_unstamped_app_session(pool: PgPool) {
    let (author, author_group) = fixture::seed_agent_with_group(&pool, "mf-unstamped").await;
    let claim = seed_author_owned_public_claim(
        &pool,
        author,
        author_group,
        "mass_functions gate: unstamped",
    )
    .await;
    let frame = seed_frame(&pool, "mf-unstamped-frame").await;
    assert_app_role_does_not_bypass(&pool).await;
    let masses = serde_json::json!({"true": 0.6, "true,false": 0.4});

    let out = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        set_gucs(&mut conn, "", "", "").await;
        let out = MassFunctionRepository::store_with_perspective(
            &mut *conn,
            claim,
            frame,
            Some(author),
            None,
            &masses,
            None,
            Some("Dempster"),
            None,
            None,
            "unknown",
            None,
        )
        .await;
        (conn, out)
    })
    .await;

    let msg = out
        .expect_err("an unstamped app session must not be able to store a BBA")
        .to_string();
    assert!(
        msg.contains("42501") || msg.to_lowercase().contains("row-level security"),
        "the refusal must be the row-level security one: {msg}"
    );
    assert_eq!(mass_function_count(&pool, claim).await, 0);
}

/// The converted shape for `mass_functions`, and the calibration for the arm
/// above: identical call, identical role, stamp added, row lands.
#[sqlx::test(migrations = "../../migrations")]
async fn a_mass_function_insert_lands_when_the_session_carries_the_claims_group(pool: PgPool) {
    let (author, author_group) = fixture::seed_agent_with_group(&pool, "mf-stamped").await;
    let claim =
        seed_author_owned_public_claim(&pool, author, author_group, "mass_functions gate: stamped")
            .await;
    let frame = seed_frame(&pool, "mf-stamped-frame").await;
    assert_app_role_does_not_bypass(&pool).await;
    let masses = serde_json::json!({"true": 0.6, "true,false": 0.4});

    let out = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        set_gucs(
            &mut conn,
            &author_group.to_string(),
            &author_group.to_string(),
            &author.to_string(),
        )
        .await;
        let out = MassFunctionRepository::store_with_perspective(
            &mut *conn,
            claim,
            frame,
            Some(author),
            None,
            &masses,
            None,
            Some("Dempster"),
            None,
            None,
            "unknown",
            None,
        )
        .await;
        (conn, out)
    })
    .await;

    assert!(out.is_ok(), "stamped BBA store must land: {out:?}");
    assert_eq!(mass_function_count(&pool, claim).await, 1);
}

// ===========================================================================
// `update_labels`' RESIDUAL: relabelling a FOREIGN agent's claim.
//
// `tools/claims.rs::update_labels` stamps `begin_author_stamped_tx(server,
// server.agent_id(), …)` — the MCP process's own agent, deliberately narrower
// than author-stamping, because `server.rs::agent_id` ensures a personal group
// for that agent and nothing else, so the writable set is exactly one group.
// Its own comment concedes the consequence: a `claims:admin` HTTP caller
// relabelling ANOTHER agent's claim is still refused on a cleanly-migrated
// schema.
//
// That concession had no measurement behind it. The MCP-level arm that looks
// like it measures it — `epigraph-mcp/tests/retirement_label_ownership.rs::
// update_labels_admin_scope_passes_the_retirement_authz_gate` — runs on the
// `#[sqlx::test]` superuser, so its write half is vacuous: it passes identically
// whatever the policies say. What that arm legitimately pins is issue #374's
// AUTHZ gate (does `claims:admin` satisfy `require_owner_or_admin`); the tenancy
// half is measured here, on the non-bypassing role, in both directions.
//
// This matters operationally rather than academically. `gate_retirement_label`'s
// own doc records that epiclaw's baked `CLAUDE.md` instructs every scheduled
// agent to retire cross-agent backlog items with
// `update_labels(original_id, add=["resolved"])` precisely BECAUSE
// `resolve_backlog_item` refuses them — and a cross-agent backlog item is a
// foreign claim by definition. So the sanctioned ops path is the one the arm
// below shows is refused once the orphan `claims_privacy` policy is dropped.
// Registered, not fixed: the fix is a tenancy-model decision (may an admin scope
// carry write authority into a group it is not a member of?), not a stamping one,
// and the same residual applies to `challenge_claim` above and to
// `update_with_evidence`'s `update_truth_value` / `update_labels` on a foreign
// claim.
// ===========================================================================

async fn labels_of(pool: &PgPool, claim: Uuid) -> Vec<String> {
    sqlx::query_scalar::<_, Vec<String>>(
        "SELECT COALESCE(labels, ARRAY[]::text[]) FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("read labels")
}

/// **The residual.** A session stamped from agent A's writable set — which is
/// what `update_labels` stamps, whatever the HTTP caller's scope — cannot add a
/// label to a claim owned by agent B's personal group. `claims_tenancy`'s
/// `WITH CHECK` asks `owner_group_id = ANY(epigraph_writable_groups())` about the
/// NEW row, and the UPDATE does not change `owner_group_id`, so the foreign group
/// is still the group being asked about.
#[sqlx::test(migrations = "../../migrations")]
async fn relabelling_a_foreign_groups_claim_is_refused_on_a_stamped_app_session(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "label-owner").await;
    let (server_agent, server_group) = fixture::seed_agent_with_group(&pool, "label-server").await;
    let claim =
        seed_author_owned_public_claim(&pool, owner, owner_group, "update_labels gate: foreign")
            .await;
    assert_app_role_does_not_bypass(&pool).await;
    assert_ne!(
        owner_group, server_group,
        "the two groups must differ or this arm measures nothing"
    );

    let out = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        set_gucs(
            &mut conn,
            &server_group.to_string(),
            &server_group.to_string(),
            &server_agent.to_string(),
        )
        .await;
        let out = epigraph_db::ClaimRepository::update_labels_conn(
            &mut conn,
            claim,
            &["resolved".to_string()],
            &[],
        )
        .await;
        (conn, out)
    })
    .await;

    let msg = out
        .expect_err(
            "a session carrying only the MCP server agent's own group must not be able to \
             relabel a claim owned by another agent's group. If this now succeeds, either the \
             policies were widened (which migration 077 §2 names as the failure it exists to \
             prevent) or `update_labels` changed whose viewer it stamps — both require editing \
             the comment at that call site.",
        )
        .to_string();
    assert!(
        msg.contains("42501") || msg.to_lowercase().contains("row-level security"),
        "the refusal must be the row-level security one, not an unrelated failure: {msg}"
    );
    assert!(
        !labels_of(&pool, claim).await.contains(&"resolved".to_string()),
        "nothing may be written on the refused path"
    );
}

/// **The calibration.** Same role, same function, same claim shape — stamped
/// with the CLAIM's own owning group, the relabel lands. Without this arm the
/// refusal above could be an unrelated failure (a rejected label, a missing row)
/// and nothing would tell the difference.
#[sqlx::test(migrations = "../../migrations")]
async fn relabelling_lands_when_the_session_carries_the_claims_own_group(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "label-self").await;
    let claim =
        seed_author_owned_public_claim(&pool, owner, owner_group, "update_labels gate: own group")
            .await;
    assert_app_role_does_not_bypass(&pool).await;

    let out = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        set_gucs(
            &mut conn,
            &owner_group.to_string(),
            &owner_group.to_string(),
            &owner.to_string(),
        )
        .await;
        let out = epigraph_db::ClaimRepository::update_labels_conn(
            &mut conn,
            claim,
            &["resolved".to_string()],
            &[],
        )
        .await;
        (conn, out)
    })
    .await;

    assert!(
        out.is_ok(),
        "a session stamped with the claim's own owning group must be able to relabel it: {out:?}"
    );
    assert!(labels_of(&pool, claim)
        .await
        .contains(&"resolved".to_string()));
}
