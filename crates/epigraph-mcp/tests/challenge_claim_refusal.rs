//! `challenge_claim` against a claim whose owning group the challenger cannot
//! write is REFUSED BY NAME, not reported as a raw row-security error.
//!
//! The challenge row inherits the challenged claim's `(visibility,
//! owner_group_id)` (migration 074's BEFORE-row trigger, re-stamped by 070), and
//! migration 077's `WITH CHECK` on `challenges` asks for that group in the
//! stamp's writable set. So a challenger that can READ a claim (it is public)
//! but cannot WRITE its group is refused by the database. That refusal is
//! intended (the tool's own doc: "a policy question rather than a bug"); what
//! it reached the caller as was not: an `INTERNAL_ERROR` carrying `new row
//! violates row-level security policy for table "challenges"` (backlog
//! deebc487, 3/3 attempts, no row written).
//!
//! Both pools of the server are downgraded to `epigraph_app` (a superuser pool
//! bypasses the policy, so the challenge would simply land); the fixture is
//! seeded on the superuser pool. Both transports are covered: stdio (`auth:
//! None`, the server's own agent) and an HTTP caller with a `claims:write`
//! token, which is the reported shape.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::challenges::challenge_claim;
use epigraph_mcp::types::ChallengeclaimParams;
use rmcp::model::ErrorCode;
use sqlx::PgPool;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> (EpiGraphMcpFull, Uuid, Viewer) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let server = build_scoped_test_server(plain, scoped);
    let agent = server.server_agent_id().await.expect("server agent");
    let viewer = Viewer::resolve(pool, agent).await.expect("viewer");
    (server, agent, viewer)
}

/// A `visibility = 'public'` claim OWNED BY `group`: readable by every
/// session, writable only by the group's writers. The reported shape (another
/// agent's public claim, in that agent's group).
async fn public_claim_in(pool: &PgPool, agent: Uuid, group: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             is_current, visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.8, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(content)
    .bind(blake3::hash(content.as_bytes()).as_bytes().as_slice())
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed public claim");
    id
}

fn params(claim: Uuid) -> ChallengeclaimParams {
    ChallengeclaimParams {
        claim_id: claim.to_string(),
        challenge_type: "factual_error".to_string(),
        explanation: "the cited figure contradicts its own source".to_string(),
    }
}

async fn challenges_on(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM challenges WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("count challenges")
}

fn assert_clean_refusal(e: &rmcp::ErrorData, claim: Uuid, group: Uuid, arm: &str) {
    assert_eq!(e.code, ErrorCode::INVALID_REQUEST, "{arm}: {e:?}");
    assert!(
        !e.message.contains("row-level security"),
        "{arm}: the refusal must not be the raw row-security error: {e:?}"
    );
    assert!(
        e.message.contains(&claim.to_string()) && e.message.contains("nothing was written"),
        "{arm}: the message names the claim and says nothing was written: {e:?}"
    );
    let data = e.data.clone().expect("the refusal carries data");
    assert_eq!(data["error"], "not_writer", "{arm}: {data}");
    assert_eq!(
        data["rule"], "challenge_requires_claim_group_writer",
        "{arm}: {data}"
    );
    assert_eq!(data["claim_id"], claim.to_string(), "{arm}: {data}");
    assert_eq!(data["retryable"], false, "{arm}: {data}");
    // The owning group is not disclosed: no claim read surface returns it, and
    // for another agent's public claim it is usually that agent's personal
    // group.
    assert!(
        data.get("owner_group_id").is_none(),
        "{arm}: the refusal must not disclose the claim's owning group: {data}"
    );
    assert!(
        !e.message.contains(&group.to_string()) && !data.to_string().contains(&group.to_string()),
        "{arm}: the owning group's id appears nowhere in the refusal: {e:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn challenge_claim_on_an_unwritable_group_claim_is_a_clean_refusal(pool: PgPool) {
    let (server, agent, viewer) = app_role_server(&pool).await;
    let own_group = personal_group_of(&pool, agent).await;
    let (author, author_group) =
        fixture::seed_agent_with_group(&pool, "challenge-target-author").await;
    let foreign = public_claim_in(&pool, author, author_group, "a public claim, B's group").await;

    // stdio: the server's own agent challenges another group's public claim.
    let e = challenge_claim(&server, &viewer, params(foreign), None)
        .await
        .expect_err("the server agent does not write the claim's group");
    assert_clean_refusal(&e, foreign, author_group, "stdio");
    assert_eq!(
        challenges_on(&pool, foreign).await,
        0,
        "stdio: nothing written"
    );

    // HTTP: a `claims:write` caller, the reported shape.
    let (caller, token, caller_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let e = challenge_claim(&server, &caller_viewer, params(foreign), Some(&token))
        .await
        .expect_err("the caller does not write the claim's group");
    assert_clean_refusal(&e, foreign, author_group, "http");
    assert_eq!(
        challenges_on(&pool, foreign).await,
        0,
        "http: nothing written"
    );

    // HTTP control: a claim in the CALLER's own group is challenged. The same
    // claim is first refused on stdio (the server agent does not write the
    // caller's personal group), so the two identities are distinguishable:
    // a preflight that resolved the wrong identity's writable groups, or none,
    // refuses this call.
    let caller_group = personal_group_of(&pool, caller).await;
    let callers = public_claim_in(
        &pool,
        caller,
        caller_group,
        "a public claim, caller's group",
    )
    .await;
    let e = challenge_claim(&server, &viewer, params(callers), None)
        .await
        .expect_err("the server agent does not write the caller's group");
    assert_clean_refusal(&e, callers, caller_group, "stdio on the caller's claim");
    assert_eq!(challenges_on(&pool, callers).await, 0);
    challenge_claim(&server, &caller_viewer, params(callers), Some(&token))
        .await
        .expect("an HTTP caller challenges a claim in its own group");
    assert_eq!(
        challenges_on(&pool, callers).await,
        1,
        "http: the control lands"
    );

    // A claim the challenger cannot READ is not found: the refusal above is
    // only ever about a claim the caller can already see, so it adds no
    // existence oracle.
    let hidden = fixture::seed_group_claim(&pool, author, author_group, "B's private claim").await;
    let e = challenge_claim(&server, &viewer, params(hidden), None)
        .await
        .expect_err("an unreadable claim");
    assert!(
        e.message.contains("not found") && !e.message.contains("row-level security"),
        "an unreadable claim is not found: {e:?}"
    );
    assert!(
        !matches!(e.data.as_ref(), Some(d) if d["error"] == "not_writer"),
        "an unreadable claim must not be answered as a write refusal: {e:?}"
    );
    assert_eq!(challenges_on(&pool, hidden).await, 0);

    // Control: a claim in the challenger's own group is challenged normally.
    let mine = public_claim_in(&pool, agent, own_group, "a public claim, own group").await;
    challenge_claim(&server, &viewer, params(mine), None)
        .await
        .expect("the server agent challenges a claim in its own group");
    assert_eq!(challenges_on(&pool, mine).await, 1, "the control lands");
}

/// A `42501` from the challenge INSERT itself, AFTER the preflight admitted
/// the challenger (here forced by a trigger; in production a membership
/// revoked in between, or a GRANT / policy fault), is a server fault: it is
/// answered as `INTERNAL_ERROR` with a fixed message, neither the raw database
/// text nor a `not_writer` refusal that would blame the caller.
#[sqlx::test(migrations = "../../migrations")]
async fn a_42501_past_the_preflight_is_a_fixed_text_internal_error(pool: PgPool) {
    let (server, agent, viewer) = app_role_server(&pool).await;
    let own_group = personal_group_of(&pool, agent).await;
    let mine = public_claim_in(&pool, agent, own_group, "a public claim, own group").await;

    const MARKER: &str = "forced-insufficient-privilege-c41d";
    sqlx::query(&format!(
        "CREATE FUNCTION test_force_42501() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION '{MARKER}' USING ERRCODE = '42501'; END $$"
    ))
    .execute(&pool)
    .await
    .expect("create the forcing function");
    sqlx::query("GRANT EXECUTE ON FUNCTION test_force_42501() TO PUBLIC")
        .execute(&pool)
        .await
        .expect("grant execute");
    sqlx::query(
        "CREATE TRIGGER test_force_42501 BEFORE INSERT ON challenges \
         FOR EACH ROW EXECUTE FUNCTION test_force_42501()",
    )
    .execute(&pool)
    .await
    .expect("create the forcing trigger");

    let e = challenge_claim(&server, &viewer, params(mine), None)
        .await
        .expect_err("the forced 42501 refuses the INSERT");
    assert_eq!(e.code, ErrorCode::INTERNAL_ERROR, "{e:?}");
    assert!(
        !e.message.contains(MARKER),
        "the raw database text is not passed on: {e:?}"
    );
    assert!(
        e.message.contains("nothing was written") && e.message.contains(&mine.to_string()),
        "the fixed message names the claim and says nothing was written: {e:?}"
    );
    let data = e.data.clone().expect("the error carries data");
    assert_eq!(data["error"], "write_refused_after_preflight", "{data}");
    assert_eq!(challenges_on(&pool, mine).await, 0, "nothing written");
}
