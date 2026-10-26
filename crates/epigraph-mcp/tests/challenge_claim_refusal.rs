//! `challenge_claim` under operator ruling R-CH1 (migration 168) and R-CH1b.
//!
//! * An OUTSIDER (a challenger that cannot write the challenged claim's owning
//!   group) challenging a PUBLIC claim succeeds, and the row is owned by the
//!   outsider's own write group, public, `writer_owned`. Before 168 the row
//!   inherited the claim's group and was refused (the tool answered that by
//!   name, backlog deebc487).
//! * An insider's challenge inherits the claim's tenancy, as before.
//! * A group-private claim the challenger can READ but not write is a clean,
//!   named refusal (no outsider-owned private row the claim's owners could not
//!   see).
//! * A claim the challenger cannot read answers EXACTLY like a nonexistent
//!   claim id (R-CH1b): same code, same text modulo the id, same data.
//! * After the claim is privatized, `list_challenges` on it answers a
//!   non-member exactly as it answers a random id: the outsider's public row
//!   must not become an existence oracle for the private claim.
//!
//! Both pools of the server are downgraded to `epigraph_app` (a superuser pool
//! bypasses the policies, and 114's attach rule leaves a privileged session on
//! the inherit path, so every arm would be vacuous); the fixture is seeded on
//! the superuser pool. Both transports are covered: stdio (`auth: None`, the
//! server's own agent) and an HTTP caller with a `claims:write` token.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::challenges::{challenge_claim, list_challenges};
use epigraph_mcp::tools::events::list_events;
use epigraph_mcp::types::{ChallengeclaimParams, ListChallengesParams, ListEventsParams};
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

/// `(owner_group_id, visibility, writer_owned)` of the one challenge on `claim`.
async fn challenge_tenancy(pool: &PgPool, claim: Uuid) -> (Uuid, String, bool) {
    sqlx::query_as(
        "SELECT owner_group_id, visibility::text, writer_owned FROM challenges \
          WHERE claim_id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("exactly one challenge on the claim")
}

fn ok_json(r: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = r
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("a text result");
    serde_json::from_str(&text).expect("json result")
}

/// R-CH1 on both transports: an outsider's challenge on another group's PUBLIC
/// claim lands, owned by the outsider's own group, public and flagged; an
/// insider's challenge (the HTTP caller on its own claim) inherits as before.
#[sqlx::test(migrations = "../../migrations")]
async fn an_outsiders_challenge_on_a_public_claim_is_owned_by_the_outsider(pool: PgPool) {
    let (server, agent, viewer) = app_role_server(&pool).await;
    let server_group = personal_group_of(&pool, agent).await;
    let (author, author_group) =
        fixture::seed_agent_with_group(&pool, "challenge-target-author").await;
    let on_stdio = public_claim_in(&pool, author, author_group, "public, B's group, stdio").await;
    let on_http = public_claim_in(&pool, author, author_group, "public, B's group, http").await;

    // stdio: the server's own agent challenges another group's public claim.
    let r = challenge_claim(&server, &viewer, params(on_stdio), None)
        .await
        .expect("an outsider's challenge on a public claim lands (R-CH1)");
    assert_eq!(ok_json(&r)["claim_id"], on_stdio.to_string());
    assert_eq!(
        challenge_tenancy(&pool, on_stdio).await,
        (server_group, "public".to_string(), true),
        "stdio: owned by the server agent's group, public, writer-owned"
    );

    // HTTP: a `claims:write` caller, a different identity from the server's.
    let (caller, token, caller_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let caller_group = personal_group_of(&pool, caller).await;
    challenge_claim(&server, &caller_viewer, params(on_http), Some(&token))
        .await
        .expect("an HTTP outsider's challenge on a public claim lands");
    assert_eq!(
        challenge_tenancy(&pool, on_http).await,
        (caller_group, "public".to_string(), true),
        "http: owned by the CALLER's group, not the server's"
    );

    // Insider control: the caller challenges its own public claim and the row
    // inherits the claim's tenancy, unflagged.
    let callers = public_claim_in(&pool, caller, caller_group, "public, caller's group").await;
    challenge_claim(&server, &caller_viewer, params(callers), Some(&token))
        .await
        .expect("an insider's challenge lands");
    assert_eq!(
        challenge_tenancy(&pool, callers).await,
        (caller_group, "public".to_string(), false)
    );
}

/// A group-private claim the challenger can READ (a reader member of its
/// group) but not write: a clean, named refusal, not the raw row-security
/// error, and the owning group is not disclosed. Nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_readable_private_claim_the_challenger_cannot_write_is_a_clean_refusal(pool: PgPool) {
    let (server, _agent, _viewer) = app_role_server(&pool).await;
    let (author, author_group) =
        fixture::seed_agent_with_group(&pool, "challenge-private-author").await;
    let (caller, token, _) = seed_caller(&pool, &["claims:write"]).await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(author_group)
    .bind(caller)
    .execute(&pool)
    .await
    .expect("reader membership");
    let caller_viewer = Viewer::resolve(&pool, caller).await.expect("viewer");
    let private = fixture::seed_group_claim(&pool, author, author_group, "B's private claim").await;

    let e = challenge_claim(&server, &caller_viewer, params(private), Some(&token))
        .await
        .expect_err("a reader cannot challenge a private claim");
    assert_clean_refusal(&e, private, author_group, "reader");
    assert_eq!(challenges_on(&pool, private).await, 0, "nothing written");
}

/// R-CH1b: a claim the challenger cannot read is answered EXACTLY like a claim
/// id that does not exist, on both transports: same error code, same message
/// with the id replaced, same data. Nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unreadable_claim_is_indistinguishable_from_a_nonexistent_one(pool: PgPool) {
    let (server, _agent, viewer) = app_role_server(&pool).await;
    let (author, author_group) =
        fixture::seed_agent_with_group(&pool, "challenge-hidden-author").await;
    let hidden = fixture::seed_group_claim(&pool, author, author_group, "B's hidden claim").await;
    let missing = Uuid::new_v4();
    let (_caller, token, caller_viewer) = seed_caller(&pool, &["claims:write"]).await;

    let shape = |e: &rmcp::ErrorData, id: Uuid| {
        (
            e.code,
            e.message.replace(&id.to_string(), "<id>"),
            e.data
                .as_ref()
                .map(|d| d.to_string().replace(&id.to_string(), "<id>")),
        )
    };
    for (arm, v, auth) in [
        ("stdio", &viewer, None),
        ("http", &caller_viewer, Some(&token)),
    ] {
        let on_hidden = challenge_claim(&server, v, params(hidden), auth)
            .await
            .expect_err("an unreadable claim");
        let on_missing = challenge_claim(&server, v, params(missing), auth)
            .await
            .expect_err("a nonexistent claim");
        assert_eq!(
            shape(&on_hidden, hidden),
            shape(&on_missing, missing),
            "{arm}: an unreadable claim must answer exactly as a nonexistent one"
        );
        assert!(
            on_missing.message.contains("not found"),
            "{arm}: positive pin on the shared text: {on_missing:?}"
        );
    }
    assert_eq!(challenges_on(&pool, hidden).await, 0, "nothing written");
}

/// R-CH1b on the read side. The outsider's challenge is public and stays where
/// it is when the claim is privatized (168), so `list_challenges` on the now
/// private claim must answer a non-member exactly as it answers a random id:
/// otherwise the outsider's row is an existence oracle for a private claim.
/// While the claim is public the challenge is listed (the positive control).
#[sqlx::test(migrations = "../../migrations")]
async fn listing_a_privatized_claims_challenges_is_no_existence_oracle(pool: PgPool) {
    let (server, _agent, viewer) = app_role_server(&pool).await;
    let (author, author_group) =
        fixture::seed_agent_with_group(&pool, "challenge-list-author").await;
    let claim = public_claim_in(&pool, author, author_group, "public, to be privatized").await;
    challenge_claim(&server, &viewer, params(claim), None)
        .await
        .expect("an outsider's challenge on a public claim lands");
    let (_stranger, _token, stranger_viewer) = seed_caller(&pool, &["claims:read"]).await;

    let listed = |r: rmcp::model::CallToolResult| ok_json(&r)["total"].as_u64().expect("total");
    let list = |id: Uuid| ListChallengesParams {
        claim_id: id.to_string(),
    };
    let before = list_challenges(&server, &stranger_viewer, list(claim))
        .await
        .expect("list");
    assert_eq!(
        listed(before),
        1,
        "control: a public claim's challenge is listed"
    );
    // The `claim.challenged` event names the claim: the event surface must
    // hide it with the claim too.
    let events_naming_claim = |r: rmcp::model::CallToolResult| {
        ok_json(&r).to_string().matches(&claim.to_string()).count()
    };
    let challenged = || ListEventsParams {
        event_type: Some("claim.challenged".to_string()),
        actor_id: None,
        limit: Some(100),
    };
    let ev_before = list_events(&server, &stranger_viewer, challenged())
        .await
        .expect("list events");
    assert!(
        events_naming_claim(ev_before) > 0,
        "control: the challenge's event is listed while the claim is public"
    );

    sqlx::query("UPDATE claims SET visibility = 'group' WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .expect("privatize the claim");
    let on_private = list_challenges(&server, &stranger_viewer, list(claim))
        .await
        .expect("list");
    let on_random = list_challenges(&server, &stranger_viewer, list(Uuid::new_v4()))
        .await
        .expect("list");
    assert_eq!(
        ok_json(&on_private),
        ok_json(&on_random),
        "a privatized claim's challenges answer a non-member exactly as a random id does"
    );
    let ev_after = list_events(&server, &stranger_viewer, challenged())
        .await
        .expect("list events");
    assert_eq!(
        events_naming_claim(ev_after),
        0,
        "no event names the privatized claim to a non-member"
    );
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
