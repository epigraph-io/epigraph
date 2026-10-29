//! `resolve_challenge`: the claim owner's MCP route to migration 168's
//! `epigraph_resolve_challenge` (operator rulings R-3, R-13, R-14, R-CH1b;
//! backlog bcd55cad). The HTTP twin is `POST /api/v1/challenges/:id/resolve`
//! (`epigraph-api/tests/challenge_resolution_http.rs`).
//!
//! * a writer of the challenged claim's owning group sets the status of an
//!   OUTSIDER's challenge, on both transports, and the resolver recorded is the
//!   calling principal: the server's agent on stdio, the token's own agent over
//!   HTTP (never the server's, never a caller-named id: the parameters have no
//!   resolver field and refuse unknown ones);
//! * R-14: a pending challenge is accepted directly and a settled one
//!   re-resolved, every change audited;
//! * R-13: the outsider (the row's owner) and a stranger are refused by name,
//!   `withdrawn` is not a resolution, and a withdrawn challenge takes none;
//!   nothing is written by any refusal;
//! * R-CH1b: a challenge on a claim the caller cannot read answers exactly as
//!   a random id.
//!
//! Both pools of the server are `epigraph_app` (a superuser pool would bypass
//! every policy and make each arm vacuous); fixtures are seeded on the harness
//! pool.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::challenges::{challenge_claim, resolve_challenge};
use epigraph_mcp::types::{ChallengeclaimParams, ResolveChallengeParams};
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

/// The outsider (holder of `token`) files a challenge on `claim` through the
/// real tool; returns its id.
async fn outsiders_challenge(
    server: &EpiGraphMcpFull,
    viewer: &Viewer,
    token: &epigraph_auth::AuthContext,
    claim: Uuid,
) -> Uuid {
    let r = challenge_claim(
        server,
        viewer,
        ChallengeclaimParams {
            claim_id: claim.to_string(),
            challenge_type: "factual_error".to_string(),
            explanation: "the cited figure contradicts its own source".to_string(),
        },
        Some(token),
    )
    .await
    .expect("the outsider's challenge on a public claim lands (R-CH1)");
    ok_json(&r)["challenge_id"]
        .as_str()
        .expect("challenge_id")
        .parse()
        .expect("uuid")
}

fn resolve(id: Uuid, state: &str, details: Option<serde_json::Value>) -> ResolveChallengeParams {
    ResolveChallengeParams {
        challenge_id: id.to_string(),
        state: state.to_string(),
        resolution_details: details,
    }
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

/// `(state, resolved_by, resolved_at IS NOT NULL, resolution_details)`.
async fn resolution(
    pool: &PgPool,
    id: Uuid,
) -> (String, Option<Uuid>, bool, Option<serde_json::Value>) {
    sqlx::query_as(
        "SELECT state::text, resolved_by, resolved_at IS NOT NULL, resolution_details \
           FROM challenges WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read challenge")
}

/// `(agent_id, state_after)` of every audited resolution of `id`, oldest first.
async fn audit(pool: &PgPool, id: Uuid) -> Vec<(Option<Uuid>, String)> {
    sqlx::query_as(
        "SELECT agent_id, details->>'state_after' FROM security_events \
          WHERE event_type = 'challenges.claim_owner_resolution' \
            AND details->>'challenge_id' = $1::text \
          ORDER BY created_at, id",
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .expect("read the resolution audit")
}

/// R-3 / R-14 on both transports. stdio: the server's own agent owns the
/// claim and resolves an outsider's challenge; HTTP: a caller owns its claim
/// and resolves an outsider's challenge, and the resolver recorded is THAT
/// caller, not the server's agent. A pending challenge is accepted directly
/// and then re-resolved; each change is one audit row naming the resolver.
#[sqlx::test(migrations = "../../migrations")]
async fn the_claims_owner_resolves_an_outsiders_challenge_on_both_transports(pool: PgPool) {
    let (server, server_agent, server_viewer) = app_role_server(&pool).await;
    let server_group = personal_group_of(&pool, server_agent).await;
    let (owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let owner_group = personal_group_of(&pool, owner).await;
    let (_outsider, out_token, out_viewer) = seed_caller(&pool, &["claims:write"]).await;

    let on_stdio = public_claim_in(&pool, server_agent, server_group, "server's claim").await;
    let on_http = public_claim_in(&pool, owner, owner_group, "http owner's claim").await;
    let ch_stdio = outsiders_challenge(&server, &out_viewer, &out_token, on_stdio).await;
    let ch_http = outsiders_challenge(&server, &out_viewer, &out_token, on_http).await;

    let details = serde_json::json!({ "reason": "the figure is correct" });
    for (arm, id, claim, viewer, auth, resolver) in [
        (
            "stdio",
            ch_stdio,
            on_stdio,
            &server_viewer,
            None,
            server_agent,
        ),
        (
            "http",
            ch_http,
            on_http,
            &owner_viewer,
            Some(&owner_token),
            owner,
        ),
    ] {
        let r = resolve_challenge(
            &server,
            viewer,
            resolve(id, "accepted", Some(details.clone())),
            auth,
        )
        .await
        .unwrap_or_else(|e| panic!("{arm}: the claim's owner resolves (R-3): {e:?}"));
        let body = ok_json(&r);
        assert_eq!(body["challenge_id"], id.to_string(), "{arm}");
        assert_eq!(body["claim_id"], claim.to_string(), "{arm}");
        assert_eq!(body["state"], "accepted", "{arm}");
        assert_eq!(body["resolved_by"], resolver.to_string(), "{arm}: {body}");
        assert_eq!(body["resolution_details"], details, "{arm}");
        assert_eq!(
            resolution(&pool, id).await,
            (
                "accepted".to_string(),
                Some(resolver),
                true,
                Some(details.clone())
            ),
            "{arm}: pending -> accepted directly (R-14), the resolver is the calling principal"
        );

        resolve_challenge(&server, viewer, resolve(id, "rejected", None), auth)
            .await
            .unwrap_or_else(|e| panic!("{arm}: the owner re-resolves (R-14): {e:?}"));
        assert_eq!(resolution(&pool, id).await.0, "rejected", "{arm}");
        assert_eq!(
            audit(&pool, id).await,
            vec![
                (Some(resolver), "accepted".to_string()),
                (Some(resolver), "rejected".to_string())
            ],
            "{arm}: every change is audited, naming the resolver"
        );
    }
    assert_ne!(owner, server_agent, "CALIBRATION: the two resolvers differ");
}

/// R-13. The outsider owns its row and still cannot resolve it; a stranger
/// cannot either. Both get the same named refusal on both transports, and
/// nothing is written. `withdrawn` is the challenger's act, not a resolution
/// (refused before any lookup); a withdrawn challenge takes no resolution. The
/// parameters carry no resolver, and a caller that names one is refused at
/// deserialization.
#[sqlx::test(migrations = "../../migrations")]
async fn only_the_claims_owner_resolves_and_no_caller_names_the_resolver(pool: PgPool) {
    let (server, server_agent, server_viewer) = app_role_server(&pool).await;
    let (owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let owner_group = personal_group_of(&pool, owner).await;
    let (outsider, out_token, out_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let claim = public_claim_in(&pool, owner, owner_group, "owner's claim, r13").await;
    let theirs = outsiders_challenge(&server, &out_viewer, &out_token, claim).await;
    let withdrawn = outsiders_challenge(&server, &out_viewer, &out_token, claim).await;
    sqlx::query("UPDATE challenges SET state = 'withdrawn' WHERE id = $1")
        .bind(withdrawn)
        .execute(&pool)
        .await
        .expect("withdraw (as the harness)");

    for (who, viewer, auth) in [
        ("the outsider over http", &out_viewer, Some(&out_token)),
        ("a stranger on stdio", &server_viewer, None),
    ] {
        let e = resolve_challenge(&server, viewer, resolve(theirs, "accepted", None), auth)
            .await
            .expect_err(who);
        assert_eq!(e.code, ErrorCode::INVALID_REQUEST, "{who}: {e:?}");
        let data = e.data.clone().expect("the refusal carries data");
        assert_eq!(data["error"], "not_claim_owner", "{who}: {data}");
        assert_eq!(data["challenge_id"], theirs.to_string(), "{who}: {data}");
        assert!(
            e.message.contains("nothing was written") && !e.message.contains("row-level security"),
            "{who}: a named refusal, not the raw row-security text: {e:?}"
        );
    }
    assert_eq!(
        resolution(&pool, theirs).await,
        ("pending".to_string(), None, false, None),
        "no refusal wrote anything"
    );
    assert!(
        audit(&pool, theirs).await.is_empty(),
        "nor audited anything"
    );

    let e = resolve_challenge(
        &server,
        &owner_viewer,
        resolve(theirs, "withdrawn", None),
        Some(&owner_token),
    )
    .await
    .expect_err("withdrawn is not a resolution status");
    assert_eq!(e.code, ErrorCode::INVALID_PARAMS, "{e:?}");
    assert!(e.message.contains("withdraw"), "{e:?}");

    let e = resolve_challenge(
        &server,
        &owner_viewer,
        resolve(withdrawn, "rejected", None),
        Some(&owner_token),
    )
    .await
    .expect_err("a withdrawn challenge takes no resolution");
    assert_eq!(e.code, ErrorCode::INVALID_REQUEST, "{e:?}");
    assert_eq!(e.data.expect("data")["error"], "challenge_withdrawn");
    assert_eq!(resolution(&pool, withdrawn).await.0, "withdrawn");

    let named = serde_json::from_value::<ResolveChallengeParams>(serde_json::json!({
        "challenge_id": theirs,
        "state": "accepted",
        "resolved_by": outsider,
    }));
    assert!(
        named.is_err(),
        "a caller-named resolver is refused, not silently ignored"
    );
    assert_eq!(resolution(&pool, theirs).await.0, "pending");
    assert_ne!(server_agent, owner);
}

/// R-CH1b on both transports: a challenge on a claim the caller cannot read
/// answers EXACTLY like a random id (code, text with the id replaced, data),
/// and nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unreadable_challenge_answers_exactly_as_a_nonexistent_one(pool: PgPool) {
    let (server, _agent, viewer) = app_role_server(&pool).await;
    let (author, author_group) =
        fixture::seed_agent_with_group(&pool, "resolve-hidden-author").await;
    let private = fixture::seed_group_claim(&pool, author, author_group, "resolve hidden").await;
    let hidden: Uuid = sqlx::query_scalar(
        "INSERT INTO challenges (claim_id, challenger_id, challenge_type, explanation, state) \
         VALUES ($1, $2, 'factual_error', 'an insider on a private claim', 'pending') \
         RETURNING id",
    )
    .bind(private)
    .bind(author)
    .fetch_one(&pool)
    .await
    .expect("seed a challenge on the private claim");
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
        let on_hidden = resolve_challenge(&server, v, resolve(hidden, "accepted", None), auth)
            .await
            .expect_err("an unreadable challenge");
        let on_missing = resolve_challenge(&server, v, resolve(missing, "accepted", None), auth)
            .await
            .expect_err("a nonexistent challenge");
        assert_eq!(
            shape(&on_hidden, hidden),
            shape(&on_missing, missing),
            "{arm}: an unreadable challenge answers exactly as a nonexistent one"
        );
        assert!(
            on_missing.message.contains("not found"),
            "{arm}: positive pin on the shared text: {on_missing:?}"
        );
    }
    assert_eq!(
        resolution(&pool, hidden).await,
        ("pending".to_string(), None, false, None),
        "nothing written"
    );
}
