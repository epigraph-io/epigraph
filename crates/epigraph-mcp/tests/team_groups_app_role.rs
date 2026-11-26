//! The MCP half of person-facing keyless team groups and consented
//! invitations (migration 263, backlog ee9e05b4) on the APPLICATION ROLE:
//! `create_team_group`, `list_my_groups`, `invite_to_group`,
//! `accept_group_invitation` and `decline_group_invitation`.
//!
//! The server is built from ONE `ScopedPool` downgraded to `epigraph_app`
//! (NOSUPERUSER, NOBYPASSRLS), and each tool runs with an HTTP-shaped token
//! naming the caller, so every write is stamped from that caller. The raw
//! pool is the harness superuser, used only to seed and to read state back.
//!
//! Pinned: a Person creates a group and invites another Person, and the
//! membership goes live only when the invitee accepts; refusal parity with
//! the REST routes: each designed refusal reaches the caller with its
//! `TGPnn` code, input as `INVALID_PARAMS`, authority and state as
//! `INVALID_REQUEST`, and a group or invitation the caller may not see as
//! `INVALID_PARAMS` "not found"; an operated agent cannot act for its human.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::visibility::Viewer;
use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::team_groups::{
    accept_group_invitation, create_team_group, decline_group_invitation, invite_to_group,
    list_my_groups,
};
use epigraph_mcp::types::{
    AcceptGroupInvitationParams, CreateTeamGroupParams, DeclineGroupInvitationParams,
    InviteToGroupParams, ListMyGroupsParams,
};
use rmcp::model::{CallToolResult, ErrorCode};
use sqlx::PgPool;
use uuid::Uuid;

async fn app_server(pool: &PgPool) -> EpiGraphMcpFull {
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
    server.server_agent_id().await.expect("server agent");
    server
}

fn token(agent: Uuid) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Human,
        scopes: vec!["groups:read".to_string(), "groups:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

async fn viewer(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("resolve")
}

async fn human(pool: &PgPool, label: &str) -> Uuid {
    fixture::seed_human_operator(pool, label).await.0
}

async fn operated(pool: &PgPool, operator: Uuid, label: &str) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("link the agent");
    agent
}

fn json_of(r: CallToolResult) -> serde_json::Value {
    first_text(&r)
}

fn id(v: &serde_json::Value, field: &str) -> Uuid {
    v[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} in {v}"))
        .parse()
        .expect("uuid")
}

/// `(code, message)` of a refusal.
fn refusal<T: std::fmt::Debug>(r: Result<T, rmcp::model::ErrorData>) -> (ErrorCode, String) {
    let e = r.expect_err("a refusal");
    (e.code, e.message.to_string())
}

async fn live_rows(pool: &PgPool, group: Uuid, agent: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(group)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("count")
}

struct Mcp<'a> {
    pool: &'a PgPool,
    server: &'a EpiGraphMcpFull,
}

impl Mcp<'_> {
    async fn create(
        &self,
        who: Uuid,
        name: &str,
    ) -> Result<CallToolResult, rmcp::model::ErrorData> {
        let auth = token(who);
        create_team_group(
            self.server,
            &viewer(self.pool, who).await,
            CreateTeamGroupParams {
                name: name.to_string(),
                reason: None,
            },
            Some(&auth),
        )
        .await
    }

    async fn invite(
        &self,
        who: Uuid,
        group: Uuid,
        invitee: Uuid,
        role: Option<&str>,
    ) -> Result<CallToolResult, rmcp::model::ErrorData> {
        let auth = token(who);
        invite_to_group(
            self.server,
            &viewer(self.pool, who).await,
            InviteToGroupParams {
                group_id: group.to_string(),
                agent_id: invitee.to_string(),
                role: role.map(str::to_string),
                reason: Some("join us".to_string()),
            },
            Some(&auth),
        )
        .await
    }

    async fn accept(
        &self,
        who: Uuid,
        invitation: Uuid,
    ) -> Result<CallToolResult, rmcp::model::ErrorData> {
        let auth = token(who);
        accept_group_invitation(
            self.server,
            &viewer(self.pool, who).await,
            AcceptGroupInvitationParams {
                invitation_id: invitation.to_string(),
            },
            Some(&auth),
        )
        .await
    }

    async fn decline(
        &self,
        who: Uuid,
        invitation: Uuid,
    ) -> Result<CallToolResult, rmcp::model::ErrorData> {
        let auth = token(who);
        decline_group_invitation(
            self.server,
            &viewer(self.pool, who).await,
            DeclineGroupInvitationParams {
                invitation_id: invitation.to_string(),
            },
            Some(&auth),
        )
        .await
    }

    async fn mine(&self, who: Uuid) -> serde_json::Value {
        let auth = token(who);
        json_of(
            list_my_groups(
                self.server,
                &viewer(self.pool, who).await,
                ListMyGroupsParams::default(),
                Some(&auth),
            )
            .await
            .expect("list_my_groups"),
        )
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_person_creates_invites_and_the_membership_goes_live_on_accept(pool: PgPool) {
    let server = app_server(&pool).await;
    let mcp = Mcp {
        pool: &pool,
        server: &server,
    };
    let a = human(&pool, "mcp-a").await;
    let b = human(&pool, "mcp-b").await;

    let created = json_of(mcp.create(a, "Synthetic MCP Team").await.expect("create"));
    let group = id(&created, "group_id");
    assert_eq!(created["role"], "admin");
    assert_eq!(live_rows(&pool, group, a).await, 1);

    let invited = json_of(
        mcp.invite(a, group, b, Some("writer"))
            .await
            .expect("invite"),
    );
    assert_eq!(invited["status"], "pending");
    let invitation = id(&invited, "invitation_id");
    assert_eq!(
        live_rows(&pool, group, b).await,
        0,
        "no membership before consent"
    );
    let b_mine = mcp.mine(b).await;
    assert!(!b_mine["groups"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["group_id"] == group.to_string()));
    assert_eq!(
        b_mine["invitations"][0]["invitation_id"],
        invitation.to_string(),
        "{b_mine}"
    );
    assert!(
        mcp.mine(a).await["invitations"]
            .as_array()
            .unwrap()
            .is_empty(),
        "only the invitee sees it"
    );

    let accepted = json_of(mcp.accept(b, invitation).await.expect("accept"));
    assert_eq!(accepted["role"], "writer");
    assert_eq!(live_rows(&pool, group, b).await, 1, "live once accepted");
    assert!(mcp.mine(b).await["groups"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["group_id"] == group.to_string() && g["role"] == "writer"));

    let c = human(&pool, "mcp-c").await;
    let inv_c = id(
        &json_of(mcp.invite(a, group, c, None).await.expect("invite c")),
        "invitation_id",
    );
    let declined = json_of(mcp.decline(c, inv_c).await.expect("decline"));
    assert_eq!(declined["status"], "declined");
    assert_eq!(live_rows(&pool, group, c).await, 0);
}

/// Refusal parity with the REST routes: the same definer refusals, each with
/// its code, mapped by kind; nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn each_refusal_reaches_the_caller_by_its_kind(pool: PgPool) {
    let server = app_server(&pool).await;
    let mcp = Mcp {
        pool: &pool,
        server: &server,
    };
    let a = human(&pool, "par-a").await;
    let b = human(&pool, "par-b").await;
    let outsider = human(&pool, "par-out").await;
    let b_agent = operated(&pool, b, "par-b-agent").await;
    let group = id(
        &json_of(mcp.create(a, "Synthetic Parity").await.expect("create")),
        "group_id",
    );
    let invitation = id(
        &json_of(
            mcp.invite(a, group, b, Some("writer"))
                .await
                .expect("invite"),
        ),
        "invitation_id",
    );

    let (code, msg) = refusal(mcp.create(a, "synthetic parity").await);
    assert_eq!(
        (code, &msg[..6]),
        (ErrorCode::INVALID_REQUEST, "TGP06:"),
        "{msg}"
    );
    let (code, msg) = refusal(mcp.create(b_agent, "Synthetic Agent").await);
    assert_eq!(
        (code, &msg[..6]),
        (ErrorCode::INVALID_REQUEST, "TGP01:"),
        "{msg}"
    );
    // Operator ruling C10 (migration 321): an agent a Person operates is
    // invited like anyone (the invite never says whether an id is a person);
    // only a role's node or a system identity, whose kind is public, is
    // refused TGP03. The agent's invitation is refused at accept (TGP01).
    let to_agent = id(
        &json_of(
            mcp.invite(a, group, b_agent, None)
                .await
                .expect("C10: an operated agent is invited like anyone"),
        ),
        "invitation_id",
    );
    let (code, msg) = refusal(mcp.accept(b_agent, to_agent).await);
    assert_eq!(
        (code, &msg[..6]),
        (ErrorCode::INVALID_REQUEST, "TGP01:"),
        "the refusal is at accept time: {msg}"
    );
    let role: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, role, labels) \
         VALUES (uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid()), 'role:par', \
                 'role', 'custom', ARRAY['role']) RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("role node");
    let (code, msg) = refusal(mcp.invite(a, group, role, None).await);
    assert_eq!(
        (code, &msg[..6]),
        (ErrorCode::INVALID_PARAMS, "TGP03:"),
        "{msg}"
    );
    let (code, msg) = refusal(mcp.invite(a, group, b, None).await);
    assert_eq!(
        (code, &msg[..6]),
        (ErrorCode::INVALID_REQUEST, "TGP04:"),
        "{msg}"
    );
    let (code, msg) = refusal(mcp.invite(a, group, outsider, Some("owner")).await);
    assert_eq!(
        (code, &msg[..6]),
        (ErrorCode::INVALID_PARAMS, "TGP09:"),
        "{msg}"
    );
    let (code, msg) = refusal(mcp.invite(outsider, group, b, None).await);
    assert_eq!(code, ErrorCode::INVALID_PARAMS, "{msg}");
    assert!(
        msg.contains("not found"),
        "a non-member sees no group: {msg}"
    );
    let (code, msg) = refusal(mcp.accept(a, invitation).await);
    assert_eq!(code, ErrorCode::INVALID_PARAMS, "{msg}");
    assert!(msg.contains("not found"), "only the invitee sees it: {msg}");
    let (code, msg) = refusal(mcp.accept(b_agent, invitation).await);
    assert_eq!(
        (code, &msg[..6]),
        (ErrorCode::INVALID_REQUEST, "TGP01:"),
        "the human's agent does not consent for them: {msg}"
    );
    let (code, msg) = refusal(mcp.decline(outsider, invitation).await);
    assert_eq!(code, ErrorCode::INVALID_PARAMS, "{msg}");
    assert_eq!(
        live_rows(&pool, group, b).await,
        0,
        "no refusal joined anyone"
    );

    mcp.accept(b, invitation)
        .await
        .expect("POSITIVE CONTROL: the invitee accepts");
    let (code, msg) = refusal(mcp.invite(b, group, outsider, None).await);
    assert_eq!(
        (code, &msg[..6]),
        (ErrorCode::INVALID_REQUEST, "TGP02:"),
        "{msg}"
    );
    let (code, msg) = refusal(mcp.accept(b, invitation).await);
    assert_eq!(
        (code, &msg[..6]),
        (ErrorCode::INVALID_REQUEST, "TGP05:"),
        "{msg}"
    );
    let (code, msg) = refusal(mcp.accept(b, Uuid::nil()).await);
    assert_eq!(code, ErrorCode::INVALID_PARAMS, "{msg}");
    let r = invite_to_group(
        &server,
        &viewer(&pool, a).await,
        InviteToGroupParams {
            group_id: "not-a-uuid".to_string(),
            agent_id: b.to_string(),
            role: None,
            reason: None,
        },
        Some(&token(a)),
    )
    .await;
    assert_eq!(refusal(r).0, ErrorCode::INVALID_PARAMS);
}

/// Input is normalised exactly as the REST twin normalises it: the role is
/// trimmed, and the echoed `display_name` is what was stored (SQL `btrim`
/// strips spaces only, so a trailing tab stays).
#[sqlx::test(migrations = "../../migrations")]
async fn input_is_normalised_as_the_rest_twin_normalises_it(pool: PgPool) {
    let server = app_server(&pool).await;
    let mcp = Mcp {
        pool: &pool,
        server: &server,
    };
    let a = human(&pool, "mcp-parity-a").await;
    let b = human(&pool, "mcp-parity-b").await;

    let created = json_of(
        mcp.create(a, "  Synthetic Parity Team\t ")
            .await
            .expect("create"),
    );
    let group = id(&created, "group_id");
    let stored: String = sqlx::query_scalar("SELECT display_name::text FROM groups WHERE id = $1")
        .bind(group)
        .fetch_one(&pool)
        .await
        .expect("stored name");
    assert_eq!(
        stored, "Synthetic Parity Team\t",
        "PREMISE: btrim strips spaces only"
    );
    assert_eq!(
        created["display_name"], stored,
        "the echo is the stored name"
    );

    let invited = json_of(
        mcp.invite(a, group, b, Some(" writer "))
            .await
            .expect("invite"),
    );
    assert_eq!(invited["role"], "writer");
}
