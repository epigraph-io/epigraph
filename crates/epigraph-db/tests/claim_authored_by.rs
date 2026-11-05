//! `AuthoredByRepository::for_claim`: a claim's `authored_by` block, decided
//! under the caller's viewer on the caller's stamped connection.
//!
//! * `human` is shown only through a binding the caller can already read:
//!   the caller is that human, or an `OPERATED_BY` edge from the agent to that
//!   human is readable under the caller's viewer. A link whose edge is private
//!   to a group, a link with no edge, and a human-operator self-binding are
//!   hidden from everyone else, and hidden reads exactly as "no human".
//! * `prompt_snapshot` follows the audience setting: under
//!   `OperatorAndAdmins` only the agent's human and admins see it; under
//!   `ClaimReaders` every caller does.
//!
//! The scoped pool is the APPLICATION ROLE (no bypass), as in production; the
//! viewers are resolved and every fixture row is seeded on the superuser pool.

#[path = "viewer_fixture.rs"]
mod fixture;

use chrono::{Duration, Utc};
use epigraph_db::visibility::Viewer;
use epigraph_db::{
    AgentRepository, AuthorRef, AuthoredBy, AuthoredByRepository, PromptSnapshotAudience,
    ScopedPool, SessionGucMode,
};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

async fn app_scoped(pool: &PgPool) -> ScopedPool {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let bypass: bool = sqlx::query_scalar("SELECT public.epigraph_bypass()")
        .fetch_one(scoped.inner())
        .await
        .expect("bypass probe");
    assert!(!bypass, "CALIBRATION: the scoped pool must not bypass");
    scoped
}

async fn named(pool: &PgPool, agent: Uuid, name: &str) {
    sqlx::query("UPDATE agents SET display_name = $2 WHERE id = $1")
        .bind(agent)
        .bind(name)
        .execute(pool)
        .await
        .expect("name the agent");
}

/// A registered human operator with its personal group, named `name`.
async fn human(pool: &PgPool, name: &str) -> (Uuid, Uuid) {
    let (agent, group) = fixture::seed_agent_with_group(pool, name).await;
    fixture::make_human_operator(pool, agent).await;
    named(pool, agent, name).await;
    (agent, group)
}

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let out = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_operator(&mut conn, agent, operator).await;
        (conn, r)
    })
    .await
    .expect("the maintenance role links the agent");
    assert!(out.link_live, "CALIBRATION: the manual link is live");
}

async fn authored_by(
    pool: &PgPool,
    scoped: &ScopedPool,
    caller: Uuid,
    agent: Uuid,
    audience: PromptSnapshotAudience,
) -> AuthoredBy {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve");
    let mut read = scoped.read_as(&viewer).await.expect("stamped read");
    let out = AuthoredByRepository::for_claim(
        &mut read,
        &viewer,
        agent,
        Utc::now() + Duration::seconds(5),
        audience,
    )
    .await
    .expect("authored_by");
    read.commit().await.expect("finish");
    out
}

async fn human_seen(pool: &PgPool, scoped: &ScopedPool, caller: Uuid, agent: Uuid) -> Option<Uuid> {
    authored_by(
        pool,
        scoped,
        caller,
        agent,
        PromptSnapshotAudience::OperatorAndAdmins,
    )
    .await
    .human
    .map(|h| h.id)
}

/// Public edge: every caller sees the human, with names on both parts.
/// Group-private edge: a member of the group and the human see it, a
/// stranger does not.
#[sqlx::test(migrations = "../../migrations")]
async fn the_human_is_shown_only_through_a_link_edge_the_caller_can_read(pool: PgPool) {
    let scoped = app_scoped(&pool).await;
    let (operator, _) = human(&pool, "Operator Fixture").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "member").await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "agent").await;
    named(&pool, agent, "agent-fixture").await;
    link(&pool, agent, operator).await;

    let seen = authored_by(
        &pool,
        &scoped,
        stranger,
        agent,
        PromptSnapshotAudience::OperatorAndAdmins,
    )
    .await;
    assert_eq!(
        seen.agent,
        AuthorRef {
            id: agent,
            display_name: Some("agent-fixture".into())
        }
    );
    assert_eq!(
        seen.human,
        Some(AuthorRef {
            id: operator,
            display_name: Some("Operator Fixture".into())
        }),
        "CONTROL: a public link edge shows the human to a stranger"
    );

    let moved = sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $3, co_owner_group_id = NULL \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'OPERATED_BY'",
    )
    .bind(agent)
    .bind(operator)
    .bind(group)
    .execute(&pool)
    .await
    .expect("make the link edge group-private")
    .rows_affected();
    assert_eq!(moved, 1, "CALIBRATION: the link wrote one OPERATED_BY edge");

    assert_eq!(
        human_seen(&pool, &scoped, member, agent).await,
        Some(operator),
        "a member of the edge's group reads it"
    );
    assert_eq!(
        human_seen(&pool, &scoped, operator, agent).await,
        Some(operator),
        "the human sees itself"
    );
    assert_eq!(
        human_seen(&pool, &scoped, stranger, agent).await,
        None,
        "a stranger who cannot read the edge does not learn the link"
    );
}

/// A link with no edge, and a human operator filing its own claim, are
/// bindings no edge records: only the human sees them, and a stranger's
/// block is exactly the block of an agent bound to no human.
#[sqlx::test(migrations = "../../migrations")]
async fn a_binding_without_a_readable_edge_reads_as_no_human(pool: PgPool) {
    let scoped = app_scoped(&pool).await;
    let (operator, operator_group) = human(&pool, "Operator Fixture").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let (edgeless, _) = fixture::seed_agent_with_group(&pool, "edgeless").await;
    let (unbound, _) = fixture::seed_agent_with_group(&pool, "unbound").await;
    sqlx::query(
        "INSERT INTO operator_links (agent_id, operator_id, operator_group_id) VALUES ($1, $2, $3)",
    )
    .bind(edgeless)
    .bind(operator)
    .bind(operator_group)
    .execute(&pool)
    .await
    .expect("a link row with no edge");
    let edges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND relationship = 'OPERATED_BY'",
    )
    .bind(edgeless)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(edges, 0, "CALIBRATION: no edge records this link");
    let bound: Option<Uuid> = sqlx::query_scalar("SELECT public.epigraph_human_of($1, false)")
        .bind(edgeless)
        .fetch_one(&pool)
        .await
        .expect("human_of");
    assert_eq!(
        bound,
        Some(operator),
        "CALIBRATION: the link binds the agent"
    );

    assert_eq!(
        human_seen(&pool, &scoped, operator, edgeless).await,
        Some(operator),
        "CONTROL: the human sees its own binding"
    );
    assert_eq!(human_seen(&pool, &scoped, stranger, edgeless).await, None);

    // A human operator's own claim: the binding is the agent itself.
    assert_eq!(
        human_seen(&pool, &scoped, operator, operator).await,
        Some(operator),
        "CONTROL: a human sees itself as the human behind its own claim"
    );
    assert_eq!(
        human_seen(&pool, &scoped, stranger, operator).await,
        None,
        "a stranger does not learn that an agent is a registered human operator"
    );

    let hidden = authored_by(
        &pool,
        &scoped,
        stranger,
        edgeless,
        PromptSnapshotAudience::OperatorAndAdmins,
    )
    .await;
    let none = authored_by(
        &pool,
        &scoped,
        stranger,
        unbound,
        PromptSnapshotAudience::OperatorAndAdmins,
    )
    .await;
    let strip = |b: &AuthoredBy| {
        let mut v = serde_json::to_value(b).expect("serialize");
        v["agent"] = json!(null);
        v
    };
    assert_eq!(
        strip(&hidden),
        strip(&none),
        "hidden reads byte for byte as no human"
    );
}

/// A registered identity (no parent) through the attestor: its agent id.
async fn registered(pool: &PgPool) -> Uuid {
    let pubkey: Vec<u8> = [
        Uuid::new_v4().as_bytes().as_slice(),
        Uuid::new_v4().as_bytes().as_slice(),
    ]
    .concat();
    let hash = blake3::hash(&pubkey).to_hex().to_string();
    let signing: Vec<u8> = [
        Uuid::new_v4().as_bytes().as_slice(),
        Uuid::new_v4().as_bytes().as_slice(),
    ]
    .concat();
    let snap = json!({
        "identity_md": null, "global_claude_md": null, "group_claude_md": null,
        "learned_md": null,
        "in_prompt": {"identity_md": false, "global_claude_md": false,
                      "group_claude_md": false, "learned_md": false},
        "runner_version": "runner-test", "host_sha": null
    });
    fixture::as_role(pool, "epigraph_identity_attestor", |mut conn| async move {
        let r: Uuid = sqlx::query_scalar(
            "SELECT agent_id FROM public.epigraph_register_agent_identity( \
                 $1, NULL, 'model-fixture', $2, 'g-authored', $3, $4)",
        )
        .bind(&pubkey)
        .bind(&hash)
        .bind(&signing)
        .bind(&snap)
        .fetch_one(&mut *conn)
        .await
        .expect("the attestor registers");
        (conn, r)
    })
    .await
}

/// Gated: the agent's human and an admin see the snapshot, a stranger does
/// not. Open: the stranger sees the same snapshot.
#[sqlx::test(migrations = "../../migrations")]
async fn the_prompt_snapshot_follows_the_audience_setting(pool: PgPool) {
    let scoped = app_scoped(&pool).await;
    let (operator, _) = human(&pool, "Operator Fixture").await;
    let (custodian, _) = human(&pool, "Custodian Fixture").await;
    fixture::make_custodian(&pool, custodian).await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let agent = registered(&pool).await;
    link(&pool, agent, operator).await;

    let gated = PromptSnapshotAudience::OperatorAndAdmins;
    let mine = authored_by(&pool, &scoped, operator, agent, gated)
        .await
        .prompt_snapshot
        .expect("the agent's human sees the snapshot");
    assert_eq!(mine.model, "model-fixture");
    assert_eq!(mine.prompt_hash.len(), 64);
    assert_eq!(
        authored_by(&pool, &scoped, custodian, agent, gated)
            .await
            .prompt_snapshot
            .as_ref(),
        Some(&mine),
        "an admin sees it"
    );
    assert_eq!(
        authored_by(&pool, &scoped, stranger, agent, gated)
            .await
            .prompt_snapshot,
        None,
        "gated: a stranger does not"
    );

    let open = PromptSnapshotAudience::ClaimReaders;
    assert_eq!(
        authored_by(&pool, &scoped, stranger, agent, open)
            .await
            .prompt_snapshot,
        Some(mine),
        "open: every reader sees it"
    );

    let before = AuthoredByRepository::for_claim(
        &mut scoped
            .read_as(&Viewer::resolve(&pool, operator).await.expect("resolve"))
            .await
            .expect("read"),
        &Viewer::resolve(&pool, operator).await.expect("resolve"),
        agent,
        Utc::now() - Duration::days(1),
        gated,
    )
    .await
    .expect("authored_by");
    assert_eq!(
        before.prompt_snapshot, None,
        "a claim filed before the first registration has no snapshot"
    );
}
