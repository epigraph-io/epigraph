//! `AuthoredByRepository::for_claim`: a claim's `authored_by` block, decided
//! under the caller's viewer on the caller's stamped connection.
//!
//! * `human` is the agent's binding (`epigraph_human_of(agent, false)`),
//!   shown to every reader of the claim. No `OPERATED_BY` edge decides it:
//!   anyone with edges:write can forge one, so a forged edge changes nothing.
//!   A registered human's own claim names no human (it is bound to itself,
//!   which is not an operator), exactly as an agent bound to no human.
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
    AgentRepository, AuthorRef, AuthoredBy, AuthoredByRepository, EdgeRepository,
    PromptSnapshotAudience, ScopedPool, SessionGucMode,
};
use serde_json::{json, Value};
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

/// `epigraph_human_of(agent, false)`, the binding itself (harness pool).
async fn binding(pool: &PgPool, agent: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT public.epigraph_human_of($1, false)")
        .bind(agent)
        .fetch_one(pool)
        .await
        .expect("human_of")
}

/// A link row and no `OPERATED_BY` edge: a binding no edge records.
async fn edgeless_link(pool: &PgPool, agent: Uuid, operator: Uuid, operator_group: Uuid) {
    sqlx::query(
        "INSERT INTO operator_links (agent_id, operator_id, operator_group_id) VALUES ($1, $2, $3)",
    )
    .bind(agent)
    .bind(operator)
    .bind(operator_group)
    .execute(pool)
    .await
    .expect("a link row with no edge");
    let edges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND relationship = 'OPERATED_BY'",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("count");
    assert_eq!(edges, 0, "CALIBRATION: no edge records this link");
    assert_eq!(
        binding(pool, agent).await,
        Some(operator),
        "CALIBRATION: the link binds the agent"
    );
}

/// `caller` writes an `OPERATED_BY` edge `agent -> target` through the
/// application role, as REST `create_edge` would for any edges:write caller.
async fn forge(pool: &PgPool, scoped: &ScopedPool, caller: Uuid, agent: Uuid, target: Uuid) {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve");
    let mut tx = scoped.begin_as(&viewer).await.expect("stamped write");
    EdgeRepository::create(
        &mut *tx,
        agent,
        "agent",
        target,
        "agent",
        "OPERATED_BY",
        None,
        None,
        None,
    )
    .await
    .expect("CALIBRATION: the application role writes the forged edge");
    tx.commit().await.expect("commit the forged edge");
}

async fn block_json(pool: &PgPool, scoped: &ScopedPool, caller: Uuid, agent: Uuid) -> Value {
    serde_json::to_value(
        authored_by(
            pool,
            scoped,
            caller,
            agent,
            PromptSnapshotAudience::OperatorAndAdmins,
        )
        .await,
    )
    .expect("serialize")
}

/// The human is the agent's binding, shown to every reader: through a link
/// with its edge, and through a link no edge records, alike.
#[sqlx::test(migrations = "../../migrations")]
async fn the_human_is_the_binding_for_every_reader(pool: PgPool) {
    let scoped = app_scoped(&pool).await;
    let (operator, operator_group) = human(&pool, "Operator Fixture").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "agent").await;
    named(&pool, agent, "agent-fixture").await;
    link(&pool, agent, operator).await;
    let (edgeless, _) = fixture::seed_agent_with_group(&pool, "edgeless").await;
    edgeless_link(&pool, edgeless, operator, operator_group).await;

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
        "a stranger sees a linked agent's human"
    );
    assert_eq!(
        human_seen(&pool, &scoped, stranger, edgeless).await,
        Some(operator),
        "a link no edge records is the same binding, and is shown the same way"
    );
    assert_eq!(
        human_seen(&pool, &scoped, operator, edgeless).await,
        Some(operator),
        "the human sees it too"
    );
}

/// An `OPERATED_BY` edge anyone can write decides nothing. A stranger who
/// forges edges from a bound agent, to a wrong guess and then to the right
/// human, leaves every reader's block byte for byte as it was; a forged edge
/// from an unbound agent shows no human; a forged edge from a bound agent to a
/// decoy never shows the decoy.
#[sqlx::test(migrations = "../../migrations")]
async fn a_forged_operated_by_edge_changes_nothing(pool: PgPool) {
    let scoped = app_scoped(&pool).await;
    let (operator, operator_group) = human(&pool, "Operator Fixture").await;
    let (decoy, _) = human(&pool, "Decoy Fixture").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let (bystander, _) = fixture::seed_agent_with_group(&pool, "bystander").await;
    let (edgeless, _) = fixture::seed_agent_with_group(&pool, "edgeless").await;
    edgeless_link(&pool, edgeless, operator, operator_group).await;
    let (linked, _) = fixture::seed_agent_with_group(&pool, "linked").await;
    link(&pool, linked, operator).await;
    let (unbound, _) = fixture::seed_agent_with_group(&pool, "unbound").await;
    assert_eq!(binding(&pool, unbound).await, None, "CALIBRATION: unbound");

    let before_stranger = block_json(&pool, &scoped, stranger, edgeless).await;
    let before_bystander = block_json(&pool, &scoped, bystander, edgeless).await;
    assert_eq!(
        before_stranger["human"]["id"],
        json!(operator),
        "CALIBRATION: the binding is shown before any forgery"
    );

    forge(&pool, &scoped, stranger, edgeless, decoy).await;
    assert_eq!(
        block_json(&pool, &scoped, stranger, edgeless).await,
        before_stranger,
        "a wrong guess changes nothing"
    );
    forge(&pool, &scoped, stranger, edgeless, operator).await;
    assert_eq!(
        block_json(&pool, &scoped, stranger, edgeless).await,
        before_stranger,
        "a right guess changes nothing"
    );
    assert_eq!(
        block_json(&pool, &scoped, bystander, edgeless).await,
        before_bystander,
        "nor does it change a third reader's block"
    );

    let unbound_before = block_json(&pool, &scoped, bystander, unbound).await;
    forge(&pool, &scoped, stranger, unbound, operator).await;
    assert_eq!(
        human_seen(&pool, &scoped, bystander, unbound).await,
        None,
        "a forged edge from an unbound agent shows no human"
    );
    assert_eq!(
        block_json(&pool, &scoped, bystander, unbound).await,
        unbound_before
    );

    forge(&pool, &scoped, stranger, linked, decoy).await;
    assert_eq!(
        human_seen(&pool, &scoped, bystander, linked).await,
        Some(operator),
        "a bound agent shows its real human, never the forged decoy"
    );
}

/// A registered human filing its own claim is bound to itself. That is not
/// an operator: the block names no human, to the human and to a stranger
/// alike, byte for byte the block of an agent bound to no human, so it never
/// says who is a registered human operator.
#[sqlx::test(migrations = "../../migrations")]
async fn a_registered_humans_own_claim_names_no_human(pool: PgPool) {
    let scoped = app_scoped(&pool).await;
    let (operator, _) = human(&pool, "Operator Fixture").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let (unbound, _) = fixture::seed_agent_with_group(&pool, "unbound").await;
    assert_eq!(
        binding(&pool, operator).await,
        Some(operator),
        "CALIBRATION: a registered human is its own binding"
    );

    let strip = |mut v: Value| {
        v["agent"] = json!(null);
        v
    };
    let none = strip(block_json(&pool, &scoped, stranger, unbound).await);
    for caller in [stranger, operator] {
        assert_eq!(
            strip(block_json(&pool, &scoped, caller, operator).await),
            none,
            "a human's own claim reads as no human"
        );
    }
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
