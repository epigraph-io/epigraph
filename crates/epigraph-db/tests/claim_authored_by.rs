//! `AuthoredByRepository::for_claim`: a claim's `authored_by` block, decided
//! under the caller's viewer on the caller's stamped connection.
//!
//! * `human` is the human the agent was bound to when the claim was filed,
//!   from its binding RECORD (its operator link until retirement, else the
//!   client allowance in force then), shown to every reader of the claim. No
//!   `OPERATED_BY` edge decides it (anyone with edges:write can forge one, so
//!   a forged edge changes nothing), and no client or registration status
//!   moves it. A registered human's own claim names no human, exactly as an
//!   agent bound to no human.
//! * A document's authors are a claim's primary authors only when the
//!   ingest's creation record says that document's ingest created it; other
//!   recorded documents corroborate, every ingester is listed, and pending
//!   authors are listed apart.
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
    AgentRepository, AuthorRef, AuthoredBy, AuthoredByRepository, ClaimIngestRepository,
    EdgeRepository, PromptSnapshotAudience, ScopedPool, SessionGucMode,
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
    // No claim row: no document asserts it, so the block is the agent's.
    let out = AuthoredByRepository::for_claim(
        &mut read,
        &viewer,
        Uuid::new_v4(),
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
    .filer()
    .human
    .as_ref()
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
    assert!(matches!(seen, AuthoredBy::Agent(_)), "{seen:?}");
    let seen = seen.filer();
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

/// A fresh agent bound to `operator` by a client allowance (a service
/// client on the maintenance-only registry): `(agent, client)`.
async fn allowance_bound(pool: &PgPool, operator: Uuid) -> (Uuid, Uuid) {
    let (agent, _) = fixture::seed_agent_with_group(pool, "allowance").await;
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, legal_entity_name, legal_contact_email) \
         VALUES ($1, 'authored-by allowance fixture', 'service', ARRAY['claims:write'], \
                 'active', $2, 'Fixture Org', 'fixture@example.invalid') RETURNING id",
    )
    .bind(format!("authored-by-allowance-{}", Uuid::new_v4()))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("service client");
    let allowed: bool = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r: bool = sqlx::query_scalar(
            "SELECT allowed_now FROM public.epigraph_allow_author_binding_client($1, $2, $3)",
        )
        .bind(client)
        .bind(operator)
        .bind("authored-by test")
        .fetch_one(&mut *conn)
        .await
        .expect("allow the client for the operator");
        (conn, r)
    })
    .await;
    assert!(allowed, "CALIBRATION: the allowance is in force");
    (agent, client)
}

async fn human_client_of(pool: &PgPool, agent: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM oauth_clients WHERE agent_id = $1 AND client_type = 'human' \
          ORDER BY created_at LIMIT 1",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("the human's client")
}

async fn set_client_status(pool: &PgPool, client: Uuid, status: &str) {
    sqlx::query("UPDATE oauth_clients SET status = $2 WHERE id = $1")
        .bind(client)
        .bind(status)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("client status -> {status}: {e}"));
}

/// The human is read from the binding RECORD, so no client or registration
/// event moves it: a stranger's whole block for each agent is byte-identical
/// before and after every event, while each event is shown (CALIBRATION) to
/// move `epigraph_human_of`. A reader can never watch a suspension.
#[sqlx::test(migrations = "../../migrations")]
async fn the_human_does_not_move_with_client_or_registration_status(pool: PgPool) {
    let scoped = app_scoped(&pool).await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let (h1, _) = human(&pool, "Linked Operator").await;
    let (linked, _) = fixture::seed_agent_with_group(&pool, "linked").await;
    link(&pool, linked, h1).await;
    let (h2, _) = human(&pool, "Allowance Operator").await;
    let (allowed, allowed_client) = allowance_bound(&pool, h2).await;
    // A registered human that is also linked as an agent: link, then register.
    let (o3, _) = human(&pool, "Dual Operator").await;
    let (dual, _) = fixture::seed_agent_with_group(&pool, "dual").await;
    link(&pool, dual, o3).await;
    fixture::make_human_operator(&pool, dual).await;
    assert_eq!(binding(&pool, allowed).await, Some(h2), "CALIBRATION");

    let agents = [linked, allowed, dual];
    let blocks = || {
        let pool = pool.clone();
        let scoped = &scoped;
        async move {
            let mut out = Vec::new();
            for a in agents {
                out.push(block_json(&pool, scoped, stranger, a).await);
            }
            out
        }
    };
    let before = blocks().await;
    let shown: Vec<Value> = before.iter().map(|b| b["human"]["id"].clone()).collect();
    assert_eq!(
        shown,
        vec![json!(h1), json!(h2), json!(o3)],
        "each agent's operator, a dual principal's included"
    );

    // 1. The allowlisted agent's own client suspended.
    set_client_status(&pool, allowed_client, "suspended").await;
    assert_eq!(binding(&pool, allowed).await, None, "CALIBRATION 1");
    assert_eq!(blocks().await, before, "allowlisted client suspended");
    set_client_status(&pool, allowed_client, "active").await;

    // 2. The allowance operator's human client suspended.
    let h2_client = human_client_of(&pool, h2).await;
    set_client_status(&pool, h2_client, "suspended").await;
    assert_eq!(binding(&pool, allowed).await, None, "CALIBRATION 2");
    assert_eq!(blocks().await, before, "operator's human client suspended");
    set_client_status(&pool, h2_client, "active").await;

    // 3. The dual principal's own human client suspended.
    assert_eq!(binding(&pool, dual).await, Some(dual), "CALIBRATION 3a");
    let dual_client = human_client_of(&pool, dual).await;
    set_client_status(&pool, dual_client, "suspended").await;
    assert_eq!(binding(&pool, dual).await, Some(o3), "CALIBRATION 3b");
    assert_eq!(blocks().await, before, "dual principal's client suspended");
    set_client_status(&pool, dual_client, "active").await;

    // 4. The allowlisted client revoked (the allowance itself is not).
    set_client_status(&pool, allowed_client, "revoked").await;
    assert_eq!(blocks().await, before, "allowlisted client revoked");
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
        .filer()
        .prompt_snapshot
        .clone()
        .expect("the agent's human sees the snapshot");
    assert_eq!(mine.model, "model-fixture");
    assert_eq!(mine.prompt_hash.len(), 64);
    assert_eq!(
        authored_by(&pool, &scoped, custodian, agent, gated)
            .await
            .filer()
            .prompt_snapshot
            .as_ref(),
        Some(&mine),
        "an admin sees it"
    );
    assert_eq!(
        authored_by(&pool, &scoped, stranger, agent, gated)
            .await
            .filer()
            .prompt_snapshot,
        None,
        "gated: a stranger does not"
    );

    let open = PromptSnapshotAudience::ClaimReaders;
    assert_eq!(
        authored_by(&pool, &scoped, stranger, agent, open)
            .await
            .filer()
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
        Uuid::new_v4(),
        agent,
        Utc::now() - Duration::days(1),
        gated,
    )
    .await
    .expect("authored_by");
    assert_eq!(
        before.filer().prompt_snapshot,
        None,
        "a claim filed before the first registration has no snapshot"
    );
}

// ── The human bound when the claim was filed ───────────────────────────────

/// The block of a claim filed by `agent` at `at`, as `caller` sees it.
async fn human_at(
    pool: &PgPool,
    scoped: &ScopedPool,
    caller: Uuid,
    agent: Uuid,
    at: chrono::DateTime<Utc>,
) -> Option<Uuid> {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve");
    let mut read = scoped.read_as(&viewer).await.expect("stamped read");
    let out = AuthoredByRepository::for_claim(
        &mut read,
        &viewer,
        Uuid::new_v4(),
        agent,
        at,
        PromptSnapshotAudience::OperatorAndAdmins,
    )
    .await
    .expect("authored_by");
    read.commit().await.expect("finish");
    out.filer().human.as_ref().map(|h| h.id)
}

async fn linked_at(pool: &PgPool, agent: Uuid) -> chrono::DateTime<Utc> {
    sqlx::query_scalar("SELECT created_at FROM operator_links WHERE agent_id = $1")
        .bind(agent)
        .fetch_one(pool)
        .await
        .expect("link row")
}

/// `authored_by.human` names the human the agent was BOUND to when the claim
/// was filed, from the binding record (migration 199's
/// `epigraph_operator_bound_at`): a link names its operator until it is
/// retired, and nobody after; a link recorded already retired names its
/// operator only for what the agent filed before the link was recorded; a
/// client allowance names its operator while it is in force. Every reader
/// sees the same.
#[sqlx::test(migrations = "../../migrations")]
async fn the_human_is_the_one_bound_when_the_claim_was_filed(pool: PgPool) {
    let scoped = app_scoped(&pool).await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let us = Duration::microseconds(1);

    // A live link, later retired.
    let (op, _) = human(&pool, "Linked Operator").await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "retiring").await;
    link(&pool, agent, op).await;
    let linked = linked_at(&pool, agent).await;
    for caller in [stranger, op] {
        assert_eq!(
            human_at(&pool, &scoped, caller, agent, linked - Duration::days(1)).await,
            Some(op),
            "before the link, with no allowance: the operator owns the agent's claims"
        );
        assert_eq!(
            human_at(
                &pool,
                &scoped,
                caller,
                agent,
                Utc::now() + Duration::days(1)
            )
            .await,
            Some(op),
            "a live link"
        );
    }
    let outcome: String = sqlx::query_scalar(
        "SELECT outcome FROM public.epigraph_retire_operator_link($1, 'bound-at test', true)",
    )
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("retire");
    assert_eq!(outcome, "retired", "CALIBRATION");
    let retired: chrono::DateTime<Utc> = sqlx::query_scalar(
        "SELECT created_at FROM security_events \
          WHERE agent_id = $1 AND event_type = 'operator.link_retired'",
    )
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("the retirement's audit row");
    for caller in [stranger, op] {
        assert_eq!(
            human_at(&pool, &scoped, caller, agent, retired - us).await,
            Some(op),
            "filed while the link was live"
        );
        assert_eq!(
            human_at(&pool, &scoped, caller, agent, retired).await,
            None,
            "filed at or after the retirement"
        );
    }

    // A link recorded already retired (107 section 7).
    let (op2, _) = human(&pool, "Retired-link Operator").await;
    let (old, _) = fixture::seed_agent_with_group(&pool, "old-identity").await;
    let out = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_retired_agent(&mut conn, old, op2).await;
        (conn, r)
    })
    .await
    .expect("record a retired link");
    assert!(out.link_retired, "CALIBRATION: recorded retired");
    let recorded = linked_at(&pool, old).await;
    assert_eq!(
        human_at(&pool, &scoped, stranger, old, recorded - us).await,
        Some(op2),
        "the operator owns what the identity filed before the link was recorded"
    );
    assert_eq!(
        human_at(&pool, &scoped, stranger, old, recorded + us).await,
        None,
        "and nothing after"
    );

    // A client allowance, later revoked.
    let (op3, _) = human(&pool, "Allowance Operator").await;
    let (allowed, client) = allowance_bound(&pool, op3).await;
    let added: chrono::DateTime<Utc> =
        sqlx::query_scalar("SELECT added_at FROM author_binding_clients WHERE client_id = $1")
            .bind(client)
            .fetch_one(&pool)
            .await
            .expect("added_at");
    assert_eq!(
        human_at(&pool, &scoped, stranger, allowed, added - us).await,
        None,
        "before the allowance"
    );
    assert_eq!(
        human_at(&pool, &scoped, stranger, allowed, added).await,
        Some(op3),
        "while the allowance is in force"
    );
    let revoked: bool = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r: bool = sqlx::query_scalar(
            "SELECT revoked_now FROM public.epigraph_revoke_author_binding_client($1, $2)",
        )
        .bind(client)
        .bind("bound-at test")
        .fetch_one(&mut *conn)
        .await
        .expect("revoke");
        (conn, r)
    })
    .await;
    assert!(revoked, "CALIBRATION");
    let revoked_at: chrono::DateTime<Utc> =
        sqlx::query_scalar("SELECT revoked_at FROM author_binding_clients WHERE client_id = $1")
            .bind(client)
            .fetch_one(&pool)
            .await
            .expect("revoked_at");
    for caller in [stranger, op3] {
        assert_eq!(
            human_at(&pool, &scoped, caller, allowed, revoked_at - us).await,
            Some(op3),
            "filed while the allowance was in force"
        );
        assert_eq!(
            human_at(&pool, &scoped, caller, allowed, revoked_at).await,
            None,
            "filed at or after the revocation"
        );
    }
}

/// `INSERT` one `security_events` row on `conn`: `(event_type, agent_id,
/// details {operator_id}, created_at or now())`.
async fn plant_event(
    conn: &mut sqlx::PgConnection,
    event_type: &str,
    agent: Uuid,
    operator: Uuid,
    created_at: Option<chrono::DateTime<Utc>>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO security_events (event_type, agent_id, success, details, created_at) \
         VALUES ($1, $2, true, jsonb_build_object('operator_id', $3::text), \
                 COALESCE($4, now()))",
    )
    .bind(event_type)
    .bind(agent)
    .bind(operator)
    .bind(created_at)
    .execute(&mut *conn)
    .await
    .map(|_| ())
}

/// The retirement instant is read from the `operator.link_retired` audit row,
/// and migration 191's restrictive policy makes that row the trigger's alone.
/// Both arms the permissive append policy admits are refused for it, with or
/// without a backdated `created_at`: a session stamped as the agent itself,
/// and an application session with no principal. CALIBRATION: the same
/// sessions append a benign event attributed the same way, so the refusal is
/// the restrictive policy's. No planted row cuts a live agent's claims off
/// its human.
#[sqlx::test(migrations = "../../migrations")]
async fn an_application_session_cannot_plant_or_backdate_a_retirement(pool: PgPool) {
    let scoped = app_scoped(&pool).await;
    let (op, _) = human(&pool, "Linked Operator").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "agent").await;
    link(&pool, agent, op).await;
    let plain = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let as_agent = Viewer::resolve(&pool, agent).await.expect("resolve");
    let backdated = Some(Utc::now() - Duration::days(30));

    for created_at in [None, backdated] {
        // No principal (the append policy's pre-authentication arm).
        let mut conn = plain.acquire().await.expect("conn");
        plant_event(&mut conn, "test.provenance_benign", agent, op, created_at)
            .await
            .expect("CALIBRATION: a principal-less session appends a benign event");
        assert!(
            plant_event(&mut conn, "operator.link_retired", agent, op, created_at)
                .await
                .is_err(),
            "no principal: refused (created_at {created_at:?})"
        );
        drop(conn);

        // Stamped as the agent itself (the append policy's attribution arm).
        let mut tx = scoped.begin_as(&as_agent).await.expect("stamped write");
        plant_event(&mut tx, "test.provenance_benign", agent, op, created_at)
            .await
            .expect("CALIBRATION: the agent appends a benign event about itself");
        tx.commit().await.expect("commit");
        let mut tx = scoped.begin_as(&as_agent).await.expect("stamped write");
        assert!(
            plant_event(&mut tx, "operator.link_retired", agent, op, created_at)
                .await
                .is_err(),
            "stamped as the agent: refused (created_at {created_at:?})"
        );
        drop(tx);
    }

    let planted: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events \
          WHERE agent_id = $1 AND event_type = 'operator.link_retired'",
    )
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(planted, 0, "no retirement row landed");
    assert_eq!(
        human_at(
            &pool,
            &scoped,
            stranger,
            agent,
            Utc::now() + Duration::days(1)
        )
        .await,
        Some(op)
    );
}

// ── Documents: the creating ingest's authors first, the filer apart ────────

/// An author node: a bare agent row named `name` (no group, no human).
async fn author_node(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, display_name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(&pk)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed an author node");
    id
}

async fn paper(pool: &PgPool, doi: &str, title: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO papers (doi, title) VALUES ($1, $2) RETURNING id")
        .bind(doi)
        .bind(title)
        .fetch_one(pool)
        .await
        .expect("seed a paper")
}

/// An edge whose tenancy the endpoint trigger stamps (public endpoints give a
/// public edge).
async fn edge(
    pool: &PgPool,
    (source, source_type): (Uuid, &str),
    (target, target_type): (Uuid, &str),
    relationship: &str,
    properties: Value,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(source)
    .bind(source_type)
    .bind(target)
    .bind(target_type)
    .bind(relationship)
    .bind(properties)
    .fetch_one(pool)
    .await
    .expect("seed an edge")
}

/// Force an edge private to `group`. Administrative only: no application
/// path makes a public claim's assertion private (the insert trigger takes
/// the endpoints' meet), so this state arises only from such an UPDATE.
async fn private_to(pool: &PgPool, edge: Uuid, group: Uuid) {
    let n = sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
          WHERE id = $1",
    )
    .bind(edge)
    .bind(group)
    .execute(pool)
    .await
    .expect("make the edge group-private")
    .rows_affected();
    assert_eq!(n, 1);
}

/// The ingest's record that `by` ingested `paper` and (per `created`)
/// whether that ingest created the claim, written with the walk's own
/// primitive.
async fn record(pool: &PgPool, paper: Uuid, claim: Uuid, by: Uuid, created: bool) {
    let mut conn = pool.acquire().await.expect("conn");
    let wrote = ClaimIngestRepository::record_signed_conn(
        &mut conn,
        None,
        paper,
        claim,
        by,
        created,
        "ingest_document",
        "test-pipeline",
    )
    .await
    .expect("record");
    assert!(wrote, "CALIBRATION: a new record");
}

/// The document's `asserts` edge onto the claim, as the walk writes it, AND
/// the ingest's record of it. Returns the asserts edge.
async fn ingested(pool: &PgPool, paper: Uuid, claim: Uuid, by: Uuid, created: bool) -> Uuid {
    let mut conn = pool.acquire().await.expect("conn");
    let e = EdgeRepository::create_if_absent_including_retracted_signed_conn(
        &mut conn, None, paper, "paper", claim, "claim", "asserts", None, None, None,
    )
    .await
    .expect("asserts")
    .0
    .id;
    drop(conn);
    record(pool, paper, claim, by, created).await;
    e
}

async fn authored(pool: &PgPool, author: Uuid, paper: Uuid, properties: Value) -> Uuid {
    edge(
        pool,
        (author, "agent"),
        (paper, "paper"),
        "authored",
        properties,
    )
    .await
}

/// The block of the real claim `claim`, filed by `agent`, as `caller` sees it.
async fn claim_block(
    pool: &PgPool,
    scoped: &ScopedPool,
    caller: Uuid,
    claim: Uuid,
    agent: Uuid,
) -> AuthoredBy {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve");
    let mut read = scoped.read_as(&viewer).await.expect("stamped read");
    let out = AuthoredByRepository::for_claim(
        &mut read,
        &viewer,
        claim,
        agent,
        Utc::now() + Duration::seconds(5),
        PromptSnapshotAudience::OperatorAndAdmins,
    )
    .await
    .expect("authored_by");
    read.commit().await.expect("finish");
    out
}

fn literature(block: &AuthoredBy) -> &epigraph_db::LiteratureAuthorship {
    match block {
        AuthoredBy::Literature(l) => l,
        AuthoredBy::Agent(_) => panic!("expected a literature block: {block:?}"),
    }
}

fn ids(list: &[epigraph_db::PaperAuthor]) -> Vec<Uuid> {
    list.iter().map(|a| a.id).collect()
}

/// A claim a document's ingest CREATED names that document's authors first,
/// in position order with role and affiliations, keeps an ingester's
/// uncountersigned naming apart as pending (with who named them), shows the
/// filer apart as `ingested_by`, lists a converging document as
/// corroborating, and lists every ingester with its human. Agent-to-claim
/// `asserts` edges are not authors.
#[sqlx::test(migrations = "../../migrations")]
async fn a_created_claim_names_its_documents_authors_first_and_the_filer_apart(pool: PgPool) {
    let scoped = app_scoped(&pool).await;
    let (operator, _) = human(&pool, "Operator Fixture").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let (ingester, _) = fixture::seed_agent_with_group(&pool, "ingester").await;
    named(&pool, ingester, "ingest-fixture").await;
    link(&pool, ingester, operator).await;
    let (second, _) = fixture::seed_agent_with_group(&pool, "second-ingester").await;
    let claim = fixture::seed_public_claim(&pool, ingester, "a literature fixture claim").await;
    let doc = paper(&pool, "10.0000/fixture.one", "Fixture Paper One").await;
    ingested(&pool, doc, claim, ingester, true).await;
    let other = paper(&pool, "10.0000/fixture.two", "Fixture Paper Two").await;
    ingested(&pool, other, claim, second, false).await;
    let other_author = author_node(&pool, "Other Author").await;
    authored(&pool, other_author, other, json!({"position": 0})).await;

    let third = author_node(&pool, "Third Author").await;
    let first_a = author_node(&pool, "First Author").await;
    let first_b = author_node(&pool, "Also First").await;
    let second_author = author_node(&pool, "Second Author").await;
    let unplaced = author_node(&pool, "Unplaced Author").await;
    let named_person = author_node(&pool, "Named Person").await;
    authored(
        &pool,
        third,
        doc,
        json!({"position": 2, "role": "corresponding", "affiliations": ["Lab A", null, "Lab B"]}),
    )
    .await;
    authored(
        &pool,
        first_a,
        doc,
        json!({"position": 0, "role": "author"}),
    )
    .await;
    authored(&pool, first_b, doc, json!({"position": 0})).await;
    authored(
        &pool,
        second_author,
        doc,
        json!({"position": 1, "affiliations": "Lab C"}),
    )
    .await;
    authored(&pool, unplaced, doc, json!({"position": "x"})).await;
    authored(
        &pool,
        named_person,
        doc,
        json!({"position": 3, "pending_countersign": true, "ingested_by": second.to_string()}),
    )
    .await;
    let claim_asserter = author_node(&pool, "Claim Asserter").await;
    edge(
        &pool,
        (claim_asserter, "agent"),
        (claim, "claim"),
        "asserts",
        json!({}),
    )
    .await;

    let block = claim_block(&pool, &scoped, stranger, claim, ingester).await;
    let lit = literature(&block);
    let p = &lit.paper;
    assert_eq!(p.paper.id, doc);
    assert_eq!(p.paper.doi, "10.0000/fixture.one");
    assert_eq!(p.paper.title.as_deref(), Some("Fixture Paper One"));
    assert!(!p.authors_truncated);
    assert_eq!(
        ids(&p.authors),
        vec![first_a, first_b, second_author, third, unplaced],
        "by position (a shared one in recording order), a missing one last; never the \
         claim asserter, never the pending person"
    );
    let by_id = |id: Uuid| p.authors.iter().find(|a| a.id == id).expect("listed");
    let t = by_id(third);
    assert_eq!(t.display_name.as_deref(), Some("Third Author"));
    assert_eq!(t.position, Some(2));
    assert_eq!(t.role, "corresponding");
    assert_eq!(
        t.affiliations,
        vec!["Lab A".to_string(), "Lab B".to_string()]
    );
    assert_eq!(by_id(first_b).role, "author", "a missing role reads author");
    assert!(
        by_id(second_author).affiliations.is_empty(),
        "a non-array is none"
    );
    assert_eq!(by_id(unplaced).position, None);
    assert!(p
        .authors
        .iter()
        .all(|a| !a.pending_countersign && a.named_by.is_none()));

    assert_eq!(ids(&p.pending_authors), vec![named_person], "pending apart");
    assert!(p.pending_authors[0].pending_countersign);
    assert_eq!(
        p.pending_authors[0].named_by.as_ref().map(|n| n.id),
        Some(second),
        "the ingester whose word it is"
    );

    assert_eq!(lit.ingested_by.agent.id, ingester);
    assert_eq!(
        lit.ingested_by.human.as_ref().map(|h| h.id),
        Some(operator),
        "the ingesting human is shown apart, to every reader"
    );
    let c = &lit.corroboration;
    assert_eq!(
        c.corroborated_by
            .iter()
            .map(|p| p.paper.id)
            .collect::<Vec<_>>(),
        vec![other],
        "the converging document corroborates"
    );
    assert_eq!(ids(&c.corroborated_by[0].authors), vec![other_author]);
    assert_eq!(
        c.ingesters
            .iter()
            .map(|i| (i.agent.id, i.paper_id, i.created_claim))
            .collect::<Vec<_>>(),
        vec![(ingester, doc, true), (second, other, false)],
        "every ingester, oldest first"
    );
    assert_eq!(
        c.ingesters[0].human.as_ref().map(|h| h.id),
        Some(operator),
        "each ingester's human, bound when it ingested"
    );
    assert_eq!(c.ingesters[1].human, None, "an unbound ingester has none");

    let wire = serde_json::to_value(&block).expect("serialize");
    assert_eq!(wire["source"], json!("literature"));
    assert!(
        wire.get("agent").is_none(),
        "the filer is not primary: {wire}"
    );
    assert_eq!(
        wire["paper"]["pending_authors"][0]["pending_countersign"],
        json!(true)
    );
    assert_eq!(
        wire["ingesters"].as_array().map(Vec::len),
        Some(2),
        "{wire}"
    );
}

/// Only the CREATING ingest makes a document primary. A claim no record
/// says a document created (filed directly, then repeated by a document),
/// or whose creation record names someone other than its filer, is the
/// filer's: the document is corroborating. A bare `asserts` edge with no
/// record is not read at all.
#[sqlx::test(migrations = "../../migrations")]
async fn only_the_creating_ingest_makes_a_document_primary(pool: PgPool) {
    let scoped = app_scoped(&pool).await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let (filer, _) = fixture::seed_agent_with_group(&pool, "filer").await;
    let (other, _) = fixture::seed_agent_with_group(&pool, "other-ingester").await;
    let plain = fixture::seed_public_claim(&pool, filer, "no document recorded this").await;
    let none = serde_json::to_value(claim_block(&pool, &scoped, stranger, plain, filer).await)
        .expect("serialize");
    assert_eq!(none["source"], json!("agent"), "CALIBRATION: {none}");

    // A bare asserts edge: no record.
    let bare_claim = fixture::seed_public_claim(&pool, filer, "barely asserted").await;
    let bare = paper(&pool, "10.0000/fixture.bare", "Bare Paper").await;
    edge(
        &pool,
        (bare, "paper"),
        (bare_claim, "claim"),
        "asserts",
        json!({}),
    )
    .await;
    authored(
        &pool,
        author_node(&pool, "Bare Author").await,
        bare,
        json!({"position": 0}),
    )
    .await;
    assert_eq!(
        serde_json::to_value(claim_block(&pool, &scoped, stranger, bare_claim, filer).await)
            .expect("serialize"),
        none,
        "a bare asserts edge reads exactly as no document"
    );

    // Repeated by a document whose ingest did not create the claim.
    let repeated = fixture::seed_public_claim(&pool, filer, "stated, then repeated").await;
    let doc = paper(&pool, "10.0000/fixture.repeat", "Repeating Paper").await;
    ingested(&pool, doc, repeated, other, false).await;
    let block = claim_block(&pool, &scoped, stranger, repeated, filer).await;
    let AuthoredBy::Agent(a) = &block else {
        panic!("a repeated claim stays its filer's: {block:?}");
    };
    assert_eq!(a.filer.agent.id, filer);
    assert_eq!(
        a.corroboration
            .corroborated_by
            .iter()
            .map(|p| p.paper.id)
            .collect::<Vec<_>>(),
        vec![doc]
    );
    assert_eq!(
        a.corroboration
            .ingesters
            .iter()
            .map(|i| (i.agent.id, i.created_claim))
            .collect::<Vec<_>>(),
        vec![(other, false)]
    );

    // A record that says "created" but names someone other than the filer.
    let misnamed = fixture::seed_public_claim(&pool, filer, "creation misattributed").await;
    let doc2 = paper(&pool, "10.0000/fixture.misnamed", "Misnamed Paper").await;
    ingested(&pool, doc2, misnamed, other, true).await;
    assert!(
        matches!(
            claim_block(&pool, &scoped, stranger, misnamed, filer).await,
            AuthoredBy::Agent(_)
        ),
        "a creation record is the creator's only when it names the filer"
    );
}

/// A document whose assertion the caller cannot read, or whose assertion is
/// retracted, is no document: the caller gets the agent block, byte for byte
/// the block of a claim no document recorded. An `authored` edge the caller
/// cannot read is no author.
#[sqlx::test(migrations = "../../migrations")]
async fn a_document_edge_the_caller_cannot_read_is_no_document(pool: PgPool) {
    let scoped = app_scoped(&pool).await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "member").await;
    let (ingester, _) = fixture::seed_agent_with_group(&pool, "ingester").await;
    let plain = fixture::seed_public_claim(&pool, ingester, "no document asserts this").await;

    let hidden_claim = fixture::seed_public_claim(&pool, ingester, "privately asserted").await;
    let hidden_doc = paper(&pool, "10.0000/fixture.hidden", "Hidden Paper").await;
    let e = ingested(&pool, hidden_doc, hidden_claim, ingester, true).await;
    private_to(&pool, e, group).await;
    authored(
        &pool,
        author_node(&pool, "Hidden Author").await,
        hidden_doc,
        json!({"position": 0}),
    )
    .await;

    assert_eq!(
        literature(&claim_block(&pool, &scoped, member, hidden_claim, ingester).await)
            .paper
            .paper
            .id,
        hidden_doc,
        "CONTROL: a member of the assertion's group sees the document"
    );
    let as_json = |b: AuthoredBy| serde_json::to_value(b).expect("serialize");
    let none = as_json(claim_block(&pool, &scoped, stranger, plain, ingester).await);
    assert_eq!(none["source"], json!("agent"), "CALIBRATION: {none}");
    assert_eq!(
        as_json(claim_block(&pool, &scoped, stranger, hidden_claim, ingester).await),
        none,
        "a hidden assertion reads exactly as no document"
    );

    // A retracted assertion.
    let retracted_claim = fixture::seed_public_claim(&pool, ingester, "once asserted").await;
    let old_doc = paper(&pool, "10.0000/fixture.retracted", "Retracted Paper").await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            valid_from, valid_to) \
         VALUES ($1, 'paper', $2, 'claim', 'asserts', now() - interval '2 hours', \
                 now() - interval '1 hour')",
    )
    .bind(old_doc)
    .bind(retracted_claim)
    .execute(&pool)
    .await
    .expect("a retracted asserts edge");
    record(&pool, old_doc, retracted_claim, ingester, true).await;
    assert_eq!(
        as_json(claim_block(&pool, &scoped, member, retracted_claim, ingester).await),
        as_json(claim_block(&pool, &scoped, member, plain, ingester).await),
        "a retracted assertion is no document"
    );

    // A public document with one public and one group-private author edge.
    let open_claim = fixture::seed_public_claim(&pool, ingester, "openly asserted").await;
    let open_doc = paper(&pool, "10.0000/fixture.open", "Open Paper").await;
    ingested(&pool, open_doc, open_claim, ingester, true).await;
    let shown = author_node(&pool, "Shown Author").await;
    let kept = author_node(&pool, "Kept Author").await;
    authored(&pool, shown, open_doc, json!({"position": 1})).await;
    let k = authored(&pool, kept, open_doc, json!({"position": 0})).await;
    private_to(&pool, k, group).await;
    let authors_of = |b: &AuthoredBy| ids(&literature(b).paper.authors);
    assert_eq!(
        authors_of(&claim_block(&pool, &scoped, member, open_claim, ingester).await),
        vec![kept, shown],
        "CONTROL: the member reads both author edges"
    );
    assert_eq!(
        authors_of(&claim_block(&pool, &scoped, stranger, open_claim, ingester).await),
        vec![shown],
        "a hidden authored edge is no author"
    );
}

/// Corroborating documents are listed in record order, at most
/// `MAX_PAPERS`, and each lists at most `MAX_PAPER_AUTHORS` authors; both
/// caps say when they cut. Every ingester is listed, past the paper cap.
#[sqlx::test(migrations = "../../migrations")]
async fn corroborating_documents_are_capped_and_every_ingester_is_listed(pool: PgPool) {
    use epigraph_db::authored_by::{MAX_PAPERS, MAX_PAPER_AUTHORS};
    let scoped = app_scoped(&pool).await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let (filer, _) = fixture::seed_agent_with_group(&pool, "filer").await;
    let claim = fixture::seed_public_claim(&pool, filer, "a converged claim").await;

    let mut docs = Vec::new();
    for i in 0..=MAX_PAPERS {
        let d = paper(
            &pool,
            &format!("10.0000/fixture.many.{i}"),
            &format!("Paper {i}"),
        )
        .await;
        let (by, _) = fixture::seed_agent_with_group(&pool, "many-ingester").await;
        ingested(&pool, d, claim, by, false).await;
        docs.push(d);
    }
    for i in 0..=MAX_PAPER_AUTHORS {
        let a = author_node(&pool, &format!("Author {i}")).await;
        authored(&pool, a, docs[0], json!({"position": i})).await;
    }

    let block = claim_block(&pool, &scoped, stranger, claim, filer).await;
    let AuthoredBy::Agent(a) = &block else {
        panic!("{block:?}");
    };
    let c = &a.corroboration;
    assert!(
        c.corroborated_by_truncated,
        "one more document than the cap"
    );
    assert_eq!(
        c.corroborated_by
            .iter()
            .map(|p| p.paper.id)
            .collect::<Vec<_>>(),
        docs[..MAX_PAPERS].to_vec(),
        "in record order"
    );
    assert_eq!(c.corroborated_by[0].authors.len(), MAX_PAPER_AUTHORS);
    assert!(c.corroborated_by[0].authors_truncated);
    assert!(c.corroborated_by[1].authors.is_empty());
    assert_eq!(c.ingesters.len(), MAX_PAPERS + 1, "every ingester");
    assert!(!c.ingesters_truncated);
}

/// The same hidden edges, read on a SUPERUSER scoped connection, where row
/// security filters nothing: only the in-query viewer predicates decide. On
/// the application role the `edges` policy re-filters, so the test above
/// stays green without them; this one does not.
#[sqlx::test(migrations = "../../migrations")]
async fn the_document_and_author_edges_are_filtered_in_the_query_itself(pool: PgPool) {
    let superuser = fixture::scoped_pool(&pool).await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "member").await;
    let (ingester, _) = fixture::seed_agent_with_group(&pool, "ingester").await;

    let hidden_claim = fixture::seed_public_claim(&pool, ingester, "privately asserted").await;
    let hidden_doc = paper(&pool, "10.0000/fixture.su.hidden", "Hidden Paper").await;
    let e = ingested(&pool, hidden_doc, hidden_claim, ingester, true).await;
    private_to(&pool, e, group).await;

    let open_claim = fixture::seed_public_claim(&pool, ingester, "openly asserted").await;
    let open_doc = paper(&pool, "10.0000/fixture.su.open", "Open Paper").await;
    ingested(&pool, open_doc, open_claim, ingester, true).await;
    let shown = author_node(&pool, "Shown Author").await;
    let kept = author_node(&pool, "Kept Author").await;
    authored(&pool, shown, open_doc, json!({"position": 1})).await;
    let k = authored(&pool, kept, open_doc, json!({"position": 0})).await;
    private_to(&pool, k, group).await;

    assert!(
        matches!(
            claim_block(&pool, &superuser, member, hidden_claim, ingester).await,
            AuthoredBy::Literature(_)
        ),
        "CONTROL: the member's viewer admits the assertion"
    );
    assert!(
        matches!(
            claim_block(&pool, &superuser, stranger, hidden_claim, ingester).await,
            AuthoredBy::Agent(_)
        ),
        "the assertion predicate is in the query"
    );
    let block = claim_block(&pool, &superuser, stranger, open_claim, ingester).await;
    assert_eq!(
        ids(&literature(&block).paper.authors),
        vec![shown],
        "the authored-edge predicate is in the query"
    );
}
