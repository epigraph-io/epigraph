//! `AuthoredByRepository::for_claim`: a claim's `authored_by` block, decided
//! under the caller's viewer on the caller's stamped connection.
//!
//! * `human` is the agent's binding RECORD (its operator link in any state,
//!   else its unrevoked client allowance), shown to every reader of the
//!   claim. No `OPERATED_BY` edge decides it (anyone with edges:write can
//!   forge one, so a forged edge changes nothing), and no client or
//!   registration status moves it. A registered human's own claim names no
//!   human, exactly as an agent bound to no human.
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

// ── Literature: a document's authors first, the filer apart ────────────────

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

/// A document row, created `age_days` days ago (its listing order).
async fn paper(pool: &PgPool, doi: &str, title: &str, age_days: i64) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO papers (doi, title, created_at) VALUES ($1, $2, now() - make_interval(days => $3::int)) \
         RETURNING id",
    )
    .bind(doi)
    .bind(title)
    .bind(i32::try_from(age_days).expect("small"))
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

/// Force an edge private to `group` (the trigger fires only on endpoint
/// changes, so this UPDATE sticks).
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

async fn asserts(pool: &PgPool, paper: Uuid, claim: Uuid) -> Uuid {
    edge(
        pool,
        (paper, "paper"),
        (claim, "claim"),
        "asserts",
        json!({}),
    )
    .await
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

fn papers_of(block: &AuthoredBy) -> &[epigraph_db::PaperAuthorship] {
    match block {
        AuthoredBy::Literature { papers, .. } => papers,
        AuthoredBy::Agent(_) => panic!("expected a literature block: {block:?}"),
    }
}

/// A claim a document asserts names the document's authors, ordered by the
/// `authored` edge's position (a shared position by agent id, a missing one
/// last) with role and affiliations, and the agent that filed the claim
/// apart as `ingested_by`, with its human. Agent-to-claim `asserts` edges are
/// not authors.
#[sqlx::test(migrations = "../../migrations")]
async fn a_literature_claim_names_the_document_authors_first_and_the_ingester_apart(pool: PgPool) {
    let scoped = app_scoped(&pool).await;
    let (operator, _) = human(&pool, "Operator Fixture").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let (ingester, _) = fixture::seed_agent_with_group(&pool, "ingester").await;
    named(&pool, ingester, "ingest-fixture").await;
    link(&pool, ingester, operator).await;
    let claim = fixture::seed_public_claim(&pool, ingester, "a literature fixture claim").await;
    let doc = paper(&pool, "10.0000/fixture.one", "Fixture Paper One", 1).await;
    asserts(&pool, doc, claim).await;

    let third = author_node(&pool, "Third Author").await;
    let first_a = author_node(&pool, "First Author").await;
    let first_b = author_node(&pool, "Also First").await;
    let second = author_node(&pool, "Second Author").await;
    let unplaced = author_node(&pool, "Unplaced Author").await;
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
    authored(&pool, first_b, doc, json!({"position": 0, "role": 7})).await;
    authored(
        &pool,
        second,
        doc,
        json!({"position": 1, "affiliations": "Lab C"}),
    )
    .await;
    authored(&pool, unplaced, doc, json!({"position": "x"})).await;
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
    let AuthoredBy::Literature {
        papers,
        papers_truncated,
        ingested_by,
    } = &block
    else {
        panic!("a claim a readable document asserts is literature: {block:?}");
    };
    assert!(!papers_truncated);
    assert_eq!(papers.len(), 1, "{block:?}");
    let p = &papers[0];
    assert_eq!(p.paper.id, doc);
    assert_eq!(p.paper.doi, "10.0000/fixture.one");
    assert_eq!(p.paper.title.as_deref(), Some("Fixture Paper One"));
    assert!(!p.authors_truncated);
    let (lo, hi) = if first_a < first_b {
        (first_a, first_b)
    } else {
        (first_b, first_a)
    };
    let order: Vec<Uuid> = p.authors.iter().map(|a| a.id).collect();
    assert_eq!(
        order,
        vec![lo, hi, second, third, unplaced],
        "by position, a shared position by id, a missing one last; never the claim asserter"
    );
    let by_id = |id: Uuid| p.authors.iter().find(|a| a.id == id).expect("listed");
    let t = by_id(third);
    assert_eq!(t.display_name.as_deref(), Some("Third Author"));
    assert_eq!(t.position, Some(2));
    assert_eq!(t.role.as_deref(), Some("corresponding"));
    assert_eq!(
        t.affiliations,
        vec!["Lab A".to_string(), "Lab B".to_string()]
    );
    assert_eq!(by_id(first_a).role.as_deref(), Some("author"));
    assert_eq!(by_id(first_b).role, None, "a non-string role is not shown");
    assert!(by_id(second).affiliations.is_empty(), "a non-array is none");
    assert_eq!(by_id(unplaced).position, None);

    assert_eq!(ingested_by.agent.id, ingester);
    assert_eq!(
        ingested_by.human.as_ref().map(|h| h.id),
        Some(operator),
        "the ingesting human is shown apart, to every reader"
    );
    assert_eq!(
        ingested_by,
        authored_by(
            &pool,
            &scoped,
            stranger,
            ingester,
            PromptSnapshotAudience::OperatorAndAdmins
        )
        .await
        .filer(),
        "ingested_by is the same filer block the agent shape carries"
    );

    let wire = serde_json::to_value(&block).expect("serialize");
    assert_eq!(wire["source"], json!("literature"));
    assert!(
        wire.get("agent").is_none(),
        "the filer is not primary: {wire}"
    );
    assert_eq!(
        serde_json::to_value(
            authored_by(
                &pool,
                &scoped,
                stranger,
                ingester,
                PromptSnapshotAudience::OperatorAndAdmins
            )
            .await
        )
        .expect("serialize")["source"],
        json!("agent")
    );
}

/// A document whose `asserts` edge the caller cannot read, or whose edge is
/// retracted, is no document: the caller gets the agent block, byte for byte
/// the block of a claim no document asserts. An `authored` edge the caller
/// cannot read is no author.
#[sqlx::test(migrations = "../../migrations")]
async fn a_document_edge_the_caller_cannot_read_is_no_document(pool: PgPool) {
    let scoped = app_scoped(&pool).await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "member").await;
    let (ingester, _) = fixture::seed_agent_with_group(&pool, "ingester").await;
    let plain = fixture::seed_public_claim(&pool, ingester, "no document asserts this").await;

    // A document whose asserts edge is private to the member's group.
    let hidden_claim = fixture::seed_public_claim(&pool, ingester, "privately asserted").await;
    let hidden_doc = paper(&pool, "10.0000/fixture.hidden", "Hidden Paper", 1).await;
    let e = asserts(&pool, hidden_doc, hidden_claim).await;
    private_to(&pool, e, group).await;
    let writer = author_node(&pool, "Hidden Author").await;
    authored(&pool, writer, hidden_doc, json!({"position": 0})).await;

    assert_eq!(
        papers_of(&claim_block(&pool, &scoped, member, hidden_claim, ingester).await)[0]
            .paper
            .id,
        hidden_doc,
        "CONTROL: a member of the edge's group sees the document"
    );
    let as_json = |b: AuthoredBy| serde_json::to_value(b).expect("serialize");
    let none = as_json(claim_block(&pool, &scoped, stranger, plain, ingester).await);
    assert_eq!(none["source"], json!("agent"), "CALIBRATION: {none}");
    assert_eq!(
        as_json(claim_block(&pool, &scoped, stranger, hidden_claim, ingester).await),
        none,
        "a hidden asserts edge reads exactly as no document"
    );

    // A retracted asserts edge.
    let retracted_claim = fixture::seed_public_claim(&pool, ingester, "once asserted").await;
    let old_doc = paper(&pool, "10.0000/fixture.retracted", "Retracted Paper", 1).await;
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
    assert_eq!(
        as_json(claim_block(&pool, &scoped, member, retracted_claim, ingester).await),
        as_json(claim_block(&pool, &scoped, member, plain, ingester).await),
        "a retracted asserts edge is no document"
    );

    // A public document with one public and one group-private author edge.
    let open_claim = fixture::seed_public_claim(&pool, ingester, "openly asserted").await;
    let open_doc = paper(&pool, "10.0000/fixture.open", "Open Paper", 1).await;
    asserts(&pool, open_doc, open_claim).await;
    let shown = author_node(&pool, "Shown Author").await;
    let kept = author_node(&pool, "Kept Author").await;
    authored(&pool, shown, open_doc, json!({"position": 1})).await;
    let k = authored(&pool, kept, open_doc, json!({"position": 0})).await;
    private_to(&pool, k, group).await;
    let ids =
        |b: &AuthoredBy| -> Vec<Uuid> { papers_of(b)[0].authors.iter().map(|a| a.id).collect() };
    assert_eq!(
        ids(&claim_block(&pool, &scoped, member, open_claim, ingester).await),
        vec![kept, shown],
        "CONTROL: the member reads both author edges"
    );
    assert_eq!(
        ids(&claim_block(&pool, &scoped, stranger, open_claim, ingester).await),
        vec![shown],
        "a hidden authored edge is no author"
    );
}

/// Converged claims collect documents: every readable one is listed, oldest
/// document row first, at most `MAX_PAPERS`, and each lists at most
/// `MAX_PAPER_AUTHORS` authors; both caps say when they cut.
#[sqlx::test(migrations = "../../migrations")]
async fn several_documents_are_listed_oldest_first_and_capped(pool: PgPool) {
    use epigraph_db::authored_by::{MAX_PAPERS, MAX_PAPER_AUTHORS};
    let scoped = app_scoped(&pool).await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let (ingester, _) = fixture::seed_agent_with_group(&pool, "ingester").await;
    let claim = fixture::seed_public_claim(&pool, ingester, "a converged claim").await;

    let mut docs = Vec::new();
    for i in 0..=MAX_PAPERS {
        // Oldest first: i = 0 is the oldest.
        let d = paper(
            &pool,
            &format!("10.0000/fixture.many.{i}"),
            &format!("Paper {i}"),
            100 - i,
        )
        .await;
        asserts(&pool, d, claim).await;
        docs.push(d);
    }
    for i in 0..=MAX_PAPER_AUTHORS {
        let a = author_node(&pool, &format!("Author {i}")).await;
        authored(&pool, a, docs[0], json!({"position": i})).await;
    }
    let solo = author_node(&pool, "Solo Author").await;
    authored(&pool, solo, docs[1], json!({"position": 0})).await;

    let block = claim_block(&pool, &scoped, stranger, claim, ingester).await;
    let AuthoredBy::Literature {
        papers,
        papers_truncated,
        ..
    } = &block
    else {
        panic!("{block:?}");
    };
    assert!(papers_truncated, "one more document than the cap");
    let listed: Vec<Uuid> = papers.iter().map(|p| p.paper.id).collect();
    assert_eq!(
        listed,
        docs[..usize::try_from(MAX_PAPERS).expect("small")].to_vec(),
        "the oldest documents, oldest first"
    );
    assert_eq!(
        papers[0].authors.len(),
        usize::try_from(MAX_PAPER_AUTHORS).expect("small")
    );
    assert!(papers[0].authors_truncated);
    assert_eq!(papers[0].authors[0].position, Some(0));
    assert_eq!(
        papers[1].authors.iter().map(|a| a.id).collect::<Vec<_>>(),
        vec![solo]
    );
    assert!(!papers[1].authors_truncated);
    assert!(papers[2].authors.is_empty());
}

/// The same two hidden edges, read on a SUPERUSER scoped connection, where
/// row security filters nothing: only the in-query viewer predicates decide.
/// On the application role the `edges` policy re-filters, so the test above
/// stays green without them; this one does not.
#[sqlx::test(migrations = "../../migrations")]
async fn the_document_and_author_edges_are_filtered_in_the_query_itself(pool: PgPool) {
    let superuser = fixture::scoped_pool(&pool).await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "member").await;
    let (ingester, _) = fixture::seed_agent_with_group(&pool, "ingester").await;

    let hidden_claim = fixture::seed_public_claim(&pool, ingester, "privately asserted").await;
    let hidden_doc = paper(&pool, "10.0000/fixture.su.hidden", "Hidden Paper", 1).await;
    let e = asserts(&pool, hidden_doc, hidden_claim).await;
    private_to(&pool, e, group).await;

    let open_claim = fixture::seed_public_claim(&pool, ingester, "openly asserted").await;
    let open_doc = paper(&pool, "10.0000/fixture.su.open", "Open Paper", 1).await;
    asserts(&pool, open_doc, open_claim).await;
    let shown = author_node(&pool, "Shown Author").await;
    let kept = author_node(&pool, "Kept Author").await;
    authored(&pool, shown, open_doc, json!({"position": 1})).await;
    let k = authored(&pool, kept, open_doc, json!({"position": 0})).await;
    private_to(&pool, k, group).await;

    assert!(
        matches!(
            claim_block(&pool, &superuser, member, hidden_claim, ingester).await,
            AuthoredBy::Literature { .. }
        ),
        "CONTROL: the member's viewer admits the edge"
    );
    assert!(
        matches!(
            claim_block(&pool, &superuser, stranger, hidden_claim, ingester).await,
            AuthoredBy::Agent(_)
        ),
        "the asserts-edge predicate is in the query"
    );
    let block = claim_block(&pool, &superuser, stranger, open_claim, ingester).await;
    assert_eq!(
        papers_of(&block)[0]
            .authors
            .iter()
            .map(|a| a.id)
            .collect::<Vec<_>>(),
        vec![shown],
        "the authored-edge predicate is in the query"
    );
}
