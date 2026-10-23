//! Migration 161: host-attested agent identity registration, succession, link
//! inheritance and prompt history (agent identity lineage design D2-D4).
//!
//! # What is under test
//!
//! * `epigraph_register_agent_identity` is the ONLY write path for agent
//!   lineage and prompt snapshots. It is EXECUTE-able by the
//!   `epigraph_identity_attestor` role alone: the session settings
//!   (`epigraph.principal_id`, the group lists) are plain variables any login
//!   can SET, so the trust boundary is the database ROLE of the connection,
//!   never the principal it claims.
//! * A child registered with a LIVE-linked parent is linked to the same
//!   operator through the same body `epigraph_link_operator` runs (writer
//!   membership, `OPERATED_BY` edge). An unlinked or retired parent passes on
//!   nothing.
//! * Refusals: AID03 (the parent is not an LLM agent), AID05 (adopting an agent
//!   with claims that was never registered), AID07 (the child is linked to a
//!   different operator than the parent's). Each refusal changes nothing.
//! * `epigraph_agent_prompt_history` is readable by the agent's operator (or an
//!   admin) and refused (AID06) to anyone else.
//!
//! # Why the arms run through `fixture::as_role`
//!
//! `#[sqlx::test]` connects as a superuser, which skips every grant check and
//! every row-security policy. Each property here is about grants and
//! policies, so each call is made from a session whose `session_user` IS the
//! role under test (`SET SESSION AUTHORIZATION`). Fixture rows (agents, human
//! operators, claims) are seeded on the superuser connection.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::AgentRepository;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const ATTESTOR: &str = "epigraph_identity_attestor";
const INSUFFICIENT_PRIVILEGE: &str = "42501";
const MODEL: &str = "test-model-1";

/// A synthetic identity: a random 32-byte public key, a prompt hash that is a
/// function of it (the real one is the BLAKE3 of the prompt files; nothing
/// here depends on how it was computed, only that it is 64 hex chars), and the
/// signing key the host generated for it ONCE (D2): every registration of the
/// same identity presents the same signing key, as the host does.
struct Identity {
    pubkey: Vec<u8>,
    prompt_hash: String,
    signing: Vec<u8>,
}

fn random32() -> Vec<u8> {
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    [a.as_bytes().as_slice(), b.as_bytes().as_slice()].concat()
}

fn new_identity() -> Identity {
    let pubkey = random32();
    let prompt_hash = blake3::hash(&pubkey).to_hex().to_string();
    let signing = blake3::hash(&[b"signing:".as_slice(), &pubkey].concat())
        .as_bytes()
        .to_vec();
    Identity {
        pubkey,
        prompt_hash,
        signing,
    }
}

/// The wire form of one stored prompt file: BLAKE3 of the RAW bytes, the raw
/// size, and the zstd frame, hex-encoded.
fn blob_json(raw: &[u8]) -> Value {
    let compressed = zstd::bulk::compress(raw, 19).expect("zstd compress");
    json!({
        "blob_hash": blake3::hash(raw).to_hex().to_string(),
        "raw_size": raw.len(),
        "codec": "zstd",
        "content": hex::encode(compressed),
    })
}

/// A snapshot whose group CLAUDE.md and LEARNED.md are present and whose
/// IDENTITY.md and global CLAUDE.md are absent: the common shape of a main
/// chat container today.
fn snapshot(group_claude: &str, learned: &str) -> Value {
    json!({
        "identity_md": null,
        "global_claude_md": null,
        "group_claude_md": blob_json(group_claude.as_bytes()),
        "learned_md": blob_json(learned.as_bytes()),
        "in_prompt": {
            "identity_md": false,
            "global_claude_md": false,
            "group_claude_md": true,
            "learned_md": true
        },
        "runner_version": "runner-test",
        "host_sha": "0000000"
    })
}

#[derive(Debug, sqlx::FromRow)]
struct Registered {
    agent_id: Uuid,
    agent_created: bool,
    succession_created: bool,
    snapshot_id: Uuid,
    snapshot_created: bool,
    signing_key_registered: bool,
    operator_id: Option<Uuid>,
    inherited: bool,
    inherit_reason: Option<String>,
}

#[allow(clippy::too_many_arguments)]
async fn try_register_as(
    pool: &PgPool,
    role: &str,
    id: &Identity,
    parent: Option<Uuid>,
    group: &str,
    signing: Option<Vec<u8>>,
    snap: Value,
    principal: Option<String>,
) -> Result<Registered, sqlx::Error> {
    let pubkey = id.pubkey.clone();
    let hash = id.prompt_hash.clone();
    let group = group.to_string();
    fixture::as_role(pool, role, |mut conn| async move {
        // ALWAYS set both, '' for "no principal": a session-level setting
        // survives on a pooled connection, so leaving it unset would inherit
        // whatever an earlier call on the same connection claimed.
        let p = principal.unwrap_or_default();
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(&p)
            .execute(&mut *conn)
            .await
            .expect("set principal");
        sqlx::query("SELECT set_config('epigraph.writable_group_ids', $1, false)")
            .bind(&p)
            .execute(&mut *conn)
            .await
            .expect("set writable groups");
        let r = sqlx::query_as::<_, Registered>(
            "SELECT * FROM public.epigraph_register_agent_identity($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&pubkey)
        .bind(parent)
        .bind(MODEL)
        .bind(&hash)
        .bind(&group)
        .bind(signing)
        .bind(&snap)
        .fetch_one(&mut *conn)
        .await;
        (conn, r)
    })
    .await
}

async fn try_register(
    pool: &PgPool,
    id: &Identity,
    parent: Option<Uuid>,
    group: &str,
    snap: Value,
) -> Result<Registered, sqlx::Error> {
    try_register_as(
        pool,
        ATTESTOR,
        id,
        parent,
        group,
        Some(id.signing.clone()),
        snap,
        None,
    )
    .await
}

async fn register(
    pool: &PgPool,
    id: &Identity,
    parent: Option<Uuid>,
    group: &str,
    snap: Value,
) -> Registered {
    try_register(pool, id, parent, group, snap)
        .await
        .expect("the attestor registers the identity")
}

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.to_string())
}

/// A registered human operator with no personal group yet.
async fn human_operator(pool: &PgPool) -> Uuid {
    let agent = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(random32())
        .execute(pool)
        .await
        .expect("seed operator agent");
    fixture::make_human_operator(pool, agent).await;
    agent
}

/// A manual (maintenance) link, the path an operator CLI takes today.
async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let out = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_operator(&mut conn, agent, operator).await;
        (conn, r)
    })
    .await
    .expect("the maintenance role links the agent");
    assert!(out.link_live, "the manual link must be live");
}

/// A parent that is registered (no parent of its own) and then linked to
/// `operator` by maintenance.
async fn live_linked_parent(pool: &PgPool, operator: Uuid, group: &str) -> Uuid {
    let p = register(
        pool,
        &new_identity(),
        None,
        group,
        snapshot("group v1", "learned p"),
    )
    .await;
    link(pool, p.agent_id, operator).await;
    p.agent_id
}

async fn operator_group(pool: &PgPool, operator: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:' || $1::text")
        .bind(operator)
        .fetch_one(pool)
        .await
        .expect("operator personal group")
}

/// Row counts of every table the registration path can touch, so "nothing
/// changed" is measured rather than inferred from a single table.
async fn footprint(pool: &PgPool) -> Vec<(String, i64)> {
    let mut out = Vec::new();
    for t in [
        "agents",
        "agent_succession",
        "agent_prompt_snapshots",
        "agent_prompt_blobs",
        "agent_keys",
        "operator_links",
        "group_memberships",
        "groups",
        "edges",
        "security_events",
    ] {
        let n: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM public.{t}"))
            .fetch_one(pool)
            .await
            .unwrap_or_else(|e| panic!("count {t}: {e}"));
        out.push((t.to_string(), n));
    }
    out
}

async fn human_of(pool: &PgPool, agent: Uuid, live_only: bool) -> Option<Uuid> {
    sqlx::query_scalar("SELECT public.epigraph_human_of($1, $2)")
        .bind(agent)
        .bind(live_only)
        .fetch_one(pool)
        .await
        .expect("human_of")
}

/// `(role, live)` of every membership of `agent` in `group`.
async fn memberships(pool: &PgPool, group: Uuid, agent: Uuid) -> Vec<(String, bool)> {
    sqlx::query_as(
        "SELECT role::text, revoked_at IS NULL FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 ORDER BY epoch",
    )
    .bind(group)
    .bind(agent)
    .fetch_all(pool)
    .await
    .expect("memberships")
}

/// The `source` property of every OPERATED_BY edge from `agent` to `operator`.
async fn operated_by_sources(pool: &PgPool, agent: Uuid, operator: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT COALESCE(properties->>'source', '') FROM edges \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'OPERATED_BY'",
    )
    .bind(agent)
    .bind(operator)
    .fetch_all(pool)
    .await
    .expect("edges")
}

// ─────────────────────────────────────────────────────────────────────────────
// The trust boundary: the ROLE of the connection, never the principal it claims.
// ─────────────────────────────────────────────────────────────────────────────

/// `epigraph_app` cannot execute the registration, whatever principal and
/// writable groups the session claims: the operator's own id, a custodian's
/// id, or a random one. Every attempt is a permission denial (42501) and
/// writes nothing. CALIBRATION: the attestor, with the same inputs, succeeds.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_register_even_with_a_forged_principal(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let custodian = human_operator(&pool).await;
    fixture::make_custodian(&pool, custodian).await;
    let parent = live_linked_parent(&pool, operator, "g-forge").await;
    let child = new_identity();

    let before = footprint(&pool).await;
    for principal in [
        Some(operator.to_string()),
        Some(custodian.to_string()),
        Some(Uuid::new_v4().to_string()),
        None,
    ] {
        let err = try_register_as(
            &pool,
            "epigraph_app",
            &child,
            Some(parent),
            "g-forge",
            Some(random32()),
            snapshot("group", "learned"),
            principal.clone(),
        )
        .await
        .expect_err("epigraph_app executed epigraph_register_agent_identity");
        assert_eq!(
            sqlstate(&err).as_deref(),
            Some(INSUFFICIENT_PRIVILEGE),
            "principal {principal:?}: the refusal must be a permission denial, not {err}"
        );
    }
    assert_eq!(
        footprint(&pool).await,
        before,
        "a refused registration must write nothing"
    );

    // CALIBRATION: the same inputs on the attestor role succeed.
    let ok = register(
        &pool,
        &child,
        Some(parent),
        "g-forge",
        snapshot("group", "learned"),
    )
    .await;
    assert!(ok.agent_created && ok.inherited);
}

/// The attestor role is created NOLOGIN (ops grants LOGIN out of band), is a
/// member of no role, holds no elevated attribute and no read of the lineage
/// tables, and can execute the registration but neither link function nor the
/// history read. The registration's ACL is EXACTLY the attestor's EXECUTE, and
/// it is a maintenance-owned definer pinned to a search_path.
#[sqlx::test(migrations = "../../migrations")]
async fn the_attestor_role_holds_registration_and_nothing_else_it_could_abuse(pool: PgPool) {
    let (login, sup, createrole, createdb, bypass, repl): (bool, bool, bool, bool, bool, bool) =
        sqlx::query_as(
            "SELECT rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication \
               FROM pg_roles WHERE rolname = $1",
        )
        .bind(ATTESTOR)
        .fetch_one(&pool)
        .await
        .expect("the attestor role exists");
    assert!(!login, "the migration must create the attestor NOLOGIN");
    assert!(!(sup || createrole || createdb || bypass || repl));

    let member_of: Vec<String> = sqlx::query_scalar(
        "SELECT r.rolname::text FROM pg_auth_members m \
           JOIN pg_roles r ON r.oid = m.roleid \
           JOIN pg_roles u ON u.oid = m.member \
          WHERE u.rolname = $1",
    )
    .bind(ATTESTOR)
    .fetch_all(&pool)
    .await
    .expect("memberships");
    assert!(
        member_of.is_empty(),
        "the attestor must be a member of nothing, is a member of {member_of:?}"
    );

    for table in [
        "agent_succession",
        "agent_prompt_blobs",
        "agent_prompt_snapshots",
        "operator_links",
    ] {
        let can: bool = sqlx::query_scalar("SELECT has_table_privilege($1, $2, 'SELECT')")
            .bind(ATTESTOR)
            .bind(format!("public.{table}"))
            .fetch_one(&pool)
            .await
            .expect("table privilege");
        assert!(!can, "the attestor can SELECT {table}");
    }

    for (signature, attestor_may, app_may) in [
        (
            "public.epigraph_register_agent_identity(bytea, uuid, text, text, text, bytea, jsonb)",
            true,
            false,
        ),
        ("public.epigraph_link_operator(uuid, uuid)", false, false),
        (
            "public.epigraph_link_operator_body(uuid, uuid, jsonb)",
            false,
            false,
        ),
        ("public.epigraph_agent_prompt_history(uuid)", false, true),
    ] {
        for (role, want) in [(ATTESTOR, attestor_may), ("epigraph_app", app_may)] {
            let can: bool = sqlx::query_scalar("SELECT has_function_privilege($1, $2, 'EXECUTE')")
                .bind(role)
                .bind(signature)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| panic!("{signature}: {e}"));
            assert_eq!(can, want, "{role} EXECUTE on {signature}");
        }
    }

    let (secdef, owner, acl, config): (bool, String, Option<String>, Option<Vec<String>>) =
        sqlx::query_as(
            "SELECT p.prosecdef, pg_get_userbyid(p.proowner)::text, p.proacl::text, p.proconfig \
               FROM pg_proc p WHERE p.oid = \
                 'public.epigraph_register_agent_identity(bytea, uuid, text, text, text, bytea, jsonb)'::regprocedure",
        )
        .fetch_one(&pool)
        .await
        .expect("register's catalog row");
    assert!(secdef, "the registration must be SECURITY DEFINER");
    assert_eq!(owner, "epigraph_maintenance");
    assert_eq!(
        acl.as_deref(),
        Some("{epigraph_identity_attestor=X/epigraph_maintenance}"),
        "EXECUTE on the registration must be granted to the attestor and to nobody else \
         (PUBLIC, epigraph_app and the owner itself revoked)"
    );
    assert!(
        config
            .unwrap_or_default()
            .iter()
            .any(|c| c.starts_with("search_path=")),
        "a definer must pin its search_path"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// D3 step 5: link inheritance.
// ─────────────────────────────────────────────────────────────────────────────

/// A child registered with a LIVE-linked parent ends up exactly as a manual
/// link leaves an agent: a live link to the parent's operator, a writer
/// membership in the operator's personal group, an OPERATED_BY edge, the
/// succession row, `parent_agent_id`, and one audit row naming the parent.
async fn assert_inherits(pool: &PgPool) {
    let operator = human_operator(pool).await;
    let parent = live_linked_parent(pool, operator, "g-main").await;
    let child = new_identity();

    let r = register(
        pool,
        &child,
        Some(parent),
        "g-main",
        snapshot("group v1", "learned v2"),
    )
    .await;
    assert!(r.agent_created && r.succession_created && r.snapshot_created);
    assert!(r.signing_key_registered);
    assert!(
        r.inherited,
        "a child of a live-linked parent inherits the link"
    );
    assert_eq!(r.inherit_reason, None);
    assert_eq!(r.operator_id, Some(operator));
    assert_ne!(r.agent_id, parent);

    assert_eq!(
        human_of(pool, r.agent_id, true).await,
        human_of(pool, parent, true).await,
        "the child must be live-linked to the same operator as its parent"
    );
    let group = operator_group(pool, operator).await;
    assert_eq!(
        memberships(pool, group, r.agent_id).await,
        memberships(pool, group, parent).await,
        "the child's membership must be what the manual link gave the parent"
    );
    assert_eq!(
        memberships(pool, group, r.agent_id).await,
        vec![("writer".to_string(), true)]
    );
    assert_eq!(
        operated_by_sources(pool, r.agent_id, operator).await,
        vec!["epigraph_register_agent_identity".to_string()],
        "the inherited link writes one OPERATED_BY edge, attributed to the registration"
    );
    assert_eq!(
        operated_by_sources(pool, parent, operator).await,
        vec!["epigraph_link_operator".to_string()],
        "the manual link's edge keeps its own source"
    );

    let (succ, parent_col): (i64, Option<Uuid>) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM agent_succession \
                  WHERE child_agent_id = $1 AND parent_agent_id = $2 AND group_folder = 'g-main'), \
                (SELECT parent_agent_id FROM agents WHERE id = $1)",
    )
    .bind(r.agent_id)
    .bind(parent)
    .fetch_one(pool)
    .await
    .expect("succession");
    assert_eq!(succ, 1);
    assert_eq!(parent_col, Some(parent));

    let audit: Vec<Value> = sqlx::query_scalar(
        "SELECT details FROM security_events \
          WHERE event_type = 'agent.identity_registered' AND agent_id = $1",
    )
    .bind(r.agent_id)
    .fetch_all(pool)
    .await
    .expect("audit");
    assert_eq!(
        audit.len(),
        1,
        "one audit row per registration that changed state"
    );
    assert_eq!(audit[0]["parent_agent_id"], json!(parent.to_string()));
    assert_eq!(audit[0]["operator_id"], json!(operator.to_string()));
    assert_eq!(audit[0]["group_folder"], json!("g-main"));
    assert_eq!(audit[0]["recorded_by"], json!(ATTESTOR));
    assert_eq!(audit[0]["snapshot_id"], json!(r.snapshot_id.to_string()));
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_child_of_a_live_linked_parent_inherits_the_parents_operator(pool: PgPool) {
    assert_inherits(&pool).await;
}

/// The same inheritance on a database whose operator binding is ARMED: the
/// membership door (`group_memberships_operator_scope`) is then live, and the
/// inherited writer row must still pass it.
#[sqlx::test(migrations = "../../migrations")]
async fn inheritance_holds_with_the_operator_binding_armed(pool: PgPool) {
    let armed = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r: bool =
            sqlx::query_scalar("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
                .fetch_one(&mut *conn)
                .await
                .expect("the maintenance role arms");
        (conn, r)
    })
    .await;
    assert!(armed);
    assert_inherits(&pool).await;
}

/// An unlinked parent and a RETIRED-linked parent pass on nothing: the child
/// is registered with its succession row, but gets no link, no membership and
/// no edge, and the result says why. CALIBRATION in the same database: a
/// live-linked parent does pass its link on.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unlinked_or_retired_parent_passes_on_nothing(pool: PgPool) {
    let operator = human_operator(&pool).await;

    let unlinked = register(&pool, &new_identity(), None, "g-a", snapshot("g", "l1")).await;
    let retired = register(&pool, &new_identity(), None, "g-b", snapshot("g", "l2")).await;
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_retired_agent(&mut conn, retired.agent_id, operator).await;
        (conn, r)
    })
    .await
    .expect("retire-link the second parent");
    let live = live_linked_parent(&pool, operator, "g-c").await;

    for (parent, group, reason) in [
        (unlinked.agent_id, "g-a", "parent_unlinked"),
        (retired.agent_id, "g-b", "parent_link_retired"),
    ] {
        let r = register(
            &pool,
            &new_identity(),
            Some(parent),
            group,
            snapshot("g", "next"),
        )
        .await;
        assert!(r.agent_created && r.succession_created);
        assert!(!r.inherited, "{reason}: nothing may be inherited");
        assert_eq!(r.inherit_reason.as_deref(), Some(reason));
        assert_eq!(r.operator_id, None);
        assert_eq!(human_of(&pool, r.agent_id, false).await, None);
        let (links, mems, edges): (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM operator_links WHERE agent_id = $1), \
                    (SELECT count(*) FROM group_memberships WHERE agent_id = $1), \
                    (SELECT count(*) FROM edges WHERE source_id = $1 AND relationship = 'OPERATED_BY')",
        )
        .bind(r.agent_id)
        .fetch_one(&pool)
        .await
        .expect("child state");
        assert_eq!((links, mems, edges), (0, 0, 0), "{reason}");
    }

    let calibration = register(
        &pool,
        &new_identity(),
        Some(live),
        "g-c",
        snapshot("g", "c"),
    )
    .await;
    assert!(calibration.inherited);
    assert_eq!(calibration.operator_id, Some(operator));
}

// ─────────────────────────────────────────────────────────────────────────────
// Idempotence and identities shared across groups.
// ─────────────────────────────────────────────────────────────────────────────

/// Registering the same (child, parent, group) with the same files twice
/// writes nothing the second time but `last_seen`: every table's row count is
/// unchanged, the snapshot is the same row, and its `first_seen` stays.
#[sqlx::test(migrations = "../../migrations")]
async fn the_same_child_parent_and_group_twice_only_bumps_last_seen(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let parent = live_linked_parent(&pool, operator, "g-idem").await;
    let child = new_identity();
    let signing = random32();

    let first = try_register_as(
        &pool,
        ATTESTOR,
        &child,
        Some(parent),
        "g-idem",
        Some(signing.clone()),
        snapshot("group", "learned"),
        None,
    )
    .await
    .expect("first registration");
    // Age the snapshot by an hour (superuser, guard off for this one statement)
    // so "last_seen moved forward" does not depend on two transactions being
    // ordered by a wall clock that a build host may step backward.
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("ALTER TABLE agent_prompt_snapshots DISABLE TRIGGER USER")
        .execute(&mut *tx)
        .await
        .expect("disable the snapshot guard (test only)");
    sqlx::query(
        "UPDATE agent_prompt_snapshots SET first_seen = first_seen - interval '1 hour', \
                last_seen = last_seen - interval '1 hour' WHERE id = $1",
    )
    .bind(first.snapshot_id)
    .execute(&mut *tx)
    .await
    .expect("age the snapshot");
    sqlx::query("ALTER TABLE agent_prompt_snapshots ENABLE TRIGGER USER")
        .execute(&mut *tx)
        .await
        .expect("re-enable");
    tx.commit().await.expect("commit");
    let (first_seen_1, last_seen_1): (
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    ) = sqlx::query_as("SELECT first_seen, last_seen FROM agent_prompt_snapshots WHERE id = $1")
        .bind(first.snapshot_id)
        .fetch_one(&pool)
        .await
        .expect("snapshot times");

    let before = footprint(&pool).await;
    let second = try_register_as(
        &pool,
        ATTESTOR,
        &child,
        Some(parent),
        "g-idem",
        Some(signing),
        snapshot("group", "learned"),
        None,
    )
    .await
    .expect("second registration");
    assert_eq!(
        footprint(&pool).await,
        before,
        "a repeat registration adds no row anywhere"
    );

    assert_eq!(second.agent_id, first.agent_id);
    assert_eq!(second.snapshot_id, first.snapshot_id);
    assert!(
        !(second.agent_created
            || second.succession_created
            || second.snapshot_created
            || second.signing_key_registered
            || second.inherited)
    );
    assert_eq!(second.operator_id, Some(operator));
    assert_eq!(second.inherit_reason.as_deref(), Some("already_linked"));

    let (first_seen_2, last_seen_2): (
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    ) = sqlx::query_as("SELECT first_seen, last_seen FROM agent_prompt_snapshots WHERE id = $1")
        .bind(first.snapshot_id)
        .fetch_one(&pool)
        .await
        .expect("snapshot times");
    assert_eq!(first_seen_2, first_seen_1, "first_seen never moves");
    assert!(last_seen_2 > last_seen_1, "a repeat start bumps last_seen");
}

/// One identity is legitimately shared by many groups (same model, same
/// files). The same child from a second group with the same parent succeeds,
/// adds a succession row and a snapshot row for that group, re-uses the
/// stored blobs (content-addressed), and links nothing twice.
#[sqlx::test(migrations = "../../migrations")]
async fn the_same_child_from_a_second_group_adds_a_snapshot_and_reuses_the_blobs(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let parent = live_linked_parent(&pool, operator, "g-one").await;
    let child = new_identity();

    let one = register(
        &pool,
        &child,
        Some(parent),
        "g-one",
        snapshot("shared", "shared"),
    )
    .await;
    let blobs_before: i64 = sqlx::query_scalar("SELECT count(*) FROM agent_prompt_blobs")
        .fetch_one(&pool)
        .await
        .expect("blobs");
    let links_before: i64 = sqlx::query_scalar("SELECT count(*) FROM operator_links")
        .fetch_one(&pool)
        .await
        .expect("links");

    let two = register(
        &pool,
        &child,
        Some(parent),
        "g-two",
        snapshot("shared", "shared"),
    )
    .await;
    assert_eq!(two.agent_id, one.agent_id);
    assert!(!two.agent_created);
    assert!(
        two.succession_created,
        "a new (child, parent, group) is a new succession row"
    );
    assert!(two.snapshot_created, "a new group is a new snapshot row");
    assert_ne!(two.snapshot_id, one.snapshot_id);
    assert_eq!(two.operator_id, Some(operator));

    let (succ, snaps, blobs, links): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM agent_succession WHERE child_agent_id = $1), \
                (SELECT count(*) FROM agent_prompt_snapshots WHERE agent_id = $1), \
                (SELECT count(*) FROM agent_prompt_blobs), \
                (SELECT count(*) FROM operator_links)",
    )
    .bind(one.agent_id)
    .fetch_one(&pool)
    .await
    .expect("state");
    assert_eq!((succ, snaps), (2, 2));
    assert_eq!(blobs, blobs_before, "identical file content is stored once");
    assert_eq!(links, links_before, "the second group links nothing new");
}

/// A parent equal to the child (only a non-identity file changed, so the host
/// re-registers the identity it already had) records no lineage at all.
#[sqlx::test(migrations = "../../migrations")]
async fn a_parent_equal_to_the_child_records_no_lineage(pool: PgPool) {
    let id = new_identity();
    let first = register(&pool, &id, None, "g-self", snapshot("group v1", "l")).await;
    let again = register(
        &pool,
        &id,
        Some(first.agent_id),
        "g-self",
        snapshot("group v2", "l"),
    )
    .await;
    assert_eq!(again.agent_id, first.agent_id);
    assert!(!again.succession_created);
    assert!(
        again.snapshot_created,
        "the changed group CLAUDE.md is a new snapshot"
    );
    assert_eq!(again.inherit_reason.as_deref(), Some("no_parent"));
    let (succ, parent_col): (i64, Option<Uuid>) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM agent_succession WHERE child_agent_id = $1), \
                (SELECT parent_agent_id FROM agents WHERE id = $1)",
    )
    .bind(first.agent_id)
    .fetch_one(&pool)
    .await
    .expect("lineage");
    assert_eq!((succ, parent_col), (0, None));
}

// ─────────────────────────────────────────────────────────────────────────────
// Refusals, each paired with the same harness succeeding.
// ─────────────────────────────────────────────────────────────────────────────

/// AID07: the child is already linked to operator B, and the parent is
/// live-linked to operator A. The call raises and NOTHING changes anywhere,
/// not even the snapshot. CALIBRATION: the same child with a parent linked to
/// B registers fine.
#[sqlx::test(migrations = "../../migrations")]
async fn a_child_linked_to_a_different_operator_is_refused_aid07(pool: PgPool) {
    let op_a = human_operator(&pool).await;
    let op_b = human_operator(&pool).await;
    let parent_a = live_linked_parent(&pool, op_a, "g-x").await;
    let parent_b = live_linked_parent(&pool, op_b, "g-y").await;

    let child = new_identity();
    let c = register(&pool, &child, None, "g-x", snapshot("g", "l")).await;
    link(&pool, c.agent_id, op_b).await;

    let before = footprint(&pool).await;
    let err = try_register(
        &pool,
        &child,
        Some(parent_a),
        "g-x",
        snapshot("g changed", "l"),
    )
    .await
    .expect_err("a child linked to another operator must be refused");
    assert_eq!(sqlstate(&err).as_deref(), Some("AID07"), "{err}");
    assert_eq!(footprint(&pool).await, before, "AID07 changes nothing");
    assert_eq!(human_of(&pool, c.agent_id, true).await, Some(op_b));

    let ok = register(&pool, &child, Some(parent_b), "g-y", snapshot("g", "l")).await;
    assert!(!ok.inherited);
    assert_eq!(ok.inherit_reason.as_deref(), Some("already_linked"));
    assert_eq!(ok.operator_id, Some(op_b));
}

/// AID05: an existing agent that has authored claims and was never registered
/// is not EpiClaw's to adopt. CALIBRATIONS: an existing agent with no claims
/// can be adopted, and an agent registered earlier (no parent, a new group)
/// that has since written claims re-registers fine: its earlier snapshot is
/// the prior registration.
#[sqlx::test(migrations = "../../migrations")]
async fn adopting_an_agent_with_claims_and_no_registration_is_refused_aid05(pool: PgPool) {
    let foreign = new_identity();
    let foreign_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'software_agent')",
    )
    .bind(foreign_id)
    .bind(&foreign.pubkey)
    .execute(&pool)
    .await
    .expect("seed a non-EpiClaw agent");
    fixture::seed_public_claim(&pool, foreign_id, "a claim by an agent EpiClaw never ran").await;

    let before = footprint(&pool).await;
    let err = try_register(&pool, &foreign, None, "g-adopt", snapshot("g", "l"))
        .await
        .expect_err("adopting an agent with claims must be refused");
    assert_eq!(sqlstate(&err).as_deref(), Some("AID05"), "{err}");
    assert_eq!(footprint(&pool).await, before, "AID05 changes nothing");

    // CALIBRATION 1: the same shape with no claims is adoptable.
    let quiet = new_identity();
    let quiet_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'software_agent')",
    )
    .bind(quiet_id)
    .bind(&quiet.pubkey)
    .execute(&pool)
    .await
    .expect("seed a claimless agent");
    let adopted = register(&pool, &quiet, None, "g-adopt", snapshot("g", "l")).await;
    assert_eq!(adopted.agent_id, quiet_id);
    assert!(!adopted.agent_created);

    // CALIBRATION 2: registered earlier, then wrote claims, re-registers.
    let ours = new_identity();
    let first = register(&pool, &ours, None, "g-new", snapshot("g v1", "l")).await;
    fixture::seed_public_claim(&pool, first.agent_id, "a claim by a registered agent").await;
    let again = register(&pool, &ours, None, "g-new", snapshot("g v2", "l")).await;
    assert_eq!(again.agent_id, first.agent_id);
    assert!(again.snapshot_created);
}

/// AID03: the parent must be an LLM agent (a derived identity, or one whose
/// properties carry `llm_model`). A human operator is refused, and the call
/// changes nothing. CALIBRATIONS: an `ed25519` agent carrying `llm_model` (the
/// shape epigraph-mcp's legacy path creates) and a registered (derived)
/// identity are both accepted as parents.
#[sqlx::test(migrations = "../../migrations")]
async fn a_parent_that_is_not_an_llm_agent_is_refused_aid03(pool: PgPool) {
    let human = human_operator(&pool).await;
    let before = footprint(&pool).await;
    let err = try_register(
        &pool,
        &new_identity(),
        Some(human),
        "g-h",
        snapshot("g", "l"),
    )
    .await
    .expect_err("a human parent must be refused");
    assert_eq!(sqlstate(&err).as_deref(), Some("AID03"), "{err}");
    assert_eq!(footprint(&pool).await, before, "AID03 changes nothing");

    let legacy = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type, properties) \
         VALUES ($1, $2, 'software_agent', jsonb_build_object('llm_model', 'old-model', \
                 'source', 'mcp-llm-agent'))",
    )
    .bind(legacy)
    .bind(random32())
    .execute(&pool)
    .await
    .expect("seed a legacy LLM agent");
    let from_legacy = register(
        &pool,
        &new_identity(),
        Some(legacy),
        "g-h",
        snapshot("g", "l"),
    )
    .await;
    assert!(from_legacy.succession_created);

    let derived = register(&pool, &new_identity(), None, "g-d", snapshot("g", "l")).await;
    let from_derived = register(
        &pool,
        &new_identity(),
        Some(derived.agent_id),
        "g-d",
        snapshot("g", "l"),
    )
    .await;
    assert!(from_derived.succession_created);
}

/// A new identity is created as a derived LLM agent carrying its model and
/// prompt hash, and an existing identity re-registered under a DIFFERENT model
/// or prompt hash is refused: the identity key is a function of both, so a
/// mismatch is a host bug, not a new fact to record.
#[sqlx::test(migrations = "../../migrations")]
async fn a_registered_identity_records_its_model_and_refuses_a_mismatch(pool: PgPool) {
    let id = new_identity();
    let r = register(&pool, &id, None, "g-m", snapshot("g", "l")).await;
    let (kind, atype, props): (String, Option<String>, Value) = sqlx::query_as(
        "SELECT key_kind::text, agent_type::text, properties FROM agents WHERE id = $1",
    )
    .bind(r.agent_id)
    .fetch_one(&pool)
    .await
    .expect("agent row");
    assert_eq!(kind, "derived");
    assert_eq!(atype.as_deref(), Some("llm"));
    assert_eq!(props["llm_model"], json!(MODEL));
    assert_eq!(props["llm_prompt_hash"], json!(id.prompt_hash));
    assert_eq!(props["source"], json!("epiclaw"));

    let wrong = Identity {
        pubkey: id.pubkey.clone(),
        prompt_hash: blake3::hash(b"other").to_hex().to_string(),
        signing: id.signing.clone(),
    };
    let before = footprint(&pool).await;
    let err = try_register(&pool, &wrong, None, "g-m", snapshot("g", "l"))
        .await
        .expect_err("a different prompt hash for the same key must be refused");
    assert_eq!(sqlstate(&err).as_deref(), Some("22023"), "{err}");
    assert_eq!(footprint(&pool).await, before);
}

// ─────────────────────────────────────────────────────────────────────────────
// Signing keys (D2) and stored blobs (D4).
// ─────────────────────────────────────────────────────────────────────────────

/// The signing key is registered once per agent as an active `signing` key; a
/// later registration with another key does not replace it; a key already
/// bound to a different agent is refused; and the identity key itself can
/// never be the signing key.
#[sqlx::test(migrations = "../../migrations")]
async fn the_signing_key_is_registered_once_and_never_shared(pool: PgPool) {
    let id = new_identity();
    let key = random32();
    let r = try_register_as(
        &pool,
        ATTESTOR,
        &id,
        None,
        "g-k",
        Some(key.clone()),
        snapshot("g", "l"),
        None,
    )
    .await
    .expect("first registration");
    assert!(r.signing_key_registered);
    let again = try_register_as(
        &pool,
        ATTESTOR,
        &id,
        None,
        "g-k",
        Some(random32()),
        snapshot("g", "l"),
        None,
    )
    .await
    .expect("second registration");
    assert!(
        !again.signing_key_registered,
        "an active signing key is never replaced here"
    );
    let keys: Vec<(Vec<u8>, String)> = sqlx::query_as(
        "SELECT public_key, status::text FROM agent_keys \
          WHERE agent_id = $1 AND key_type = 'signing'",
    )
    .bind(r.agent_id)
    .fetch_all(&pool)
    .await
    .expect("keys");
    assert_eq!(keys, vec![(key.clone(), "active".to_string())]);

    let other = new_identity();
    let err = try_register_as(
        &pool,
        ATTESTOR,
        &other,
        None,
        "g-k",
        Some(key),
        snapshot("g", "l"),
        None,
    )
    .await
    .expect_err("a signing key bound to another agent must be refused");
    assert_eq!(sqlstate(&err).as_deref(), Some("22023"), "{err}");

    let selfish = new_identity();
    let err = try_register_as(
        &pool,
        ATTESTOR,
        &selfish,
        None,
        "g-k",
        Some(selfish.pubkey.clone()),
        snapshot("g", "l"),
        None,
    )
    .await
    .expect_err("the identity key cannot be the signing key");
    assert_eq!(sqlstate(&err).as_deref(), Some("22023"), "{err}");
}

/// A file the host refused to store (a secret was found in it) is recorded BY
/// NAME with no content: its blob column is NULL, no blob is written for it,
/// and a later start with the same refusal is the same snapshot.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_file_is_recorded_by_name_with_no_content(pool: PgPool) {
    let mut snap = snapshot("group", "unused");
    snap["learned_md"] = json!({"refused": true});
    let blobs_before: i64 = sqlx::query_scalar("SELECT count(*) FROM agent_prompt_blobs")
        .fetch_one(&pool)
        .await
        .expect("blobs");
    let id = new_identity();
    let r = register(&pool, &id, None, "g-r", snap.clone()).await;
    let (refused, learned, group): (Vec<String>, Option<Vec<u8>>, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT blob_refused, learned_md, group_claude_md FROM agent_prompt_snapshots WHERE id = $1",
    )
    .bind(r.snapshot_id)
    .fetch_one(&pool)
    .await
    .expect("snapshot");
    assert_eq!(refused, vec!["learned_md".to_string()]);
    assert_eq!(learned, None);
    assert!(
        group.is_some(),
        "the files that were not refused are still stored"
    );
    let blobs_after: i64 = sqlx::query_scalar("SELECT count(*) FROM agent_prompt_blobs")
        .fetch_one(&pool)
        .await
        .expect("blobs");
    assert_eq!(
        blobs_after,
        blobs_before + 1,
        "only the group CLAUDE.md is stored"
    );

    let again = register(&pool, &id, None, "g-r", snap).await;
    assert_eq!(again.snapshot_id, r.snapshot_id);
    assert!(!again.snapshot_created);
}

/// Stored blobs are immutable even for the maintenance role (and a
/// superuser): content-addressing is only a guarantee if the content under a
/// hash can never change.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stored_blob_can_be_neither_rewritten_nor_deleted(pool: PgPool) {
    register(&pool, &new_identity(), None, "g-i", snapshot("g", "l")).await;
    // CALIBRATION: the maintenance role SEES the blobs (so a zero-row answer
    // below would not be the policy hiding them).
    let visible = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM agent_prompt_blobs")
            .fetch_one(&mut *conn)
            .await
            .expect("maintenance reads blobs");
        (conn, n)
    })
    .await;
    assert_eq!(visible, 2, "the registration stored two blobs");

    for stmt in [
        "UPDATE agent_prompt_blobs SET raw_size = raw_size + 1",
        "DELETE FROM agent_prompt_blobs",
    ] {
        let s = stmt.to_string();
        let maint = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let r = sqlx::query(&s).execute(&mut *conn).await;
            (conn, r)
        })
        .await;
        let err = maint.expect_err("the maintenance role changed a stored blob");
        assert_eq!(
            sqlstate(&err).as_deref(),
            Some(INSUFFICIENT_PRIVILEGE),
            "{stmt}: {err}"
        );

        // A superuser skips grants and row security; the append-only guard
        // still refuses, with its own SQLSTATE (not the FK's 23503).
        let err = sqlx::query(stmt)
            .execute(&pool)
            .await
            .expect_err("a superuser changed a stored blob");
        assert_eq!(sqlstate(&err).as_deref(), Some("55000"), "{stmt}: {err}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// D2 historic signatures: the legacy-key backfill.
// ─────────────────────────────────────────────────────────────────────────────

/// Every agent that exists when 161 applies gets exactly one active
/// `identity-legacy` key row carrying its current public key, open-ended
/// (`valid_until` NULL until cut-over). Measured by migrating to 160,
/// seeding agents, then migrating to head.
#[sqlx::test(migrations = false)]
async fn the_backfill_gives_every_existing_agent_its_legacy_key(pool: PgPool) {
    let migrator = sqlx::migrate!("../../migrations");
    let before = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            migrator
                .migrations
                .iter()
                .filter(|m| m.version < 161)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    };
    let mut conn = pool.acquire().await.expect("acquire");
    before.run(&mut *conn).await.expect("migrate to 160");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
    drop(conn);

    let mut seeded = Vec::new();
    for kind in ["ed25519", "derived"] {
        let id = Uuid::new_v4();
        let key = random32();
        sqlx::query(
            "INSERT INTO agents (id, public_key, agent_type, key_kind) VALUES ($1, $2, 'software_agent', $3)",
        )
        .bind(id)
        .bind(&key)
        .bind(kind)
        .execute(&pool)
        .await
        .expect("seed agent");
        seeded.push((id, key));
    }

    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate to head");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
    drop(conn);

    let without: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agents a WHERE NOT EXISTS (\
           SELECT 1 FROM agent_keys k WHERE k.agent_id = a.id AND k.key_type = 'identity-legacy')",
    )
    .fetch_one(&pool)
    .await
    .expect("agents without a legacy key");
    assert_eq!(
        without, 0,
        "every pre-existing agent must have its legacy key row"
    );

    for (id, key) in seeded {
        let rows: Vec<(Vec<u8>, String, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as(
            "SELECT public_key, status::text, valid_until FROM agent_keys \
              WHERE agent_id = $1 AND key_type = 'identity-legacy'",
        )
        .bind(id)
        .fetch_all(&pool)
        .await
        .expect("legacy rows");
        assert_eq!(rows, vec![(key, "active".to_string(), None)]);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// D4: prompt history.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
struct HistoryRow {
    agent_id: Uuid,
    relation: String,
    readable: bool,
    snapshot_id: Option<Uuid>,
    learned_md_hash: Option<Vec<u8>>,
    learned_md: Option<Vec<u8>>,
}

async fn history_as(
    pool: &PgPool,
    principal: Option<Uuid>,
    agent: Uuid,
) -> Result<Vec<HistoryRow>, sqlx::Error> {
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        // ALWAYS set it, '' for "no principal": a session-level setting
        // survives on a pooled connection, so leaving it unset would read as
        // whichever principal an earlier call on the same connection set.
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(principal.map(|p| p.to_string()).unwrap_or_default())
            .execute(&mut *conn)
            .await
            .expect("set principal");
        let r = sqlx::query_as::<_, HistoryRow>(
            "SELECT agent_id, relation, readable, snapshot_id, learned_md_hash, learned_md \
               FROM public.epigraph_agent_prompt_history($1)",
        )
        .bind(agent)
        .fetch_all(&mut *conn)
        .await;
        (conn, r)
    })
    .await
}

/// The operator reads its agent's history, including the parent it succeeded,
/// and the stored LEARNED.md decompresses to exactly what was registered under
/// exactly its hash. A stranger (another registered human) and a session with
/// no principal are refused AID06. CALIBRATION: a custodian reads it.
#[sqlx::test(migrations = "../../migrations")]
async fn history_is_the_operators_and_refused_aid06_to_a_stranger(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let stranger = human_operator(&pool).await;
    let custodian = human_operator(&pool).await;
    fixture::make_custodian(&pool, custodian).await;
    let parent = live_linked_parent(&pool, operator, "g-h").await;
    let learned = "the child learned this\n".repeat(40);
    let child = register(
        &pool,
        &new_identity(),
        Some(parent),
        "g-h",
        snapshot("group", &learned),
    )
    .await;

    let rows = history_as(&pool, Some(operator), child.agent_id)
        .await
        .expect("the operator reads its agent's history");
    let me = rows
        .iter()
        .find(|r| r.relation == "self")
        .expect("a self row");
    assert_eq!(me.agent_id, child.agent_id);
    assert!(me.readable);
    assert_eq!(me.snapshot_id, Some(child.snapshot_id));
    let raw = zstd::bulk::decompress(me.learned_md.as_deref().expect("content"), 1 << 20)
        .expect("a zstd frame");
    assert_eq!(
        raw,
        learned.as_bytes(),
        "the stored file is exactly what was registered"
    );
    assert_eq!(
        me.learned_md_hash.as_deref(),
        Some(blake3::hash(learned.as_bytes()).as_bytes().as_slice())
    );
    assert!(
        rows.iter()
            .any(|r| r.relation == "ancestor" && r.agent_id == parent && r.readable),
        "the history walks up to the parent this agent succeeded"
    );
    let up = history_as(&pool, Some(operator), parent)
        .await
        .expect("the operator reads the parent's history");
    assert!(
        up.iter()
            .any(|r| r.relation == "descendant" && r.agent_id == child.agent_id),
        "the history walks down to the parent's successors"
    );

    for who in [Some(stranger), Some(Uuid::new_v4()), None] {
        let err = history_as(&pool, who, child.agent_id)
            .await
            .expect_err("only the operator or an admin reads prompt history");
        assert_eq!(sqlstate(&err).as_deref(), Some("AID06"), "{who:?}: {err}");
    }

    let admin = history_as(&pool, Some(custodian), child.agent_id)
        .await
        .expect("a custodian reads any agent's history");
    assert!(admin.iter().any(|r| r.relation == "self" && r.readable));
}

/// A lineage member the caller does not operate shows up by id only: its row
/// says `readable = false` and carries no snapshot and no content.
/// CALIBRATION: the caller's own agent in the same answer carries both.
#[sqlx::test(migrations = "../../migrations")]
async fn history_withholds_the_content_of_an_ancestor_the_caller_does_not_operate(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let unlinked = register(
        &pool,
        &new_identity(),
        None,
        "g-w",
        snapshot("g", "secret-ish"),
    )
    .await;
    let child = register(
        &pool,
        &new_identity(),
        Some(unlinked.agent_id),
        "g-w",
        snapshot("g", "l"),
    )
    .await;
    assert!(!child.inherited);
    link(&pool, child.agent_id, operator).await;

    let rows = history_as(&pool, Some(operator), child.agent_id)
        .await
        .expect("the operator reads its agent's history");
    let ancestor = rows
        .iter()
        .find(|r| r.agent_id == unlinked.agent_id)
        .expect("the unlinked parent is listed in the lineage");
    assert_eq!(ancestor.relation, "ancestor");
    assert!(!ancestor.readable);
    assert_eq!(ancestor.snapshot_id, None);
    assert_eq!(ancestor.learned_md, None);

    let me = rows.iter().find(|r| r.relation == "self").expect("self");
    assert!(me.readable && me.learned_md.is_some());
}

/// The registration's audit event family is reserved: an application session
/// cannot write an `agent.identity_registered` row, even one attributed to its
/// own principal, so a forged "the host registered X" record cannot exist.
/// CALIBRATION: the same session writes an unreserved event type about itself.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_forge_a_registration_audit_row(pool: PgPool) {
    fixture::grant_app_privileges(&pool, "epigraph_app").await;
    let me = human_operator(&pool).await;
    let (forged, allowed) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(me.to_string())
            .execute(&mut *conn)
            .await
            .expect("set principal");
        let insert = "INSERT INTO security_events (event_type, agent_id, success, details) \
                      VALUES ($1, $2, true, '{}'::jsonb)";
        let forged = sqlx::query(insert)
            .bind("agent.identity_registered")
            .bind(me)
            .execute(&mut *conn)
            .await;
        let allowed = sqlx::query(insert)
            .bind("agent.self_reported")
            .bind(me)
            .execute(&mut *conn)
            .await;
        (conn, (forged, allowed))
    })
    .await;
    allowed.expect("CALIBRATION: an app session records an unreserved event about itself");
    let err = forged.expect_err("an app session forged a registration audit row");
    assert_eq!(
        sqlstate(&err).as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "{err}"
    );
}
