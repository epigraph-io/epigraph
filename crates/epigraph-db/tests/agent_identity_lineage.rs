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
    link_live: bool,
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
    try_register_full(
        pool, role, id, MODEL, parent, group, signing, snap, principal,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn try_register_full(
    pool: &PgPool,
    role: &str,
    id: &Identity,
    model: &str,
    parent: Option<Uuid>,
    group: &str,
    signing: Option<Vec<u8>>,
    snap: Value,
    principal: Option<String>,
) -> Result<Registered, sqlx::Error> {
    let pubkey = id.pubkey.clone();
    let hash = id.prompt_hash.clone();
    let group = group.to_string();
    let model = model.to_string();
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
        .bind(&model)
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
/// it is a maintenance-owned definer pinned to a search_path. No other role can
/// act as it, and the only privilege granted to it BY NAME, on any function or
/// relation in `public`, is that EXECUTE plus, since migration 166, EXECUTE on
/// `epigraph_role_agent_may_run` (a catalog sweep, not a hand list).
///
/// NOLOGIN is pinned in the migration TEXT, not on the role: the role is
/// cluster-wide and operations give it LOGIN on any cluster where the host
/// registers (review TC9), which must not turn this test red there.
#[sqlx::test(migrations = "../../migrations")]
async fn the_attestor_role_holds_registration_and_nothing_else_it_could_abuse(pool: PgPool) {
    assert!(
        include_str!("../../../migrations/161_agent_identity_lineage.sql")
            .contains("CREATE ROLE epigraph_identity_attestor NOLOGIN;"),
        "the migration must create the attestor NOLOGIN"
    );
    let (sup, createrole, createdb, bypass, repl): (bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication \
               FROM pg_roles WHERE rolname = $1",
    )
    .bind(ATTESTOR)
    .fetch_one(&pool)
    .await
    .expect("the attestor role exists");
    assert!(!(sup || createrole || createdb || bypass || repl));

    // Nobody can act as the attestor (161's own fault list, which the
    // migration also enforces), and it is a member of nothing.
    let faults: Vec<String> =
        sqlx::query_scalar("SELECT public.epigraph_identity_attestor_faults()")
            .fetch_one(&pool)
            .await
            .expect("faults");
    assert!(faults.is_empty(), "{faults:?}");

    // Every privilege granted to the attestor by name, swept from the catalog.
    let granted: Vec<String> = sqlx::query_scalar(
        "SELECT p.oid::regprocedure::text || ' ' || a.privilege_type \
           FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a \
          WHERE p.pronamespace = 'public'::regnamespace \
            AND a.grantee = (SELECT oid FROM pg_roles WHERE rolname = $1) \
         UNION ALL \
         SELECT c.oid::regclass::text || ' ' || a.privilege_type \
           FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a \
          WHERE c.relnamespace = 'public'::regnamespace \
            AND a.grantee = (SELECT oid FROM pg_roles WHERE rolname = $1) \
         ORDER BY 1",
    )
    .bind(ATTESTOR)
    .fetch_all(&pool)
    .await
    .expect("the attestor's grants");
    assert_eq!(
        granted,
        vec![
            "epigraph_register_agent_identity(bytea,uuid,text,text,text,bytea,jsonb) EXECUTE"
                .to_string(),
            // Migration 166: the host asks whether a role-attached identity may
            // run before it starts one. A read that answers one agent at a
            // time, never the roster.
            "epigraph_role_agent_may_run(uuid) EXECUTE".to_string(),
        ],
        "the attestor holds exactly the registration and the role-agent question"
    );

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
        ("public.epigraph_role_agent_may_run(uuid)", true, true),
        (
            "public.epigraph_role_agent_gate(uuid, timestamp with time zone)",
            false,
            false,
        ),
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
    assert!(r.link_live, "the inherited link is live");
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
        assert!(!r.link_live, "{reason}: the child cannot write");
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
    let props: Value = sqlx::query_scalar("SELECT properties FROM agents WHERE id = $1")
        .bind(quiet_id)
        .fetch_one(&pool)
        .await
        .expect("adopted properties");
    assert_eq!(
        props["llm_model"],
        json!(MODEL),
        "adoption records the model"
    );
    assert_eq!(props["llm_prompt_hash"], json!(quiet.prompt_hash));

    // CALIBRATION 2: registered earlier, then wrote claims, re-registers.
    let ours = new_identity();
    let first = register(&pool, &ours, None, "g-new", snapshot("g v1", "l")).await;
    fixture::seed_public_claim(&pool, first.agent_id, "a claim by a registered agent").await;
    let again = register(&pool, &ours, None, "g-new", snapshot("g v2", "l")).await;
    assert_eq!(again.agent_id, first.agent_id);
    assert!(again.snapshot_created);
}

/// AID09: an existing agent that has authored nothing but is ALREADY BOUND to
/// something is not EpiClaw's to adopt. Adoption would overwrite its
/// properties, bind a signing key and inherit an operator link onto it. Each
/// binding is refused on its own, and each refusal changes nothing:
///
/// * a registered human operator;
/// * the agent side of an operator link;
/// * an OAuth client's principal;
/// * an agent that already holds an active signing key;
/// * a member of any group other than its own personal group;
/// * an agent that ever held a non-legacy key (a rotated signing key).
///
/// The rule fails closed: adoption is allowed only for a FRESH agent.
/// CALIBRATION: `adopting_an_agent_with_claims_and_no_registration_is_refused_aid05`
/// keeps a claimless, unbound software agent adoptable.
#[sqlx::test(migrations = "../../migrations")]
async fn adopting_a_bound_agent_is_refused_aid09(pool: PgPool) {
    async fn bare(pool: &PgPool, id: &Identity) -> Uuid {
        let aid = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'software_agent')",
        )
        .bind(aid)
        .bind(&id.pubkey)
        .execute(pool)
        .await
        .expect("seed a claimless agent");
        aid
    }

    // A registered human operator, presented under its own public key.
    let human_id = human_operator(&pool).await;
    let human_key: Vec<u8> = sqlx::query_scalar("SELECT public_key FROM agents WHERE id = $1")
        .bind(human_id)
        .fetch_one(&pool)
        .await
        .expect("the human's key");
    let human = Identity {
        prompt_hash: blake3::hash(&human_key).to_hex().to_string(),
        signing: random32(),
        pubkey: human_key,
    };

    // The agent side of an operator link.
    let operated = new_identity();
    let operated_id = bare(&pool, &operated).await;
    let op = human_operator(&pool).await;
    link(&pool, operated_id, op).await;

    // An OAuth client's principal.
    let client = new_identity();
    let client_id = bare(&pool, &client).await;
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, agent_id, \
                                    allowed_scopes, granted_scopes, status) \
         VALUES ($1, 'aid09 client', 'human', $2, ARRAY['claims:read'], \
                 ARRAY['claims:read'], 'active')",
    )
    .bind(format!("aid09-{}", Uuid::new_v4()))
    .bind(client_id)
    .execute(&pool)
    .await
    .expect("seed an OAuth client principal");

    // An agent that already holds an active signing key.
    let keyed = new_identity();
    let keyed_id = bare(&pool, &keyed).await;
    sqlx::query(
        "INSERT INTO agent_keys (agent_id, public_key, key_type, status) \
         VALUES ($1, $2, 'signing', 'active')",
    )
    .bind(keyed_id)
    .bind(random32())
    .execute(&pool)
    .await
    .expect("seed an active signing key");

    // A member of a group that is not its own personal group.
    let member = new_identity();
    let member_id = bare(&pool, &member).await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(fixture::seed_group(&pool).await)
    .bind(member_id)
    .execute(&pool)
    .await
    .expect("seed a non-personal membership");

    // An agent that once held a signing key, now rotated (any status counts).
    let retired = new_identity();
    let retired_id = bare(&pool, &retired).await;
    sqlx::query(
        "INSERT INTO agent_keys (agent_id, public_key, key_type, status) \
         VALUES ($1, $2, 'signing', 'rotated')",
    )
    .bind(retired_id)
    .bind(random32())
    .execute(&pool)
    .await
    .expect("seed a rotated signing key");

    for (what, id) in [
        ("a registered human operator", &human),
        ("an operated agent", &operated),
        ("an OAuth client principal", &client),
        ("an agent with an active signing key", &keyed),
        ("a member of a non-personal group", &member),
        ("an agent with a rotated signing key", &retired),
    ] {
        let before = footprint(&pool).await;
        let err = try_register(&pool, id, None, "g-aid09", snapshot("g", "l"))
            .await
            .expect_err(what);
        assert_eq!(sqlstate(&err).as_deref(), Some("AID09"), "{what}: {err}");
        assert_eq!(
            footprint(&pool).await,
            before,
            "{what}: AID09 changes nothing"
        );
    }

    // CALIBRATION: an agent whose only binding is its OWN personal group (the
    // shape epigraph-mcp creates when it meets an identity before the host
    // has registered it) is fresh, and adoptable.
    let fresh = new_identity();
    let fresh_id = bare(&pool, &fresh).await;
    sqlx::query("SELECT public.epigraph_ensure_personal_group($1)")
        .bind(fresh_id)
        .execute(&pool)
        .await
        .expect("its own personal group");
    let adopted = register(&pool, &fresh, None, "g-aid09", snapshot("g", "l")).await;
    assert_eq!(adopted.agent_id, fresh_id);
    assert!(!adopted.agent_created);
}

/// AID09 is a GENERIC scan, not a list: an agent referenced by ANY foreign
/// key into `agents` (other than its genuine personal group, that group's
/// membership, its legacy key and audit rows) is not fresh. These bindings
/// appear in no hand-written list. Each is refused AID09 and changes nothing:
///
/// * an instance admin, a row that predates migration 123 (a row-security table);
/// * a perspective's owner (a row-security table);
/// * an `agent_capabilities` row;
/// * a member of a group whose `did_key` spells its personal key but which is
///   NOT a personal group (a forged "personal" group).
#[sqlx::test(migrations = "../../migrations")]
async fn aid09_refuses_any_foreign_key_binding_not_only_listed_ones(pool: PgPool) {
    async fn bare(pool: &PgPool, id: &Identity) -> Uuid {
        let aid = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'software_agent')",
        )
        .bind(aid)
        .bind(&id.pubkey)
        .execute(pool)
        .await
        .expect("seed a claimless agent");
        aid
    }

    let admin = new_identity();
    let admin_id = bare(&pool, &admin).await;
    // `instance_admins` is frozen since migration 123 (CUS05), so a row can
    // only be one that predates it: planted with triggers off.
    {
        let mut tx = pool.begin().await.expect("begin");
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *tx)
            .await
            .expect("replica");
        sqlx::query("INSERT INTO instance_admins (agent_id, note) VALUES ($1, 'aid09 test')")
            .bind(admin_id)
            .execute(&mut *tx)
            .await
            .expect("plant a pre-123 instance admin");
        tx.commit().await.expect("commit");
    }

    let owner = new_identity();
    let owner_id = bare(&pool, &owner).await;
    sqlx::query("INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2)")
        .bind(format!("aid09-{}", Uuid::new_v4()))
        .bind(owner_id)
        .execute(&pool)
        .await
        .expect("seed a perspective owner");

    let capable = new_identity();
    let capable_id = bare(&pool, &capable).await;
    sqlx::query("INSERT INTO agent_capabilities (agent_id) VALUES ($1)")
        .bind(capable_id)
        .execute(&pool)
        .await
        .expect("seed agent capabilities");

    let forged = new_identity();
    let forged_id = bare(&pool, &forged).await;
    let team: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind) \
         VALUES ('forged personal', 'did:epigraph:personal:' || $1::text, \
                 sha256(gen_random_uuid()::text::bytea), 'team') RETURNING id",
    )
    .bind(forged_id)
    .fetch_one(&pool)
    .await
    .expect("seed a team group spelled like a personal group");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'admin')",
    )
    .bind(team)
    .bind(forged_id)
    .execute(&pool)
    .await
    .expect("seed a membership in the forged group");

    for (what, id) in [
        ("an instance admin", &admin),
        ("a perspective owner", &owner),
        ("an agent with capabilities", &capable),
        ("a member of a forged personal group", &forged),
    ] {
        let before = footprint(&pool).await;
        let err = try_register(&pool, id, None, "g-aid09-generic", snapshot("g", "l"))
            .await
            .expect_err(what);
        assert_eq!(sqlstate(&err).as_deref(), Some("AID09"), "{what}: {err}");
        assert_eq!(
            footprint(&pool).await,
            before,
            "{what}: AID09 changes nothing"
        );
    }
}

/// AID03: the parent must be an LLM agent (a derived identity, or one whose
/// properties carry `llm_model`) and must not be a human. Each arm of the
/// refusal is driven by a parent that ONLY that arm catches (review TC4), and
/// each refusal changes nothing:
///
/// * a plain `ed25519` software agent with no `llm_model` (the LLM arm);
/// * a REGISTERED human operator whose key is `derived` (a keyless OAuth
///   human) and whose `agent_type` is not `human` (the human-operator arm);
/// * an `agent_type 'human'` agent with a `derived` key that is not a
///   registered operator (the agent-type arm).
///
/// CALIBRATIONS: an `ed25519` agent carrying `llm_model` (the shape
/// epigraph-mcp's legacy path creates) and a registered (derived) identity are
/// both accepted as parents.
#[sqlx::test(migrations = "../../migrations")]
async fn a_parent_that_is_not_an_llm_agent_is_refused_aid03(pool: PgPool) {
    let seed = |agent_type: &'static str, kind: &'static str| {
        let pool = pool.clone();
        async move {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO agents (id, public_key, agent_type, key_kind) VALUES ($1, $2, $3, $4)",
            )
            .bind(id)
            .bind(random32())
            .bind(agent_type)
            .bind(kind)
            .execute(&pool)
            .await
            .expect("seed parent");
            id
        }
    };
    let plain = seed("software_agent", "ed25519").await;
    let keyless_operator = seed("system", "derived").await;
    fixture::make_human_operator(&pool, keyless_operator).await;
    let human_typed = seed("human", "derived").await;

    for (parent, what) in [
        (plain, "an ed25519 software agent with no llm_model"),
        (
            keyless_operator,
            "a registered human operator with a derived key",
        ),
        (
            human_typed,
            "an agent_type 'human' agent with a derived key",
        ),
    ] {
        let before = footprint(&pool).await;
        let err = try_register(
            &pool,
            &new_identity(),
            Some(parent),
            "g-h",
            snapshot("g", "l"),
        )
        .await
        .expect_err(what);
        assert_eq!(sqlstate(&err).as_deref(), Some("AID03"), "{what}: {err}");
        assert_eq!(
            footprint(&pool).await,
            before,
            "{what}: AID03 changes nothing"
        );
    }

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

    // The other arm: the same key and prompt hash under another MODEL.
    let err = try_register_full(
        &pool,
        ATTESTOR,
        &id,
        "test-model-2",
        None,
        "g-m",
        Some(id.signing.clone()),
        snapshot("g", "l"),
        None,
    )
    .await
    .expect_err("a different model for the same key must be refused");
    assert_eq!(sqlstate(&err).as_deref(), Some("22023"), "{err}");
    assert_eq!(footprint(&pool).await, before);
}

// ─────────────────────────────────────────────────────────────────────────────
// Signing keys (D2) and stored blobs (D4).
// ─────────────────────────────────────────────────────────────────────────────

/// The signing key is bound once per agent as an active `signing` key. The same
/// key again is a no-op; a DIFFERENT key while one is active is refused AID08
/// and changes nothing (the host must be told, not answered "not registered":
/// review TC1/CR1); a key already bound to another agent is refused; a revoked
/// key is never bound again, while a new key after the revoke is; and the
/// identity key itself can never be the signing key.
#[sqlx::test(migrations = "../../migrations")]
async fn the_signing_key_is_bound_once_and_a_different_one_is_refused_aid08(pool: PgPool) {
    let id = new_identity();
    let key = random32();
    let register_with = |k: Vec<u8>, group: &'static str, learned: &'static str| {
        let pool = pool.clone();
        let id = Identity {
            pubkey: id.pubkey.clone(),
            prompt_hash: id.prompt_hash.clone(),
            signing: k.clone(),
        };
        async move {
            try_register_as(
                &pool,
                ATTESTOR,
                &id,
                None,
                group,
                Some(k),
                snapshot("g", learned),
                None,
            )
            .await
        }
    };
    let r = register_with(key.clone(), "g-k", "l")
        .await
        .expect("first registration");
    assert!(r.signing_key_registered);

    let same = register_with(key.clone(), "g-k", "l2")
        .await
        .expect("CALIBRATION: the same key again registers");
    assert!(
        !same.signing_key_registered,
        "the same key is already bound"
    );

    let before = footprint(&pool).await;
    let err = register_with(random32(), "g-k", "l3")
        .await
        .expect_err("a different signing key while one is active must be refused");
    assert_eq!(sqlstate(&err).as_deref(), Some("AID08"), "{err}");
    assert_eq!(footprint(&pool).await, before, "AID08 changes nothing");

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
        Some(key.clone()),
        snapshot("g", "l"),
        None,
    )
    .await
    .expect_err("a signing key bound to another agent must be refused");
    assert_eq!(sqlstate(&err).as_deref(), Some("22023"), "{err}");

    // The operations path: the maintenance session revokes the bound key.
    let kid: Uuid = sqlx::query_scalar(
        "SELECT id FROM agent_keys WHERE agent_id = $1 AND key_type = 'signing'",
    )
    .bind(r.agent_id)
    .fetch_one(&pool)
    .await
    .expect("key id");
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query(
            "SELECT * FROM public.epigraph_agent_key_set_status($1, 'revoked', 'test', NULL)",
        )
        .bind(kid)
        .execute(&mut *conn)
        .await;
        (conn, r)
    })
    .await
    .expect("the maintenance role revokes a bound signing key");
    let err = register_with(key, "g-k", "l4")
        .await
        .expect_err("a revoked signing key is never bound again");
    assert_eq!(sqlstate(&err).as_deref(), Some("22023"), "{err}");
    let fresh = register_with(random32(), "g-k", "l5")
        .await
        .expect("CALIBRATION: a new key after the revoke is bound");
    assert!(fresh.signing_key_registered);

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

    // An agent whose current public key was already retired in agent_keys
    // (rotated) and one whose key was revoked: the backfill must not re-mint
    // either as an ACTIVE legacy key.
    let mut retired = Vec::new();
    for status in ["rotated", "revoked"] {
        let id = Uuid::new_v4();
        let key = random32();
        sqlx::query(
            "INSERT INTO agents (id, public_key, agent_type, key_kind) VALUES ($1, $2, 'software_agent', 'ed25519')",
        )
        .bind(id)
        .bind(&key)
        .execute(&pool)
        .await
        .expect("seed agent with a retired key");
        sqlx::query(
            "INSERT INTO agent_keys (agent_id, public_key, key_type, status) VALUES ($1, $2, 'signing', $3)",
        )
        .bind(id)
        .bind(&key)
        .bind(status)
        .execute(&pool)
        .await
        .expect("seed the retired key row");
        retired.push((id, status));
    }

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

    for (id, status) in &retired {
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM agent_keys \
              WHERE agent_id = $1 AND key_type = 'identity-legacy' AND status = 'active'",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("legacy rows of a retired key");
        assert_eq!(
            active, 0,
            "a key already {status} in agent_keys must not come back as an active legacy key"
        );
    }

    let retired_ids: Vec<Uuid> = retired.iter().map(|(id, _)| *id).collect();
    let without: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agents a WHERE a.id <> ALL($1) AND NOT EXISTS (\
           SELECT 1 FROM agent_keys k WHERE k.agent_id = a.id AND k.key_type = 'identity-legacy')",
    )
    .bind(&retired_ids)
    .fetch_one(&pool)
    .await
    .expect("agents without a legacy key");
    assert_eq!(
        without, 0,
        "every other pre-existing agent must have its legacy key row"
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

// ─────────────────────────────────────────────────────────────────────────────
// Council review of the first cut (PR #661): attested keys (TC1/CR1, CR2, CR4b).
// ─────────────────────────────────────────────────────────────────────────────

/// Run `f` as `epigraph_app` stamped as `principal` with `groups` as both its
/// readable and writable set: what a container holding the application DSN
/// can claim to be.
async fn as_app_stamped<F, Fut, T>(pool: &PgPool, principal: Uuid, groups: &[Uuid], f: F) -> T
where
    F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
    Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, T)>,
{
    let set = groups
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.group_ids', $2, false), \
                    set_config('epigraph.writable_group_ids', $2, false)",
        )
        .bind(principal.to_string())
        .bind(&set)
        .execute(&mut *conn)
        .await
        .expect("stamp");
        let (mut conn, out) = f(conn).await;
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', '', false), \
                    set_config('epigraph.group_ids', '', false), \
                    set_config('epigraph.writable_group_ids', '', false)",
        )
        .execute(&mut *conn)
        .await
        .expect("unstamp");
        (conn, out)
    })
    .await
}

/// An agent seeded on the superuser connection, with no key rows.
async fn plain_agent(pool: &PgPool, agent_type: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(random32())
        .bind(agent_type)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

/// `epigraph_agent_key_set_status(key, status)` on `role`'s session.
async fn set_key_status_as(
    pool: &PgPool,
    role: &str,
    principal: Uuid,
    key: Uuid,
    status: &'static str,
) -> Result<(), sqlx::Error> {
    fixture::as_role(pool, role, |mut conn| async move {
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(principal.to_string())
            .execute(&mut *conn)
            .await
            .expect("stamp");
        let r = sqlx::query(
            "SELECT * FROM public.epigraph_agent_key_set_status($1, $2, 'review test', NULL)",
        )
        .bind(key)
        .bind(status)
        .execute(&mut *conn)
        .await
        .map(|_| ());
        (conn, r)
    })
    .await
}

/// D2: "Agents cannot self-register it." A `signing` key (what S2's
/// verify_claim will bind a claim to) and an `identity-legacy` key are
/// attested state. An application session, stamped as the victim itself,
/// can neither INSERT one for any agent (in any spelling of the type) nor move
/// a bound one through 118's status definer (rotate or revoke); the bound key
/// stays active. CALIBRATIONS: the same session still records and rotates a
/// key of another type (so the refusal is not a blanket loss of INSERT or of
/// the definer), the attestor's registration binds a signing key, and the
/// maintenance session can revoke it (the operations path).
#[sqlx::test(migrations = "../../migrations")]
async fn an_application_session_can_neither_bind_nor_move_an_attested_key(pool: PgPool) {
    let victim = plain_agent(&pool, "software_agent").await;
    let (signing, legacy, spelled, other) =
        as_app_stamped(&pool, victim, &[], |mut conn| async move {
            let ins =
                "INSERT INTO agent_keys (agent_id, public_key, key_type, status, valid_from) \
                       VALUES ($1, $2, $3, 'active', '2020-01-01')";
            let mut out = Vec::new();
            for t in ["signing", "identity-legacy", " Signing", "encryption"] {
                out.push(
                    sqlx::query(ins)
                        .bind(victim)
                        .bind(random32())
                        .bind(t)
                        .execute(&mut *conn)
                        .await
                        .map(|_| ()),
                );
            }
            let other = out.pop().expect("encryption");
            let spelled = out.pop().expect("spelled");
            let legacy = out.pop().expect("legacy");
            let signing = out.pop().expect("signing");
            (conn, (signing, legacy, spelled, other))
        })
        .await;
    other.expect("CALIBRATION: the application role still records a key of another type");
    for (what, r) in [
        ("signing", signing),
        ("identity-legacy", legacy),
        (" Signing", spelled),
    ] {
        let err = r.expect_err("an application session bound an attested key type");
        assert_eq!(
            sqlstate(&err).as_deref(),
            Some(INSUFFICIENT_PRIVILEGE),
            "{what}: {err}"
        );
    }

    // The attested path binds one (positive control for the type itself).
    let id = new_identity();
    let r = register(&pool, &id, None, "g-ak", snapshot("g", "l")).await;
    assert!(r.signing_key_registered);
    sqlx::query(
        "INSERT INTO agent_keys (agent_id, public_key, key_type, status, valid_from) \
         VALUES ($1, $2, 'identity-legacy', 'active', '2020-01-01')",
    )
    .bind(victim)
    .bind(random32())
    .execute(&pool)
    .await
    .expect("seed a legacy key on the harness connection");
    let key_of = |agent: Uuid, t: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM agent_keys WHERE agent_id = $1 AND key_type = $2",
            )
            .bind(agent)
            .bind(t)
            .fetch_one(&pool)
            .await
            .expect("key id")
        }
    };
    let bound = key_of(r.agent_id, "signing").await;
    let legacy_key = key_of(victim, "identity-legacy").await;
    let other_key = key_of(victim, "encryption").await;

    for (key, owner) in [(bound, r.agent_id), (legacy_key, victim)] {
        for status in ["rotated", "revoked"] {
            let err = set_key_status_as(&pool, "epigraph_app", owner, key, status)
                .await
                .expect_err("an application session moved an attested key");
            assert_eq!(
                sqlstate(&err).as_deref(),
                Some(INSUFFICIENT_PRIVILEGE),
                "{status}: {err}"
            );
        }
    }
    set_key_status_as(&pool, "epigraph_app", victim, other_key, "rotated")
        .await
        .expect("CALIBRATION: the application role still rotates a key of another type");
    let statuses: Vec<String> =
        sqlx::query_scalar("SELECT status::text FROM agent_keys WHERE id = ANY($1) ORDER BY id")
            .bind(vec![bound, legacy_key])
            .fetch_all(&pool)
            .await
            .expect("statuses");
    assert_eq!(statuses, vec!["active".to_string(), "active".to_string()]);

    set_key_status_as(&pool, "epigraph_maintenance", victim, bound, "revoked")
        .await
        .expect("CALIBRATION: the maintenance session revokes a bound signing key");
}

/// The rotate route's key lookup (`get_active_key`) returns the agent's active
/// SIGNING key and never its `identity-legacy` key: after 161 every agent has
/// an active legacy row whose private half is often computable from public
/// inputs, and the route rotates whatever this returns (review CR2).
/// CALIBRATION: a registered identity's signing key is found, even when a
/// legacy row is newer.
#[sqlx::test(migrations = "../../migrations")]
async fn the_active_key_lookup_never_returns_a_legacy_identity_key(pool: PgPool) {
    let legacy_only = plain_agent(&pool, "software_agent").await;
    sqlx::query(
        "INSERT INTO agent_keys (agent_id, public_key, key_type, status, valid_from) \
         VALUES ($1, $2, 'identity-legacy', 'active', now())",
    )
    .bind(legacy_only)
    .bind(random32())
    .execute(&pool)
    .await
    .expect("seed a legacy key");
    let got = epigraph_db::AgentKeyRepository::get_active_key(
        &pool,
        epigraph_core::AgentId::from_uuid(legacy_only),
        "signing",
    )
    .await
    .expect("lookup");
    assert!(
        got.is_none(),
        "the lookup returned a {:?} key for an agent with no signing key",
        got.map(|k| k.key_type)
    );

    let id = new_identity();
    let r = register(&pool, &id, None, "g-lookup", snapshot("g", "l")).await;
    sqlx::query(
        "INSERT INTO agent_keys (agent_id, public_key, key_type, status, valid_from, created_at) \
         VALUES ($1, $2, 'identity-legacy', 'active', now(), now() + interval '1 hour')",
    )
    .bind(r.agent_id)
    .bind(random32())
    .execute(&pool)
    .await
    .expect("seed a NEWER legacy key on the registered identity");
    let got = epigraph_db::AgentKeyRepository::get_active_key(
        &pool,
        epigraph_core::AgentId::from_uuid(r.agent_id),
        "signing",
    )
    .await
    .expect("lookup")
    .expect("the registered identity's signing key");
    assert_eq!(got.key_type, "signing");
    assert_eq!(got.public_key, id.signing);
}

/// A container that learns an identity's signing public key (it is on every
/// claim the identity signs) and records it as a key of its own, of a type the
/// application may still write, must not stop the host re-registering that
/// identity with its own key (review CR4b). CALIBRATION: the squat itself
/// lands, so the re-registration is not passing because nothing was planted.
#[sqlx::test(migrations = "../../migrations")]
async fn a_squatted_signing_key_does_not_block_re_registration(pool: PgPool) {
    let id = new_identity();
    let first = register(&pool, &id, None, "g-squat", snapshot("g v1", "l")).await;
    let squatter = plain_agent(&pool, "software_agent").await;
    let signing = id.signing.clone();
    as_app_stamped(&pool, squatter, &[], |mut conn| async move {
        sqlx::query(
            "INSERT INTO agent_keys (agent_id, public_key, key_type, status) \
             VALUES ($1, $2, 'encryption', 'active')",
        )
        .bind(squatter)
        .bind(&signing)
        .execute(&mut *conn)
        .await
        .expect("CALIBRATION: the squat lands");
        (conn, ())
    })
    .await;
    let again = try_register(&pool, &id, None, "g-squat", snapshot("g v2", "l"))
        .await
        .expect("a squatted copy of the bound key must not block the identity's own host");
    assert_eq!(again.agent_id, first.agent_id);
    assert!(again.snapshot_created);
}

// ─────────────────────────────────────────────────────────────────────────────
// Council review: what a registration inherits and reports (CR3, CR4a, CR4c,
// CR8/TC10).
// ─────────────────────────────────────────────────────────────────────────────

/// `(inherited, link_live, inherit_reason, operator_id)` of one attestor
/// registration, read by NAME so a result that lacks a column fails here.
async fn register_outcome(
    pool: &PgPool,
    id: &Identity,
    parent: Option<Uuid>,
    group: &str,
    snap: Value,
) -> (bool, bool, Option<String>, Option<Uuid>) {
    let (pubkey, hash, signing, group) = (
        id.pubkey.clone(),
        id.prompt_hash.clone(),
        id.signing.clone(),
        group.to_string(),
    );
    fixture::as_role(pool, ATTESTOR, |mut conn| async move {
        let r = sqlx::query_as(
            "SELECT inherited, link_live, inherit_reason, operator_id \
               FROM public.epigraph_register_agent_identity($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&pubkey)
        .bind(parent)
        .bind(MODEL)
        .bind(&hash)
        .bind(&group)
        .bind(&signing)
        .bind(&snap)
        .fetch_one(&mut *conn)
        .await;
        (conn, r)
    })
    .await
    .expect("the attestor registers")
}

/// One identity is shared by every group with the same model and files (the
/// empty-files identity of a fresh group above all). An identity that is
/// UNLINKED and already runs in another group must not take the operator of
/// whichever group's parent names it first: a container controls its own
/// LEARNED.md, so it controls which shared identity its group runs next, and
/// every other group running that identity would then write as that operator
/// (review CR3). The lineage is still recorded; the link is left to a manual
/// act. CALIBRATIONS: an identity with no other group inherits from the same
/// parent, and an identity that inherited in its first group says
/// `already_linked` in its second.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unlinked_identity_running_in_another_group_inherits_nothing(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let parent = live_linked_parent(&pool, operator, "g-own").await;

    let shared = new_identity();
    let fresh_group = register(&pool, &shared, None, "g-fresh", snapshot("template", "")).await;
    assert_eq!(fresh_group.inherit_reason.as_deref(), Some("no_parent"));

    let r = register(
        &pool,
        &shared,
        Some(parent),
        "g-own",
        snapshot("template", ""),
    )
    .await;
    assert!(r.succession_created, "the lineage is still recorded");
    assert!(!r.inherited, "a shared unlinked identity must not inherit");
    assert_eq!(r.inherit_reason.as_deref(), Some("shared_identity"));
    assert_eq!(r.operator_id, None);
    assert_eq!(human_of(&pool, r.agent_id, false).await, None);

    let solo = register(
        &pool,
        &new_identity(),
        Some(parent),
        "g-own",
        snapshot("t", "x"),
    )
    .await;
    assert!(
        solo.inherited,
        "CALIBRATION: an identity with no other group inherits"
    );

    let first = new_identity();
    let a = register(&pool, &first, Some(parent), "g-own", snapshot("t", "y")).await;
    assert!(a.inherited);
    let b = register(&pool, &first, Some(parent), "g-other", snapshot("t", "y")).await;
    assert_eq!(b.inherit_reason.as_deref(), Some("already_linked"));
    assert_eq!(b.operator_id, Some(operator));
}

/// `agents.properties` is application-writable on the agent's own row (118's
/// column grant, 077's `agents_self_update`), and the principal is a variable
/// any login can set. So a container that rewrites an identity's recorded
/// model must neither block the host's next registration of it (every group
/// running it would fail to start) nor change what the identity is: the
/// registration compares against the snapshots it alone writes and re-asserts
/// the properties (review CR4a). CALIBRATION: the rewrite lands.
#[sqlx::test(migrations = "../../migrations")]
async fn rewriting_an_identitys_properties_neither_blocks_nor_redefines_it(pool: PgPool) {
    let id = new_identity();
    let r = register(&pool, &id, None, "g-props", snapshot("g", "l")).await;
    let agent = r.agent_id;
    let rewritten = as_app_stamped(&pool, agent, &[], |mut conn| async move {
        let n = sqlx::query(
            "UPDATE agents SET properties = properties || \
                    jsonb_build_object('llm_model', 'forged-model', 'llm_prompt_hash', $2::text) \
              WHERE id = $1",
        )
        .bind(agent)
        .bind("0".repeat(64))
        .execute(&mut *conn)
        .await
        .expect("an application session rewrites its own properties")
        .rows_affected();
        (conn, n)
    })
    .await;
    assert_eq!(rewritten, 1, "CALIBRATION: the rewrite lands");

    let again = try_register(&pool, &id, None, "g-props", snapshot("g", "l2"))
        .await
        .expect("a rewritten properties document must not block the host");
    assert_eq!(again.agent_id, agent);
    let props: Value = sqlx::query_scalar("SELECT properties FROM agents WHERE id = $1")
        .bind(agent)
        .fetch_one(&pool)
        .await
        .expect("properties");
    assert_eq!(props["llm_model"], json!(MODEL));
    assert_eq!(props["llm_prompt_hash"], json!(id.prompt_hash));
}

/// OPERATED_BY edges are writable by any application session (122's own
/// comment), and two of them from one agent are 107's shared-signer
/// fingerprint, which the link body refuses with 55000. A container that
/// forges that fingerprint on an unlinked identity must not abort the host's
/// registration of it (the group could not start): the registration records
/// the identity, inherits nothing and says why (review CR4c). CALIBRATION:
/// the forged edges land.
#[sqlx::test(migrations = "../../migrations")]
async fn a_forged_shared_signer_fingerprint_does_not_abort_registration(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let parent = live_linked_parent(&pool, operator, "g-fp").await;
    let x = new_identity();
    let first = register(&pool, &x, None, "g-fp", snapshot("g", "l1")).await;
    let (forger, forger_group) = fixture::seed_agent_with_group(&pool, "forger").await;
    let (p1, p2) = (
        plain_agent(&pool, "system").await,
        plain_agent(&pool, "system").await,
    );
    let target = first.agent_id;
    as_app_stamped(&pool, forger, &[forger_group], |mut conn| async move {
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
             VALUES ($1, 'agent', $2, 'agent', 'OPERATED_BY'), \
                    ($1, 'agent', $3, 'agent', 'OPERATED_BY')",
        )
        .bind(target)
        .bind(p1)
        .bind(p2)
        .execute(&mut *conn)
        .await
        .expect("CALIBRATION: an application session writes the forged edges");
        (conn, ())
    })
    .await;

    let r = try_register(&pool, &x, Some(parent), "g-fp", snapshot("g", "l2"))
        .await
        .expect("forged edges must not abort the host's registration");
    assert!(r.snapshot_created && r.succession_created);
    assert!(!r.inherited);
    assert_eq!(r.inherit_reason.as_deref(), Some("link_refused"));
    assert_eq!(human_of(&pool, r.agent_id, false).await, None);
}

/// The result says whether the child can write afterwards (`link_live`), and a
/// child whose own link to the parent's operator is RETIRED is reported as
/// such, not as `already_linked` (review TC10/CR8): the host alerts on it,
/// because the identity will fail at boot. CALIBRATION: a live-linked child
/// of the same operator is `already_linked` with `link_live`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_child_whose_own_link_is_retired_is_reported_retired(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let parent = live_linked_parent(&pool, operator, "g-ret").await;
    let child = new_identity();
    let c = register(&pool, &child, None, "g-ret", snapshot("g", "l")).await;
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_retired_agent(&mut conn, c.agent_id, operator).await;
        (conn, r)
    })
    .await
    .expect("retire-link the child to the same operator");

    let (inherited, live, reason, op) =
        register_outcome(&pool, &child, Some(parent), "g-ret", snapshot("g", "l2")).await;
    assert!(!inherited);
    assert!(!live, "a retired link cannot write");
    assert_eq!(reason.as_deref(), Some("child_link_retired"));
    assert_eq!(op, Some(operator));

    let sibling = new_identity();
    let s = register(&pool, &sibling, None, "g-ret2", snapshot("g", "s")).await;
    link(&pool, s.agent_id, operator).await;
    let (inherited, live, reason, _) =
        register_outcome(&pool, &sibling, Some(parent), "g-ret2", snapshot("g", "s2")).await;
    assert!(!inherited);
    assert!(live, "CALIBRATION: a live-linked child can write");
    assert_eq!(reason.as_deref(), Some("already_linked"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Council review: the lineage walk is linear in the lineage (TC2/CR5).
// ─────────────────────────────────────────────────────────────────────────────

/// One identity shared by many groups is the design's own case: every group
/// with the same files is one agent. A lineage of `GENERATIONS` identities,
/// each registered in all `GROUPS` groups with the previous one as its parent,
/// has `GROUPS` succession rows per hop. The history read must expand each
/// lineage member ONCE: one row per (member, snapshot), inside a statement
/// timeout. A walk over paths instead of members materialises
/// GROUPS^(GENERATIONS-1) rows first (review TC2/CR5). Read as the maintenance
/// session, so the read gate and link inheritance play no part.
#[sqlx::test(migrations = "../../migrations")]
async fn history_over_a_lineage_shared_by_many_groups_stays_linear(pool: PgPool) {
    const GROUPS: usize = 10;
    const GENERATIONS: usize = 8;
    let groups: Vec<String> = (0..GROUPS).map(|g| format!("g-wide-{g}")).collect();
    let mut lineage: Vec<Uuid> = Vec::new();
    for gen in 0..GENERATIONS {
        let id = new_identity();
        let parent = lineage.last().copied();
        let mut agent = None;
        for g in &groups {
            let r = register(&pool, &id, parent, g, snapshot(g, &format!("gen {gen}"))).await;
            agent = Some(r.agent_id);
        }
        lineage.push(agent.expect("registered"));
    }
    let newest = *lineage.last().expect("newest");

    let rows = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SET statement_timeout = '3s'")
            .execute(&mut *conn)
            .await
            .expect("timeout");
        let r: Result<Vec<(Uuid, i32, Option<Uuid>)>, sqlx::Error> = sqlx::query_as(
            "SELECT agent_id, depth, snapshot_id FROM public.epigraph_agent_prompt_history($1)",
        )
        .bind(newest)
        .fetch_all(&mut *conn)
        .await;
        sqlx::query("RESET statement_timeout")
            .execute(&mut *conn)
            .await
            .expect("reset");
        (conn, r)
    })
    .await
    .expect("the history of a wide lineage reads inside the timeout");

    assert_eq!(
        rows.len(),
        GROUPS * GENERATIONS,
        "one row per (lineage member, snapshot)"
    );
    let distinct: std::collections::BTreeSet<(Uuid, Option<Uuid>)> =
        rows.iter().map(|(a, _, s)| (*a, *s)).collect();
    assert_eq!(distinct.len(), rows.len(), "no (member, snapshot) twice");
    for (i, agent) in lineage.iter().enumerate() {
        let want = i as i32 - (GENERATIONS as i32 - 1);
        assert!(
            rows.iter()
                .filter(|(a, _, _)| a == agent)
                .all(|(_, d, _)| *d == want),
            "generation {i} must sit at depth {want}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Council review: the legacy backfill is re-runnable (CR6).
// ─────────────────────────────────────────────────────────────────────────────

/// D2 keeps a claim signed before cut-over bound to its author's legacy key.
/// The fleet keeps minting unkeyed identities between this migration and the
/// cut-over, so the backfill must be re-runnable (review CR6): a maintenance
/// call gives every agent with no legacy row one (its current public key,
/// valid from its creation, open-ended), skips a host-registered identity
/// (whose identity key never signs, D1), and a second call adds nothing.
/// The application role cannot run it.
#[sqlx::test(migrations = "../../migrations")]
async fn the_legacy_key_backfill_reruns_for_agents_created_after_161(pool: PgPool) {
    let late = plain_agent(&pool, "software_agent").await;
    let registered = register(&pool, &new_identity(), None, "g-late", snapshot("g", "l")).await;

    let run = |role: &'static str| {
        let pool = pool.clone();
        async move {
            fixture::as_role(&pool, role, |mut conn| async move {
                let r: Result<i32, sqlx::Error> =
                    sqlx::query_scalar("SELECT public.epigraph_backfill_legacy_agent_keys()")
                        .fetch_one(&mut *conn)
                        .await;
                (conn, r)
            })
            .await
        }
    };
    let err = run("epigraph_app")
        .await
        .expect_err("the application role ran the legacy backfill");
    assert_eq!(
        sqlstate(&err).as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "{err}"
    );

    let added = run("epigraph_maintenance")
        .await
        .expect("maintenance backfills");
    assert!(added >= 1, "the late agent gets its row");
    let rows: Vec<(Vec<u8>, String, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as(
        "SELECT k.public_key, k.status::text, k.valid_until FROM agent_keys k \
          WHERE k.agent_id = $1 AND k.key_type = 'identity-legacy'",
    )
    .bind(late)
    .fetch_all(&pool)
    .await
    .expect("legacy rows");
    let pk: Vec<u8> = sqlx::query_scalar("SELECT public_key FROM agents WHERE id = $1")
        .bind(late)
        .fetch_one(&pool)
        .await
        .expect("pk");
    assert_eq!(rows, vec![(pk, "active".to_string(), None)]);
    let reg_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent_keys WHERE agent_id = $1 AND key_type = 'identity-legacy'",
    )
    .bind(registered.agent_id)
    .fetch_one(&pool)
    .await
    .expect("registered identity's legacy rows");
    assert_eq!(reg_rows, 0, "a host-registered identity key never signs");

    let again = run("epigraph_maintenance").await.expect("re-run");
    assert_eq!(again, 0, "a re-run adds nothing");
}

// ─────────────────────────────────────────────────────────────────────────────
// Council review: TRUNCATE is refused too (CR9).
// ─────────────────────────────────────────────────────────────────────────────

/// Row triggers do not fire on TRUNCATE, so "append-only for every role" held
/// only for UPDATE and DELETE: the owner or a superuser could TRUNCATE ...
/// CASCADE all three lineage tables at once (review CR9). Each is refused with
/// the guard's 55000, alone and cascaded. CALIBRATION: the rows are there
/// before and after.
#[sqlx::test(migrations = "../../migrations")]
async fn no_role_can_truncate_the_lineage_tables(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let parent = live_linked_parent(&pool, operator, "g-t").await;
    register(
        &pool,
        &new_identity(),
        Some(parent),
        "g-t",
        snapshot("g", "l"),
    )
    .await;
    let counts = |pool: PgPool| async move {
        sqlx::query_as::<_, (i64, i64, i64)>(
            "SELECT (SELECT count(*) FROM agent_prompt_blobs), \
                    (SELECT count(*) FROM agent_prompt_snapshots), \
                    (SELECT count(*) FROM agent_succession)",
        )
        .fetch_one(&pool)
        .await
        .expect("counts")
    };
    let before = counts(pool.clone()).await;
    assert!(
        before.0 > 0 && before.1 > 0 && before.2 > 0,
        "CALIBRATION: rows exist"
    );
    for stmt in [
        "TRUNCATE agent_succession",
        "TRUNCATE agent_prompt_snapshots CASCADE",
        "TRUNCATE agent_prompt_blobs CASCADE",
    ] {
        let err = sqlx::query(stmt)
            .execute(&pool)
            .await
            .expect_err("a superuser truncated a lineage table");
        assert_eq!(sqlstate(&err).as_deref(), Some("55000"), "{stmt}: {err}");
    }
    assert_eq!(counts(pool.clone()).await, before);
}

// ─────────────────────────────────────────────────────────────────────────────
// Council review: a pre-provisioned attestor is validated (CR10, TC8).
// ─────────────────────────────────────────────────────────────────────────────

/// The attestor role is cluster-wide, so 161 may find it already provisioned
/// and must not accept one that could be abused (review CR10).
/// `epigraph_identity_attestor_faults()` names each way it could be: a role
/// that can act as it (SET or USAGE, superusers aside), a membership of its
/// own, or an elevated attribute. The migration refuses to proceed on any.
/// On a fresh database it names none; with the application role granted the
/// attestor (inside a rolled-back transaction) it names that grant; and as
/// `epigraph_app` the role cannot be assumed (42501).
#[sqlx::test(migrations = "../../migrations")]
async fn a_pre_provisioned_attestor_is_checked_for_isolation(pool: PgPool) {
    let faults: Vec<String> =
        sqlx::query_scalar("SELECT public.epigraph_identity_attestor_faults()")
            .fetch_one(&pool)
            .await
            .expect("faults on a fresh database");
    assert!(
        faults.is_empty(),
        "a fresh attestor has no faults: {faults:?}"
    );

    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("GRANT epigraph_identity_attestor TO epigraph_app")
        .execute(&mut *tx)
        .await
        .expect("grant (rolled back)");
    let faults: Vec<String> =
        sqlx::query_scalar("SELECT public.epigraph_identity_attestor_faults()")
            .fetch_one(&mut *tx)
            .await
            .expect("faults with a member");
    tx.rollback().await.expect("rollback");
    assert!(
        faults.iter().any(|f| f.contains("epigraph_app")),
        "a role that can act as the attestor is a fault: {faults:?}"
    );

    let err = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let r = sqlx::query("SET ROLE epigraph_identity_attestor")
            .execute(&mut *conn)
            .await;
        (conn, r)
    })
    .await
    .expect_err("the application role assumed the attestor");
    assert_eq!(
        sqlstate(&err).as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "{err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Council review: coverage the first cut lacked (TC3, TC5, TC6, and the walk's
// cycle case).
// ─────────────────────────────────────────────────────────────────────────────

/// R5's confidentiality rests on an application session reading no blob,
/// snapshot or succession row DIRECTLY, only through the gated history read
/// (review TC3). Measured at runtime, as `epigraph_app` stamped as the agent's
/// own operator with the operator's group writable (the strongest claim a
/// container can make): every table reads 0 rows and refuses an INSERT with
/// 42501. CALIBRATION: the maintenance session sees rows in all three, and the
/// same stamped session reads the history through the definer.
#[sqlx::test(migrations = "../../migrations")]
async fn an_application_session_reads_and_writes_no_lineage_row_directly(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let parent = live_linked_parent(&pool, operator, "g-direct").await;
    let child = register(
        &pool,
        &new_identity(),
        Some(parent),
        "g-direct",
        snapshot("g", "l"),
    )
    .await;
    let group = operator_group(&pool, operator).await;
    const TABLES: [&str; 3] = [
        "agent_prompt_blobs",
        "agent_prompt_snapshots",
        "agent_succession",
    ];

    let seen = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let mut out = Vec::new();
        for t in TABLES {
            let n: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM public.{t}"))
                .fetch_one(&mut *conn)
                .await
                .expect("maintenance count");
            out.push(n);
        }
        (conn, out)
    })
    .await;
    assert!(
        seen.iter().all(|n| *n > 0),
        "CALIBRATION: rows exist: {seen:?}"
    );

    let (counts, inserts, history) =
        as_app_stamped(&pool, operator, &[group], |mut conn| async move {
            let mut counts = Vec::new();
            for t in TABLES {
                let n: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM public.{t}"))
                    .fetch_one(&mut *conn)
                    .await
                    .expect("app count");
                counts.push(n);
            }
            let snapshot_id = child.snapshot_id;
            let mut inserts = Vec::new();
            for stmt in [
                "INSERT INTO agent_prompt_blobs (blob_hash, codec, raw_size, content) \
                 VALUES (decode(repeat('ab', 32), 'hex'), 'zstd', 0, '\\x28b52ffd00'::bytea)",
                "INSERT INTO agent_prompt_snapshots (agent_id, group_folder, model, prompt_hash, \
                                                    in_prompt) \
                 SELECT $1, 'g-forged', 'm', repeat('a', 64), '{}'::jsonb",
                "INSERT INTO agent_succession (child_agent_id, parent_agent_id, group_folder, \
                                              snapshot_id) \
                 SELECT $1, $2, 'g-forged', $3",
            ] {
                let mut q = sqlx::query(stmt);
                if stmt.contains("$3") {
                    q = q.bind(child.agent_id).bind(parent).bind(snapshot_id);
                } else if stmt.contains("$1") {
                    q = q.bind(child.agent_id);
                }
                inserts.push(q.execute(&mut *conn).await.map(|_| ()));
            }
            let history: Result<i64, sqlx::Error> =
                sqlx::query_scalar("SELECT count(*) FROM public.epigraph_agent_prompt_history($1)")
                    .bind(child.agent_id)
                    .fetch_one(&mut *conn)
                    .await;
            (conn, (counts, inserts, history))
        })
        .await;
    assert_eq!(
        counts,
        vec![0, 0, 0],
        "an application session reads no lineage row"
    );
    for (t, r) in TABLES.iter().zip(inserts) {
        let err = r.expect_err("an application session inserted a lineage row");
        assert_eq!(
            sqlstate(&err).as_deref(),
            Some(INSUFFICIENT_PRIVILEGE),
            "{t}: {err}"
        );
    }
    assert!(
        history.expect("CALIBRATION: the gated read answers the operator") > 0,
        "the operator reads through the definer"
    );
}

/// The history read's admin arm under ARMED admin scopes (129's model): a
/// custodian reads another operator's agent only while ELEVATED; unelevated it
/// is refused AID06 like anyone else (review TC5). CALIBRATIONS: the arming
/// took, the connection's elevation is what the database says it is, and the
/// agent's own operator still reads.
#[sqlx::test(migrations = "../../migrations")]
async fn armed_admin_scopes_admit_an_elevated_custodian_only(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let parent = live_linked_parent(&pool, operator, "g-armed").await;
    let child = register(
        &pool,
        &new_identity(),
        Some(parent),
        "g-armed",
        snapshot("g", "l"),
    )
    .await;
    let custodian = elevation::holder(&pool, "armed custodian", 7).await;
    let live = elevation::session(&pool, &custodian).await;

    let armed: bool = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r: bool = sqlx::query_scalar(
            "SELECT armed FROM public.epigraph_set_admin_scope_enforcement(true, 'lineage test')",
        )
        .fetch_one(&mut *conn)
        .await
        .expect("maintenance arms admin scopes");
        (conn, r)
    })
    .await;
    assert!(armed, "CALIBRATION: admin scopes are armed");

    let read = |elevated: bool| {
        let pool = pool.clone();
        let (person, family) = (custodian.person, custodian.family);
        let agent = child.agent_id;
        async move {
            fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
                sqlx::query(
                    "SELECT set_config('epigraph.principal_id', $1, false), \
                            set_config('epigraph.elevation_id', $2, false), \
                            set_config('epigraph.family_id', $3, false), \
                            set_config('epigraph.access_recorder', 'on', false)",
                )
                .bind(person.to_string())
                .bind(if elevated {
                    live.to_string()
                } else {
                    String::new()
                })
                .bind(family.to_string())
                .execute(&mut *conn)
                .await
                .expect("stamp");
                let is: bool = sqlx::query_scalar("SELECT public.epigraph_is_elevated()")
                    .fetch_one(&mut *conn)
                    .await
                    .expect("is_elevated");
                let r: Result<i64, sqlx::Error> = sqlx::query_scalar(
                    "SELECT count(*) FROM public.epigraph_agent_prompt_history($1)",
                )
                .bind(agent)
                .fetch_one(&mut *conn)
                .await;
                sqlx::query(
                    "SELECT set_config('epigraph.principal_id', '', false), \
                            set_config('epigraph.elevation_id', '', false), \
                            set_config('epigraph.family_id', '', false), \
                            set_config('epigraph.access_recorder', '', false)",
                )
                .execute(&mut *conn)
                .await
                .expect("unstamp");
                (conn, (is, r))
            })
            .await
        }
    };
    let (is, plain) = read(false).await;
    assert!(
        !is,
        "CALIBRATION: the unelevated connection is not elevated"
    );
    let err = plain.expect_err("an unelevated custodian read under armed admin scopes");
    assert_eq!(sqlstate(&err).as_deref(), Some("AID06"), "{err}");

    let (is, elevated) = read(true).await;
    assert!(is, "CALIBRATION: the elevated connection is elevated");
    assert!(elevated.expect("an elevated custodian reads") > 0);

    let own = history_as(&pool, Some(operator), child.agent_id)
        .await
        .expect("CALIBRATION: the operator still reads under armed scopes");
    assert!(own.iter().any(|r| r.relation == "self" && r.readable));
}

/// A snapshot changes in one way only (`last_seen`, forward) and a succession
/// row never changes, for every role (review TC6). Maintenance holds UPDATE
/// (last_seen) on snapshots and its policy admits the maintenance session, so
/// the guard is the only control on that path. CALIBRATION: moving
/// `last_seen` forward as maintenance succeeds.
#[sqlx::test(migrations = "../../migrations")]
async fn a_snapshot_only_moves_last_seen_forward_and_succession_never_changes(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let parent = live_linked_parent(&pool, operator, "g-guard").await;
    let child = register(
        &pool,
        &new_identity(),
        Some(parent),
        "g-guard",
        snapshot("g", "l"),
    )
    .await;
    let snap = child.snapshot_id;
    let agent = child.agent_id;

    let as_maint = |stmt: &'static str| {
        let pool = pool.clone();
        async move {
            fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
                let r = sqlx::query(stmt)
                    .bind(snap)
                    .bind(agent)
                    .execute(&mut *conn)
                    .await
                    .map(|r| r.rows_affected());
                (conn, r)
            })
            .await
        }
    };
    let backward = "UPDATE agent_prompt_snapshots SET last_seen = last_seen - interval '1 hour' \
          WHERE id = $1 AND agent_id = $2";
    let host = "UPDATE agent_prompt_snapshots SET host_sha = 'x' WHERE id = $1 AND agent_id = $2";
    let succ_update = "UPDATE agent_succession SET group_folder = 'g-moved' \
                        WHERE snapshot_id = $1 AND child_agent_id = $2";
    let succ_delete = "DELETE FROM agent_succession WHERE snapshot_id = $1 AND child_agent_id = $2";
    let snap_delete = "DELETE FROM agent_prompt_snapshots WHERE id = $1 AND agent_id = $2";

    for (stmt, maint_code) in [
        (backward, "55000"),
        (host, INSUFFICIENT_PRIVILEGE),
        (succ_update, INSUFFICIENT_PRIVILEGE),
        (succ_delete, INSUFFICIENT_PRIVILEGE),
        (snap_delete, INSUFFICIENT_PRIVILEGE),
    ] {
        let err = as_maint(stmt)
            .await
            .expect_err("the maintenance role changed lineage state");
        assert_eq!(
            sqlstate(&err).as_deref(),
            Some(maint_code),
            "maintenance {stmt}: {err}"
        );
        let err = sqlx::query(stmt)
            .bind(snap)
            .bind(agent)
            .execute(&pool)
            .await
            .expect_err("a superuser changed lineage state");
        assert_eq!(
            sqlstate(&err).as_deref(),
            Some("55000"),
            "superuser {stmt}: {err}"
        );
    }

    let forward = as_maint(
        "UPDATE agent_prompt_snapshots SET last_seen = last_seen + interval '1 second' \
          WHERE id = $1 AND agent_id = $2",
    )
    .await
    .expect("CALIBRATION: maintenance moves last_seen forward");
    assert_eq!(forward, 1);
}

/// A lineage with a CYCLE (a LEARNED.md revert brings back an earlier
/// identity, so X's descendant C is also its grandparent) still lists every
/// ancestor, each at its nearest depth: the walk keeps one visited set per
/// direction, so reaching C downward first does not stop the upward walk
/// before C's own parent Q. Read as maintenance.
#[sqlx::test(migrations = "../../migrations")]
async fn history_through_a_cycle_keeps_every_ancestor_at_its_nearest_depth(pool: PgPool) {
    let q = register(&pool, &new_identity(), None, "g-c3", snapshot("g", "q"))
        .await
        .agent_id;
    let p_id = new_identity();
    let p = register(&pool, &p_id, None, "g-c1", snapshot("g", "p"))
        .await
        .agent_id;
    let x = register(&pool, &new_identity(), Some(p), "g-c1", snapshot("g", "x"))
        .await
        .agent_id;
    let c_id = new_identity();
    let c = register(&pool, &c_id, Some(x), "g-c1", snapshot("g", "c"))
        .await
        .agent_id;
    register(&pool, &p_id, Some(c), "g-c2", snapshot("g", "p2")).await; // C -> P
    register(&pool, &c_id, Some(q), "g-c3", snapshot("g", "c3")).await; // Q -> C

    let rows: Vec<(Uuid, i32)> =
        fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let r = sqlx::query_as(
                "SELECT DISTINCT agent_id, depth FROM public.epigraph_agent_prompt_history($1)",
            )
            .bind(x)
            .fetch_all(&mut *conn)
            .await
            .expect("history");
            (conn, r)
        })
        .await;
    let depth = |a: Uuid| rows.iter().find(|(id, _)| *id == a).map(|(_, d)| *d);
    assert_eq!(depth(x), Some(0));
    assert_eq!(depth(p), Some(-1), "P is X's parent");
    assert_eq!(
        depth(c),
        Some(1),
        "C is nearer as X's child than as its grandparent"
    );
    assert_eq!(
        depth(q),
        Some(-3),
        "Q, C's parent, is X's ancestor through P and C"
    );
    assert_eq!(rows.len(), 4, "each member once: {rows:?}");
}

/// A custodian with a confirmed elevation session, built through migration
/// 125's definers exactly as `elevated_arms.rs` builds one (the minimal subset
/// of its fixtures).
mod elevation {
    use super::fixture;
    use sqlx::PgPool;
    use uuid::Uuid;

    pub struct Holder {
        pub person: Uuid,
        pub client: Uuid,
        pub cred: Vec<u8>,
        pub family: Uuid,
    }

    async fn as_app<F, Fut, T>(pool: &PgPool, principal: Option<Uuid>, f: F) -> T
    where
        F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
        Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, T)>,
    {
        let principal = principal.map(|p| p.to_string()).unwrap_or_default();
        fixture::as_role(pool, "epigraph_app", |mut conn| async move {
            sqlx::query(
                "SELECT set_config('epigraph.principal_id', $1, false), \
                        set_config('epigraph.elevation_id', '', false), \
                        set_config('epigraph.family_id', '', false)",
            )
            .bind(&principal)
            .execute(&mut *conn)
            .await
            .expect("stamp");
            let (mut conn, out) = f(conn).await;
            sqlx::query("SELECT set_config('epigraph.principal_id', '', false)")
                .execute(&mut *conn)
                .await
                .expect("unstamp");
            (conn, out)
        })
        .await
    }

    pub async fn holder(pool: &PgPool, label: &str, n: u8) -> Holder {
        let (person, _group) = fixture::seed_human_operator(pool, label).await;
        let client: Uuid = sqlx::query_scalar(
            "SELECT id FROM oauth_clients WHERE agent_id = $1 AND client_type = 'human'",
        )
        .bind(person)
        .fetch_one(pool)
        .await
        .expect("the human's client");
        fixture::make_custodian(pool, person).await;
        let e: Uuid = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
            let e = sqlx::query_scalar(
                "SELECT public.epigraph_create_passkey_enrollment($1, 'lineage test', 'key')",
            )
            .bind(person)
            .fetch_one(&mut *conn)
            .await
            .expect("enroll");
            (conn, e)
        })
        .await;
        let mut cred = vec![0xA5_u8; 16];
        cred[0] = n;
        let c = cred.clone();
        as_app(pool, None, |mut conn| async move {
            sqlx::query(
                "SELECT public.epigraph_set_passkey_enrollment_challenge($1, '{\"rs\": 1}'::jsonb)",
            )
            .bind(e)
            .execute(&mut *conn)
            .await
            .expect("enrollment challenge");
            sqlx::query(
                "SELECT public.epigraph_complete_passkey_enrollment($1, $2, \
                        '{\"cred\": 1}'::jsonb, '00000000-0000-0000-0000-000000000000'::uuid, \
                        'none', true, false)",
            )
            .bind(e)
            .bind(c)
            .execute(&mut *conn)
            .await
            .expect("complete the enrollment");
            (conn, ())
        })
        .await;
        let hash: Vec<u8> = [
            Uuid::new_v4().as_bytes().to_vec(),
            Uuid::new_v4().as_bytes().to_vec(),
        ]
        .concat();
        let family: Uuid = sqlx::query_scalar(
            "INSERT INTO refresh_tokens (token_hash, client_id, scopes, expires_at) \
             VALUES ($1, $2, ARRAY['claims:read'], now() + interval '1 day') RETURNING id",
        )
        .bind(&hash)
        .bind(client)
        .fetch_one(pool)
        .await
        .expect("a refresh token");
        Holder {
            person,
            client,
            cred,
            family,
        }
    }

    /// A confirmed grant-mode session for `h`; its id.
    pub async fn session(pool: &PgPool, h: &Holder) -> Uuid {
        let (client, fam) = (h.client, h.family);
        let ticket: Uuid = as_app(pool, Some(h.person), |mut conn| async move {
            let t = sqlx::query_scalar(
                "SELECT public.epigraph_create_elevation_ticket($1, $2, 'grant', \
                        'lineage test', sha256('a lineage test secret'::bytea))",
            )
            .bind(client)
            .bind(fam)
            .fetch_one(&mut *conn)
            .await
            .expect("a ticket");
            (conn, t)
        })
        .await;
        let cred = h.cred.clone();
        as_app(pool, None, |mut conn| async move {
            sqlx::query(
                "SELECT public.epigraph_set_elevation_ticket_challenge($1, '{\"st\": 1}'::jsonb)",
            )
            .bind(ticket)
            .execute(&mut *conn)
            .await
            .expect("the ceremony's challenge");
            let (outcome, session): (String, Option<Uuid>) = sqlx::query_as(
                "SELECT outcome, session_id \
                   FROM public.epigraph_confirm_elevation($1, $2, 0, false, '{\"ev\": 1}'::jsonb)",
            )
            .bind(ticket)
            .bind(cred)
            .fetch_one(&mut *conn)
            .await
            .expect("confirm");
            assert_eq!(outcome, "confirmed", "CALIBRATION: the ceremony confirms");
            (conn, session.expect("a session"))
        })
        .await
    }
}
