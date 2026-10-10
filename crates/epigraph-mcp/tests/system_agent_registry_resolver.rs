//! Migration 148: the workflow-ingest system agent is RESOLVED from the
//! `system_agents` registry, never re-derived from its public-constant key once
//! a row exists, and never derived at all on an armed database.
//!
//! The rotation this protects: an operator rotates the system agent off the
//! public-constant key (`UPDATE agents SET public_key = <fresh>`). Before 148
//! the next ingest missed the key lookup and minted a SECOND agent holding the
//! public-constant key: a split identity, unlinked, with its own group. Every
//! test here reaches the resolver (`get_or_create_system_agent`) or its
//! entry points on APPLICATION-ROLE connections; the harness superuser only
//! seeds, rotates keys and arms (standing in for the maintenance session, as
//! `operator_binding_system_agent.rs` does). Registration goes through the real
//! definer on a maintenance session (`fixture::register_system_agent`). No test
//! calls `fixture::grant_app_privileges`.
//!
//! Verified to fail (the one mutation run against this file):
//! `SystemAgentRepository::lookup` keyed on
//! `epigraph_operator_binding_enforced()` instead of `..._armed()` ->
//! `the_valve_does_not_reopen_the_fallback` returns `Ok`. Each test's "Kills:"
//! line names the mutation it is designed to catch; those were not run
//! individually (every test was seen red against the pre-registry resolver).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{ScopedPool, SessionGucMode, SystemAgentRole};
use epigraph_ingest_executor::IngestExecutorError;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::types::StoreWorkflowParams;
use sqlx::PgPool;
use uuid::Uuid;

fn legacy_key() -> [u8; 32] {
    SystemAgentRole::WorkflowIngest.legacy_public_key()
}

/// The pre-148 key, as a literal computed from the tree before 148 existed
/// (the same literal `epigraph-db`'s unit drift guard pins).
const PRE_148_KEY_HEX: &str = "bf97389e58aabc8680d6a376a0fdc8ffccccb5bc20cb9c5dedd4a3b6fe37aa33";

async fn count(pool: &PgPool, table: &str) -> i64 {
    // Table names are test-local literals.
    sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("count {table}: {e}"))
}

async fn k_holders(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM agents WHERE public_key = $1")
        .bind(legacy_key().as_slice())
        .fetch_one(pool)
        .await
        .expect("K holders")
}

/// `(agents, groups, group_memberships, claims)`.
async fn snapshot(pool: &PgPool) -> (i64, i64, i64, i64) {
    (
        count(pool, "agents").await,
        count(pool, "groups").await,
        count(pool, "group_memberships").await,
        count(pool, "claims").await,
    )
}

async fn rotate(pool: &PgPool, agent: Uuid) {
    sqlx::query(
        "UPDATE agents SET public_key = decode(md5(random()::text) || md5(random()::text), 'hex') \
          WHERE id = $1",
    )
    .bind(agent)
    .execute(pool)
    .await
    .expect("rotate the agent's key");
}

async fn arm(pool: &PgPool) {
    sqlx::query("INSERT INTO operator_binding_arming DEFAULT VALUES")
        .execute(pool)
        .await
        .expect("arm (the harness stands in for the maintenance role)");
}

async fn link_live(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("live link");
}

async fn app_pool(pool: &PgPool) -> PgPool {
    fixture::downgraded_pool(pool, "epigraph_app").await
}

async fn app_scoped(pool: &PgPool) -> ScopedPool {
    let url = fixture::database_url_for(pool).await;
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("app-role ScopedPool")
}

/// The resolver on an application-role connection.
async fn resolve(pool: &PgPool) -> Result<Uuid, IngestExecutorError> {
    let app = app_pool(pool).await;
    let mut conn = app.acquire().await.expect("app conn");
    epigraph_ingest_executor::get_or_create_system_agent(&mut conn).await
}

/// An app-role stdio server whose own agent (the CALLER of every tool) is
/// keyed by `seed`, pre-created so a test can link it before the first call.
async fn app_role_server(pool: &PgPool, seed: u8) -> (EpiGraphMcpFull, Uuid) {
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let caller: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, 'mcp-agent') RETURNING id",
    )
    .bind(signer.public_key().as_slice())
    .fetch_one(pool)
    .await
    .expect("the caller's agent row");
    let scoped = app_scoped(pool).await;
    let plain = app_pool(pool).await;
    let embedder =
        epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None).with_scoped_pool(scoped.clone());
    let server = EpiGraphMcpFull::new(plain, signer, embedder, /* read_only */ false)
        .with_scoped_pool(scoped);
    (server, caller)
}

async fn store(server: &EpiGraphMcpFull, step: &str) -> Result<String, String> {
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("stdio viewer");
    let goal = format!("system agent registry goal {}", Uuid::new_v4());
    epigraph_mcp::tools::workflows::store_workflow(
        server,
        &viewer,
        StoreWorkflowParams {
            goal: goal.clone(),
            steps: vec![step.to_string()],
            prerequisites: None,
            expected_outcome: None,
            confidence: None,
            tags: None,
        },
        None,
    )
    .await
    .map(|_| goal)
    .map_err(|e| e.message.to_string())
}

async fn author_of(pool: &PgPool, content: &str) -> (Uuid, Uuid) {
    sqlx::query_as("SELECT agent_id, owner_group_id FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("claim {content:?}: {e}"))
}

/// S created by the unarmed legacy fallback (so it holds K), then registered.
async fn legacy_system_agent_registered(pool: &PgPool) -> Uuid {
    let s = resolve(pool).await.expect("unarmed fallback creates S");
    assert!(fixture::register_system_agent(pool, s).await);
    s
}

// ── 4.2: the resolver ───────────────────────────────────────────────────────

/// After registration and a key rotation the resolver answers S and mints
/// nothing. Kills: the `Registered` arm deleted, or the row read but the key
/// looked up first (either re-creates a K holder, which the `agents` guard
/// refuses, so the resolver errors).
async fn resolves_after_rotation(pool: PgPool, armed: bool) {
    let s = legacy_system_agent_registered(&pool).await;
    rotate(&pool, s).await;
    if armed {
        let (a, _) = fixture::seed_human_operator(&pool, "a").await;
        link_live(&pool, s, a).await;
        arm(&pool).await;
    }
    let agents = count(&pool, "agents").await;
    assert_eq!(resolve(&pool).await.expect("resolves"), s);
    assert_eq!(
        k_holders(&pool).await,
        0,
        "nothing holds the public-constant key"
    );
    assert_eq!(count(&pool, "agents").await, agents, "no agent minted");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_registry_resolves_after_a_key_rotation_and_mints_nothing_unarmed(pool: PgPool) {
    resolves_after_rotation(pool, false).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_registry_resolves_after_a_key_rotation_and_mints_nothing_armed(pool: PgPool) {
    resolves_after_rotation(pool, true).await;
}

/// S registered while holding a RANDOM key (so K is never its registered key
/// and a second agent X may hold K); the resolver and the write authority both
/// answer S, never X. Kills: the lookup order swapped (key first, registry
/// second), or any "prefer an agent holding K" heuristic.
async fn second_holder_never_wins(pool: PgPool, armed: bool) {
    let (s, _) = fixture::seed_agent_with_group(&pool, "s").await;
    assert!(fixture::register_system_agent(&pool, s).await);
    let x: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, 'workflow-ingest-system') \
         RETURNING id",
    )
    .bind(legacy_key().as_slice())
    .fetch_one(&pool)
    .await
    .expect("X holds K");
    if armed {
        let (a, _) = fixture::seed_human_operator(&pool, "a").await;
        link_live(&pool, s, a).await;
        arm(&pool).await;
    }
    let resolved = resolve(&pool).await.expect("resolves");
    assert_eq!(resolved, s, "the registered agent, not the K holder {x}");
    let authority =
        epigraph_ingest_executor::system_agent_write_authority(&app_scoped(&pool).await)
            .await
            .expect("write authority");
    assert_eq!(authority.agent_id, s);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_second_constant_key_agent_never_becomes_the_system_agent_unarmed(pool: PgPool) {
    second_holder_never_wins(pool, false).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_second_constant_key_agent_never_becomes_the_system_agent_armed(pool: PgPool) {
    second_holder_never_wins(pool, true).await;
}

/// Every existing database holds the workflow-ingest agent under the pre-148
/// derivation. The first ≥148 binary must ADOPT it (unarmed, unregistered),
/// not mint a second one. Kills: any drift of `legacy_public_key()` away from
/// the pre-148 derivation.
#[sqlx::test(migrations = "../../migrations")]
async fn the_resolver_adopts_an_agent_seeded_by_the_pre_148_derivation(pool: PgPool) {
    let key = hex::decode(PRE_148_KEY_HEX).expect("hex");
    let seeded: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, 'workflow-ingest-system') \
         RETURNING id",
    )
    .bind(&key)
    .fetch_one(&pool)
    .await
    .expect("a pre-148 system agent");
    let agents = count(&pool, "agents").await;
    assert_eq!(resolve(&pool).await.expect("resolves"), seeded);
    assert_eq!(count(&pool, "agents").await, agents);
    assert_eq!(count(&pool, "system_agents").await, 0);
}

/// Armed with no registration: refused BEFORE anything is written (no agent,
/// no group, no membership, no claim). Kills: the refusal placed after the
/// `boot` lookup/create or after the personal-group provisioning (counts move);
/// an armed fallback that still creates.
#[sqlx::test(migrations = "../../migrations")]
async fn an_armed_database_with_no_registration_refuses_before_writing_anything(pool: PgPool) {
    arm(&pool).await;
    let before = snapshot(&pool).await;
    let r = epigraph_ingest_executor::system_agent_write_authority(&app_scoped(&pool).await).await;
    assert!(
        matches!(
            r,
            Err(IngestExecutorError::SystemAgentUnregistered {
                role: "workflow-ingest"
            })
        ),
        "armed and unregistered must refuse by name: {r:?}"
    );
    assert_eq!(snapshot(&pool).await, before, "nothing written");
    assert_eq!(k_holders(&pool).await, 0);
}

/// The session valve (`epigraph.operator_link_enforcement = off`) relieves the
/// binding only; it must not reopen the create path. The GUC is set on the
/// SAME connection the resolver runs on (`system_agent_write_authority` would
/// acquire its own connection, where the GUC is absent), with a calibration on
/// that connection. Kills: `SystemAgentRepository::lookup` keyed on
/// `epigraph_operator_binding_enforced()` instead of `..._armed()`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_valve_does_not_reopen_the_fallback(pool: PgPool) {
    arm(&pool).await;
    let before = snapshot(&pool).await;
    let app = app_pool(&pool).await;
    let mut conn = app.acquire().await.expect("app conn");
    sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', 'off', false)")
        .execute(&mut *conn)
        .await
        .expect("open the valve");
    let calibration: (bool, bool) = sqlx::query_as(
        "SELECT epigraph_operator_binding_armed(), epigraph_operator_binding_enforced()",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("calibration");
    assert_eq!(calibration, (true, false), "CALIBRATION: armed, valve open");
    let r = epigraph_ingest_executor::get_or_create_system_agent(&mut conn).await;
    assert!(
        matches!(r, Err(IngestExecutorError::SystemAgentUnregistered { .. })),
        "the valve must not reopen the fallback: {r:?}"
    );
    drop(conn);
    assert_eq!(snapshot(&pool).await, before);
}

/// Armed, an agent holding K exists, no registration: still refused. Kills the
/// weaker rule "armed: the key lookup is allowed, only a create is refused",
/// which would let a later K holder become the system agent.
#[sqlx::test(migrations = "../../migrations")]
async fn an_armed_database_with_a_key_holder_but_no_registration_still_refuses(pool: PgPool) {
    let s = resolve(&pool).await.expect("unarmed fallback creates S");
    arm(&pool).await;
    let r = resolve(&pool).await;
    assert!(
        matches!(r, Err(IngestExecutorError::SystemAgentUnregistered { .. })),
        "armed and unregistered refuses even with a K holder ({s}): {r:?}"
    );
}

/// The pre-148 behaviour, kept for unarmed unregistered databases (every fresh
/// install and test database). Kills: a resolver that refuses whenever
/// unregistered (fresh installs break); one that creates on every call; one
/// that "self-registers" what it found or created.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unarmed_unregistered_database_keeps_the_legacy_resolution(pool: PgPool) {
    let agents = count(&pool, "agents").await;
    let first = resolve(&pool).await.expect("first resolution creates");
    let (key, name): (Vec<u8>, Option<String>) =
        sqlx::query_as("SELECT public_key, display_name FROM agents WHERE id = $1")
            .bind(first)
            .fetch_one(&pool)
            .await
            .expect("the created agent");
    assert_eq!(key, legacy_key().to_vec());
    assert_eq!(name.as_deref(), Some("workflow-ingest-system"));
    let second = resolve(&pool).await.expect("second resolution");
    assert_eq!(second, first);
    assert_eq!(count(&pool, "agents").await, agents + 1);
    assert_eq!(k_holders(&pool).await, 1);
    assert_eq!(
        count(&pool, "system_agents").await,
        0,
        "the resolver never registers"
    );
}

/// A registered agent that cannot write (its personal-group membership was
/// revoked) is REFUSED by name; the resolver never falls back to the key
/// lookup or a create. The write authority runs once first, so S's personal
/// group exists and the revoked-membership branch (not the never-provisioned
/// branch) is the one measured. Kills: "if the registered agent cannot write,
/// fall back to the key lookup / create" (re-mints K: the split).
#[sqlx::test(migrations = "../../migrations")]
async fn a_registered_agent_with_a_revoked_membership_is_refused_and_nothing_is_minted(
    pool: PgPool,
) {
    let scoped = app_scoped(&pool).await;
    let s = epigraph_ingest_executor::system_agent_write_authority(&scoped)
        .await
        .expect("unarmed: S created and provisioned")
        .agent_id;
    assert!(fixture::register_system_agent(&pool, s).await);
    let revoked = sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() WHERE agent_id = $1 AND revoked_at IS NULL",
    )
    .bind(s)
    .execute(&pool)
    .await
    .expect("revoke S's membership")
    .rows_affected();
    assert!(revoked >= 1, "CALIBRATION: S held a live membership");
    rotate(&pool, s).await;
    let agents = count(&pool, "agents").await;

    let r = epigraph_ingest_executor::system_agent_write_authority(&scoped).await;
    let msg = match r {
        Err(IngestExecutorError::AgentCreation(m)) => m,
        other => panic!("expected a refusal naming the revoked membership, got {other:?}"),
    };
    assert!(msg.contains("REVOKED"), "names the revocation: {msg}");
    assert_eq!(count(&pool, "agents").await, agents);
    assert_eq!(k_holders(&pool).await, 0);
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships WHERE agent_id = $1 AND revoked_at IS NULL",
    )
    .bind(s)
    .fetch_one(&pool)
    .await
    .expect("live memberships");
    assert_eq!(live, 0, "the revocation is not reversed");
}

/// Two first resolutions on a fresh database, made deterministic: connection A
/// inserts the K holder and holds its transaction open; the resolver on B
/// misses the lookup, blocks on the unique index (observed in
/// `pg_stat_activity` from the superuser pool), and A commits. B must answer
/// A's agent. Kills: removal of the duplicate-key re-lookup (B then returns
/// `AgentCreation("create: Duplicate ...")`). Also pins that `create_conn` maps
/// 23505 to `DbError::DuplicateKey`.
#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_first_resolutions_on_a_fresh_database_agree(pool: PgPool) {
    let id_a = Uuid::new_v4();
    let mut a = pool.acquire().await.expect("connection A");
    sqlx::query("BEGIN").execute(&mut *a).await.expect("begin");
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name) VALUES ($1, $2, 'workflow-ingest-system')",
    )
    .bind(id_a)
    .bind(legacy_key().as_slice())
    .execute(&mut *a)
    .await
    .expect("A's uncommitted K holder");

    let app = app_pool(&pool).await;
    let b = tokio::spawn(async move {
        let mut conn = app.acquire().await.expect("connection B");
        epigraph_ingest_executor::get_or_create_system_agent(&mut conn).await
    });

    let mut waited = false;
    for _ in 0..200 {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
              WHERE datname = current_database() AND wait_event_type = 'Lock' \
                AND query ILIKE '%INSERT INTO agents%'",
        )
        .fetch_one(&pool)
        .await
        .expect("pg_stat_activity");
        if waiting > 0 {
            waited = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(waited, "CALIBRATION: B must block on A's uncommitted key");
    sqlx::query("COMMIT")
        .execute(&mut *a)
        .await
        .expect("commit A");

    let got = b.await.expect("join B");
    assert_eq!(got.expect("B adopts A's agent after losing the race"), id_a);
    assert_eq!(k_holders(&pool).await, 1);
}

/// The documented order, end to end: (1) the unarmed fallback creates S;
/// (2) register S; (3) rotate S's key; (4) a squatter on K cannot exist;
/// (5) live-link S to human A; (6) arm. Then a caller bound to A stores a
/// workflow (authored by S, owned by A's group, nothing minted) and an unbound
/// caller is refused OPL01 with nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn the_rotation_order_keeps_one_system_identity(pool: PgPool) {
    let (a, a_group) = fixture::seed_human_operator(&pool, "a").await;
    let s = legacy_system_agent_registered(&pool).await;
    // S's personal group is provisioned while it is unlinked, as on a live
    // database where the system agent has written before.
    epigraph_ingest_executor::system_agent_write_authority(&app_scoped(&pool).await)
        .await
        .expect("provision S");
    rotate(&pool, s).await;
    let squat = sqlx::query(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, 'workflow-ingest-system')",
    )
    .bind(legacy_key().as_slice())
    .execute(&pool)
    .await;
    let e = squat.expect_err("(4) the squatter must be refused");
    assert_eq!(
        e.as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("55000"),
        "{e}"
    );
    link_live(&pool, s, a).await;
    let (bound, bound_caller) = app_role_server(&pool, 0xC1).await;
    let (unbound, _) = app_role_server(&pool, 0xC2).await;
    link_live(&pool, bound_caller, a).await;
    arm(&pool).await;

    let agents = count(&pool, "agents").await;
    let step = format!("rotation order step {}", Uuid::new_v4());
    store(&bound, &step)
        .await
        .expect("a bound caller stores through the registered system agent");
    assert_eq!(author_of(&pool, &step).await, (s, a_group));
    assert_eq!(count(&pool, "agents").await, agents, "no agent minted");
    assert_eq!(k_holders(&pool).await, 0);

    let refused_step = format!("unbound step {}", Uuid::new_v4());
    let refused = store(&unbound, &refused_step)
        .await
        .expect_err("an unbound caller is refused");
    assert!(refused.contains("OPL01"), "{refused}");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM claims WHERE content = $1")
            .bind(&refused_step)
            .fetch_one(&pool)
            .await
            .expect("count"),
        0
    );
}

// ── 4.3: the MCP entry points ───────────────────────────────────────────────

/// `store_workflow` after a rotation authors as S and mints nothing. Kills: a
/// caller path that still does its own key lookup (after the rotation it would
/// try to re-create K, which the `agents` guard refuses, so the store fails).
#[sqlx::test(migrations = "../../migrations")]
async fn store_workflow_after_rotation_authors_as_the_registered_agent(pool: PgPool) {
    let s = legacy_system_agent_registered(&pool).await;
    rotate(&pool, s).await;
    let (server, _) = app_role_server(&pool, 0xD1).await;
    let step = format!("post-rotation step {}", Uuid::new_v4());
    store(&server, &step)
        .await
        .expect("store_workflow after the rotation");
    assert_eq!(author_of(&pool, &step).await.0, s);
    assert_eq!(k_holders(&pool).await, 0);
}

/// `add_step` (whose executor resolves the system agent again inside the
/// stamped transaction) after a rotation authors as S and mints nothing. The
/// workflow is stored BEFORE the rotation, so the only post-rotation resolution
/// is `add_step`'s own.
#[sqlx::test(migrations = "../../migrations")]
async fn mcp_add_step_after_rotation_mints_nothing(pool: PgPool) {
    let s = legacy_system_agent_registered(&pool).await;
    let (server, _) = app_role_server(&pool, 0xD2).await;
    store(&server, &format!("first step {}", Uuid::new_v4()))
        .await
        .expect("store before the rotation");
    let canonical: String =
        sqlx::query_scalar("SELECT canonical_name FROM workflows ORDER BY created_at DESC LIMIT 1")
            .fetch_one(&pool)
            .await
            .expect("the stored workflow");
    rotate(&pool, s).await;

    let added = format!("added step {}", Uuid::new_v4());
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&server, None)
        .await
        .expect("stdio viewer");
    epigraph_mcp::tools::step_ops::add_step(
        &server,
        &viewer,
        epigraph_mcp::tools::step_ops::AddStepParams {
            canonical_name: canonical,
            step_text: added.clone(),
            position: None,
        },
        None,
    )
    .await
    .map_err(|e| e.message.to_string())
    .expect("add_step after the rotation");
    assert_eq!(author_of(&pool, &added).await.0, s);
    assert_eq!(k_holders(&pool).await, 0);
}

// ── 4.4: author-NAME paths never adopt or mint a system agent ──────────────
//
// Each runs in three states, in order on one database: (0) S holds the
// public-constant key K and NOTHING is registered (every database between the
// >=148 deploy and the registration, and every fresh install); (a) S
// registered while holding K; (b) after S's key rotation. The reserved author
// is "Workflow-Ingest-System." (case AND punctuation): a lowercase+trim string
// guard misses it, but `normalize_author_name` strips the `.`, so it derives K.
//
// State (0) is the one where the legacy-key check is the ONLY guard: the
// registered-id check has an empty set and the `agents` trigger has no
// snapshot. Kills, per path: the legacy-key check missing, weakened to the
// create branch only, or run only when something is registered (state (0)
// adopts S as an author; in (a) the registered-id check would hide it, in (b)
// the `agents` guard would); a weak string compare (the punctuation variant
// passes).

const RESERVED_AUTHOR: &str = "Workflow-Ingest-System.";

fn name_key(name: &str) -> [u8; 32] {
    epigraph_crypto::did_key::did_key_for_author(None, name).1
}

async fn agent_with_key(pool: &PgPool, key: &[u8; 32]) -> Option<Uuid> {
    sqlx::query_scalar("SELECT id FROM agents WHERE public_key = $1")
        .bind(key.as_slice())
        .fetch_optional(pool)
        .await
        .expect("agent by key")
}

/// Edges (any relationship) whose SOURCE is the agent `agent`.
async fn edges_from(pool: &PgPool, agent: Uuid, relationship: Option<&str>) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND source_type = 'agent' \
           AND ($2::text IS NULL OR relationship = $2)",
    )
    .bind(agent)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .expect("edges from agent")
}

/// Edges from ANY agent holding K (a re-minted clone included).
async fn edges_from_k_holders(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges e JOIN agents a ON a.id = e.source_id \
          WHERE e.source_type = 'agent' AND a.public_key = $1",
    )
    .bind(legacy_key().as_slice())
    .fetch_one(pool)
    .await
    .expect("edges from K holders")
}

fn workflow_extraction(
    canonical: &str,
    authors: &[&str],
) -> epigraph_ingest::workflow::WorkflowExtraction {
    use epigraph_ingest::common::schema::{AuthorEntry, ThesisDerivation};
    use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
    epigraph_ingest::workflow::WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical.to_string(),
            goal: format!("author guard goal {canonical}"),
            generation: 0,
            parent_canonical_name: None,
            authors: authors
                .iter()
                .map(|n| AuthorEntry {
                    name: (*n).to_string(),
                    affiliations: vec![],
                    roles: vec![],
                })
                .collect(),
            expected_outcome: None,
            tags: vec![],
            metadata: serde_json::json!({}),
        },
        thesis: Some(format!("author guard thesis {canonical}")),
        thesis_derivation: ThesisDerivation::TopDown,
        phases: vec![Phase {
            title: "Phase".to_string(),
            summary: format!("author guard phase {canonical}"),
            steps: vec![Step {
                compound: format!("author guard step {canonical}"),
                rationale: "probe".to_string(),
                operations: vec![format!("author guard op {canonical}")],
                generality: vec![2],
                confidence: 0.9,
                evidence_type: None,
            }],
        }],
        relationships: vec![],
    }
}

async fn ingest_workflow_authors(pool: &PgPool, authors: &[&str]) {
    let extraction = workflow_extraction(&format!("author-guard-{}", Uuid::new_v4()), authors);
    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(&extraction);
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_ingest_executor::execute_workflow_ingest_plan(&mut conn, &plan, &extraction)
        .await
        .expect("the workflow ingest succeeds with a reserved author present");
}

/// A server on the superuser pool built from a ScopedPool (the document walk
/// needs one; the stamp is inert on a superuser, and no tenancy question is
/// asked here), as `ingest_document_smoke.rs` builds one.
async fn superuser_server(pool: &PgPool) -> EpiGraphMcpFull {
    let scoped = fixture::scoped_pool(pool).await;
    let signer = epigraph_crypto::AgentSigner::generate();
    let embedder =
        epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(pool.clone(), signer, embedder, false).with_scoped_pool(scoped)
}

fn document(
    authors: &[&str],
    source_text: Option<&str>,
) -> epigraph_ingest::schema::DocumentExtraction {
    let tag = Uuid::new_v4();
    serde_json::from_value(serde_json::json!({
        "source": {
            "title": format!("Author guard paper {tag}"),
            "doi": format!("10.1234/author-guard-{tag}"),
            "source_type": "Paper",
            "authors": authors.iter().map(|n| serde_json::json!({
                "name": n, "affiliations": [], "roles": ["author"]
            })).collect::<Vec<_>>()
        },
        "source_text": source_text,
        "thesis": format!("Author guard thesis {tag}"),
        "thesis_derivation": "TopDown",
        "sections": [{
            "title": "Intro",
            "paragraphs": [{
                "text": format!("Author guard paragraph {tag}"),
                "atoms": [format!("Author guard atom {tag}")],
                "generality": [3],
                "confidence": 0.8
            }]
        }],
        "relationships": []
    }))
    .expect("document extraction")
}

#[derive(Clone, Copy)]
enum DocPath {
    Full,
    Spine,
}

async fn ingest_document_authors(
    pool: &PgPool,
    path: DocPath,
    authors: &[&str],
    text: Option<&str>,
) {
    let server = superuser_server(pool).await;
    let viewer = fixture::public_viewer(pool).await;
    let extraction = document(authors, text);
    let r = match path {
        DocPath::Full => {
            epigraph_mcp::tools::ingestion::do_ingest_document(&server, &viewer, &extraction, None)
                .await
        }
        DocPath::Spine => {
            epigraph_mcp::tools::ingestion::do_ingest_document_spine(
                &server,
                &viewer,
                &extraction,
                None,
            )
            .await
        }
    };
    r.map_err(|e| e.message.to_string())
        .expect("the document ingest succeeds with a reserved author present");
}

/// The three states, in order. `enter` moves the database from the previous
/// state into `state` and calibrates (0): S holds K and nothing is registered.
const RESERVED_STATES: [&str; 3] = [
    "(0) S holds K, nothing registered",
    "(a) S holds K, registered",
    "(b) S rotated",
];

async fn enter(pool: &PgPool, s: Uuid, state: &str) {
    match &state[..3] {
        "(0)" => {
            assert_eq!(count(pool, "system_agents").await, 0, "CALIBRATION {state}");
            assert_eq!(k_holders(pool).await, 1, "CALIBRATION {state}");
        }
        "(a)" => assert!(fixture::register_system_agent(pool, s).await),
        _ => rotate(pool, s).await,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn workflow_ingest_skips_an_author_naming_the_system_identity(pool: PgPool) {
    let s = resolve(&pool).await.expect("unarmed fallback creates S");
    for state in RESERVED_STATES {
        enter(&pool, s, state).await;
        ingest_workflow_authors(&pool, &["Ada Lovelace", RESERVED_AUTHOR]).await;
        let ada = agent_with_key(&pool, &name_key("Ada Lovelace"))
            .await
            .expect("control: the Ada agent exists");
        assert!(
            edges_from(&pool, ada, None).await > 0,
            "{state}: control edge from Ada"
        );
        assert_eq!(
            edges_from(&pool, s, None).await,
            0,
            "{state}: no author edge from S"
        );
        assert_eq!(edges_from_k_holders(&pool).await, 0, "{state}");
        let expected_holders = if state.starts_with("(b)") { 0 } else { 1 };
        assert_eq!(
            k_holders(&pool).await,
            expected_holders,
            "{state}: K holders"
        );
    }
}

async fn document_skips_reserved(pool: PgPool, path: DocPath) {
    let s = resolve(&pool).await.expect("unarmed fallback creates S");
    for state in RESERVED_STATES {
        enter(&pool, s, state).await;
        let ada_before = match agent_with_key(&pool, &name_key("Ada Lovelace")).await {
            Some(a) => edges_from(&pool, a, Some("authored")).await,
            None => 0,
        };
        ingest_document_authors(&pool, path, &["Ada Lovelace", RESERVED_AUTHOR], None).await;
        let ada = agent_with_key(&pool, &name_key("Ada Lovelace"))
            .await
            .expect("control: the Ada agent exists");
        assert_eq!(
            edges_from(&pool, ada, Some("authored")).await,
            ada_before + 1,
            "{state}: control: Ada authored the new paper"
        );
        assert_eq!(
            edges_from(&pool, s, Some("authored")).await,
            0,
            "{state}: S authored nothing"
        );
        assert_eq!(edges_from_k_holders(&pool).await, 0, "{state}");
        if state.starts_with("(b)") {
            assert_eq!(k_holders(&pool).await, 0, "{state}: no K holder minted");
        }
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn ingest_document_skips_an_author_naming_the_system_identity(pool: PgPool) {
    document_skips_reserved(pool, DocPath::Full).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn ingest_document_spine_skips_an_author_naming_the_system_identity(pool: PgPool) {
    document_skips_reserved(pool, DocPath::Spine).await;
}

/// The byline fallback (a Paper with `authors: []`) runs the same guard. The
/// byline parser only emits 2-4 whitespace-separated tokens, and
/// `normalize_author_name` maps whitespace to `_`, so no byline name can derive
/// the legacy key; what a byline CAN name is an agent that is REGISTERED under
/// a name-derived key. So the registered agent here is the one keyed by
/// "Grace Hopper", and the byline names it beside a control author. Kills: the
/// registered-agent check missing on the byline path.
#[sqlx::test(migrations = "../../migrations")]
async fn ingest_document_byline_fallback_skips_the_system_identity(pool: PgPool) {
    let n: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, 'Grace Hopper') RETURNING id",
    )
    .bind(name_key("Grace Hopper").as_slice())
    .fetch_one(&pool)
    .await
    .expect("an agent keyed by a person's name");
    assert!(fixture::register_system_agent(&pool, n).await);
    let text = "Author Guard Byline Paper\n\nAda Lovelace, Grace Hopper\n\nAbstract\nBody.\n";
    assert_eq!(
        epigraph_ingest::document::byline::parse_byline_authors(text).len(),
        2,
        "CALIBRATION: the byline parses to two authors"
    );
    ingest_document_authors(&pool, DocPath::Full, &[], Some(text)).await;
    let ada = agent_with_key(&pool, &name_key("Ada Lovelace"))
        .await
        .expect("control: the byline path ran and created the Ada agent");
    assert_eq!(edges_from(&pool, ada, Some("authored")).await, 1, "control");
    assert_eq!(
        edges_from(&pool, n, Some("authored")).await,
        0,
        "N authored nothing"
    );
}

/// An author whose name resolves to the REGISTERED agent through a key that is
/// not the legacy one (an agent registered under a name-derived key) is never
/// adopted. Kills: the second check (registered-id set) missing, since the
/// first check (legacy key) passes "Some Name".
#[sqlx::test(migrations = "../../migrations")]
async fn an_author_resolving_to_a_registered_agent_is_never_adopted(pool: PgPool) {
    let n: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, 'Some Name') RETURNING id",
    )
    .bind(name_key("Some Name").as_slice())
    .fetch_one(&pool)
    .await
    .expect("an agent keyed by a name");
    assert!(fixture::register_system_agent(&pool, n).await);

    ingest_workflow_authors(&pool, &["Ada Lovelace", "Some Name"]).await;
    let ada = agent_with_key(&pool, &name_key("Ada Lovelace"))
        .await
        .expect("control: the Ada agent exists");
    assert!(
        edges_from(&pool, ada, None).await > 0,
        "workflow: control edge from Ada"
    );
    assert_eq!(
        edges_from(&pool, n, None).await,
        0,
        "workflow: no author edge from N"
    );

    let server = superuser_server(&pool).await;
    let viewer = fixture::public_viewer(&pool).await;
    let result = epigraph_mcp::tools::ingestion::do_ingest_document(
        &server,
        &viewer,
        &document(&["Ada Lovelace", "Some Name"], None),
        None,
    )
    .await
    .map_err(|e| e.message.to_string())
    .expect("document ingest");
    assert_eq!(
        edges_from(&pool, ada, Some("authored")).await,
        1,
        "document: control: Ada authored the paper"
    );
    assert_eq!(
        edges_from(&pool, n, Some("authored")).await,
        0,
        "document: N authored nothing"
    );
    let body = serde_json::to_string(&result).expect("result json");
    assert!(
        !body.contains(&n.to_string()),
        "N is not among the response's authors: {body}"
    );
}
