//! Shared test helpers for epigraph-mcp integration tests. Mirrors
//! crates/epigraph-db/tests/claim_repo_helpers.rs — same try_test_pool,
//! pre-107/post-107 fixture toggling, agent insert, claim builder.

#![allow(dead_code)]

use epigraph_auth::{AuthContext, ClientType};
use epigraph_core::{AgentId, Claim, TruthValue};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

/// An admin `AuthContext` for tests that exercise ownership-gated tools
/// (`supersede_claim` / `mark_duplicate`). The `claims:admin` scope satisfies
/// `require_owner_or_admin` regardless of the seeded claim's author, so the
/// test keeps asserting the supersede/duplicate *behavior* rather than auth.
pub fn admin_auth() -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: None,
        owner_id: None,
        client_type: ClientType::Service,
        scopes: vec!["claims:admin".to_string()],
        jti: Uuid::new_v4(),
    }
}

/// Names these fixtures may mutate without an explicit opt-in.
/// Mirrors `db_is_disposable` in
/// `crates/epigraph-db/tests/claim_repo_helpers.rs` — see that file for the
/// full rationale.
pub fn db_is_disposable(name: &str) -> bool {
    name.starts_with("_sqlx_test") || name.ends_with("_test")
}

/// Environment opt-in for running these fixtures against a
/// non-disposable-looking database (set by CI, whose DB is named `epigraph`).
pub const DESTRUCTIVE_OPT_IN: &str = "EPIGRAPH_TEST_DESTRUCTIVE_DB";

/// Refuse to hand back a pool onto a database these fixtures must not touch.
///
/// Guards pool construction, not the individual helpers: `try_test_pool`
/// itself runs `sqlx::migrate!` against whatever `DATABASE_URL` names, so a
/// per-helper guard would leave that path unprotected. Panics rather than
/// skips so a misdirected `DATABASE_URL` cannot masquerade as a green run.
pub async fn assert_disposable_db(pool: &PgPool) {
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await
        .expect("query current_database()");

    if db_is_disposable(&db) || std::env::var(DESTRUCTIVE_OPT_IN).as_deref() == Ok("1") {
        return;
    }

    panic!(
        "refusing to run destructive claim fixtures against database {db:?}.\n\
         These tests DROP the uq_claims_content_hash_agent constraint and run a \
         table-wide dedup DELETE on `claims`.\n\
         Point DATABASE_URL at a scratch database (e.g. epigraph_db_repo_test), or \
         set {DESTRUCTIVE_OPT_IN}=1 if {db:?} really is disposable."
    );
}

pub async fn try_test_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .ok()?;
    assert_disposable_db(&pool).await;
    sqlx::migrate!("../../migrations").run(&pool).await.ok()?;
    Some(pool)
}

#[macro_export]
macro_rules! test_pool_or_skip {
    () => {{
        match $crate::common::try_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping DB test: DATABASE_URL not set or unreachable");
                return;
            }
        }
    }};
}

/// Drop the (content_hash, agent_id) UNIQUE constraint to exercise the
/// pre-107 fixture path.
pub async fn drop_unique_constraint(pool: &PgPool) {
    sqlx::query("ALTER TABLE claims DROP CONSTRAINT IF EXISTS uq_claims_content_hash_agent")
        .execute(pool)
        .await
        .expect("drop constraint");
}

/// Add the (content_hash, agent_id) UNIQUE constraint, deduping any
/// existing duplicate rows first. Postgres has no `ADD CONSTRAINT IF NOT
/// EXISTS`, so the DO block swallows the already-present cases.
///
/// # `duplicate_table` is not optional, and it is not the same as
/// `duplicate_object`
///
/// MEASURED when `claim_helper_tests.rs` moved to `#[sqlx::test]`:
/// `helper_post_107_idempotent` failed with `42P07 relation
/// "uq_claims_content_hash_agent" already exists`, which is `duplicate_table`
/// — Postgres reports the collision against the constraint's backing INDEX, not
/// against the constraint — while the handler named only `duplicate_object`
/// (`42710`). On the old shared database this never fired, because an earlier
/// arm had always just DROPPED the constraint. On a freshly-migrated database
/// migration 013 has already created it, so the ADD raises 42P07 EVERY time and
/// the swallow is the normal path rather than the fallback.
/// `epigraph-db/tests/claim_repo_helpers.rs` hit and fixed this first; this is
/// the same fix, and the divergence between the two copies is exactly the class
/// that made it survive.
///
/// # Why the post-condition is asserted rather than trusted
///
/// Because the ADD now always raises and is always caught, a future edit that
/// renamed the constraint, named the wrong columns or targeted the wrong table
/// would be swallowed identically, and every post-107 arm would go on asserting
/// `DuplicateKey` against whatever migration 013 happens to provide. Reading
/// `pg_constraint` makes the fixture prove the precondition it claims.
pub async fn add_unique_constraint(pool: &PgPool) {
    sqlx::query(
        "DELETE FROM claims a USING claims b
         WHERE a.ctid > b.ctid
           AND a.content_hash = b.content_hash
           AND a.agent_id = b.agent_id",
    )
    .execute(pool)
    .await
    .expect("dedup before constraint");

    sqlx::query(
        r#"DO $$ BEGIN
              ALTER TABLE claims ADD CONSTRAINT uq_claims_content_hash_agent
                  UNIQUE (content_hash, agent_id);
           EXCEPTION WHEN duplicate_object OR duplicate_table THEN NULL;
           END $$"#,
    )
    .execute(pool)
    .await
    .expect("add constraint");

    let present: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_constraint
         WHERE conname = 'uq_claims_content_hash_agent'
           AND conrelid = 'claims'::regclass",
    )
    .fetch_one(pool)
    .await
    .expect("inspect pg_constraint");
    assert_eq!(
        present, 1,
        "post-107 fixture requires uq_claims_content_hash_agent on `claims`"
    );
}

pub async fn insert_test_agent(pool: &PgPool, agent_id: Uuid) {
    sqlx::query(
        r#"INSERT INTO agents (id, public_key, created_at, updated_at)
           VALUES ($1, sha256($1::text::bytea), NOW(), NOW())
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("upsert agent");
}

pub fn make_claim(content: &str, agent_id: Uuid) -> Claim {
    Claim::new(
        content.to_string(),
        AgentId::from_uuid(agent_id),
        [0u8; 32],
        TruthValue::new(0.5).unwrap(),
    )
}

// ── Additional helpers for workflow/claim/edge seeding and MCP server ────────

use epigraph_crypto::AgentSigner;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::EpiGraphMcpFull;
use rmcp::model::CallToolResult;
use serde_json::Value;

/// A server whose signer identity is DECLARED — the fixed key stands in for
/// `--agent-key`, which is what `main::select_signer` rung 3 produces. This is
/// the strict-ownership configuration; `EpiGraphMcpFull::new` defaults
/// `signer_identity_declared` to `true`.
pub fn build_test_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0xA7u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, /* read_only */ false)
}

/// [`build_test_server`] plus the [`epigraph_db::ScopedPool`] that the canonical
/// write path now REQUIRES.
///
/// # Why a second constructor rather than changing the first
///
/// `submit_claim`, `memorize`, `batch_submit_claims` and `resolve_backlog_item`
/// run their claim + trace + evidence + `update_trace_id` in ONE transaction
/// stamped from the author's viewer, and `ScopedPool::begin_as` is the only thing
/// that can open one. A server with no `ScopedPool` REFUSES those tools outright,
/// deliberately — falling back to the unstamped pool is how a `42501` on
/// `reasoning_traces` becomes a committed claim with no provenance. So a write
/// test needs this; a read test does not, and making the ~230 `build_test_server`
/// call sites async to give every one of them a pool they will not use would be
/// churn with a running cost (each `ScopedPool::connect` opens its own
/// connections).
///
/// # Why `scoped` is a PARAMETER and not built in here
///
/// The pool has to come from `fixture::scoped_pool`, and this module cannot reach
/// it. Two routes were tried and both are worse:
///
/// * `#[path]`-including the canonical fixture here as well — MEASURED to fail
///   `clippy::duplicate_mod` under `-D warnings`, because every test binary that
///   uses this helper also declares its own `mod fixture;` over the same file
///   ("file is loaded as a module multiple times").
/// * `crate::fixture::scoped_pool` — `mod fixture;` is declared per test BINARY,
///   so this would compile in some binaries and not others, and the error would
///   surface in THIS file rather than in the test that forgot the declaration.
///
/// Passing it in keeps the derivation single-sourced in the canonical fixture and
/// makes each call site say where its pool came from:
///
/// ```ignore
/// let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
/// ```
/// # The pool is attached TWICE, and both are load-bearing
///
/// `EpiGraphMcpFull::with_scoped_pool` is what lets the claim write stamp a
/// transaction; `McpEmbedder::with_scoped_pool` is what lets the post-commit
/// embed stamp a connection. A server with the first and not the second writes
/// claims correctly and embeds NONE of them, silently, because the embed is
/// best-effort — which is the release gate this branch exists to close. Both are
/// given the same pool here (`ScopedPool` is `Clone`, and the clone shares the
/// underlying `PgPool`, so this opens no extra connections).
pub fn build_scoped_test_server(pool: PgPool, scoped: epigraph_db::ScopedPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0xA7u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(pool, signer, embedder, /* read_only */ false).with_scoped_pool(scoped)
}

/// [`build_test_server_generated_signer`] plus a `ScopedPool`. See
/// [`build_scoped_test_server`] for why the scoped variant exists and why the
/// pool is a parameter.
pub fn build_scoped_test_server_generated_signer(
    pool: PgPool,
    scoped: epigraph_db::ScopedPool,
) -> EpiGraphMcpFull {
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(pool, signer, embedder, /* read_only */ false)
        .with_generated_signer_identity()
        .with_scoped_pool(scoped)
}

/// A server in `main::select_signer`'s rung-4 configuration: neither
/// `--agent-key` nor `--agent-model` was supplied, so the signer is a fresh
/// random keypair belonging to this process alone. Both halves matter — the
/// random signer reproduces the throwaway agent UUID, and
/// `with_generated_signer_identity` is the bit `main` sets on that rung.
///
/// This is what epiclaw agent containers run: the agent-runner spawns
/// `epigraph-mcp --database-url <url>` over stdio with no key.
pub fn build_test_server_generated_signer(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, /* read_only */ false)
        .with_generated_signer_identity()
}

pub async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) \
         VALUES ($1, $2, 'system') ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed agent");
    id
}

/// Resolve `owner`'s personal group, minting it and the owner's live membership
/// if absent, and return its id.
///
/// This is migration 071's fallback arm, lifted into a fixture. Until PR-22 the
/// tests below reached it by writing a `partition_type = 'private'` row into
/// `ownership` and letting the `ownership_transcribe` trigger resolve-or-mint
/// the group and stamp the claim. Migration 084 retires that table, so the
/// fixture does both halves itself.
///
/// **Two ways to identify a personal group, and both are needed.** The canonical
/// one is the deterministic `did:epigraph:personal:<agent uuid>` key, but the
/// semantics are `kind = 'personal'` created by this agent, and
/// `tests/viewer_fixture.rs::seed_agent_with_group` mints one under a
/// `did:epigraph:test:` key instead. **The membership targets the composite
/// `(group_id, agent_id, epoch)` and REVIVES**, because an untargeted
/// `DO NOTHING` no-ops against a revoked row and leaves the agent with no live
/// membership in its own personal group.
pub async fn personal_group_of(pool: &PgPool, owner: Uuid) -> Uuid {
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM groups \
          WHERE (did_key = 'did:epigraph:personal:' || $1::text) \
             OR (kind = 'personal' AND created_by_agent_id = $1) \
          ORDER BY (did_key = 'did:epigraph:personal:' || $1::text) DESC, created_at ASC \
          LIMIT 1",
    )
    .bind(owner)
    .fetch_optional(pool)
    .await
    .expect("resolve personal group");

    let group = match existing {
        Some(g) => g,
        None => sqlx::query_scalar(
            "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) \
             VALUES ('personal:' || $1::text, 'did:epigraph:personal:' || $1::text, \
                     ''::bytea, 'personal', $1) \
             ON CONFLICT (did_key) DO UPDATE SET updated_at = now() RETURNING id",
        )
        .bind(owner)
        .fetch_one(pool)
        .await
        .expect("mint personal group"),
    };

    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'admin') \
         ON CONFLICT (group_id, agent_id, epoch) \
         DO UPDATE SET revoked_at = NULL, role = 'admin'",
    )
    .bind(group)
    .bind(owner)
    .execute(pool)
    .await
    .expect("revive personal group membership");

    group
}

/// Make `claim_id` readable only by `owner`'s personal group, and CHECK that it
/// landed.
///
/// The read-back is not decoration. Every caller asserts that a STRANGER sees
/// less, and a fixture that silently failed to privatise the row would leave all
/// of them green while testing nothing — the failure mode is invisible in
/// exactly the tests that exist to catch it.
pub async fn seed_private_tenancy(pool: &PgPool, claim_id: Uuid, owner: Uuid) -> Uuid {
    let group = personal_group_of(pool, owner).await;
    stamp_group_private(pool, claim_id, group).await;
    group
}

/// `UPDATE claims SET visibility = 'group', owner_group_id = $2`, with the
/// post-condition asserted. See [`seed_private_tenancy`] for why.
pub async fn stamp_group_private(pool: &PgPool, claim_id: Uuid, group: Uuid) {
    sqlx::query("UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(claim_id)
        .bind(group)
        .execute(pool)
        .await
        .expect("stamp the claim group-private");

    let got: Option<(String, Uuid)> =
        sqlx::query_as("SELECT visibility, owner_group_id FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_optional(pool)
            .await
            .expect("read the stamped claim back");
    assert_eq!(
        got,
        Some(("group".to_string(), group)),
        "the fixture must leave claim {claim_id} at ('group', {group}); a \
         mis-stamped fixture makes every absence assertion vacuous"
    );
}

pub async fn seed_claim(pool: &PgPool, content: &str, truth: f64) -> Uuid {
    let agent = seed_agent(pool).await;
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels) \
         VALUES ($1, $2, $3, $4, $5, true, ARRAY[]::text[])",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(truth)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// Seed a claim with explicit DST belief-measure fields.
///
/// Used by `update_with_evidence_plausibility_one.rs` (issue #139 regression):
/// the test needs to plant a claim at `plausibility = 1.0` so that any
/// post-evidence drift above 1.0 trips `claims_plausibility_bounds`. The
/// standard `seed_claim` helper leaves these columns at their defaults.
///
/// Returns the new claim's UUID. Reuses `seed_agent`'s test-signer pattern.
pub async fn seed_claim_with_belief(
    pool: &PgPool,
    belief: f64,
    plausibility: f64,
    pignistic_prob: Option<f64>,
) -> Uuid {
    let agent_id = seed_agent(pool).await;
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims \
            (id, content, content_hash, agent_id, truth_value, \
             belief, plausibility, pignistic_prob, is_current, labels) \
         VALUES ($1, $2, $3, $4, 0.5, $5, $6, $7, true, ARRAY[]::text[])",
    )
    .bind(id)
    .bind(format!("seed_claim_with_belief regression {id}"))
    .bind(&hash)
    .bind(agent_id)
    .bind(belief)
    .bind(plausibility)
    .bind(pignistic_prob)
    .execute(pool)
    .await
    .expect("seed claim with belief");
    id
}

pub async fn seed_claim_with_labels(pool: &PgPool, content: &str, labels: &[&str]) -> Uuid {
    let id = seed_claim(pool, content, 0.5).await;
    let labels_owned: Vec<String> = labels.iter().map(|s| (*s).to_string()).collect();
    sqlx::query("UPDATE claims SET labels = $1 WHERE id = $2")
        .bind(&labels_owned)
        .bind(id)
        .execute(pool)
        .await
        .expect("set labels");
    id
}

pub async fn seed_workflow_claim(pool: &PgPool, goal: &str, steps: &[&str]) -> Uuid {
    let agent = seed_agent(pool).await;
    let id = Uuid::new_v4();
    let content = format!("{goal}\n{}", steps.join("\n"));
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    let props = serde_json::json!({
        "goal": goal, "steps": steps, "generation": 0,
        "use_count": 0, "success_count": 0, "failure_count": 0, "avg_variance": 0.0,
    });
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels, properties) \
         VALUES ($1, $2, $3, 0.5, $4, true, ARRAY['workflow']::text[], $5)",
    )
    .bind(id)
    .bind(&content)
    .bind(&hash)
    .bind(agent)
    .bind(&props)
    .execute(pool)
    .await
    .expect("seed workflow claim");
    id
}

pub async fn insert_claim_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', $3, '{}'::jsonb)",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("insert edge");
}

pub fn first_text(result: &CallToolResult) -> Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("at least one text content block");
    serde_json::from_str(&text).expect("valid JSON")
}

pub fn parse_uuid_field(json: &Value, key: &str) -> Uuid {
    json.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("missing field {key} in {json}"))
        .parse()
        .expect("valid UUID")
}

/// THIS SERVER's own agent holding a `claims:admin` token, with the viewer the
/// request would have resolved for it (batch H-b, D1).
///
/// `admin_auth()` above carries no `agent_id`, and since D1 a write tool
/// refuses such a token — it has no author, exactly as `request_viewer`
/// refuses it no reader — so a test that needs an admin CALLER needs one with
/// an `agents.id` and a matching viewer. The server's own agent is the
/// cheapest real one: `agent_id()` has already provisioned its personal group.
pub async fn server_admin(
    server: &epigraph_mcp::EpiGraphMcpFull,
) -> (AuthContext, epigraph_db::visibility::Viewer) {
    let agent = server.server_agent_id().await.expect("server agent");
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("the server agent's viewer");
    (
        AuthContext {
            client_id: Uuid::new_v4(),
            agent_id: Some(agent),
            owner_id: None,
            client_type: ClientType::Service,
            scopes: vec!["claims:admin".to_string()],
            jti: Uuid::new_v4(),
        },
        viewer,
    )
}

/// A real agent with a live personal group, a `claims:write`-style token that
/// names it the way `oauth/token.rs` does (`sub`/`owner_id` are
/// `oauth_clients` ids, only `agent_id` is an `agents.id`), and its viewer.
pub async fn seed_caller(
    pool: &PgPool,
    scopes: &[&str],
) -> (Uuid, AuthContext, epigraph_db::visibility::Viewer) {
    let agent = seed_agent(pool).await;
    personal_group_of(pool, agent).await;
    let viewer = epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("caller viewer");
    (
        agent,
        AuthContext {
            client_id: Uuid::new_v4(),
            agent_id: Some(agent),
            owner_id: Some(Uuid::new_v4()),
            client_type: ClientType::Agent,
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            jti: Uuid::new_v4(),
        },
        viewer,
    )
}
