//! Qual/GUC coherence: the group set a `Viewer` binds as `$V` and the group set
//! the database sees in `epigraph.group_ids` are the same set (plan §4.5).
//!
//! # Why this property, and why it needs a test rather than a comment
//!
//! The in-query predicate (`Viewer::predicate_fragment`) and the RLS policy
//! (migration 077) are two independent filters over the same rows, populated by
//! two different code paths: `Viewer::resolve` → the `$V` bind, and `ScopedPool`
//! → `set_config`. If they drift, RLS silently drops rows the index already
//! returned. That failure is **fail-closed and invisible** — indistinguishable
//! from data loss, and it passes every adversarial test written as "assert a
//! stranger CANNOT read".
//!
//! The mechanism that makes the property hold is structural, not procedural:
//! `apply_session_gucs` is private, takes the `&Viewer` itself, and has exactly
//! two callers (`acquire_as`, `begin_as`). These tests pin the observable half.
//!
//! # Why every test takes `(PgPoolOptions, PgConnectOptions)`
//!
//! `ScopedPool::connect` must own pool construction — `PgPoolOptions::after_release`,
//! the release scrub, can only be installed at build time — so a `ScopedPool`
//! cannot be made from the `PgPool` that `#[sqlx::test]` normally injects.
//! sqlx 0.8.6 offers exactly four `TestFn` shapes (`sqlx-core/src/testing/mod.rs:86-140`)
//! and `(PoolOptions, ConnectOptions)` is the only one that exposes where the
//! per-test database lives. Migrations still run for this shape
//! (`run_test` → `setup_test_db`), so these tests see the same schema as every
//! other `#[sqlx::test]` in the workspace.
//!
//! # `Viewer::test_scoped` is not reachable from here
//!
//! It is `#[cfg(test)]` on the DEFINITION (deliberately — a cargo feature can be
//! switched on from a dependent crate's build graph), and integration tests link
//! the lib compiled *without* `cfg(test)`. Every viewer below is therefore built
//! through `Viewer::resolve` against seeded rows, which is the more honest
//! fixture anyway: it exercises the real constructor.
//!
//! # PR-17: what "under FORCE" means here, and where it is asserted
//!
//! The plan's PR-17 *Tests* line asks that this file run under `FORCE`. Two
//! different things could mean, and only one of them is a real strengthening:
//!
//! * **Schema-level** — every `#[sqlx::test(migrations = "../../migrations")]`
//!   here now provisions a database at head, so the schema carries 077's
//!   policies and 079's `FORCE`. That happened for free and proves nothing on
//!   its own.
//! * **Role-level** — the session is one the policies actually FILTER.
//!   `#[sqlx::test]` connects as `epigraph`, which is superuser, `BYPASSRLS` and
//!   the table owner, so **no assertion on the default session is affected by a
//!   policy at all**. Most of this file is unaffected by that, because GUC
//!   plumbing is role-independent: `set_config` and `current_setting` behave
//!   identically for any role, so those tests are complete as they stand.
//!
//! The half that is NOT role-independent is the coherence claim itself — that
//! the group set `$V` binds and the group set the RLS policy reads are the same
//! set. That one is only observable on a filtered session, and
//! `the_guc_and_the_policy_agree_on_a_filtered_session` below is where it is
//! asserted, via `SET SESSION AUTHORIZATION epigraph_app`.
//!
//! # What is deliberately NOT here
//!
//! Plan §4.5's fourth bullet — the POSITIVE class, "with FORCE on, a `Scoped`
//! viewer reads back exactly its own N group-private rows through each of the 17
//! `claim.rs` read functions" — is not in this file. It belongs to PR-06
//! (`tenant_isolation.rs`) and to `rls_enforcement.rs`. Note also that the
//! plan's "17" is wrong: it is the count of claim-derived TABLES elsewhere in
//! the plan. Measured by brace-matching the `#[cfg(test)]` boundary,
//! `repos/claim.rs` has 81 `pub fn` before the test module, 57 of which take a
//! `Viewer`, of which 55 are reads. The unit that actually governs them all is
//! ONE policy, `claims_tenancy`, which is why `rls_enforcement.rs` asserts at
//! the policy level.

use epigraph_db::{
    repos::AgentRepository, DbError, ScopedPool, ScopedPoolOptions, SessionGucMode, SystemReason,
    Viewer,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Executor, PgPool};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

/// The two pools each test needs: a plain one for seeding, and the `ScopedPool`
/// under test.
struct Env {
    pool: PgPool,
    scoped: ScopedPool,
}

/// The connection URL for the temporary database `#[sqlx::test]` provisioned.
///
/// The ambient `DATABASE_URL` supplies the authority and credentials;
/// `PgConnectOptions::get_database` supplies the per-test database name.
fn scoped_url(opts: &PgConnectOptions) -> String {
    let base = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set to run epigraph-db's database tests");
    let db = opts
        .get_database()
        .expect("#[sqlx::test] always names a database");

    // Strip any query string before touching the path, or `?sslmode=require`
    // would be mistaken for part of the database name.
    let (authority, query) = match base.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (base.as_str(), None),
    };
    let prefix = authority
        .trim_end_matches('/')
        .rsplit_once('/')
        .expect("DATABASE_URL must carry a database path")
        .0;

    match query {
        Some(q) => format!("{prefix}/{db}?{q}"),
        None => format!("{prefix}/{db}"),
    }
}

async fn env(pool_opts: PgPoolOptions, conn_opts: PgConnectOptions, mode: SessionGucMode) -> Env {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let scoped = ScopedPool::connect(&scoped_url(&conn_opts), mode)
        .await
        .expect("ScopedPool::connect");
    Env { pool, scoped }
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_group(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, did_key, public_key, kind, display_name) \
         VALUES ($1, $2, $3, 'team', 'qual-guc-test')",
    )
    .bind(id)
    .bind(format!("did:key:qual-guc-{id}"))
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed group");
    id
}

async fn seed_membership(pool: &PgPool, group_id: Uuid, agent_id: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, $3, 0, $4)",
    )
    .bind(group_id)
    .bind(agent_id)
    .bind(vec![0u8; 48])
    .bind(role)
    .execute(pool)
    .await
    .expect("seed membership");
}

fn sorted(mut v: Vec<Uuid>) -> Vec<Uuid> {
    v.sort_unstable();
    v
}

// ---------------------------------------------------------------------------
// 1 & 2 — the group GUC equals the viewer's bind, under both mechanisms
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn acquire_as_sets_the_group_gucs_from_the_same_viewer(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let Env { pool, scoped } = env(pool_opts, conn_opts, SessionGucMode::Session).await;

    let agent = seed_agent(&pool).await;
    let mut groups = Vec::new();
    for _ in 0..3 {
        let g = seed_group(&pool).await;
        seed_membership(&pool, g, agent, "writer").await;
        groups.push(g);
    }

    let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");
    let mut conn = scoped.acquire_as(&viewer).await.expect("acquire_as");

    let (observed,): (Vec<Uuid>,) = sqlx::query_as("SELECT epigraph_session_groups()")
        .fetch_one(&mut *conn)
        .await
        .expect("epigraph_session_groups()");

    assert_eq!(
        sorted(observed),
        sorted(groups.clone()),
        "the GUC the RLS policy reads must hold exactly the set the viewer binds as $V"
    );
    assert_eq!(
        sorted(viewer.group_bind().expect("scoped").to_vec()),
        sorted(groups)
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn begin_as_sets_the_group_gucs_transaction_locally(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let Env { pool, scoped } = env(pool_opts, conn_opts, SessionGucMode::Session).await;

    let agent = seed_agent(&pool).await;
    let g1 = seed_group(&pool).await;
    let g2 = seed_group(&pool).await;
    seed_membership(&pool, g1, agent, "admin").await;
    seed_membership(&pool, g2, agent, "reader").await;

    let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");
    let mut tx = scoped.begin_as(&viewer).await.expect("begin_as");

    let (observed,): (Vec<Uuid>,) = sqlx::query_as("SELECT epigraph_session_groups()")
        .fetch_one(&mut *tx)
        .await
        .expect("epigraph_session_groups()");
    assert_eq!(sorted(observed), sorted(vec![g1, g2]));

    tx.rollback().await.expect("rollback");
}

// ---------------------------------------------------------------------------
// 3 — the writable GUC is the *narrower* set
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn writable_gucs_match_the_viewers_writable_set(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let Env { pool, scoped } = env(pool_opts, conn_opts, SessionGucMode::Session).await;

    let agent = seed_agent(&pool).await;
    let writer = seed_group(&pool).await;
    let admin = seed_group(&pool).await;
    let reader = seed_group(&pool).await;
    seed_membership(&pool, writer, agent, "writer").await;
    seed_membership(&pool, admin, agent, "admin").await;
    seed_membership(&pool, reader, agent, "reader").await;

    let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");
    let mut conn = scoped.acquire_as(&viewer).await.expect("acquire_as");

    let (readable,): (Vec<Uuid>,) = sqlx::query_as("SELECT epigraph_session_groups()")
        .fetch_one(&mut *conn)
        .await
        .expect("epigraph_session_groups()");
    let (writable,): (Vec<Uuid>,) = sqlx::query_as("SELECT epigraph_writable_groups()")
        .fetch_one(&mut *conn)
        .await
        .expect("epigraph_writable_groups()");

    assert_eq!(sorted(readable), sorted(vec![writer, admin, reader]));
    assert_eq!(
        sorted(writable.clone()),
        sorted(vec![writer, admin]),
        "a `reader` membership grants read authority and NOT write authority; \
         every WITH CHECK in migration 077 reads the second array"
    );
    assert!(
        !writable.contains(&reader),
        "the reader group must not reach the writable GUC"
    );
    assert_eq!(
        sorted(writable),
        sorted(viewer.writable_groups().to_vec()),
        "the GUC and the Viewer must agree"
    );
}

// ---------------------------------------------------------------------------
// 4 — the principal GUC
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn principal_guc_round_trips(pool_opts: PgPoolOptions, conn_opts: PgConnectOptions) {
    let Env { pool, scoped } = env(pool_opts, conn_opts, SessionGucMode::Session).await;

    let agent = seed_agent(&pool).await;
    let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");
    let mut conn = scoped.acquire_as(&viewer).await.expect("acquire_as");

    let (observed,): (Option<Uuid>,) = sqlx::query_as("SELECT epigraph_principal_id()")
        .fetch_one(&mut *conn)
        .await
        .expect("epigraph_principal_id()");

    assert_eq!(observed, viewer.principal());
    assert_eq!(observed, Some(agent));
}

// ---------------------------------------------------------------------------
// 5 — THE SCRUB. The one failure mode that would be a cross-tenant read.
// ---------------------------------------------------------------------------

/// A leaked group set on a recycled connection is the single failure mode in
/// this design that reads as *another tenant's data*, rather than as an empty
/// result. Every other failure here is fail-closed.
///
/// The assertion does not depend on the pool actually reusing the backend: if
/// the scrub failed and the connection was closed instead, the fresh checkout is
/// a fresh backend and the GUCs are empty for that reason too. Both outcomes are
/// correct; a non-empty group set is the only failure.
#[sqlx::test(migrations = "../../migrations")]
async fn a_released_connection_carries_no_tenancy_into_the_next_checkout(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let Env { pool, scoped } = env(pool_opts, conn_opts, SessionGucMode::Session).await;

    let agent = seed_agent(&pool).await;
    let g = seed_group(&pool).await;
    seed_membership(&pool, g, agent, "admin").await;

    let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");

    {
        let mut conn = scoped.acquire_as(&viewer).await.expect("acquire_as");
        let (observed,): (Vec<Uuid>,) = sqlx::query_as("SELECT epigraph_session_groups()")
            .fetch_one(&mut *conn)
            .await
            .expect("epigraph_session_groups()");
        assert_eq!(observed, vec![g], "precondition: the stamp took effect");
    } // release -> after_release scrub

    // A PLAIN acquire, with no `acquire_as`. This is the shape of every call
    // site that has not been migrated to the scoped API yet.
    let mut plain = scoped
        .inner()
        .acquire()
        .await
        .expect("plain acquire from the same pool");

    let (groups,): (Vec<Uuid>,) = sqlx::query_as("SELECT epigraph_session_groups()")
        .fetch_one(&mut *plain)
        .await
        .expect("epigraph_session_groups()");
    let (writable,): (Vec<Uuid>,) = sqlx::query_as("SELECT epigraph_writable_groups()")
        .fetch_one(&mut *plain)
        .await
        .expect("epigraph_writable_groups()");
    let (principal,): (Option<Uuid>,) = sqlx::query_as("SELECT epigraph_principal_id()")
        .fetch_one(&mut *plain)
        .await
        .expect("epigraph_principal_id()");

    assert!(
        groups.is_empty(),
        "a recycled connection carried a previous principal's group set: {groups:?}. \
         This is the one failure mode in this design that reads as ANOTHER TENANT'S DATA \
         rather than as an empty result."
    );
    assert!(writable.is_empty(), "leaked writable set: {writable:?}");
    assert_eq!(principal, None, "leaked principal: {principal:?}");
}

/// The boot probe itself, which is what `bin/server.rs` `.expect()`s. Against a
/// session-mode endpoint it must pass; the negative half (a transaction-mode
/// pooler) cannot be staged in this environment — see `docs/deploy.md`'s PR-04
/// section, and M5 in the plan's blocked measurements.
#[sqlx::test(migrations = "../../migrations")]
async fn probe_session_gucs_passes_against_a_session_mode_endpoint(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let Env { scoped, .. } = env(pool_opts, conn_opts, SessionGucMode::Session).await;
    scoped
        .probe_session_gucs()
        .await
        .expect("the local cluster is a session-mode endpoint; the probe must pass");
}

// ---------------------------------------------------------------------------
// 6, 7, 9 — the bypass boundary and the mode switch
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn acquire_as_refuses_a_bypass_viewer(pool_opts: PgPoolOptions, conn_opts: PgConnectOptions) {
    let Env { scoped, .. } = env(pool_opts, conn_opts, SessionGucMode::Session).await;

    let (_conn, lease) = scoped
        .unscoped_for_maintenance(SystemReason::SchemaContractTest)
        .await
        .expect("unscoped_for_maintenance");
    let bypass = Viewer::system(&lease, SystemReason::SchemaContractTest);

    let err = scoped
        .acquire_as(&bypass)
        .await
        .expect_err("a Bypass viewer must not be servable by acquire_as");

    match err {
        DbError::InvalidData { reason } => assert!(
            reason.contains("unscoped_for_maintenance"),
            "the error must name the path a bypass belongs on; got: {reason}"
        ),
        other => panic!("expected DbError::InvalidData, got {other:?}"),
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn unscoped_for_maintenance_mints_a_lease_and_a_bypass_viewer(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let Env { scoped, .. } = env(pool_opts, conn_opts, SessionGucMode::Session).await;

    let (mut conn, lease) = scoped
        .unscoped_for_maintenance(SystemReason::EmbeddingBackfill)
        .await
        .expect("unscoped_for_maintenance");

    // The connection works and carries no tenancy context.
    let (groups,): (Vec<Uuid>,) = sqlx::query_as("SELECT epigraph_session_groups()")
        .fetch_one(&mut *conn)
        .await
        .expect("epigraph_session_groups()");
    assert!(
        groups.is_empty(),
        "a maintenance connection is UNSTAMPED, not stamped with everything"
    );

    let v = Viewer::system(&lease, SystemReason::EmbeddingBackfill);
    assert!(v.is_bypass());
    assert_eq!(v.group_bind(), None, "a bypass viewer supplies no $V bind");
    assert_eq!(v.principal(), None);
    assert_eq!(v.bypass_reason(), Some(SystemReason::EmbeddingBackfill));
    assert_eq!(
        v.predicate_fragment(),
        " ",
        "a bypass viewer emits no predicate"
    );
}

/// `epigraph_bypass()` is TOTAL: it answers, it never raises.
///
/// This is the `EXISTS (SELECT 1 FROM pg_roles …)` guard in migration 067.
/// Migration 060 creates `epigraph_maintenance` under a guard that swallows
/// `insufficient_privilege`, so on managed Postgres the role may not exist at
/// all. Without the `EXISTS`, `pg_has_role` raises **42704** — and every RLS
/// policy in migration 077 calls this function, so every query against a
/// policy-bearing table would error instead of filtering. That is a
/// whole-database outage wearing a permissions bug's clothes.
///
/// **What this test does NOT assert is that the answer is `false`.** It is not,
/// here: the test cluster connects as a superuser, and a superuser is
/// `pg_has_role`-a-member of every role in the cluster. Asserting `false` would
/// pin an accident of the local fixture rather than the property. What is pinned
/// is that the function agrees with the predicate its body claims to compute.
#[sqlx::test(migrations = "../../migrations")]
async fn epigraph_bypass_is_total_and_agrees_with_pg_has_role(pool: PgPool) {
    let (bypass,): (bool,) = sqlx::query_as("SELECT epigraph_bypass()")
        .fetch_one(&pool)
        .await
        .expect("epigraph_bypass() must not raise, whether or not the role exists");

    // `session_user`, NOT `current_user`: inside a SECURITY DEFINER frame
    // `current_user` is the function owner, which is the escalation the security
    // review flagged. Recomputing the predicate here is how a body edited to use
    // `current_user` gets caught.
    let (expected,): (bool,) = sqlx::query_as(
        "SELECT COALESCE((SELECT pg_has_role(session_user, 'epigraph_maintenance', 'MEMBER') \
                            WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance')), \
                         false)",
    )
    .fetch_one(&pool)
    .await
    .expect("reference predicate");
    assert_eq!(
        bypass, expected,
        "epigraph_bypass() must be exactly `session_user is a member of \
         epigraph_maintenance, or false if that role does not exist`"
    );

    // The same totality for the `current_user` variant (sec F10). It is not the
    // same function and must not become one — it exists precisely so the two
    // notions of "who am I" stay distinguishable inside a definer frame.
    let (definer,): (bool,) = sqlx::query_as("SELECT epigraph_definer_bypass()")
        .fetch_one(&pool)
        .await
        .expect("epigraph_definer_bypass() must not raise either");
    let (definer_expected,): (bool,) = sqlx::query_as(
        "SELECT COALESCE((SELECT pg_has_role(current_user, 'epigraph_maintenance', 'MEMBER') \
                            WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance')), \
                         false)",
    )
    .fetch_one(&pool)
    .await
    .expect("reference predicate");
    assert_eq!(definer, definer_expected);

    // And the guard's absent-role branch, which the local cluster cannot stage
    // (the role exists, and dropping it is cluster-wide and would race every
    // other test database): evaluate the same shape against a role name that
    // certainly does not exist. If `EXISTS` were dropped from the body, THIS is
    // the expression that would raise 42704.
    let (absent,): (bool,) = sqlx::query_as(
        "SELECT COALESCE((SELECT pg_has_role(session_user, 'epigraph_no_such_role', 'MEMBER') \
                            WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_no_such_role')), \
                         false)",
    )
    .fetch_one(&pool)
    .await
    .expect("the EXISTS guard must short-circuit before pg_has_role sees a missing role");
    assert!(!absent);
}

#[sqlx::test(migrations = "../../migrations")]
async fn transaction_mode_rejects_acquire_as(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let Env { pool, scoped } = env(pool_opts, conn_opts, SessionGucMode::Transaction).await;

    let agent = seed_agent(&pool).await;
    let g = seed_group(&pool).await;
    seed_membership(&pool, g, agent, "writer").await;
    let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");

    assert_eq!(scoped.mode(), SessionGucMode::Transaction);

    let err = scoped
        .acquire_as(&viewer)
        .await
        .expect_err("session-scoped GUCs are unusable in transaction mode");
    match err {
        DbError::InvalidData { reason } => assert!(
            reason.contains("begin_as"),
            "the refusal must name the supported fallback; got: {reason}"
        ),
        other => panic!("expected DbError::InvalidData, got {other:?}"),
    }

    // And `begin_as` serves the same viewer.
    let mut tx = scoped.begin_as(&viewer).await.expect("begin_as");
    let (observed,): (Vec<Uuid>,) = sqlx::query_as("SELECT epigraph_session_groups()")
        .fetch_one(&mut *tx)
        .await
        .expect("epigraph_session_groups()");
    assert_eq!(observed, vec![g]);
    tx.rollback().await.expect("rollback");
}

// ---------------------------------------------------------------------------
// The personal-group union, seen from the GUC side
// ---------------------------------------------------------------------------

/// Plan §4.3's personal-group invariant, asserted at the layer where it matters:
/// the group set the *database* sees. `no_anonymous_viewer.rs` pins it at the
/// `Viewer` layer; if only that one existed, a `ScopedPool` that dropped the
/// personal group on the way to `set_config` would pass.
#[sqlx::test(migrations = "../../migrations")]
async fn the_personal_group_reaches_the_session_gucs(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let Env { pool, scoped } = env(pool_opts, conn_opts, SessionGucMode::Session).await;

    let agent = seed_agent(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let personal = AgentRepository::ensure_personal_group(&mut conn, agent)
        .await
        .expect("ensure_personal_group");
    drop(conn);

    let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");
    let mut c = scoped.acquire_as(&viewer).await.expect("acquire_as");

    let (groups,): (Vec<Uuid>,) = sqlx::query_as("SELECT epigraph_session_groups()")
        .fetch_one(&mut *c)
        .await
        .expect("epigraph_session_groups()");
    let (writable,): (Vec<Uuid>,) = sqlx::query_as("SELECT epigraph_writable_groups()")
        .fetch_one(&mut *c)
        .await
        .expect("epigraph_writable_groups()");

    assert!(
        groups.contains(&personal),
        "the principal's own personal group must reach epigraph.group_ids"
    );
    assert!(
        writable.contains(&personal),
        "the personal-group membership is role='admin', so it is writable"
    );
}

/// `set_config`'s value is a comma-joined list, so an empty group set must
/// produce an EMPTY array — not `ARRAY['']`, which is a cast error, and not a
/// one-element array of nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn an_empty_group_set_round_trips_as_an_empty_array(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let Env { pool, scoped } = env(pool_opts, conn_opts, SessionGucMode::Session).await;

    let agent = seed_agent(&pool).await; // no memberships at all
    let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");
    assert_eq!(viewer.group_bind(), Some(&[][..]));

    let mut conn = scoped.acquire_as(&viewer).await.expect("acquire_as");

    let (groups,): (Vec<Uuid>,) = sqlx::query_as("SELECT epigraph_session_groups()")
        .fetch_one(&mut *conn)
        .await
        .expect("an empty group set must not raise a cast error");
    assert!(groups.is_empty());

    // The principal is still set: "no groups" is not "no principal".
    let (principal,): (Option<Uuid>,) = sqlx::query_as("SELECT epigraph_principal_id()")
        .fetch_one(&mut *conn)
        .await
        .expect("epigraph_principal_id()");
    assert_eq!(principal, Some(agent));
}

/// A `ScopedConn` derefs to a `PgConnection`, so ordinary sqlx calls work
/// against it unchanged — the property PR-06's incremental migration depends on.
#[sqlx::test(migrations = "../../migrations")]
async fn a_scoped_conn_is_a_usable_pg_connection(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let Env { pool, scoped } = env(pool_opts, conn_opts, SessionGucMode::Session).await;

    let agent = seed_agent(&pool).await;
    let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");
    let mut conn = scoped.acquire_as(&viewer).await.expect("acquire_as");

    conn.execute("SELECT 1").await.expect("plain execute");
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM agents WHERE id = $1")
        .bind(agent)
        .fetch_one(&mut *conn)
        .await
        .expect("query through a ScopedConn");
    assert_eq!(n, 1);
}

/// `SessionGucMode::from_env` is the only place `EPIGRAPH_SESSION_GUC_MODE` is
/// interpreted, and `bin/server.rs` passes the raw environment value straight
/// into it. A typo must NOT silently select the slow mode.
#[test]
fn session_guc_mode_from_env_only_accepts_transaction() {
    assert_eq!(SessionGucMode::from_env(""), SessionGucMode::Session);
    assert_eq!(SessionGucMode::from_env("session"), SessionGucMode::Session);
    assert_eq!(
        SessionGucMode::from_env("tranaction"),
        SessionGucMode::Session
    );
    assert_eq!(
        SessionGucMode::from_env("transaction"),
        SessionGucMode::Transaction
    );
    assert_eq!(
        SessionGucMode::from_env("  TRANSACTION \n"),
        SessionGucMode::Transaction
    );
}

// ---------------------------------------------------------------------------
// PR-17 — the coherence claim on a session the policies actually FILTER
// ---------------------------------------------------------------------------

/// The group set `$V` binds and the group set the RLS policy reads are the same
/// set, asserted where that can fail: on a non-owner, non-`BYPASSRLS` session.
///
/// Every other test in this file runs on the `#[sqlx::test]` connection, which
/// is `epigraph` — superuser, `BYPASSRLS`, and the owner of `claims`. A policy
/// filters none of those, so those tests establish the GUC plumbing (which is
/// role-independent and genuinely is what they are for) and nothing about
/// enforcement. Switching `session_user` is the only lever available:
/// `epigraph_app` is `NOLOGIN` (migration 060) so there is no second DSN, and
/// `SET ROLE` would change only `current_user` while `epigraph_bypass()` keys on
/// `session_user`.
///
/// The ORDER of the two statements is load-bearing. `acquire_as` stamps the GUCs
/// first; `SET SESSION AUTHORIZATION` then changes the role WITHOUT clearing
/// them, because GUCs are session state and a role change is not a reset. That
/// is what lets one connection carry a real viewer's group set into a filtered
/// role — and it is also the honest simulation of what step 11d produces.
///
/// Three assertions, and the middle one is the calibration: without it, a policy
/// that returned nothing to anybody would satisfy the third.
#[sqlx::test(migrations = "../../migrations")]
async fn the_guc_and_the_policy_agree_on_a_filtered_session(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let Env { pool, scoped } = env(pool_opts, conn_opts, SessionGucMode::Session).await;

    let agent = seed_agent(&pool).await;
    let mine = seed_group(&pool).await;
    seed_membership(&pool, mine, agent, "admin").await;
    let theirs = seed_group(&pool).await; // no membership for `agent`

    let my_claim = seed_group_claim(&pool, agent, mine).await;
    let their_claim = seed_group_claim(&pool, agent, theirs).await;

    let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");
    let mut c = scoped.acquire_as(&viewer).await.expect("acquire_as");

    // Migration 077 issues the app-role grants itself; NOT re-granting here is
    // deliberate, because it makes this test depend on the migration rather
    // than on a fixture that would paper over a missing grant.
    c.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("SET SESSION AUTHORIZATION requires a superuser connection");

    let (gucs,): (Vec<Uuid>,) = sqlx::query_as("SELECT epigraph_session_groups()")
        .fetch_one(&mut *c)
        .await
        .expect("epigraph_session_groups() after the role switch");
    let visible_mine: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = $1")
        .bind(my_claim)
        .fetch_one(&mut *c)
        .await
        .expect("read my own group-private claim");
    let visible_theirs: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = $1")
        .bind(their_claim)
        .fetch_one(&mut *c)
        .await
        .expect("read a claim in a group I am not in");
    let bypass: bool = sqlx::query_scalar("SELECT epigraph_bypass()")
        .fetch_one(&mut *c)
        .await
        .expect("epigraph_bypass()");

    c.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");

    assert!(
        !bypass,
        "CALIBRATION: this session must NOT hold bypass, or every assertion below passes \
         vacuously — which is the failure mode the whole file's header warns about"
    );
    assert!(
        sorted(gucs.clone()).contains(&mine),
        "the viewer's group must still be in epigraph.group_ids after the role switch; \
         got {gucs:?}"
    );
    assert_eq!(
        visible_mine, 1,
        "COHERENCE: the group the viewer bound as $V is in the GUC, so claims_tenancy must \
         admit that group's private claim. Zero here means the qual and the policy disagree — \
         the fail-closed drift this file exists to catch, indistinguishable from data loss."
    );
    assert_eq!(
        visible_theirs, 0,
        "the other direction of the same claim: a group NOT in the GUC must be filtered, or \
         the policy is admitting more than $V would"
    );
}

/// Seed a `visibility = 'group'` claim owned by `group`.
async fn seed_group_claim(pool: &PgPool, agent: Uuid, group: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             is_current, visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.8, $4, true, 'group', $5)",
    )
    .bind(id)
    .bind(format!("qual-guc claim {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed group claim");
    id
}

// ---------------------------------------------------------------------------
// `ScopedPool::read_as` — the mode-dispatch helper
// ---------------------------------------------------------------------------
//
// The helper exists because `acquire_as` HARD-REFUSES `Transaction` mode
// (`transaction_mode_rejects_acquire_as`, above) while `begin_as` costs two
// extra round trips in `Session` mode. A request path converted onto either
// primitive alone is therefore either unservable behind a transaction-mode
// pooler or permanently slower, and the first of those is discovered in
// production because this repo has no pgbouncer fixture (blocked measurement
// M5).
//
// Every test below runs in BOTH modes on purpose. Testing only the `Session`
// arm would prove the half that already worked and ship the dispatch — the
// arm that is the entire reason the helper exists — unexercised.

/// The observations a filtered session makes about a viewer's own rows.
struct FilteredObservation {
    gucs: Vec<Uuid>,
    visible_mine: i64,
    visible_theirs: i64,
    bypass: bool,
    arm: SessionGucMode,
}

/// Drive `read_as` end to end in `mode`, under `SET SESSION AUTHORIZATION
/// epigraph_app` so the policies actually filter.
///
/// Factored over the mode rather than duplicated so the two arms cannot drift
/// into asserting different properties — which is how a dispatch helper ends up
/// with one arm covered and one arm assumed.
async fn read_as_filtered_case(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
    mode: SessionGucMode,
) -> FilteredObservation {
    let Env { pool, scoped } = env(pool_opts, conn_opts, mode).await;

    let agent = seed_agent(&pool).await;
    let mine = seed_group(&pool).await;
    seed_membership(&pool, mine, agent, "admin").await;
    let theirs = seed_group(&pool).await; // no membership for `agent`

    let my_claim = seed_group_claim(&pool, agent, mine).await;
    let their_claim = seed_group_claim(&pool, agent, theirs).await;

    let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");

    // THE CALL UNDER TEST. Identical source in both modes — that is the claim.
    let mut r = scoped.read_as(&viewer).await.expect("read_as");
    let arm = r.mode();

    // As above: migration 077 issues the app-role grants itself, and NOT
    // re-granting here keeps the test dependent on the migration rather than on
    // a fixture that would paper over a missing grant.
    r.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("SET SESSION AUTHORIZATION requires a superuser connection");

    // Every read below is a SEPARATE statement from the stamp. In `Transaction`
    // mode that is the point: `set_config(…, is_local => true)` is a silent
    // no-op outside a transaction block, so observing the group set here at all
    // proves `read_as` opened one.
    let (gucs,): (Vec<Uuid>,) = sqlx::query_as("SELECT epigraph_session_groups()")
        .fetch_one(&mut *r)
        .await
        .expect("epigraph_session_groups() after the role switch");
    let visible_mine: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = $1")
        .bind(my_claim)
        .fetch_one(&mut *r)
        .await
        .expect("read my own group-private claim");
    let visible_theirs: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = $1")
        .bind(their_claim)
        .fetch_one(&mut *r)
        .await
        .expect("read a claim in a group I am not in");
    let bypass: bool = sqlx::query_scalar("SELECT epigraph_bypass()")
        .fetch_one(&mut *r)
        .await
        .expect("epigraph_bypass()");

    r.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");

    // The explicit finish: a COMMIT on the transaction arm, nothing on the
    // session arm. Exercised here so the no-op arm is not merely assumed.
    r.commit().await.expect("commit");

    assert!(
        sorted(gucs.clone()).contains(&mine),
        "the viewer's group must be in epigraph.group_ids on the connection read_as \
         returned; got {gucs:?}"
    );
    FilteredObservation {
        gucs,
        visible_mine,
        visible_theirs,
        bypass,
        arm,
    }
}

/// Assert the coherence property on one arm's observation.
fn assert_coherent(o: &FilteredObservation, mode: SessionGucMode) {
    assert_eq!(
        o.arm, mode,
        "read_as must dispatch on the pool's mode: a {mode:?} pool that hands back the other \
         arm means the helper is not reading `ScopedPool::mode` at all, and the fallback \
         bin/server.rs advertises is not actually wired"
    );
    assert!(
        !o.bypass,
        "CALIBRATION ({mode:?}): this session must NOT hold bypass, or every assertion here \
         passes vacuously — the failure mode this file's header warns about"
    );
    assert!(
        !o.gucs.is_empty(),
        "CALIBRATION ({mode:?}): an empty group set would satisfy the fail-closed assertion \
         below for the wrong reason"
    );
    assert_eq!(
        o.visible_mine, 1,
        "COHERENCE ({mode:?}): the group the viewer bound as $V is in the GUC read_as stamped, \
         so claims_tenancy must admit that group's private claim. Zero here is the fail-closed \
         drift that is indistinguishable from data loss — and is exactly the §9.2 step 11d \
         outage this helper exists to prevent."
    );
    assert_eq!(
        o.visible_theirs, 0,
        "the other direction ({mode:?}): a group NOT in the GUC must be filtered, or the \
         policy is admitting more than $V would"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn read_as_agrees_with_the_policy_on_a_filtered_session_in_session_mode(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let o = read_as_filtered_case(pool_opts, conn_opts, SessionGucMode::Session).await;
    assert_coherent(&o, SessionGucMode::Session);
}

/// The arm that does not exist without this helper.
///
/// `transaction_mode_rejects_acquire_as` pins that the primitive refuses here.
/// This pins that the helper nonetheless SERVES the same viewer, filtered
/// correctly, through the identical call site.
#[sqlx::test(migrations = "../../migrations")]
async fn read_as_agrees_with_the_policy_on_a_filtered_session_in_transaction_mode(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let o = read_as_filtered_case(pool_opts, conn_opts, SessionGucMode::Transaction).await;
    assert_coherent(&o, SessionGucMode::Transaction);
}

/// The direct statement of why the helper is not just an alias for `acquire_as`.
///
/// One pool, one viewer, in `Transaction` mode: the primitive refuses and the
/// helper succeeds. If `read_as` ever collapses to a bare `acquire_as`, this is
/// the test that fails.
#[sqlx::test(migrations = "../../migrations")]
async fn read_as_serves_the_viewer_acquire_as_refuses_in_transaction_mode(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let Env { pool, scoped } = env(pool_opts, conn_opts, SessionGucMode::Transaction).await;

    let agent = seed_agent(&pool).await;
    let g = seed_group(&pool).await;
    seed_membership(&pool, g, agent, "writer").await;
    let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");

    let err = scoped
        .acquire_as(&viewer)
        .await
        .expect_err("CALIBRATION: the primitive must still refuse, or this test proves nothing");
    match err {
        DbError::InvalidData { reason } => assert!(
            reason.contains("begin_as"),
            "the refusal must still name the fallback; got: {reason}"
        ),
        other => panic!("expected DbError::InvalidData, got {other:?}"),
    }

    let mut r = scoped
        .read_as(&viewer)
        .await
        .expect("read_as must serve in transaction mode — that is its entire purpose");
    assert_eq!(r.mode(), SessionGucMode::Transaction);

    let (observed,): (Vec<Uuid>,) = sqlx::query_as("SELECT epigraph_session_groups()")
        .fetch_one(&mut *r)
        .await
        .expect("epigraph_session_groups()");
    assert_eq!(
        sorted(observed),
        sorted(vec![g]),
        "the transaction arm must stamp the same group set the session arm would"
    );
    r.commit().await.expect("commit");
}

/// Fail closed: a bypass viewer is refused on BOTH arms.
///
/// It emits no predicate and is still filtered by RLS, so on an application
/// connection it reads zero rows rather than all rows. The helper must not
/// become the one path that lets one through — a dispatch layer is exactly
/// where such a guard gets lost.
#[sqlx::test(migrations = "../../migrations")]
async fn read_as_refuses_a_bypass_viewer_in_both_modes(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    for mode in [SessionGucMode::Session, SessionGucMode::Transaction] {
        let Env { pool: _, scoped } = env(pool_opts.clone(), conn_opts.clone(), mode).await;

        let (_conn, lease) = scoped
            .unscoped_for_maintenance(SystemReason::SchemaContractTest)
            .await
            .expect("maintenance lease");
        let bypass = Viewer::system(&lease, SystemReason::SchemaContractTest);

        // `expect_err` takes a `&str` and does not interpolate, so the mode has
        // to be formatted explicitly — otherwise the one message that says
        // WHICH arm of this loop failed prints the braces literally.
        let err = match scoped.read_as(&bypass).await {
            Ok(_) => panic!("read_as must refuse a bypass viewer in {mode:?}"),
            Err(e) => e,
        };
        match err {
            DbError::InvalidData { reason } => assert!(
                reason.contains("unscoped_for_maintenance"),
                "the refusal must name where a bypass belongs ({mode:?}); got: {reason}"
            ),
            other => panic!("expected DbError::InvalidData in {mode:?}, got {other:?}"),
        }
    }
}

/// The release scrub still runs behind the helper, on both arms.
///
/// A dispatch layer that returned a connection the pool no longer scrubs would
/// reintroduce cross-tenant carry-over — one principal's group set surviving
/// into the next checkout — while every functional test above stayed green.
///
/// # `max_connections(1)`, so "the same connection" is STRUCTURAL
///
/// `ScopedPoolOptions::default()` is 10 connections. With it, "a fresh checkout
/// from the same pool" is the same physical backend only *by construction* —
/// the pool is cold, one checkout has happened, and sqlx pops an idle
/// connection before opening a new one — which is an argument about sqlx's
/// internals rather than an assertion this test makes. Pinning the pool to one
/// connection makes the recycle the only possible outcome, so a green run
/// cannot mean "we happened to get a virgin backend".
///
/// # The two arms are NOT double coverage of the scrub
///
/// Only the `Session` arm exercises it. In `Transaction` mode
/// `apply_session_gucs` uses `set_config(…, is_local => true)`, so `COMMIT`
/// discards the GUCs whether or not `after_release` ever ran — that arm would
/// still pass with the scrub deleted. It is kept because transaction-local
/// discard is itself worth asserting, and because a reader comparing the arms
/// should find the asymmetry written down rather than infer it.
#[sqlx::test(migrations = "../../migrations")]
async fn read_as_carries_no_tenancy_into_the_next_checkout(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    for mode in [SessionGucMode::Session, SessionGucMode::Transaction] {
        let pool = pool_opts
            .clone()
            .connect_with(conn_opts.clone())
            .await
            .expect("seeding pool");
        let scoped = ScopedPool::connect_with_options(
            &scoped_url(&conn_opts),
            mode,
            ScopedPoolOptions {
                max_connections: 1,
                ..ScopedPoolOptions::default()
            },
        )
        .await
        .expect("single-connection ScopedPool");

        let agent = seed_agent(&pool).await;
        let g = seed_group(&pool).await;
        seed_membership(&pool, g, agent, "writer").await;
        let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");

        {
            let mut r = scoped.read_as(&viewer).await.expect("read_as");
            let (observed,): (Vec<Uuid>,) = sqlx::query_as("SELECT epigraph_session_groups()")
                .fetch_one(&mut *r)
                .await
                .expect("epigraph_session_groups()");
            assert_eq!(
                sorted(observed),
                sorted(vec![g]),
                "CALIBRATION ({mode:?}): the stamp must land, or the emptiness below is vacuous"
            );
            r.commit().await.expect("commit");
        } // release -> after_release scrub

        let mut next = scoped
            .inner()
            .acquire()
            .await
            .expect("a fresh checkout from the same pool");
        let carried: String = sqlx::query_scalar(
            "SELECT COALESCE(current_setting('epigraph.group_ids', true), '') \
             || COALESCE(current_setting('epigraph.principal_id', true), '')",
        )
        .fetch_one(&mut *next)
        .await
        .expect("read the tenancy GUCs back");
        assert!(
            carried.is_empty(),
            "a connection released by read_as ({mode:?}) still carries tenancy GUCs \
             ({carried:?}); a recycled connection can then carry one principal's group set \
             into another's request"
        );
    }
}
