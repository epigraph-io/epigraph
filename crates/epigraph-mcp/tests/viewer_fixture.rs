//! Shared `Viewer` construction for integration tests.
//!
//! Included, not linked:
//!
//! ```ignore
//! #[path = "viewer_fixture.rs"]
//! mod fixture;
//! ```
//!
//! # Why this file exists
//!
//! [`epigraph_db::Viewer::test_scoped`] is `#[cfg(test)]` **on its definition**
//! and deliberately not behind a cargo feature (a feature can be switched on
//! from a dependent crate's build graph, and then the constructor is reachable
//! in production). `crates/epigraph-db/tests/*` compiles against `epigraph-db`
//! as a dependency, so `cfg(test)` is off and `test_scoped` is invisible here.
//!
//! Every viewer in an integration test therefore has to be built the same way
//! production builds one — [`Viewer::resolve`] for a scoped viewer, or
//! `ScopedPool::unscoped_for_maintenance` + [`Viewer::system`] for a bypass.
//! That is more ceremony than a test wants to repeat, and before this file it
//! was copy-pasted (the `DATABASE_URL`-reassembly block in
//! `qual_guc_coherence.rs` and `agent_public_profile.rs`). PR-06 would have
//! duplicated it a further dozen times.
//!
//! # How the URL is recovered
//!
//! `#[sqlx::test]` provisions a randomly-named throwaway database and hands the
//! test a `PgPool` for it. `ScopedPool::connect` needs a URL, and the pool does
//! not expose one — so [`scoped_pool`] asks the database its own name
//! (`SELECT current_database()`) and splices it onto the ambient
//! `DATABASE_URL`'s authority. This works from a bare `pool: PgPool` signature,
//! unlike the `PgConnectOptions`-based derivation in `qual_guc_coherence.rs`,
//! which requires the two-argument `#[sqlx::test]` form.

#![allow(dead_code)]

use epigraph_db::visibility::{SystemReason, Viewer};
use epigraph_db::{ScopedPool, SessionGucMode};
use sqlx::PgPool;
use uuid::Uuid;

/// Rebuild a connection URL for the database `pool` is connected to.
pub async fn database_url_for(pool: &PgPool) -> String {
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await
        .expect("current_database()");

    let base = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set to run the database integration tests");

    // Strip the query string before touching the path, or `?sslmode=require`
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

/// A [`ScopedPool`] over the same database as `pool`.
pub async fn scoped_pool(pool: &PgPool) -> ScopedPool {
    ScopedPool::connect(&database_url_for(pool).await, SessionGucMode::Session)
        .await
        .expect("ScopedPool::connect")
}

/// A bypass viewer under [`SystemReason::SchemaContractTest`].
///
/// The `MaintenanceConn` is dropped immediately, which is sound while no RLS
/// policy is ENABLEd (before PR-17). From PR-17 on a bypass viewer on a
/// non-maintenance connection reads **zero** rows, and this helper has to
/// return the connection alongside the viewer. `visibility.rs`'s module doc
/// records that coupling; this comment is the test-side reminder.
pub async fn bypass_viewer(scoped: &ScopedPool) -> Viewer {
    let (_conn, lease) = scoped
        .unscoped_for_maintenance(SystemReason::SchemaContractTest)
        .await
        .expect("maintenance lease");
    Viewer::system(&lease, SystemReason::SchemaContractTest)
}

/// [`scoped_pool`] + [`bypass_viewer`] in one call.
///
/// Hold the `ScopedPool`: dropping it closes the pool the viewer was minted
/// from.
pub async fn bypass(pool: &PgPool) -> (ScopedPool, Viewer) {
    let scoped = scoped_pool(pool).await;
    let viewer = bypass_viewer(&scoped).await;
    (scoped, viewer)
}

/// A `Scoped` viewer over the NIL principal: a real, resolvable viewer with an
/// empty group set, so it reads exactly the `visibility = 'public'` corpus.
///
/// This is the right default for the ~45 pre-existing integration tests PR-06
/// had to touch. Their fixtures write claims through `ClaimRepository::create`,
/// which takes migration 062's `visibility` DEFAULT of `'public'`, so a
/// public-only viewer returns exactly what those tests asserted before the
/// predicate existed — which is the "nothing changes" property the conversion
/// is supposed to have. A bypass viewer would also pass, and would prove less:
/// it emits no predicate at all, so it cannot distinguish "the filter is
/// correct" from "the filter is missing".
pub async fn public_viewer(pool: &PgPool) -> Viewer {
    Viewer::resolve(pool, Uuid::nil())
        .await
        .expect("resolve over the nil principal cannot fail on a live pool")
}

/// Insert an agent, its personal group, and a live `admin` membership; return
/// `(agent_id, group_id)`.
///
/// Mirrors what `AgentRepository::ensure_personal_group` does in production
/// (PR-02), so a viewer resolved for the returned agent has a non-empty group
/// set — which is the property `no_anonymous_viewer.rs` pins and the reason a
/// fixture that inserts straight into `agents` produces a viewer that can read
/// only public rows.
pub async fn seed_agent_with_group(pool: &PgPool, label: &str) -> (Uuid, Uuid) {
    let agent = Uuid::new_v4();
    let pk: Vec<u8> = agent.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");

    // Same shape as `AgentRepository::ensure_personal_group` (PR-02): a
    // `personal` group carries an empty `public_key` (only `kind = 'team'` may
    // carry 32 bytes, per `groups_public_key_shape`) and an `admin` membership
    // at epoch 0.
    //
    // THE `did_key` MUST BE `did:epigraph:personal:<agent>`, NOT A TEST-LOCAL
    // SPELLING. `ensure_personal_group`'s idempotency comes entirely from that
    // deterministic key against `groups_did_key_key UNIQUE` — there is no
    // column on `agents` remembering which group is the personal one. This
    // fixture used `did:epigraph:test:<label>:<agent>`, so a later production
    // call to `ensure_personal_group` for the same agent MINTED A SECOND
    // `kind='personal'` group and returned that one instead.
    //
    // Measured: `ClaimRepository::consolidate`'s all-public fallback resolves
    // the actor's group through `ensure_personal_group`, and the merged row
    // landed on a group the test had never heard of. Every assertion comparing
    // "the group the fixture made" with "the group production resolves" was
    // therefore comparing two different rows — and the ones that passed did so
    // because they never crossed that boundary.
    let group: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, 'did:epigraph:personal:' || $2::text, ''::bytea, 'personal', $2) \
         ON CONFLICT (did_key) DO UPDATE SET updated_at = now() \
         RETURNING id",
    )
    .bind(format!("{label}:{agent}"))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed group");

    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'admin')",
    )
    .bind(group)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed membership");

    (agent, group)
}

/// A `visibility = 'public'` claim authored by `agent`.
pub async fn seed_public_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    seed_claim(pool, agent, content, "public", world_group(pool).await).await
}

/// A `visibility = 'group'` claim owned by `group`.
pub async fn seed_group_claim(pool: &PgPool, agent: Uuid, group: Uuid, content: &str) -> Uuid {
    seed_claim(pool, agent, content, "group", group).await
}

/// The seeded world group (migration 060/062).
///
/// It **was** the `owner_group_id` DEFAULT every pre-existing row carried;
/// migration 074 (PR-16) dropped that default, so it is now a shape constant
/// only — the sentinel for *owned by nobody*, memberless by design, and legal
/// on a row only in the pair `('public', world)`. `('group', world)` is refused
/// by `<table>_group_needs_real_group`.
///
/// Fixtures that stamp it are declaring "this row has no owner", which is true
/// of the ownerless registry tables and of a public claim written before D2's
/// backfill. It is NOT what migration 074's seed escape hatch stamps — that is
/// [`seed_group`], and §8.2 A4 asserts no CLAIM is world-owned.
pub async fn world_group(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM groups WHERE kind = 'world' LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("the world group is seeded by migration 060")
}

/// The seeded `epigraph_seed` group (migration 062), which migration 074's
/// arm 4 stamps on an undeclared insert by a member of the `epigraph_seed`
/// role.
pub async fn seed_group(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM groups WHERE kind = 'seed' LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("the seed group is seeded by migration 062")
}

/// Run `f` on a connection whose **`session_user`** is `role`, then restore.
///
/// # Why `SET SESSION AUTHORIZATION` and not `SET ROLE`
///
/// Migration 074's seed escape hatch is
/// `pg_has_role(session_user, 'epigraph_seed', 'MEMBER')`, keyed on
/// `session_user` and not `current_user` because inside a `SECURITY DEFINER`
/// frame `current_user` is the function owner. `SET ROLE` changes only
/// `current_user`, so **it does not reach the arm at all** — measured: an
/// undeclared `INSERT INTO claims` under `SET ROLE epigraph_app` still takes
/// arm 4 and succeeds, because the session is still the superuser the test
/// harness connected as.
///
/// `SET SESSION AUTHORIZATION` changes both, is available to a superuser, and
/// is the only way a test on this harness can produce the `23502` that
/// `tenancy_required.rs` exists to assert. Without it every such assertion is
/// vacuous.
///
/// `epigraph_app` and `epigraph_maintenance` are `NOLOGIN` (migration 060), so
/// there is no second connection to open instead.
///
/// The reset is `RESET SESSION AUTHORIZATION`, issued whether or not `f`
/// failed: a connection left as `epigraph_app` and returned to the pool would
/// make an unrelated later test fail somewhere else entirely.
pub async fn as_role<F, Fut, T>(pool: &PgPool, role: &str, f: F) -> T
where
    F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
    Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, T)>,
{
    use sqlx::Executor;
    let mut conn = pool.acquire().await.expect("acquire");
    // Role names are test-local literals, never caller data; there is no
    // identifier-quoting facility for SET SESSION AUTHORIZATION in a bind.
    conn.execute(format!("SET SESSION AUTHORIZATION {role}").as_str())
        .await
        .unwrap_or_else(|e| panic!("SET SESSION AUTHORIZATION {role}: {e}"));
    let (mut conn, out) = f(conn).await;
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("RESET SESSION AUTHORIZATION");
    out
}

/// Grant every table privilege on `public` to `role`.
///
/// `epigraph_app` is a bare `CREATE ROLE ... NOLOGIN` (migration 060 issues no
/// GRANT of its own), so an [`as_role`] block that does not do this first fails
/// with `42501 permission denied for table claims` — a plausible-looking error
/// that has nothing to do with tenancy and would mask the `23502` under test.
pub async fn grant_app_privileges(pool: &PgPool, role: &str) {
    use sqlx::Executor;
    for stmt in [
        format!("GRANT USAGE ON SCHEMA public TO {role}"),
        format!("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role}"),
        format!("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}"),
    ] {
        pool.execute(stmt.as_str())
            .await
            .unwrap_or_else(|e| panic!("{stmt}: {e}"));
    }
}

async fn seed_claim(
    pool: &PgPool,
    agent: Uuid,
    content: &str,
    visibility: &str,
    owner_group_id: Uuid,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = {
        let mut h = blake3_like(content);
        h.truncate(32);
        h
    };
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             is_current, visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.8, $4, true, $5, $6)",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent)
    .bind(visibility)
    .bind(owner_group_id)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// A deterministic 32-byte stand-in for a content hash. The tests never verify
/// it; the column is just NOT NULL.
fn blake3_like(s: &str) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    for (i, b) in s.as_bytes().iter().enumerate() {
        out[i % 32] ^= *b;
    }
    out
}
