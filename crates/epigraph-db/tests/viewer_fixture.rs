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
    let group: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, $2, ''::bytea, 'personal', $3) RETURNING id",
    )
    .bind(format!("{label}:{agent}"))
    .bind(format!("did:epigraph:test:{label}:{agent}"))
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

/// The seeded world group (migration 060/062), which is the `owner_group_id`
/// DEFAULT every pre-existing row carries.
pub async fn world_group(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM groups WHERE kind = 'world' LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("the world group is seeded by migration 060")
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
