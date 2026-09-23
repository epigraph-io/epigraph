//! Shared `Viewer` construction for integration tests.
//!
//! # THIS FILE IS THE ONLY COPY. Do not add a second one.
//!
//! Included, not linked. Inside `epigraph-db`, that is the plain form:
//!
//! ```ignore
//! #[path = "viewer_fixture.rs"]
//! mod fixture;
//! ```
//!
//! Four other crates' test trees held a hand-maintained copy of this file:
//! `epigraph-api` a byte-identical 544-line twin, and `epigraph-cli`,
//! `epigraph-engine` and `epigraph-mcp` a byte-identical 321-line variant of it
//! between them. Measured with `diff`, the 321-line variant CHANGED exactly two
//! lines of the twin — one doc line and `scoped_pool`'s body — and simply LACKED
//! the other 223 (`2` changed + `223` added = 544). So it was a strict
//! behavioural subset, not a tailored fork, and one canonical text serves all
//! five. Each of those four paths is now a three-line re-export shim
//! that `#[path]`-includes THIS file, so `mod viewer_fixture;` still resolves
//! crate-locally at all ~145 declaration sites and there is one text to change.
//!
//! Why that shape rather than the alternatives: a shared test-support crate is a
//! new workspace member, and the last one added to this workspace took
//! `~/.cargo-target` from 48G to 64G. A bare `include!` cannot carry this file's
//! `//!` docs or its `#![allow(dead_code)]`, because inner attributes may not
//! arrive by macro expansion. Rewriting all 145 declarations to `#[path]` the
//! canonical file directly would work but is 145 edits to remove 4 files.
//!
//! `epigraph-db` is the canonical home because it is the crate that defines
//! `Viewer`, `ScopedPool` and `SessionGucMode`, and every other crate here
//! depends on it — so the fixture cannot acquire a dependency the consumers
//! lack.
//!
//! `viewer_fixture_single_source.rs` is the ratchet: it fails if a second full
//! copy reappears anywhere in the workspace tree. Not `crates/*/tests/` — that
//! narrower root was rejected in the ratchet's own doc, because it misses
//! `tests/engine-integration`.
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

/// A [`ScopedPool`] over the same database as `pool`, in `Session` mode.
pub async fn scoped_pool(pool: &PgPool) -> ScopedPool {
    scoped_pool_with_mode(pool, SessionGucMode::Session).await
}

/// [`scoped_pool`] with the [`SessionGucMode`] chosen by the caller.
///
/// `scoped_pool` hardcodes `Session`, which is the arm that already worked
/// before `read_as` existed. A test that only exercises it proves the easy half:
/// in `Session` mode a `ScopedRead` is a bare connection, so "these N statements
/// run in one transaction" is simply false there, while the identical code in
/// `Transaction` mode is atomic. Anything claiming atomicity has to drive both,
/// which is why `qual_guc_coherence.rs` factors its filtered-session case over
/// the mode rather than duplicating it.
pub async fn scoped_pool_with_mode(pool: &PgPool, mode: SessionGucMode) -> ScopedPool {
    ScopedPool::connect(&database_url_for(pool).await, mode)
        .await
        .expect("ScopedPool::connect")
}

/// A plain [`PgPool`] over the same database as `pool` whose every connection
/// authenticates as the superuser and is then DOWNGRADED to `role`.
///
/// # Why this exists, and why it is not a second DSN
///
/// `#[sqlx::test]` connects as `epigraph`, which is superuser, `BYPASSRLS` and
/// the table owner, so on the pool it hands you **no RLS policy filters
/// anything**. Every "a stranger cannot read this" assertion written on that
/// pool observes the in-query `$V` predicate alone — never migration 077's
/// policies, and never the FORCE differential that makes an UNSTAMPED
/// connection lose rows to its own owner. A test that cannot see that
/// differential passes identically on the converted and the unconverted tree.
///
/// The routes NOT taken, so nobody re-derives them:
/// * `session_authorization` as a connect-option — MEASURED not to work:
///   `PGOPTIONS='-c session_authorization=…'` leaves `current_user` and
///   `session_user` both at `epigraph`.
/// * a new LOGIN role — `epigraph_app` is `NOLOGIN` (migration 060) and 077
///   states the LOGIN is issued out of band and *never in this repository — it
///   is public*. `CREATE ROLE` is also cluster-global and leaks on panic.
/// * `ScopedPoolOptions` — it exposes `max_connections` / `acquire_timeout` /
///   `statement_timeout` and no `after_connect`, so this trick does NOT
///   generalise to the scoped arm. That limitation is the follow-up's scope,
///   not a defect in this helper.
///
/// What is left is the move `qual_guc_coherence.rs::read_as_filtered_case`
/// already proves works — connect as the superuser, then
/// `SET SESSION AUTHORIZATION` on the connection — hoisted into
/// `PgPoolOptions::after_connect` so that EVERY checkout is filtered and the
/// pool can be handed to production code that acquires its own connections.
///
/// **Do not pair this with [`grant_app_privileges`].** Migration 077 issues the
/// app-role grants itself; re-granting here would paper over a missing grant,
/// and a `42501` from this pool is a finding about the migration, not a fixture
/// bug. (`grant_app_privileges` exists for the `tenancy_required.rs` fixtures,
/// which run before 077's grants are in play.)
///
/// Seeding, and `Viewer::resolve`, must still run on the ORIGINAL superuser
/// pool: `Viewer::resolve` reads `group_memberships`, and on a downgraded
/// unstamped session it resolves to an EMPTY group set — which would make every
/// assertion keyed on that viewer pass for the wrong reason.
///
/// **That warning is now load-bearing in five crates, not two.** Until the
/// fixture was collapsed onto one body this helper existed only in the
/// `epigraph-api` and `epigraph-db` copies, and the pairing hazard was contained
/// by convention in `epigraph-db/tests/privatization_authz.rs` and
/// `privatization_plan_policies.rs`, whose own headers spell it out.
/// `epigraph-cli`, `epigraph-engine` and `epigraph-mcp` can now reach it too,
/// with no such header. Nothing detects the wrong pairing —
/// `viewer_fixture_single_source.rs` ratchets against a second COPY, not against
/// a misuse — so a `resolve` on this pool is a silent, permanently green
/// "a stranger cannot read this". Resolve first, downgrade second.
pub async fn downgraded_pool(pool: &PgPool, role: &str) -> PgPool {
    use sqlx::Executor;
    let url = database_url_for(pool).await;
    // Role names here are test-local literals, never caller data.
    let role = role.to_string();
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .after_connect(move |conn, _meta| {
            let role = role.clone();
            Box::pin(async move {
                conn.execute(format!("SET SESSION AUTHORIZATION {role}").as_str())
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("downgraded pool")
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

/// Give a seeded claim an `embedding`, so vector-ranked and vector-aggregating
/// reads can see it. `vec` is pgvector literal text, e.g. `"[0,1,...]"`.
///
/// `seed_public_claim` / `seed_group_claim` write no embedding, and the reads
/// that AGGREGATE embeddings — `ClaimThemeRepository::set_centroid_from_claims`
/// is the one this was added for — are invisible without it: with no embedded
/// claim in the corpus the aggregate is empty for every viewer, so an isolation
/// assertion over it passes for the wrong reason.
///
/// This lived as a file-local copy in
/// `epigraph-api/tests/search_voids_methods_scoped_read.rs`, whose own comment
/// gave the reason: the fixture was duplicated by hand across crates and adding
/// a helper meant adding it twice. That is no longer true — this file is the
/// only copy — so the helper lives here and that file delegates to it.
///
/// Writes `claims.embedding`, the 1536-d column every read in this workspace
/// ranks on. `embedding_3072` is a separate column and is deliberately not
/// touched: a helper that wrote both would make a test pass on whichever one
/// the read did not use.
pub async fn set_claim_embedding(pool: &PgPool, claim: Uuid, vec: &str) {
    sqlx::query("UPDATE claims SET embedding = $2::vector WHERE id = $1")
        .bind(claim)
        .bind(vec)
        .execute(pool)
        .await
        .expect("set claim embedding");
}

/// A `reasoning_traces` row for `claim`, wired up as that claim's `trace_id`.
///
/// Both halves are needed. `ClaimRepository::claim_ids_by_methodology` joins
/// `claims c INNER JOIN reasoning_traces rt ON c.trace_id = rt.id`, so a trace
/// that merely names the claim in its own `claim_id` column (which is NOT NULL
/// and so cannot be omitted) matches nothing; the pointer has to go the other
/// way too.
///
/// `reasoning_type` must be one of the five values
/// `reasoning_type_valid` admits: deductive, inductive, abductive, analogical,
/// statistical.
///
/// # No tenancy columns are declared, deliberately
///
/// `reasoning_traces` is in migration 070's `inheritors` array, and arm (c) of
/// `epigraph_inherit_tenancy_stmt` is **unconditional** — it has no no-widening
/// gate, so it overwrites whatever a caller declares with the parent claim's
/// `(visibility, owner_group_id)`. Declaring them here would be a lie a reader
/// might then reason from: a derived row's tenancy TRACKS its claim's and
/// cannot be set apart from it.
pub async fn seed_reasoning_trace(pool: &PgPool, claim: Uuid, reasoning_type: &str) -> Uuid {
    let trace: Uuid = sqlx::query_scalar(
        "INSERT INTO reasoning_traces (claim_id, reasoning_type, confidence, explanation) \
         VALUES ($1, $2, 0.9, 'seeded by viewer_fixture') RETURNING id",
    )
    .bind(claim)
    .bind(reasoning_type)
    .fetch_one(pool)
    .await
    .expect("seed reasoning trace");

    sqlx::query("UPDATE claims SET trace_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(trace)
        .execute(pool)
        .await
        .expect("point the claim at its trace");

    trace
}

/// An `evidence` row of `evidence_type` attached to `claim`.
///
/// `evidence_type` must be one of the seven `evidence_type_valid` admits:
/// document, observation, testimony, computation, reference, figure,
/// conversational.
///
/// No tenancy columns here either, and for the same reason as
/// [`seed_reasoning_trace`] — `evidence` is in the same 070 `inheritors` array,
/// and 070's own comment records that omitting it once stamped the evidence of a
/// group-private claim as world/public.
pub async fn seed_evidence(pool: &PgPool, claim: Uuid, evidence_type: &str) -> Uuid {
    let hash: Vec<u8> = {
        let mut h = blake3_like(&format!("{claim}:{evidence_type}"));
        h.truncate(32);
        h
    };
    sqlx::query_scalar(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash) \
         VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(claim)
    .bind(evidence_type)
    .bind(&hash)
    .fetch_one(pool)
    .await
    .expect("seed evidence")
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

/// A `supports` edge `source -> target`, left exactly as migration 070's
/// `edges_tenancy` trigger stamps it.
///
/// This is what `EdgeRepository::create` produces: the INSERT names no tenancy
/// columns, and the BEFORE-ROW trigger derives them from the two ENDPOINTS —
/// public/public gives `('public', world)`, otherwise the surviving private
/// endpoint's group. Use this when you want an edge that is visible to whoever
/// can see its endpoints, which is the ordinary case.
pub async fn seed_edge(pool: &PgPool, source: Uuid, target: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'claim', $3, 'claim', 'supports')",
    )
    .bind(id)
    .bind(source)
    .bind(target)
    .execute(pool)
    .await
    .expect("seed edge");
    id
}

/// [`seed_edge`], then FORCE the edge's own tenancy columns to
/// `(visibility, owner_group_id)`.
///
/// # Why the UPDATE, and why declaring the columns on the INSERT is not enough
///
/// Migration 070's trigger is `BEFORE INSERT OR UPDATE **OF source_id,
/// target_id**`. So it rewrites the tenancy columns on every INSERT, and it does
/// not fire for an UPDATE that touches only `visibility` / `owner_group_id`.
/// Its INSERT arms honour exactly one declaration — a `('group', G)` edge
/// between two PUBLIC endpoints, which the meet would widen — and silently
/// overwrite every other, including a declared `('public', world)`.
///
/// That matters far beyond one test, which is why this is a named helper rather
/// than an inline `UPDATE`: roughly half of the remaining conversion shards walk
/// a graph, and a graph fixture that lets the trigger stamp the edge gets an
/// edge whose visibility TRACKS its endpoints'. A "the stranger's private
/// ancestor is absent" assertion built that way is satisfied by the EDGE
/// predicate alone and stays green with the claim predicate deleted — a
/// mutation proof that reports a false pass.
///
/// The corollary is that this must be applied ASYMMETRICALLY. Forcing an edge
/// public on the arm that tests OVER-suppression (the viewer's own private
/// ancestor, which must remain visible) destroys the calibration that direction
/// exists to provide.
///
/// # `co_owner_group_id` is cleared, and it has to be
///
/// The result is a SINGLE-OWNER edge. Migration 072's `edges_co_owner_shape`
/// is `co_owner_group_id IS NULL OR (visibility = 'group' AND co_owner_group_id
/// <> owner_group_id)`, and the trigger's cross-group arm sets a co-owner — so
/// an edge between two claims private to DIFFERENT groups arrives here co-owned,
/// and forcing it `('public', world)` while leaving the co-owner raises `23514`.
/// Clearing it is also the semantics a caller of this helper wants: it says
/// "these are the edge's tenancy columns", and the intersection semantics of a
/// surviving co-owner would silently add a second condition the caller did not
/// write.
pub async fn seed_edge_owned_by(
    pool: &PgPool,
    source: Uuid,
    target: Uuid,
    visibility: &str,
    owner_group_id: Uuid,
) -> Uuid {
    let id = seed_edge(pool, source, target).await;
    sqlx::query(
        "UPDATE edges SET visibility = $2, owner_group_id = $3, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .bind(visibility)
    .bind(owner_group_id)
    .execute(pool)
    .await
    .expect("force edge tenancy");
    id
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
