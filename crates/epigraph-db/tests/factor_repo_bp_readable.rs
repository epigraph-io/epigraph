//! `FactorRepository`'s whole-graph and per-claim loaders read no
//! `decomposes_to` factor (atom-level belief, SPEC §1.3 D3, §6.2).
//!
//! `get_all` and `get_for_claim` are the repository's BP factor loaders: they
//! return `factors` rows in the shape `run_bp` / `run_cdst_bp` consume. No
//! caller uses them today, and nothing stopped a future one (a job, an MCP
//! diagnostic) from feeding BP the `directional_support` factor the
//! `edges_auto_factor` trigger mints for every `decomposes_to` edge, the echo
//! D3 forbids. They apply the same predicate as the API's factor load,
//! `factor::bp_readable_factor_sql`.

mod viewer_fixture;

use epigraph_db::FactorRepository;
use serde_json::json;
use sqlx::PgPool;
use std::collections::BTreeSet;
use uuid::Uuid;
use viewer_fixture::{seed_agent_with_group, seed_group_claim};

async fn decomposes_to(pool: &PgPool, compound: Uuid, atom: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'decomposes_to') RETURNING id",
    )
    .bind(compound)
    .bind(atom)
    .fetch_one(pool)
    .await
    .expect("seed a decomposes_to edge")
}

async fn trigger_factor(pool: &PgPool, edge: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT id FROM factors WHERE properties->>'source_edge_id' = $1")
        .bind(edge.to_string())
        .fetch_one(pool)
        .await
        .expect("the edges_auto_factor trigger mints one factor per decomposes_to edge")
}

/// `k` decomposes to `a` (the trigger's KEYED row) and to `c` (the trigger's
/// row with its properties stripped: a LEGACY row), and shares an ordinary
/// `evidential_support` factor with `b`.
struct Graph {
    k: Uuid,
    keyed: Uuid,
    legacy: Uuid,
    legacy_edge: Uuid,
    ordinary: Uuid,
}

async fn graph(pool: &PgPool) -> Graph {
    let (agent, group) = seed_agent_with_group(pool, "factor-repo-bp").await;
    let k = seed_group_claim(pool, agent, group, "factor repo compound").await;
    let a = seed_group_claim(pool, agent, group, "factor repo atom a").await;
    let b = seed_group_claim(pool, agent, group, "factor repo atom b").await;
    let c = seed_group_claim(pool, agent, group, "factor repo atom c").await;

    let keyed = trigger_factor(pool, decomposes_to(pool, k, a).await).await;
    let legacy_edge = decomposes_to(pool, k, c).await;
    let legacy = trigger_factor(pool, legacy_edge).await;
    sqlx::query("UPDATE factors SET properties = '{}'::jsonb WHERE id = $1")
        .bind(legacy)
        .execute(pool)
        .await
        .expect("strip the row to the legacy shape");

    let mut vars = [k, b];
    vars.sort();
    let ordinary: Uuid = sqlx::query_scalar(
        "INSERT INTO factors (factor_type, variable_ids, potential, properties) \
         VALUES ('evidential_support', $1, $2, $3) RETURNING id",
    )
    .bind(vars.to_vec())
    .bind(json!({"strength": 0.8}))
    .bind(json!({"relationship": "supports"}))
    .fetch_one(pool)
    .await
    .expect("seed an ordinary factor");

    Graph {
        k,
        keyed,
        legacy,
        legacy_edge,
        ordinary,
    }
}

async fn loaded(pool: &PgPool, k: Uuid) -> (BTreeSet<Uuid>, BTreeSet<Uuid>) {
    let all = FactorRepository::get_all(pool, None)
        .await
        .expect("get_all")
        .into_iter()
        .map(|f| f.id)
        .collect();
    let for_k = FactorRepository::get_for_claim(pool, k)
        .await
        .expect("get_for_claim")
        .into_iter()
        .map(|f| f.id)
        .collect();
    (all, for_k)
}

#[sqlx::test(migrations = "../../migrations")]
async fn factor_repo_loaders_skip_decomposes_to(pool: PgPool) {
    let g = graph(&pool).await;
    let (all, for_k) = loaded(&pool, g.k).await;

    for (name, set) in [("get_all", &all), ("get_for_claim", &for_k)] {
        assert!(
            set.contains(&g.ordinary),
            "control: {name} still loads an ordinary factor naming the compound: {set:?}"
        );
        assert!(
            !set.contains(&g.keyed),
            "{name} loaded the keyed decomposes_to factor {}: {set:?}",
            g.keyed
        );
        assert!(
            !set.contains(&g.legacy),
            "{name} loaded the legacy unkeyed factor {} on an in-force decomposes_to pair: \
             {set:?}",
            g.legacy
        );
    }

    // Control: retracted, the legacy pair is no longer a decomposition and the
    // same unkeyed row is an ordinary factor again, so the exclusion above is
    // the in-force edge match and not the row's shape.
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 day' WHERE id = $1")
        .bind(g.legacy_edge)
        .execute(&pool)
        .await
        .expect("retract the edge");
    let (all, for_k) = loaded(&pool, g.k).await;
    assert!(
        all.contains(&g.legacy) && for_k.contains(&g.legacy),
        "control: with its edge retracted the unkeyed row is loaded again; \
         get_all={all:?} get_for_claim={for_k:?}"
    );
}

// ── the policy half: the legacy arm under row security ──────────────────────
//
// `bp_readable_factor_sql`'s legacy arm decides by reading `edges`, which row
// security filters, so what it excludes depends on the session it runs on.
// The API runs it on the caller's `read_as` connection. These arms run the
// predicate itself on a genuinely filtered session (`epigraph_app`, no
// bypass), the shape of `lineage_scoped_read_policy.rs`: stamped by
// `ScopedPool::read_as` first, or not stamped at all.

/// Whether the predicate admits `factor` on `conn`, and whether `conn`
/// bypasses row security (it must not, or the arm proves nothing).
async fn readable_on(conn: &mut sqlx::PgConnection, factor: Uuid) -> (bool, bool) {
    let bypass: bool = sqlx::query_scalar("SELECT epigraph_bypass()")
        .fetch_one(&mut *conn)
        .await
        .expect("epigraph_bypass()");
    let readable: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS (SELECT 1 FROM factors f WHERE f.id = $1 AND {})",
        epigraph_db::repos::factor::bp_readable_factor_sql()
    ))
    .bind(factor)
    .fetch_one(&mut *conn)
    .await
    .expect("run the predicate");
    (readable, bypass)
}

async fn stamped_readable(
    pool: &PgPool,
    mode: epigraph_db::SessionGucMode,
    agent: Uuid,
    factor: Uuid,
) -> (bool, bool) {
    use sqlx::Executor;
    let scoped = viewer_fixture::scoped_pool_with_mode(pool, mode).await;
    let viewer = epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("resolve on the superuser pool, before any downgrade");
    let mut r = scoped.read_as(&viewer).await.expect("read_as");
    r.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade the stamped connection");
    let out = readable_on(&mut r, factor).await;
    r.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    r.commit().await.expect("commit");
    out
}

async fn unstamped_readable(pool: &PgPool, factor: Uuid) -> (bool, bool) {
    use sqlx::Executor;
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade");
    let out = readable_on(&mut conn, factor).await;
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    out
}

#[sqlx::test(migrations = "../../migrations")]
async fn legacy_arm_sees_the_callers_private_decomposition_only_when_stamped(pool: PgPool) {
    let (owner, group) = seed_agent_with_group(&pool, "factor-policy-owner").await;
    let (stranger, _) = seed_agent_with_group(&pool, "factor-policy-stranger").await;
    let k = seed_group_claim(&pool, owner, group, "factor policy compound").await;
    let a = seed_group_claim(&pool, owner, group, "factor policy atom").await;
    // Both ends private to `group`, so the trigger stamps the edge private to
    // `group` too.
    let edge = decomposes_to(&pool, k, a).await;
    let legacy = trigger_factor(&pool, edge).await;
    sqlx::query("UPDATE factors SET properties = '{}'::jsonb WHERE id = $1")
        .bind(legacy)
        .execute(&pool)
        .await
        .expect("strip the row to the legacy shape");

    for mode in [
        epigraph_db::SessionGucMode::Session,
        epigraph_db::SessionGucMode::Transaction,
    ] {
        let (readable, bypass) = stamped_readable(&pool, mode, owner, legacy).await;
        assert!(
            !bypass,
            "CALIBRATION ({mode:?}): the stamped arm must be filtered"
        );
        assert!(
            !readable,
            "{mode:?}: stamped as a member of the edge's group, the legacy arm sees the \
             decomposition and excludes the row"
        );

        // KNOWN GAP, pinned so a structural fix shows up here: a caller who
        // cannot see the decomposition cannot exclude its legacy row. The
        // structural close is deleting such rows on the maintenance connection
        // (SPEC §6.2), not this predicate.
        let (readable, bypass) = stamped_readable(&pool, mode, stranger, legacy).await;
        assert!(
            !bypass,
            "CALIBRATION ({mode:?}): the stranger arm must be filtered"
        );
        assert!(
            readable,
            "{mode:?}: known gap changed: a caller outside the edge's group now excludes \
             the legacy row; update bp_readable_factor_sql's doc and this assertion"
        );
    }

    // Unstamped, even the owner's session sees no private edge: the reason the
    // API loads factors on `read_as` and not on the raw pool.
    let (readable, bypass) = unstamped_readable(&pool, legacy).await;
    assert!(!bypass, "CALIBRATION: the unstamped arm must be filtered");
    assert!(
        readable,
        "unstamped, the legacy arm cannot see a group-private edge, so the row is admitted"
    );

    // Control: a KEYED row needs no edge read, so it is excluded on every
    // session, the unstamped one included.
    sqlx::query("UPDATE factors SET properties = $2 WHERE id = $1")
        .bind(legacy)
        .bind(json!({"relationship": "decomposes_to", "source_edge_id": edge.to_string()}))
        .execute(&pool)
        .await
        .expect("re-key the row");
    let (readable, _) = unstamped_readable(&pool, legacy).await;
    assert!(
        !readable,
        "control: a keyed decomposes_to row is excluded without any edge read"
    );
}
