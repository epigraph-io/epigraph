//! `FactorRepository`'s whole-graph and per-claim loaders read no
//! `decomposes_to` factor (atom-level belief, SPEC §1.3 D3, §6.2).
//!
//! `get_all` and `get_for_claim` are the repository's BP factor loaders: they
//! return `factors` rows in the shape `run_bp` / `run_cdst_bp` consume. No
//! caller uses them today, and nothing stopped a future one (a job, an MCP
//! diagnostic) from feeding BP the `directional_support` factor the
//! `edges_auto_factor` trigger minted for every `decomposes_to` edge before
//! migration 262, the echo D3 forbids. They apply the same predicate as the
//! API's factor load, `factor::bp_readable_factor_sql`. Since 262 the trigger
//! mints no such row (pinned below), so the fixtures seed the row a database
//! migrated before 262 holds.

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

/// The factor 217's `edges_auto_factor` minted for the `decomposes_to` edge
/// `edge` (a database migrated before 262 holds it; 262's trigger mints
/// none), seeded as that trigger wrote it.
async fn trigger_factor(pool: &PgPool, edge: Uuid) -> Uuid {
    let (source, target): (Uuid, Uuid) =
        sqlx::query_as("SELECT source_id, target_id FROM edges WHERE id = $1")
            .bind(edge)
            .fetch_one(pool)
            .await
            .expect("read the edge");
    let minted: i64 =
        sqlx::query_scalar("SELECT count(*) FROM factors WHERE properties->>'source_edge_id' = $1")
            .bind(edge.to_string())
            .fetch_one(pool)
            .await
            .expect("count the edge's factors");
    assert_eq!(
        minted, 0,
        "since 262 the trigger mints no decomposes_to factor"
    );
    let mut vars = [source, target];
    vars.sort();
    sqlx::query_scalar(
        "INSERT INTO factors (factor_type, variable_ids, potential, description, properties) \
         VALUES ('directional_support', $1, $2, $3, $4) RETURNING id",
    )
    .bind(vars.to_vec())
    .bind(
        json!({"forward_strength": 0.0, "reverse_strength": 0.6, "source_var": source.to_string()}),
    )
    .bind(format!("Auto-generated from decomposes_to edge {edge}"))
    .bind(json!({
        "source_edge_id": edge, "relationship": "decomposes_to",
        "edge_source_id": source, "edge_target_id": target
    }))
    .fetch_one(pool)
    .await
    .expect("seed the pre-262 decomposes_to factor")
}

/// Migration 262: the `edges_auto_factor` trigger mints no factor for a
/// `decomposes_to` edge, and still mints one for an ordinary edge (control).
/// Fails on 217's trigger body, which mapped `decomposes_to` to a keyed
/// `directional_support` row.
#[sqlx::test(migrations = "../../migrations")]
async fn trigger_mints_no_decomposes_to_factor(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "factor-trigger-262").await;
    let k = seed_group_claim(&pool, agent, group, "trigger compound").await;
    let a = seed_group_claim(&pool, agent, group, "trigger atom").await;
    let s = seed_group_claim(&pool, agent, group, "trigger supporter").await;

    let dec = decomposes_to(&pool, k, a).await;
    let pair_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM factors \
          WHERE properties->>'source_edge_id' = $1 OR variable_ids @> ARRAY[$2, $3]::uuid[]",
    )
    .bind(dec.to_string())
    .bind(k)
    .bind(a)
    .fetch_one(&pool)
    .await
    .expect("count the decomposition's factors");
    assert_eq!(
        pair_rows, 0,
        "the trigger minted a factor for decomposes_to edge {dec}"
    );

    let sup: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports') RETURNING id",
    )
    .bind(s)
    .bind(k)
    .fetch_one(&pool)
    .await
    .expect("seed a supports edge");
    let rel: String = sqlx::query_scalar(
        "SELECT properties->>'relationship' FROM factors WHERE properties->>'source_edge_id' = $1",
    )
    .bind(sup.to_string())
    .fetch_one(&pool)
    .await
    .expect("control: the trigger still mints a supports edge's factor");
    assert_eq!(rel, "supports");
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

        // KNOWN GAP of the PREDICATE, pinned: a caller who cannot see the
        // decomposition cannot exclude its legacy row. The structural close
        // is deleting such rows on the maintenance connection (SPEC §6.2):
        // `decomposes_to_factor_sweep`, pinned in epigraph-cli's
        // `decomposes_to_factor_sweep` test.
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

/// `docs/runbooks/262-undo.sql` re-states 217's mint body exactly (md5 of
/// `prosrc`, as 262's precondition reads it), keeps the owner, and a new
/// `decomposes_to` edge mints its factor again. A second run is refused by
/// its own precondition and changes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn the_262_undo_restores_217s_mint(pool: PgPool) {
    async fn mint(pool: &PgPool) -> (String, String) {
        sqlx::query_as(
            "SELECT md5(p.prosrc), pg_get_userbyid(p.proowner)::text FROM pg_proc p \
              WHERE p.oid = to_regprocedure('public.auto_create_factor_from_edge()')",
        )
        .fetch_one(pool)
        .await
        .expect("pg_proc")
    }
    let (at_head, owner) = mint(&pool).await;
    assert_ne!(
        at_head, "b98f7326df4cc26924091dc61a8289f3",
        "calibration: at head the body is 262's, not 217's"
    );
    let undo = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/runbooks/262-undo.sql"
    ))
    .expect("read the undo");
    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("apply the undo");
    assert_eq!(
        mint(&pool).await,
        (
            "b98f7326df4cc26924091dc61a8289f3".to_string(),
            owner.clone()
        ),
        "the undo restores 217's body and keeps the owner"
    );

    let (agent, group) = seed_agent_with_group(&pool, "factor-trigger-262-undo").await;
    let k = seed_group_claim(&pool, agent, group, "undo compound").await;
    let a = seed_group_claim(&pool, agent, group, "undo atom").await;
    let dec = decomposes_to(&pool, k, a).await;
    let rel: String = sqlx::query_scalar(
        "SELECT properties->>'relationship' FROM factors WHERE properties->>'source_edge_id' = $1",
    )
    .bind(dec.to_string())
    .fetch_one(&pool)
    .await
    .expect("after the undo the trigger mints a decomposes_to factor again");
    assert_eq!(rel, "decomposes_to");

    let mut conn = pool.acquire().await.expect("acquire");
    let err = sqlx::raw_sql(&undo)
        .execute(&mut *conn)
        .await
        .expect_err("a second run is refused by the precondition");
    assert!(format!("{err:?}").contains("262-undo"), "{err:?}");
    sqlx::query("ROLLBACK")
        .execute(&mut *conn)
        .await
        .expect("end the refused run's transaction");
    drop(conn);
    assert_eq!(
        mint(&pool).await,
        ("b98f7326df4cc26924091dc61a8289f3".to_string(), owner),
        "the refused run changed nothing"
    );
}
