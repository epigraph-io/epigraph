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
