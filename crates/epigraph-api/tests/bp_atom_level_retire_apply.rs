#![cfg(feature = "db")]

//! Atom-level belief, BP half (SPEC §1.3 D3/D4, §4.1 W10, §6.2, §10.1 H4).
//!
//! Under atom-level belief a compound (a claim with an in-force
//! `decomposes_to` out-edge) is a query over its atoms. Loopy BP over the
//! legacy `factors` table contradicts that in three ways, each pinned here:
//!
//! 1. `POST /api/v1/bp/propagate` with `apply_updates: true` rewrites claim
//!    caches from a whole-graph BP run, compounds included. BP apply is
//!    retired: refused (409) unless the process runs with
//!    `EPIGRAPH_BP_APPLY=on`, and even then it never writes a compound (D4).
//! 2. The factor load feeds BP the `directional_support` factor the
//!    `edges_auto_factor` trigger mints for every `decomposes_to` edge, so a
//!    compound's BP value carries its own atoms' evidence back up (an echo).
//!    No BP run may read such a factor, whether it is keyed by
//!    `properties.relationship` or is a legacy row with no key whose sorted
//!    pair is an in-force `decomposes_to` edge (D3).
//! 3. `POST /api/v1/edges` inserted its own route-level factor ("P2a") beside
//!    the trigger's, unkeyed, for `supports` / `contradicts`. It fed only BP
//!    and is removed (W10).
//!
//! Read-only BP stays available as a diagnostic, and still loads
//! `evidential_support` / `mutual_exclusion` factors that name compounds: the
//! fixtures below put a compound in BP through exactly such a factor.
//!
//! Every test runs the handlers directly on a fresh database
//! (`#[sqlx::test]`), the shape `qualifies_edge_http.rs` uses.

mod viewer_fixture;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Extension;
use axum::Json;
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::computation::{propagate_beliefs, PropagateRequest};
use epigraph_api::routes::edges::{create_edge, CreateEdgeRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::BTreeMap;
use uuid::Uuid;
use viewer_fixture::{
    database_url_for, downgraded_pool, scoped_pool, seed_agent_with_group, seed_group_claim,
    seed_public_claim,
};

/// Two BP runs agree when every claim's BetP agrees to this tolerance. The
/// engines fold messages in `HashMap` order, so two runs over the same graph
/// can differ in the last bits; a real difference from one extra factor is
/// orders of magnitude larger (each control below asserts one).
const SAME: f64 = 1e-9;

/// Every `mode` `POST /api/v1/bp/propagate` accepts. `interval` runs the
/// scalar track and `auto` picks cdst or scalar by BBA coverage, but each is
/// its own branch of the handler's mode dispatch, so each is driven.
const ENGINES: [&str; 4] = ["cdst", "scalar", "interval", "auto"];

// ── fixtures ────────────────────────────────────────────────────────────────

/// A session-stamped `ScopedPool` state, so `write_as` can stamp the apply.
/// BP apply OFF: the default every constructor gives.
async fn state_default(pool: &PgPool) -> AppState {
    let url = database_url_for(pool).await;
    let scoped = ScopedPool::connect(&url, SessionGucMode::Session)
        .await
        .expect("connect a scoped pool");
    let state = AppState::with_scoped_pool(scoped, ApiConfig::default());
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

/// [`state_default`] with BP apply switched ON, as a process started with
/// `EPIGRAPH_BP_APPLY=on` is.
async fn state_bp_apply_on(pool: &PgPool) -> AppState {
    state_default(pool)
        .await
        .with_bp_apply(epigraph_api::state::BpApply::On)
}

/// A binary frame for the seeded BBAs (`mass_functions.frame_id` is a FK).
async fn binary_frame(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) \
         VALUES ($1, ARRAY['supported','unsupported']::text[]) \
         RETURNING id",
    )
    .bind(format!("bp_atom_level_binary_{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed a binary frame")
}

/// A claim private to `group`, carrying a stored belief interval and BetP so
/// a write is observable and the scalar engine has a prior.
async fn claim(pool: &PgPool, agent: Uuid, group: Uuid, label: &str, betp: f64) -> Uuid {
    let id = seed_group_claim(pool, agent, group, &format!("bp atom-level {label}")).await;
    with_belief(pool, id, betp).await
}

/// [`claim`], but public.
async fn public_claim(pool: &PgPool, agent: Uuid, label: &str, betp: f64) -> Uuid {
    let id = seed_public_claim(pool, agent, &format!("bp atom-level {label}")).await;
    with_belief(pool, id, betp).await
}

async fn with_belief(pool: &PgPool, id: Uuid, betp: f64) -> Uuid {
    sqlx::query(
        "UPDATE claims SET belief = $2, plausibility = $3, pignistic_prob = $4 WHERE id = $1",
    )
    .bind(id)
    .bind(betp - 0.1)
    .bind(betp + 0.1)
    .bind(betp)
    .execute(pool)
    .await
    .expect("give the claim a stored belief");
    id
}

/// One BBA on `claim`: `support` on {supported}, the rest on the frame.
async fn bba(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Uuid, support: f64) {
    sqlx::query(
        "INSERT INTO mass_functions \
           (claim_id, frame_id, source_agent_id, masses, source_strength, evidence_type) \
         VALUES ($1, $2, $3, $4, 1.0, 'empirical')",
    )
    .bind(claim)
    .bind(frame)
    .bind(agent)
    .bind(json!({"0": support, "0,1": 1.0 - support}))
    .execute(pool)
    .await
    .expect("seed a BBA");
}

/// A symmetric `evidential_support` factor over `a` and `b`: a BP coupling
/// that names a compound and that read-only BP must still load (D4).
async fn evidential_factor(pool: &PgPool, a: Uuid, b: Uuid, frame: Option<Uuid>) {
    let mut vars = [a, b];
    vars.sort();
    sqlx::query(
        "INSERT INTO factors (factor_type, variable_ids, potential, frame_id, properties) \
         VALUES ('evidential_support', $1, '{\"strength\": 0.8}', $2, \
                 '{\"relationship\": \"supports\"}')",
    )
    .bind(vars.to_vec())
    .bind(frame)
    .execute(pool)
    .await
    .expect("seed an evidential_support factor");
}

/// An in-force `decomposes_to` edge `compound -> atom`. Its INSERT fires the
/// `edges_auto_factor` trigger, which mints the keyed `directional_support`
/// factor (frame NULL) these tests are about.
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

/// The id of the factor the trigger minted for `edge`.
async fn trigger_factor(pool: &PgPool, edge: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT id FROM factors WHERE properties->>'source_edge_id' = $1")
        .bind(edge.to_string())
        .fetch_one(pool)
        .await
        .expect("the edges_auto_factor trigger mints one factor per decomposes_to edge")
}

async fn set_factor_properties(pool: &PgPool, factor: Uuid, properties: Value) {
    sqlx::query("UPDATE factors SET properties = $2 WHERE id = $1")
        .bind(factor)
        .bind(properties)
        .execute(pool)
        .await
        .expect("rewrite the factor's properties");
}

/// Everything an apply could change on a claim row.
async fn stored(pool: &PgPool, claim: Uuid) -> (Option<f64>, Option<f64>, Option<f64>, String) {
    sqlx::query_as(
        "SELECT belief, plausibility, pignistic_prob, updated_at::text FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("read the claim's stored belief")
}

async fn propagate(
    pool: &PgPool,
    state: &AppState,
    agent: Uuid,
    request: Value,
) -> Result<Value, StatusCode> {
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let request: PropagateRequest =
        serde_json::from_value(request).expect("a well-formed propagate request");
    match propagate_beliefs(ViewerExtractor(viewer), State(state.clone()), Json(request)).await {
        Ok(Json(body)) => Ok(body),
        Err(e) => Err(e.into_response().status()),
    }
}

/// A read-only run over every factor (no frame filter: the trigger's factors
/// carry no frame), as `{claim -> betp}`, plus the factor count.
async fn diagnose(
    pool: &PgPool,
    state: &AppState,
    agent: Uuid,
    mode: &str,
) -> (BTreeMap<Uuid, f64>, u64) {
    let body = propagate(
        pool,
        state,
        agent,
        json!({"mode": mode, "apply_updates": false, "max_iterations": 30}),
    )
    .await
    .unwrap_or_else(|s| panic!("read-only {mode} BP must answer 200, got {s}"));
    (betps(&body), body["factors_count"].as_u64().unwrap_or(0))
}

fn betps(body: &Value) -> BTreeMap<Uuid, f64> {
    body["updated_beliefs"]
        .as_array()
        .expect("updated_beliefs is a list")
        .iter()
        .map(|u| {
            (
                u["claim_id"].as_str().unwrap().parse().unwrap(),
                u["betp"].as_f64().unwrap(),
            )
        })
        .collect()
}

fn max_gap(a: &BTreeMap<Uuid, f64>, b: &BTreeMap<Uuid, f64>) -> f64 {
    assert_eq!(
        a.keys().collect::<Vec<_>>(),
        b.keys().collect::<Vec<_>>(),
        "the two runs must cover the same claims"
    );
    a.iter()
        .map(|(id, x)| (x - b[id]).abs())
        .fold(0.0_f64, f64::max)
}

/// The baseline graph, with NO `decomposes_to` edge yet: two evidenced atoms
/// `a` and `b` coupled by an `evidential_support` factor, and a claim `k`
/// coupled to `b` by another. `k` becomes a compound of `a` when a test adds
/// the edge. `k`'s only coupling to `a` is then the edge's factor, so that
/// factor, if read, carries `a`'s evidence into `k` as a message from a
/// source `k` hears from nowhere else (a second factor from the SAME source
/// would be grouped with the first and could move nothing).
struct Tree {
    agent: Uuid,
    k: Uuid,
    a: Uuid,
}

async fn tree(pool: &PgPool) -> Tree {
    let (agent, group) = seed_agent_with_group(pool, "bp-atom-level").await;
    let frame = binary_frame(pool).await;
    let k = claim(pool, agent, group, "compound", 0.5).await;
    let a = claim(pool, agent, group, "atom", 0.8).await;
    let b = claim(pool, agent, group, "sibling atom", 0.7).await;
    bba(pool, a, frame, agent, 0.85).await;
    bba(pool, b, frame, agent, 0.6).await;
    evidential_factor(pool, a, b, None).await;
    evidential_factor(pool, k, b, None).await;
    Tree { agent, k, a }
}

// ── (1) BP apply is refused by default ──────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn apply_bp_updates_refused_by_default(pool: PgPool) {
    let t = tree(&pool).await;
    let before = (stored(&pool, t.k).await, stored(&pool, t.a).await);

    let state = state_default(&pool).await;

    // Precondition: on this fixture BP HAS something to write, so a refusal
    // below is the switch, not an empty result.
    let (dry, _) = diagnose(&pool, &state, t.agent, "cdst").await;
    assert!(
        dry.contains_key(&t.a) && dry.contains_key(&t.k),
        "read-only BP must still run and cover both claims: {dry:?}"
    );

    for mode in ["cdst", "scalar"] {
        let refused = propagate(
            &pool,
            &state,
            t.agent,
            json!({"mode": mode, "apply_updates": true}),
        )
        .await;
        assert_eq!(
            refused.err(),
            Some(StatusCode::CONFLICT),
            "{mode}: apply_updates:true must be refused (409) when EPIGRAPH_BP_APPLY is not on"
        );
    }
    // A frame with no factors used to short-circuit to 200 before any apply
    // logic ran; the refusal must not depend on there being work to do.
    let empty = propagate(
        &pool,
        &state,
        t.agent,
        json!({"frame_id": Uuid::new_v4(), "apply_updates": true}),
    )
    .await;
    assert_eq!(
        empty.err(),
        Some(StatusCode::CONFLICT),
        "apply_updates:true over an empty factor set must be refused too"
    );

    assert_eq!(
        (stored(&pool, t.k).await, stored(&pool, t.a).await),
        before,
        "a refused apply writes no claim row"
    );

    // Positive control: the same request on a process with BP apply ON does
    // write, so the unchanged rows above are the refusal's doing.
    let on = state_bp_apply_on(&pool).await;
    let applied = propagate(
        &pool,
        &on,
        t.agent,
        json!({"mode": "cdst", "apply_updates": true}),
    )
    .await
    .expect("with BP apply on, apply_updates:true runs");
    assert!(
        applied["applied_count"].as_u64().unwrap_or(0) >= 1,
        "control: the flag-on apply writes at least the atom: {applied}"
    );
    assert_ne!(
        stored(&pool, t.a).await,
        before.1,
        "control: the flag-on apply changed the atom's stored row"
    );
}

// ── (2) a keyed decomposes_to factor is not read by BP ──────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn bp_loaders_skip_decomposes_to(pool: PgPool) {
    let state = state_default(&pool).await;

    // A fresh tree per engine: the other engine's tree stays in the graph, so
    // each comparison is between two runs over the same rows but one.
    for mode in ENGINES {
        let t = tree(&pool).await;
        let (without, n_without) = diagnose(&pool, &state, t.agent, mode).await;
        assert!(
            without.contains_key(&t.k),
            "{mode}: the compound is a BP variable"
        );

        // Make `k` a compound of `a`. The trigger mints a keyed factor.
        let edge = decomposes_to(&pool, t.k, t.a).await;
        let factor = trigger_factor(&pool, edge).await;

        let (with, n_with) = diagnose(&pool, &state, t.agent, mode).await;
        let gap = max_gap(&without, &with);
        assert!(
            gap < SAME,
            "{mode}: adding a decomposes_to edge moved the BP result by {gap}; \
             without={without:?} with={with:?}"
        );
        assert_eq!(
            n_with, n_without,
            "{mode}: the decomposes_to factor must not be loaded"
        );

        // Control: the SAME row under another relationship IS a live factor
        // that moves the compound, so the equality above is the skip.
        set_factor_properties(
            &pool,
            factor,
            json!({"relationship": "supports", "source_edge_id": edge.to_string()}),
        )
        .await;
        let (rekeyed, _) = diagnose(&pool, &state, t.agent, mode).await;
        assert!(
            max_gap(&without, &rekeyed) > 1e-4,
            "{mode} control: the re-keyed factor must move the result; \
             without={without:?} rekeyed={rekeyed:?}"
        );
    }
}

// ── (3) a legacy unkeyed factor on an in-force decomposes_to pair ───────────

#[sqlx::test(migrations = "../../migrations")]
async fn bp_loaders_skip_legacy_unkeyed_decomposes_to(pool: PgPool) {
    let state = state_default(&pool).await;

    for mode in ENGINES {
        // Both orders of `variable_ids`, each pinned explicitly: the trigger
        // sorts them by uuid, so a row taken as minted would exercise only
        // whichever arm of the either-order edge match the random ids pick.
        for compound_first in [true, false] {
            let t = tree(&pool).await;
            let (without, _) = diagnose(&pool, &state, t.agent, mode).await;

            let edge = decomposes_to(&pool, t.k, t.a).await;
            let factor = trigger_factor(&pool, edge).await;
            // The shape rows minted before the trigger keyed them: no
            // properties, and the pair in the order this case pins.
            let vars = if compound_first {
                vec![t.k, t.a]
            } else {
                vec![t.a, t.k]
            };
            sqlx::query(
                "UPDATE factors SET properties = '{}'::jsonb, variable_ids = $2 WHERE id = $1",
            )
            .bind(factor)
            .bind(&vars)
            .execute(&pool)
            .await
            .expect("reshape the row to a legacy row in the pinned order");

            let (legacy, _) = diagnose(&pool, &state, t.agent, mode).await;
            let gap = max_gap(&without, &legacy);
            assert!(
                gap < SAME,
                "{mode} compound_first={compound_first}: an unkeyed factor on an in-force \
                 decomposes_to pair moved BP by {gap}; without={without:?} legacy={legacy:?}"
            );

            // The legacy arm is narrow: only a `directional_support` row (the
            // type the trigger mints for decomposes_to) is matched to the
            // edge. An unkeyed `evidential_support` row on the SAME in-force
            // pair is not a decomposes_to factor and stays readable (D4 keeps
            // read-only BP's evidential couplings to compounds).
            let mut sorted = [t.k, t.a];
            sorted.sort();
            let evidential: Uuid = sqlx::query_scalar(
                "INSERT INTO factors (factor_type, variable_ids, potential, properties) \
                 VALUES ('evidential_support', $1, '{\"strength\": 0.8}', '{}') RETURNING id",
            )
            .bind(sorted.to_vec())
            .fetch_one(&pool)
            .await
            .expect("seed an unkeyed evidential_support row on the decomposition pair");
            let (with_evidential, _) = diagnose(&pool, &state, t.agent, mode).await;
            assert!(
                max_gap(&legacy, &with_evidential) > 1e-4,
                "{mode} compound_first={compound_first}: an unkeyed evidential_support row on \
                 an in-force decomposes_to pair must still be read; legacy={legacy:?} \
                 with_evidential={with_evidential:?}"
            );
            sqlx::query("DELETE FROM factors WHERE id = $1")
                .bind(evidential)
                .execute(&pool)
                .await
                .expect("remove the evidential_support row again");

            // Control: once the edge is retracted (`valid_to` in the past) the
            // pair is no longer an in-force decomposition, and the same
            // unkeyed row is an ordinary factor again.
            sqlx::query("UPDATE edges SET valid_to = now() - interval '1 day' WHERE id = $1")
                .bind(edge)
                .execute(&pool)
                .await
                .expect("retract the edge");
            let (retracted, _) = diagnose(&pool, &state, t.agent, mode).await;
            assert!(
                max_gap(&without, &retracted) > 1e-4,
                "{mode} compound_first={compound_first} control: with the edge retracted the \
                 unkeyed factor is read; without={without:?} retracted={retracted:?}"
            );
        }
    }
}

// ── (2b) a supports edge parallel to a decomposition ────────────────────────

/// An in-force `supports` edge `source -> target`. The `edges_auto_factor`
/// trigger maps it to `directional_support`, the same factor type as
/// `decomposes_to`, keyed `relationship = 'supports'`.
async fn supports(pool: &PgPool, source: Uuid, target: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports') RETURNING id",
    )
    .bind(source)
    .bind(target)
    .fetch_one(pool)
    .await
    .expect("seed a supports edge")
}

/// The `relationship` keys of every factor over the pair.
async fn pair_factor_keys(pool: &PgPool, x: Uuid, y: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT COALESCE(properties->>'relationship', '') FROM factors \
         WHERE variable_ids @> ARRAY[$1, $2]::uuid[] AND cardinality(variable_ids) = 2 \
         ORDER BY 1",
    )
    .bind(x)
    .bind(y)
    .fetch_all(pool)
    .await
    .expect("read the pair's factors")
}

/// The plan's fixture: a compound and its atom joined by `decomposes_to` AND
/// `supports`, created in both orders. `idx_factors_type_vars_frame` is
/// UNIQUE on (factor_type, sorted variable_ids, frame), and the trigger
/// inserts `ON CONFLICT DO NOTHING`, so the pair holds ONE trigger factor,
/// keyed by whichever edge came first.
#[sqlx::test(migrations = "../../migrations")]
async fn bp_parallel_supports_and_decomposes_to(pool: PgPool) {
    let state = state_default(&pool).await;

    for mode in ENGINES {
        // supports first: the pair's factor is the supports one, and the later
        // decomposes_to edge adds nothing to BP. The result is the
        // supports-only graph's.
        let t = tree(&pool).await;
        let (without, _) = diagnose(&pool, &state, t.agent, mode).await;
        supports(&pool, t.a, t.k).await;
        let (supports_only, n_supports_only) = diagnose(&pool, &state, t.agent, mode).await;
        assert!(
            max_gap(&without, &supports_only) > 1e-4,
            "{mode} control: the supports edge's factor is read and moves the compound; \
             without={without:?} supports_only={supports_only:?}"
        );
        decomposes_to(&pool, t.k, t.a).await;
        assert_eq!(
            pair_factor_keys(&pool, t.k, t.a).await,
            vec!["supports".to_string()],
            "{mode}: the decomposes_to edge's trigger row conflicts with the supports row"
        );
        let (both, n_both) = diagnose(&pool, &state, t.agent, mode).await;
        let gap = max_gap(&supports_only, &both);
        assert!(
            gap < SAME && n_both == n_supports_only,
            "{mode} supports first: adding the decomposes_to edge moved BP by {gap} \
             ({n_supports_only} -> {n_both} factors); supports_only={supports_only:?} \
             both={both:?}"
        );

        // decomposes_to first: the pair's only factor is the decomposes_to
        // one, which BP does not read, and the supports edge's trigger row is
        // dropped by the conflict. BP is identical to the graph without the
        // decomposes_to factor (the plan's property), which here has NO
        // factor over the pair at all.
        //
        // KNOWN GAP, pinned: the supports relationship has no BP coupling in
        // this order, unlike the order above. The trigger, not this PR, drops
        // its row; a migration that stops the trigger minting decomposes_to
        // factors closes it, and deleting this pair's decomposes_to row does
        // not restore a supports factor.
        let t = tree(&pool).await;
        let (without, n_without) = diagnose(&pool, &state, t.agent, mode).await;
        decomposes_to(&pool, t.k, t.a).await;
        supports(&pool, t.a, t.k).await;
        assert_eq!(
            pair_factor_keys(&pool, t.k, t.a).await,
            vec!["decomposes_to".to_string()],
            "{mode}: the supports edge's trigger row conflicts with the decomposes_to row"
        );
        let (both, n_both) = diagnose(&pool, &state, t.agent, mode).await;
        let gap = max_gap(&without, &both);
        assert!(
            gap < SAME && n_both == n_without,
            "{mode} decomposes_to first: known gap changed, BP now reads a coupling for the \
             pair (moved by {gap}, {n_without} -> {n_both} factors); update this test and \
             bp_readable_factor_sql's doc; without={without:?} both={both:?}"
        );
    }
}

// ── (3b) the legacy arm, on a session row security filters ────────────────

/// The split `AppState` of `belief_computation_scoped_read.rs`: the raw
/// `db_pool` is downgraded to `epigraph_app` (filtered by row security and
/// stamped with no viewer, as a request-path raw-pool read is), while
/// `scoped` is an ordinary `ScopedPool`. Every other fixture in this file runs
/// on the superuser test DSN, which bypasses row security, so a read that only
/// works because it sees every edge passes there; here it cannot.
async fn state_app_role(pool: &PgPool) -> AppState {
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped_pool(pool).await);
    let raw_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&state.db_pool)
        .await
        .expect("current_user on the raw pool");
    assert_eq!(
        raw_user, "epigraph_app",
        "CALIBRATION: the raw pool must be the filtered application role"
    );
    state
}

/// The baseline [`Tree`] with PUBLIC claims, so their priors and BBAs are
/// readable on a filtered session whatever is stamped on it, and only the
/// edge's own tenancy differs between the arms below.
async fn public_tree(pool: &PgPool) -> (Tree, Uuid) {
    let (agent, group) = seed_agent_with_group(pool, "bp-atom-level-app-role").await;
    let frame = binary_frame(pool).await;
    let k = public_claim(pool, agent, "public compound", 0.5).await;
    let a = public_claim(pool, agent, "public atom", 0.8).await;
    let b = public_claim(pool, agent, "public sibling atom", 0.7).await;
    bba(pool, a, frame, agent, 0.85).await;
    bba(pool, b, frame, agent, 0.6).await;
    evidential_factor(pool, a, b, None).await;
    evidential_factor(pool, k, b, None).await;
    (Tree { agent, k, a }, group)
}

/// An in-force `decomposes_to` edge `compound -> atom` declared private to
/// `group`. Both ends are public, so migration 072's no-widening arm keeps
/// the declaration: a decomposition only `group` can see.
async fn private_decomposes_to(pool: &PgPool, compound: Uuid, atom: Uuid, group: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            visibility, owner_group_id) \
         VALUES ($1, 'claim', $2, 'claim', 'decomposes_to', 'group', $3) RETURNING id",
    )
    .bind(compound)
    .bind(atom)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("seed a group-private decomposes_to edge")
}

#[sqlx::test(migrations = "../../migrations")]
async fn bp_legacy_skip_holds_on_the_app_role_for_the_callers_private_edge(pool: PgPool) {
    let state = state_app_role(&pool).await;

    for mode in ["cdst", "scalar"] {
        // `private = false` is the calibration arm: a public edge is visible
        // to any session, so the skip must hold there whatever the loader runs
        // on. `private = true` is the subject: the edge is private to the
        // caller's own group.
        for private in [false, true] {
            let (t, group) = public_tree(&pool).await;
            let (without, _) = diagnose(&pool, &state, t.agent, mode).await;

            let edge = if private {
                private_decomposes_to(&pool, t.k, t.a, group).await
            } else {
                decomposes_to(&pool, t.k, t.a).await
            };
            let visibility: String =
                sqlx::query_scalar("SELECT visibility::text FROM edges WHERE id = $1")
                    .bind(edge)
                    .fetch_one(&pool)
                    .await
                    .expect("read the edge's visibility");
            assert_eq!(
                visibility,
                if private { "group" } else { "public" },
                "CALIBRATION: the edge carries the tenancy this arm is about"
            );
            let factor = trigger_factor(&pool, edge).await;
            set_factor_properties(&pool, factor, json!({})).await;

            let (legacy, _) = diagnose(&pool, &state, t.agent, mode).await;
            let gap = max_gap(&without, &legacy);
            assert!(
                gap < SAME,
                "{mode} private={private}: an unkeyed factor on the caller's own in-force \
                 decomposes_to pair moved BP by {gap} on a filtered session; \
                 without={without:?} legacy={legacy:?}"
            );

            // Control: retracted, the same row is an ordinary factor and moves
            // the result, so the equality above is the skip and not a factor
            // the engine could not use.
            sqlx::query("UPDATE edges SET valid_to = now() - interval '1 day' WHERE id = $1")
                .bind(edge)
                .execute(&pool)
                .await
                .expect("retract the edge");
            let (retracted, _) = diagnose(&pool, &state, t.agent, mode).await;
            assert!(
                max_gap(&without, &retracted) > 1e-4,
                "{mode} private={private} control: with the edge retracted the unkeyed \
                 factor is read; without={without:?} retracted={retracted:?}"
            );
        }
    }
}

// ── (4) an edge create inserts no route-level factor ────────────────────────

fn auth(agent: Uuid) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: agent,
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: ClientType::Service,
        scopes: vec!["edges:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }))
}

#[sqlx::test(migrations = "../../migrations")]
async fn edge_create_inserts_no_route_factor(pool: PgPool) {
    let state = state_default(&pool).await;
    let (agent, group) = seed_agent_with_group(&pool, "bp-p2a").await;
    let source = claim(&pool, agent, group, "supporter", 0.6).await;
    let target = claim(&pool, agent, group, "supported", 0.6).await;

    let viewer = Viewer::resolve(&pool, agent).await.expect("resolve viewer");
    let (status, Json(created)) = create_edge(
        ViewerExtractor(viewer),
        State(state.clone()),
        auth(agent),
        Json(CreateEdgeRequest {
            source_id: source,
            target_id: target,
            source_type: "claim".to_string(),
            target_type: "claim".to_string(),
            relationship: "supports".to_string(),
            properties: None,
            labels: None,
            valid_from: None,
            valid_to: None,
            if_not_exists: false,
        }),
    )
    .await
    .unwrap_or_else(|e| panic!("POST /api/v1/edges supports must succeed: {e:?}"));
    assert_eq!(status, StatusCode::CREATED);
    let edge = created.edge.id;

    // Every factor over the pair is derived from an edge row and says which:
    // the trigger keys its factor by `source_edge_id`. A factor over the pair
    // that names no edge was written by the route itself.
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT factor_type, properties->>'source_edge_id' FROM factors \
         WHERE variable_ids @> ARRAY[$1, $2]::uuid[]",
    )
    .bind(source)
    .bind(target)
    .fetch_all(&pool)
    .await
    .expect("read the factors over the pair");
    assert!(
        !rows.is_empty(),
        "control: the edges_auto_factor trigger still keys a factor to a supports edge"
    );
    let unkeyed: Vec<&(String, Option<String>)> = rows
        .iter()
        .filter(|(_, src)| src.as_deref() != Some(edge.to_string().as_str()))
        .collect();
    assert!(
        unkeyed.is_empty(),
        "an edge create must not insert a route-level factor; factors not keyed to \
         edge {edge}: {unkeyed:?}"
    );
}

// ── (5) BP apply, when switched on, never writes a compound (D4) ────────────

#[sqlx::test(migrations = "../../migrations")]
async fn bp_apply_skips_compounds(pool: PgPool) {
    // Both engines' apply call sites (the cdst branch writes an interval, the
    // scalar branch a BetP only) and their `skipped_compounds` keys.
    for mode in ["cdst", "scalar"] {
        apply_skips_compounds_case(&pool, mode).await;
    }
}

/// One BP apply over a small decomposition, checked claim by claim:
///
/// * `k` (a root: `k -> m`) and `m` (a mid node: `m -> leaf`) are compounds
///   and must not be written (D4);
/// * `leaf` (a decomposes_to TARGET), `r` (whose only decomposes_to out-edge
///   is retracted) and the standalone `a` are atoms and must be written with
///   BP's value.
///
/// Every claim is a BP variable through an `evidential_support` factor it
/// shares with the evidenced atom `a`.
async fn apply_skips_compounds_case(pool: &PgPool, mode: &str) {
    // The case owns the factor graph, so `skipped_compounds` counts this
    // case's compounds only.
    sqlx::query("DELETE FROM factors")
        .execute(pool)
        .await
        .expect("clear the factor graph");
    let (agent, group) = seed_agent_with_group(pool, &format!("bp-apply-compound-{mode}")).await;
    let frame = binary_frame(pool).await;
    let k = claim(pool, agent, group, "root compound", 0.5).await;
    let m = claim(pool, agent, group, "mid compound", 0.5).await;
    let leaf = claim(pool, agent, group, "leaf", 0.5).await;
    let r = claim(pool, agent, group, "retracted decomposition", 0.5).await;
    let x = claim(pool, agent, group, "retracted part", 0.5).await;
    let a = claim(pool, agent, group, "evidenced atom", 0.85).await;
    bba(pool, a, frame, agent, 0.85).await;
    decomposes_to(pool, k, m).await;
    decomposes_to(pool, m, leaf).await;
    let retracted = decomposes_to(pool, r, x).await;
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 day' WHERE id = $1")
        .bind(retracted)
        .execute(pool)
        .await
        .expect("retract r's decomposition");
    for c in [k, m, leaf, r] {
        evidential_factor(pool, c, a, None).await;
    }

    let before: BTreeMap<Uuid, _> = {
        let mut map = BTreeMap::new();
        for c in [k, m, leaf, r] {
            map.insert(c, stored(pool, c).await);
        }
        map
    };
    let state = state_bp_apply_on(pool).await;
    let body = propagate(
        pool,
        &state,
        agent,
        json!({"mode": mode, "apply_updates": true, "max_iterations": 30}),
    )
    .await
    .expect("with BP apply on, apply_updates:true runs");
    let result = betps(&body);

    // Precondition: BP computed a new value for every claim checked below, so
    // a write, or its absence, is visible in the stored row.
    for (name, c) in [("k", k), ("m", m), ("leaf", leaf), ("r", r)] {
        let betp = *result
            .get(&c)
            .unwrap_or_else(|| panic!("{mode}: {name} is a BP variable: {body}"));
        let was = before[&c].2.unwrap();
        assert!(
            (betp - was).abs() > 1e-4,
            "{mode} precondition: BP computed a new value for {name} ({betp} vs {was})"
        );
    }

    for (name, c) in [("root k", k), ("mid m", m)] {
        assert_eq!(
            stored(pool, c).await,
            before[&c],
            "{mode}: BP apply wrote the {name} {c}: atoms only (D4)"
        );
    }
    assert_eq!(
        body["skipped_compounds"].as_u64(),
        Some(2),
        "{mode}: the response counts the two compounds it did not write: {body}"
    );

    // Positive controls: every atom in the same run IS written, with BP's
    // value: a leaf (a decomposes_to target is not a compound), a claim whose
    // only decomposition is retracted, and the standalone atom.
    for (name, c) in [("leaf", leaf), ("r", r), ("a", a)] {
        let after = stored(pool, c)
            .await
            .2
            .unwrap_or_else(|| panic!("{mode}: {name} has a stored BetP"));
        assert!(
            (after - result[&c]).abs() < 1e-12,
            "{mode} control: {name}'s stored BetP is the value BP computed ({after} vs {})",
            result[&c]
        );
    }
}
