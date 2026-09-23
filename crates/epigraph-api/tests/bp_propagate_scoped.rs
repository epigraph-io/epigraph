//! `POST /api/v1/bp/propagate` reads only what the caller may read and writes
//! only what the caller may write.
//!
//! Deferred-commitment screen key `f-shard4-a2-propagate-beliefs`, recorded
//! on register entry `F-SHARD4-A2`. Before the fix, all seven of the handler's
//! statements ran on the raw pool with no viewer predicate and the route
//! checked no scope. So any bearer:
//!
//! * got a propagated BetP for every claim any factor named, the caller's
//!   unreadable claims included, and took in factors derived from edges or
//!   filed in frames it cannot read;
//! * could overwrite `pignistic_prob` / `belief` / `plausibility` on any such
//!   claim with `apply_updates: true`, with or without `claims:write`;
//! * got no failure count from the scalar branch at all, which discarded its
//!   write errors.
//!
//! Every refusal below asserts the ROWS as well as the response: a claim's
//! `(belief, plausibility, pignistic_prob, belief_frame_id)` is read back and
//! compared with what was seeded. A response that said "refused" while the row
//! changed would pass a response-only test.
//!
//! # Fixture shape
//!
//! Each test makes its own frame and passes it as `frame_id`, so factors other
//! tests left in the shared `DATABASE_URL` database never join the run. Claims
//! are declared `(visibility, <author's personal group>)` explicitly, as
//! `hypothesis_promote_authority.rs` does: an undeclared claim lands in the
//! seed group through migration 074's escape hatch, and nobody can write that.
//! Every claim starts at `(0.3, 0.9, 0.8, <the test's frame>)`. The factors
//! are `mutual_exclusion` over claims that both start at BetP 0.8, which BP
//! pushes down, so a write that happened is always a visible change.

#![cfg(feature = "db")]

use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

mod common;

/// The world group: the owner a public registry row carries.
const WORLD: &str = "00000000-0000-0000-0000-000000000000";

/// What every claim here is seeded with: `(belief, plausibility, pignistic_prob)`.
const SEEDED: (f64, f64, f64) = (0.3, 0.9, 0.8);

async fn test_pool() -> (String, PgPool) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to test DB");
    (url, pool)
}

/// A frame of this test's own.
async fn fresh_frame(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses, visibility, owner_group_id) \
         VALUES ($1, ARRAY['supported','unsupported'], 'public', $2::uuid) RETURNING id",
    )
    .bind(format!("bp-propagate-scoped-{}", Uuid::new_v4()))
    .bind(WORLD)
    .fetch_one(pool)
    .await
    .expect("seed frame")
}

/// An agent with a personal group it administers.
async fn seed_principal(pool: &PgPool) -> Uuid {
    let agent = common::seed_system_agent(pool).await;
    common::personal_group_of(pool, agent).await;
    agent
}

/// A claim authored by `author`, declared `(visibility, <author's personal
/// group>)`, with the [`SEEDED`] cached belief summarizing `frame`.
async fn seed_claim(pool: &PgPool, author: Uuid, visibility: &str, frame: Uuid) -> Uuid {
    let group = common::personal_group_of(pool, author).await;
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, \
                             labels, visibility, owner_group_id, belief, plausibility, \
                             pignistic_prob, belief_frame_id) \
         VALUES ($1, $2, $3, $4, 0.5, true, ARRAY[]::text[], $5, $6, $7, $8, $9, $10)",
    )
    .bind(id)
    .bind(format!("bp-propagate-scoped claim {id}"))
    .bind(&hash)
    .bind(author)
    .bind(visibility)
    .bind(group)
    .bind(SEEDED.0)
    .bind(SEEDED.1)
    .bind(SEEDED.2)
    .bind(frame)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// A `mutual_exclusion` factor over `vars` in `frame`.
async fn seed_factor(pool: &PgPool, frame: Uuid, vars: &[Uuid]) {
    sqlx::query(
        "INSERT INTO factors (factor_type, variable_ids, potential, frame_id) \
         VALUES ('mutual_exclusion', $1, '{}'::jsonb, $2)",
    )
    .bind(vars)
    .bind(frame)
    .execute(pool)
    .await
    .expect("seed factor");
}

/// A `CONTRADICTS` edge from `source` to `target`, DECLARED private to
/// `author`'s personal group in the INSERT, and the factor the
/// `edges_auto_factor` trigger derives from it, moved into `frame`.
///
/// The trigger writes the factor, as it does for every epistemic claim->claim
/// edge in production, and stamps `properties->>'source_edge_id'`.
/// `epigraph_edges_tenancy`'s no-widening rule keeps the declaration even
/// though both endpoints are public. Both are asserted, so a trigger that
/// stopped doing either fails here rather than passing vacuously.
///
/// The trigger writes the factor with no frame. It is moved into the test's
/// frame, as `promote_hypothesis` moves factors in production, because a
/// `frame_id`-less run would take in every factor in the shared database.
async fn seed_private_edge_factor(
    pool: &PgPool,
    author: Uuid,
    source: Uuid,
    target: Uuid,
    frame: Uuid,
) {
    let group = common::personal_group_of(pool, author).await;
    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            visibility, owner_group_id) \
         VALUES ($1, 'claim', $2, 'claim', 'CONTRADICTS', 'group', $3) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("seed private CONTRADICTS edge");
    let visibility: String = sqlx::query_scalar("SELECT visibility FROM edges WHERE id = $1")
        .bind(edge)
        .fetch_one(pool)
        .await
        .expect("read edge visibility");
    assert_eq!(
        visibility, "group",
        "CALIBRATION: the tenancy trigger must keep the edge's private declaration"
    );
    let moved =
        sqlx::query("UPDATE factors SET frame_id = $2 WHERE properties->>'source_edge_id' = $1")
            .bind(edge.to_string())
            .bind(frame)
            .execute(pool)
            .await
            .expect("move the derived factor into the test's frame")
            .rows_affected();
    assert_eq!(
        moved, 1,
        "CALIBRATION: edges_auto_factor must derive exactly one factor from the edge"
    );
}

/// `(belief, plausibility, pignistic_prob, belief_frame_id)`.
async fn cached(pool: &PgPool, id: Uuid) -> (f64, f64, f64, Option<Uuid>) {
    sqlx::query_as(
        "SELECT belief, plausibility, pignistic_prob, belief_frame_id FROM claims WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read cached belief")
}

async fn assert_unchanged(pool: &PgPool, id: Uuid, frame: Uuid, what: &str) {
    assert_eq!(
        cached(pool, id).await,
        (SEEDED.0, SEEDED.1, SEEDED.2, Some(frame)),
        "{what}: the row must be exactly as seeded"
    );
}

async fn propagate(addr: std::net::SocketAddr, token: &str, body: Value) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/bp/propagate"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("POST /api/v1/bp/propagate");
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let json = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (status, json)
}

/// The claim ids in the response's `updated_beliefs`.
fn reported(body: &Value) -> HashSet<Uuid> {
    body["updated_beliefs"]
        .as_array()
        .unwrap_or_else(|| panic!("no updated_beliefs array; body={body}"))
        .iter()
        .map(|b| {
            b["claim_id"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| panic!("bad claim_id in {b}"))
        })
        .collect()
}

/// The response's BetP for `id`.
fn betp_of(body: &Value, id: Uuid) -> f64 {
    body["updated_beliefs"]
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|b| b["claim_id"].as_str() == Some(&id.to_string()))
        })
        .and_then(|b| b["betp"].as_f64())
        .unwrap_or_else(|| panic!("no betp for {id}; body={body}"))
}

fn apply_failures(body: &Value) -> u64 {
    body["apply_failures"]
        .as_u64()
        .unwrap_or_else(|| panic!("no apply_failures count; body={body}"))
}

/// A stranger's run never names, or computes from, a claim it cannot read.
///
/// The owner holds a public claim `p`, a public claim `q` and a group-private
/// claim `h`, with factors over `(p, h)` and `(p, q)`. The stranger's run must
/// drop the `(p, h)` factor whole: its response names only `p` and `q`, and
/// counts one factor. The owner's run over the same frame names all three,
/// which is what makes the stranger's result a filter and not an empty fixture.
#[tokio::test(flavor = "multi_thread")]
async fn a_stranger_gets_no_belief_for_a_claim_it_cannot_read() {
    let (url, pool) = test_pool().await;
    let owner = seed_principal(&pool).await;
    let stranger = seed_principal(&pool).await;
    let frame = fresh_frame(&pool).await;
    let p = seed_claim(&pool, owner, "public", frame).await;
    let q = seed_claim(&pool, owner, "public", frame).await;
    let h = seed_claim(&pool, owner, "group", frame).await;
    seed_factor(&pool, frame, &[p, h]).await;
    seed_factor(&pool, frame, &[p, q]).await;

    let (addr, _shutdown) = common::spawn_app(&url).await;

    for mode in ["scalar", "cdst"] {
        let body = json!({ "frame_id": frame, "mode": mode });

        let stranger_token = common::test_bearer_token_for_principal(stranger, &["graph:read"]);
        let (status, got) = propagate(addr, &stranger_token, body.clone()).await;
        assert_eq!(status, 200, "{mode}: body={got}");
        assert_eq!(
            reported(&got),
            HashSet::from([p, q]),
            "{mode}: the stranger's run must not name the owner's private claim; body={got}"
        );
        assert_eq!(got["factors_count"], 1, "{mode}: body={got}");
        assert_eq!(got["variables_count"], 2, "{mode}: body={got}");

        let owner_token = common::test_bearer_token_for_principal(owner, &["graph:read"]);
        let (status, got) = propagate(addr, &owner_token, body).await;
        assert_eq!(status, 200, "{mode}: body={got}");
        assert_eq!(
            reported(&got),
            HashSet::from([p, q, h]),
            "{mode}: CALIBRATION, the owner's run over the same frame names all three; \
             body={got}"
        );
        assert_eq!(got["factors_count"], 2, "{mode}: body={got}");
    }

    for id in [p, q, h] {
        assert_unchanged(&pool, id, frame, "a run without apply_updates").await;
    }
}

/// A stranger's run never takes in a factor derived from an edge it cannot
/// read, even when both of the factor's claims are public.
///
/// Most factors are written by the `edges_auto_factor` trigger, not by a
/// handler, and the trigger ignores the edge's tenancy. Here the owner's
/// public claims `p` and `q` are joined only by a `CONTRADICTS` edge private
/// to the owner's group. If its factor reached the stranger's run,
/// `factors_count` and the propagated BetPs would disclose that the private
/// edge exists and what it asserts. The owner's run over the same frame counts
/// the factor, which is what makes the stranger's zero a filter and not an
/// empty fixture.
#[tokio::test(flavor = "multi_thread")]
async fn a_stranger_gets_no_factor_from_an_edge_it_cannot_read() {
    let (url, pool) = test_pool().await;
    let owner = seed_principal(&pool).await;
    let stranger = seed_principal(&pool).await;
    let frame = fresh_frame(&pool).await;
    let p = seed_claim(&pool, owner, "public", frame).await;
    let q = seed_claim(&pool, owner, "public", frame).await;
    seed_private_edge_factor(&pool, owner, p, q, frame).await;

    let (addr, _shutdown) = common::spawn_app(&url).await;

    for mode in ["scalar", "cdst"] {
        let body = json!({ "frame_id": frame, "mode": mode });

        let stranger_token = common::test_bearer_token_for_principal(stranger, &["graph:read"]);
        let (status, got) = propagate(addr, &stranger_token, body.clone()).await;
        assert_eq!(status, 200, "{mode}: body={got}");
        assert_eq!(
            got["factors_count"], 0,
            "{mode}: the factor derived from the owner's private edge must not reach a \
             stranger's run; body={got}"
        );
        assert!(
            reported(&got).is_empty(),
            "{mode}: the stranger's run must propagate nothing; body={got}"
        );

        let owner_token = common::test_bearer_token_for_principal(owner, &["graph:read"]);
        let (status, got) = propagate(addr, &owner_token, body).await;
        assert_eq!(status, 200, "{mode}: body={got}");
        assert_eq!(
            got["factors_count"], 1,
            "{mode}: CALIBRATION, the owner's run over the same frame takes in the factor; \
             body={got}"
        );
        assert_eq!(
            reported(&got),
            HashSet::from([p, q]),
            "{mode}: CALIBRATION; body={got}"
        );
    }

    for id in [p, q] {
        assert_unchanged(&pool, id, frame, "a run without apply_updates").await;
    }
}

/// `apply_updates` needs `claims:write`. Without it the request is 403 even
/// for the claims' owner, and nothing is written.
#[tokio::test(flavor = "multi_thread")]
async fn apply_updates_without_claims_write_is_403_and_writes_nothing() {
    let (url, pool) = test_pool().await;
    let owner = seed_principal(&pool).await;
    let frame = fresh_frame(&pool).await;
    let p = seed_claim(&pool, owner, "public", frame).await;
    let q = seed_claim(&pool, owner, "public", frame).await;
    seed_factor(&pool, frame, &[p, q]).await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token_for_principal(owner, &["graph:read"]);
    let (status, body) = propagate(
        addr,
        &token,
        json!({ "frame_id": frame, "mode": "scalar", "apply_updates": true }),
    )
    .await;
    assert_eq!(status, 403, "body={body}");

    assert_unchanged(&pool, p, frame, "the owner's claim, without claims:write").await;
    assert_unchanged(&pool, q, frame, "the owner's claim, without claims:write").await;
}

/// A caller with `claims:write` still cannot overwrite a claim it can READ but
/// not WRITE: another principal's public claims. Both branches report each one
/// in `apply_failures` and leave every row as seeded.
#[tokio::test(flavor = "multi_thread")]
async fn apply_updates_cannot_overwrite_a_claim_the_caller_can_read_but_not_write() {
    let (url, pool) = test_pool().await;
    let owner = seed_principal(&pool).await;
    let stranger = seed_principal(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token_for_principal(stranger, &["claims:write"]);

    for mode in ["scalar", "cdst"] {
        let frame = fresh_frame(&pool).await;
        let p = seed_claim(&pool, owner, "public", frame).await;
        let q = seed_claim(&pool, owner, "public", frame).await;
        seed_factor(&pool, frame, &[p, q]).await;

        let (status, body) = propagate(
            addr,
            &token,
            json!({ "frame_id": frame, "mode": mode, "apply_updates": true }),
        )
        .await;
        assert_eq!(status, 200, "{mode}: body={body}");
        assert_eq!(body["mode"], mode, "{mode}: body={body}");
        assert_eq!(
            reported(&body),
            HashSet::from([p, q]),
            "{mode}: CALIBRATION, both public claims are readable, so both are computed; \
             body={body}"
        );
        assert_eq!(
            apply_failures(&body),
            2,
            "{mode}: both results must be counted as not written; body={body}"
        );

        assert_unchanged(
            &pool,
            p,
            frame,
            &format!("{mode}: another principal's claim"),
        )
        .await;
        assert_unchanged(
            &pool,
            q,
            frame,
            &format!("{mode}: another principal's claim"),
        )
        .await;
    }
}

/// One run over the caller's own claim and another principal's: the caller's
/// is written, the other is counted and left alone.
///
/// The written row carries the response's BetP and a NULL `belief_frame_id`,
/// because a propagation run does not summarize one frame. The CDST branch
/// writes the interval too; the scalar branch leaves `belief` and
/// `plausibility` as they were.
#[tokio::test(flavor = "multi_thread")]
async fn the_callers_own_claim_is_written_and_the_other_is_counted() {
    let (url, pool) = test_pool().await;
    let owner = seed_principal(&pool).await;
    let other = seed_principal(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token_for_principal(owner, &["claims:write"]);

    for mode in ["scalar", "cdst"] {
        let frame = fresh_frame(&pool).await;
        let own = seed_claim(&pool, owner, "public", frame).await;
        let foreign = seed_claim(&pool, other, "public", frame).await;
        seed_factor(&pool, frame, &[own, foreign]).await;

        let (status, body) = propagate(
            addr,
            &token,
            json!({ "frame_id": frame, "mode": mode, "apply_updates": true }),
        )
        .await;
        assert_eq!(status, 200, "{mode}: body={body}");
        assert_eq!(body["applied"], true, "{mode}: body={body}");
        assert_eq!(
            apply_failures(&body),
            1,
            "{mode}: exactly the other principal's claim is not written; body={body}"
        );

        let (bel, pl, betp, frame_after) = cached(&pool, own).await;
        let expected = betp_of(&body, own);
        assert!(
            (betp - expected).abs() < 1e-12,
            "{mode}: the owner's claim must carry the run's BetP: row {betp}, response \
             {expected}"
        );
        assert_ne!(
            betp, SEEDED.2,
            "{mode}: CALIBRATION, the run moved the BetP"
        );
        assert_eq!(
            frame_after, None,
            "{mode}: belief_frame_id must be NULLed, not left naming a frame the run \
             does not summarize"
        );
        if mode == "scalar" {
            assert_eq!(
                (bel, pl),
                (SEEDED.0, SEEDED.1),
                "the scalar branch writes pignistic_prob only"
            );
        } else {
            assert!(
                (0.0..=1.0).contains(&bel) && (0.0..=1.0).contains(&pl) && bel <= pl,
                "the CDST branch writes a clamped interval: ({bel}, {pl})"
            );
        }

        assert_unchanged(
            &pool,
            foreign,
            frame,
            &format!("{mode}: the other principal's claim"),
        )
        .await;
    }
}
