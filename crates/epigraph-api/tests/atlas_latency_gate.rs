#![cfg(feature = "db")]
//! The Atlas latency budget as a gate (backlog W12 824ac5ac, design §6).
//!
//! The kernel's share of the budget, measured on a PROD-SHAPED synthetic team
//! map and asserted at p95. The plan, with the budget split and the "done
//! when" mapping, is
//! `docs/superpowers/plans/2026-11-13-atlas-w12-latency-gate-plan.md`.
//!
//! # The budget split
//!
//! A level transition or switch flip is on screen within 200 ms at p95 warm
//! and 500 ms cold. [`CLIENT_ALLOWANCE`] (50 ms) of that is the browser's, to
//! draw the level; [`BFF_SHARE`] (30 ms) is the Explorer BFF's, measured by
//! `services/explorer/tests/atlas_latency.rs`. The kernel gets the rest:
//! [`KERNEL_WARM`] 120 ms and [`KERNEL_COLD`] 420 ms. The page-load routes
//! (maps, themes) run once per `/atlas` load and are held to the cold server
//! share, [`PAGE_LOAD`] 450 ms. Every measurement is on loopback: the network
//! between the browser and the server is not modelled.
//!
//! # The map
//!
//! [`Scale::from_env`] reads `ATLAS_LATENCY_SCALE`: `small` (the default, the
//! per-PR run) is [`SMALL_THEMES`] themes; `full` (the staging run) is
//! [`FULL_THEMES`]; an integer is a theme count. Each theme holds [`CLAIMS_PER_THEME`] real
//! `claims` rows (366k / 210), one in five the team's and the rest public,
//! authored by a pool of agents, with an evidence row on one claim in eight.
//! Its levels are `epigraph_atlas_contract::scale::theme_levels` (the W10a
//! generator, re-keyed to those rows), stored through W2's
//! `AtlasMapRepository` in one finished run. The viewer is a reader of the
//! team.
//!
//! # What is timed
//!
//! A full HTTP round trip to `create_router` served by `axum::serve` on a
//! loopback listener, from a `reqwest` client carrying the viewer's bearer:
//! from the request being sent to the last body byte. Every sample is then
//! checked (status 200, and the level, leaf or list asked for) OUTSIDE the
//! timer, so a regression that answers a fast 404 cannot pass, and each
//! distinct level body is checked against the contract once.
//!
//! - **Warm:** one server and one pooled client, after one untimed request
//!   of every type. Samples cycle over distinct levels.
//! - **Cold:** a fresh `ScopedPool`, `AppState`, listener and client for
//!   EVERY sample (no pooled HTTP connection, an empty statement cache), and
//!   a level not asked for before, inside the test's own process.
//! - **Process:** the first request after a deploy or restart. A fresh
//!   `server` binary for EVERY sample (`common/served.rs`), so process
//!   start-up, lazy statics and first-use allocation are inside the sample,
//!   and a fresh client. The binary logs in the way the production login
//!   does: a NOSUPERUSER member of `epigraph_app` whose role default is
//!   `epigraph_app`, so its RLS posture check is armed (asserted per boot)
//!   and every read runs under row security. Its first request is timed (a
//!   switch's is its second: the level flipped from is shown first, untimed)
//!   on a level neither earlier arm asked for, and held to the cold budget.
//!   Start-up itself (spawn to listening) is reported, not gated: nothing is
//!   served before the listener binds. Not covered by any arm: a cold
//!   Postgres buffer cache or OS page cache (the seed has just written the
//!   rows).
//!
//! # The scaling rule
//!
//! Beside the absolute budget, warm claim to leaf may cost at most
//! [`CLAIM_LEAF_OVER_LEAF`] times a warm leaf at p95. Both sides are timed on
//! the same machine in the same run, so a lookup whose cost grows with the
//! whole run turns the per-PR gate red however fast the runner is.
//!
//! The JSON report goes to `ATLAS_LATENCY_REPORT` (a path) when it is set,
//! and is written BEFORE the gate asserts, so a red run keeps its numbers.

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "common/served.rs"]
mod served;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_atlas_contract::check::{check_level_body, Expected};
use epigraph_atlas_contract::scale::{theme_levels, ScaleMap, ScaleTheme};
use epigraph_atlas_contract::{Hierarchy, LevelDocument, MapScope, Node};
use epigraph_db::repos::atlas_map::{AtlasHierarchy, AtlasMap, LevelDoc, NewMapRun};
use epigraph_db::{AtlasMapRepository, ScopedPool, SessionGucMode};
use serde_json::{json, Value};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

// ---- the budget -------------------------------------------------------------------

/// Design §6: a level on screen within this, p95, warm.
const WARM_TOTAL: Duration = Duration::from_millis(200);
/// Design §6: the same, cold.
const COLD_TOTAL: Duration = Duration::from_millis(500);
/// The browser's share: drawing the level once its bytes arrive.
const CLIENT_ALLOWANCE: Duration = Duration::from_millis(50);
/// The Explorer BFF's share (proxy, mirror decode, digest, compression),
/// gated by `services/explorer/tests/atlas_latency.rs`.
const BFF_SHARE: Duration = Duration::from_millis(30);
/// The kernel's share of a warm transition.
const KERNEL_WARM: Duration = WARM_TOTAL
    .saturating_sub(CLIENT_ALLOWANCE)
    .saturating_sub(BFF_SHARE);
/// The kernel's share of a cold transition.
const KERNEL_COLD: Duration = COLD_TOTAL
    .saturating_sub(CLIENT_ALLOWANCE)
    .saturating_sub(BFF_SHARE);
/// The page-load routes (maps, themes): once per `/atlas` load, held to the
/// cold server share.
const PAGE_LOAD: Duration = COLD_TOTAL.saturating_sub(CLIENT_ALLOWANCE);

/// Claim to leaf, warm, at p95, may cost at most this many times a leaf.
///
/// The route is a leaf read plus one lookup of the claim's leaf, so its cost
/// should track a leaf's, whatever the run's size; a lookup whose cost grows
/// with the whole run (the scan W12 found: every level of the run detoasted
/// before the theme narrowed anything) breaks the ratio long before it breaks
/// the absolute budget on a fast machine. Both sides are measured on the
/// same machine in the same run, so the rule does not depend on its speed.
/// Measured: 1.04 to 1.2 at the per-PR scale in debug, 1.7 at full scale in
/// release; the old scan was about 9 at the per-PR scale and 118 at full.
const CLAIM_LEAF_OVER_LEAF: f64 = 3.0;

/// Claims per theme: about 366k current claims over about 210 themes.
const CLAIMS_PER_THEME: usize = 1_743;
/// Themes at the per-PR scale (about 42k claims, 1.6k levels): large enough
/// that a read whose cost grows with the whole run, not with one theme,
/// shows in the gate (the claim-to-leaf scan did: about 7 ms per 100
/// levels in a debug build).
const SMALL_THEMES: usize = 24;
/// Themes at the staging scale: about 366k claims.
const FULL_THEMES: usize = 210;

// ---- the verdict (pure) -----------------------------------------------------------

/// What one request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Kind {
    /// A theme's level-0 group.
    Root,
    /// A group below the root.
    Group,
    /// A leaf (the `for_viewer` path).
    Leaf,
    /// The twin, in the other hierarchy, of the level just shown.
    Switch,
    /// `/claims/:id/leaf`.
    ClaimLeaf,
    /// `/maps/:map/themes`.
    Themes,
    /// `/maps`.
    Maps,
}

const KINDS: [Kind; 7] = [
    Kind::Root,
    Kind::Group,
    Kind::Leaf,
    Kind::Switch,
    Kind::ClaimLeaf,
    Kind::Themes,
    Kind::Maps,
];

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Root => "root",
            Kind::Group => "group",
            Kind::Leaf => "leaf",
            Kind::Switch => "switch",
            Kind::ClaimLeaf => "claim_leaf",
            Kind::Themes => "themes",
            Kind::Maps => "maps",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Temp {
    Warm,
    Cold,
    /// The first request of a freshly started `server` binary.
    Process,
}

const TEMPS: [Temp; 3] = [Temp::Warm, Temp::Cold, Temp::Process];

impl Temp {
    fn name(self) -> &'static str {
        match self {
            Temp::Warm => "warm",
            Temp::Cold => "cold",
            Temp::Process => "process",
        }
    }
}

/// The kernel's budget for one (type, warm/cold).
fn budget(kind: Kind, temp: Temp) -> Duration {
    match (kind, temp) {
        (Kind::Themes | Kind::Maps, _) => PAGE_LOAD,
        (_, Temp::Warm) => KERNEL_WARM,
        (_, Temp::Cold | Temp::Process) => KERNEL_COLD,
    }
}

type Samples = BTreeMap<(Kind, Temp), Vec<Duration>>;

/// The `q` quantile of `xs` by nearest rank (`None` when empty).
fn quantile(xs: &[Duration], q: f64) -> Option<Duration> {
    if xs.is_empty() {
        return None;
    }
    let mut s = xs.to_vec();
    s.sort();
    let rank = ((q * s.len() as f64).ceil() as usize).clamp(1, s.len());
    Some(s[rank - 1])
}

/// One (type, warm/cold) over its budget.
#[derive(Debug, Clone, PartialEq)]
struct Breach {
    kind: Kind,
    temp: Temp,
    /// `None`: nothing was measured.
    p95: Option<Duration>,
    budget: Duration,
}

/// Every (type, warm/cold) of `expected` whose p95 exceeds its budget, or
/// that has no sample: a type that measured nothing cannot pass.
fn verdict(
    samples: &Samples,
    expected: &[(Kind, Temp)],
    budget: impl Fn(Kind, Temp) -> Duration,
) -> Vec<Breach> {
    expected
        .iter()
        .filter_map(|&(kind, temp)| {
            let b = budget(kind, temp);
            let p95 = samples.get(&(kind, temp)).and_then(|xs| quantile(xs, 0.95));
            match p95 {
                Some(p) if p <= b => None,
                _ => Some(Breach {
                    kind,
                    temp,
                    p95,
                    budget: b,
                }),
            }
        })
        .collect()
}

/// Warm claim to leaf over `max_ratio` times the warm leaf, at p95.
#[derive(Debug, Clone, PartialEq)]
struct ScalingBreach {
    claim_leaf_p95: Duration,
    leaf_p95: Duration,
    ratio: f64,
    max_ratio: f64,
}

/// The scaling rule ([`CLAIM_LEAF_OVER_LEAF`]): `Some` when warm claim to
/// leaf costs more than `max_ratio` warm leaves at p95. `None` when either
/// side measured nothing: [`verdict`] already reports that as a breach.
fn scaling_verdict(samples: &Samples, max_ratio: f64) -> Option<ScalingBreach> {
    let p95 = |k| {
        samples
            .get(&(k, Temp::Warm))
            .and_then(|xs| quantile(xs, 0.95))
    };
    let (claim_leaf_p95, leaf_p95) = (p95(Kind::ClaimLeaf)?, p95(Kind::Leaf)?);
    let ratio = claim_leaf_p95.as_secs_f64() / leaf_p95.as_secs_f64().max(1e-9);
    (ratio > max_ratio).then_some(ScalingBreach {
        claim_leaf_p95,
        leaf_p95,
        ratio,
        max_ratio,
    })
}

fn all_expected() -> Vec<(Kind, Temp)> {
    KINDS.iter().flat_map(|&k| TEMPS.map(|t| (k, t))).collect()
}

fn ms(d: Duration) -> f64 {
    (d.as_secs_f64() * 1000.0 * 100.0).round() / 100.0
}

#[test]
fn the_verdict_is_p95_against_the_budget() {
    let d = Duration::from_millis;
    let b = |_: Kind, _: Temp| d(100);
    let mut s: Samples = BTreeMap::new();
    // 95 fast samples and 5 slow: nearest-rank p95 is the 95th, fast.
    s.insert(
        (Kind::Leaf, Temp::Warm),
        (0..100).map(|i| d(if i < 95 { 10 } else { 900 })).collect(),
    );
    // p50 well under budget, but 10 of 100 over it: p95 is over.
    s.insert(
        (Kind::Group, Temp::Warm),
        (0..100).map(|i| d(if i < 90 { 10 } else { 150 })).collect(),
    );
    let got = verdict(
        &s,
        &[
            (Kind::Leaf, Temp::Warm),
            (Kind::Group, Temp::Warm),
            (Kind::Root, Temp::Cold),
        ],
        b,
    );
    assert_eq!(
        got,
        vec![
            Breach {
                kind: Kind::Group,
                temp: Temp::Warm,
                p95: Some(d(150)),
                budget: d(100),
            },
            // Nothing measured is a breach, not a pass.
            Breach {
                kind: Kind::Root,
                temp: Temp::Cold,
                p95: None,
                budget: d(100),
            },
        ]
    );
    assert_eq!(quantile(&[d(3), d(1), d(2)], 0.5), Some(d(2)));
    assert_eq!(quantile(&[], 0.5), None);
}

#[test]
fn claim_to_leaf_is_held_to_a_multiple_of_a_leaf() {
    let d = Duration::from_millis;
    let with = |claim_leaf: u64, leaf: u64| -> Samples {
        let mut s: Samples = BTreeMap::new();
        s.insert((Kind::ClaimLeaf, Temp::Warm), vec![d(claim_leaf); 20]);
        s.insert((Kind::Leaf, Temp::Warm), vec![d(leaf); 20]);
        // Cold is not held to the ratio: connection setup dominates it.
        s.insert((Kind::ClaimLeaf, Temp::Cold), vec![d(900); 20]);
        s.insert((Kind::Leaf, Temp::Cold), vec![d(10); 20]);
        s
    };
    // Both well inside the absolute budget, but claim to leaf costs nine
    // leaves: the old whole-run scan at the per-PR scale.
    let got = scaling_verdict(&with(90, 10), 3.0).expect("a breach");
    assert_eq!((got.claim_leaf_p95, got.leaf_p95), (d(90), d(10)));
    assert!((got.ratio - 9.0).abs() < 1e-9, "{got:?}");
    // At the bound, and under it: no breach.
    assert_eq!(scaling_verdict(&with(30, 10), 3.0), None);
    assert_eq!(scaling_verdict(&with(12, 10), 3.0), None);
    // Nothing measured is left to `verdict`.
    assert_eq!(scaling_verdict(&BTreeMap::new(), 3.0), None);
}

#[test]
fn the_kernel_budget_is_the_design_budget_less_the_other_shares() {
    assert_eq!(KERNEL_WARM, Duration::from_millis(120));
    assert_eq!(KERNEL_COLD, Duration::from_millis(420));
    assert_eq!(PAGE_LOAD, Duration::from_millis(450));
    assert_eq!(budget(Kind::Switch, Temp::Warm), KERNEL_WARM);
    assert_eq!(budget(Kind::Themes, Temp::Warm), PAGE_LOAD);
}

/// Backlog 01d7e2ff: the first request after a deploy or restart is gated.
/// Every type has a fresh-process arm, held to the cold budget, and that
/// arm alone can turn the verdict red: over budget, or never measured.
#[test]
fn a_fresh_process_is_gated_on_every_type_at_the_cold_budget() {
    let expected = all_expected();
    for k in KINDS {
        assert!(
            expected.contains(&(k, Temp::Process)),
            "{k:?} has no fresh-process arm in the gate"
        );
        assert_eq!(budget(k, Temp::Process), budget(k, Temp::Cold), "{k:?}");
    }
    let d = Duration::from_millis;
    let over = KERNEL_COLD + d(1);
    let mut s: Samples = BTreeMap::new();
    for k in KINDS {
        s.insert((k, Temp::Warm), vec![d(1); 20]);
        s.insert((k, Temp::Cold), vec![d(1); 20]);
        if k != Kind::Maps {
            s.insert((k, Temp::Process), vec![d(1); 20]);
        }
    }
    // Two of twenty fresh-process leaves over the cold budget: p95 is over,
    // though every in-process sample is fast.
    s.insert(
        (Kind::Leaf, Temp::Process),
        (0..20).map(|i| if i < 18 { d(1) } else { over }).collect(),
    );
    let got: Vec<(Kind, Temp, Option<Duration>)> = verdict(&s, &expected, budget)
        .into_iter()
        .map(|b| (b.kind, b.temp, b.p95))
        .collect();
    assert_eq!(
        got,
        vec![
            (Kind::Leaf, Temp::Process, Some(over)),
            // No fresh-process sample is a breach, not a pass.
            (Kind::Maps, Temp::Process, None),
        ]
    );
}

/// The report carries the fresh-process p50 and p95 per type beside the
/// in-process cold numbers, and the process start-up times.
#[test]
fn the_report_carries_the_fresh_process_arm_per_type() {
    let d = Duration::from_millis;
    let mut samples: Samples = BTreeMap::new();
    for (i, k) in KINDS.into_iter().enumerate() {
        let base = 10 * (i as u64 + 1);
        samples.insert((k, Temp::Cold), vec![d(base); 4]);
        samples.insert(
            (k, Temp::Process),
            vec![d(base + 1), d(base + 3), d(base + 2)],
        );
    }
    let s = Seeded {
        team: Uuid::nil(),
        viewer: Uuid::nil(),
        themes: 1,
        claims: 1,
        levels: Vec::new(),
        leaf_of: BTreeMap::new(),
        probe_claims: Vec::new(),
        seed_time: Duration::ZERO,
    };
    let scale = Scale {
        themes: 1,
        claims_per_theme: 1,
        warm: 0,
        cold: 4,
        process: 3,
    };
    let boots = [d(700), d(900), d(800)];
    let breaches = verdict(&samples, &all_expected(), budget);
    let r = report(scale, &s, &samples, &boots, &breaches, None);
    let rows = r["results"].as_array().expect("rows");
    for (i, k) in KINDS.into_iter().enumerate() {
        let base = 10.0 * (i as f64 + 1.0);
        let row = |t: &str| {
            rows.iter()
                .find(|row| row["type"] == json!(k.name()) && row["temp"] == json!(t))
                .unwrap_or_else(|| panic!("no {t} row for {k:?}: {r}"))
        };
        let p = row("process");
        assert_eq!(p["n"], json!(3), "{k:?}");
        assert_eq!(p["p50_ms"], json!(base + 2.0), "{k:?}");
        assert_eq!(p["p95_ms"], json!(base + 3.0), "{k:?}");
        assert_eq!(p["budget_ms"], row("cold")["budget_ms"], "{k:?}");
        assert_eq!(p["pass"], json!(true), "{k:?}");
    }
    assert_eq!(r["scale"]["process_samples_per_type"], json!(3));
    assert_eq!(r["process_start"]["n"], json!(3));
    assert_eq!(r["process_start"]["p50_ms"], json!(800.0));
    assert_eq!(r["process_start"]["max_ms"], json!(900.0));
}

// ---- the seeded map ---------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Scale {
    themes: usize,
    claims_per_theme: usize,
    warm: usize,
    cold: usize,
    /// Fresh-process samples per type: one `server` binary each.
    process: usize,
}

impl Scale {
    fn from_env() -> Scale {
        let themes = match std::env::var("ATLAS_LATENCY_SCALE").as_deref() {
            Err(_) | Ok("") | Ok("small") => SMALL_THEMES,
            Ok("full") => FULL_THEMES,
            Ok(n) => n
                .parse()
                .unwrap_or_else(|_| panic!("ATLAS_LATENCY_SCALE={n}: small, full or a count")),
        };
        let n = |var: &str, default: usize| {
            std::env::var(var)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        };
        Scale {
            themes,
            claims_per_theme: CLAIMS_PER_THEME,
            warm: n("ATLAS_LATENCY_WARM_SAMPLES", 60),
            cold: n("ATLAS_LATENCY_COLD_SAMPLES", 8),
            process: n("ATLAS_LATENCY_PROCESS_SAMPLES", 3),
        }
    }
}

/// One stored level, as the harness asks for it.
#[derive(Debug, Clone)]
struct Lvl {
    hierarchy: Hierarchy,
    id: Uuid,
    twin: Uuid,
    kind: Kind,
}

struct Seeded {
    team: Uuid,
    viewer: Uuid,
    themes: usize,
    claims: usize,
    levels: Vec<Lvl>,
    /// (claim, hierarchy) -> the leaf holding it.
    leaf_of: BTreeMap<(Uuid, Hierarchy), Uuid>,
    /// Claims to look up, spread over every theme.
    probe_claims: Vec<Uuid>,
    seed_time: Duration,
}

fn seg(h: Hierarchy) -> &'static str {
    match h {
        Hierarchy::Meaning => "meaning",
        Hierarchy::Links => "links",
    }
}

fn store_h(h: Hierarchy) -> AtlasHierarchy {
    match h {
        Hierarchy::Meaning => AtlasHierarchy::Meaning,
        Hierarchy::Links => AtlasHierarchy::Links,
    }
}

async fn team(pool: &PgPool, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, $2, 'did:epigraph:test-team:' || $1::text, $3, 'team')",
    )
    .bind(id)
    .bind(label)
    .bind(&key)
    .execute(pool)
    .await
    .expect("seed team");
    id
}

async fn add_member(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed membership");
}

/// Seed the map: rows first (claims in batches), then one finished run.
async fn seed(pool: &PgPool, scale: Scale) -> Seeded {
    let started = Instant::now();
    let team_id = team(pool, "Latency team").await;
    let (viewer, _) = fixture::seed_agent_with_group(pool, "latency-viewer").await;
    add_member(pool, team_id, viewer, "reader").await;
    let world = fixture::world_group(pool).await;
    let mut agents = Vec::new();
    for i in 0..32 {
        agents.push(
            fixture::seed_agent_with_group(pool, &format!("latency-author-{i}"))
                .await
                .0,
        );
    }

    let mut theme_ids = Vec::new();
    let mut theme_claims: Vec<Vec<Uuid>> = Vec::new();
    for t in 0..scale.themes {
        let id: Uuid =
            sqlx::query_scalar("INSERT INTO claim_themes (label) VALUES ($1) RETURNING id")
                .bind(format!("latency theme {t}"))
                .fetch_one(pool)
                .await
                .expect("seed theme");
        theme_ids.push(id);
        theme_claims.push(
            (0..scale.claims_per_theme)
                .map(|_| Uuid::new_v4())
                .collect(),
        );
    }

    // Claims, in batches of whole themes.
    let mut evidence_of_theme: Vec<Vec<Uuid>> = vec![Vec::new(); scale.themes];
    for (chunk_start, chunk) in theme_claims.chunks(8).enumerate() {
        let (mut ids, mut authors, mut vis, mut owners, mut themes) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for (k, claims) in chunk.iter().enumerate() {
            let t = chunk_start * 8 + k;
            for (i, c) in claims.iter().enumerate() {
                ids.push(*c);
                authors.push(agents[i % agents.len()]);
                let mine = i % 5 == 0;
                vis.push(if mine { "group" } else { "public" }.to_string());
                owners.push(if mine { team_id } else { world });
                themes.push(theme_ids[t]);
            }
        }
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                                 is_current, visibility, owner_group_id, theme_id) \
             SELECT t.id, 'synthetic latency claim ' || t.id::text, \
                    decode(md5(t.id::text) || md5(t.id::text || ':'), 'hex'), \
                    0.6, t.agent, true, t.vis, t.owner, t.theme \
               FROM unnest($1::uuid[], $2::uuid[], $3::text[], $4::uuid[], $5::uuid[]) \
                    AS t(id, agent, vis, owner, theme)",
        )
        .bind(&ids)
        .bind(&authors)
        .bind(&vis)
        .bind(&owners)
        .bind(&themes)
        .execute(pool)
        .await
        .expect("seed claims");
        // Evidence on one claim in eight; it inherits its claim's tenancy.
        let backed: Vec<Uuid> = ids.iter().copied().step_by(8).collect();
        let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "INSERT INTO evidence (claim_id, evidence_type, content_hash) \
             SELECT c, 'document', decode(md5(c::text || 'e') || md5(c::text || 'f'), 'hex') \
               FROM unnest($1::uuid[]) AS c \
             RETURNING id, claim_id",
        )
        .bind(&backed)
        .fetch_all(pool)
        .await
        .expect("seed evidence");
        let theme_of: HashMap<Uuid, usize> = chunk
            .iter()
            .enumerate()
            .flat_map(|(k, cs)| cs.iter().map(move |c| (*c, chunk_start * 8 + k)))
            .collect();
        for (ev, claim) in rows {
            evidence_of_theme[theme_of[&claim]].push(ev);
        }
    }

    // One finished run holding every theme's levels.
    let map = AtlasMap::Team(team_id);
    let (_scoped, system) = fixture::bypass(pool).await;
    let mut conn = pool.begin().await.expect("begin the build");
    let epochs = AtlasMapRepository::begin_build_snapshot(&mut conn, &system, map)
        .await
        .expect("snapshot");
    let run = AtlasMapRepository::write_run(
        &mut conn,
        &NewMapRun {
            map,
            algo: "w12-latency".into(),
            params: json!({}),
            epochs,
        },
    )
    .await
    .expect("write_run");
    let mut levels = Vec::new();
    let mut leaf_of = BTreeMap::new();
    let mut probe_claims = Vec::new();
    for t in 0..scale.themes {
        let docs = theme_levels(
            0x0A71_A512 + t as u64,
            &ScaleMap {
                map_scope: MapScope::Team,
                map_group_id: Some(team_id),
                run_id: run,
            },
            &ScaleTheme {
                theme_id: theme_ids[t],
                claims: &theme_claims[t],
                agents: &agents,
                evidence: &evidence_of_theme[t],
            },
        );
        // Spread the lookups: claims at fixed strides through each theme.
        probe_claims.extend(theme_claims[t].iter().step_by(97).copied());
        for l in docs {
            let (id, depth, twin) = match &l.doc {
                LevelDocument::Group(g) => (g.level_id, g.depth, g.switch.level_id),
                LevelDocument::Leaf(f) => (f.level_id, f.depth, f.switch.level_id),
            };
            let kind = match (&l.doc, depth) {
                (LevelDocument::Leaf(f), _) => {
                    for n in &f.nodes {
                        if let Node::Claim(c) = n {
                            leaf_of.insert((c.id, l.hierarchy), f.level_id);
                        }
                    }
                    Kind::Leaf
                }
                (LevelDocument::Group(_), 0) => Kind::Root,
                (LevelDocument::Group(_), _) => Kind::Group,
            };
            AtlasMapRepository::put_level(
                &mut conn,
                run,
                &LevelDoc {
                    hierarchy: store_h(l.hierarchy),
                    group_id: id,
                    parent_group_id: l.parent,
                    theme_id: theme_ids[t],
                    level: i32::from(depth),
                    schema_version: 1,
                    payload: serde_json::to_value(&l.doc).expect("a level serialises"),
                },
            )
            .await
            .expect("put_level");
            levels.push(Lvl {
                hierarchy: l.hierarchy,
                id,
                twin,
                kind,
            });
        }
    }
    AtlasMapRepository::finish_run(&mut conn, run)
        .await
        .expect("finish_run");
    conn.commit().await.expect("commit the build");
    // Fresh statistics, as autovacuum would have them on a settled table.
    sqlx::query("ANALYZE claims, evidence, atlas_map_levels, atlas_map_runs")
        .execute(pool)
        .await
        .expect("analyze");
    Seeded {
        team: team_id,
        viewer,
        themes: scale.themes,
        claims: scale.themes * scale.claims_per_theme,
        levels,
        leaf_of,
        probe_claims,
        seed_time: started.elapsed(),
    }
}

// ---- the server and the client ----------------------------------------------------

/// A test-only delay on every request whose path ends with one of `paths`:
/// the "deliberately slow route" the red-on-regression test injects. It is
/// layered OUTSIDE `create_router`, so nothing under `src/` changes.
#[derive(Clone)]
struct Delay {
    suffixes: Arc<BTreeSet<String>>,
    by: Duration,
}

impl Delay {
    fn applies_to(&self, path: &str) -> bool {
        self.suffixes.iter().any(|s| path.ends_with(s.as_str()))
    }
}

async fn delay_layer(
    axum::extract::State(delay): axum::extract::State<Delay>,
    req: Request,
    next: Next,
) -> Response {
    if delay.applies_to(req.uri().path()) {
        tokio::time::sleep(delay.by).await;
    }
    next.run(req).await
}

/// The fresh-process arm's [`Delay`]: a spawned binary cannot take a test
/// layer, so the treated run puts this loopback proxy in front of it. Every
/// chunk the client sends that starts a request line whose path the delay
/// applies to is held for `by`, then forwarded; the answer is piped back
/// untouched. A test-only instrument: nothing under `src/` changes.
struct DelayProxy {
    port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for DelayProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The path of an HTTP/1 request line at the start of `chunk`, if any.
fn request_path(chunk: &[u8]) -> Option<&str> {
    let line = chunk.split(|b| *b == b'\n').next()?;
    let mut parts = std::str::from_utf8(line).ok()?.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    (method.bytes().all(|b| b.is_ascii_uppercase()) && version.starts_with("HTTP/"))
        .then(|| target.split('?').next().unwrap_or(target))
}

async fn delay_proxy(upstream: u16, delay: Delay) -> DelayProxy {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the delay proxy");
    let port = listener.local_addr().expect("proxy addr").port();
    let task = tokio::spawn(async move {
        while let Ok((down, _)) = listener.accept().await {
            let delay = delay.clone();
            tokio::spawn(async move {
                let Ok(up) = tokio::net::TcpStream::connect(("127.0.0.1", upstream)).await else {
                    return;
                };
                let (mut down_r, mut down_w) = down.into_split();
                let (mut up_r, mut up_w) = up.into_split();
                let to_server = async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    loop {
                        let n = match down_r.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if request_path(&buf[..n]).is_some_and(|p| delay.applies_to(p)) {
                            tokio::time::sleep(delay.by).await;
                        }
                        if up_w.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    let _ = up_w.shutdown().await;
                };
                let to_client = async move {
                    let _ = tokio::io::copy(&mut up_r, &mut down_w).await;
                    let _ = down_w.shutdown().await;
                };
                tokio::join!(to_server, to_client);
            });
        }
    });
    DelayProxy { port, task }
}

/// A kernel on a loopback listener with a fresh scoped pool.
///
/// The pool runs as `epigraph_app`, as production does: every connection is
/// downgraded with `SET SESSION AUTHORIZATION` right after it connects, so
/// each read is filtered by the `<table>_tenancy` row policies as well as the
/// in-query viewer predicate. On the superuser DSN `#[sqlx::test]` hands out,
/// no policy is evaluated and the gate would time a cheaper query than prod
/// runs. A cold sample's fresh connection therefore pays that one extra
/// statement too, before its first request (prod pays it once per pooled
/// connection, never per request), so cold is slightly overstated.
struct Server {
    base: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A fresh `ScopedPool` over `pool`'s database whose every connection is
/// downgraded to `epigraph_app` (see [`Server`]).
async fn app_pool(pool: &PgPool) -> ScopedPool {
    ScopedPool::connect_downgraded_for_tests(
        &fixture::database_url_for(pool).await,
        SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("an epigraph_app ScopedPool")
}

async fn serve(pool: &PgPool, delay: Option<&Delay>) -> Server {
    let state = AppState::with_scoped_pool(app_pool(pool).await, ApiConfig::default());
    let mut router = create_router(state);
    if let Some(d) = delay {
        router = router.layer(axum::middleware::from_fn_with_state(d.clone(), delay_layer));
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("serve");
    });
    Server {
        base: format!("http://{addr}"),
        task,
    }
}

/// A database login shaped like production's: NOSUPERUSER, NOBYPASSRLS, a
/// member of `epigraph_app` whose role default is `epigraph_app`, so a
/// binary connecting as it acts as the application role from its first
/// statement (and after any `RESET ALL`) and its RLS posture check is armed.
/// Roles are cluster-wide and outlive the per-test database: the name is
/// unique, and the login drops itself on every exit, a panic included.
struct AppLogin {
    role: String,
    dsn: String,
    /// The fixture's DSN, which created the role and drops it.
    admin_url: String,
}

impl Drop for AppLogin {
    /// `Drop` cannot await, and the test's runtime cannot be blocked on from
    /// inside it, so the role is dropped on a thread with its own runtime and
    /// connection. While unwinding, a failure is printed, not raised (a panic
    /// in a panic aborts the test binary).
    fn drop(&mut self) {
        let (url, role) = (self.admin_url.clone(), self.role.clone());
        let dropped = std::thread::spawn(move || -> Result<(), String> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            rt.block_on(async {
                use sqlx::Connection as _;
                let mut conn = sqlx::PgConnection::connect(&url)
                    .await
                    .map_err(|e| e.to_string())?;
                sqlx::query(&format!("DROP ROLE IF EXISTS {role}"))
                    .execute(&mut conn)
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = conn.close().await;
                Ok(())
            })
        })
        .join()
        .unwrap_or_else(|_| Err("the drop thread panicked".into()));
        if let Err(e) = dropped {
            if std::thread::panicking() {
                eprintln!("could not drop the app login {}: {e}", self.role);
            } else {
                panic!("drop the app login {}: {e}", self.role);
            }
        }
    }
}

async fn app_login(pool: &PgPool) -> AppLogin {
    let admin_url = fixture::database_url_for(pool).await;
    let role = format!("atlas_latency_{}", Uuid::new_v4().simple());
    let password = format!("pw-{}", Uuid::new_v4().simple());
    let (scheme, rest) = admin_url.split_once("://").expect("a DSN scheme");
    let host = rest.rsplit_once('@').map_or(rest, |(_, h)| h);
    let dsn = format!("{scheme}://{role}:{password}@{host}");
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE \
         NOREPLICATION INHERIT PASSWORD '{password}' IN ROLE epigraph_app"
    ))
    .execute(pool)
    .await
    .expect(
        "create the app login: the fresh-process arm needs a DATABASE_URL that may \
         CREATE ROLE, on a cluster that accepts password logins over TCP",
    );
    // From here the guard owns the role: a failure below still drops it.
    let login = AppLogin {
        role,
        dsn,
        admin_url,
    };
    sqlx::query(&format!(
        "ALTER ROLE {} SET role = 'epigraph_app'",
        login.role
    ))
    .execute(pool)
    .await
    .expect("default the app login to the app role");
    login
}

/// Logged by the binary when its connection is the application role under
/// row security (`AppState::assert_rls_posture`).
const RLS_ARMED: &str = "RLS posture armed";

/// Start a fresh `server` binary on `login` and wait until it serves.
/// Returns it with the time from spawn to the serving line (to
/// `served::boot`'s 100 ms poll).
async fn serve_process(login: &AppLogin) -> (served::Server, Duration) {
    let dsn = login.dsn.clone();
    // `base_command` clears the environment; the bearer the test mints must
    // verify in the child.
    let secret = std::env::var("EPIGRAPH_JWT_SECRET").ok();
    tokio::task::spawn_blocking(move || {
        let mut cmd = served::base_command(&dsn);
        // Loopback only: the default binds every interface.
        cmd.env("EPIGRAPH_BIND_ADDR", "127.0.0.1");
        // Each sample is stopped by SIGTERM once timed (to read what it
        // answered): bound the drain.
        cmd.env("EPIGRAPH_SHUTDOWN_GRACE_SECS", "5");
        if let Some(secret) = secret {
            cmd.env("EPIGRAPH_JWT_SECRET", secret);
        }
        let started = Instant::now();
        let srv = served::boot(cmd).serving();
        let took = started.elapsed();
        assert!(
            srv.boot_log.contains(RLS_ARMED),
            "the fresh process must serve as the application role under row security:\n{}",
            srv.boot_log
        );
        (srv, took)
    })
    .await
    .expect("join the boot")
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("a client")
}

/// One timed request.
struct Hit {
    status: u16,
    body: Vec<u8>,
    took: Duration,
}

async fn hit(c: &reqwest::Client, base: &str, path: &str, token: &str) -> Hit {
    let started = Instant::now();
    let resp = c
        .get(format!("{base}{path}"))
        .bearer_auth(token)
        .send()
        .await
        .expect("send");
    let status = resp.status().as_u16();
    let body = resp.bytes().await.expect("body").to_vec();
    Hit {
        status,
        body,
        took: started.elapsed(),
    }
}

// ---- one request of each type -----------------------------------------------------

/// What a request asks for and how its answer is checked.
#[derive(Debug, Clone)]
enum Ask {
    Level {
        h: Hierarchy,
        id: Uuid,
    },
    ClaimLeaf {
        h: Hierarchy,
        claim: Uuid,
        leaf: Uuid,
    },
    Themes,
    Maps,
}

impl Ask {
    fn path(&self, team: Uuid) -> String {
        match self {
            Ask::Level { h, id } => format!("/api/v1/atlas/maps/{team}/{}/levels/{id}", seg(*h)),
            Ask::ClaimLeaf { h, claim, .. } => {
                format!("/api/v1/atlas/maps/{team}/{}/claims/{claim}/leaf", seg(*h))
            }
            Ask::Themes => format!("/api/v1/atlas/maps/{team}/themes"),
            Ask::Maps => "/api/v1/atlas/maps".to_string(),
        }
    }
}

/// The plan: for each type, the requests to cycle through, in order. A
/// switch sample is (the level shown, untimed; its twin, timed).
struct Plan {
    asks: BTreeMap<Kind, Vec<(Option<Ask>, Ask)>>,
}

fn plan(s: &Seeded) -> Plan {
    let mut asks: BTreeMap<Kind, Vec<(Option<Ask>, Ask)>> = BTreeMap::new();
    for l in &s.levels {
        let here = Ask::Level {
            h: l.hierarchy,
            id: l.id,
        };
        asks.entry(l.kind).or_default().push((None, here.clone()));
        // Flip from every level of the meaning tree to its links twin, and
        // back from the links tree, so a switch lands on every kind.
        asks.entry(Kind::Switch).or_default().push((
            Some(here),
            Ask::Level {
                h: l.hierarchy.other(),
                id: l.twin,
            },
        ));
    }
    for (i, c) in s.probe_claims.iter().enumerate() {
        let h = if i % 2 == 0 {
            Hierarchy::Meaning
        } else {
            Hierarchy::Links
        };
        asks.entry(Kind::ClaimLeaf).or_default().push((
            None,
            Ask::ClaimLeaf {
                h,
                claim: *c,
                leaf: s.leaf_of[&(*c, h)],
            },
        ));
    }
    asks.insert(Kind::Themes, vec![(None, Ask::Themes)]);
    asks.insert(Kind::Maps, vec![(None, Ask::Maps)]);
    // Interleave themes and hierarchies, deterministically: a stride walk.
    for v in asks.values_mut() {
        let n = v.len();
        if n > 2 {
            let stride = (1..n)
                .rev()
                .find(|k| gcd(*k, n) == 1 && *k <= n / 2 + 1)
                .unwrap_or(1);
            let walked: Vec<_> = (0..n).map(|i| v[(i * stride) % n].clone()).collect();
            *v = walked;
        }
    }
    Plan { asks }
}

fn gcd(a: usize, b: usize) -> usize {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

/// Check one answer outside the timer. Returns a level id to contract-check
/// when the answer is a level.
fn check_answer(ask: &Ask, h: &Hit, s: &Seeded) -> Option<Uuid> {
    assert_eq!(
        h.status,
        200,
        "{ask:?}: {}",
        String::from_utf8_lossy(&h.body[..h.body.len().min(300)])
    );
    let v: Value = serde_json::from_slice(&h.body).expect("a JSON body");
    match ask {
        Ask::Level { id, .. } => {
            assert_eq!(v["level_id"], json!(id), "{ask:?} answered another level");
            Some(*id)
        }
        Ask::ClaimLeaf { claim, leaf, .. } => {
            assert_eq!(v["claim_id"], json!(claim));
            assert_eq!(v["level_id"], json!(leaf), "{ask:?} found another leaf");
            None
        }
        Ask::Themes => {
            assert_eq!(
                v["themes"].as_array().map(Vec::len),
                Some(s.themes),
                "every theme listed"
            );
            None
        }
        Ask::Maps => {
            let maps = v["maps"].as_array().expect("a map list");
            assert!(
                maps.iter().any(|m| m["group_id"] == json!(s.team)),
                "the team map listed"
            );
            None
        }
    }
}

/// The paths of the requests a server answered, in order, from its log after
/// the serving line: one `request finished` line per request
/// (`serving.rs::log_response`). The shutdown's "every in-flight request
/// finished" is not a request.
fn answered(log: &str) -> Vec<&str> {
    log.lines()
        .filter(|l| l.contains("request finished") && !l.contains("in-flight"))
        .collect()
}

/// Backlog 01d7e2ff: a fresh-process sample times the process's FIRST
/// request (a switch's second, after its untimed flip-from). Anything the
/// process answered before it, a warm-up or a readiness probe, would make
/// the arm measure a warm process under the `process` label.
fn assert_first_requests(log: &str, expect: &[String]) {
    let got = answered(log);
    assert!(
        got.len() == expect.len() && got.iter().zip(expect).all(|(l, p)| l.contains(p.as_str())),
        "a fresh process must answer exactly {expect:?}, in order, the timed one last; \
         it answered:\n{}\nfull log after serving:\n{log}",
        got.join("\n")
    );
}

/// What one run measured: the samples, and each fresh process's start-up.
struct Measured {
    samples: Samples,
    starts: Vec<Duration>,
}

/// Measure every type, warm, cold, then on a fresh process. Every answer is
/// checked; each distinct level body once against the contract.
async fn measure(
    pool: &PgPool,
    login: &AppLogin,
    s: &Seeded,
    scale: Scale,
    delay: Option<&Delay>,
) -> Measured {
    let token = common::mint_token_with_agent(&["claims:read"], s.viewer);
    let p = plan(s);
    let mut samples: Samples = BTreeMap::new();
    let mut contract_checked: BTreeSet<Uuid> = BTreeSet::new();
    let mut bodies: Vec<(Uuid, Vec<u8>)> = Vec::new();
    let mut keep = |id: Option<Uuid>, body: &[u8], bodies: &mut Vec<(Uuid, Vec<u8>)>| {
        if let Some(id) = id {
            if contract_checked.insert(id) {
                bodies.push((id, body.to_vec()));
            }
        }
    };

    // Warm: one server, one pooled client, one untimed request per type.
    {
        let srv = serve(pool, delay).await;
        let c = client();
        for kind in KINDS {
            let (_, ask) = &p.asks[&kind][0];
            let h = hit(&c, &srv.base, &ask.path(s.team), &token).await;
            check_answer(ask, &h, s);
        }
        for kind in KINDS {
            let list = &p.asks[&kind];
            for i in 0..scale.warm {
                let (before, ask) = &list[i % list.len()];
                if let Some(b) = before {
                    let h = hit(&c, &srv.base, &b.path(s.team), &token).await;
                    check_answer(b, &h, s);
                }
                let h = hit(&c, &srv.base, &ask.path(s.team), &token).await;
                let id = check_answer(ask, &h, s);
                keep(id, &h.body, &mut bodies);
                samples.entry((kind, Temp::Warm)).or_default().push(h.took);
            }
        }
    }

    // Cold: a fresh pool, server and client per sample, on levels the warm
    // pass did not ask for where the map has them.
    for kind in KINDS {
        let list = &p.asks[&kind];
        for i in 0..scale.cold {
            let (before, ask) = &list[(scale.warm + i) % list.len()];
            let srv = serve(pool, delay).await;
            let c = client();
            if let Some(b) = before {
                // The level the viewer flips FROM was on screen: shown on
                // the same server, so only the flip is cold.
                let h = hit(&c, &srv.base, &b.path(s.team), &token).await;
                check_answer(b, &h, s);
            }
            let h = hit(&c, &srv.base, &ask.path(s.team), &token).await;
            let id = check_answer(ask, &h, s);
            keep(id, &h.body, &mut bodies);
            samples.entry((kind, Temp::Cold)).or_default().push(h.took);
        }
    }

    // Process: a fresh `server` binary and client per sample, on levels
    // neither arm above asked for where the map has them. One binary at a
    // time; each is killed and reaped before the next starts.
    let mut starts = Vec::new();
    let mut pids = BTreeSet::new();
    for kind in KINDS {
        let list = &p.asks[&kind];
        for i in 0..scale.process {
            let (before, ask) = &list[(scale.warm + scale.cold + i) % list.len()];
            let (srv, started) = serve_process(login).await;
            assert!(
                pids.insert(srv.child.id()),
                "a fresh-process sample reused a server"
            );
            starts.push(started);
            let proxy = match delay {
                Some(d) => Some(delay_proxy(srv.port, d.clone()).await),
                None => None,
            };
            let base = format!(
                "http://127.0.0.1:{}",
                proxy.as_ref().map_or(srv.port, |p| p.port)
            );
            let c = client();
            if let Some(b) = before {
                // As in the cold arm: the level flipped from was on screen.
                let h = hit(&c, &base, &b.path(s.team), &token).await;
                check_answer(b, &h, s);
            }
            let h = hit(&c, &base, &ask.path(s.team), &token).await;
            let id = check_answer(ask, &h, s);
            keep(id, &h.body, &mut bodies);
            samples
                .entry((kind, Temp::Process))
                .or_default()
                .push(h.took);
            // Close the client's connections (and the proxy's) first, so the
            // drain has nothing in flight; stop the process off the runtime
            // so those connection tasks can run meanwhile.
            drop(c);
            drop(proxy);
            let expect: Vec<String> = before
                .iter()
                .map(|b| b.path(s.team))
                .chain([ask.path(s.team)])
                .collect();
            let mut srv = srv;
            let log = tokio::task::spawn_blocking(move || {
                let (status, log) = srv.terminate(Duration::from_secs(15));
                assert!(
                    status.is_some(),
                    "a fresh process did not stop within 15 s of SIGTERM:\n{log}"
                );
                log
            })
            .await
            .expect("join the stop");
            assert_first_requests(&log, &expect);
        }
    }

    for (id, body) in &bodies {
        check_level_body(body, &Expected::team(s.team, *id))
            .unwrap_or_else(|e| panic!("level {id} fails the contract: {e:?}"));
    }
    Measured { samples, starts }
}

// ---- the report -------------------------------------------------------------------

fn report(
    scale: Scale,
    s: &Seeded,
    samples: &Samples,
    starts: &[Duration],
    breaches: &[Breach],
    scaling: Option<&ScalingBreach>,
) -> Value {
    let rows: Vec<Value> = all_expected()
        .into_iter()
        .map(|(kind, temp)| {
            let xs = samples.get(&(kind, temp)).cloned().unwrap_or_default();
            let b = budget(kind, temp);
            let p95 = quantile(&xs, 0.95);
            json!({
                "type": kind.name(),
                "temp": temp.name(),
                "n": xs.len(),
                "p50_ms": quantile(&xs, 0.5).map(ms),
                "p95_ms": p95.map(ms),
                "max_ms": xs.iter().max().copied().map(ms),
                "budget_ms": ms(b),
                "pass": p95.is_some_and(|p| p <= b),
            })
        })
        .collect();
    json!({
        "harness": "atlas-latency-kernel",
        "backlog": "824ac5ac",
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "scale": {
            "themes": scale.themes,
            "claims_per_theme": scale.claims_per_theme,
            "claims": s.claims,
            "levels": s.levels.len(),
            "warm_samples_per_type": scale.warm,
            "cold_samples_per_type": scale.cold,
            "process_samples_per_type": scale.process,
            "seed_seconds": (s.seed_time.as_secs_f64() * 10.0).round() / 10.0,
        },
        "budget_ms": {
            "warm_total": ms(WARM_TOTAL),
            "cold_total": ms(COLD_TOTAL),
            "client_allowance": ms(CLIENT_ALLOWANCE),
            "bff_share": ms(BFF_SHARE),
            "kernel_warm": ms(KERNEL_WARM),
            "kernel_cold": ms(KERNEL_COLD),
            "page_load": ms(PAGE_LOAD),
        },
        "results": rows,
        // Spawn to the serving line, per fresh process: reported, not gated
        // (nothing is served before the listener binds).
        "process_start": {
            "n": starts.len(),
            "p50_ms": quantile(starts, 0.5).map(ms),
            "p95_ms": quantile(starts, 0.95).map(ms),
            "max_ms": starts.iter().max().copied().map(ms),
        },
        "scaling_rule": {
            "rule": "claim_leaf warm p95 <= max_ratio x leaf warm p95",
            "max_ratio": CLAIM_LEAF_OVER_LEAF,
        },
        "scaling_breaches": scaling.map(|b| json!({
            "rule": "claim_leaf_over_leaf",
            "claim_leaf_warm_p95_ms": ms(b.claim_leaf_p95),
            "leaf_warm_p95_ms": ms(b.leaf_p95),
            "ratio": (b.ratio * 100.0).round() / 100.0,
            "max_ratio": b.max_ratio,
        })).into_iter().collect::<Vec<_>>(),
        "breaches": breaches.iter().map(|b| json!({
            "type": b.kind.name(),
            "temp": b.temp.name(),
            "p95_ms": b.p95.map(ms),
            "budget_ms": ms(b.budget),
        })).collect::<Vec<_>>(),
    })
}

fn print_table(r: &Value) {
    eprintln!(
        "atlas latency ({}, {} claims, {} levels):",
        r["profile"], r["scale"]["claims"], r["scale"]["levels"]
    );
    eprintln!(
        "  {:<11} {:<7} {:>4} {:>9} {:>9} {:>9} {:>9}",
        "type", "temp", "n", "p50 ms", "p95 ms", "max ms", "budget"
    );
    for row in r["results"].as_array().into_iter().flatten() {
        eprintln!(
            "  {:<11} {:<7} {:>4} {:>9} {:>9} {:>9} {:>9} {}",
            row["type"].as_str().unwrap_or(""),
            row["temp"].as_str().unwrap_or(""),
            row["n"],
            row["p50_ms"],
            row["p95_ms"],
            row["max_ms"],
            row["budget_ms"],
            if row["pass"] == json!(true) {
                "ok"
            } else {
                "OVER"
            }
        );
    }
    let warm_p95 = |t: &str| {
        r["results"]
            .as_array()
            .into_iter()
            .flatten()
            .find_map(|row| {
                (row["type"] == json!(t) && row["temp"] == json!("warm"))
                    .then(|| row["p95_ms"].as_f64())
                    .flatten()
            })
    };
    eprintln!(
        "  process start-up (spawn to serving, not gated): n {} p50 {} p95 {} max {}",
        r["process_start"]["n"],
        r["process_start"]["p50_ms"],
        r["process_start"]["p95_ms"],
        r["process_start"]["max_ms"]
    );
    if let (Some(c), Some(l)) = (warm_p95("claim_leaf"), warm_p95("leaf")) {
        eprintln!(
            "  claim_leaf / leaf, warm p95: {:.2} (max {CLAIM_LEAF_OVER_LEAF}) {}",
            c / l.max(1e-9),
            if r["scaling_breaches"].as_array().is_some_and(Vec::is_empty) {
                "ok"
            } else {
                "OVER"
            }
        );
    }
}

// ---- the gate ---------------------------------------------------------------------

/// THE GATE: the kernel's p95 for every level type, the switch, claim to
/// leaf and the page-load routes, warm and cold, within its share of the
/// design §6 budget, on a map of `ATLAS_LATENCY_SCALE`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_kernel_meets_the_latency_budget(pool: PgPool) {
    let scale = Scale::from_env();
    // The kernel under test reads as the application role, under row
    // security, as production does; checked on a pool of its own so no
    // timed pool is warmed by the check.
    let role: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(app_pool(&pool).await.inner())
        .await
        .expect("the kernel pool's role");
    assert_eq!(
        role, "epigraph_app",
        "the gate must time the application role"
    );
    let s = seed(&pool, scale).await;
    let login = app_login(&pool).await;
    let m = measure(&pool, &login, &s, scale, None).await;
    drop(login);
    let samples = m.samples;
    let breaches = verdict(&samples, &all_expected(), budget);
    let scaling = scaling_verdict(&samples, CLAIM_LEAF_OVER_LEAF);
    let r = report(scale, &s, &samples, &m.starts, &breaches, scaling.as_ref());
    print_table(&r);
    if let Ok(path) = std::env::var("ATLAS_LATENCY_REPORT") {
        if !path.is_empty() {
            std::fs::write(&path, serde_json::to_vec_pretty(&r).expect("json"))
                .unwrap_or_else(|e| panic!("write the report to {path}: {e}"));
        }
    }
    assert!(
        breaches.is_empty() && scaling.is_none(),
        "the Atlas latency budget is exceeded: budget {} scaling {}",
        serde_json::to_string(&r["breaches"]).unwrap_or_default(),
        serde_json::to_string(&r["scaling_breaches"]).unwrap_or_default()
    );
}

/// A deliberately slow route turns the gate red, and only for the types it
/// serves. Control: the same map and plan with no delay is green. Treated:
/// a test-only layer (in process) and a loopback proxy (in front of the
/// fresh process) sleep past the cold budget on every LEAF level path; leaf
/// (warm, cold and fresh process) is then in breach, and no type that never
/// asks for a leaf (root, group, claim to leaf, themes, maps) is. A switch
/// sample may land on a leaf, so the switch may go red too.
#[sqlx::test(migrations = "../../migrations")]
async fn a_deliberately_slow_route_turns_the_gate_red(pool: PgPool) {
    // 600 claims: 10 leaves under 2 groups per hierarchy, so every type has
    // levels to ask for.
    let scale = Scale {
        themes: 1,
        claims_per_theme: 600,
        warm: 6,
        cold: 2,
        process: 1,
    };
    let s = seed(&pool, scale).await;
    let login = app_login(&pool).await;

    let control = measure(&pool, &login, &s, scale, None).await.samples;
    let green = verdict(&control, &all_expected(), budget);
    assert!(green.is_empty(), "the control run is red: {green:?}");

    let leaves: BTreeSet<String> = s
        .levels
        .iter()
        .filter(|l| l.kind == Kind::Leaf)
        .map(|l| format!("/levels/{}", l.id))
        .collect();
    let delay = Delay {
        suffixes: Arc::new(leaves),
        by: KERNEL_COLD + Duration::from_millis(100),
    };
    let treated = measure(&pool, &login, &s, scale, Some(&delay))
        .await
        .samples;
    drop(login);
    let red: BTreeSet<(Kind, Temp)> = verdict(&treated, &all_expected(), budget)
        .into_iter()
        .map(|b| (b.kind, b.temp))
        .collect();
    for t in TEMPS {
        assert!(
            red.contains(&(Kind::Leaf, t)),
            "a slow leaf route did not turn the {t:?} gate red: {red:?}"
        );
    }
    for k in [
        Kind::Root,
        Kind::Group,
        Kind::ClaimLeaf,
        Kind::Themes,
        Kind::Maps,
    ] {
        for t in TEMPS {
            assert!(
                !red.contains(&(k, t)),
                "{k:?} {t:?} is red though it asks for no leaf: {red:?}"
            );
        }
    }
}

/// A run that panics mid-measure still drops its login. Roles are
/// cluster-wide: a leaked one (a LOGIN member of `epigraph_app` with a
/// password) outlives the per-test database and piles up on a shared test
/// cluster.
#[sqlx::test(migrations = "../../migrations")]
async fn a_panicking_run_drops_its_app_login(pool: PgPool) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let p = pool.clone();
    let run = tokio::spawn(async move {
        let login = app_login(&p).await;
        let _ = tx.send(login.role.clone());
        panic!("a run fails mid-measure");
    });
    assert!(run.await.expect_err("the run panics").is_panic());
    let role = rx.await.expect("the login's role name");
    let left: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
            .bind(&role)
            .fetch_one(&pool)
            .await
            .expect("read pg_roles");
    assert!(
        !left,
        "a panicking run left its login {role} on the cluster"
    );
}
