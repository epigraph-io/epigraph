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
//!   a level not asked for before. Not a fresh process: see the plan.
//!
//! The JSON report goes to `ATLAS_LATENCY_REPORT` (a path) when it is set,
//! and is written BEFORE the gate asserts, so a red run keeps its numbers.

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

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
use epigraph_db::AtlasMapRepository;
use serde_json::{json, Value};
use sqlx::PgPool;
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
}

impl Temp {
    fn name(self) -> &'static str {
        match self {
            Temp::Warm => "warm",
            Temp::Cold => "cold",
        }
    }
}

/// The kernel's budget for one (type, warm/cold).
fn budget(kind: Kind, temp: Temp) -> Duration {
    match (kind, temp) {
        (Kind::Themes | Kind::Maps, _) => PAGE_LOAD,
        (_, Temp::Warm) => KERNEL_WARM,
        (_, Temp::Cold) => KERNEL_COLD,
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
            let p95 = samples
                .get(&(kind, temp))
                .and_then(|xs| quantile(xs, 0.95));
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

fn all_expected() -> Vec<(Kind, Temp)> {
    KINDS
        .iter()
        .flat_map(|&k| [(k, Temp::Warm), (k, Temp::Cold)])
        .collect()
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
fn the_kernel_budget_is_the_design_budget_less_the_other_shares() {
    assert_eq!(KERNEL_WARM, Duration::from_millis(120));
    assert_eq!(KERNEL_COLD, Duration::from_millis(420));
    assert_eq!(PAGE_LOAD, Duration::from_millis(450));
    assert_eq!(budget(Kind::Switch, Temp::Warm), KERNEL_WARM);
    assert_eq!(budget(Kind::Themes, Temp::Warm), PAGE_LOAD);
}

// ---- the seeded map ---------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Scale {
    themes: usize,
    claims_per_theme: usize,
    warm: usize,
    cold: usize,
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
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO claim_themes (label) VALUES ($1) RETURNING id",
        )
        .bind(format!("latency theme {t}"))
        .fetch_one(pool)
        .await
        .expect("seed theme");
        theme_ids.push(id);
        theme_claims.push((0..scale.claims_per_theme).map(|_| Uuid::new_v4()).collect());
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

async fn delay_layer(
    axum::extract::State(delay): axum::extract::State<Delay>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    if delay.suffixes.iter().any(|s| path.ends_with(s.as_str())) {
        tokio::time::sleep(delay.by).await;
    }
    next.run(req).await
}

/// A kernel on a loopback listener with a fresh scoped pool.
struct Server {
    base: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(pool: &PgPool, delay: Option<&Delay>) -> Server {
    let state = AppState::with_scoped_pool(fixture::scoped_pool(pool).await, ApiConfig::default());
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
    Level { h: Hierarchy, id: Uuid },
    ClaimLeaf { h: Hierarchy, claim: Uuid, leaf: Uuid },
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

/// Measure every type, warm then cold. Every answer is checked; each
/// distinct level body once against the contract.
async fn measure(pool: &PgPool, s: &Seeded, scale: Scale, delay: Option<&Delay>) -> Samples {
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
                samples
                    .entry((kind, Temp::Warm))
                    .or_default()
                    .push(h.took);
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
            samples
                .entry((kind, Temp::Cold))
                .or_default()
                .push(h.took);
        }
    }

    for (id, body) in &bodies {
        check_level_body(body, &Expected::team(s.team, *id))
            .unwrap_or_else(|e| panic!("level {id} fails the contract: {e:?}"));
    }
    samples
}

// ---- the report -------------------------------------------------------------------

fn report(scale: Scale, s: &Seeded, samples: &Samples, breaches: &[Breach]) -> Value {
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
        "  {:<11} {:<5} {:>4} {:>9} {:>9} {:>9} {:>9}",
        "type", "temp", "n", "p50 ms", "p95 ms", "max ms", "budget"
    );
    for row in r["results"].as_array().into_iter().flatten() {
        eprintln!(
            "  {:<11} {:<5} {:>4} {:>9} {:>9} {:>9} {:>9} {}",
            row["type"].as_str().unwrap_or(""),
            row["temp"].as_str().unwrap_or(""),
            row["n"],
            row["p50_ms"],
            row["p95_ms"],
            row["max_ms"],
            row["budget_ms"],
            if row["pass"] == json!(true) { "ok" } else { "OVER" }
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
    let s = seed(&pool, scale).await;
    let samples = measure(&pool, &s, scale, None).await;
    let breaches = verdict(&samples, &all_expected(), budget);
    let r = report(scale, &s, &samples, &breaches);
    print_table(&r);
    if let Ok(path) = std::env::var("ATLAS_LATENCY_REPORT") {
        if !path.is_empty() {
            std::fs::write(&path, serde_json::to_vec_pretty(&r).expect("json"))
                .unwrap_or_else(|e| panic!("write the report to {path}: {e}"));
        }
    }
    assert!(
        breaches.is_empty(),
        "the Atlas latency budget is exceeded: {}",
        serde_json::to_string(&r["breaches"]).unwrap_or_default()
    );
}

/// A deliberately slow route turns the gate red, and only for the types it
/// serves. Control: the same map and plan with no delay is green. Treated:
/// a test-only layer sleeps past the cold budget on every LEAF level path;
/// leaf (warm and cold) is then in breach, and no type that never asks for
/// a leaf (root, group, claim to leaf, themes, maps) is. A switch sample
/// may land on a leaf, so the switch may go red too.
#[sqlx::test(migrations = "../../migrations")]
async fn a_deliberately_slow_route_turns_the_gate_red(pool: PgPool) {
    // 600 claims: 10 leaves under 2 groups per hierarchy, so every type has
    // levels to ask for.
    let scale = Scale {
        themes: 1,
        claims_per_theme: 600,
        warm: 6,
        cold: 2,
    };
    let s = seed(&pool, scale).await;

    let control = measure(&pool, &s, scale, None).await;
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
    let treated = measure(&pool, &s, scale, Some(&delay)).await;
    let red: BTreeSet<(Kind, Temp)> = verdict(&treated, &all_expected(), budget)
        .into_iter()
        .map(|b| (b.kind, b.temp))
        .collect();
    assert!(
        red.contains(&(Kind::Leaf, Temp::Warm)) && red.contains(&(Kind::Leaf, Temp::Cold)),
        "a slow leaf route did not turn the gate red: {red:?}"
    );
    for k in [
        Kind::Root,
        Kind::Group,
        Kind::ClaimLeaf,
        Kind::Themes,
        Kind::Maps,
    ] {
        for t in [Temp::Warm, Temp::Cold] {
            assert!(
                !red.contains(&(k, t)),
                "{k:?} {t:?} is red though it asks for no leaf: {red:?}"
            );
        }
    }
}
