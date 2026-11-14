//! The incremental nightly Atlas refresh (Atlas W9, backlog 1da9ed16) on a
//! fresh database: two teams and public claims, each map first built the way
//! an operator builds it (W5's `apply_hierarchies`, from results the test
//! writes), then refreshed by `run_night` with a fake naming backend.
//!
//! Every read runs as the timer runs it: the `#[sqlx::test]` pool (a
//! BYPASSRLS superuser, the maintenance stand-in) with a BYPASS viewer, so
//! the map predicates are the only thing keeping another team's rows off a
//! map.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::{BTreeMap, BTreeSet};

use epigraph_atlas_contract::{parse_and_validate, LevelDocument, Node};
use epigraph_cli::atlas_links::build::apply_hierarchies;
use epigraph_cli::atlas_links::files::{LinksComputeVersions, LinksResultDoc, LinksResultTheme};
use epigraph_cli::atlas_meaning::files::{ComputeVersions, ResultDoc, ResultTheme};
use epigraph_cli::atlas_meaning::tree::{group_id, map_key, root_id, WireGroup, WireKind};
use epigraph_cli::atlas_naming::backend::RecordingBackend;
use epigraph_cli::atlas_nightly::build::{run_night, NightOptions};
use epigraph_db::repos::atlas_map::{AtlasHierarchy, AtlasMap, MapEpochs, NewMapRun};
use epigraph_db::{AtlasMapRepository, Viewer};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

const CAP: usize = 100;
const DIM: usize = 1536;
const M: AtlasHierarchy = AtlasHierarchy::Meaning;
const L: AtlasHierarchy = AtlasHierarchy::Links;
const WORLD: Uuid = Uuid::nil();

// ── seeding ─────────────────────────────────────────────────────────────────

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

async fn agent(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type, display_name) \
         VALUES ($1, $2, 'system', $3)",
    )
    .bind(id)
    .bind(&pk)
    .bind(name)
    .execute(pool)
    .await
    .expect("seed agent");
    id
}

/// A 1536-d vector near axis `axis`, jittered by `jitter`.
fn vector(axis: usize, jitter: u32) -> String {
    let mut v = vec![0.0_f32; DIM];
    v[axis % DIM] = 1.0;
    v[(axis + 7 + jitter as usize) % DIM] = 0.01;
    let parts: Vec<String> = v.iter().map(|x| format!("{x}")).collect();
    format!("[{}]", parts.join(","))
}

async fn theme(pool: &PgPool, label: &str, axis: usize) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claim_themes (label, centroid) VALUES ($1, $2::vector) RETURNING id",
    )
    .bind(label)
    .bind(vector(axis, 0))
    .fetch_one(pool)
    .await
    .expect("seed theme")
}

/// `n` current embedded claims of `theme` (or none), filed by `filer`,
/// owned by `owner` (`None`: public).
async fn claims(
    pool: &PgPool,
    theme: Option<Uuid>,
    filer: Uuid,
    owner: Option<Uuid>,
    n: u32,
    axis: usize,
) -> Vec<Uuid> {
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                                 visibility, owner_group_id, theme_id, embedding) \
             VALUES (gen_random_uuid(), 'nightly claim ' || gen_random_uuid()::text, \
                     decode(md5(random()::text) || md5(random()::text), 'hex'), 0.7, $1, true, \
                     CASE WHEN $2::uuid IS NULL THEN 'public' ELSE 'group' END, \
                     COALESCE($2, $5), $3, $4::vector) \
             RETURNING id",
        )
        .bind(filer)
        .bind(owner)
        .bind(theme)
        .bind(vector(axis, i))
        .bind(WORLD)
        .fetch_one(pool)
        .await
        .expect("seed claim");
        out.push(id);
    }
    out
}

/// One evidence row on each claim, linked by a stored `evidence -> claim`
/// edge (070 stamps both from the claim). Returns the evidence ids.
async fn evidence_on_each(pool: &PgPool, claims: &[Uuid]) -> Vec<Uuid> {
    let mut out = Vec::new();
    for &c in claims {
        let ev: Uuid = sqlx::query_scalar(
            "INSERT INTO evidence (claim_id, evidence_type, content_hash, raw_content) \
             VALUES ($1, 'document', decode(md5(random()::text) || md5(random()::text), 'hex'), \
                     'evidence text ' || gen_random_uuid()::text) \
             RETURNING id",
        )
        .bind(c)
        .fetch_one(pool)
        .await
        .expect("seed evidence");
        link(pool, ev, "evidence", c, "supports").await;
        out.push(ev);
    }
    out
}

async fn link(pool: &PgPool, source: Uuid, source_type: &str, target: Uuid, rel: &str) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, 'claim', $4)",
    )
    .bind(source)
    .bind(source_type)
    .bind(target)
    .bind(rel)
    .execute(pool)
    .await
    .expect("seed edge");
}

/// An evidence-keyed BBA on a binary frame: `m({0}) = 0.7` for `claim`
/// (hypothesis 0), so the `ev -supports-> claim` edge is `exact`, weight 0.7.
async fn exact_mass(pool: &PgPool, ev: Uuid, claim: Uuid, filer: Uuid) {
    let frame: Uuid =
        sqlx::query_scalar("INSERT INTO frames (name, hypotheses) VALUES ($1, $2) RETURNING id")
            .bind(format!("nightly-{}", Uuid::new_v4()))
            .bind(vec!["true".to_string(), "false".to_string()])
            .fetch_one(pool)
            .await
            .expect("seed frame");
    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, 0)",
    )
    .bind(claim)
    .bind(frame)
    .execute(pool)
    .await
    .expect("seed claim_frames");
    sqlx::query(
        "INSERT INTO perspectives (id, name, owner_agent_id, perspective_type, visibility, \
                                   owner_group_id) \
         VALUES ($1, 'nightly', $2, 'evidence', 'public', $3)",
    )
    .bind(ev)
    .bind(filer)
    .bind(WORLD)
    .execute(pool)
    .await
    .expect("seed perspective");
    sqlx::query(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, perspective_id, \
                                     masses, evidence_id, source_strength) \
         VALUES ($1, $2, $3, $4, $5, $4, 0.5)",
    )
    .bind(claim)
    .bind(frame)
    .bind(filer)
    .bind(ev)
    .bind(serde_json::json!({"0": 0.7, "0,1": 0.3}))
    .execute(pool)
    .await
    .expect("seed bba");
}

/// Two teams and public claims:
/// * team A, theme `t1`: `a` (30 claims chained by `supports`, an evidence
///   row each, one with an exact mass), `b` (likewise), `u` (20 unlinked),
///   plus `p`, 5 PUBLIC unlinked claims; 148 nodes, so not one leaf;
/// * team A, theme `t2`: 5 claims (one leaf);
/// * team B, theme `t3`: 8 claims (one leaf).
///
/// Each team map also draws `t1`'s public claims, so team B's map holds
/// `t1` (one leaf of `p`) beside `t3`.
struct Corpus {
    a_team: Uuid,
    b_team: Uuid,
    t1: Uuid,
    t2: Uuid,
    t3: Uuid,
    fa: Uuid,
    a: Vec<Uuid>,
    b: Vec<Uuid>,
    u: Vec<Uuid>,
    p: Vec<Uuid>,
    t2c: Vec<Uuid>,
    t3c: Vec<Uuid>,
}

impl Corpus {
    async fn new(pool: &PgPool) -> Self {
        let a_team = team(pool, "nightly team a").await;
        let b_team = team(pool, "nightly team b").await;
        let t1 = theme(pool, "nightly t1", 0).await;
        let t2 = theme(pool, "nightly t2", 300).await;
        let t3 = theme(pool, "nightly t3", 400).await;
        let fa = agent(pool, "Filer A").await;
        let fb = agent(pool, "Filer B").await;
        let fu = agent(pool, "Filer U").await;
        let a = claims(pool, Some(t1), fa, Some(a_team), 30, 0).await;
        let b = claims(pool, Some(t1), fb, Some(a_team), 30, 100).await;
        let ev_a = evidence_on_each(pool, &a).await;
        evidence_on_each(pool, &b).await;
        exact_mass(pool, ev_a[0], a[0], fa).await;
        for w in a.windows(2) {
            link(pool, w[0], "claim", w[1], "supports").await;
        }
        for w in b.windows(2) {
            link(pool, w[0], "claim", w[1], "supports").await;
        }
        let u = claims(pool, Some(t1), fu, Some(a_team), 20, 200).await;
        let p = claims(pool, Some(t1), fu, None, 5, 200).await;
        let t2c = claims(pool, Some(t2), fu, Some(a_team), 5, 300).await;
        let t3c = claims(pool, Some(t3), fu, Some(b_team), 8, 400).await;
        Self {
            a_team,
            b_team,
            t1,
            t2,
            t3,
            fa,
            a,
            b,
            u,
            p,
            t2c,
            t3c,
        }
    }

    fn up(&self) -> BTreeSet<Uuid> {
        self.u.iter().chain(&self.p).copied().collect()
    }
}

fn set(v: &[Uuid]) -> BTreeSet<Uuid> {
    v.iter().copied().collect()
}

fn wire_leaf(id: Uuid, parent: Option<Uuid>, depth: u8, members: &BTreeSet<Uuid>) -> WireGroup {
    WireGroup {
        id,
        parent,
        depth,
        kind: WireKind::Leaf,
        claim_count: u32::try_from(members.len()).unwrap(),
        weight: 0,
        members: Some(members.iter().copied().collect()),
        children: None,
    }
}

/// A flat tree under the theme root, one leaf per part (or one root leaf).
fn flat(map: AtlasMap, h: AtlasHierarchy, theme: Uuid, parts: &[BTreeSet<Uuid>]) -> Vec<WireGroup> {
    let root = root_id(map, h, theme);
    if parts.len() == 1 {
        return vec![wire_leaf(root, None, 0, &parts[0])];
    }
    let ids: Vec<Uuid> = parts.iter().map(|p| group_id(map, h, theme, p)).collect();
    let mut out = vec![WireGroup {
        id: root,
        parent: None,
        depth: 0,
        kind: WireKind::Group,
        claim_count: 0,
        weight: 0,
        members: None,
        children: Some(ids.clone()),
    }];
    for (id, p) in ids.into_iter().zip(parts) {
        out.push(wire_leaf(id, Some(root), 1, p));
    }
    out
}

/// One theme of an operator build: (theme, meaning parts, links parts).
type ThemeParts = (Uuid, Vec<BTreeSet<Uuid>>, Vec<BTreeSet<Uuid>>);

/// The operator's build of `map`, applied as ONE run of both hierarchies.
async fn operator_build(
    pool: &PgPool,
    viewer: &Viewer,
    map: AtlasMap,
    themes: &[ThemeParts],
) -> Uuid {
    let meaning = ResultDoc {
        format: "atlas-meaning-result/1".to_string(),
        map: map_key(map),
        hierarchy: "meaning".to_string(),
        cap: CAP,
        seed: 42,
        versions: ComputeVersions::default(),
        themes: themes
            .iter()
            .map(|(t, m, _)| ResultTheme {
                theme_id: *t,
                id_chunk_cuts: 0,
                groups: flat(map, M, *t, m),
            })
            .collect(),
    };
    let links = LinksResultDoc {
        format: "atlas-links-result/1".to_string(),
        map: map_key(map),
        hierarchy: "links".to_string(),
        cap: CAP,
        seed: 42,
        versions: LinksComputeVersions::default(),
        themes: themes
            .iter()
            .map(|(t, _, l)| LinksResultTheme {
                theme_id: *t,
                id_chunk_cuts: 0,
                embedding_splits: 0,
                groups: flat(map, L, *t, l),
            })
            .collect(),
    };
    let mut conn = pool.acquire().await.unwrap();
    let report = apply_hierarchies(&mut conn, viewer, map, &meaning, &links, CAP, true)
        .await
        .expect("the operator build applies");
    serde_json::from_value(report["run_id"].clone()).unwrap()
}

/// Build all three maps as an operator would.
async fn build_all(pool: &PgPool, viewer: &Viewer, c: &Corpus) {
    operator_build(
        pool,
        viewer,
        AtlasMap::Team(c.a_team),
        &[
            (
                c.t1,
                vec![set(&c.a), set(&c.b), c.up()],
                vec![set(&c.a), set(&c.b), c.up()],
            ),
            (c.t2, vec![set(&c.t2c)], vec![set(&c.t2c)]),
        ],
    )
    .await;
    operator_build(
        pool,
        viewer,
        AtlasMap::Team(c.b_team),
        &[
            (c.t1, vec![set(&c.p)], vec![set(&c.p)]),
            (c.t3, vec![set(&c.t3c)], vec![set(&c.t3c)]),
        ],
    )
    .await;
    operator_build(
        pool,
        viewer,
        AtlasMap::Public,
        &[(c.t1, vec![set(&c.p)], vec![set(&c.p)])],
    )
    .await;
}

/// A deterministic fake model: a name hashed from the prompt.
fn namer() -> RecordingBackend {
    RecordingBackend::new(|prompt: &str| {
        let mut h: u32 = 0x811c_9dc5;
        for b in prompt.bytes() {
            h = (h ^ u32::from(b)).wrapping_mul(0x0100_0193);
        }
        Ok(format!("{{\"name\": \"Topic {h:08x}\"}}"))
    })
}

fn opts() -> NightOptions {
    NightOptions {
        apply: true,
        ..NightOptions::default()
    }
}

async fn night(
    pool: &PgPool,
    viewer: &Viewer,
    backend: &RecordingBackend,
    o: &NightOptions,
) -> Value {
    let mut conn = pool.acquire().await.unwrap();
    let (summary, ok) = run_night(&mut conn, viewer, backend, o)
        .await
        .expect("the night runs");
    assert!(ok, "a map failed: {summary:#}");
    summary
}

fn map_report(summary: &Value, map: AtlasMap) -> &Value {
    summary["maps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["map"] == map_key(map))
        .unwrap_or_else(|| panic!("no report for {}: {summary:#}", map_key(map)))
}

/// The latest finished run of `map`.
async fn latest(pool: &PgPool, map: AtlasMap) -> Uuid {
    let (owner, vis) = map.tenancy();
    sqlx::query_scalar(
        "SELECT id FROM atlas_map_runs WHERE owner_group_id = $1 AND visibility = $2 \
           AND finished_at IS NOT NULL ORDER BY finished_at DESC, id DESC LIMIT 1",
    )
    .bind(owner)
    .bind(vis)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Every stored level of `run`: (hierarchy, group id) -> (theme, payload).
async fn levels(pool: &PgPool, run: Uuid) -> BTreeMap<(String, Uuid), (Uuid, Value)> {
    sqlx::query_as::<_, (String, Uuid, Uuid, Value)>(
        "SELECT hierarchy, group_id, theme_id, payload FROM atlas_map_levels WHERE run_id = $1",
    )
    .bind(run)
    .fetch_all(pool)
    .await
    .unwrap()
    .into_iter()
    .map(|(h, g, t, p)| ((h, g), (t, p)))
    .collect()
}

fn parse(p: &Value) -> LevelDocument {
    parse_and_validate(&serde_json::to_vec(p).unwrap())
        .unwrap_or_else(|v| panic!("a stored level breaks the contract: {v}"))
}

fn relaid(report: &Value) -> BTreeSet<String> {
    report["layout"]["relaid"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap().to_string())
        .collect()
}

// ── the tests ───────────────────────────────────────────────────────────────

/// Done when: a run over a synthetic multi-team corpus completes, every
/// stored level validates, both hierarchies are present, the switches
/// resolve, and leaves carry real nodes, weights, positions and names.
#[sqlx::test(migrations = "../../migrations")]
async fn a_night_over_two_teams_stores_real_validated_levels_in_both_hierarchies(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    build_all(&pool, &viewer, &c).await;
    let backend = namer();
    let summary = night(&pool, &viewer, &backend, &opts()).await;
    assert!(backend.calls() > 0);

    let maps = [
        (AtlasMap::Team(c.a_team), vec![c.t1, c.t2]),
        (AtlasMap::Team(c.b_team), vec![c.t1, c.t3]),
        (AtlasMap::Public, vec![c.t1]),
    ];
    let mut saw_exact = false;
    for (map, themes) in maps {
        let r = map_report(&summary, map);
        assert_eq!(r["status"], "written", "{r:#}");
        let run = latest(&pool, map).await;
        assert_eq!(r["run_id"], serde_json::json!(run));
        let stored = levels(&pool, run).await;
        let ids: BTreeSet<(String, Uuid)> = stored.keys().cloned().collect();
        for t in &themes {
            for h in [M, L] {
                assert!(
                    ids.contains(&(h.as_str().to_string(), root_id(map, h, *t))),
                    "theme {t} has no {} root on {}",
                    h.as_str(),
                    map_key(map)
                );
            }
        }
        for ((h, gid), (_, payload)) in &stored {
            let doc = parse(payload);
            let (switch, name, needs) = match &doc {
                LevelDocument::Group(g) => (g.switch.clone(), g.name.clone(), g.needs_naming),
                LevelDocument::Leaf(l) => (l.switch.clone(), l.name.clone(), l.needs_naming),
            };
            // The switch names a stored level of the other hierarchy.
            let other = if h == "meaning" { "links" } else { "meaning" };
            assert!(
                ids.contains(&(other.to_string(), switch.level_id)),
                "{h}/{gid} switches to a level the run does not hold"
            );
            assert!(name.is_some() && !needs, "{h}/{gid} is unnamed");
            match doc {
                LevelDocument::Leaf(l) => {
                    let claims: Vec<Uuid> = l
                        .nodes
                        .iter()
                        .filter(|n| matches!(n, Node::Claim(_)))
                        .map(Node::id)
                        .collect();
                    assert!(
                        l.nodes.iter().any(|n| matches!(n, Node::Agent(_))),
                        "leaf {gid} has no agent node (a skeleton)"
                    );
                    assert!(!l.edges.is_empty(), "leaf {gid} has no edge");
                    if l.nodes.len() > 1 {
                        assert!(
                            l.nodes.iter().any(|n| match n {
                                Node::Claim(x) => x.x != 0.0 || x.y != 0.0,
                                Node::Agent(x) | Node::Evidence(x) => x.x != 0.0 || x.y != 0.0,
                            }),
                            "leaf {gid} has no position"
                        );
                    }
                    for e in &l.edges {
                        if e.flow_basis == epigraph_atlas_contract::FlowBasis::Exact {
                            assert!((e.flow_weight - 0.7).abs() < 1e-9);
                            saw_exact = true;
                        }
                    }
                    // A team map never draws another team's claim; the
                    // public map only public claims.
                    for cl in claims {
                        match map {
                            AtlasMap::Team(t) if t == c.a_team => {
                                assert!(!c.t3c.contains(&cl), "team B's claim on A's map");
                            }
                            AtlasMap::Team(_) => {
                                assert!(c.t3c.contains(&cl) || c.p.contains(&cl));
                            }
                            AtlasMap::Public => {
                                assert!(c.p.contains(&cl), "a team claim on the public map")
                            }
                        }
                    }
                }
                LevelDocument::Group(g) => {
                    assert!(g.children.iter().all(|ch| ch.r > 0.0 && ch.name.is_some()));
                }
            }
        }
    }
    assert!(saw_exact, "no leaf carries the exact evidence mass");
    // The claim proxy weights are W7's strength x sign (supports: 0.8).
    let run = latest(&pool, AtlasMap::Team(c.a_team)).await;
    let leaf_a = &levels(&pool, run).await[&(
        "meaning".to_string(),
        group_id(AtlasMap::Team(c.a_team), M, c.t1, &set(&c.a)),
    )]
        .1;
    let proxy: Vec<f64> = leaf_a["edges"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["flow_basis"] == "proxy")
        .map(|e| e["flow_weight"].as_f64().unwrap())
        .collect();
    assert_eq!(proxy.len(), 29);
    assert!(proxy.iter().all(|w| (w - 0.8).abs() < 1e-9));
    // A deep meaning level switches to its best links group, not the root.
    let a_map = AtlasMap::Team(c.a_team);
    let mleaf =
        &levels(&pool, run).await[&("meaning".to_string(), group_id(a_map, M, c.t1, &c.up()))].1;
    assert_eq!(
        mleaf["switch"]["level_id"],
        serde_json::json!(group_id(a_map, L, c.t1, &c.up()))
    );
}

/// Done when: two consecutive runs over unchanged input change nothing. The
/// variant built: the second night writes NO run (every level equal to the
/// stored one, `run_id` aside, and the epochs equal), lays nothing out and
/// makes zero model calls.
#[sqlx::test(migrations = "../../migrations")]
async fn a_second_night_over_unchanged_input_writes_nothing_and_calls_no_model(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    build_all(&pool, &viewer, &c).await;
    let backend = namer();
    night(&pool, &viewer, &backend, &opts()).await;
    let calls = backend.calls();
    let maps = [
        AtlasMap::Team(c.a_team),
        AtlasMap::Team(c.b_team),
        AtlasMap::Public,
    ];
    let mut runs = Vec::new();
    for m in maps {
        runs.push(latest(&pool, m).await);
    }
    let second = night(&pool, &viewer, &backend, &opts()).await;
    assert_eq!(backend.calls(), calls, "the second night called the model");
    for (m, run) in maps.into_iter().zip(runs) {
        let r = map_report(&second, m);
        assert_eq!(r["status"], "unchanged", "{r:#}");
        assert_eq!(r["documents_unchanged"], true);
        assert_eq!(r["layout"]["computed"], 0, "{r:#}");
        assert_eq!(r["naming"]["report"]["calls"], 0);
        assert!(relaid(r).is_empty());
        assert_eq!(latest(&pool, m).await, run, "a run was written");
    }
}

/// Done when: a run with new claims touches only the affected groups. One
/// new unthemed claim, near leaf `a`: the theme step assigns it to `t1`, the
/// nightly puts it in meaning leaf `a` and (unlinked) in a new mirror; only
/// those two leaves and the two roots are laid out again or renamed, and
/// every other level keeps its nodes, edges, positions and name.
#[sqlx::test(migrations = "../../migrations")]
async fn a_new_claim_relays_and_renames_only_its_leaf_and_ancestors(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    build_all(&pool, &viewer, &c).await;
    let backend = namer();
    night(&pool, &viewer, &backend, &opts()).await;
    let a_map = AtlasMap::Team(c.a_team);
    let before = levels(&pool, latest(&pool, a_map).await).await;

    let new = claims(&pool, None, c.fa, Some(c.a_team), 1, 0).await[0];
    let calls = backend.calls();
    let summary = night(&pool, &viewer, &backend, &opts()).await;
    let made = backend.calls() - calls;
    assert_eq!(summary["themes"]["assigned"], 1, "{summary:#}");
    let r = map_report(&summary, a_map);
    assert_eq!(r["status"], "written", "{r:#}");
    let mut a2 = set(&c.a);
    a2.insert(new);
    let affected: BTreeSet<String> = [
        format!("meaning/{}", group_id(a_map, M, c.t1, &a2)),
        format!("meaning/{}", root_id(a_map, M, c.t1)),
        format!("links/{}", group_id(a_map, L, c.t1, &set(&[new]))),
        format!("links/{}", root_id(a_map, L, c.t1)),
    ]
    .into();
    assert_eq!(relaid(r), affected, "{r:#}");
    let renamed: BTreeSet<String> = r["naming"]["renamed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();
    assert!(
        !renamed.is_empty() && renamed.is_subset(&affected),
        "{renamed:?}"
    );
    // Only the affected levels may cost a model call; every other name is
    // copied by key.
    assert!(
        (1..=affected.len()).contains(&made),
        "{made} model calls for {} affected levels",
        affected.len()
    );
    assert_eq!(r["naming"]["report"]["calls"], made);
    // The other maps did not change at all.
    for m in [AtlasMap::Team(c.b_team), AtlasMap::Public] {
        assert_eq!(map_report(&summary, m)["status"], "unchanged");
    }
    // Every unaffected level keeps its nodes, edges, positions and name.
    let after = levels(&pool, latest(&pool, a_map).await).await;
    let mut kept = 0;
    for ((h, gid), (_, payload)) in &after {
        if affected.contains(&format!("{h}/{gid}")) {
            continue;
        }
        let (_, old) = before
            .get(&(h.clone(), *gid))
            .unwrap_or_else(|| panic!("{h}/{gid} is new but not affected"));
        for k in ["nodes", "edges", "children", "name"] {
            assert_eq!(payload.get(k), old.get(k), "{h}/{gid}: {k} changed");
        }
        kept += 1;
    }
    assert!(kept >= 6, "{kept}");
    // The meaning leaf holds the new claim; the links tree mirrors it.
    let leaf = &after[&("meaning".to_string(), group_id(a_map, M, c.t1, &a2))].1;
    assert!(leaf["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n["id"] == serde_json::json!(new)));
    // The prune kept the map's runs at the default three or fewer.
    let (owner, vis) = a_map.tenancy();
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM atlas_map_runs WHERE owner_group_id = $1 AND visibility = $2",
    )
    .bind(owner)
    .bind(vis)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(n <= 3, "{n} runs kept");
}

/// 26 new team-A claims in `t1`, near `u` (so they join meaning leaf `u+p`),
/// linked to each other twice over: 1,300 edges, past the contract's 1,024
/// per leaf, so theme `t1`'s update fails. One more claim joins `t2`.
async fn break_t1_and_grow_t2(pool: &PgPool, c: &Corpus) -> Uuid {
    let fx = agent(pool, "Filer X").await;
    let clique = claims(pool, Some(c.t1), fx, Some(c.a_team), 26, 200).await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         SELECT s, 'claim', t, 'claim', r \
           FROM unnest($1::uuid[]) s, unnest($1::uuid[]) t, \
                (VALUES ('supports'), ('corroborates')) v(r) \
          WHERE s <> t",
    )
    .bind(&clique)
    .execute(pool)
    .await
    .expect("seed the clique");
    claims(pool, Some(c.t2), c.fa, Some(c.a_team), 1, 300).await[0]
}

/// Done when: a drifted theme does not fail the night. Theme `t1` fails;
/// its leaves are unchanged, so its previous levels are carried (both
/// hierarchies, documents equal to the previous run's) while `t2` is
/// updated in the same new run.
#[sqlx::test(migrations = "../../migrations")]
async fn a_theme_that_fails_is_carried_and_the_night_completes(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    build_all(&pool, &viewer, &c).await;
    let backend = namer();
    night(&pool, &viewer, &backend, &opts()).await;
    let a_map = AtlasMap::Team(c.a_team);
    let before = levels(&pool, latest(&pool, a_map).await).await;
    let grown = break_t1_and_grow_t2(&pool, &c).await;

    let summary = night(&pool, &viewer, &backend, &opts()).await;
    let r = map_report(&summary, a_map);
    assert_eq!(r["status"], "written", "{r:#}");
    let carried = r["themes"]["carried"].as_array().unwrap();
    assert_eq!(carried.len(), 1, "{r:#}");
    assert_eq!(carried[0]["theme_id"], serde_json::json!(c.t1));
    assert!(
        carried[0]["error"].as_str().unwrap().contains("1024"),
        "{r:#}"
    );
    let run = latest(&pool, a_map).await;
    let after = levels(&pool, run).await;
    let mut t1_levels = 0;
    for (k, (theme, payload)) in &before {
        if *theme != c.t1 {
            continue;
        }
        let (_, now) = after.get(k).expect("a carried level is in the new run");
        let mut a = parse(payload);
        let mut b = parse(now);
        for d in [&mut a, &mut b] {
            match d {
                LevelDocument::Group(g) => g.run_id = Uuid::nil(),
                LevelDocument::Leaf(l) => l.run_id = Uuid::nil(),
            }
        }
        assert_eq!(a, b, "carried level {k:?} changed");
        t1_levels += 1;
    }
    assert!(t1_levels >= 8);
    let t2_root = &after[&("meaning".to_string(), root_id(a_map, M, c.t2))].1;
    assert!(t2_root["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n["id"] == serde_json::json!(grown)));
    let params: Value = sqlx::query_scalar("SELECT params FROM atlas_map_runs WHERE id = $1")
        .bind(run)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(params["themes"]["carried"], serde_json::json!([c.t1]));
}

/// The carry is a leak control: when theme `t1` fails AND one of its claims
/// has left team A's map, `t1` is dropped from the run, not carried, and no
/// stored level of the map names that claim.
#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_theme_with_a_narrowed_claim_is_dropped_not_carried(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    build_all(&pool, &viewer, &c).await;
    let backend = namer();
    night(&pool, &viewer, &backend, &opts()).await;
    let a_map = AtlasMap::Team(c.a_team);
    break_t1_and_grow_t2(&pool, &c).await;
    let moved = c.a[3];
    sqlx::query("UPDATE claims SET owner_group_id = $2 WHERE id = $1")
        .bind(moved)
        .bind(c.b_team)
        .execute(&pool)
        .await
        .expect("move a claim to team B");

    let summary = night(&pool, &viewer, &backend, &opts()).await;
    let r = map_report(&summary, a_map);
    assert_eq!(r["status"], "written", "{r:#}");
    assert!(
        r["themes"]["carried"].as_array().unwrap().is_empty(),
        "{r:#}"
    );
    let dropped = r["themes"]["dropped"].as_array().unwrap();
    assert_eq!(dropped.len(), 1, "{r:#}");
    assert_eq!(dropped[0]["theme_id"], serde_json::json!(c.t1));
    let after = levels(&pool, latest(&pool, a_map).await).await;
    assert!(
        after.values().all(|(t, _)| *t != c.t1),
        "a level of the dropped theme"
    );
    let text = serde_json::to_string(&after.values().map(|(_, p)| p).collect::<Vec<_>>()).unwrap();
    assert!(
        !text.contains(&moved.to_string()),
        "the moved claim is on A's map"
    );
}

/// Done when: pruning keeps exactly K finished runs (of that map only), and
/// an unfinished run older than the newest finished one, but not a newer
/// one.
#[sqlx::test(migrations = "../../migrations")]
async fn pruning_keeps_exactly_k_finished_runs_of_that_map_only(pool: PgPool) {
    let a = AtlasMap::Team(team(&pool, "prune a").await);
    let b = AtlasMap::Team(team(&pool, "prune b").await);
    let mut conn = pool.acquire().await.unwrap();
    let open = |map| NewMapRun {
        map,
        algo: "prune-test".to_string(),
        params: serde_json::json!({}),
        epochs: MapEpochs::default(),
    };
    let stale = AtlasMapRepository::write_run(&mut conn, &open(a))
        .await
        .unwrap();
    let mut finished = Vec::new();
    for _ in 0..5 {
        let r = AtlasMapRepository::write_run(&mut conn, &open(a))
            .await
            .unwrap();
        AtlasMapRepository::finish_run(&mut conn, r).await.unwrap();
        finished.push(r);
    }
    let in_flight = AtlasMapRepository::write_run(&mut conn, &open(a))
        .await
        .unwrap();
    for _ in 0..2 {
        let r = AtlasMapRepository::write_run(&mut conn, &open(b))
            .await
            .unwrap();
        AtlasMapRepository::finish_run(&mut conn, r).await.unwrap();
    }
    assert!(AtlasMapRepository::prune_runs(&mut conn, a, 0)
        .await
        .is_err());
    let deleted = AtlasMapRepository::prune_runs(&mut conn, a, 3)
        .await
        .unwrap();
    assert_eq!(
        deleted, 3,
        "two old finished runs and the stale unfinished one"
    );
    let left: BTreeSet<Uuid> =
        sqlx::query_scalar("SELECT id FROM atlas_map_runs WHERE owner_group_id = $1")
            .bind(a.tenancy().0)
            .fetch_all(&pool)
            .await
            .unwrap()
            .into_iter()
            .collect();
    let want: BTreeSet<Uuid> = finished[2..].iter().copied().chain([in_flight]).collect();
    assert_eq!(left, want);
    assert!(!left.contains(&stale));
    let b_runs: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM atlas_map_runs WHERE owner_group_id = $1")
            .bind(b.tenancy().0)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(b_runs, 2, "another map's runs are untouched");
}
