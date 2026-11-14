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
use epigraph_cli::atlas_layout::force::{layout_group, GroupInput};
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
    let trees: Vec<ThemeTrees> = themes
        .iter()
        .map(|(t, m, l)| (*t, flat(map, M, *t, m), flat(map, L, *t, l)))
        .collect();
    operator_build_trees(pool, viewer, map, &trees).await
}

/// One theme of an operator build as wire trees: (theme, meaning, links).
type ThemeTrees = (Uuid, Vec<WireGroup>, Vec<WireGroup>);

/// [`operator_build`] with any tree shape.
async fn operator_build_trees(
    pool: &PgPool,
    viewer: &Viewer,
    map: AtlasMap,
    themes: &[ThemeTrees],
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
                groups: m.clone(),
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
                groups: l.clone(),
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
/// linked to each other twice over: 1,300 edges among 26 claims, past the
/// contract's 1,024 per leaf, so the leaf that takes them must split on
/// edges. Returns the clique.
async fn grow_t1_by_a_clique(pool: &PgPool, c: &Corpus) -> Vec<Uuid> {
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
    clique
}

/// One new team-A claim in `t1`, near `u`, with 33 evidence rows of its own
/// that all cite each other: 33 + 1,056 + 1 edges among its own 35 nodes.
/// No split can bring ONE claim under the contract's 1,024 edges, so theme
/// `t1`'s update fails. One more claim joins `t2`.
async fn break_t1_and_grow_t2(pool: &PgPool, c: &Corpus) -> Uuid {
    let fx = agent(pool, "Filer X").await;
    let dense = claims(pool, Some(c.t1), fx, Some(c.a_team), 1, 200).await;
    let ev = evidence_on_each(pool, &vec![dense[0]; 33]).await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            visibility, owner_group_id) \
         SELECT s, 'evidence', t, 'evidence', 'cites', 'group', $2 \
           FROM unnest($1::uuid[]) s, unnest($1::uuid[]) t \
          WHERE s <> t",
    )
    .bind(&ev)
    .bind(c.a_team)
    .execute(pool)
    .await
    .expect("seed the dense evidence");
    claims(pool, Some(c.t2), c.fa, Some(c.a_team), 1, 300).await[0]
}

/// The edge limit splits, it does not freeze (review finding: a leaf over
/// 1,024 edges used to fail its theme on every night, carried forever). The
/// clique joins leaf `u+p`; the nightly splits that leaf on edges, builds
/// theme `t1` (nothing carried or dropped), every stored level validates and
/// every clique claim is drawn in both hierarchies. The next night over the
/// same input writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_leaf_over_the_edge_limit_is_split_not_frozen(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    build_all(&pool, &viewer, &c).await;
    let backend = namer();
    night(&pool, &viewer, &backend, &opts()).await;
    let a_map = AtlasMap::Team(c.a_team);
    let clique = grow_t1_by_a_clique(&pool, &c).await;

    let summary = night(&pool, &viewer, &backend, &opts()).await;
    let r = map_report(&summary, a_map);
    assert_eq!(r["status"], "written", "{r:#}");
    for k in ["carried", "dropped", "unbuilt"] {
        assert!(r["themes"][k].as_array().unwrap().is_empty(), "{k}: {r:#}");
    }
    let after = levels(&pool, latest(&pool, a_map).await).await;
    let mut drawn: BTreeMap<String, BTreeSet<Uuid>> = BTreeMap::new();
    for ((h, _), (theme, payload)) in &after {
        if let LevelDocument::Leaf(l) = parse(payload) {
            if *theme == c.t1 {
                for n in &l.nodes {
                    if let Node::Claim(cl) = n {
                        drawn.entry(h.clone()).or_default().insert(cl.id);
                    }
                }
            }
        }
    }
    for h in ["meaning", "links"] {
        let got = drawn.get(h).cloned().unwrap_or_default();
        assert!(
            set(&clique).is_subset(&got),
            "{h}: a clique claim is not drawn"
        );
    }

    let calls = backend.calls();
    let again = night(&pool, &viewer, &backend, &opts()).await;
    assert_eq!(
        map_report(&again, a_map)["status"],
        "unchanged",
        "{again:#}"
    );
    assert_eq!(
        backend.calls(),
        calls,
        "an unchanged night called the model"
    );
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

/// The first night after an operator build carries a failing theme too: the
/// previous run holds skeleton leaves (claims only), and every node of them
/// is still drawable, so `t1` keeps its levels (both hierarchies, the same
/// claims in the same leaves) instead of vanishing from the map.
#[sqlx::test(migrations = "../../migrations")]
async fn a_theme_that_fails_on_the_first_night_keeps_its_skeleton_levels(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    build_all(&pool, &viewer, &c).await;
    let a_map = AtlasMap::Team(c.a_team);
    let before = levels(&pool, latest(&pool, a_map).await).await;
    break_t1_and_grow_t2(&pool, &c).await;

    let backend = namer();
    let summary = night(&pool, &viewer, &backend, &opts()).await;
    let r = map_report(&summary, a_map);
    assert_eq!(r["status"], "written", "{r:#}");
    let carried = r["themes"]["carried"].as_array().unwrap();
    assert_eq!(carried.len(), 1, "{r:#}");
    assert_eq!(carried[0]["theme_id"], serde_json::json!(c.t1));
    let after = levels(&pool, latest(&pool, a_map).await).await;
    let claims_of = |p: &Value| -> BTreeSet<String> {
        p["nodes"]
            .as_array()
            .map(|n| {
                n.iter()
                    .filter(|x| x["kind"] == "claim")
                    .map(|x| x["id"].as_str().unwrap().to_string())
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut t1_levels = 0;
    for (k, (theme, payload)) in &before {
        if *theme != c.t1 {
            continue;
        }
        let (_, now) = after.get(k).expect("a carried level is in the new run");
        assert_eq!(claims_of(now), claims_of(payload), "{k:?}");
        parse(now);
        t1_levels += 1;
    }
    assert!(t1_levels >= 8);
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

/// Done when: pruning keeps exactly K finished runs, through the nightly
/// itself (`--keep-runs`), not only the repository call: an operator build
/// and three nights that each change team A's map make four runs of it;
/// with `keep_runs = 2` exactly the two newest are left.
#[sqlx::test(migrations = "../../migrations")]
async fn the_nightly_prunes_its_map_to_keep_runs(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    build_all(&pool, &viewer, &c).await;
    let a_map = AtlasMap::Team(c.a_team);
    let backend = namer();
    let o = NightOptions {
        keep_runs: 2,
        ..opts()
    };
    let mut written = Vec::new();
    for k in 0..3_usize {
        claims(&pool, None, c.fa, Some(c.a_team), 1, 0).await;
        let summary = night(&pool, &viewer, &backend, &o).await;
        let r = map_report(&summary, a_map);
        assert_eq!(r["status"], "written", "night {k}: {r:#}");
        written.push(latest(&pool, a_map).await);
    }
    let (owner, vis) = a_map.tenancy();
    let left: BTreeSet<Uuid> = sqlx::query_scalar(
        "SELECT id FROM atlas_map_runs WHERE owner_group_id = $1 AND visibility = $2",
    )
    .bind(owner)
    .bind(vis)
    .fetch_all(&pool)
    .await
    .unwrap()
    .into_iter()
    .collect();
    assert_eq!(
        left,
        set(&written[1..]),
        "exactly the two newest runs are kept"
    );
}

/// The nightly's "a newer run was published meanwhile" path: another
/// session holds team A's publish lock while the nightly builds, publishes a
/// newer run of the map and lets go. The nightly, which built from the
/// older run, writes nothing over it ("superseded"); the newer run stays
/// served.
#[sqlx::test(migrations = "../../migrations")]
async fn a_night_that_finds_a_newer_run_at_publish_writes_nothing(pool: PgPool) {
    use sqlx::Connection;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    build_all(&pool, &viewer, &c).await;
    let a_map = AtlasMap::Team(c.a_team);
    let backend = namer();
    night(&pool, &viewer, &backend, &opts()).await;
    claims(&pool, None, c.fa, Some(c.a_team), 1, 0).await;

    let mut holder = pool.acquire().await.unwrap();
    let mut tx = holder.begin().await.unwrap();
    AtlasMapRepository::lock_map_for_publish(&mut tx, a_map)
        .await
        .unwrap();
    let watcher = pool.clone();
    let publish = async move {
        let mut waited = false;
        for _ in 0..600 {
            waited = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_locks \
                   WHERE locktype = 'advisory' AND NOT granted)",
            )
            .fetch_one(&watcher)
            .await
            .unwrap();
            if waited {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        let newer = AtlasMapRepository::write_run(
            &mut tx,
            &NewMapRun {
                map: a_map,
                algo: "operator-rebuild-test".to_string(),
                params: serde_json::json!({}),
                epochs: MapEpochs::default(),
            },
        )
        .await
        .unwrap();
        AtlasMapRepository::finish_run(&mut tx, newer)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        (waited, newer)
    };
    let mut conn = pool.acquire().await.unwrap();
    let o = opts();
    let (ran, (waited, newer)) = tokio::join!(run_night(&mut conn, &viewer, &backend, &o), publish);
    assert!(waited, "the nightly never waited for the publish lock");
    let (summary, ok) = ran.expect("the night runs");
    assert!(ok, "{summary:#}");
    let r = map_report(&summary, a_map);
    assert_eq!(r["status"], "superseded", "{r:#}");
    assert!(r.get("run_id").is_none(), "{r:#}");
    assert_eq!(
        latest(&pool, a_map).await,
        newer,
        "the newer run stays served"
    );
}

/// Claims with no embedding are in no leaf; the map's summary counts them
/// in EVERY theme (review finding: a theme with no embedded member, which
/// has no tree, was not counted). Team A: one unembedded claim in `t1` and
/// two in a theme with no embedded member at all; team B's unembedded claim
/// in that theme is not on A's map.
#[sqlx::test(migrations = "../../migrations")]
async fn unembedded_members_are_counted_in_every_theme_of_the_map(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    build_all(&pool, &viewer, &c).await;
    let t4 = theme(&pool, "nightly t4", 500).await;
    let mut bare = claims(&pool, Some(c.t1), c.fa, Some(c.a_team), 1, 0).await;
    bare.extend(claims(&pool, Some(t4), c.fa, Some(c.a_team), 2, 500).await);
    bare.extend(claims(&pool, Some(t4), c.fa, Some(c.b_team), 1, 500).await);
    sqlx::query("UPDATE claims SET embedding = NULL WHERE id = ANY($1)")
        .bind(&bare)
        .execute(&pool)
        .await
        .unwrap();
    let dry = NightOptions {
        apply: false,
        ..opts()
    };
    let summary = night(&pool, &viewer, &namer(), &dry).await;
    let a = map_report(&summary, AtlasMap::Team(c.a_team));
    assert_eq!(a["unembedded_members"], 3, "{a:#}");
    let b = map_report(&summary, AtlasMap::Team(c.b_team));
    assert_eq!(b["unembedded_members"], 1, "{b:#}");
}

// ── cross-group links ───────────────────────────────────────────────────────

/// A stored claim-to-claim edge; returns its id.
async fn link_id(pool: &PgPool, source: Uuid, target: Uuid, rel: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(rel)
    .fetch_one(pool)
    .await
    .expect("seed edge")
}

/// Force an edge's tenancy (070 stamps it from the endpoints on insert).
async fn force_edge(pool: &PgPool, id: Uuid, visibility: &str, owner: Uuid, co: Option<Uuid>) {
    let n = sqlx::query(
        "UPDATE edges SET visibility = $2, owner_group_id = $3, \
                          co_owner_group_id = $4 WHERE id = $1",
    )
    .bind(id)
    .bind(visibility)
    .bind(owner)
    .bind(co)
    .execute(pool)
    .await
    .expect("force edge tenancy")
    .rows_affected();
    assert_eq!(n, 1);
}

/// [`claims`] of team `owner` in `theme`, with the given ids.
async fn claims_with_ids(
    pool: &PgPool,
    theme: Uuid,
    filer: Uuid,
    owner: Uuid,
    ids: &[Uuid],
    axis: usize,
) -> Vec<Uuid> {
    for (i, id) in ids.iter().enumerate() {
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                                 visibility, owner_group_id, theme_id, embedding) \
             VALUES ($1, 'nightly claim ' || $1::text, \
                     decode(md5($1::text) || md5($1::text), 'hex'), 0.7, $2, true, 'group', $3, \
                     $4, $5::vector)",
        )
        .bind(id)
        .bind(filer)
        .bind(owner)
        .bind(theme)
        .bind(vector(axis, u32::try_from(i).unwrap()))
        .execute(pool)
        .await
        .expect("seed claim");
    }
    ids.to_vec()
}

async fn chain(pool: &PgPool, claims: &[Uuid]) {
    for w in claims.windows(2) {
        link(pool, w[0], "claim", w[1], "supports").await;
    }
}

/// A map with links across groups, leaves and themes. Team T:
/// * theme `x1`: leaves `a`, `b`, `c`, `d` of 25 claims each, each chained by
///   `supports` and filed by its own agent (104 nodes, so not one leaf; every
///   claim linked, so no mirror), built as `root -> {A, G -> {B, C}, D}` in
///   both hierarchies;
/// * theme `x2`: 3 claims `t`, one root leaf.
///
/// The links between leaves:
/// * `a1 -> b1` supports (also stored as `SUPPORTS`: one link), `a2 -> b2`
///   refutes, `b4 -> c4` contradicts, `c5 -> a5` elaborates, `d9 -> a9`
///   decomposes_to, `a3 -> t0` cites (another theme);
/// * `d6 -> b6` corroborates, a PUBLIC edge (it counts);
/// * `a6 -> b6` supports, co-owned with team O (never counts);
/// * `a7 -> d7` supports, owned by team O (never counts).
struct Linked {
    team: Uuid,
    x1: Uuid,
    x2: Uuid,
    a: Vec<Uuid>,
    b: Vec<Uuid>,
    c: Vec<Uuid>,
    d: Vec<Uuid>,
    t: Vec<Uuid>,
}

/// The level ids of [`Linked`] in one hierarchy.
struct LinkedIds {
    root: Uuid,
    g: Uuid,
    a: Uuid,
    b: Uuid,
    c: Uuid,
    d: Uuid,
    rt: Uuid,
}

impl Linked {
    async fn new(pool: &PgPool) -> Self {
        let t_team = team(pool, "links team t").await;
        let o_team = team(pool, "links team o").await;
        let x1 = theme(pool, "links x1", 600).await;
        let x2 = theme(pool, "links x2", 900).await;
        let mut parts = Vec::new();
        for (i, name) in ["Filer LA", "Filer LB", "Filer LC", "Filer LD"]
            .into_iter()
            .enumerate()
        {
            let f = agent(pool, name).await;
            let cl = claims(pool, Some(x1), f, Some(t_team), 25, 600 + i * 10).await;
            chain(pool, &cl).await;
            parts.push(cl);
        }
        let ft = agent(pool, "Filer LT").await;
        let t = claims(pool, Some(x2), ft, Some(t_team), 3, 900).await;
        let d = parts.pop().unwrap();
        let c = parts.pop().unwrap();
        let b = parts.pop().unwrap();
        let a = parts.pop().unwrap();
        link(pool, a[1], "claim", b[1], "supports").await;
        link(pool, a[1], "claim", b[1], "SUPPORTS").await;
        link(pool, a[2], "claim", b[2], "refutes").await;
        link(pool, b[4], "claim", c[4], "contradicts").await;
        link(pool, c[5], "claim", a[5], "elaborates").await;
        link(pool, d[9], "claim", a[9], "decomposes_to").await;
        link(pool, a[3], "claim", t[0], "cites").await;
        let public = link_id(pool, d[6], b[6], "corroborates").await;
        force_edge(pool, public, "public", WORLD, None).await;
        let co = link_id(pool, a[6], b[6], "supports").await;
        force_edge(pool, co, "group", t_team, Some(o_team)).await;
        let other = link_id(pool, a[7], d[7], "supports").await;
        force_edge(pool, other, "group", o_team, None).await;
        Self {
            team: t_team,
            x1,
            x2,
            a,
            b,
            c,
            d,
            t,
        }
    }

    fn map(&self) -> AtlasMap {
        AtlasMap::Team(self.team)
    }

    fn ids(&self, h: AtlasHierarchy) -> LinkedIds {
        let m = self.map();
        let bc: BTreeSet<Uuid> = self.b.iter().chain(&self.c).copied().collect();
        LinkedIds {
            root: root_id(m, h, self.x1),
            g: group_id(m, h, self.x1, &bc),
            a: group_id(m, h, self.x1, &set(&self.a)),
            b: group_id(m, h, self.x1, &set(&self.b)),
            c: group_id(m, h, self.x1, &set(&self.c)),
            d: group_id(m, h, self.x1, &set(&self.d)),
            rt: root_id(m, h, self.x2),
        }
    }

    /// `root -> {A, G -> {B, C}, D}` as a wire tree.
    fn tree(&self, h: AtlasHierarchy) -> Vec<WireGroup> {
        let i = self.ids(h);
        let group = |id, parent, depth, children: Vec<Uuid>| WireGroup {
            id,
            parent,
            depth,
            kind: WireKind::Group,
            claim_count: 0,
            weight: 0,
            members: None,
            children: Some(children),
        };
        vec![
            group(i.root, None, 0, vec![i.a, i.g, i.d]),
            wire_leaf(i.a, Some(i.root), 1, &set(&self.a)),
            group(i.g, Some(i.root), 1, vec![i.b, i.c]),
            wire_leaf(i.b, Some(i.g), 2, &set(&self.b)),
            wire_leaf(i.c, Some(i.g), 2, &set(&self.c)),
            wire_leaf(i.d, Some(i.root), 1, &set(&self.d)),
        ]
    }

    async fn build(&self, pool: &PgPool, viewer: &Viewer) {
        let t = set(&self.t);
        operator_build_trees(
            pool,
            viewer,
            self.map(),
            &[
                (self.x1, self.tree(M), self.tree(L)),
                (
                    self.x2,
                    flat(self.map(), M, self.x2, std::slice::from_ref(&t)),
                    flat(self.map(), L, self.x2, std::slice::from_ref(&t)),
                ),
            ],
        )
        .await;
    }
}

type BundleRow = (Uuid, Uuid, u32, i8);
type OutRow = (Uuid, u32, i8, Vec<Uuid>);

/// A stored run's documents of one hierarchy, by level id.
async fn docs_of(pool: &PgPool, run: Uuid, h: AtlasHierarchy) -> BTreeMap<Uuid, LevelDocument> {
    levels(pool, run)
        .await
        .into_iter()
        .filter(|((hh, _), _)| hh == h.as_str())
        .map(|((_, id), (_, p))| (id, parse(&p)))
        .collect()
}

fn bundles_of(docs: &BTreeMap<Uuid, LevelDocument>, id: Uuid) -> BTreeSet<BundleRow> {
    let LevelDocument::Group(g) = &docs[&id] else {
        panic!("{id} is not a group")
    };
    g.bundles
        .iter()
        .map(|b| (b.source, b.target, b.count, b.net_sign))
        .collect()
}

fn targets_of(docs: &BTreeMap<Uuid, LevelDocument>, id: Uuid) -> BTreeSet<(Uuid, Uuid, u8)> {
    let LevelDocument::Group(g) = &docs[&id] else {
        panic!("{id} is not a group")
    };
    g.targets
        .iter()
        .map(|t| (t.level_id, t.theme_id, t.depth))
        .collect()
}

fn outgoing_of(docs: &BTreeMap<Uuid, LevelDocument>, id: Uuid) -> BTreeSet<OutRow> {
    let LevelDocument::Leaf(l) = &docs[&id] else {
        panic!("{id} is not a leaf")
    };
    l.outgoing
        .iter()
        .map(|o| {
            let mut s = o.sources.clone();
            s.sort();
            (o.target.level_id, o.count, o.net_sign, s)
        })
        .collect()
}

fn name_of(doc: &LevelDocument) -> Option<String> {
    match doc {
        LevelDocument::Group(g) => g.name.clone(),
        LevelDocument::Leaf(l) => l.name.clone(),
    }
}

/// The run's documents with `run_id` taken out, serialised: what must stay
/// byte-identical for a level the night did not change.
async fn bodies(pool: &PgPool, run: Uuid) -> BTreeMap<(String, Uuid), Vec<u8>> {
    levels(pool, run)
        .await
        .into_iter()
        .map(|(k, (_, mut p))| {
            p.as_object_mut().unwrap().remove("run_id");
            (k, serde_json::to_vec(&p).unwrap())
        })
        .collect()
}

fn built_ids(r: &Value) -> BTreeSet<Uuid> {
    r["themes"]["built"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| serde_json::from_value(t["theme_id"].clone()).unwrap())
        .collect()
}

/// Done when: a two-theme map with links across groups, leaves and themes
/// stores the expected bundles, targets and outgoing links in both
/// hierarchies. Each outside link points at the shallowest level the viewer
/// can navigate to: the group under the common ancestor in the same theme,
/// the other theme's root (depth 0) across themes. Counts and net signs
/// follow W7's sign rule, and every target carries its own level's name.
#[sqlx::test(migrations = "../../migrations")]
async fn links_across_groups_leaves_and_themes_fill_bundles_targets_and_outgoing(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let l = Linked::new(&pool).await;
    l.build(&pool, &viewer).await;
    let summary = night(&pool, &viewer, &namer(), &opts()).await;
    let r = map_report(&summary, l.map());
    assert_eq!(r["status"], "written", "{r:#}");
    assert_eq!(built_ids(r), [l.x1, l.x2].into(), "{r:#}");
    assert_eq!(r["links"]["dropped_outgoing"], 0, "{r:#}");
    let run = latest(&pool, l.map()).await;
    for h in [M, L] {
        let i = l.ids(h);
        let docs = docs_of(&pool, run, h).await;
        assert_eq!(
            bundles_of(&docs, i.root),
            [
                (i.a, i.g, 2, 0),
                (i.g, i.a, 1, 1),
                (i.a, i.rt, 1, 0),
                (i.d, i.a, 1, 0),
                (i.d, i.g, 1, 1),
            ]
            .into(),
            "{} root",
            h.as_str()
        );
        assert_eq!(targets_of(&docs, i.root), [(i.rt, l.x2, 0)].into());
        assert_eq!(
            bundles_of(&docs, i.g),
            [
                (i.b, i.a, 2, 0),
                (i.b, i.c, 1, -1),
                (i.c, i.a, 1, 1),
                (i.b, i.d, 1, 1),
            ]
            .into(),
            "{} G",
            h.as_str()
        );
        assert_eq!(
            targets_of(&docs, i.g),
            [(i.a, l.x1, 1), (i.d, l.x1, 1)].into()
        );
        let sorted = |v: &[Uuid]| {
            let mut v = v.to_vec();
            v.sort();
            v
        };
        let (a, b, c, d) = (&l.a, &l.b, &l.c, &l.d);
        assert_eq!(
            outgoing_of(&docs, i.a),
            [
                (i.g, 3, 1, sorted(&[a[1], a[2], a[5]])),
                (i.rt, 1, 0, vec![a[3]]),
                (i.d, 1, 0, vec![a[9]]),
            ]
            .into(),
            "{} A",
            h.as_str()
        );
        assert_eq!(
            outgoing_of(&docs, i.b),
            [
                (i.a, 2, 0, sorted(&[b[1], b[2]])),
                (i.c, 1, -1, vec![b[4]]),
                (i.d, 1, 1, vec![b[6]]),
            ]
            .into()
        );
        assert_eq!(
            outgoing_of(&docs, i.c),
            [(i.b, 1, -1, vec![c[4]]), (i.a, 1, 1, vec![c[5]])].into()
        );
        assert_eq!(
            outgoing_of(&docs, i.d),
            [(i.a, 1, 0, vec![d[9]]), (i.g, 1, 1, vec![d[6]])].into()
        );
        assert_eq!(
            outgoing_of(&docs, i.rt),
            [(i.root, 1, 0, vec![l.t[0]])].into()
        );
        // Every link target is named as its own level is.
        for doc in docs.values() {
            let named: Vec<&epigraph_atlas_contract::LinkTarget> = match doc {
                LevelDocument::Group(g) => g.targets.iter().collect(),
                LevelDocument::Leaf(x) => x.outgoing.iter().map(|o| &o.target).collect(),
            };
            for t in named {
                assert!(t.name.is_some());
                assert_eq!(t.name, name_of(&docs[&t.level_id]));
            }
        }
    }
}

/// Done when: a co-owned edge, or one another team owns, never contributes
/// to a bundle, a target or an outgoing link, even between two of the team's
/// own claims; a public edge between them does (the positive control).
#[sqlx::test(migrations = "../../migrations")]
async fn a_co_owned_or_other_teams_edge_never_makes_a_link_but_a_public_one_does(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let l = Linked::new(&pool).await;
    l.build(&pool, &viewer).await;
    night(&pool, &viewer, &namer(), &opts()).await;
    let run = latest(&pool, l.map()).await;
    for h in [M, L] {
        let i = l.ids(h);
        let docs = docs_of(&pool, run, h).await;
        let mut sources = BTreeSet::new();
        for doc in docs.values() {
            if let LevelDocument::Leaf(x) = doc {
                for o in &x.outgoing {
                    sources.extend(o.sources.iter().copied());
                }
            }
        }
        // a6 and a7 have only the co-owned and the other team's edge across
        // leaves; d7 only the other team's.
        for (who, id) in [("a6", l.a[6]), ("a7", l.a[7]), ("d7", l.d[7])] {
            assert!(
                !sources.contains(&id),
                "{}: {who} is a link source",
                h.as_str()
            );
        }
        // The public edge d6 -> b6 counts.
        assert!(sources.contains(&l.d[6]) && sources.contains(&l.b[6]));
        let root = bundles_of(&docs, i.root);
        assert!(
            root.contains(&(i.a, i.g, 2, 0)),
            "{}: the co-owned edge counted: {root:?}",
            h.as_str()
        );
        assert!(
            !root.iter().any(|b| (b.0, b.1) == (i.a, i.d)),
            "{}: the other team's edge counted: {root:?}",
            h.as_str()
        );
        assert!(
            root.contains(&(i.d, i.g, 1, 1)),
            "the public edge is missing"
        );
    }
}

/// Done when: a second night over unchanged input, links included, is still
/// unchanged (no run written, so every stored byte stays) with zero model
/// calls; and one new link changes only the levels it passes through, every
/// other level byte-identical, with no model call and only its group
/// re-laid.
#[sqlx::test(migrations = "../../migrations")]
async fn links_stay_byte_identical_until_a_link_changes_and_then_only_where_it_passes(
    pool: PgPool,
) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let l = Linked::new(&pool).await;
    l.build(&pool, &viewer).await;
    let backend = namer();
    night(&pool, &viewer, &backend, &opts()).await;
    let first = latest(&pool, l.map()).await;
    let before = bodies(&pool, first).await;
    let calls = backend.calls();

    let second = night(&pool, &viewer, &backend, &opts()).await;
    let r = map_report(&second, l.map());
    assert_eq!(r["status"], "unchanged", "{r:#}");
    assert_eq!(backend.calls(), calls, "the second night called the model");
    assert_eq!(latest(&pool, l.map()).await, first);

    // One more link inside G: B -> C.
    link(&pool, l.b[10], "claim", l.c[10], "supports").await;
    let third = night(&pool, &viewer, &backend, &opts()).await;
    let r = map_report(&third, l.map());
    assert_eq!(r["status"], "written", "{r:#}");
    assert_eq!(backend.calls(), calls, "a new link called the model");
    let after = bodies(&pool, latest(&pool, l.map()).await).await;
    assert_eq!(
        after.keys().collect::<BTreeSet<_>>(),
        before.keys().collect::<BTreeSet<_>>()
    );
    let mut changed = BTreeSet::new();
    for (k, body) in &after {
        if before[k] != *body {
            changed.insert(format!("{}/{}", k.0, k.1));
        }
    }
    let mut want = BTreeSet::new();
    let mut relay = BTreeSet::new();
    for h in [M, L] {
        let i = l.ids(h);
        for id in [i.g, i.b, i.c] {
            want.insert(format!("{}/{id}", h.as_str()));
        }
        relay.insert(format!("{}/{}", h.as_str(), i.g));
    }
    assert_eq!(changed, want);
    assert_eq!(relaid(r), relay, "{r:#}");
}

/// Done when: positions pull linked children together. Twelve equal leaves
/// under one root, in two families of six densely linked to each other (as
/// W6's own layout test): the root's linked children sit closer on average
/// than its unlinked ones, in both hierarchies, and closer than W6 places
/// the same children with no bundles (same seed, same sizes).
#[sqlx::test(migrations = "../../migrations")]
async fn the_group_layout_pulls_linked_children_together(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    // Fixed team, theme and claim ids, so every group id (UUIDv5 of the map,
    // the theme and the members) and with them the layout's seeds are the
    // same on every run.
    let t_team = Uuid::from_u128(0x6c61_796f_7574_0001_0000_0000_0000_0001);
    let key: Vec<u8> = t_team.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, 'layout team', 'did:epigraph:test-team:' || $1::text, $2, 'team')",
    )
    .bind(t_team)
    .bind(&key)
    .execute(&pool)
    .await
    .unwrap();
    let y = Uuid::from_u128(0x6c61_796f_7574_0002_0000_0000_0000_0001);
    sqlx::query(
        "INSERT INTO claim_themes (id, label, centroid) VALUES ($1, 'layout y', $2::vector)",
    )
    .bind(y)
    .bind(vector(1000, 0))
    .execute(&pool)
    .await
    .unwrap();
    let mut kids = Vec::new();
    for i in 0..12_u32 {
        let f = agent(&pool, &format!("Filer K{i}")).await;
        let ids: Vec<Uuid> = (0..10_u32)
            .map(|j| {
                Uuid::from_u128(0x6c61_796f_7574_0000_0000_0000_0000_0000 | u128::from(i * 100 + j))
            })
            .collect();
        let cl = claims_with_ids(&pool, y, f, t_team, &ids, 1000 + i as usize * 10).await;
        chain(&pool, &cl).await;
        kids.push(cl);
    }
    for fam in 0..2 {
        for x in 0..6 {
            for z in (x + 1)..6 {
                for k in 0..8 {
                    link(
                        &pool,
                        kids[fam * 6 + x][k],
                        "claim",
                        kids[fam * 6 + z][k],
                        "supports",
                    )
                    .await;
                }
            }
        }
    }
    let map = AtlasMap::Team(t_team);
    let parts: Vec<BTreeSet<Uuid>> = kids.iter().map(|k| set(k)).collect();
    operator_build(&pool, &viewer, map, &[(y, parts.clone(), parts.clone())]).await;
    night(&pool, &viewer, &namer(), &opts()).await;
    let run = latest(&pool, map).await;
    for h in [M, L] {
        let docs = docs_of(&pool, run, h).await;
        let LevelDocument::Group(root) = &docs[&root_id(map, h, y)] else {
            panic!("the root is not a group")
        };
        let ids: Vec<Uuid> = parts.iter().map(|p| group_id(map, h, y, p)).collect();
        // The ratio of the linked pairs' mean distance to the unlinked
        // pairs'.
        let ratio = |at: &BTreeMap<Uuid, (f64, f64)>| {
            let (mut on, mut non, mut off, mut noff) = (0.0, 0.0, 0.0, 0.0);
            for i in 0..12 {
                for j in (i + 1)..12 {
                    let (p, q) = (at[&ids[i]], at[&ids[j]]);
                    let d = ((p.0 - q.0).powi(2) + (p.1 - q.1).powi(2)).sqrt();
                    if i / 6 == j / 6 {
                        on += d;
                        non += 1.0;
                    } else {
                        off += d;
                        noff += 1.0;
                    }
                }
            }
            (on / non) / (off / noff)
        };
        let stored: BTreeMap<Uuid, (f64, f64)> =
            root.children.iter().map(|c| (c.id, (c.x, c.y))).collect();
        // The same level laid out by W6 with the same seed and sizes but no
        // bundles: what the night stored before the links were built.
        let unlinked = layout_group(
            root.level_id,
            &GroupInput::new(
                root.children
                    .iter()
                    .map(|c| (c.id, u64::from(c.claim_count))),
                std::iter::empty(),
            )
            .unwrap(),
        );
        let without: BTreeMap<Uuid, (f64, f64)> = unlinked
            .into_iter()
            .map(|(id, c)| (id, (c.x, c.y)))
            .collect();
        let (with_links, no_links) = (ratio(&stored), ratio(&without));
        assert!(
            with_links < 1.0,
            "{}: linked children sit no closer than unlinked ones ({with_links})",
            h.as_str()
        );
        assert!(
            with_links < no_links - 0.05,
            "{}: the links did not pull their children together ({with_links} against \
             {no_links} without them)",
            h.as_str()
        );
    }
}

/// Done when: over-cap truncation keeps the heaviest and reports the rest.
/// One leaf linked into 65 other themes' root leaves (the contract allows a
/// leaf 64 outgoing targets): 64 targets carry two links, one carries one.
/// The night completes, the light target is the one cut, and the run summary
/// and the run's params count it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_leaf_over_the_outgoing_cap_keeps_its_heaviest_targets_and_the_night_reports_the_rest(
    pool: PgPool,
) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let t_team = team(&pool, "cap team").await;
    let f = agent(&pool, "Filer Z").await;
    let z0 = theme(&pool, "cap z0", 1100).await;
    let hub = claims(&pool, Some(z0), f, Some(t_team), 1, 1100).await[0];
    let n = epigraph_atlas_contract::MAX_LEAF_OUTGOING + 1;
    let mut themes = Vec::new();
    // A run is the whole map, so the operator build holds every theme.
    let mut parts: Vec<ThemeParts> = vec![(z0, vec![set(&[hub])], vec![set(&[hub])])];
    for i in 0..n {
        let z = theme(&pool, &format!("cap z{}", i + 1), 1200 + i).await;
        let k = if i == 0 { 1 } else { 2 };
        let cl = claims(&pool, Some(z), f, Some(t_team), k, 1200 + i).await;
        for c in &cl {
            link(&pool, hub, "claim", *c, "supports").await;
        }
        parts.push((z, vec![set(&cl)], vec![set(&cl)]));
        themes.push(z);
    }
    let map = AtlasMap::Team(t_team);
    operator_build(&pool, &viewer, map, &parts).await;
    let summary = night(&pool, &viewer, &namer(), &opts()).await;
    let r = map_report(&summary, map);
    assert_eq!(r["status"], "written", "{r:#}");
    assert_eq!(built_ids(r).len(), n + 1, "{r:#}");
    // One cut per hierarchy.
    assert_eq!(r["links"]["dropped_outgoing"], 2, "{r:#}");
    assert_eq!(r["links"]["dropped_links"], 2, "{r:#}");
    let run = latest(&pool, map).await;
    let params: Value = sqlx::query_scalar("SELECT params FROM atlas_map_runs WHERE id = $1")
        .bind(run)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(params["links"], r["links"]);
    for h in [M, L] {
        let docs = docs_of(&pool, run, h).await;
        let out = outgoing_of(&docs, root_id(map, h, z0));
        assert_eq!(out.len(), epigraph_atlas_contract::MAX_LEAF_OUTGOING);
        assert!(out.iter().all(|o| o.1 == 2), "a light target was kept");
        assert!(!out.iter().any(|o| o.0 == root_id(map, h, themes[0])));
    }
}

/// Done when: a leaf claim's `truth_value` is its stored one (the colour
/// value; `claims.truth_value` is NOT NULL, so every drawn claim has one).
#[sqlx::test(migrations = "../../migrations")]
async fn leaf_claims_carry_their_stored_truth_value(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let l = Linked::new(&pool).await;
    for (i, c) in l.a.iter().chain(&l.t).enumerate() {
        sqlx::query("UPDATE claims SET truth_value = $2 WHERE id = $1")
            .bind(c)
            .bind(0.01 * (i as f64 + 1.0))
            .execute(&pool)
            .await
            .unwrap();
    }
    l.build(&pool, &viewer).await;
    night(&pool, &viewer, &namer(), &opts()).await;
    let stored: BTreeMap<Uuid, f64> = sqlx::query_as::<_, (Uuid, f64)>(
        "SELECT id, truth_value FROM claims WHERE theme_id = ANY($1)",
    )
    .bind(vec![l.x1, l.x2])
    .fetch_all(&pool)
    .await
    .unwrap()
    .into_iter()
    .collect();
    let run = latest(&pool, l.map()).await;
    let mut seen = 0;
    for h in [M, L] {
        for doc in docs_of(&pool, run, h).await.values() {
            if let LevelDocument::Leaf(x) = doc {
                for n in &x.nodes {
                    if let Node::Claim(c) = n {
                        assert_eq!(c.truth_value, Some(stored[&c.id]), "claim {}", c.id);
                        seen += 1;
                    }
                }
            }
        }
    }
    assert_eq!(seen, 2 * stored.len());
}
