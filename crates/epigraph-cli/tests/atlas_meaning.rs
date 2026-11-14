//! The Atlas "by meaning" hierarchy (Atlas W4, backlog f9fc052c) on a fresh
//! database: export a map's themes, apply a result, and check what is stored.
//!
//! The clustering itself (`scripts/atlas_meaning_core.py`) is tested in
//! `tests/theme/test_atlas_meaning_core.py`; its cross-language contract (file
//! formats and ids) in `atlas_meaning::files`. Here the result trees are
//! written by the test, so each test controls exactly what the box half
//! receives, including a deliberately coarse tree (the whole theme as one
//! leaf) that only the on-box W3 re-check can bring under the cap.
//!
//! Every read runs as the nightly runs it: a transaction opened by
//! `AtlasMapRepository::begin_build_snapshot` on the `#[sqlx::test]` pool (a
//! BYPASSRLS superuser, the maintenance stand-in) with a BYPASS viewer, where
//! neither the viewer splice nor row security filters anything, so the map
//! predicate is the only thing keeping another team's rows out.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use epigraph_cli::atlas_meaning::build::{apply_result, export_map, ExportOptions};
use epigraph_cli::atlas_meaning::files::{
    ComputeVersions, ExportIndex, ResultDoc, ResultTheme, ThemeFile,
};
use epigraph_cli::atlas_meaning::tree::{group_id, map_key, root_id, WireGroup, WireKind};
use epigraph_db::repos::atlas_leaf::{assemble_leaf, AtlasLeafRepository, LeafOutcome};
use epigraph_db::repos::atlas_map::{AtlasHierarchy, AtlasMap};
use epigraph_db::{AtlasMapRepository, AtlasMeaningRepository, Viewer};
use sqlx::PgPool;
use uuid::Uuid;

const CAP: usize = 100;
const DIM: usize = 1536;
const M: AtlasHierarchy = AtlasHierarchy::Meaning;

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

async fn agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn theme(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("INSERT INTO claim_themes (label) VALUES ('meaning test') RETURNING id")
        .fetch_one(pool)
        .await
        .expect("seed theme")
}

/// A 1536-d vector near axis `axis`, jittered by `jitter`.
fn vector(axis: usize, jitter: u32) -> String {
    let mut v = vec![0.0_f32; DIM];
    v[axis % DIM] = 1.0;
    v[(axis + 7 + jitter as usize) % DIM] = 0.01;
    let parts: Vec<String> = v.iter().map(|x| format!("{x}")).collect();
    format!("[{}]", parts.join(","))
}

/// `n` current claims of `theme`, filed by `filer`, declared `(visibility,
/// owner)`, embedded near `axis` (`None`: no embedding).
async fn claims(
    pool: &PgPool,
    theme: Uuid,
    filer: Uuid,
    (visibility, owner): (&str, Uuid),
    n: u32,
    axis: Option<usize>,
) -> Vec<Uuid> {
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                                 visibility, owner_group_id, theme_id, embedding) \
             VALUES (gen_random_uuid(), 'meaning claim ' || gen_random_uuid()::text, \
                     decode(md5(random()::text) || md5(random()::text), 'hex'), 0.7, $1, true, \
                     $2, $3, $4, $5::vector) \
             RETURNING id",
        )
        .bind(filer)
        .bind(visibility)
        .bind(owner)
        .bind(theme)
        .bind(axis.map(|a| vector(a, i)))
        .fetch_one(pool)
        .await
        .expect("seed claim");
        out.push(id);
    }
    out
}

/// One evidence row on each claim, linked by a stored `evidence -> claim`
/// edge (070 stamps both from the claim).
async fn evidence_on_each(pool: &PgPool, claims: &[Uuid]) {
    for &c in claims {
        let ev: Uuid = sqlx::query_scalar(
            "INSERT INTO evidence (claim_id, evidence_type, content_hash) \
             VALUES ($1, 'document', decode(md5(random()::text) || md5(random()::text), 'hex')) \
             RETURNING id",
        )
        .bind(c)
        .fetch_one(pool)
        .await
        .expect("seed evidence");
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
             VALUES ($1, 'evidence', $2, 'claim', 'supports')",
        )
        .bind(ev)
        .bind(c)
        .execute(pool)
        .await
        .expect("seed evidence edge");
    }
}

/// A theme of one team's map: three blobs of 40 claims (each with its own
/// evidence row, filers shared within a blob), ten public claims, twenty
/// claims of another team, two retired claims and three unembedded ones.
struct Corpus {
    team: Uuid,
    other: Uuid,
    world: Uuid,
    theme: Uuid,
    blobs: Vec<Vec<Uuid>>,
    public: Vec<Uuid>,
    others: Vec<Uuid>,
    retired: Vec<Uuid>,
    unembedded: Vec<Uuid>,
}

impl Corpus {
    async fn new(pool: &PgPool) -> Self {
        let team = team(pool, "meaning team").await;
        let other = team_other(pool).await;
        let world = fixture::world_group(pool).await;
        let theme = theme(pool).await;
        let mut blobs = Vec::new();
        for b in 0..3 {
            let filer = agent(pool).await;
            let c = claims(pool, theme, filer, ("group", team), 40, Some(100 * b)).await;
            evidence_on_each(pool, &c).await;
            blobs.push(c);
        }
        let filer = agent(pool).await;
        let public = claims(pool, theme, filer, ("public", world), 10, Some(700)).await;
        let others = claims(pool, theme, filer, ("group", other), 20, Some(0)).await;
        let retired = claims(pool, theme, filer, ("group", team), 2, None).await;
        sqlx::query("UPDATE claims SET is_current = false WHERE id = ANY($1)")
            .bind(&retired)
            .execute(pool)
            .await
            .expect("retire");
        let unembedded = claims(pool, theme, filer, ("group", team), 3, None).await;
        Self {
            team,
            other,
            world,
            theme,
            blobs,
            public,
            others,
            retired,
            unembedded,
        }
    }

    fn team_members(&self) -> BTreeSet<Uuid> {
        self.blobs
            .iter()
            .flatten()
            .chain(&self.public)
            .copied()
            .collect()
    }
}

async fn team_other(pool: &PgPool) -> Uuid {
    team(pool, "other team").await
}

// ── the build, as the binary runs it ────────────────────────────────────────

/// A fresh owner-only directory (the export refuses one others can read).
fn tmpdir() -> PathBuf {
    use std::os::unix::fs::DirBuilderExt;
    let d = std::env::temp_dir().join(format!("atlas-meaning-test-{}", Uuid::new_v4()));
    std::fs::DirBuilder::new().mode(0o700).create(&d).unwrap();
    d
}

async fn export(pool: &PgPool, viewer: &Viewer, map: AtlasMap, out: &Path) -> serde_json::Value {
    let mut conn = pool.acquire().await.unwrap();
    export_map(
        &mut conn,
        viewer,
        &ExportOptions {
            map,
            themes: None,
            cap: CAP,
            seed: 42,
        },
        out,
    )
    .await
    .expect("export")
}

async fn apply(
    pool: &PgPool,
    viewer: &Viewer,
    map: AtlasMap,
    result: &ResultDoc,
) -> anyhow::Result<serde_json::Value> {
    let mut conn = pool.acquire().await.unwrap();
    apply_result(&mut conn, viewer, map, result, CAP, true).await
}

fn result(map: AtlasMap, themes: Vec<ResultTheme>) -> ResultDoc {
    ResultDoc {
        format: "atlas-meaning-result/1".to_string(),
        map: map_key(map),
        hierarchy: "meaning".to_string(),
        cap: CAP,
        seed: 42,
        versions: ComputeVersions::default(),
        themes,
    }
}

fn leaf(id: Uuid, parent: Option<Uuid>, depth: u8, members: &BTreeSet<Uuid>) -> WireGroup {
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

fn group(id: Uuid, parent: Option<Uuid>, depth: u8, children: Vec<Uuid>) -> WireGroup {
    WireGroup {
        id,
        parent,
        depth,
        kind: WireKind::Group,
        claim_count: 0,
        weight: 0,
        members: None,
        children: Some(children),
    }
}

/// The coarse tree: the whole theme as ONE root leaf, whatever its size.
fn coarse(map: AtlasMap, theme: Uuid, members: &BTreeSet<Uuid>) -> ResultTheme {
    ResultTheme {
        theme_id: theme,
        id_chunk_cuts: 0,
        groups: vec![leaf(root_id(map, M, theme), None, 0, members)],
    }
}

/// A clustering-shaped tree: root -> {blob 0 split in two leaves under one
/// group, blob 1, blob 2 + the public claims}.
fn by_blob(map: AtlasMap, c: &Corpus) -> ResultTheme {
    let set = |v: &[Uuid]| -> BTreeSet<Uuid> { v.iter().copied().collect() };
    let root = root_id(map, M, c.theme);
    let (b0a, b0b) = c.blobs[0].split_at(20);
    let (a, b) = (set(b0a), set(b0b));
    let g0 = set(&c.blobs[0]);
    let b1 = set(&c.blobs[1]);
    let b2: BTreeSet<Uuid> = c.blobs[2].iter().chain(&c.public).copied().collect();
    let id = |s: &BTreeSet<Uuid>| group_id(map, M, c.theme, s);
    ResultTheme {
        theme_id: c.theme,
        id_chunk_cuts: 0,
        groups: vec![
            group(root, None, 0, vec![id(&g0), id(&b1), id(&b2)]),
            group(id(&g0), Some(root), 1, vec![id(&a), id(&b)]),
            leaf(id(&a), Some(id(&g0)), 2, &a),
            leaf(id(&b), Some(id(&g0)), 2, &b),
            leaf(id(&b1), Some(root), 1, &b1),
            leaf(id(&b2), Some(root), 1, &b2),
        ],
    }
}

/// One stored level row.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
struct Stored {
    group_id: Uuid,
    parent_group_id: Option<Uuid>,
    level: i32,
    owner_group_id: Uuid,
    visibility: String,
    payload: serde_json::Value,
}

async fn stored(pool: &PgPool, run: Uuid) -> Vec<Stored> {
    sqlx::query_as(
        "SELECT group_id, parent_group_id, level, owner_group_id, visibility::text AS visibility, \
                payload \
           FROM atlas_map_levels WHERE run_id = $1 AND hierarchy = 'meaning' \
          ORDER BY level, group_id",
    )
    .bind(run)
    .fetch_all(pool)
    .await
    .expect("read stored levels")
}

/// A stored level's (group, parent, level, leaf claims).
type Shape = (Uuid, Option<Uuid>, i32, Option<Vec<Uuid>>);

fn run_id(report: &serde_json::Value) -> Uuid {
    serde_json::from_value(report["run_id"].clone()).expect("a run id")
}

fn leaf_claims(s: &Stored) -> Option<Vec<Uuid>> {
    (s.payload["kind"] == "leaf").then(|| {
        s.payload["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|n| n["kind"] == "claim")
            .map(|n| serde_json::from_value(n["id"].clone()).unwrap())
            .collect()
    })
}

fn every_claim(levels: &[Stored]) -> BTreeSet<Uuid> {
    levels.iter().filter_map(leaf_claims).flatten().collect()
}

/// W3, independently of the build: read the leaf's rows afresh in a new
/// snapshot and assemble it.
async fn w3_count(pool: &PgPool, viewer: &Viewer, map: AtlasMap, ids: &[Uuid]) -> LeafOutcome {
    let mut tx = pool.begin().await.unwrap();
    AtlasMapRepository::begin_build_snapshot(&mut tx, viewer, map)
        .await
        .unwrap();
    let rows = AtlasLeafRepository::read_leaf_rows(&mut tx, viewer, map, ids)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assemble_leaf(&rows, ids, CAP).unwrap()
}

// ── the tests ───────────────────────────────────────────────────────────────

/// Done when: a test team map has every leaf at most 100 nodes. The theme
/// (130 claims, 120 evidence rows, 4 filers: 254 nodes) arrives as ONE root
/// leaf; W3's re-check on the box splits it, and every stored leaf, re-read
/// and re-assembled by W3 afresh, fits.
#[sqlx::test(migrations = "../../migrations")]
async fn every_leaf_of_a_team_map_fits_the_cap_as_w3_counts(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let map = AtlasMap::Team(c.team);
    let members = c.team_members();
    let report = apply(
        &pool,
        &viewer,
        map,
        &result(map, vec![coarse(map, c.theme, &members)]),
    )
    .await
    .expect("apply");
    assert!(
        report["params"]["resplit_leaves"].as_u64().unwrap() >= 1,
        "{report}"
    );

    let levels = stored(&pool, run_id(&report)).await;
    let root: Vec<&Stored> = levels.iter().filter(|s| s.level == 0).collect();
    assert_eq!(root.len(), 1);
    assert_eq!(root[0].group_id, root_id(map, M, c.theme));
    assert_eq!(
        root[0].payload["kind"], "group",
        "the over-cap root became a group"
    );
    let mut leaves = 0;
    for s in &levels {
        let Some(ids) = leaf_claims(s) else { continue };
        leaves += 1;
        match w3_count(&pool, &viewer, map, &ids).await {
            LeafOutcome::Fits(set) => {
                assert!(
                    set.counts.nodes <= CAP,
                    "{}: {}",
                    s.group_id,
                    set.counts.nodes
                );
                assert_eq!(set.counts.claims, ids.len());
            }
            other => panic!("leaf {} is over the cap: {other:?}", s.group_id),
        }
    }
    assert!(leaves >= 3, "254 nodes need at least three leaves of 100");
    assert_eq!(
        every_claim(&levels),
        members,
        "every member in exactly one leaf"
    );
}

/// Done when: a second run over unchanged input reproduces the same group ids
/// (and parents and levels), including the leaves W3's re-check made on the box.
#[sqlx::test(migrations = "../../migrations")]
async fn a_second_apply_over_unchanged_input_reproduces_every_group_id(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let map = AtlasMap::Team(c.team);
    let members = c.team_members();
    let shape = |levels: Vec<Stored>| -> Vec<Shape> {
        levels
            .iter()
            .map(|s| (s.group_id, s.parent_group_id, s.level, leaf_claims(s)))
            .collect()
    };
    let mut runs = Vec::new();
    for tree in [coarse(map, c.theme, &members), by_blob(map, &c)] {
        let r = result(map, vec![tree]);
        let first = apply(&pool, &viewer, map, &r).await.expect("first apply");
        let second = apply(&pool, &viewer, map, &r).await.expect("second apply");
        assert_ne!(run_id(&first), run_id(&second));
        let (a, b) = (
            shape(stored(&pool, run_id(&first)).await),
            shape(stored(&pool, run_id(&second)).await),
        );
        assert!(a.len() > 1);
        assert_eq!(a, b);
        runs.push(a);
    }
    // An unchanged group keeps its id across differently shaped runs too:
    // the root, minted from the theme alone, is in both.
    assert_eq!(runs[0][0].0, runs[1][0].0);
}

/// The export's weights are W3's counts: for each leaf of a tree, claims plus
/// the distinct attachment integers of its claims equals `assemble_leaf`'s
/// node count, so the off-box clustering weighs a group as W3 will.
#[sqlx::test(migrations = "../../migrations")]
async fn export_weights_match_what_w3_counts(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let map = AtlasMap::Team(c.team);
    let out = tmpdir();
    export(&pool, &viewer, map, &out).await;
    let file: ThemeFile =
        serde_json::from_slice(&std::fs::read(out.join(format!("{}.json", c.theme))).unwrap())
            .unwrap();
    let pos: BTreeMap<Uuid, usize> = file
        .claim_ids
        .iter()
        .enumerate()
        .map(|(i, c)| (*c, i))
        .collect();
    let parts: Vec<Vec<Uuid>> = vec![
        c.blobs[0].clone(),
        c.blobs[0][..7].to_vec(),
        c.blobs[1].iter().chain(&c.public).copied().collect(),
        c.blobs.concat(),
    ];
    for part in parts {
        let distinct: BTreeSet<u32> = part
            .iter()
            .flat_map(|id| file.attachments[pos[id]].iter().copied())
            .collect();
        let weight = part.len() + distinct.len();
        let counted = match w3_count(&pool, &viewer, map, &part).await {
            LeafOutcome::Fits(s) => s.counts.nodes,
            LeafOutcome::NeedsSplit(n) => n.counts.nodes,
            LeafOutcome::Empty { .. } => 0,
        };
        assert_eq!(weight, counted, "a part of {} claims", part.len());
    }
    // A blob's shared filer is ONE node: 40 claims + 40 evidence + 1 filer.
    let blob0: BTreeSet<u32> = c.blobs[0]
        .iter()
        .flat_map(|id| file.attachments[pos[id]].iter().copied())
        .collect();
    assert_eq!(blob0.len(), 41);
    std::fs::remove_dir_all(&out).ok();
}

/// A team map never includes another team's claim: not in the export, not in
/// any stored document, and a result that names one is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn a_team_map_never_holds_another_teams_claim(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let map = AtlasMap::Team(c.team);
    let out = tmpdir();
    let report = export(&pool, &viewer, map, &out).await;
    let file: ThemeFile =
        serde_json::from_slice(&std::fs::read(out.join(format!("{}.json", c.theme))).unwrap())
            .unwrap();
    let exported: BTreeSet<Uuid> = file.claim_ids.iter().copied().collect();
    assert_eq!(exported, c.team_members());
    assert!(c.others.iter().all(|o| !exported.contains(o)));
    assert_eq!(report["themes"][0]["unembedded"], 3, "{report}");
    let text = std::fs::read_to_string(out.join(format!("{}.json", c.theme))).unwrap();
    assert!(
        !text.contains("meaning claim"),
        "no claim text leaves the box"
    );

    let r = apply(&pool, &viewer, map, &result(map, vec![by_blob(map, &c)]))
        .await
        .expect("apply");
    let levels = stored(&pool, run_id(&r)).await;
    assert!(levels
        .iter()
        .all(|s| s.owner_group_id == c.team && s.visibility == "group"));
    let drawn = every_claim(&levels);
    assert_eq!(drawn, c.team_members());
    for o in &c.others {
        assert!(!drawn.contains(o));
        assert!(levels
            .iter()
            .all(|s| !s.payload.to_string().contains(&o.to_string())));
    }

    // A result that puts the other team's claims in a leaf, with every id
    // correctly minted, is refused: they are not members of this map.
    let mut forged = c.team_members();
    forged.extend(c.others.iter().copied());
    let err = apply(
        &pool,
        &viewer,
        map,
        &result(map, vec![coarse(map, c.theme, &forged)]),
    )
    .await
    .expect_err("another team's claim");
    assert!(err.to_string().contains("do not cover"), "{err}");
    std::fs::remove_dir_all(&out).ok();
}

/// The public map includes only public claims.
#[sqlx::test(migrations = "../../migrations")]
async fn the_public_map_holds_only_public_claims(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let map = AtlasMap::Public;
    let out = tmpdir();
    export(&pool, &viewer, map, &out).await;
    let index: ExportIndex =
        serde_json::from_slice(&std::fs::read(out.join("export.json")).unwrap()).unwrap();
    assert_eq!(index.map, "public");
    let file: ThemeFile =
        serde_json::from_slice(&std::fs::read(out.join(format!("{}.json", c.theme))).unwrap())
            .unwrap();
    let public: BTreeSet<Uuid> = c.public.iter().copied().collect();
    assert_eq!(
        file.claim_ids.iter().copied().collect::<BTreeSet<_>>(),
        public
    );

    let r = apply(
        &pool,
        &viewer,
        map,
        &result(map, vec![coarse(map, c.theme, &public)]),
    )
    .await
    .expect("apply");
    let levels = stored(&pool, run_id(&r)).await;
    assert_eq!(
        levels.len(),
        1,
        "ten claims fit one root leaf: no empty level"
    );
    assert_eq!(levels[0].payload["kind"], "leaf");
    assert_eq!(levels[0].payload["map_scope"], "public");
    assert!(levels
        .iter()
        .all(|s| s.owner_group_id == c.world && s.visibility == "public"));
    assert_eq!(every_claim(&levels), public);

    // The team's tree is not the public map's.
    let team_tree = by_blob(AtlasMap::Team(c.team), &c);
    let err = apply(&pool, &viewer, map, &result(map, vec![team_tree]))
        .await
        .expect_err("a team tree on the public map");
    assert!(err.to_string().contains("root id"), "{err}");
    std::fs::remove_dir_all(&out).ok();
}

/// Every stored level document validates against the contract, and the
/// stored rows chain: each non-root's parent is stored and lists it as a
/// child, with the right kind and claim count.
#[sqlx::test(migrations = "../../migrations")]
async fn stored_level_documents_validate_against_the_contract(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let map = AtlasMap::Team(c.team);
    let r = apply(&pool, &viewer, map, &result(map, vec![by_blob(map, &c)]))
        .await
        .expect("apply");
    let run = run_id(&r);
    let levels = stored(&pool, run).await;
    assert_eq!(levels.len(), 6);
    let by_id: BTreeMap<Uuid, &Stored> = levels.iter().map(|s| (s.group_id, s)).collect();
    for s in &levels {
        let body = serde_json::to_vec(&s.payload).unwrap();
        let doc = epigraph_atlas_contract::parse_and_validate(&body)
            .unwrap_or_else(|v| panic!("{}: {v}", s.group_id));
        assert_eq!(doc.level_id(), s.group_id);
        assert_eq!(s.payload["run_id"], serde_json::json!(run));
        assert_eq!(s.payload["depth"], s.level);
        assert_eq!(s.payload["map_group_id"], serde_json::json!(c.team));
        if let Some(p) = s.parent_group_id {
            let parent = by_id[&p];
            assert_eq!(parent.level, s.level - 1);
            let child = parent.payload["children"]
                .as_array()
                .unwrap()
                .iter()
                .find(|ch| ch["id"] == serde_json::json!(s.group_id))
                .expect("listed by its parent");
            assert_eq!(child["kind"], s.payload["kind"]);
            if let Some(ids) = leaf_claims(s) {
                assert_eq!(child["claim_count"], ids.len());
            }
        }
    }
}

/// Membership (claim to leaf) reads back from the stored leaf documents.
#[sqlx::test(migrations = "../../migrations")]
async fn leaf_membership_reads_back_every_claim(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let map = AtlasMap::Team(c.team);
    let tree = by_blob(map, &c);
    let r = apply(&pool, &viewer, map, &result(map, vec![tree.clone()]))
        .await
        .expect("apply");
    let mut conn = pool.acquire().await.unwrap();
    let got = AtlasMeaningRepository::leaf_membership(&mut conn, &viewer, map, run_id(&r), M)
        .await
        .expect("leaf_membership");
    let mut want = BTreeMap::new();
    for g in &tree.groups {
        for m in g.members.iter().flatten() {
            want.insert(*m, g.id);
        }
    }
    assert_eq!(got, want);
    // Another map's run reads nothing.
    let none = AtlasMeaningRepository::leaf_membership(
        &mut conn,
        &viewer,
        AtlasMap::Team(c.other),
        run_id(&r),
        M,
    )
    .await
    .unwrap();
    assert!(none.is_empty());
}

/// A claim filed since the export makes the result stale: refused, nothing
/// written.
#[sqlx::test(migrations = "../../migrations")]
async fn apply_refuses_a_result_whose_members_drifted(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let map = AtlasMap::Team(c.team);
    let r = result(map, vec![by_blob(map, &c)]);
    let filer = agent(&pool).await;
    claims(&pool, c.theme, filer, ("group", c.team), 1, Some(5)).await;
    let err = apply(&pool, &viewer, map, &r).await.expect_err("drift");
    assert!(err.to_string().contains("do not cover"), "{err}");
    let runs: i64 = sqlx::query_scalar("SELECT count(*) FROM atlas_map_runs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(runs, 0, "nothing written");
}

/// A run is the WHOLE map (the latest finished run is what is served): a
/// result that lacks a theme the map draws with an embedded member is refused
/// and nothing is written. Themes the map does not draw (only another team's
/// claims, or only unembedded members) are not required, and a result naming
/// one is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn apply_refuses_a_result_that_lacks_a_theme_the_map_draws(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let map = AtlasMap::Team(c.team);
    let filer = agent(&pool).await;
    // Not drawn on this team's map: another team's theme, and a theme whose
    // members have no embedding (a retired claim has none either:
    // chk_deprecated_no_embedding).
    let theirs = theme(&pool).await;
    claims(&pool, theirs, filer, ("group", c.other), 5, Some(300)).await;
    let bare = theme(&pool).await;
    claims(&pool, bare, filer, ("group", c.team), 2, None).await;
    // Drawn: a second theme of the team's own claims.
    let second = theme(&pool).await;
    let members: BTreeSet<Uuid> = claims(&pool, second, filer, ("group", c.team), 6, Some(500))
        .await
        .into_iter()
        .collect();

    let runs = |pool: PgPool| async move {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM atlas_map_runs")
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    let err = apply(&pool, &viewer, map, &result(map, vec![by_blob(map, &c)]))
        .await
        .expect_err("a theme is missing");
    assert!(err.to_string().contains("lacks 1 of the 2 themes"), "{err}");
    assert_eq!(runs(pool.clone()).await, 0, "nothing written");

    let foreign = coarse(map, theirs, &BTreeSet::new());
    let err = apply(
        &pool,
        &viewer,
        map,
        &result(
            map,
            vec![by_blob(map, &c), coarse(map, second, &members), foreign],
        ),
    )
    .await
    .expect_err("a theme the map does not draw");
    assert!(err.to_string().contains("does not draw"), "{err}");
    assert_eq!(runs(pool.clone()).await, 0, "nothing written");

    let report = apply(
        &pool,
        &viewer,
        map,
        &result(map, vec![by_blob(map, &c), coarse(map, second, &members)]),
    )
    .await
    .expect("every drawn theme");
    assert_eq!(report["params"]["themes"], 2, "{report}");
    assert_eq!(runs(pool.clone()).await, 1);
}

/// An id that is not the minted one is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn apply_refuses_a_forged_group_id(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let map = AtlasMap::Team(c.team);
    let mut tree = by_blob(map, &c);
    let forged = Uuid::new_v4();
    let old = tree.groups[4].id;
    tree.groups[4].id = forged;
    for g in &mut tree.groups {
        if let Some(ch) = g.children.as_mut() {
            for k in ch.iter_mut().filter(|k| **k == old) {
                *k = forged;
            }
        }
    }
    let err = apply(&pool, &viewer, map, &result(map, vec![tree]))
        .await
        .expect_err("forged id");
    assert!(err.to_string().contains("minted"), "{err}");
}

/// Retired claims (superseded or duplicate-marked) and current claims with no
/// embedding are not members of the tree; the report counts the second.
#[sqlx::test(migrations = "../../migrations")]
async fn retired_and_unembedded_claims_are_not_members(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let map = AtlasMap::Team(c.team);
    let mut tx = pool.begin().await.unwrap();
    AtlasMapRepository::begin_build_snapshot(&mut tx, &viewer, map)
        .await
        .unwrap();
    let members = AtlasMeaningRepository::theme_members(&mut tx, &viewer, map, c.theme)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let ids: BTreeSet<Uuid> = members.embedded.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, c.team_members());
    assert_eq!(members.unembedded, c.unembedded.len());
    assert!(c.retired.iter().all(|r| !ids.contains(r)));
    assert!(members
        .embedded
        .iter()
        .all(|(_, e)| e.starts_with('[') && e.matches(',').count() == DIM - 1));
}

/// The export, run as the real binary under a typical umask (022), leaves
/// nothing another local user can read: the directory it creates is 0700 and
/// every file in it 0600. Embeddings approximate claim text. Also the box
/// half end to end through the process an operator runs.
#[sqlx::test(migrations = "../../migrations")]
async fn the_binary_export_is_owner_only_under_umask_022(pool: PgPool) {
    let c = Corpus::new(&pool).await;
    let url = fixture::database_url_for(&pool).await;
    let parent = tmpdir();
    let out = parent.join("export");
    let run = std::process::Command::new("sh")
        .arg("-c")
        .arg(r#"umask 022; exec "$0" "$@""#)
        .arg(env!("CARGO_BIN_EXE_atlas_meaning"))
        .args(["export", "--map", &map_key(AtlasMap::Team(c.team)), "--out"])
        .arg(&out)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("DATABASE_URL", &url)
        .env("MAINTENANCE_DATABASE_URL", &url)
        .env("RUST_LOG", "warn")
        .current_dir(&parent)
        .output()
        .expect("run atlas_meaning");
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(run.status.success(), "export failed: {stderr}");
    let report: serde_json::Value = serde_json::from_slice(&run.stdout).expect("the report");
    assert_eq!(report["exported_themes"], 1, "{report}");

    let mode = |p: &Path| {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    };
    assert_eq!(mode(&out) & 0o077, 0, "the directory is {:o}", mode(&out));
    let files: Vec<PathBuf> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(
        files.len(),
        3,
        "export.json and the theme's two files: {files:?}"
    );
    for f in &files {
        assert_eq!(mode(f), 0o600, "{} is {:o}", f.display(), mode(f));
    }
    let file: ThemeFile =
        serde_json::from_slice(&std::fs::read(out.join(format!("{}.json", c.theme))).unwrap())
            .unwrap();
    let got: BTreeSet<Uuid> = file.claim_ids.into_iter().collect();
    assert_eq!(got, c.team_members());
    std::fs::remove_dir_all(&parent).ok();
}

/// The binary refuses a malformed map or an out-of-range cap before it
/// connects anywhere (the database URL names nothing that answers).
#[test]
fn the_binary_refuses_a_bad_map_or_cap_before_connecting() {
    let bin = env!("CARGO_BIN_EXE_atlas_meaning");
    let dir = tmpdir();
    let cases: [(&[&str], &str); 4] = [
        (
            &["export", "--map", "team:not-a-uuid", "--out"],
            "is not a uuid",
        ),
        (
            &["export", "--map", "group:x", "--out"],
            "a map is `public`",
        ),
        (
            &["export", "--map", "public", "--cap", "101", "--out"],
            "--cap must be 1 to 100",
        ),
        (
            &["apply", "--map", "public", "--cap", "0", "--from"],
            "--cap must be 1 to 100",
        ),
    ];
    for (args, want) in cases {
        let out = std::process::Command::new(bin)
            .env_clear()
            .current_dir(&dir)
            .arg("--database-url")
            .arg("postgres://nobody@127.0.0.1:1/none")
            .args(args)
            .arg(&dir)
            .output()
            .expect("run atlas_meaning");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{args:?} succeeded");
        assert!(stderr.contains(want), "{args:?}: {stderr}");
    }
    std::fs::remove_dir_all(&dir).ok();
}
