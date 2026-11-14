//! The Atlas "by links" hierarchy (Atlas W5, backlog 4e02c23f, with W5b
//! febb2a77) on a fresh database: export a map's themes for the off-box
//! grouping, apply a meaning result and a links result as ONE run, and check
//! what is stored.
//!
//! The grouping itself (`scripts/atlas_links_core.py`) is tested in
//! `tests/theme/test_atlas_links_core.py`; its cross-language contract (file
//! formats, ids, the mirror rule) in `atlas_links::files`. Here both result
//! trees are written by the test, so each test controls exactly what the box
//! half receives, including a deliberately coarse links leaf (two linked
//! clusters as one leaf) that only the on-box W3 re-check can bring under the
//! cap.
//!
//! Every read runs as the nightly runs it: a transaction opened by
//! `AtlasMapRepository::begin_build_snapshot` on the `#[sqlx::test]` pool (a
//! BYPASSRLS superuser, the maintenance stand-in) with a BYPASS viewer, where
//! neither the viewer splice nor row security filters anything, so the map
//! predicate (W3's edge rule included) is the only thing keeping another
//! team's rows and every co-owned edge out.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use epigraph_cli::atlas_links::build::{apply_hierarchies, export_links, LinksExportOptions};
use epigraph_cli::atlas_links::files::{
    LinksComputeVersions, LinksResultDoc, LinksResultTheme, LinksThemeFile,
};
use epigraph_cli::atlas_meaning::files::{ComputeVersions, ResultDoc, ResultTheme};
use epigraph_cli::atlas_meaning::tree::{group_id, map_key, root_id, WireGroup, WireKind};
use epigraph_db::repos::atlas_leaf::{assemble_leaf, AtlasLeafRepository, LeafOutcome};
use epigraph_db::repos::atlas_map::{AtlasHierarchy, AtlasMap};
use epigraph_db::{AtlasMapRepository, AtlasMeaningRepository, Viewer};
use sqlx::PgPool;
use uuid::Uuid;

const CAP: usize = 100;
const DIM: usize = 1536;
const M: AtlasHierarchy = AtlasHierarchy::Meaning;
const L: AtlasHierarchy = AtlasHierarchy::Links;

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

/// A 1536-d vector near axis `axis`, jittered by `jitter`.
fn vector(axis: usize, jitter: u32) -> String {
    let mut v = vec![0.0_f32; DIM];
    v[axis % DIM] = 1.0;
    v[(axis + 7 + jitter as usize) % DIM] = 0.01;
    let parts: Vec<String> = v.iter().map(|x| format!("{x}")).collect();
    format!("[{}]", parts.join(","))
}

/// `n` current embedded claims of `theme`, filed by `filer`, owned by `owner`.
async fn claims(
    pool: &PgPool,
    theme: Uuid,
    filer: Uuid,
    owner: Uuid,
    n: u32,
    axis: usize,
) -> Vec<Uuid> {
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                                 visibility, owner_group_id, theme_id, embedding) \
             VALUES (gen_random_uuid(), 'links claim ' || gen_random_uuid()::text, \
                     decode(md5(random()::text) || md5(random()::text), 'hex'), 0.7, $1, true, \
                     'group', $2, $3, $4::vector) \
             RETURNING id",
        )
        .bind(filer)
        .bind(owner)
        .bind(theme)
        .bind(vector(axis, i))
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
        link(pool, ev, "evidence", c, "supports").await;
    }
}

/// A stored edge to claim `target`, tenancy as 070's trigger stamps it.
async fn link(pool: &PgPool, source: Uuid, source_type: &str, target: Uuid, rel: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, 'claim', $4) RETURNING id",
    )
    .bind(source)
    .bind(source_type)
    .bind(target)
    .bind(rel)
    .fetch_one(pool)
    .await
    .expect("seed edge")
}

/// Force an edge's tenancy columns (the trigger fires on endpoint changes only).
async fn force_edge(pool: &PgPool, id: Uuid, owner: Uuid, co_owner: Option<Uuid>) {
    let n = sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = $3 \
         WHERE id = $1",
    )
    .bind(id)
    .bind(owner)
    .bind(co_owner)
    .execute(pool)
    .await
    .expect("force edge tenancy")
    .rows_affected();
    assert_eq!(n, 1);
}

/// One team theme:
/// * `a`: 30 claims chained by `supports`, one filer, an evidence row each
///   (61 nodes);
/// * `b`: 30 claims chained by `DECOMPOSES_TO` and `CITES` (the other
///   spellings), likewise (61 nodes); `a` and `b` together are 122 nodes;
/// * `u1`, `u2`: 20 unlinked claims each (one `same_as` edge in `u1`, which
///   does not count), in two meaning leaves;
/// * `x`: one claim whose ONLY edge (to `a[0]`) is co-owned with another
///   team, so it is unlinked on this team's map;
/// * between `a` and `b`, one co-owned `supports` edge and one `supports`
///   edge owned by the other team: neither may join them.
struct Corpus {
    team: Uuid,
    other: Uuid,
    theme: Uuid,
    a: Vec<Uuid>,
    b: Vec<Uuid>,
    u1: Vec<Uuid>,
    u2: Vec<Uuid>,
    x: Uuid,
}

impl Corpus {
    async fn new(pool: &PgPool) -> Self {
        let other = team(pool, "other team").await;
        let team = team(pool, "links team").await;
        let theme: Uuid = sqlx::query_scalar(
            "INSERT INTO claim_themes (label) VALUES ('links test') RETURNING id",
        )
        .fetch_one(pool)
        .await
        .expect("seed theme");
        let (fa, fb, fu) = (agent(pool).await, agent(pool).await, agent(pool).await);
        let a = claims(pool, theme, fa, team, 30, 0).await;
        let b = claims(pool, theme, fb, team, 30, 100).await;
        evidence_on_each(pool, &a).await;
        evidence_on_each(pool, &b).await;
        for w in a.windows(2) {
            link(pool, w[0], "claim", w[1], "supports").await;
        }
        for (i, w) in b.windows(2).enumerate() {
            let rel = if i % 2 == 0 { "DECOMPOSES_TO" } else { "CITES" };
            link(pool, w[0], "claim", w[1], rel).await;
        }
        let u1 = claims(pool, theme, fu, team, 20, 200).await;
        let u2 = claims(pool, theme, fu, team, 20, 300).await;
        link(pool, u1[0], "claim", u1[1], "same_as").await;
        let x = claims(pool, theme, fu, team, 1, 200).await[0];
        let co = link(pool, x, "claim", a[0], "supports").await;
        force_edge(pool, co, team, Some(other)).await;
        let co = link(pool, a[5], "claim", b[5], "supports").await;
        force_edge(pool, co, team, Some(other)).await;
        let theirs = link(pool, a[6], "claim", b[6], "supports").await;
        force_edge(pool, theirs, other, None).await;
        Self {
            team,
            other,
            theme,
            a,
            b,
            u1,
            u2,
            x,
        }
    }

    fn map(&self) -> AtlasMap {
        AtlasMap::Team(self.team)
    }

    fn members(&self) -> BTreeSet<Uuid> {
        self.a
            .iter()
            .chain(&self.b)
            .chain(&self.u1)
            .chain(&self.u2)
            .chain([&self.x])
            .copied()
            .collect()
    }

    /// The unlinked claims, by their meaning leaf's members.
    fn mirror1(&self) -> BTreeSet<Uuid> {
        self.u1.iter().chain([&self.x]).copied().collect()
    }

    fn mirror2(&self) -> BTreeSet<Uuid> {
        self.u2.iter().copied().collect()
    }

    fn linked(&self) -> BTreeSet<Uuid> {
        self.a.iter().chain(&self.b).copied().collect()
    }
}

fn set(v: &[Uuid]) -> BTreeSet<Uuid> {
    v.iter().copied().collect()
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

/// A flat tree of `h` under the theme root, one leaf per part.
fn flat(map: AtlasMap, h: AtlasHierarchy, theme: Uuid, parts: &[BTreeSet<Uuid>]) -> Vec<WireGroup> {
    let root = root_id(map, h, theme);
    let ids: Vec<Uuid> = parts.iter().map(|p| group_id(map, h, theme, p)).collect();
    let mut out = vec![group(root, None, 0, ids.clone())];
    for (id, p) in ids.into_iter().zip(parts) {
        out.push(leaf(id, Some(root), 1, p));
    }
    out
}

/// The meaning result: one leaf per blob (`a`, `b`, `u1` + `x`, `u2`).
fn meaning_result(c: &Corpus) -> ResultDoc {
    let map = c.map();
    ResultDoc {
        format: "atlas-meaning-result/1".to_string(),
        map: map_key(map),
        hierarchy: "meaning".to_string(),
        cap: CAP,
        seed: 42,
        versions: ComputeVersions::default(),
        themes: vec![ResultTheme {
            theme_id: c.theme,
            id_chunk_cuts: 0,
            groups: flat(
                map,
                M,
                c.theme,
                &[set(&c.a), set(&c.b), c.mirror1(), c.mirror2()],
            ),
        }],
    }
}

fn links_doc(c: &Corpus, groups: Vec<WireGroup>) -> LinksResultDoc {
    LinksResultDoc {
        format: "atlas-links-result/1".to_string(),
        map: map_key(c.map()),
        hierarchy: "links".to_string(),
        cap: CAP,
        seed: 42,
        versions: LinksComputeVersions::default(),
        themes: vec![LinksResultTheme {
            theme_id: c.theme,
            id_chunk_cuts: 0,
            embedding_splits: 0,
            groups,
        }],
    }
}

/// The links result: the two linked clusters as ONE coarse leaf (122 nodes,
/// so W3's re-check must split it on the box), and the two mirrors.
fn links_result(c: &Corpus) -> LinksResultDoc {
    links_doc(
        c,
        flat(c.map(), L, c.theme, &[c.linked(), c.mirror1(), c.mirror2()]),
    )
}

async fn apply(
    pool: &PgPool,
    viewer: &Viewer,
    c: &Corpus,
    links: &LinksResultDoc,
) -> anyhow::Result<serde_json::Value> {
    let mut conn = pool.acquire().await.unwrap();
    apply_hierarchies(
        &mut conn,
        viewer,
        c.map(),
        &meaning_result(c),
        links,
        CAP,
        true,
    )
    .await
}

fn run_id(report: &serde_json::Value) -> Uuid {
    serde_json::from_value(report["run_id"].clone()).expect("a run id")
}

/// One stored level row.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
struct Stored {
    hierarchy: String,
    group_id: Uuid,
    parent_group_id: Option<Uuid>,
    level: i32,
    payload: serde_json::Value,
}

async fn stored(pool: &PgPool, run: Uuid, hierarchy: &str) -> Vec<Stored> {
    sqlx::query_as(
        "SELECT hierarchy::text AS hierarchy, group_id, parent_group_id, level, payload \
           FROM atlas_map_levels WHERE run_id = $1 AND hierarchy = $2 \
          ORDER BY level, group_id",
    )
    .bind(run)
    .bind(hierarchy)
    .fetch_all(pool)
    .await
    .expect("read stored levels")
}

fn leaf_claims(s: &Stored) -> Option<BTreeSet<Uuid>> {
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

/// W3, independently of the build: read the leaf's rows afresh and assemble.
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

/// A fresh owner-only directory (the export refuses one others can read).
fn tmpdir() -> PathBuf {
    use std::os::unix::fs::DirBuilderExt;
    let d = std::env::temp_dir().join(format!("atlas-links-test-{}", Uuid::new_v4()));
    std::fs::DirBuilder::new().mode(0o700).create(&d).unwrap();
    d
}

async fn export(pool: &PgPool, viewer: &Viewer, c: &Corpus, out: &Path) -> LinksThemeFile {
    let mut conn = pool.acquire().await.unwrap();
    export_links(
        &mut conn,
        viewer,
        &LinksExportOptions {
            map: c.map(),
            themes: None,
            cap: CAP,
            seed: 42,
        },
        &meaning_result(c),
        out,
    )
    .await
    .expect("export");
    serde_json::from_slice(&std::fs::read(out.join(format!("{}.json", c.theme))).unwrap()).unwrap()
}

// ── the tests ───────────────────────────────────────────────────────────────

/// Done when (W5 and W5b): a test team map has every links leaf at most 100
/// nodes as W3 counts them, and every unlinked claim is in the links leaf
/// that mirrors its meaning leaf, read back from the SAME stored run with
/// `leaf_membership`. The linked clusters arrive as one 122-node leaf that
/// W3's re-check splits on the box; the mirrors are left intact.
#[sqlx::test(migrations = "../../migrations")]
async fn every_leaf_fits_and_unlinked_claims_mirror_their_meaning_leaf(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let map = c.map();
    let report = apply(&pool, &viewer, &c, &links_result(&c))
        .await
        .expect("apply");
    let params = &report["params"]["links"];
    assert!(params["resplit_leaves"].as_u64().unwrap() >= 1, "{report}");
    assert_eq!(params["mirror_leaves"], 2, "{report}");
    assert_eq!(params["unlinked_claims"], 41, "{report}");
    let run = run_id(&report);

    let levels = stored(&pool, run, "links").await;
    let mut covered = BTreeSet::new();
    for s in &levels {
        let Some(ids) = leaf_claims(s) else { continue };
        let ids_v: Vec<Uuid> = ids.iter().copied().collect();
        match w3_count(&pool, &viewer, map, &ids_v).await {
            LeafOutcome::Fits(set) => assert!(set.counts.nodes <= CAP, "{}", s.group_id),
            other => panic!("links leaf {} is over the cap: {other:?}", s.group_id),
        }
        for id in &ids {
            assert!(covered.insert(*id), "claim {id} in two links leaves");
        }
    }
    assert_eq!(
        covered,
        c.members(),
        "every member in exactly one links leaf"
    );

    let mut conn = pool.acquire().await.unwrap();
    let membership = AtlasMeaningRepository::leaf_membership(&mut conn, &viewer, map, run, M)
        .await
        .expect("meaning membership of the same run");
    let linked = c.linked();
    let links_leaf_of: BTreeMap<Uuid, BTreeSet<Uuid>> = levels
        .iter()
        .filter_map(leaf_claims)
        .flat_map(|ids| ids.clone().into_iter().map(move |id| (id, ids.clone())))
        .collect();
    let mut checked = 0;
    for u in c.members().difference(&linked) {
        let meaning_leaf = membership[u];
        let want: BTreeSet<Uuid> = membership
            .iter()
            .filter(|(id, leaf)| **leaf == meaning_leaf && !linked.contains(id))
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(links_leaf_of[u], want, "unlinked claim {u}");
        checked += 1;
    }
    assert_eq!(checked, 41);
    // The co-owned edge did not link x: it sits with u1, its meaning leaf.
    assert_eq!(links_leaf_of[&c.x], c.mirror1());
}

/// No co-owned or other-team edge influences the grouping. The two linked
/// clusters are joined only by a co-owned edge and another team's edge, and
/// x's only edge is co-owned: the export (the compute's whole input) has no
/// pair across the clusters and none touching x, and an apply that groups x
/// with the linked claims instead of its mirror is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn no_co_owned_or_other_team_edge_counts_as_a_link(pool: PgPool) {
    use std::os::unix::fs::PermissionsExt;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    // The bridges exist as seeded: two edges co-owned with the other team
    // (x's and the cluster bridge) and one the other team owns.
    let (co, theirs): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE owner_group_id = $1 AND co_owner_group_id = $2), \
                COUNT(*) FILTER (WHERE owner_group_id = $2 AND co_owner_group_id IS NULL) \
           FROM edges WHERE source_type = 'claim' AND target_type = 'claim'",
    )
    .bind(c.team)
    .bind(c.other)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((co, theirs), (2, 1));
    let out = tmpdir();
    let file = export(&pool, &viewer, &c, &out).await;
    let id = |i: u32| file.claim_ids[i as usize];
    let (a, b) = (set(&c.a), set(&c.b));
    for [i, j] in &file.links {
        let (p, q) = (id(*i), id(*j));
        assert!(p != c.x && q != c.x, "a co-owned edge linked x");
        assert!(
            (a.contains(&p) && a.contains(&q)) || (b.contains(&p) && b.contains(&q)),
            "a link crosses the clusters or leaves them: {p} {q}"
        );
    }
    // Both chains count in full, in either spelling; same_as does not.
    assert_eq!(file.links.len(), 29 + 29);
    let linked: BTreeSet<Uuid> = file
        .linked()
        .into_iter()
        .map(|i| file.claim_ids[i])
        .collect();
    assert_eq!(linked, c.linked());
    // Each claim's meaning-leaf integer names its meaning leaf: four leaves,
    // and x with u1.
    let ml: BTreeMap<Uuid, u32> = file
        .claim_ids
        .iter()
        .copied()
        .zip(file.meaning_leaf.iter().copied())
        .collect();
    let leaf_of = |ids: &BTreeSet<Uuid>| ids.iter().map(|i| ml[i]).collect::<BTreeSet<u32>>();
    let parts = [set(&c.a), set(&c.b), c.mirror1(), c.mirror2()];
    let numbers: Vec<BTreeSet<u32>> = parts.iter().map(leaf_of).collect();
    assert!(numbers.iter().all(|n| n.len() == 1), "{numbers:?}");
    assert_eq!(numbers.iter().flatten().collect::<BTreeSet<_>>().len(), 4);
    // The export is owner-only, and holds only the linked claims' embeddings.
    for name in [
        format!("{}.json", c.theme),
        format!("{}.f32", c.theme),
        "export.json".into(),
    ] {
        let mode = std::fs::metadata(out.join(&name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{name}");
    }
    let f32_len = std::fs::metadata(out.join(format!("{}.f32", c.theme)))
        .unwrap()
        .len();
    assert_eq!(f32_len, (60 * DIM * 4) as u64);
    std::fs::remove_dir_all(&out).ok();

    // x grouped with the linked claims (minted correctly) is refused.
    let with_x: BTreeSet<Uuid> = c.linked().into_iter().chain([c.x]).collect();
    let bad = links_doc(
        &c,
        flat(c.map(), L, c.theme, &[with_x, set(&c.u1), c.mirror2()]),
    );
    let err = apply(&pool, &viewer, &c, &bad)
        .await
        .expect_err("x is unlinked")
        .to_string();
    assert!(err.contains("not the mirror"), "{err}");
}

/// The meaning <-> links switch round-trips at the root through the serving
/// read, because both hierarchies are in the one latest run; every deeper
/// links level's switch names a meaning level that is served too.
#[sqlx::test(migrations = "../../migrations")]
async fn the_root_switch_round_trips_between_the_hierarchies(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let map = c.map();
    let run = run_id(
        &apply(&pool, &viewer, &c, &links_result(&c))
            .await
            .expect("apply"),
    );
    let mut conn = pool.acquire().await.unwrap();
    let mroot = root_id(map, M, c.theme);
    let meaning_root = AtlasMapRepository::level_for_viewer(&mut conn, &viewer, map, M, mroot)
        .await
        .unwrap()
        .expect("the meaning root is served");
    assert_eq!(meaning_root.run_id, run);
    assert_eq!(meaning_root.payload["switch"]["hierarchy"], "links");
    let lroot: Uuid =
        serde_json::from_value(meaning_root.payload["switch"]["level_id"].clone()).unwrap();
    assert_eq!(lroot, root_id(map, L, c.theme));
    let links_root = AtlasMapRepository::level_for_viewer(&mut conn, &viewer, map, L, lroot)
        .await
        .unwrap()
        .expect("the links root is served from the same run");
    assert_eq!(links_root.run_id, run);
    assert_eq!(links_root.payload["switch"]["hierarchy"], "meaning");
    assert_eq!(
        links_root.payload["switch"]["level_id"],
        serde_json::json!(mroot)
    );

    for s in stored(&pool, run, "links").await {
        let target: Uuid = serde_json::from_value(s.payload["switch"]["level_id"].clone()).unwrap();
        let served = AtlasMapRepository::level_for_viewer(&mut conn, &viewer, map, M, target)
            .await
            .unwrap();
        assert!(
            served.is_some(),
            "links level {} switches to an unserved {target}",
            s.group_id
        );
    }
    // A mirror switches to the meaning leaf it mirrors (best overlap).
    let mirror = group_id(map, L, c.theme, &c.mirror2());
    let level = AtlasMapRepository::level_for_viewer(&mut conn, &viewer, map, L, mirror)
        .await
        .unwrap()
        .expect("the mirror is served");
    assert_eq!(
        level.payload["switch"]["level_id"],
        serde_json::json!(group_id(map, M, c.theme, &c.mirror2()))
    );
}

/// Every stored document of both hierarchies validates against the W10a
/// contract, and the stored rows chain: each non-root's parent is stored in
/// the same hierarchy and lists it as a child.
#[sqlx::test(migrations = "../../migrations")]
async fn stored_documents_of_both_hierarchies_validate(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let run = run_id(
        &apply(&pool, &viewer, &c, &links_result(&c))
            .await
            .expect("apply"),
    );
    for h in ["meaning", "links"] {
        let levels = stored(&pool, run, h).await;
        assert!(levels.len() >= 4, "{h}: {}", levels.len());
        let by_id: BTreeMap<Uuid, &Stored> = levels.iter().map(|s| (s.group_id, s)).collect();
        for s in &levels {
            assert_eq!(s.hierarchy, h);
            let body = serde_json::to_vec(&s.payload).unwrap();
            let doc = epigraph_atlas_contract::parse_and_validate(&body)
                .unwrap_or_else(|v| panic!("{h} {}: {v}", s.group_id));
            assert_eq!(doc.level_id(), s.group_id);
            assert_eq!(s.payload["run_id"], serde_json::json!(run));
            assert_eq!(s.payload["hierarchy"], h);
            assert_eq!(s.payload["needs_naming"], true);
            if let Some(p) = s.parent_group_id {
                let parent = by_id[&p];
                assert_eq!(parent.level, s.level - 1);
                assert!(parent.payload["children"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|ch| ch["id"] == serde_json::json!(s.group_id)));
            }
        }
    }
}

/// A stored level's (group, parent, level, leaf claims).
type Shape = (Uuid, Option<Uuid>, i32, Option<BTreeSet<Uuid>>);

/// Done when: a rerun over unchanged input reproduces every links group id,
/// including the leaves W3's re-check made on the box.
#[sqlx::test(migrations = "../../migrations")]
async fn a_second_apply_reproduces_every_links_group_id(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let shape = |levels: Vec<Stored>| -> Vec<Shape> {
        levels
            .iter()
            .map(|s| (s.group_id, s.parent_group_id, s.level, leaf_claims(s)))
            .collect()
    };
    let r = links_result(&c);
    let first = run_id(&apply(&pool, &viewer, &c, &r).await.expect("first"));
    let second = run_id(&apply(&pool, &viewer, &c, &r).await.expect("second"));
    assert_ne!(first, second);
    let (x, y) = (
        shape(stored(&pool, first, "links").await),
        shape(stored(&pool, second, "links").await),
    );
    assert!(x.len() > 4, "the coarse leaf was split");
    assert_eq!(x, y);
}

/// A forged id, a links result whose themes are not the meaning result's, or
/// a link filed since the result was computed (two claims of a mirror now
/// linked) refuses the whole apply and writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn apply_refuses_a_forged_or_drifted_links_result(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let mut forged = links_result(&c);
    let g = &mut forged.themes[0].groups;
    let fake = Uuid::new_v4();
    let old = g[1].id;
    g[1].id = fake;
    g[0].children.as_mut().unwrap()[0] = fake;
    assert_eq!(g[0].children.as_ref().unwrap().len(), 3);
    assert_ne!(old, fake);
    let err = apply(&pool, &viewer, &c, &forged)
        .await
        .expect_err("forged")
        .to_string();
    assert!(err.contains("minted"), "{err}");

    let mut none = links_result(&c);
    none.themes.clear();
    let err = apply(&pool, &viewer, &c, &none)
        .await
        .expect_err("no theme")
        .to_string();
    assert!(err.contains("same themes"), "{err}");

    let r = links_result(&c);
    link(&pool, c.u2[0], "claim", c.u2[1], "refutes").await;
    let err = apply(&pool, &viewer, &c, &r)
        .await
        .expect_err("drifted")
        .to_string();
    assert!(err.contains("not the mirror"), "{err}");
    let runs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM atlas_map_runs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(runs, 0, "a refused apply wrote a run");
}

/// The binary checks its arguments before it connects.
#[test]
fn the_binary_refuses_a_bad_map_or_cap_before_connecting() {
    let bin = env!("CARGO_BIN_EXE_atlas_links");
    let dir = tmpdir();
    let cases: [(&[&str], &str); 4] = [
        (
            &[
                "export",
                "--map",
                "team:not-a-uuid",
                "--meaning-from",
                "m.json",
                "--out",
            ],
            "is not a uuid",
        ),
        (
            &[
                "export",
                "--map",
                "group:x",
                "--meaning-from",
                "m.json",
                "--out",
            ],
            "a map is `public`",
        ),
        (
            &[
                "export",
                "--map",
                "public",
                "--meaning-from",
                "m.json",
                "--cap",
                "101",
                "--out",
            ],
            "--cap must be 1 to 100",
        ),
        (
            &[
                "apply",
                "--map",
                "public",
                "--cap",
                "0",
                "--meaning-from",
                "m.json",
                "--from",
            ],
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
            .expect("run atlas_links");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{args:?} succeeded");
        assert!(stderr.contains(want), "{args:?}: {stderr}");
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// W5 finding #4 (fixed for W9): a deep meaning level's switch leads to the
/// links group it overlaps most (W5's Jaccard rule the other way round), not
/// to the links root; and every meaning switch names a served links level.
#[sqlx::test(migrations = "../../migrations")]
async fn meaning_levels_switch_to_their_best_links_group(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let map = c.map();
    let run = run_id(
        &apply(&pool, &viewer, &c, &links_result(&c))
            .await
            .expect("apply"),
    );
    let mut conn = pool.acquire().await.unwrap();
    let lroot = root_id(map, L, c.theme);
    let mut deep = 0;
    for s in stored(&pool, run, "meaning").await {
        let target: Uuid = serde_json::from_value(s.payload["switch"]["level_id"].clone()).unwrap();
        let served = AtlasMapRepository::level_for_viewer(&mut conn, &viewer, map, L, target)
            .await
            .unwrap();
        assert!(
            served.is_some(),
            "meaning level {} switches to an unserved {target}",
            s.group_id
        );
        if s.level > 0 {
            deep += 1;
            assert_ne!(
                target, lroot,
                "a deep meaning level switches to the links root"
            );
        }
    }
    assert!(
        deep >= 4,
        "the corpus has four meaning leaves under the root"
    );
    // The meaning leaf of the unlinked claims leads to the mirror that holds
    // exactly them.
    let mleaf = group_id(map, M, c.theme, &c.mirror2());
    let level = AtlasMapRepository::level_for_viewer(&mut conn, &viewer, map, M, mleaf)
        .await
        .unwrap()
        .expect("the meaning leaf is served");
    assert_eq!(
        level.payload["switch"]["level_id"],
        serde_json::json!(group_id(map, L, c.theme, &c.mirror2()))
    );
}

/// W4's hand-off guard (W9): a standalone meaning apply refuses while the
/// map's latest run holds the links hierarchy, which it would hide; its dry
/// run refuses too, and the served run is left as it was.
#[sqlx::test(migrations = "../../migrations")]
async fn a_meaning_only_apply_refuses_to_hide_a_links_run(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let map = c.map();
    let mut conn = pool.acquire().await.unwrap();
    // With no run yet, a meaning-only apply is allowed (dry run).
    epigraph_cli::atlas_meaning::build::apply_result(
        &mut conn,
        &viewer,
        map,
        &meaning_result(&c),
        CAP,
        false,
    )
    .await
    .expect("no links run to hide yet");
    let run = run_id(
        &apply(&pool, &viewer, &c, &links_result(&c))
            .await
            .expect("apply"),
    );
    for write in [false, true] {
        let err = epigraph_cli::atlas_meaning::build::apply_result(
            &mut conn,
            &viewer,
            map,
            &meaning_result(&c),
            CAP,
            write,
        )
        .await
        .expect_err("a meaning-only run would hide the links levels");
        assert!(format!("{err:#}").contains("links"), "{err:#}");
    }
    let latest: Uuid = sqlx::query_scalar(
        "SELECT id FROM atlas_map_runs WHERE finished_at IS NOT NULL \
          ORDER BY finished_at DESC, id DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(latest, run, "nothing was written");
}
