//! Atlas W6 (backlog f52fff97) through W2's storage (migration 210): every
//! level of a synthetic two-hierarchy map gets its positions, is stored with
//! the run's layout record, and reads back valid; the next run over the same
//! input lays out only the leaf that changed and keeps every other level's
//! stored positions.
//!
//! The hierarchy stands in for W4's and W5's output, which do not exist on
//! this branch: what the fill needs is only the W10a documents, so the test
//! builds those directly. Each hierarchy is a theme root with two group
//! children and one leaf, the groups holding two and three leaves, one leaf at
//! the 100-node cap.
//!
//! The build runs as the nightly will: documents assembled with placeholder
//! positions, `fill_positions`, then `write_run` with the layout record in its
//! `params`, `put_level` for each level, `finish_run`. Reads go through
//! `level_for_viewer` with a public viewer, on the public map.

use std::collections::BTreeMap;

use epigraph_atlas_contract::{
    parse_and_validate, Breadcrumb, Child, ChildKind, ClaimNode, Edge, FlowBasis, GroupLevel,
    Hierarchy, LeafLevel, LevelDocument, MapScope, Node, PlainNode, Switch, SCHEMA_VERSION,
};
use epigraph_cli::atlas_layout::fill::{fill_positions, LayoutRecord, PreviousRun};
use epigraph_cli::atlas_layout::force::{GROUP_FIT_RADIUS, LEAF_MIN_DISTANCE, LEAF_RADIUS};
use epigraph_db::repos::atlas_map::{AtlasHierarchy, AtlasMap, LevelDoc, NewMapRun};
use epigraph_db::{AtlasMapRepository, Viewer};
use sqlx::PgPool;
use uuid::Uuid;

/// Claims per leaf, by leaf index (the last leaf reaches the 100-node cap).
const LEAF_CLAIMS: [usize; 6] = [5, 16, 27, 38, 49, 66];

/// One stored level: its place in the tree and its document.
struct Level {
    parent: Option<Uuid>,
    doc: LevelDocument,
}

/// Deterministic ids: two maps built in the same order share every id.
struct Ids(u64);

impl Ids {
    fn next(&mut self) -> Uuid {
        self.0 += 1;
        Uuid::from_u64_pair(0xA71A_5006, self.0)
    }
}

fn hierarchy_tag(h: Hierarchy) -> AtlasHierarchy {
    match h {
        Hierarchy::Meaning => AtlasHierarchy::Meaning,
        Hierarchy::Links => AtlasHierarchy::Links,
    }
}

/// Where a leaf sits and what it holds.
#[derive(Clone, Copy)]
struct LeafSpec<'a> {
    hierarchy: Hierarchy,
    theme: Uuid,
    level_id: Uuid,
    switch_to: Uuid,
    crumbs: &'a [(Uuid, u8)],
    n_claims: usize,
    cut_first_link: bool,
}

/// A leaf of `n_claims` claims, one agent per five claims asserting them, one
/// evidence row per three claims backing one claim each, and a chain of
/// supports between consecutive claims plus a refutation every fourth claim.
/// `cut_first_link` drops the support from claim 0 to claim 1 (the only edge
/// between that pair).
fn leaf_doc(ids: &mut Ids, spec: &LeafSpec<'_>) -> LeafLevel {
    let LeafSpec {
        hierarchy,
        theme,
        level_id,
        switch_to,
        crumbs,
        n_claims,
        cut_first_link,
    } = *spec;
    let claims: Vec<Uuid> = (0..n_claims).map(|_| ids.next()).collect();
    let n_agents = n_claims.div_ceil(5);
    let agents: Vec<Uuid> = (0..n_agents).map(|_| ids.next()).collect();
    let n_evidence = (n_claims / 3).min(100 - n_claims - n_agents);
    let evidence: Vec<Uuid> = (0..n_evidence).map(|_| ids.next()).collect();

    let mut nodes: Vec<Node> = claims
        .iter()
        .enumerate()
        .map(|(i, id)| {
            Node::Claim(ClaimNode {
                id: *id,
                label: format!("synthetic claim {i}"),
                x: 0.0,
                y: 0.0,
                truth_value: Some(0.5),
            })
        })
        .collect();
    nodes.extend(agents.iter().enumerate().map(|(i, id)| {
        Node::Agent(PlainNode {
            id: *id,
            label: format!("synthetic agent {i}"),
            x: 0.0,
            y: 0.0,
        })
    }));
    nodes.extend(evidence.iter().enumerate().map(|(i, id)| {
        Node::Evidence(PlainNode {
            id: *id,
            label: format!("synthetic evidence {i}"),
            x: 0.0,
            y: 0.0,
        })
    }));

    let edge = |source: Uuid, target: Uuid, rel: &str, basis: FlowBasis, sign: i8| Edge {
        source,
        target,
        relationship: rel.to_string(),
        sign,
        flow_weight: if basis == FlowBasis::None { 0.0 } else { 0.4 },
        flow_basis: basis,
    };
    let mut edges = Vec::new();
    for i in 0..n_claims {
        edges.push(edge(
            agents[i / 5],
            claims[i],
            "asserts",
            FlowBasis::None,
            0,
        ));
        if i + 1 < n_claims && !(cut_first_link && i == 0) {
            edges.push(edge(
                claims[i],
                claims[i + 1],
                "supports",
                FlowBasis::Proxy,
                1,
            ));
        }
        if i % 4 == 0 && i + 3 < n_claims {
            edges.push(edge(
                claims[i],
                claims[i + 3],
                "refutes",
                FlowBasis::Proxy,
                -1,
            ));
        }
    }
    for (k, ev) in evidence.iter().enumerate() {
        edges.push(edge(*ev, claims[3 * k], "supports", FlowBasis::Exact, 1));
    }

    LeafLevel {
        schema_version: SCHEMA_VERSION,
        map_scope: MapScope::Public,
        map_group_id: None,
        hierarchy,
        theme_id: theme,
        run_id: Uuid::nil(),
        level_id,
        depth: crumbs.len() as u8,
        name: Some(format!("synthetic leaf {level_id}")),
        needs_naming: false,
        breadcrumbs: crumbs
            .iter()
            .map(|(id, d)| Breadcrumb {
                level_id: *id,
                name: Some("synthetic group".into()),
                depth: *d,
            })
            .collect(),
        switch: Switch {
            hierarchy: hierarchy.other(),
            level_id: switch_to,
        },
        nodes,
        edges,
        outgoing: vec![],
    }
}

/// A group level over `children` (id, kind, claims under it), each sibling
/// bundled to the next.
fn group_doc(
    hierarchy: Hierarchy,
    theme: Uuid,
    level_id: Uuid,
    switch_to: Uuid,
    crumbs: &[(Uuid, u8)],
    children: &[(Uuid, ChildKind, usize)],
) -> GroupLevel {
    GroupLevel {
        schema_version: SCHEMA_VERSION,
        map_scope: MapScope::Public,
        map_group_id: None,
        hierarchy,
        theme_id: theme,
        run_id: Uuid::nil(),
        level_id,
        depth: crumbs.len() as u8,
        name: Some(format!("synthetic group {level_id}")),
        needs_naming: false,
        breadcrumbs: crumbs
            .iter()
            .map(|(id, d)| Breadcrumb {
                level_id: *id,
                name: Some("synthetic group".into()),
                depth: *d,
            })
            .collect(),
        switch: Switch {
            hierarchy: hierarchy.other(),
            level_id: switch_to,
        },
        children: children
            .iter()
            .map(|(id, kind, claims)| Child {
                id: *id,
                kind: *kind,
                name: Some("synthetic child".into()),
                needs_naming: false,
                claim_count: *claims as u32,
                x: 0.0,
                y: 0.0,
                r: 0.5,
            })
            .collect(),
        bundles: children
            .windows(2)
            .enumerate()
            .map(|(i, w)| epigraph_atlas_contract::Bundle {
                source: w[0].0,
                target: w[1].0,
                count: 3 + i as u32,
                net_sign: 1,
            })
            .collect(),
        targets: vec![],
    }
}

/// Both hierarchies of one theme: per hierarchy a root, two groups and six
/// leaves, every position at a placeholder. `cut` names a (hierarchy, leaf
/// index) whose first claim link is dropped.
fn synthetic_map(theme: Uuid, cut: Option<(Hierarchy, usize)>) -> Vec<Level> {
    let mut ids = Ids(0);
    let roots: BTreeMap<Hierarchy, Uuid> = [Hierarchy::Meaning, Hierarchy::Links]
        .into_iter()
        .map(|h| (h, ids.next()))
        .collect();
    let mut out = Vec::new();
    for h in [Hierarchy::Meaning, Hierarchy::Links] {
        let root = roots[&h];
        let other = roots[&h.other()];
        let (g1, g2) = (ids.next(), ids.next());
        let leaves: Vec<Uuid> = (0..6).map(|_| ids.next()).collect();
        let leaf = |ids: &mut Ids, i: usize, crumbs: &[(Uuid, u8)], parent: Uuid| Level {
            parent: Some(parent),
            doc: LevelDocument::Leaf(leaf_doc(
                ids,
                &LeafSpec {
                    hierarchy: h,
                    theme,
                    level_id: leaves[i],
                    switch_to: other,
                    crumbs,
                    n_claims: LEAF_CLAIMS[i],
                    cut_first_link: cut == Some((h, i)),
                },
            )),
        };
        // Leaf 0 sits under the root; 1..=3 under g1, 4..=5 under g2.
        out.push(leaf(&mut ids, 0, &[(root, 0)], root));
        for i in 1..=3 {
            out.push(leaf(&mut ids, i, &[(root, 0), (g1, 1)], g1));
        }
        for i in 4..=5 {
            out.push(leaf(&mut ids, i, &[(root, 0), (g2, 1)], g2));
        }
        let sum = |r: std::ops::RangeInclusive<usize>| r.map(|i| LEAF_CLAIMS[i]).sum::<usize>();
        out.push(Level {
            parent: Some(root),
            doc: LevelDocument::Group(group_doc(
                h,
                theme,
                g1,
                other,
                &[(root, 0)],
                &(1..=3)
                    .map(|i| (leaves[i], ChildKind::Leaf, LEAF_CLAIMS[i]))
                    .collect::<Vec<_>>(),
            )),
        });
        out.push(Level {
            parent: Some(root),
            doc: LevelDocument::Group(group_doc(
                h,
                theme,
                g2,
                other,
                &[(root, 0)],
                &(4..=5)
                    .map(|i| (leaves[i], ChildKind::Leaf, LEAF_CLAIMS[i]))
                    .collect::<Vec<_>>(),
            )),
        });
        out.push(Level {
            parent: None,
            doc: LevelDocument::Group(group_doc(
                h,
                theme,
                root,
                other,
                &[],
                &[
                    (g1, ChildKind::Group, sum(1..=3)),
                    (g2, ChildKind::Group, sum(4..=5)),
                    (leaves[0], ChildKind::Leaf, LEAF_CLAIMS[0]),
                ],
            )),
        });
    }
    out
}

fn hierarchy_of(doc: &LevelDocument) -> Hierarchy {
    match doc {
        LevelDocument::Group(g) => g.hierarchy,
        LevelDocument::Leaf(l) => l.hierarchy,
    }
}

async fn seed_theme(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("INSERT INTO claim_themes (label) VALUES ('atlas w6 theme') RETURNING id")
        .fetch_one(pool)
        .await
        .expect("seed theme")
}

/// Fill `levels` (against `previous`), then write them as one finished run
/// of the public map with the layout record in its params, as the nightly
/// will. Returns the run id and what the fill did.
async fn build_run(
    pool: &PgPool,
    levels: &mut [Level],
    previous: Option<&PreviousRun>,
) -> (Uuid, epigraph_cli::atlas_layout::fill::FillReport) {
    let mut docs: Vec<LevelDocument> = levels.iter().map(|l| l.doc.clone()).collect();
    let report = fill_positions(&mut docs, previous).expect("fill");
    for (l, d) in levels.iter_mut().zip(docs) {
        l.doc = d;
    }

    let viewer = Viewer::resolve(pool, Uuid::nil()).await.expect("viewer");
    let mut conn = pool.begin().await.expect("begin the build");
    let epochs = AtlasMapRepository::begin_build_snapshot(&mut conn, &viewer, AtlasMap::Public)
        .await
        .expect("begin_build_snapshot");
    let mut params = serde_json::json!({"synthetic": true});
    report.record.write_into(&mut params).expect("params");
    let run = AtlasMapRepository::write_run(
        &mut conn,
        &NewMapRun {
            map: AtlasMap::Public,
            algo: "atlas-w6-test".into(),
            params,
            epochs,
        },
    )
    .await
    .expect("write_run");
    for l in levels.iter_mut() {
        match &mut l.doc {
            LevelDocument::Group(g) => g.run_id = run,
            LevelDocument::Leaf(f) => f.run_id = run,
        }
        let body = l.doc.to_stored_json().unwrap_or_else(|v| panic!("{v}"));
        let (theme_id, depth) = match &l.doc {
            LevelDocument::Group(g) => (g.theme_id, g.depth),
            LevelDocument::Leaf(f) => (f.theme_id, f.depth),
        };
        AtlasMapRepository::put_level(
            &mut conn,
            run,
            &LevelDoc {
                hierarchy: hierarchy_tag(hierarchy_of(&l.doc)),
                group_id: l.doc.level_id(),
                parent_group_id: l.parent,
                theme_id,
                level: i32::from(depth),
                schema_version: SCHEMA_VERSION as i32,
                payload: serde_json::from_slice(&body).expect("stored json"),
            },
        )
        .await
        .expect("put_level");
    }
    AtlasMapRepository::finish_run(&mut conn, run)
        .await
        .expect("finish_run");
    conn.commit().await.expect("commit the build");
    (run, report)
}

/// Every level of the latest finished public run, read back as served and
/// validated, keyed by (hierarchy, group id).
async fn read_back(
    pool: &PgPool,
    run: Uuid,
    levels: &[Level],
) -> BTreeMap<(Hierarchy, Uuid), (serde_json::Value, LevelDocument)> {
    let viewer = Viewer::resolve(pool, Uuid::nil()).await.expect("viewer");
    let mut conn = pool.acquire().await.expect("acquire");
    let mut out = BTreeMap::new();
    for l in levels {
        let h = hierarchy_of(&l.doc);
        let stored = AtlasMapRepository::level_for_viewer(
            &mut conn,
            &viewer,
            AtlasMap::Public,
            hierarchy_tag(h),
            l.doc.level_id(),
        )
        .await
        .expect("level_for_viewer")
        .unwrap_or_else(|| panic!("level {} is not stored", l.doc.level_id()));
        assert_eq!(stored.run_id, run, "the latest finished run is served");
        let body = serde_json::to_vec(&stored.payload).unwrap();
        let doc = parse_and_validate(&body).unwrap_or_else(|v| panic!("stored level: {v}"));
        out.insert((h, l.doc.level_id()), (stored.payload, doc));
    }
    out
}

async fn run_params(pool: &PgPool, run: Uuid) -> serde_json::Value {
    sqlx::query_scalar("SELECT params FROM atlas_map_runs WHERE id = $1")
        .bind(run)
        .fetch_one(pool)
        .await
        .expect("run params")
}

fn dist(a: (f64, f64), b: (f64, f64)) -> f64 {
    ((a.0 - b.0) * (a.0 - b.0) + (a.1 - b.1) * (a.1 - b.1)).sqrt()
}

fn xy(n: &Node) -> (f64, f64) {
    match n {
        Node::Claim(c) => (c.x, c.y),
        Node::Agent(p) | Node::Evidence(p) => (p.x, p.y),
    }
}

/// Every position of a document, by node or child id.
fn positions(doc: &LevelDocument) -> BTreeMap<Uuid, (f64, f64, f64)> {
    match doc {
        LevelDocument::Leaf(l) => l
            .nodes
            .iter()
            .map(|n| {
                let (x, y) = xy(n);
                (n.id(), (x, y, 0.0))
            })
            .collect(),
        LevelDocument::Group(g) => g.children.iter().map(|c| (c.id, (c.x, c.y, c.r))).collect(),
    }
}

/// The layout bounds on one stored document: leaf nodes apart and inside the
/// leaf disc, group circles apart and inside the fit disc.
fn assert_laid_out(doc: &LevelDocument) {
    match doc {
        LevelDocument::Leaf(l) => {
            for (i, a) in l.nodes.iter().enumerate() {
                assert!(dist(xy(a), (0.0, 0.0)) <= LEAF_RADIUS, "{} outside", a.id());
                for b in &l.nodes[i + 1..] {
                    let d = dist(xy(a), xy(b));
                    assert!(
                        d >= LEAF_MIN_DISTANCE,
                        "leaf {}: {} and {} are {d} apart",
                        l.level_id,
                        a.id(),
                        b.id()
                    );
                }
            }
        }
        LevelDocument::Group(g) => {
            for (i, a) in g.children.iter().enumerate() {
                assert!(dist((a.x, a.y), (0.0, 0.0)) + a.r <= GROUP_FIT_RADIUS);
                for b in &g.children[i + 1..] {
                    assert!(dist((a.x, a.y), (b.x, b.y)) >= a.r + b.r, "overlap");
                }
            }
        }
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn every_level_of_a_synthetic_hierarchy_is_stored_with_valid_positions(pool: PgPool) {
    let theme = seed_theme(&pool).await;
    let mut levels = synthetic_map(theme, None);
    assert_eq!(levels.len(), 18);
    let (run, report) = build_run(&pool, &mut levels, None).await;
    assert_eq!((report.computed, report.reused), (18, 0));

    let stored = read_back(&pool, run, &levels).await;
    assert_eq!(stored.len(), 18);
    let leaves = stored
        .values()
        .filter(|(_, d)| matches!(d, LevelDocument::Leaf(_)))
        .count();
    assert_eq!(leaves, 12, "every leaf of both hierarchies is stored");
    let mut full = 0;
    for (_, doc) in stored.values() {
        assert_laid_out(doc);
        if let LevelDocument::Leaf(l) = doc {
            full += usize::from(l.nodes.len() == 100);
        }
    }
    assert_eq!(full, 2, "one leaf per hierarchy sits at the 100-node cap");

    // The record went through jsonb unchanged, beside the run's other params.
    let params = run_params(&pool, run).await;
    assert_eq!(params["synthetic"], true);
    assert_eq!(LayoutRecord::from_params(&params), Some(report.record));
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_rerun_lays_out_only_the_changed_leaf_and_keeps_every_other_stored_position(
    pool: PgPool,
) {
    let theme = seed_theme(&pool).await;
    let mut first = synthetic_map(theme, None);
    let (run1, _) = build_run(&pool, &mut first, None).await;
    let stored1 = read_back(&pool, run1, &first).await;

    // The next night: the previous run's params and stored documents, and the
    // same map with one link gone from one leaf.
    let previous = PreviousRun::new(
        &run_params(&pool, run1).await,
        stored1.values().map(|(payload, _)| payload.clone()),
    );
    let changed = (Hierarchy::Links, 3);
    let mut second = synthetic_map(theme, Some(changed));
    let (run2, report) = build_run(&pool, &mut second, Some(&previous)).await;
    assert_ne!(run2, run1);
    assert_eq!(
        (report.computed, report.reused),
        (1, 17),
        "only the changed leaf is laid out again"
    );

    let stored2 = read_back(&pool, run2, &second).await;
    // The two maps share every id; the changed leaf is the one whose edges
    // differ.
    let changed_ids: Vec<Uuid> = first
        .iter()
        .zip(&second)
        .filter(|(a, b)| {
            assert_eq!(a.doc.level_id(), b.doc.level_id());
            match (&a.doc, &b.doc) {
                (LevelDocument::Leaf(x), LevelDocument::Leaf(y)) => x.edges.len() != y.edges.len(),
                _ => false,
            }
        })
        .map(|(a, _)| a.doc.level_id())
        .collect();
    assert_eq!(changed_ids.len(), 1);
    let changed_id = changed_ids[0];
    for (key, (_, doc)) in &stored2 {
        let (_, was) = &stored1[key];
        if key.1 == changed_id {
            assert_ne!(positions(doc), positions(was), "the changed leaf moved");
            assert_laid_out(doc);
        } else {
            assert_eq!(
                positions(doc),
                positions(was),
                "level {key:?} kept its positions"
            );
        }
    }
}
