//! One night of the Atlas refresh: the theme assignment, then each map's
//! incremental run (see the module documentation of [`super`]).

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{ensure, Context};
use epigraph_atlas_contract::{Hierarchy, LevelDocument, SCHEMA_VERSION};
use epigraph_db::repos::atlas_leaf::{
    assemble_leaf, AtlasLeafRepository, LeafNodeKind, LeafOutcome,
};
use epigraph_db::repos::atlas_map::{AtlasHierarchy, AtlasMap, LevelDoc, MapEpochs, NewMapRun};
use epigraph_db::repos::atlas_naming::{FinishedRun, RunLevel};
use epigraph_db::{
    AtlasFlowRepository, AtlasMapRepository, AtlasMeaningRepository, AtlasNamingRepository,
    ClaimThemeRepository, Viewer,
};
use epigraph_engine::atlas_flow::weigh_leaf_edges;
use serde_json::{json, Value};
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use super::incremental::{to_wire, update_links, update_meaning, Shape};
use super::leaves::{fill_leaf, leaf_claims, leaf_shape, node_set};
use super::links::{fill_cross_links, LinksReport};
use super::previous::{by_theme, prev_tree};
use crate::atlas_layout::fill::{fill_positions, LayoutRecord, PreviousRun};
use crate::atlas_links::graph::{
    check_mirrors, counted_links, linked_claims, meaning_leaf_of, switch_targets,
};
use crate::atlas_meaning::docs::level_documents_with_switch;
use crate::atlas_meaning::tree::{check_tree, map_key, resolve_tree, MeaningTree, NodeBody};
use crate::atlas_naming::backend::NameBackend;
use crate::atlas_naming::build::{read_member_texts, read_previous};
use crate::atlas_naming::name::{name_levels, plan_samples, NamingOptions, NamingRecord};

/// The `atlas_map_runs.algo` of a nightly run.
pub const NIGHTLY_ALGO: &str = "atlas-nightly/1";

/// The run `params` key recording the links tree's mirror leaves, which the
/// next night reads back ([`update_links`]'s `prev_mirrors`).
pub const MIRRORS_KEY: &str = "mirrors";

/// What one night was asked for.
#[derive(Debug, Clone)]
pub struct NightOptions {
    /// Only these maps; every map with a finished run when `None`.
    pub maps: Option<Vec<AtlasMap>>,
    /// Assign themes, call the model and write runs. Without it nothing is
    /// written and no model is called.
    pub apply: bool,
    /// W3's leaf node cap.
    pub cap: usize,
    /// W1's theme member cap: themes over it are reported, not split.
    pub theme_cap: i64,
    /// Finished runs kept per map by the prune.
    pub keep_runs: usize,
    /// The model call budget of each map.
    pub max_calls: Option<usize>,
    /// Claims per theme-assignment statement.
    pub assign_batch: i64,
}

impl Default for NightOptions {
    fn default() -> Self {
        Self {
            maps: None,
            apply: false,
            cap: epigraph_db::repos::atlas_leaf::ATLAS_LEAF_NODE_CAP,
            theme_cap: 2_000,
            keep_runs: 3,
            max_calls: None,
            assign_batch: 2_000,
        }
    }
}

/// The night's work for one theme that built.
struct BuiltTheme {
    docs: Vec<LevelDocument>,
    mirrors: Vec<Uuid>,
    stats: Value,
}

enum ThemeOutcome {
    Built(BuiltTheme),
    /// A theme new to the map that does not fit one leaf: an operator build.
    Unbuilt(usize),
}

fn db_hierarchy(h: Hierarchy) -> AtlasHierarchy {
    match h {
        Hierarchy::Meaning => AtlasHierarchy::Meaning,
        Hierarchy::Links => AtlasHierarchy::Links,
    }
}

fn doc_key(doc: &LevelDocument) -> (Hierarchy, Uuid) {
    match doc {
        LevelDocument::Group(g) => (g.hierarchy, g.level_id),
        LevelDocument::Leaf(l) => (l.hierarchy, l.level_id),
    }
}

fn set_run_id(doc: &mut LevelDocument, run_id: Uuid) {
    match doc {
        LevelDocument::Group(g) => g.run_id = run_id,
        LevelDocument::Leaf(l) => l.run_id = run_id,
    }
}

fn record_key((h, id): (Hierarchy, Uuid)) -> String {
    crate::atlas_layout::fill::level_key(h, id)
}

/// The documents of `tree` with each level's switch from `switch`, parsed
/// back into contract documents.
fn tree_documents(
    tree: &MeaningTree,
    labels: &BTreeMap<Uuid, String>,
    switch: &BTreeMap<Uuid, Uuid>,
) -> anyhow::Result<Vec<LevelDocument>> {
    level_documents_with_switch(tree, Uuid::nil(), labels, &|n| {
        switch
            .get(&n.id)
            .copied()
            .with_context(|| format!("level {} has no switch target", n.id))
    })?
    .into_iter()
    .map(|d| serde_json::from_value(d.payload).context("a built document does not parse"))
    .collect()
}

/// Make every leaf of `docs` real: W3's node set, W7's weighted edges, the
/// agent and evidence labels; then check every document against the
/// contract (a leaf over the edge cap fails here).
async fn real_leaves(
    tx: &mut PgConnection,
    viewer: &Viewer,
    map: AtlasMap,
    rows: &epigraph_db::repos::atlas_leaf::LeafRows,
    docs: &mut [LevelDocument],
    cap: usize,
) -> anyhow::Result<()> {
    let mut sets = Vec::new();
    for doc in docs.iter() {
        if let LevelDocument::Leaf(l) = doc {
            sets.push(Some(node_set(rows, &leaf_claims(l), cap)?));
        } else {
            sets.push(None);
        }
    }
    let mut agents = BTreeSet::new();
    let mut evidence = BTreeSet::new();
    for set in sets.iter().flatten() {
        for n in &set.nodes {
            match n.kind {
                LeafNodeKind::Agent => agents.insert(n.id),
                LeafNodeKind::Evidence => evidence.insert(n.id),
                LeafNodeKind::Claim => false,
            };
        }
    }
    let agents: Vec<Uuid> = agents.into_iter().collect();
    let evidence: Vec<Uuid> = evidence.into_iter().collect();
    let (agent_labels, evidence_labels) =
        AtlasLeafRepository::node_labels(tx, viewer, map, &agents, &evidence).await?;
    for (doc, set) in docs.iter_mut().zip(&sets) {
        if let (LevelDocument::Leaf(l), Some(set)) = (doc, set) {
            let inputs = AtlasFlowRepository::read_flow_inputs(tx, viewer, map, set).await?;
            fill_leaf(l, set, &inputs, &agent_labels, &evidence_labels)?;
        }
    }
    for doc in docs.iter() {
        doc.to_stored_json()
            .map_err(|v| anyhow::anyhow!("level {} breaks the contract: {v}", doc.level_id()))?;
    }
    Ok(())
}

/// One theme's night, on the build's snapshot (the caller runs it inside a
/// savepoint). `prev_rows` are the theme's levels in the previous run and
/// `prev_mirrors` that run's mirror record.
#[allow(clippy::too_many_lines)]
async fn build_theme(
    tx: &mut PgConnection,
    viewer: &Viewer,
    map: AtlasMap,
    theme: Uuid,
    prev_rows: &[&RunLevel],
    prev_mirrors: Option<&BTreeSet<Uuid>>,
    cap: usize,
) -> anyhow::Result<ThemeOutcome> {
    let members = AtlasMeaningRepository::theme_members(tx, viewer, map, theme).await?;
    let mut emb: BTreeMap<Uuid, Vec<f32>> = BTreeMap::new();
    for (id, text) in &members.embedded {
        let v = epigraph_embeddings::Normalizer::parse_pgvector(text)
            .with_context(|| format!("claim {id} has an unreadable embedding"))?;
        emb.insert(*id, v);
    }
    let ids: Vec<Uuid> = emb.keys().copied().collect();
    let member_set: BTreeSet<Uuid> = ids.iter().copied().collect();
    let rows = AtlasLeafRepository::read_leaf_rows(tx, viewer, map, &ids).await?;
    let fits = |part: &[Uuid]| matches!(assemble_leaf(&rows, part, cap), Ok(LeafOutcome::Fits(_)));
    let fits_one = fits(&ids);
    let prev_m = prev_tree(prev_rows, AtlasHierarchy::Meaning)?;
    let prev_l = prev_tree(prev_rows, AtlasHierarchy::Links)?;

    let (meaning_shape, added, removed) = if fits_one {
        let before = prev_m
            .as_ref()
            .map(super::previous::PrevTree::claims)
            .unwrap_or_default();
        (
            Shape::Leaf(ids.clone()),
            member_set.difference(&before).count(),
            before.difference(&member_set).count(),
        )
    } else {
        let Some(p) = prev_m.as_ref() else {
            return Ok(ThemeOutcome::Unbuilt(ids.len()));
        };
        let (shape, delta) = update_meaning(p, &emb);
        (
            shape.context("the theme has no member")?,
            delta.added,
            delta.removed,
        )
    };
    let wire = to_wire(map, AtlasHierarchy::Meaning, theme, &meaning_shape);
    let m_tree = check_tree(map, AtlasHierarchy::Meaning, theme, &wire, &member_set)?;
    let (m_tree, m_stats) = resolve_tree(&m_tree, &rows, cap)?;

    let links = counted_links(&rows, &member_set);
    let linked = linked_claims(&links);
    let (links_shape, l_delta) = if fits_one {
        (
            Shape::Leaf(ids.clone()),
            super::incremental::LinksDelta::default(),
        )
    } else {
        let (shape, d) = update_links(
            prev_l.as_ref(),
            prev_mirrors,
            &m_tree,
            &linked,
            &links,
            &fits,
        );
        (shape.context("the theme has no member")?, d)
    };
    let wire = to_wire(map, AtlasHierarchy::Links, theme, &links_shape);
    let l_tree = check_tree(map, AtlasHierarchy::Links, theme, &wire, &member_set)?;
    let (l_tree, l_stats) = resolve_tree(&l_tree, &rows, cap)?;
    let mirror_count = check_mirrors(&l_tree, &linked, &meaning_leaf_of(&m_tree))?;
    let mirrors: Vec<Uuid> = l_tree
        .leaves()
        .filter(|(n, claims)| {
            l_tree.nodes.len() > 1
                && n.parent.is_some()
                && claims.iter().any(|c| !linked.contains(c))
        })
        .map(|(n, _)| n.id)
        .collect();

    // Switches both ways by W5's Jaccard rule: a deep meaning level leads to
    // its best links group, not the links root (W5 finding #4).
    let m_switch = switch_targets(&m_tree, &l_tree)?;
    let l_switch = switch_targets(&l_tree, &m_tree)?;
    let labels = AtlasMeaningRepository::claim_labels(tx, viewer, map, &ids).await?;
    let mut docs = tree_documents(&m_tree, &labels, &m_switch)?;
    docs.extend(tree_documents(&l_tree, &labels, &l_switch)?);
    real_leaves(tx, viewer, map, &rows, &mut docs, cap).await?;

    let inner = |t: &MeaningTree| {
        t.nodes
            .iter()
            .filter(|n| matches!(n.body, NodeBody::Group(_)))
            .count()
    };
    Ok(ThemeOutcome::Built(BuiltTheme {
        docs,
        mirrors,
        stats: json!({
            "members": ids.len(),
            "unembedded": members.unembedded,
            "added": added,
            "removed": removed,
            "meaning": {"leaves": m_stats.leaves, "inner": inner(&m_tree),
                        "resplit_leaves": m_stats.resplit_leaves},
            "links": {"leaves": l_stats.leaves, "inner": inner(&l_tree),
                      "resplit_leaves": l_stats.resplit_leaves, "linked": linked.len(),
                      "mirrors": mirror_count, "joined": l_delta.joined,
                      "new_link_leaves": l_delta.new_link_leaves,
                      "new_mirrors": l_delta.new_mirrors},
        }),
    }))
}

/// The previous run's documents of one theme, carried into this run when
/// the theme's update failed: both hierarchies (so every switch resolves),
/// and only if every node and every `(source, target, relationship)` of
/// every carried leaf is still in that leaf re-assembled from the rows the
/// map may draw NOW. That is the leak control: a claim, agent, evidence row
/// or edge that left the map's audience is never carried. It is a subset
/// check, not equality, so the skeleton leaves of an operator build (claims
/// only, no edges) carry on the first night too; what arrived since is
/// simply not in the carried levels.
async fn carry_theme(
    tx: &mut PgConnection,
    viewer: &Viewer,
    map: AtlasMap,
    prev_rows: &[&RunLevel],
    cap: usize,
) -> anyhow::Result<Vec<LevelDocument>> {
    let mut docs: Vec<LevelDocument> = Vec::with_capacity(prev_rows.len());
    for r in prev_rows {
        ensure!(
            u32::try_from(r.schema_version).ok() == Some(SCHEMA_VERSION),
            "level {} is schema version {}",
            r.group_id,
            r.schema_version
        );
        docs.push(serde_json::from_value(r.payload.clone()).context("a stored level")?);
    }
    let hierarchies: BTreeSet<Hierarchy> = docs.iter().map(|d| doc_key(d).0).collect();
    ensure!(
        hierarchies.len() == 2,
        "the previous run holds one hierarchy of this theme"
    );
    let mut claims = BTreeSet::new();
    for d in &docs {
        if let LevelDocument::Leaf(l) = d {
            claims.extend(leaf_claims(l));
        }
    }
    let claims: Vec<Uuid> = claims.into_iter().collect();
    let rows = AtlasLeafRepository::read_leaf_rows(tx, viewer, map, &claims).await?;
    for d in &docs {
        let LevelDocument::Leaf(l) = d else { continue };
        let set = node_set(&rows, &leaf_claims(l), cap)
            .with_context(|| format!("leaf {} no longer assembles", l.level_id))?;
        let inputs = AtlasFlowRepository::read_flow_inputs(tx, viewer, map, &set).await?;
        let fresh_nodes: BTreeSet<Uuid> = set.nodes.iter().map(|n| n.id).collect();
        let fresh_edges: BTreeSet<(Uuid, Uuid, String)> = weigh_leaf_edges(&set, &inputs)
            .into_iter()
            .map(|e| (e.source, e.target, e.relationship))
            .collect();
        let (nodes, edges) = leaf_shape(l);
        ensure!(
            nodes.is_subset(&fresh_nodes) && edges.is_subset(&fresh_edges),
            "leaf {} holds a node or an edge the map may no longer draw",
            l.level_id
        );
    }
    Ok(docs)
}

/// The stored row of `doc`.
fn level_doc(doc: &LevelDocument) -> anyhow::Result<LevelDoc> {
    let (h, id, theme, depth, parent) = match doc {
        LevelDocument::Group(g) => (
            g.hierarchy,
            g.level_id,
            g.theme_id,
            g.depth,
            g.breadcrumbs.last().map(|b| b.level_id),
        ),
        LevelDocument::Leaf(l) => (
            l.hierarchy,
            l.level_id,
            l.theme_id,
            l.depth,
            l.breadcrumbs.last().map(|b| b.level_id),
        ),
    };
    let body = doc
        .to_stored_json()
        .map_err(|v| anyhow::anyhow!("level {id} breaks the contract: {v}"))?;
    Ok(LevelDoc {
        hierarchy: db_hierarchy(h),
        group_id: id,
        parent_group_id: parent,
        theme_id: theme,
        level: i32::from(depth),
        schema_version: i32::try_from(SCHEMA_VERSION)?,
        payload: serde_json::from_slice(&body)?,
    })
}

/// What one map's snapshot read produced.
struct MapBuild {
    prev: FinishedRun,
    prev_docs: BTreeMap<(Hierarchy, Uuid), LevelDocument>,
    prev_payloads: Vec<Value>,
    epochs: MapEpochs,
    docs: Vec<LevelDocument>,
    mirrors: Vec<Uuid>,
    themes: Value,
    unembedded: i64,
    links: LinksReport,
    texts: BTreeMap<Uuid, String>,
    names: crate::atlas_naming::name::Previous,
}

#[allow(clippy::too_many_lines)]
async fn read_and_build(
    conn: &mut PgConnection,
    viewer: &Viewer,
    map: AtlasMap,
    cap: usize,
) -> anyhow::Result<Option<MapBuild>> {
    let mut tx = conn.begin().await.context("begin the build snapshot")?;
    let epochs = AtlasMapRepository::begin_build_snapshot(&mut tx, viewer, map).await?;
    let Some(prev) =
        AtlasNamingRepository::latest_finished_run(&mut tx, viewer, map, false).await?
    else {
        tx.rollback().await.ok();
        return Ok(None);
    };
    let levels = AtlasNamingRepository::run_levels(&mut tx, viewer, map, prev.id).await?;
    let mut prev_docs = BTreeMap::new();
    let mut prev_payloads = Vec::with_capacity(levels.len());
    for l in &levels {
        ensure!(
            u32::try_from(l.schema_version).ok() == Some(SCHEMA_VERSION),
            "run {} holds a level of schema version {}; this nightly reads version {SCHEMA_VERSION}",
            prev.id,
            l.schema_version
        );
        let doc: LevelDocument =
            serde_json::from_value(l.payload.clone()).context("a stored level does not parse")?;
        prev_docs.insert(doc_key(&doc), doc);
        prev_payloads.push(l.payload.clone());
    }
    let prev_mirrors: Option<BTreeSet<Uuid>> = prev
        .params
        .get(MIRRORS_KEY)
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .context("params.mirrors is not a list of ids")?;
    let prev_by_theme = by_theme(&levels);
    let themes = AtlasMeaningRepository::embedded_theme_ids_on_map(&mut tx, viewer, map).await?;

    let mut docs = Vec::new();
    let mut mirrors = Vec::new();
    let (mut built, mut carried, mut dropped, mut unbuilt) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let empty: Vec<&RunLevel> = Vec::new();
    for theme in themes {
        let rows = prev_by_theme.get(&theme).unwrap_or(&empty);
        let mut sp = tx.begin().await.context("begin a theme savepoint")?;
        let outcome = build_theme(
            &mut sp,
            viewer,
            map,
            theme,
            rows,
            prev_mirrors.as_ref(),
            cap,
        )
        .await;
        match outcome {
            Ok(ThemeOutcome::Built(b)) => {
                sp.commit().await.context("release a theme savepoint")?;
                docs.extend(b.docs);
                mirrors.extend(b.mirrors);
                built.push(json!({"theme_id": theme, "stats": b.stats}));
            }
            Ok(ThemeOutcome::Unbuilt(n)) => {
                sp.rollback().await.context("roll back a theme savepoint")?;
                unbuilt.push(json!({"theme_id": theme, "members": n,
                    "reason": "new to the map and over one leaf: build it with atlas_meaning \
                               and atlas_links (operator)"}));
            }
            Err(e) => {
                sp.rollback().await.context("roll back a theme savepoint")?;
                let error = format!("{e:#}");
                let mut sp = tx.begin().await.context("begin a carry savepoint")?;
                match carry_theme(&mut sp, viewer, map, rows, cap).await {
                    Ok(kept) => {
                        sp.commit().await.context("release a carry savepoint")?;
                        let ids: BTreeSet<(Hierarchy, Uuid)> = kept.iter().map(doc_key).collect();
                        if let Some(pm) = &prev_mirrors {
                            mirrors.extend(
                                pm.iter().filter(|m| ids.contains(&(Hierarchy::Links, **m))),
                            );
                        }
                        docs.extend(kept);
                        carried.push(json!({"theme_id": theme, "error": error}));
                    }
                    Err(why) => {
                        sp.rollback().await.context("roll back a carry savepoint")?;
                        dropped.push(json!({"theme_id": theme, "error": error,
                                            "not_carried": format!("{why:#}")}));
                    }
                }
            }
        }
    }
    // The cross-group links, once every theme is final (built or carried)
    // and before the layout, which pulls linked children together from the
    // sibling bundles. Recomputed for every level from the snapshot's edges:
    // a carried level's targets may name a group whose id has changed, and
    // its counts must follow the map's edge rule as it stands now. The
    // result is deterministic, so only levels a changed link or group passes
    // through change.
    let drawn: Vec<Uuid> = docs
        .iter()
        .filter_map(|d| match d {
            LevelDocument::Leaf(l) => Some(leaf_claims(l)),
            LevelDocument::Group(_) => None,
        })
        .flatten()
        .collect::<BTreeSet<Uuid>>()
        .into_iter()
        .collect();
    let raw = AtlasLeafRepository::map_claim_links(&mut tx, viewer, map, &drawn).await?;
    let links = fill_cross_links(&mut docs, &raw)?;
    // Every theme's, also one with no embedded member (no tree, so not in
    // `themes` above) and one carried, dropped or unbuilt.
    let unembedded =
        AtlasMeaningRepository::unembedded_members_on_map(&mut tx, viewer, map).await?;
    let plan = plan_samples(&docs)?;
    let texts = read_member_texts(&mut tx, viewer, map, &plan).await?;
    let names = read_previous(&mut tx, viewer, map).await?;
    tx.rollback().await.context("end the build snapshot")?;
    Ok(Some(MapBuild {
        prev,
        prev_docs,
        prev_payloads,
        epochs,
        docs,
        mirrors,
        themes: json!({"built": built, "carried": carried, "dropped": dropped, "unbuilt": unbuilt}),
        unembedded,
        links,
        texts,
        names,
    }))
}

/// One map's night (see the module documentation of [`super`]). Returns the
/// map's report.
///
/// # Errors
/// A database error, a previous run the nightly cannot read, or a write the
/// contract refuses. A theme that fails is NOT an error (it is carried or
/// dropped and reported).
#[allow(clippy::too_many_lines)]
pub async fn night_for_map(
    conn: &mut PgConnection,
    viewer: &Viewer,
    backend: &dyn NameBackend,
    map: AtlasMap,
    opts: &NightOptions,
) -> anyhow::Result<Value> {
    let Some(b) = read_and_build(conn, viewer, map, opts.cap).await? else {
        return Ok(json!({"map": map_key(map), "status": "skipped",
            "reason": "no finished run: build the map with atlas_meaning and atlas_links first"}));
    };
    let MapBuild {
        prev,
        prev_docs,
        prev_payloads,
        epochs,
        mut docs,
        mirrors,
        themes,
        unembedded,
        links,
        texts,
        names,
    } = b;

    // Positions: W6, warm from the previous run.
    let previous_layout = PreviousRun::new(&prev.params, prev_payloads);
    let fill =
        fill_positions(&mut docs, Some(&previous_layout)).map_err(|e| anyhow::anyhow!("{e}"))?;
    let prev_layout = LayoutRecord::from_params(&prev.params).unwrap_or_default();
    let relaid: Vec<&String> = fill
        .record
        .hashes
        .iter()
        .filter(|(k, h)| prev_layout.hashes.get(*k) != Some(*h))
        .map(|(k, _)| k)
        .collect();

    // Names: W8, no transaction open while the model runs.
    let plan = plan_samples(&docs)?;
    let (naming, naming_report) = name_levels(
        &mut docs,
        &plan,
        &texts,
        &names,
        backend,
        NamingOptions {
            max_calls: opts.max_calls,
            call_model: opts.apply,
        },
    )?;
    let prev_keys: BTreeSet<String> = NamingRecord::from_params(&prev.params)?
        .map(|r| r.keys.into_values().collect())
        .unwrap_or_default();
    let renamed: Vec<&String> = naming
        .keys
        .iter()
        .filter(|(_, k)| !prev_keys.contains(*k))
        .map(|(l, _)| l)
        .collect();

    // Unchanged: every level equal to the previous run's (with its run id),
    // the same level set, and the same snapshot epochs.
    let mut same = docs.len() == prev_docs.len();
    if same {
        for doc in &docs {
            let mut d = doc.clone();
            set_run_id(&mut d, prev.id);
            if prev_docs.get(&doc_key(doc)) != Some(&d) {
                same = false;
                break;
            }
        }
    }
    let unchanged = same && epochs == prev.epochs;
    let mut report = json!({
        "map": map_key(map),
        "from_run": prev.id,
        "levels": docs.len(),
        "themes": themes,
        "unembedded_members": unembedded,
        "links": links,
        "layout": {"computed": fill.computed, "warm_started": fill.warm_started,
                   "reused": fill.reused, "relaid": relaid},
        "naming": {"report": naming_report, "renamed": renamed},
        "documents_unchanged": same,
        "epochs_unchanged": epochs == prev.epochs,
    });
    if !opts.apply {
        report["status"] = json!("dry_run");
        report["would_write"] = json!(!unchanged);
        return Ok(report);
    }
    if unchanged {
        report["status"] = json!("unchanged");
        return Ok(report);
    }

    let mut params = json!({
        "hierarchies": ["meaning", "links"],
        "cap": opts.cap,
        "nightly_from_run": prev.id,
        "themes": report["themes"].clone(),
        "unembedded_members": unembedded,
        "links": links,
        MIRRORS_KEY: mirrors,
    });
    // Errors stay in the report (the journal), not in a row the map's
    // readers can read: keep only the theme ids in the run's params.
    for k in ["carried", "dropped", "unbuilt"] {
        let ids: Vec<Value> = params["themes"][k]
            .as_array()
            .map(|a| a.iter().map(|t| t["theme_id"].clone()).collect())
            .unwrap_or_default();
        params["themes"][k] = json!(ids);
    }
    params["themes"]["built"] = json!(params["themes"]["built"].as_array().map_or(0, Vec::len));
    fill.record
        .write_into(&mut params)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    params["naming"] = serde_json::to_value(&naming)?;

    let mut tx = conn.begin().await.context("begin the run write")?;
    AtlasMapRepository::lock_map_for_publish(&mut tx, map).await?;
    let latest = AtlasNamingRepository::latest_finished_run(&mut tx, viewer, map, false)
        .await?
        .map(|r| r.id);
    if latest != Some(prev.id) {
        tx.rollback().await.ok();
        report["status"] = json!("superseded");
        report["note"] = json!(format!(
            "a newer run ({latest:?}) was published since the build read {}; nothing was \
             written, the next night builds from it",
            prev.id
        ));
        return Ok(report);
    }
    let run_id = AtlasMapRepository::write_run(
        &mut tx,
        &NewMapRun {
            map,
            algo: NIGHTLY_ALGO.to_string(),
            params,
            epochs,
        },
    )
    .await?;
    for doc in &mut docs {
        set_run_id(doc, run_id);
        AtlasMapRepository::put_level(&mut tx, run_id, &level_doc(doc)?).await?;
    }
    AtlasMapRepository::finish_run(&mut tx, run_id).await?;
    let pruned = AtlasMapRepository::prune_runs(&mut tx, map, opts.keep_runs).await?;
    tx.commit().await.context("commit the run")?;
    report["status"] = json!("written");
    report["run_id"] = json!(run_id);
    report["pruned_runs"] = json!(pruned);
    Ok(report)
}

/// The whole night: the theme assignment, then every map. Returns the
/// summary and whether every map succeeded (a failed map is reported and the
/// next one still runs).
///
/// # Errors
/// A database error in the theme step (before any map is built).
pub async fn run_night(
    conn: &mut PgConnection,
    viewer: &Viewer,
    backend: &dyn NameBackend,
    opts: &NightOptions,
) -> anyhow::Result<(Value, bool)> {
    ensure!(
        opts.keep_runs >= 1,
        "keep at least one finished run per map"
    );
    ensure!(
        opts.assign_batch >= 1,
        "the assignment batch must be at least 1"
    );
    // 1. Themes: assign new claims to the nearest existing theme, each batch
    //    committed before any build snapshot is taken.
    let unthemed = AtlasMeaningRepository::unthemed_embedded_count(conn, viewer).await?;
    let mut assigned = 0_i64;
    if opts.apply {
        for _ in 0..100_000 {
            let n =
                ClaimThemeRepository::assign_unthemed_batch(&mut *conn, viewer, opts.assign_batch)
                    .await?;
            assigned += n;
            if n == 0 {
                break;
            }
        }
    }
    let over_cap =
        AtlasMeaningRepository::themes_over_member_cap(conn, viewer, opts.theme_cap).await?;
    let themes = json!({
        "unthemed_embedded": unthemed,
        "assigned": assigned,
        "over_cap": over_cap.iter().map(|(t, n)| json!({"theme_id": t, "members": n})).collect::<Vec<_>>(),
        "theme_cap": opts.theme_cap,
        "note": "themes over the cap are not split by the nightly: run W1's theme_cap_split \
                 (operator, off-box compute)",
    });

    // 2. Maps.
    let maps = match &opts.maps {
        Some(m) => m.clone(),
        None => AtlasMapRepository::maps_with_finished_runs(conn, viewer).await?,
    };
    let mut ok = true;
    let mut reports = Vec::with_capacity(maps.len());
    for map in maps {
        match night_for_map(conn, viewer, backend, map, opts).await {
            Ok(r) => reports.push(r),
            Err(e) => {
                ok = false;
                reports.push(json!({"map": map_key(map), "status": "failed",
                                    "error": format!("{e:#}")}));
            }
        }
    }
    Ok((
        json!({"applied": opts.apply, "themes": themes, "maps": reports, "ok": ok}),
        ok,
    ))
}

/// The record keys of `docs` (W6/W8 spelling), for a caller comparing runs.
#[must_use]
pub fn level_keys(docs: &[LevelDocument]) -> BTreeSet<String> {
    docs.iter().map(|d| record_key(doc_key(d))).collect()
}

/// Whether two stored payload sets are equal as documents, with `run_id`
/// ignored.
///
/// # Errors
/// A payload that does not parse.
pub fn same_documents(a: &[Value], b: &[Value]) -> anyhow::Result<bool> {
    let norm = |v: &[Value]| -> anyhow::Result<BTreeMap<(Hierarchy, Uuid), LevelDocument>> {
        v.iter()
            .map(|p| {
                let mut d: LevelDocument = serde_json::from_value(p.clone())?;
                set_run_id(&mut d, Uuid::nil());
                Ok((doc_key(&d), d))
            })
            .collect()
    };
    Ok(norm(a)? == norm(b)?)
}
