//! The box-side halves of the "by links" build: [`export_links`] writes a
//! map's themes for the off-box compute, [`apply_hierarchies`] checks a
//! meaning result and a links result against the live rows and writes BOTH
//! hierarchies into one run. Both run on the maintenance connection, each in
//! one REPEATABLE READ transaction opened by
//! `AtlasMapRepository::begin_build_snapshot`.
//!
//! **Why both hierarchies in one run.** The serving read takes a map's latest
//! finished run whatever it holds, and every level document's `switch` names
//! a level of the other hierarchy. A links-only run would hide the meaning
//! levels and leave every switch pointing at a level that is not served. The
//! nightly (W9) does the same with [`write_links_levels`], which writes into
//! a run the caller opened next to `write_meaning_levels`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{bail, ensure, Context};
use epigraph_db::repos::atlas_leaf::{claim_attachments, AtlasLeafRepository};
use epigraph_db::repos::atlas_map::{AtlasHierarchy, AtlasMap, NewMapRun};
use epigraph_db::{AtlasMapRepository, AtlasMeaningRepository, Viewer};
use serde_json::json;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use super::files::{
    write_links_index, write_links_theme, LinksExportIndex, LinksExportTheme, LinksResultDoc,
    LinksThemeFile, EXPORT_FORMAT,
};
use super::graph::{
    check_mirrors, counted_links, leaf_count, linked_claims, meaning_leaf_of, switch_targets,
};
use crate::atlas_meaning::build::{
    resolve_result, resolve_theme, write_meaning_levels, ResolvedTheme,
};
use crate::atlas_meaning::docs::level_documents_with_switch;
use crate::atlas_meaning::files::{index_attachments, prepare_export_dir, ResultDoc};
use crate::atlas_meaning::tree::{check_tree, map_key, resolve_tree, MeaningTree, ResolveStats};

/// The `atlas_map_runs.algo` of a run holding both hierarchies.
pub const HIERARCHIES_ALGO: &str = "atlas-hierarchies/1";

const HIERARCHY: AtlasHierarchy = AtlasHierarchy::Links;

/// What `export` was asked for.
#[derive(Debug, Clone)]
pub struct LinksExportOptions {
    pub map: AtlasMap,
    /// Only these themes; every theme the map draws with an embedded member
    /// otherwise.
    pub themes: Option<Vec<Uuid>>,
    pub cap: usize,
    pub seed: u64,
}

/// The meaning leaves of `tree` numbered in its pre-order, by claim.
fn meaning_leaf_numbers(tree: &MeaningTree) -> anyhow::Result<BTreeMap<Uuid, u32>> {
    let mut out = BTreeMap::new();
    for (n, (_, members)) in tree.leaves().enumerate() {
        let n = u32::try_from(n)?;
        for c in members {
            out.insert(*c, n);
        }
    }
    Ok(out)
}

/// Write `opts.map`'s themes into `out` for `atlas_links_core.py compute`,
/// reading everything in one snapshot: per theme, the meaning result's tree
/// resolved now with W4's code (so the mirrors follow the leaves the apply
/// will write), the theme's members (exactly the meaning tree's claims), each
/// member's attachments after W3's per-claim cap (renumbered as W4 does), the
/// counted links among the members from W3's read (the map edge rule: no
/// co-owned or other-team edge), each member's meaning leaf as an integer,
/// and the LINKED members' embeddings. Writes nothing to the database.
/// Returns the operator's report (counts only, never text or ids beyond the
/// theme's).
///
/// # Errors
/// An export directory W4's `prepare_export_dir` refuses, a theme the
/// meaning result does not hold, any refusal of W4's `resolve_theme`, a
/// database error, embeddings of different dimensions, or an I/O error.
pub async fn export_links(
    conn: &mut PgConnection,
    viewer: &Viewer,
    opts: &LinksExportOptions,
    meaning: &ResultDoc,
    out: &Path,
) -> anyhow::Result<serde_json::Value> {
    prepare_export_dir(out)?;
    ensure!(
        meaning.map == map_key(opts.map) && meaning.hierarchy == "meaning",
        "the meaning result is for map {:?} / {:?}, not {:?} / \"meaning\"",
        meaning.map,
        meaning.hierarchy,
        map_key(opts.map)
    );
    meaning.versions.check()?;
    let mut tx = conn.begin().await.context("begin the export transaction")?;
    let epochs = AtlasMapRepository::begin_build_snapshot(&mut tx, viewer, opts.map).await?;
    let themes = match &opts.themes {
        Some(t) => {
            let mut t = t.clone();
            t.sort_unstable();
            t.dedup();
            t
        }
        None => {
            AtlasMeaningRepository::embedded_theme_ids_on_map(&mut tx, viewer, opts.map).await?
        }
    };
    let mut dim: Option<usize> = None;
    let mut entries = Vec::new();
    let mut report = Vec::new();
    for theme in themes {
        let rt = meaning
            .themes
            .iter()
            .find(|t| t.theme_id == theme)
            .with_context(|| format!("the meaning result has no theme {theme}"))?;
        let resolved = resolve_theme(&mut tx, viewer, opts.map, rt, opts.cap).await?;
        let members =
            AtlasMeaningRepository::theme_members(&mut tx, viewer, opts.map, theme).await?;
        let ids: Vec<Uuid> = members.embedded.iter().map(|(id, _)| *id).collect();
        ensure!(
            ids == resolved.tree.nodes[0].claims,
            "theme {theme}: the members moved inside the export snapshot"
        );
        let embeddings = members
            .embedded
            .iter()
            .map(|(id, text)| {
                epigraph_embeddings::Normalizer::parse_pgvector(text)
                    .with_context(|| format!("claim {id} has an unreadable embedding"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let d = embeddings[0].len();
        ensure!(
            *dim.get_or_insert(d) == d,
            "theme {theme} has {d}-d embeddings, other themes {}-d",
            dim.unwrap_or(d)
        );
        let rows = AtlasLeafRepository::read_leaf_rows(&mut tx, viewer, opts.map, &ids).await?;
        let attachments = claim_attachments(&rows, opts.cap)?;
        ensure!(
            attachments.keys().copied().collect::<Vec<_>>() == ids,
            "theme {theme}: W3's read draws {} of {} members",
            attachments.len(),
            ids.len()
        );
        let (att, nodes) = index_attachments(&attachments)?;
        let member_set: BTreeSet<Uuid> = ids.iter().copied().collect();
        let links = counted_links(&rows, &member_set);
        let pos: BTreeMap<Uuid, u32> = ids
            .iter()
            .enumerate()
            .map(|(i, c)| Ok((*c, u32::try_from(i)?)))
            .collect::<anyhow::Result<_>>()?;
        let mut pairs: Vec<[u32; 2]> = links.iter().map(|(a, b)| [pos[a], pos[b]]).collect();
        for p in &mut pairs {
            p.sort_unstable();
        }
        pairs.sort_unstable();
        let numbers = meaning_leaf_numbers(&resolved.tree)?;
        let meaning_leaf: Vec<u32> = ids.iter().map(|c| numbers[c]).collect();
        let file = LinksThemeFile {
            claim_ids: ids.clone(),
            attachments: att.attachments,
            links: pairs,
            meaning_leaf,
        };
        write_links_theme(out, theme, &file, &embeddings, d)?;
        let linked = file.linked().len();
        let leaves = numbers.values().collect::<BTreeSet<_>>().len();
        entries.push(LinksExportTheme {
            theme_id: theme,
            claims: ids.len(),
            linked,
            links: file.links.len(),
            attachment_nodes: nodes,
            meaning_leaves: leaves,
        });
        report.push(
            json!({"theme_id": theme, "claims": ids.len(), "linked": linked,
                           "links": file.links.len(), "meaning_leaves": leaves,
                           "attachment_nodes": nodes}),
        );
    }
    let index = LinksExportIndex {
        format: EXPORT_FORMAT.to_string(),
        map: map_key(opts.map),
        hierarchy: HIERARCHY.as_str().to_string(),
        cap: opts.cap,
        seed: opts.seed,
        dim: dim.unwrap_or(0),
        themes: entries,
    };
    write_links_index(out, &index)?;
    tx.rollback().await.context("end the export transaction")?;
    Ok(json!({
        "map": map_key(opts.map),
        "cap": opts.cap,
        "seed": opts.seed,
        "dim": index.dim,
        "exported_themes": index.themes.len(),
        "snapshot_epochs": {"map": epochs.map, "public": epochs.public},
        "themes": report,
    }))
}

/// One theme's links tree, checked and resolved by [`resolve_links_result`].
#[derive(Debug, Clone)]
pub struct ResolvedLinksTheme {
    pub tree: MeaningTree,
    pub stats: ResolveStats,
    /// Each group's switch target in the meaning tree of the same theme
    /// ([`switch_targets`]).
    pub switch: BTreeMap<Uuid, Uuid>,
    pub linked: usize,
    pub unlinked: usize,
    pub mirrors: usize,
    pub id_chunk_cuts: u32,
    pub embedding_splits: u32,
}

/// Check `links` against `map`'s rows in the build's snapshot and against
/// `meaning`, the meaning trees resolved in the same snapshot (and written
/// into the same run): the result's map and hierarchy must be these, its cap
/// at most `cap`, its versions typed, its themes exactly `meaning`'s (which
/// W4 checks are exactly the map's); per theme, every id the minted one and
/// the leaves exactly the meaning tree's claims ([`check_tree`]), every leaf
/// re-counted by W3 and one over the cap split on the box ([`resolve_tree`]),
/// and then the W5b mirror rule on the resolved tree against the links live
/// now ([`check_mirrors`]).
///
/// # Errors
/// Any refusal above, or a database error.
pub async fn resolve_links_result(
    tx: &mut PgConnection,
    viewer: &Viewer,
    map: AtlasMap,
    links: &LinksResultDoc,
    meaning: &[ResolvedTheme],
    cap: usize,
) -> anyhow::Result<Vec<ResolvedLinksTheme>> {
    ensure!(
        links.map == map_key(map),
        "the links result is for map {:?}, not {:?}",
        links.map,
        map_key(map)
    );
    ensure!(
        links.hierarchy == HIERARCHY.as_str(),
        "the links result is for the {:?} hierarchy",
        links.hierarchy
    );
    links.versions.check()?;
    ensure!(
        links.cap <= cap,
        "the links result was computed for a cap of {}, over this apply's {cap}",
        links.cap
    );
    let mut by_theme = BTreeMap::new();
    for t in &links.themes {
        ensure!(
            by_theme.insert(t.theme_id, t).is_none(),
            "theme {} is in the links result twice",
            t.theme_id
        );
    }
    let want: BTreeSet<Uuid> = meaning.iter().map(|m| m.tree.theme_id).collect();
    let got: BTreeSet<Uuid> = by_theme.keys().copied().collect();
    ensure!(
        want == got,
        "the links result holds {} themes and the meaning result {}; they must be the same \
         themes ({} missing, {} extra)",
        got.len(),
        want.len(),
        want.difference(&got).count(),
        got.difference(&want).count()
    );
    let mut out = Vec::with_capacity(meaning.len());
    for m in meaning {
        let theme = m.tree.theme_id;
        let t = by_theme[&theme];
        let members: BTreeSet<Uuid> = m.tree.nodes[0].claims.iter().copied().collect();
        let tree = check_tree(map, HIERARCHY, theme, &t.groups, &members)?;
        let all: Vec<Uuid> = members.iter().copied().collect();
        let rows = AtlasLeafRepository::read_leaf_rows(tx, viewer, map, &all).await?;
        let linked = linked_claims(&counted_links(&rows, &members));
        let (tree, stats) = resolve_tree(&tree, &rows, cap)?;
        let mirrors = check_mirrors(&tree, &linked, &meaning_leaf_of(&m.tree))?;
        let switch = switch_targets(&tree, &m.tree)?;
        out.push(ResolvedLinksTheme {
            stats,
            switch,
            linked: linked.len(),
            unlinked: members.len() - linked.len(),
            mirrors,
            id_chunk_cuts: t.id_chunk_cuts,
            embedding_splits: t.embedding_splits,
            tree,
        });
    }
    Ok(out)
}

/// Write every links level document of `themes` into the unfinished run
/// `run_id` of `map`, each level's switch leading to its meaning group
/// ([`ResolvedLinksTheme::switch`]), reading the claim labels in the same
/// snapshot. The meaning levels must go into the same run
/// (`write_meaning_levels`), or the switches name levels that are not
/// served. Returns the number of documents written.
///
/// # Errors
/// A document the contract refuses, a claim with no readable label, a level
/// with no switch target, or a database error.
pub async fn write_links_levels(
    tx: &mut PgConnection,
    viewer: &Viewer,
    map: AtlasMap,
    run_id: Uuid,
    themes: &[ResolvedLinksTheme],
) -> anyhow::Result<usize> {
    let mut written = 0;
    for t in themes {
        for doc in links_documents(tx, viewer, map, run_id, t).await? {
            AtlasMapRepository::put_level(tx, run_id, &doc).await?;
            written += 1;
        }
    }
    Ok(written)
}

async fn links_documents(
    tx: &mut PgConnection,
    viewer: &Viewer,
    map: AtlasMap,
    run_id: Uuid,
    t: &ResolvedLinksTheme,
) -> anyhow::Result<Vec<epigraph_db::repos::atlas_map::LevelDoc>> {
    let labels =
        AtlasMeaningRepository::claim_labels(tx, viewer, map, &t.tree.nodes[0].claims).await?;
    level_documents_with_switch(&t.tree, run_id, &labels, &|node| {
        t.switch
            .get(&node.id)
            .copied()
            .with_context(|| format!("links level {} has no switch target", node.id))
    })
}

/// Check both results and, with `write`, store them as ONE finished run of
/// `map` holding both hierarchies: W4's `resolve_result` (the whole-map
/// check, the W3 re-check) for the meaning result, then
/// [`resolve_links_result`] against those trees, all in one snapshot and one
/// transaction. Without `write` it builds every document of both and writes
/// nothing. On any refusal nothing is written.
///
/// # Errors
/// Any refusal of W4's `resolve_result`, [`resolve_links_result`] or the
/// document builders, or a database error.
pub async fn apply_hierarchies(
    conn: &mut PgConnection,
    viewer: &Viewer,
    map: AtlasMap,
    meaning: &ResultDoc,
    links: &LinksResultDoc,
    cap: usize,
    write: bool,
) -> anyhow::Result<serde_json::Value> {
    let mut tx = conn.begin().await.context("begin the build transaction")?;
    let epochs = AtlasMapRepository::begin_build_snapshot(&mut tx, viewer, map).await?;
    let meaning_themes = resolve_result(&mut tx, viewer, map, meaning, cap).await?;
    let links_themes =
        resolve_links_result(&mut tx, viewer, map, links, &meaning_themes, cap).await?;

    let m_sum = |f: fn(&ResolvedTheme) -> usize| meaning_themes.iter().map(f).sum::<usize>();
    let l_sum = |f: fn(&ResolvedLinksTheme) -> usize| links_themes.iter().map(f).sum::<usize>();
    let params = json!({
        "hierarchies": ["meaning", "links"],
        "cap": cap,
        "positions": "placeholder",
        "leaves": "skeleton",
        "themes": meaning_themes.len(),
        "meaning": {
            "result_cap": meaning.cap,
            "seed": meaning.seed,
            "versions": meaning.versions,
            "leaf_groups": m_sum(|t| t.stats.leaves),
            "inner_groups": m_sum(|t| t.stats.groups),
            "resplit_leaves": m_sum(|t| t.stats.resplit_leaves),
            "id_chunk_cuts": meaning_themes.iter().map(|t| u64::from(t.id_chunk_cuts)).sum::<u64>(),
            "unembedded_members": m_sum(|t| t.unembedded),
        },
        "links": {
            "result_cap": links.cap,
            "seed": links.seed,
            "versions": links.versions,
            "leaf_groups": l_sum(|t| leaf_count(&t.tree)),
            "inner_groups": l_sum(|t| t.tree.nodes.len() - leaf_count(&t.tree)),
            "resplit_leaves": l_sum(|t| t.stats.resplit_leaves),
            "linked_claims": l_sum(|t| t.linked),
            "unlinked_claims": l_sum(|t| t.unlinked),
            "mirror_leaves": l_sum(|t| t.mirrors),
            "embedding_splits": links_themes.iter().map(|t| u64::from(t.embedding_splits)).sum::<u64>(),
            "id_chunk_cuts": links_themes.iter().map(|t| u64::from(t.id_chunk_cuts)).sum::<u64>(),
        },
    });
    let mut report = json!({
        "map": map_key(map),
        "applied": write,
        "params": params,
        "max_leaf_nodes": meaning_themes.iter().map(|t| t.stats.max_leaf_nodes)
            .chain(links_themes.iter().map(|t| t.stats.max_leaf_nodes)).max().unwrap_or(0),
    });
    if !write {
        let mut docs = 0;
        for t in &meaning_themes {
            let labels =
                AtlasMeaningRepository::claim_labels(&mut tx, viewer, map, &t.tree.nodes[0].claims)
                    .await?;
            docs +=
                crate::atlas_meaning::docs::level_documents(&t.tree, Uuid::nil(), &labels)?.len();
        }
        for t in &links_themes {
            docs += links_documents(&mut tx, viewer, map, Uuid::nil(), t)
                .await?
                .len();
        }
        report["documents"] = json!(docs);
        tx.rollback().await.context("roll back the dry run")?;
        return Ok(report);
    }
    let run_id = AtlasMapRepository::write_run(
        &mut tx,
        &NewMapRun {
            map,
            algo: HIERARCHIES_ALGO.to_string(),
            params: report["params"].clone(),
            epochs,
        },
    )
    .await?;
    let meaning_docs = write_meaning_levels(&mut tx, viewer, map, run_id, &meaning_themes).await?;
    let links_docs = write_links_levels(&mut tx, viewer, map, run_id, &links_themes).await?;
    if meaning_docs == 0 {
        bail!("the results hold no theme; nothing was written");
    }
    AtlasMapRepository::finish_run(&mut tx, run_id).await?;
    tx.commit().await.context("commit the run")?;
    report["run_id"] = json!(run_id);
    report["documents"] = json!({"meaning": meaning_docs, "links": links_docs});
    Ok(report)
}
