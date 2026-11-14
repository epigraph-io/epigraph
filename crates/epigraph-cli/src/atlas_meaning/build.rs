//! The two box-side halves of the "by meaning" build: [`export_map`] writes a
//! map's themes for the off-box compute, [`apply_result`] checks a result
//! against the live rows and writes one run. Both run on the maintenance
//! connection, each in one REPEATABLE READ transaction opened by
//! `AtlasMapRepository::begin_build_snapshot`, so every row they read comes
//! from one snapshot and the run records that snapshot's epochs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{bail, ensure, Context};
use epigraph_db::repos::atlas_leaf::{claim_attachments, AtlasLeafRepository};
use epigraph_db::repos::atlas_map::{AtlasHierarchy, AtlasMap, NewMapRun};
use epigraph_db::{AtlasMapRepository, AtlasMeaningRepository, Viewer};
use serde_json::json;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use super::docs::level_documents;
use super::files::{
    index_attachments, prepare_export_dir, write_index, write_theme, ExportIndex, ExportTheme,
    ResultDoc, EXPORT_FORMAT,
};
use super::tree::{check_tree, map_key, resolve_tree, MeaningTree, ResolveStats};

/// The `atlas_map_runs.algo` of a run this build writes.
pub const MEANING_ALGO: &str = "atlas-meaning/1";

const HIERARCHY: AtlasHierarchy = AtlasHierarchy::Meaning;

/// What `export` was asked for.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    pub map: AtlasMap,
    /// Only these themes; every theme the map draws when `None`.
    pub themes: Option<Vec<Uuid>>,
    pub cap: usize,
    pub seed: u64,
}

fn parse_embedding(claim: Uuid, text: &str) -> anyhow::Result<Vec<f32>> {
    epigraph_embeddings::Normalizer::parse_pgvector(text)
        .with_context(|| format!("claim {claim} has an unreadable embedding"))
}

/// Write `opts.map`'s themes into `out` for
/// `atlas_meaning_core.py compute`: per theme, its current embedded members,
/// their embeddings, and each member's attachment nodes after W3's per-claim
/// cap, renumbered per theme. Writes nothing to the database. Returns the
/// operator's report (counts only, never text): per theme its members, the
/// current members left out for having no embedding, and its attachment nodes.
///
/// A theme with no embedded member is reported and not exported.
///
/// `out` is made ready by [`prepare_export_dir`] first: a new path is created
/// 0700, an existing directory must be empty and owner-only, and every file
/// is created 0600, so the embeddings are never readable by another local
/// user whatever the umask.
///
/// # Errors
/// An export directory [`prepare_export_dir`] refuses, a database error,
/// embeddings of different dimensions, or an I/O error.
pub async fn export_map(
    conn: &mut PgConnection,
    viewer: &Viewer,
    opts: &ExportOptions,
    out: &Path,
) -> anyhow::Result<serde_json::Value> {
    prepare_export_dir(out)?;
    let mut tx = conn.begin().await.context("begin the export transaction")?;
    let epochs = AtlasMapRepository::begin_build_snapshot(&mut tx, viewer, opts.map).await?;
    let themes = match &opts.themes {
        Some(t) => {
            let mut t = t.clone();
            t.sort_unstable();
            t.dedup();
            t
        }
        None => AtlasMeaningRepository::theme_ids_on_map(&mut tx, viewer, opts.map).await?,
    };
    let mut dim: Option<usize> = None;
    let mut entries = Vec::new();
    let mut report = Vec::new();
    for theme in themes {
        let members =
            AtlasMeaningRepository::theme_members(&mut tx, viewer, opts.map, theme).await?;
        if members.embedded.is_empty() {
            report.push(json!({"theme_id": theme, "claims": 0,
                               "unembedded": members.unembedded, "exported": false}));
            continue;
        }
        let ids: Vec<Uuid> = members.embedded.iter().map(|(id, _)| *id).collect();
        let embeddings = members
            .embedded
            .iter()
            .map(|(id, text)| parse_embedding(*id, text))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let d = embeddings[0].len();
        ensure!(
            *dim.get_or_insert(d) == d,
            "theme {theme} has {d}-d embeddings, other themes {}-d",
            dim.unwrap_or(d)
        );
        let rows = AtlasLeafRepository::read_leaf_rows(&mut tx, viewer, opts.map, &ids).await?;
        let attachments = claim_attachments(&rows, opts.cap)?;
        let got: Vec<Uuid> = attachments.keys().copied().collect();
        ensure!(
            got == ids,
            "theme {theme}: W3's read draws {} of {} members",
            got.len(),
            ids.len()
        );
        let (file, nodes) = index_attachments(&attachments)?;
        write_theme(out, theme, &file, &embeddings, d)?;
        entries.push(ExportTheme {
            theme_id: theme,
            claims: ids.len(),
            attachment_nodes: nodes,
        });
        report.push(json!({"theme_id": theme, "claims": ids.len(),
                           "unembedded": members.unembedded, "attachment_nodes": nodes,
                           "exported": true}));
    }
    let index = ExportIndex {
        format: EXPORT_FORMAT.to_string(),
        map: map_key(opts.map),
        hierarchy: HIERARCHY.as_str().to_string(),
        cap: opts.cap,
        seed: opts.seed,
        dim: dim.unwrap_or(0),
        themes: entries,
    };
    write_index(out, &index)?;
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

/// One theme checked and resolved by [`apply_result`].
#[derive(Debug, Clone)]
pub struct ResolvedTheme {
    pub tree: MeaningTree,
    pub stats: ResolveStats,
    pub id_chunk_cuts: u32,
    pub unembedded: usize,
}

/// Check `result` against `map`'s rows in the build's snapshot and resolve
/// each theme's tree with W3: the result's map and hierarchy must be these,
/// its cap at most `cap`, its themes EXACTLY the themes the map draws with an
/// embedded member now ([`AtlasMeaningRepository::embedded_theme_ids_on_map`],
/// what `export` writes), each theme's leaves exactly the theme's current
/// embedded members now, every id the minted one; a leaf W3 finds over `cap`
/// is split on the box. Call it on the build's transaction, after
/// `begin_build_snapshot`.
///
/// The theme set is checked because a run is the WHOLE map: the serving read
/// takes the latest finished run of a map, so a run holding some themes would
/// hide every other theme's levels. A batched export (`--theme-id`) is
/// computed per batch and the results merged ([`super::files::merge_results`])
/// into one apply.
///
/// # Errors
/// Any refusal of [`check_tree`] or [`resolve_tree`], a result for another
/// map, hierarchy or a larger cap, a theme named twice, a result that lacks a
/// theme the map draws or names one it does not, or a database error.
pub async fn resolve_result(
    tx: &mut PgConnection,
    viewer: &Viewer,
    map: AtlasMap,
    result: &ResultDoc,
    cap: usize,
) -> anyhow::Result<Vec<ResolvedTheme>> {
    ensure!(
        result.map == map_key(map),
        "the result is for map {:?}, not {:?}",
        result.map,
        map_key(map)
    );
    ensure!(
        result.hierarchy == HIERARCHY.as_str(),
        "the result is for the {:?} hierarchy",
        result.hierarchy
    );
    ensure!(
        result.cap <= cap,
        "the result was computed for a cap of {}, over this apply's {cap}",
        result.cap
    );
    let mut seen = BTreeSet::new();
    for t in &result.themes {
        ensure!(
            seen.insert(t.theme_id),
            "theme {} is in the result twice",
            t.theme_id
        );
    }
    let drawn: BTreeSet<Uuid> = AtlasMeaningRepository::embedded_theme_ids_on_map(tx, viewer, map)
        .await?
        .into_iter()
        .collect();
    let missing: Vec<&Uuid> = drawn.difference(&seen).collect();
    ensure!(
        missing.is_empty(),
        "the result lacks {} of the {} themes map {} draws (first: {}); a run is the whole map \
         and would hide the others, so export every theme (or merge every batch's result into \
         one apply with repeated --from)",
        missing.len(),
        drawn.len(),
        map_key(map),
        missing[0]
    );
    let extra: Vec<&Uuid> = seen.difference(&drawn).collect();
    ensure!(
        extra.is_empty(),
        "the result names {} theme(s) map {} does not draw with an embedded member now \
         (first: {})",
        extra.len(),
        map_key(map),
        extra[0]
    );
    let mut out = Vec::with_capacity(result.themes.len());
    for t in &result.themes {
        let members = AtlasMeaningRepository::theme_members(tx, viewer, map, t.theme_id).await?;
        let ids: BTreeSet<Uuid> = members.embedded.iter().map(|(id, _)| *id).collect();
        let tree = check_tree(map, HIERARCHY, t.theme_id, &t.groups, &ids)?;
        let all: Vec<Uuid> = ids.iter().copied().collect();
        let rows = AtlasLeafRepository::read_leaf_rows(tx, viewer, map, &all).await?;
        let (tree, stats) = resolve_tree(&tree, &rows, cap)?;
        out.push(ResolvedTheme {
            tree,
            stats,
            id_chunk_cuts: t.id_chunk_cuts,
            unembedded: members.unembedded,
        });
    }
    Ok(out)
}

/// Write every level document of `themes` into the unfinished run `run_id`
/// of `map`, reading the claim labels in the same snapshot. The nightly
/// (W9) calls this on a run it also fills with the links hierarchy, because
/// the serving read takes the latest finished run of a map whatever
/// hierarchies it holds. Returns the number of documents written.
///
/// # Errors
/// A document the contract refuses, a claim with no readable label, or a
/// database error.
pub async fn write_meaning_levels(
    tx: &mut PgConnection,
    viewer: &Viewer,
    map: AtlasMap,
    run_id: Uuid,
    themes: &[ResolvedTheme],
) -> anyhow::Result<usize> {
    let mut written = 0;
    for t in themes {
        let claims: Vec<Uuid> = t.tree.nodes[0].claims.clone();
        let labels = AtlasMeaningRepository::claim_labels(tx, viewer, map, &claims).await?;
        for doc in level_documents(&t.tree, run_id, &labels)? {
            AtlasMapRepository::put_level(tx, run_id, &doc).await?;
            written += 1;
        }
    }
    Ok(written)
}

/// Check `result` and, with `write`, store it as one finished run of `map`
/// holding only the meaning hierarchy. Without `write` it builds every
/// document (so a dry run fails exactly where the apply would) and writes
/// nothing. One transaction: on any refusal nothing is written.
///
/// A run written here holds no links levels, and the serving read takes the
/// latest finished run of a map, so it hides any earlier run's links
/// hierarchy. The report says so.
///
/// # Errors
/// Any refusal of [`resolve_result`] or [`write_meaning_levels`], or a
/// database error.
pub async fn apply_result(
    conn: &mut PgConnection,
    viewer: &Viewer,
    map: AtlasMap,
    result: &ResultDoc,
    cap: usize,
    write: bool,
) -> anyhow::Result<serde_json::Value> {
    let mut tx = conn.begin().await.context("begin the build transaction")?;
    let epochs = AtlasMapRepository::begin_build_snapshot(&mut tx, viewer, map).await?;
    let themes = resolve_result(&mut tx, viewer, map, result, cap).await?;

    let sum = |f: fn(&ResolvedTheme) -> usize| themes.iter().map(f).sum::<usize>();
    let params = json!({
        "hierarchy": HIERARCHY.as_str(),
        "cap": cap,
        "result_cap": result.cap,
        "seed": result.seed,
        "versions": result.versions,
        "positions": "placeholder",
        "leaves": "skeleton",
        "themes": themes.len(),
        "leaf_groups": sum(|t| t.stats.leaves),
        "inner_groups": sum(|t| t.stats.groups),
        "resplit_leaves": sum(|t| t.stats.resplit_leaves),
        "id_chunk_cuts": themes.iter().map(|t| u64::from(t.id_chunk_cuts)).sum::<u64>(),
        "unembedded_members": sum(|t| t.unembedded),
    });
    let mut report = json!({
        "map": map_key(map),
        "applied": write,
        "params": params,
        "max_leaf_nodes": themes.iter().map(|t| t.stats.max_leaf_nodes).max().unwrap_or(0),
        "note": "this run holds the meaning hierarchy only; served as the map's latest run it \
                 hides any earlier run's links levels",
    });
    if !write {
        let mut docs = 0;
        for t in &themes {
            let labels =
                AtlasMeaningRepository::claim_labels(&mut tx, viewer, map, &t.tree.nodes[0].claims)
                    .await?;
            docs += level_documents(&t.tree, Uuid::nil(), &labels)?.len();
        }
        report["documents"] = json!(docs);
        tx.rollback().await.context("roll back the dry run")?;
        return Ok(report);
    }
    let run_id = AtlasMapRepository::write_run(
        &mut tx,
        &NewMapRun {
            map,
            algo: MEANING_ALGO.to_string(),
            params: report["params"].clone(),
            epochs,
        },
    )
    .await?;
    let docs = write_meaning_levels(&mut tx, viewer, map, run_id, &themes).await?;
    if docs == 0 {
        bail!("the result holds no theme; nothing was written");
    }
    AtlasMapRepository::finish_run(&mut tx, run_id).await?;
    tx.commit().await.context("commit the run")?;
    report["run_id"] = json!(run_id);
    report["documents"] = json!(docs);
    Ok(report)
}

/// The leaf groups of a stored run, by claim: what
/// `AtlasMeaningRepository::leaf_membership` reads, keyed for a caller that
/// wants each leaf's claims instead.
#[must_use]
pub fn claims_by_leaf(membership: &BTreeMap<Uuid, Uuid>) -> BTreeMap<Uuid, Vec<Uuid>> {
    let mut out: BTreeMap<Uuid, Vec<Uuid>> = BTreeMap::new();
    for (claim, leaf) in membership {
        out.entry(*leaf).or_default().push(*claim);
    }
    out
}
