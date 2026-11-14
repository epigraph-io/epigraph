//! The two files of the "by links" build that cross the box boundary, shared
//! with `scripts/atlas_links_core.py` (which documents them in full):
//!
//! * the EXPORT the box writes: `export.json` ([`LinksExportIndex`]), and per
//!   theme `<theme_id>.json` ([`LinksThemeFile`]: claim ids, per-claim
//!   attachment integers, links as index pairs, per-claim meaning-leaf
//!   integers) and `<theme_id>.f32` (the embeddings of the LINKED claims
//!   only, raw little-endian float32, in claim id order). Claim ids,
//!   integers and those embeddings only: no agent or evidence id, no edge
//!   id, no relationship name, no text, no tenancy;
//! * the RESULT the box reads back ([`LinksResultDoc`]).
//!
//! The JSON is compact, keys in the order Python writes them, so the Rust
//! writer and `atlas_links_core.write_export` produce the same bytes
//! (`tests/fixtures/atlas_links`). The export is owner-only exactly as W4's
//! ([`prepare_export_dir`](crate::atlas_meaning::files::prepare_export_dir),
//! [`write_owner_only`]).

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::atlas_meaning::files::{write_owner_only, MAX_VERSION_LEN};
use crate::atlas_meaning::tree::WireGroup;

pub const EXPORT_FORMAT: &str = "atlas-links-export/1";
pub const RESULT_FORMAT: &str = "atlas-links-result/1";

/// `export.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinksExportIndex {
    pub format: String,
    /// `public` or `team:<uuid>`.
    pub map: String,
    pub hierarchy: String,
    pub cap: usize,
    pub seed: u64,
    pub dim: usize,
    pub themes: Vec<LinksExportTheme>,
}

/// One theme's entry in `export.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinksExportTheme {
    pub theme_id: Uuid,
    pub claims: usize,
    /// Claims with at least one link (the rows of the `.f32` file).
    pub linked: usize,
    pub links: usize,
    /// Distinct attachment nodes over the theme's claims.
    pub attachment_nodes: usize,
    /// Distinct meaning leaves over the theme's claims.
    pub meaning_leaves: usize,
}

/// `<theme_id>.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinksThemeFile {
    /// Sorted.
    pub claim_ids: Vec<Uuid>,
    /// Per claim: its attachment nodes as W4 numbers them
    /// ([`index_attachments`](crate::atlas_meaning::files::index_attachments)).
    pub attachments: Vec<Vec<u32>>,
    /// Each link once, as `[i, j]` indices into `claim_ids` with `i < j`,
    /// sorted.
    pub links: Vec<[u32; 2]>,
    /// Per claim: its meaning leaf, numbered per theme in the meaning tree's
    /// pre-order.
    pub meaning_leaf: Vec<u32>,
}

impl LinksThemeFile {
    /// The indices of the claims with a link, ascending (the rows of the
    /// `.f32` file).
    #[must_use]
    pub fn linked(&self) -> Vec<usize> {
        let set: BTreeSet<usize> = self
            .links
            .iter()
            .flat_map(|[a, b]| [*a as usize, *b as usize])
            .collect();
        set.into_iter().collect()
    }
}

/// Write one theme's two files into `dir`, each created new with mode 0600.
/// `embeddings` holds one row per claim of `file`; only the linked claims'
/// rows are written.
///
/// # Errors
/// A malformed file (lengths that differ, a link that is not an ordered pair
/// of claims), an embedding of another dimension, or an I/O error.
pub fn write_links_theme(
    dir: &Path,
    theme_id: Uuid,
    file: &LinksThemeFile,
    embeddings: &[Vec<f32>],
    dim: usize,
) -> anyhow::Result<()> {
    let n = file.claim_ids.len();
    ensure!(
        file.attachments.len() == n && file.meaning_leaf.len() == n && embeddings.len() == n,
        "theme {theme_id}: {} attachment lists, {} meaning leaves and {} embeddings for {n} \
         claims",
        file.attachments.len(),
        file.meaning_leaf.len(),
        embeddings.len()
    );
    for [a, b] in &file.links {
        ensure!(
            a < b && (*b as usize) < n,
            "theme {theme_id}: link [{a}, {b}] is not an ordered pair of claims"
        );
    }
    let linked = file.linked();
    let mut raw = Vec::with_capacity(linked.len() * dim * 4);
    for i in linked {
        let e = &embeddings[i];
        ensure!(
            e.len() == dim,
            "claim {} has a {}-d embedding, not {dim}-d",
            file.claim_ids[i],
            e.len()
        );
        for v in e {
            raw.extend_from_slice(&v.to_le_bytes());
        }
    }
    write_owner_only(
        &dir.join(format!("{theme_id}.json")),
        &serde_json::to_vec(file)?,
    )?;
    write_owner_only(&dir.join(format!("{theme_id}.f32")), &raw)
}

/// Write `export.json` into `dir`, created new with mode 0600.
///
/// # Errors
/// An existing `export.json`, or an I/O error.
pub fn write_links_index(dir: &Path, index: &LinksExportIndex) -> anyhow::Result<()> {
    write_owner_only(&dir.join("export.json"), &serde_json::to_vec(index)?)
}

/// The library versions a links result was computed with
/// (`atlas_links_core._versions`). It comes from the off-box file and is
/// stored in the run's `params`, so it is typed: these five keys only, each
/// a short version string or null ([`LinksComputeVersions::check`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinksComputeVersions {
    #[serde(default)]
    pub numpy: Option<String>,
    #[serde(default, rename = "scikit-learn")]
    pub scikit_learn: Option<String>,
    #[serde(default, rename = "umap-learn")]
    pub umap_learn: Option<String>,
    #[serde(default)]
    pub networkx: Option<String>,
    #[serde(default)]
    pub python: Option<String>,
}

impl LinksComputeVersions {
    /// Refuse a version that is not a short version string (ASCII
    /// alphanumerics and `.+-_`, at most [`MAX_VERSION_LEN`] bytes).
    ///
    /// # Errors
    /// A version string that is too long or holds another character.
    pub fn check(&self) -> anyhow::Result<()> {
        for (key, v) in [
            ("numpy", &self.numpy),
            ("scikit-learn", &self.scikit_learn),
            ("umap-learn", &self.umap_learn),
            ("networkx", &self.networkx),
            ("python", &self.python),
        ] {
            let Some(v) = v else { continue };
            ensure!(
                !v.is_empty()
                    && v.len() <= MAX_VERSION_LEN
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)),
                "the result's {key} version is not a version string ({} bytes)",
                v.len()
            );
        }
        Ok(())
    }
}

/// The result file `atlas_links_core.py compute` writes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinksResultDoc {
    pub format: String,
    pub map: String,
    pub hierarchy: String,
    pub cap: usize,
    pub seed: u64,
    pub versions: LinksComputeVersions,
    pub themes: Vec<LinksResultTheme>,
}

/// One theme of a links result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinksResultTheme {
    pub theme_id: Uuid,
    /// Embedding-split cuts that followed claim-id order (identical vectors).
    pub id_chunk_cuts: u32,
    /// Communities Louvain would not split, cut by embedding instead.
    pub embedding_splits: u32,
    pub groups: Vec<WireGroup>,
}

/// Read and parse a links result file.
///
/// # Errors
/// An I/O error, a parse error, another format, or untyped versions.
pub fn read_links_result(path: &Path) -> anyhow::Result<LinksResultDoc> {
    let text = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let doc: LinksResultDoc =
        serde_json::from_slice(&text).with_context(|| format!("parse {}", path.display()))?;
    ensure!(
        doc.format == RESULT_FORMAT,
        "{} is not a {RESULT_FORMAT} result: {:?}",
        path.display(),
        doc.format
    );
    doc.versions
        .check()
        .with_context(|| format!("{}", path.display()))?;
    Ok(doc)
}

/// Merge the links results of a batched export into the one result an apply
/// takes: same format, map, hierarchy, cap, seed and library versions, no
/// theme twice; themes come out sorted by id.
///
/// # Errors
/// No result, a mismatch, or a theme in two results.
pub fn merge_links_results(results: Vec<LinksResultDoc>) -> anyhow::Result<LinksResultDoc> {
    let mut it = results.into_iter();
    let mut merged = it.next().context("no links result to apply")?;
    let mut seen: BTreeSet<Uuid> = BTreeSet::new();
    for t in &merged.themes {
        ensure!(
            seen.insert(t.theme_id),
            "theme {} is in a links result twice",
            t.theme_id
        );
    }
    for r in it {
        ensure!(
            (&r.format, &r.map, &r.hierarchy, r.cap, r.seed, &r.versions)
                == (
                    &merged.format,
                    &merged.map,
                    &merged.hierarchy,
                    merged.cap,
                    merged.seed,
                    &merged.versions
                ),
            "links results differ in format, map, hierarchy, cap, seed or library versions"
        );
        for t in r.themes {
            ensure!(
                seen.insert(t.theme_id),
                "theme {} is in two links results",
                t.theme_id
            );
            merged.themes.push(t);
        }
    }
    merged.themes.sort_by_key(|t| t.theme_id);
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atlas_links::graph::check_mirrors;
    use crate::atlas_meaning::tree::{check_tree, parse_map_key};
    use epigraph_db::repos::atlas_map::AtlasHierarchy;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/atlas_links")
    }

    fn scratch() -> PathBuf {
        use std::os::unix::fs::DirBuilderExt;
        let d = std::env::temp_dir().join(format!("atlas-links-{}", Uuid::new_v4()));
        std::fs::DirBuilder::new().mode(0o700).create(&d).unwrap();
        d
    }

    fn read_floats(path: &Path) -> Vec<f32> {
        std::fs::read(path)
            .unwrap()
            .as_chunks::<4>()
            .0
            .iter()
            .map(|b| f32::from_le_bytes(*b))
            .collect()
    }

    fn theme_file(dir: &Path, theme: Uuid) -> LinksThemeFile {
        serde_json::from_slice(&std::fs::read(dir.join(format!("{theme}.json"))).unwrap()).unwrap()
    }

    /// The committed export (written by the Python fixture generator) is
    /// byte for byte what this writer writes from the same content, so the
    /// Python reader reads what the box writes; the unlinked claims'
    /// embeddings are not in it.
    #[test]
    fn the_writer_reproduces_the_committed_export_bytes() {
        let src = fixture().join("export");
        let index: LinksExportIndex =
            serde_json::from_slice(&std::fs::read(src.join("export.json")).unwrap()).unwrap();
        assert_eq!(index.format, EXPORT_FORMAT);
        let out = scratch();
        for t in &index.themes {
            let file = theme_file(&src, t.theme_id);
            let floats = read_floats(&src.join(format!("{}.f32", t.theme_id)));
            let linked = file.linked();
            assert_eq!(linked.len(), t.linked);
            assert_eq!(floats.len(), linked.len() * index.dim);
            // One row per claim; an unlinked claim's row is a marker that
            // must not be written.
            let mut rows = vec![vec![f32::NAN; index.dim]; file.claim_ids.len()];
            for (k, i) in linked.iter().enumerate() {
                rows[*i] = floats[k * index.dim..(k + 1) * index.dim].to_vec();
            }
            write_links_theme(&out, t.theme_id, &file, &rows, index.dim).unwrap();
            for ext in ["json", "f32"] {
                let name = format!("{}.{ext}", t.theme_id);
                assert_eq!(
                    std::fs::read(out.join(&name)).unwrap(),
                    std::fs::read(src.join(&name)).unwrap(),
                    "{name}"
                );
                let mode = std::fs::metadata(out.join(&name))
                    .unwrap()
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o600, "{name}");
            }
        }
        write_links_index(&out, &index).unwrap();
        assert_eq!(
            std::fs::read(out.join("export.json")).unwrap(),
            std::fs::read(src.join("export.json")).unwrap()
        );
        assert!(write_links_index(&out, &index).is_err(), "never overwrites");
        std::fs::remove_dir_all(&out).ok();
    }

    /// The committed result (computed by the Python core from the committed
    /// export) passes the Rust tree check and the mirror rule: both languages
    /// mint the same ids and agree on the mirrors.
    #[test]
    fn the_committed_result_passes_the_rust_checks() {
        let result = read_links_result(&fixture().join("result.json")).unwrap();
        let map = parse_map_key(&result.map).unwrap();
        for t in &result.themes {
            let file = theme_file(&fixture().join("export"), t.theme_id);
            let members: BTreeSet<Uuid> = file.claim_ids.iter().copied().collect();
            let tree =
                check_tree(map, AtlasHierarchy::Links, t.theme_id, &t.groups, &members).unwrap();
            assert!(tree.nodes.iter().any(|n| n.depth == 2), "the fixture nests");
            let linked: BTreeSet<Uuid> = file
                .linked()
                .into_iter()
                .map(|i| file.claim_ids[i])
                .collect();
            // Stand-in meaning leaf ids: one per meaning-leaf integer.
            let meaning: BTreeMap<Uuid, Uuid> = file
                .claim_ids
                .iter()
                .zip(&file.meaning_leaf)
                .map(|(c, m)| (*c, Uuid::from_u128(u128::from(*m) + 1)))
                .collect();
            assert_eq!(check_mirrors(&tree, &linked, &meaning).unwrap(), 3);
        }
    }

    #[test]
    fn a_links_result_with_arbitrary_versions_or_format_is_refused() {
        let committed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fixture().join("result.json")).unwrap()).unwrap();
        let mut bad = Vec::new();
        for v in [
            serde_json::json!({"networkx": "3.6.1", "note": "x"}),
            serde_json::json!({"networkx": "3.6 <b>"}),
            serde_json::json!({"networkx": "1".repeat(MAX_VERSION_LEN + 1)}),
        ] {
            let mut d = committed.clone();
            d["versions"] = v;
            bad.push(d);
        }
        let mut d = committed.clone();
        d["format"] = serde_json::json!("atlas-meaning-result/1");
        bad.push(d);
        for doc in bad {
            let path = std::env::temp_dir().join(format!("atlas-links-{}.json", Uuid::new_v4()));
            std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
            assert!(read_links_result(&path).is_err(), "{doc}");
            std::fs::remove_file(&path).ok();
        }
    }

    #[test]
    fn batched_links_results_merge_only_when_they_agree() {
        let mut a = read_links_result(&fixture().join("result.json")).unwrap();
        let mut b = a.clone();
        b.themes[0].theme_id = Uuid::from_u128(1);
        a.themes[0].theme_id = Uuid::from_u128(2);
        let merged = merge_links_results(vec![a.clone(), b.clone()]).unwrap();
        let ids: Vec<Uuid> = merged.themes.iter().map(|t| t.theme_id).collect();
        assert_eq!(ids, vec![Uuid::from_u128(1), Uuid::from_u128(2)]);
        assert!(merge_links_results(vec![a.clone(), a.clone()]).is_err());
        let mut other = b;
        other.versions.networkx = Some("3.5".to_string());
        assert!(merge_links_results(vec![a, other]).is_err());
    }
}
