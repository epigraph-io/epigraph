//! The two files that cross the box boundary, shared with
//! `scripts/atlas_meaning_core.py` (which documents them in full):
//!
//! * the EXPORT the box writes: `export.json` ([`ExportIndex`]), and per theme
//!   `<theme_id>.json` (claim ids and per-claim attachment indices) and
//!   `<theme_id>.f32` (the embeddings as raw little-endian float32, in claim
//!   id order). Claim ids, embeddings and integers only: no agent or evidence
//!   id, no text, no tenancy;
//! * the RESULT the box reads back ([`ResultDoc`]).
//!
//! The JSON is compact, keys in the order Python writes them, so the Rust
//! writer and `atlas_meaning_core.write_export` produce the same bytes
//! (`tests/fixtures/atlas_meaning`).

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{ensure, Context};
use epigraph_db::repos::atlas_leaf::LeafNode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::tree::WireGroup;

pub const EXPORT_FORMAT: &str = "atlas-meaning-export/1";
pub const RESULT_FORMAT: &str = "atlas-meaning-result/1";

/// `export.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportIndex {
    pub format: String,
    /// `public` or `team:<uuid>` ([`super::tree::map_key`]).
    pub map: String,
    pub hierarchy: String,
    pub cap: usize,
    pub seed: u64,
    pub dim: usize,
    pub themes: Vec<ExportTheme>,
}

/// One theme's entry in `export.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportTheme {
    pub theme_id: Uuid,
    pub claims: usize,
    /// Distinct attachment nodes over the theme's claims.
    pub attachment_nodes: usize,
}

/// `<theme_id>.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThemeFile {
    pub claim_ids: Vec<Uuid>,
    /// Per claim, in `claim_ids` order: its attachment nodes as indices into
    /// this theme's numbering, sorted.
    pub attachments: Vec<Vec<u32>>,
}

/// Renumber each claim's attachment nodes (W3's
/// `claim_attachments`) as small integers: every distinct node of the theme,
/// sorted by (kind, id), gets its position. Returns the theme file (claims
/// sorted) and the number of distinct nodes. The numbering is per theme, so
/// two themes' files cannot be joined on it.
///
/// # Errors
/// More than `u32::MAX` distinct nodes.
pub fn index_attachments(
    attachments: &BTreeMap<Uuid, Vec<LeafNode>>,
) -> anyhow::Result<(ThemeFile, usize)> {
    let mut numbering: BTreeMap<LeafNode, u32> = BTreeMap::new();
    for n in attachments.values().flatten() {
        numbering.insert(*n, 0);
    }
    for (i, v) in numbering.values_mut().enumerate() {
        *v = u32::try_from(i)?;
    }
    let mut file = ThemeFile {
        claim_ids: Vec::with_capacity(attachments.len()),
        attachments: Vec::with_capacity(attachments.len()),
    };
    for (claim, nodes) in attachments {
        let mut idx: Vec<u32> = nodes.iter().map(|n| numbering[n]).collect();
        idx.sort_unstable();
        idx.dedup();
        file.claim_ids.push(*claim);
        file.attachments.push(idx);
    }
    Ok((file, numbering.len()))
}

/// Write one theme's two files into `dir`.
///
/// # Errors
/// An embedding of another dimension, or an I/O error.
pub fn write_theme(
    dir: &Path,
    theme_id: Uuid,
    file: &ThemeFile,
    embeddings: &[Vec<f32>],
    dim: usize,
) -> anyhow::Result<()> {
    ensure!(
        embeddings.len() == file.claim_ids.len() && file.attachments.len() == file.claim_ids.len(),
        "theme {theme_id}: {} embeddings and {} attachment lists for {} claims",
        embeddings.len(),
        file.attachments.len(),
        file.claim_ids.len()
    );
    let mut raw = Vec::with_capacity(embeddings.len() * dim * 4);
    for (claim, e) in file.claim_ids.iter().zip(embeddings) {
        ensure!(
            e.len() == dim,
            "claim {claim} has a {}-d embedding, not {dim}-d",
            e.len()
        );
        for v in e {
            raw.extend_from_slice(&v.to_le_bytes());
        }
    }
    let json = dir.join(format!("{theme_id}.json"));
    std::fs::write(&json, serde_json::to_vec(file)?)
        .with_context(|| format!("write {}", json.display()))?;
    let f32s = dir.join(format!("{theme_id}.f32"));
    std::fs::write(&f32s, raw).with_context(|| format!("write {}", f32s.display()))?;
    Ok(())
}

/// Write `export.json` into `dir`.
///
/// # Errors
/// An I/O error.
pub fn write_index(dir: &Path, index: &ExportIndex) -> anyhow::Result<()> {
    let path = dir.join("export.json");
    std::fs::write(&path, serde_json::to_vec(index)?)
        .with_context(|| format!("write {}", path.display()))
}

/// The result file `atlas_meaning_core.py compute` writes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultDoc {
    pub format: String,
    pub map: String,
    pub hierarchy: String,
    pub cap: usize,
    pub seed: u64,
    /// numpy, scikit-learn, umap-learn and python versions of the compute
    /// host: ids persist across runs only while the clustering reproduces.
    pub versions: serde_json::Value,
    pub themes: Vec<ResultTheme>,
}

/// One theme of a result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultTheme {
    pub theme_id: Uuid,
    /// Cuts that followed claim-id order because the vectors were identical.
    pub id_chunk_cuts: u32,
    pub groups: Vec<WireGroup>,
}

/// Read and parse a result file.
///
/// # Errors
/// An I/O error, a parse error, or another format.
pub fn read_result(path: &Path) -> anyhow::Result<ResultDoc> {
    let text = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let doc: ResultDoc =
        serde_json::from_slice(&text).with_context(|| format!("parse {}", path.display()))?;
    ensure!(
        doc.format == RESULT_FORMAT,
        "{} is not a {RESULT_FORMAT} result: {:?}",
        path.display(),
        doc.format
    );
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atlas_meaning::tree::{check_tree, parse_map_key};
    use epigraph_db::repos::atlas_map::AtlasHierarchy;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/atlas_meaning")
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

    /// The committed export (written by the Python fixture generator) is
    /// byte for byte what this writer writes from the same content, so the
    /// Python reader reads what the box writes.
    #[test]
    fn the_writer_reproduces_the_committed_export_bytes() {
        let src = fixture().join("export");
        let index: ExportIndex =
            serde_json::from_slice(&std::fs::read(src.join("export.json")).unwrap()).unwrap();
        assert_eq!(index.format, EXPORT_FORMAT);
        let out = std::env::temp_dir().join(format!("atlas-meaning-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&out).unwrap();
        for t in &index.themes {
            let file: ThemeFile = serde_json::from_slice(
                &std::fs::read(src.join(format!("{}.json", t.theme_id))).unwrap(),
            )
            .unwrap();
            let floats = read_floats(&src.join(format!("{}.f32", t.theme_id)));
            let embeddings: Vec<Vec<f32>> = floats.chunks(index.dim).map(<[f32]>::to_vec).collect();
            write_theme(&out, t.theme_id, &file, &embeddings, index.dim).unwrap();
            for ext in ["json", "f32"] {
                let name = format!("{}.{ext}", t.theme_id);
                assert_eq!(
                    std::fs::read(out.join(&name)).unwrap(),
                    std::fs::read(src.join(&name)).unwrap(),
                    "{name}"
                );
            }
        }
        write_index(&out, &index).unwrap();
        assert_eq!(
            std::fs::read(out.join("export.json")).unwrap(),
            std::fs::read(src.join("export.json")).unwrap()
        );
        std::fs::remove_dir_all(&out).ok();
    }

    /// The committed result (computed by the Python core from the committed
    /// export) passes the Rust tree check: both languages mint the same ids
    /// over a real nested tree.
    #[test]
    fn the_committed_result_passes_the_rust_tree_check() {
        let result = read_result(&fixture().join("result.json")).unwrap();
        let map = parse_map_key(&result.map).unwrap();
        for t in &result.themes {
            let file: ThemeFile = serde_json::from_slice(
                &std::fs::read(fixture().join(format!("export/{}.json", t.theme_id))).unwrap(),
            )
            .unwrap();
            let members: BTreeSet<Uuid> = file.claim_ids.iter().copied().collect();
            let tree = check_tree(
                map,
                AtlasHierarchy::Meaning,
                t.theme_id,
                &t.groups,
                &members,
            )
            .unwrap();
            assert!(tree.nodes.iter().any(|n| n.depth == 2), "the fixture nests");
        }
    }

    #[test]
    fn attachments_are_numbered_per_theme_by_kind_then_id() {
        let a = Uuid::from_u128(5);
        let e = Uuid::from_u128(1);
        let mut att = BTreeMap::new();
        att.insert(
            Uuid::from_u128(20),
            vec![LeafNode::agent(a), LeafNode::evidence(e)],
        );
        att.insert(Uuid::from_u128(10), vec![LeafNode::agent(a)]);
        att.insert(Uuid::from_u128(30), vec![]);
        let (file, distinct) = index_attachments(&att).unwrap();
        assert_eq!(distinct, 2);
        assert_eq!(
            file.claim_ids,
            vec![
                Uuid::from_u128(10),
                Uuid::from_u128(20),
                Uuid::from_u128(30)
            ]
        );
        // Agents sort before evidence: the agent is 0 although its id is larger.
        assert_eq!(file.attachments, vec![vec![0], vec![0, 1], vec![]]);
        let text = String::from_utf8(serde_json::to_vec(&file).unwrap()).unwrap();
        assert!(!text.contains(&a.to_string()) && !text.contains(&e.to_string()));
    }

    #[test]
    fn a_result_of_another_format_is_refused() {
        let path = std::env::temp_dir().join(format!("atlas-meaning-{}.json", Uuid::new_v4()));
        let mut doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fixture().join("result.json")).unwrap()).unwrap();
        doc["format"] = serde_json::json!("theme-cap-result/1");
        std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
        assert!(read_result(&path).is_err());
        std::fs::remove_file(&path).ok();
    }
}
