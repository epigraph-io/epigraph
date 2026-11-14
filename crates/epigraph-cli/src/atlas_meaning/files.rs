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
//!
//! Embeddings approximate claim text, so the export is OWNER-ONLY from the
//! moment it exists, whatever the umask: [`prepare_export_dir`] creates the
//! directory 0700 (or accepts an existing one only when it is empty and has
//! no group or other bits), and every file is created new with mode 0600.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
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

/// Make `dir` ready for an export, owner-only: a path that does not exist is
/// created (not recursively) with mode 0700; an existing one must be a real
/// directory (not a symlink), empty, with no group or other permission bits.
/// An operator's directory is never chmod-ed: a readable one is refused.
///
/// # Errors
/// A non-directory, a non-empty or group/other-accessible directory, or an
/// I/O error.
pub fn prepare_export_dir(dir: &Path) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::DirBuilder::new()
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("create the export directory {}", dir.display())),
        Err(e) => Err(e).with_context(|| format!("stat {}", dir.display())),
        Ok(meta) => {
            ensure!(
                meta.is_dir(),
                "{} is not a directory (a symlink is refused too)",
                dir.display()
            );
            let mode = meta.permissions().mode() & 0o777;
            ensure!(
                mode & 0o077 == 0,
                "{} has mode {mode:o}: the export holds embeddings, which approximate claim \
                 text, so it must be owner-only; pass a new path (created 0700) or chmod 700",
                dir.display()
            );
            ensure!(
                std::fs::read_dir(dir)
                    .with_context(|| format!("read {}", dir.display()))?
                    .next()
                    .is_none(),
                "{} is not empty",
                dir.display()
            );
            Ok(())
        }
    }
}

/// Create `path` new (never overwrite, never follow a planted file) with
/// mode 0600 and write `bytes`.
fn write_owner_only(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .with_context(|| format!("write {}", path.display()))
}

/// Write one theme's two files into `dir`, each created new with mode 0600.
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
pub fn write_index(dir: &Path, index: &ExportIndex) -> anyhow::Result<()> {
    write_owner_only(&dir.join("export.json"), &serde_json::to_vec(index)?)
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

/// Merge the results of a batched export (one `compute` per `--theme-id`
/// batch) into the one result an apply takes: every file must be for the same
/// map, hierarchy, cap and seed, computed with the same library versions (ids
/// persist only while the clustering reproduces), and no theme may appear
/// twice. The themes come out sorted by id. One result is returned as is.
///
/// # Errors
/// No result, a mismatch, or a theme in two results.
pub fn merge_results(results: Vec<ResultDoc>) -> anyhow::Result<ResultDoc> {
    let mut it = results.into_iter();
    let mut merged = it.next().context("no result to apply")?;
    let mut seen: std::collections::BTreeSet<Uuid> = std::collections::BTreeSet::new();
    for t in &merged.themes {
        ensure!(
            seen.insert(t.theme_id),
            "theme {} is in a result twice",
            t.theme_id
        );
    }
    for r in it {
        ensure!(
            (&r.format, &r.map, &r.hierarchy, r.cap, r.seed)
                == (
                    &merged.format,
                    &merged.map,
                    &merged.hierarchy,
                    merged.cap,
                    merged.seed
                ),
            "results differ in format, map, hierarchy, cap or seed: ({}, {}, {}, {}, {}) and \
             ({}, {}, {}, {}, {})",
            merged.format,
            merged.map,
            merged.hierarchy,
            merged.cap,
            merged.seed,
            r.format,
            r.map,
            r.hierarchy,
            r.cap,
            r.seed
        );
        ensure!(
            r.versions == merged.versions,
            "results were computed with different library versions: {:?} and {:?}",
            merged.versions,
            r.versions
        );
        for t in r.themes {
            ensure!(
                seen.insert(t.theme_id),
                "theme {} is in two results",
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

    fn scratch() -> PathBuf {
        std::env::temp_dir().join(format!("atlas-meaning-{}", Uuid::new_v4()))
    }

    /// A new export directory is created owner-only; an existing one is
    /// accepted only empty and owner-only, never chmod-ed.
    #[test]
    fn the_export_directory_must_be_owner_only_and_empty() {
        let new = scratch();
        prepare_export_dir(&new).unwrap();
        let mode = std::fs::metadata(&new).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "created {mode:o}");

        let open = scratch();
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = prepare_export_dir(&open).unwrap_err().to_string();
        assert!(err.contains("owner-only"), "{err}");
        let mode = std::fs::metadata(&open).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "the operator's directory was changed");

        std::fs::write(new.join("stray"), b"x").unwrap();
        let err = prepare_export_dir(&new).unwrap_err().to_string();
        assert!(err.contains("not empty"), "{err}");

        let link = scratch();
        std::os::unix::fs::symlink(&open, &link).unwrap();
        assert!(prepare_export_dir(&link).is_err(), "a symlink is refused");
        for d in [&new, &open] {
            std::fs::remove_dir_all(d).ok();
        }
        std::fs::remove_file(&link).ok();
    }

    /// Every export file is created 0600 and never overwrites one already
    /// there.
    #[test]
    fn export_files_are_created_new_and_owner_only() {
        let dir = scratch();
        prepare_export_dir(&dir).unwrap();
        let theme = Uuid::from_u128(7);
        let file = ThemeFile {
            claim_ids: vec![Uuid::from_u128(1)],
            attachments: vec![vec![]],
        };
        write_theme(&dir, theme, &file, &[vec![0.5, 0.25]], 2).unwrap();
        let index = ExportIndex {
            format: EXPORT_FORMAT.to_string(),
            map: "public".to_string(),
            hierarchy: "meaning".to_string(),
            cap: 100,
            seed: 42,
            dim: 2,
            themes: vec![],
        };
        write_index(&dir, &index).unwrap();
        for name in [
            format!("{theme}.json"),
            format!("{theme}.f32"),
            "export.json".into(),
        ] {
            let mode = std::fs::metadata(dir.join(&name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name}: {mode:o}");
        }
        assert!(
            write_index(&dir, &index).is_err(),
            "an existing file was overwritten"
        );
        std::fs::remove_dir_all(&dir).ok();
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

    fn split_fixture_result() -> (ResultDoc, ResultDoc) {
        let mut a = read_result(&fixture().join("result.json")).unwrap();
        let mut theme = a.themes[0].clone();
        theme.theme_id = Uuid::from_u128(1);
        let mut b = a.clone();
        b.themes = vec![theme];
        a.themes[0].theme_id = Uuid::from_u128(2);
        (a, b)
    }

    /// Batched results merge into one, themes sorted; a mismatch or a theme
    /// in two batches is refused.
    #[test]
    fn batch_results_merge_only_when_they_agree() {
        let (a, b) = split_fixture_result();
        let merged = merge_results(vec![a.clone(), b.clone()]).unwrap();
        let ids: Vec<Uuid> = merged.themes.iter().map(|t| t.theme_id).collect();
        assert_eq!(ids, vec![Uuid::from_u128(1), Uuid::from_u128(2)]);

        assert!(
            merge_results(vec![a.clone(), a.clone()]).is_err(),
            "a theme twice"
        );
        assert!(merge_results(vec![]).is_err());
        let mut other = b.clone();
        other.seed += 1;
        assert!(merge_results(vec![a.clone(), other]).is_err(), "seed");
        let mut other = b.clone();
        other.cap -= 1;
        assert!(merge_results(vec![a.clone(), other]).is_err(), "cap");
        let mut other = b.clone();
        other.map = "public".to_string();
        assert!(merge_results(vec![a.clone(), other]).is_err(), "map");
        let mut other = b;
        other.versions = serde_json::json!({"numpy": "0.0.1"});
        assert!(merge_results(vec![a, other]).is_err(), "versions");
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
