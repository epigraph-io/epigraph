//! Static ratchets over the workspace's embedding stack.
//!
//! The workspace once carried three independent OpenAI embedding clients
//! (this crate's `OpenAiProvider`, `epigraph-mcp`'s hand-rolled `McpEmbedder`
//! call and an unused `epigraph-engine::embedder`), and they disagreed on
//! truncation, retry and disabled mode, so the same claim was embedded on one
//! surface and left NULL on another (backlog ef32cdeb, 052fe5b0). These tests
//! read the source tree, need no network and no database, and fail the moment
//! a second client, or another dead seam this crate used to export, comes back.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

/// Every `.rs` file under `crates/*/src`, as (workspace-relative path, text).
/// Integration tests (`crates/*/tests`) are excluded: they may talk about the
/// endpoint, they never ship.
fn production_sources() -> Vec<(String, String)> {
    let root = workspace_root();
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = std::fs::read_dir(root.join("crates"))
        .expect("read crates/")
        .filter_map(Result::ok)
        .map(|e| e.path().join("src"))
        .filter(|p| p.is_dir())
        .collect();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|x| x == "rs") {
                let text = std::fs::read_to_string(&path).expect("read source");
                let rel = path
                    .strip_prefix(&root)
                    .expect("under root")
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, text));
            }
        }
    }
    assert!(
        out.len() > 100,
        "CALIBRATION: the walk found only {} source files; it is not reading the workspace",
        out.len()
    );
    out
}

/// `epigraph-engine` carries no embedding client of its own: its recall path
/// takes `&dyn EmbeddingService`, and the `Embedder`/`OpenAiEmbedder` pair it
/// used to define had no caller anywhere (backlog 052fe5b0).
#[test]
fn the_engine_defines_no_embedding_client() {
    let offenders: Vec<String> = production_sources()
        .into_iter()
        .filter(|(path, _)| path.starts_with("crates/epigraph-engine/"))
        .filter(|(_, text)| {
            text.contains("struct OpenAiEmbedder")
                || text.contains("trait Embedder")
                || text.contains("pub mod embedder;")
        })
        .map(|(path, _)| path)
        .collect();
    assert!(
        offenders.is_empty(),
        "epigraph-engine grew an embedding client again: {offenders:?}; use \
         epigraph_embeddings::EmbeddingService"
    );
}
