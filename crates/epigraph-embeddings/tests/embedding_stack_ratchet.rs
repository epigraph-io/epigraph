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

/// Every cargo feature this crate declares gates something.
///
/// `local = []` claimed to "enable local embedding model support" while no
/// `cfg(feature = "local")` existed anywhere and `LocalProvider` (a hash stub,
/// not a model) was exported unconditionally (backlog 9785198e). An empty
/// feature is a promise the build does not keep.
#[test]
fn every_declared_feature_gates_code() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = std::fs::read_to_string(crate_dir.join("Cargo.toml")).expect("manifest");
    let features_table = manifest
        .split("\n[features]\n")
        .nth(1)
        .expect("a [features] table")
        .split("\n[")
        .next()
        .unwrap_or_default();
    let features: Vec<&str> = features_table
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, _)| k.trim()))
        .filter(|k| !k.is_empty() && !k.starts_with('#') && *k != "default")
        .collect();
    assert!(
        features.contains(&"openai"),
        "CALIBRATION: the [features] parse found {features:?}, not this crate's table"
    );
    let sources: String = production_sources()
        .into_iter()
        .filter(|(path, _)| path.starts_with("crates/epigraph-embeddings/"))
        .map(|(_, text)| text)
        .collect();
    let ungated: Vec<&str> = features
        .into_iter()
        .filter(|f| !sources.contains(&format!("feature = \"{f}\"")))
        .collect();
    assert!(
        ungated.is_empty(),
        "epigraph-embeddings declares features that gate no code: {ungated:?}"
    );
}

/// The hash stub that posed as a local model is gone from the public surface.
#[test]
fn no_local_provider_is_exported() {
    let offenders: Vec<String> = production_sources()
        .into_iter()
        .filter(|(_, text)| text.contains("LocalProvider"))
        .map(|(path, _)| path)
        .collect();
    assert!(
        offenders.is_empty(),
        "LocalProvider is a deterministic hash, not a model; use MockProvider in tests: \
         {offenders:?}"
    );
}

/// `EmbeddingService` generates vectors; it does not store or search them.
///
/// Its `store`/`get`/`similar` were refused by both real providers with a
/// `ConfigError` pointing at `EmbeddingRepository`, and that repository wrote
/// `claims.embedding` with no seal or tenancy check from outside `epigraph-db`.
/// A caller holding the trait therefore had a store method that silently
/// stored nothing in production: `decompose_claims` discarded the error with
/// `let _ = e.store(...)` (backlog ccc588d4). Vectors are stored through
/// `epigraph-db` (`ClaimRepository::store_embedding_if_unsealed` and friends).
#[test]
fn the_generation_trait_has_no_storage_methods() {
    let service =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/service.rs"))
            .expect("service.rs");
    let start = service
        .find("pub trait EmbeddingService:")
        .expect("the trait is defined in service.rs");
    let body = &service[start..];
    let end = body.find("\n}\n").expect("end of the trait body");
    let trait_body = &body[..end];
    assert!(
        trait_body.contains("async fn generate("),
        "CALIBRATION: did not isolate the EmbeddingService trait body"
    );
    let storage: Vec<&str> = ["fn store(", "fn get(", "fn similar("]
        .into_iter()
        .filter(|m| trait_body.contains(m))
        .collect();
    assert!(
        storage.is_empty(),
        "EmbeddingService declares storage methods {storage:?}; store vectors through epigraph-db"
    );

    let offenders: Vec<String> = production_sources()
        .into_iter()
        .filter(|(_, text)| {
            text.contains("EmbeddingRepository") || text.contains("EmbeddingServiceExt")
        })
        .map(|(path, _)| path)
        .collect();
    assert!(
        offenders.is_empty(),
        "the unscoped embedding repository or its generate_and_store extension is back: \
         {offenders:?}"
    );
}
