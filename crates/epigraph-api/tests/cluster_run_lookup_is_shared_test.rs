//! Every graph `expand` route must resolve "the latest cluster run" through
//! `ClusterRunRepository::latest`, never through its own inlined SQL.
//!
//! This is a source-level test on purpose. The two lookups are *currently*
//! byte-identical SQL, so no request can tell them apart — which is exactly
//! why an inlined copy is dangerous rather than harmless: it will not fail a
//! behavioural test on the day someone changes the shared one (adds the
//! `algo` filter migration 028 invites, or a tie-break on `run_id`), and the
//! first symptom is `GET /claims/:id/placement` handing out a
//! `neighborhood_id` that `GET /themes/:id/expand` no longer recognises.
//! `repos/cluster_run.rs`'s module doc asserts this invariant in prose; this
//! test is what makes the prose true.
//!
//! Scope is deliberately narrow: the two route modules that serve the expand
//! family. `routes/clusters.rs` writes and prunes `graph_cluster_runs` rows
//! and legitimately names the table; it is not in scope here.
//!
//! The source is read through `lint_text::strip_comments`, the same helper
//! `no_redaction_sentinel.rs` uses. A raw `contains` failed on both files even
//! after a perfect refactor, because each names `graph_cluster_runs` in a
//! comment EXPLAINING that the table carries no tenancy columns — prose the
//! lint has no business forbidding.

use std::path::PathBuf;

mod lint_text;
use lint_text::strip_comments;

/// The route modules that must not know the shape of `graph_cluster_runs`.
const EXPAND_ROUTE_FILES: &[&str] = &["src/routes/graph.rs", "src/routes/graph_neighborhood.rs"];

/// Handlers that resolve the latest run, as `(file, fn signature prefix)`.
const RUN_RESOLVING_HANDLERS: &[(&str, &str)] = &[
    ("src/routes/graph.rs", "pub async fn overview("),
    ("src/routes/graph.rs", "pub async fn expand("),
    ("src/routes/graph.rs", "pub async fn themes_expand("),
    ("src/routes/graph_neighborhood.rs", "pub async fn expand("),
];

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The text of one function, from its signature to the next top-level item.
fn body_of(src: &str, signature: &str) -> String {
    let start = src
        .find(signature)
        .unwrap_or_else(|| panic!("`{signature}` not found — was the handler renamed?"));
    let rest = &src[start + signature.len()..];
    let end = ["\npub ", "\nfn ", "\nasync fn ", "\n#[", "\n/// "]
        .iter()
        .filter_map(|marker| rest.find(marker))
        .min()
        .unwrap_or(rest.len());
    rest[..end].to_string()
}

#[test]
fn no_expand_route_inlines_the_latest_run_lookup() {
    for file in EXPAND_ROUTE_FILES {
        let src = strip_comments(&read(file));
        assert!(
            !src.contains("graph_cluster_runs"),
            "{file} still names `graph_cluster_runs` in its own SQL. The latest-run \
             lookup belongs to `ClusterRunRepository::latest` (crates/epigraph-db/\
             src/repos/cluster_run.rs) so this route cannot drift from \
             `GET /claims/:id/placement`, which hands out the ids it must accept."
        );
    }
}

#[test]
fn every_run_resolving_handler_calls_the_shared_lookup() {
    for (file, signature) in RUN_RESOLVING_HANDLERS {
        let body = body_of(&strip_comments(&read(file)), signature);
        assert!(
            body.contains("ClusterRunRepository::latest"),
            "{file} `{signature}` does not call `ClusterRunRepository::latest`; \
             it must not resolve the latest run any other way"
        );
        assert!(
            !body.contains("completed_at DESC"),
            "{file} `{signature}` orders by `completed_at DESC` itself — that \
             ordering IS the latest-run lookup, and it lives in the repo"
        );
    }
}
