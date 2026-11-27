//! The `table_graph` command line.
//!
//! Its own module so the tests can parse it (`#[path]`-included, like the
//! other modules they exercise). Nothing here names another module.

use clap::{Args, Parser, Subcommand};
use std::path::Path;

#[derive(Parser, Debug)]
#[command(name = "table_graph")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Discover tables and crates; print a JSON listing.
    Discover {
        #[command(flatten)]
        roots: Roots,
    },
    /// Build dossiers + run LLM extraction; write staging files.
    Extract {
        #[command(flatten)]
        roots: Roots,
        #[arg(long)]
        only: Option<String>,
    },
    /// Ingest staged narratives via extract-claims + ingest_document.
    Ingest {
        #[arg(long)]
        dry_run: bool,
        /// Filter to a single table name (matches all repos that contain it).
        #[arg(long)]
        only: Option<String>,
    },
    /// Verification queries.
    Verify,
}

/// The two checkouts `discover` and `extract` read. Both are required: there
/// is no default checkout location, so a run names the trees it describes.
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct Roots {
    /// Root of the epigraph checkout; its `migrations/` and `crates/` are read.
    #[arg(long, value_name = "DIR")]
    pub epigraph_root: String,
    /// Root of the episcience checkout; its `migrations/` (minus the vendored
    /// `upstream/` copy of epigraph's schema) and `crates/` are read.
    #[arg(long, value_name = "DIR")]
    pub episcience_root: String,
}

/// episcience vendors epigraph's schema under `migrations/upstream/`; those
/// tables belong to epigraph, so that subdirectory is skipped.
const EPISCIENCE_SKIPS: &[&str] = &["upstream"];
const NO_SKIPS: &[&str] = &[];

impl Roots {
    /// The checkout root of `repo`, or `None` for a repository not named here.
    pub fn repo_root(&self, repo: &str) -> Option<&str> {
        match repo {
            "epigraph" => Some(&self.epigraph_root),
            "episcience" => Some(&self.episcience_root),
            _ => None,
        }
    }

    /// `[(repo, <root>/migrations, skipped subdirectories)]` for the scan.
    pub fn migration_dirs(&self) -> Vec<(&'static str, String, &'static [&'static str])> {
        vec![
            (
                "epigraph",
                join(&self.epigraph_root, "migrations"),
                NO_SKIPS,
            ),
            (
                "episcience",
                join(&self.episcience_root, "migrations"),
                EPISCIENCE_SKIPS,
            ),
        ]
    }

    /// `[(repo, <root>/crates)]` for the crate scan.
    pub fn crate_dirs(&self) -> Vec<(&'static str, String)> {
        vec![
            ("epigraph", join(&self.epigraph_root, "crates")),
            ("episcience", join(&self.episcience_root, "crates")),
        ]
    }
}

/// `root/sub`. Both halves are `String`s (always UTF-8), so the lossy
/// conversion never replaces anything.
pub fn join(root: &str, sub: &str) -> String {
    Path::new(root).join(sub).to_string_lossy().into_owned()
}
