# EpiGraph Table Graph Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a self-describing graph of every DB table in `epigraph` and `episcience`, ingested into EpiGraph as **claims about the shape of the code** with greppable function-snippet evidence — so that future git-driven loops can flag and re-extract stale claims.

**Architecture:** A Rust example binary at `crates/epigraph-tools/examples/table_graph/` discovers tables, builds per-table dossiers (DDL + git context + grep call sites + FK), runs one Claude CLI call per table to produce a structured Markdown narrative, then for each narrative shells out to `extract-claims` → `mcp__epigraph__ingest_document`. All synthetic claims are authored by a dedicated `code-graph-extractor` Ed25519 signer. Single PR — no schema changes, no API allow-list extensions, no new entity types or edge relationships.

**Tech Stack:** Rust 2021, sqlx, tokio, serde, the existing Claude CLI (OAuth), the existing `extract-claims` skill, and the `mcp__epigraph__ingest_document` MCP tool.

**Spec:** `docs/superpowers/specs/2026-04-30-epigraph-table-graph-design.md`

---

## File Structure

**New files:**
- `crates/epigraph-tools/examples/table_graph/main.rs` — entry point dispatching to subcommands
- `crates/epigraph-tools/examples/table_graph/discover.rs` — migration + crate discovery
- `crates/epigraph-tools/examples/table_graph/dossier.rs` — DDL/git/grep/FK dossier builder
- `crates/epigraph-tools/examples/table_graph/llm.rs` — Claude CLI invoker + Markdown rendering
- `crates/epigraph-tools/examples/table_graph/ingest.rs` — extract-claims + ingest_document driver
- `crates/epigraph-tools/examples/table_graph/extract.rs` — extract subcommand orchestrator (separate from `dossier.rs` because `dossier.rs` is `#[path]`-included into the integration test crate, where sibling modules `discover` and `llm` are not visible)
- `crates/epigraph-tools/examples/table_graph/types.rs` — shared structs (`Dossier`, `StagingFile`)
- `crates/epigraph-tools/tests/table_graph_dossier_tests.rs` — unit tests on dossier components
- `crates/epigraph-tools/tests/table_graph_discover_tests.rs` — discovery integration tests (episcience cases marked `#[ignore]` because the upstream repo is not present in CI)
- `docs/superpowers/artifacts/2026-04-30-table-graph/.gitkeep` — directory marker
- `docs/superpowers/artifacts/2026-04-30-table-graph/README.md` — describes contents
- `docs/superpowers/artifacts/2026-04-30-table-graph/code-graph-extractor.pubkey` — Ed25519 public key (committed)

**Modified files:**
- `crates/epigraph-tools/Cargo.toml` — add `[[example]]` entry, deps
- `.gitignore` — exclude staging/ + narratives/ generated artifacts

---

## Task 1: Worktree + scaffold the example binary

**Files:**
- Modify: `crates/epigraph-tools/Cargo.toml`
- Create: `crates/epigraph-tools/examples/table_graph/main.rs`
- Create: `crates/epigraph-tools/examples/table_graph/types.rs`
- Create: `crates/epigraph-tools/examples/table_graph/discover.rs` (stub — `pub fn run() -> anyhow::Result<()> { todo!() }`)
- Create: `crates/epigraph-tools/examples/table_graph/dossier.rs` (stub)
- Create: `crates/epigraph-tools/examples/table_graph/llm.rs` (stub)
- Create: `crates/epigraph-tools/examples/table_graph/ingest.rs` (stub)
- Create: `crates/epigraph-tools/examples/table_graph/extract.rs` (stub — owns `pub fn run(only: Option<&str>) -> Result<()>` for the extract subcommand; does not live in `dossier.rs` because the integration tests `#[path]`-include `dossier.rs` and would fail to resolve sibling `discover`/`llm` modules)

- [ ] **Step 1.1: New worktree**

```bash
cd /home/jeremy/epigraph
git fetch origin
git worktree add /home/jeremy/epigraph-wt-table-graph -b feat/table-graph origin/main
cd /home/jeremy/epigraph-wt-table-graph
```

- [ ] **Step 1.2: Add `[[example]]` entry to `Cargo.toml`**

Open `crates/epigraph-tools/Cargo.toml`. Append after existing `[dependencies]`:

```toml
[[example]]
name = "table_graph"
path = "examples/table_graph/main.rs"
```

Add (under `[dependencies]`) any of these missing — most are already in the workspace:

```toml
clap = { workspace = true, features = ["derive"] }
sha2 = { workspace = true }
walkdir = "2"
regex = "1"
hex = "0.4"
anyhow = { workspace = true }
```

If `walkdir`, `regex`, or `hex` are not in the workspace `Cargo.toml`, add them at the workspace level too.

- [ ] **Step 1.3: Create `types.rs`**

Create `crates/epigraph-tools/examples/table_graph/types.rs`:

```rust
//! Shared data structures for the table_graph example binary.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableRef {
    pub repo: String,        // "epigraph" | "episcience"
    pub name: String,        // table name
    pub migration: String,   // relative path of the migration that created it
}

impl TableRef {
    pub fn synthetic_doi(&self) -> String {
        format!("urn:epigraph-table:{}:{}", self.repo, self.name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateRef {
    pub repo: String,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    WritesTo,
    ReadsFrom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    pub crate_name: String,
    pub function: String,
    pub snippet: String,
    pub kind: CallKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitCommit {
    pub sha: String,
    pub date: String,
    pub subject: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dossier {
    pub table: TableRef,
    pub ddl: String,
    pub commits: Vec<GitCommit>,
    pub call_sites: Vec<CallSite>,
    pub fk_targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagingFile {
    pub dossier: Dossier,
    pub narrative_md: String,
    pub content_hash: String,         // sha256 of dossier + narrative
}
```

- [ ] **Step 1.4: Create `main.rs` with subcommand dispatch**

```rust
//! Table-graph extraction and ingestion driver.

mod discover;
mod dossier;
mod ingest;
mod llm;
mod types;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "table_graph")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Discover tables and crates; print a JSON listing.
    Discover,
    /// Build dossiers + run LLM extraction; write staging files.
    Extract { #[arg(long)] only: Option<String> },
    /// Ingest staged narratives via extract-claims + ingest_document.
    Ingest { #[arg(long)] dry_run: bool },
    /// Verification queries.
    Verify,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Discover => discover::run(),
        Cmd::Extract { only } => dossier::run(only.as_deref()),
        Cmd::Ingest { dry_run } => ingest::run(dry_run),
        Cmd::Verify => ingest::verify(),
    }
}
```

- [ ] **Step 1.5: Create stub modules**

Each of `discover.rs`, `dossier.rs`, `llm.rs`, `ingest.rs`:

```rust
//! Stub — implemented in later tasks.
use anyhow::Result;

pub fn run(/* args from main.rs as needed */) -> Result<()> {
    todo!("filled in by later tasks")
}
```

For `dossier.rs`, the signature is `pub fn run(_only: Option<&str>) -> Result<()>`.
For `ingest.rs`, both `pub fn run(_dry_run: bool) -> Result<()>` and `pub fn verify() -> Result<()>`.

- [ ] **Step 1.6: Build & verify**

```bash
cargo build -p epigraph-tools --example table_graph
```

Expected: clean build (modules contain `todo!()` but compile).

- [ ] **Step 1.7: Commit**

```bash
git add crates/epigraph-tools/Cargo.toml crates/epigraph-tools/examples/table_graph/
git commit -m "scaffold: table_graph example binary skeleton"
```

---

## Task 2: Generate `code-graph-extractor` Ed25519 keypair

**Files:**
- Create: `docs/superpowers/artifacts/2026-04-30-table-graph/code-graph-extractor.pubkey` (committed)
- Local-only: `~/.config/epigraph/code-graph-extractor/signer.key` (NOT committed)

- [ ] **Step 2.1: Inspect available keygen options**

```bash
cargo run -p epigraph-cli -- --help 2>&1 | grep -i 'keygen\|sign'
```

If `epigraph-cli` has a `keygen` (or similar) subcommand, use it. If not, write a minimal one-off Rust example:

```bash
mkdir -p /tmp/keygen && cat > /tmp/keygen/Cargo.toml <<'TOML'
[package]
name = "keygen"
version = "0.0.1"
edition = "2021"
[dependencies]
ed25519-dalek = "2"
rand = "0.8"
hex = "0.4"
TOML

cat > /tmp/keygen/src/main.rs <<'RUST'
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
fn main() {
    let sk = SigningKey::generate(&mut OsRng);
    let path = std::env::args().nth(1).unwrap_or("signer.key".into());
    std::fs::write(&path, sk.to_bytes()).unwrap();
    let pk = sk.verifying_key();
    println!("{}", hex::encode(pk.to_bytes()));
}
RUST
mkdir -p /tmp/keygen/src
cargo run --manifest-path /tmp/keygen/Cargo.toml -- /tmp/code-graph-extractor.signer
```

- [ ] **Step 2.2: Move private key to its permanent home + capture public key**

```bash
mkdir -p ~/.config/epigraph/code-graph-extractor
mv /tmp/code-graph-extractor.signer ~/.config/epigraph/code-graph-extractor/signer.key
chmod 600 ~/.config/epigraph/code-graph-extractor/signer.key
```

Save the printed hex pubkey:

```bash
mkdir -p docs/superpowers/artifacts/2026-04-30-table-graph
echo "<paste-hex-pubkey-from-step-2.1>" > docs/superpowers/artifacts/2026-04-30-table-graph/code-graph-extractor.pubkey
```

- [ ] **Step 2.3: Document agent registration**

The MCP server auto-registers an agent on first signed request via `crates/epigraph-mcp/src/server.rs::agent_id` (which calls `AgentRepository::get_by_public_key`, then constructs an `Agent` if not found). **Important:** the label is hard-coded to `"mcp-agent"` in `server.rs` — there is no path that mints a row labeled `code-graph-extractor`. The pinned pubkey still serves as documentation of which key is meant to be used for this work, but downstream filters MUST discriminate via the synthetic DOI prefix `urn:epigraph-table:` (and/or claim labels), NOT via the agent label.

- [ ] **Step 2.4: Commit the public key**

```bash
git add docs/superpowers/artifacts/2026-04-30-table-graph/code-graph-extractor.pubkey
git commit -m "chore: pin code-graph-extractor agent pubkey"
```

The private key stays in `~/.config/epigraph/code-graph-extractor/signer.key` and is referenced via env var (`EPIGRAPH_SIGNING_KEY` or whatever the MCP server expects — confirm in `epigraph-mcp` startup) at run time. **Do not commit the private key.**

---

## Task 3: Artifact directory + .gitignore

**Files:**
- Create: `docs/superpowers/artifacts/2026-04-30-table-graph/README.md`
- Create: `docs/superpowers/artifacts/2026-04-30-table-graph/.gitkeep`
- Modify: `.gitignore`

- [ ] **Step 3.1: README**

Create `docs/superpowers/artifacts/2026-04-30-table-graph/README.md`:

```markdown
# Table Graph Artifacts

Generated by `cargo run -p epigraph-tools --example table_graph -- extract`.

Contents (gitignored — regenerable from the source repos):

- `staging/<table>.json` — per-table dossier + LLM narrative + content hash
- `narratives/<table>.md` — Markdown narrative consumed by `extract-claims`

The committed pieces are this README, `.gitkeep`, and `code-graph-extractor.pubkey`.
```

- [ ] **Step 3.2: gitignore**

Append to `.gitignore`:

```
# Table-graph generated artifacts (regenerable from source repos)
docs/superpowers/artifacts/2026-04-30-table-graph/staging/
docs/superpowers/artifacts/2026-04-30-table-graph/narratives/
```

- [ ] **Step 3.3: Commit**

```bash
touch docs/superpowers/artifacts/2026-04-30-table-graph/.gitkeep
git add docs/superpowers/artifacts/2026-04-30-table-graph/README.md \
        docs/superpowers/artifacts/2026-04-30-table-graph/.gitkeep \
        .gitignore
git commit -m "chore: artifact directory for table-graph extraction"
```

---

## Task 4: Migration scanner — list every table

**Files:**
- Modify: `crates/epigraph-tools/examples/table_graph/discover.rs` (replace stub)
- Create: `crates/epigraph-tools/tests/table_graph_discover_tests.rs`

- [ ] **Step 4.1: Failing test**

Create `crates/epigraph-tools/tests/table_graph_discover_tests.rs`:

```rust
#[path = "../examples/table_graph/discover.rs"]
mod discover;
#[path = "../examples/table_graph/types.rs"]
mod types;

use discover::scan_migrations;

#[test]
fn finds_claims_table_in_epigraph_initial_schema() {
    let tables = scan_migrations(&[
        ("epigraph", "/home/jeremy/epigraph/migrations", &[]),
    ]).unwrap();
    assert!(
        tables.iter().any(|t| t.name == "claims" && t.repo == "epigraph"),
        "expected to find epigraph.claims"
    );
}

#[test]
fn finds_synthesis_tables_in_episcience() {
    let tables = scan_migrations(&[
        ("episcience", "/home/jeremy/episcience/migrations", &["upstream"]),
    ]).unwrap();
    assert!(
        tables.iter().any(|t| t.name == "syntheses" && t.repo == "episcience"),
        "expected to find episcience.syntheses (from migrations/synthesis/)"
    );
}

#[test]
fn skips_episcience_upstream_directory() {
    let tables = scan_migrations(&[
        ("episcience", "/home/jeremy/episcience/migrations", &["upstream"]),
    ]).unwrap();
    assert!(
        !tables.iter().any(|t| t.name == "claims" && t.repo == "episcience"),
        "upstream/ should be skipped — claims belongs to epigraph only"
    );
}
```

- [ ] **Step 4.2: Run, expect fail**

```bash
cargo test -p epigraph-tools --test table_graph_discover_tests
```

- [ ] **Step 4.3: Implement**

Replace `crates/epigraph-tools/examples/table_graph/discover.rs`:

```rust
//! Discover tables (from migration SQL files) and crates (from Cargo workspaces).

use crate::types::{CrateRef, TableRef};
use anyhow::{Context, Result};
use regex::Regex;
use walkdir::WalkDir;

/// Scan migration directories. `repo_dirs` is `[(repo_name, abs_dir, skip_subdirs)]`.
pub fn scan_migrations(
    repo_dirs: &[(&str, &str, &[&str])],
) -> Result<Vec<TableRef>> {
    let create_re = Regex::new(
        r"(?im)^\s*CREATE\s+TABLE\s+(IF\s+NOT\s+EXISTS\s+)?(?:public\.)?(\w+)\s*\("
    ).expect("regex");
    let mut out = Vec::new();
    for (repo, dir, skips) in repo_dirs {
        for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() { continue; }
            if entry.path().extension().and_then(|s| s.to_str()) != Some("sql") {
                continue;
            }
            let rel = entry.path().strip_prefix(dir).unwrap_or(entry.path());
            if skips.iter().any(|s| rel.starts_with(s)) { continue; }
            let sql = std::fs::read_to_string(entry.path())
                .with_context(|| format!("read {}", entry.path().display()))?;
            for cap in create_re.captures_iter(&sql) {
                out.push(TableRef {
                    repo: (*repo).to_string(),
                    name: cap[2].to_string(),
                    migration: rel.to_string_lossy().into_owned(),
                });
            }
        }
    }
    out.sort_by(|a, b| (a.repo.clone(), a.name.clone(), a.migration.clone())
        .cmp(&(b.repo.clone(), b.name.clone(), b.migration.clone())));
    out.dedup_by(|a, b| a.repo == b.repo && a.name == b.name);
    Ok(out)
}

pub fn scan_crates(repo_dirs: &[(&str, &str)]) -> Result<Vec<CrateRef>> {
    let mut out = Vec::new();
    for (repo, dir) in repo_dirs {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() { continue; }
            if !entry.path().join("Cargo.toml").exists() { continue; }
            out.push(CrateRef {
                repo: (*repo).to_string(),
                name: entry.file_name().to_string_lossy().into_owned(),
            });
        }
    }
    out.sort_by(|a, b| (a.repo.clone(), a.name.clone()).cmp(&(b.repo.clone(), b.name.clone())));
    Ok(out)
}

pub fn run() -> Result<()> {
    let tables = scan_migrations(&[
        ("epigraph",   "/home/jeremy/epigraph/migrations",   &[]),
        ("episcience", "/home/jeremy/episcience/migrations", &["upstream"]),
    ])?;
    let crates = scan_crates(&[
        ("epigraph",   "/home/jeremy/epigraph/crates"),
        ("episcience", "/home/jeremy/episcience/crates"),
    ])?;
    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
        "tables": tables, "crates": crates,
        "table_count": tables.len(), "crate_count": crates.len(),
    }))?);
    Ok(())
}
```

- [ ] **Step 4.4: Run, expect pass**

```bash
cargo test -p epigraph-tools --test table_graph_discover_tests
```

- [ ] **Step 4.5: Smoke run**

```bash
cargo run -p epigraph-tools --example table_graph -- discover | head -40
```

Expected: JSON listing with `table_count` ≈ 85 and `crate_count` = 18.

- [ ] **Step 4.6: Commit**

```bash
git add crates/epigraph-tools/examples/table_graph/discover.rs \
        crates/epigraph-tools/tests/table_graph_discover_tests.rs
git commit -m "feat(table_graph): discover tables and crates"
```

---

## Task 5: DDL extractor

**Files:**
- Modify: `crates/epigraph-tools/examples/table_graph/dossier.rs`
- Create: `crates/epigraph-tools/tests/table_graph_dossier_tests.rs`

- [ ] **Step 5.1: Failing test**

Create `crates/epigraph-tools/tests/table_graph_dossier_tests.rs`:

```rust
#[path = "../examples/table_graph/dossier.rs"]
mod dossier;
#[path = "../examples/table_graph/types.rs"]
mod types;

use dossier::collect_ddl;

#[test]
fn ddl_for_claims_includes_create_table() {
    let ddl = collect_ddl("/home/jeremy/epigraph/migrations", "claims").unwrap();
    assert!(ddl.contains("CREATE TABLE"), "missing CREATE TABLE for claims");
    assert!(ddl.contains("claims"), "DDL should mention 'claims'");
}
```

- [ ] **Step 5.2: Run, expect fail**

```bash
cargo test -p epigraph-tools --test table_graph_dossier_tests
```

- [ ] **Step 5.3: Implement**

Replace the stub `dossier.rs`:

```rust
//! Per-table dossier: DDL, git context, call sites, FK targets.

use crate::types::*;
use anyhow::Result;
use regex::Regex;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

pub fn collect_ddl(migrations_dir: &str, table: &str) -> Result<String> {
    let mut buf = String::new();
    let mut paths: Vec<_> = WalkDir::new(migrations_dir)
        .into_iter().filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file()
            && e.path().extension().and_then(|s| s.to_str()) == Some("sql"))
        .map(|e| e.path().to_path_buf())
        .collect();
    paths.sort();
    let stmt_re = Regex::new(&format!(
        r"(?ims)\b(CREATE\s+TABLE|ALTER\s+TABLE|CREATE\s+INDEX|CREATE\s+TRIGGER)[^;]*\b{}\b[^;]*;",
        regex::escape(table)
    )).expect("regex");
    for p in paths {
        let sql = std::fs::read_to_string(&p)?;
        for m in stmt_re.find_iter(&sql) {
            buf.push_str(&format!("-- from {}\n", p.display()));
            buf.push_str(m.as_str());
            buf.push_str("\n\n");
        }
    }
    Ok(buf)
}

pub fn run(_only: Option<&str>) -> Result<()> {
    todo!("filled in by Task 9")
}
```

- [ ] **Step 5.4: Run, expect pass**

```bash
cargo test -p epigraph-tools --test table_graph_dossier_tests
```

- [ ] **Step 5.5: Commit**

```bash
git add crates/epigraph-tools/examples/table_graph/dossier.rs \
        crates/epigraph-tools/tests/table_graph_dossier_tests.rs
git commit -m "feat(table_graph): DDL extractor"
```

---

## Task 6: Git context extractor (3 slices, dedup by SHA)

**Files:**
- Modify: `crates/epigraph-tools/examples/table_graph/dossier.rs`
- Modify: `crates/epigraph-tools/tests/table_graph_dossier_tests.rs`

- [ ] **Step 6.1: Failing test**

Append to `crates/epigraph-tools/tests/table_graph_dossier_tests.rs`:

```rust
use dossier::collect_git_context;

#[test]
fn git_context_for_claims_returns_some_commits() {
    let commits = collect_git_context(
        "/home/jeremy/epigraph",
        "001_initial_schema.sql",
        "claims",
    ).unwrap();
    assert!(!commits.is_empty(), "expected at least one commit touching claims");
    let mut shas: Vec<&str> = commits.iter().map(|c| c.sha.as_str()).collect();
    shas.sort();
    let n = shas.len();
    shas.dedup();
    assert_eq!(shas.len(), n, "duplicate SHAs in commit list");
}
```

- [ ] **Step 6.2: Run, expect fail**

- [ ] **Step 6.3: Implement**

Append to `dossier.rs`:

```rust
use std::process::Command;

/// Three-slice git history:
///   1. introducing commit (--diff-filter=A --follow)
///   2. all subsequent commits touching the migration file (--follow)
///   3. commits with the table name in the message body (--grep)
/// Deduped by SHA, sorted by author date ascending.
pub fn collect_git_context(repo: &str, migration_file: &str, table: &str) -> Result<Vec<GitCommit>> {
    let format = "--pretty=format:%H%x09%aI%x09%s%x09%b%x1e";
    let migration_path = format!("migrations/{}", migration_file);
    let mut all = Vec::new();
    for args in [
        vec!["log", "--diff-filter=A", "--follow", format, "--", &migration_path],
        vec!["log", "--follow", format, "--", &migration_path],
        vec!["log", &format!("--grep={}", regex::escape(table)), format],
    ] {
        let out = Command::new("git").current_dir(repo).args(&args).output()?;
        if !out.status.success() { continue; }
        let text = String::from_utf8_lossy(&out.stdout);
        for record in text.split('\x1e') {
            let record = record.trim();
            if record.is_empty() { continue; }
            let parts: Vec<&str> = record.splitn(4, '\t').collect();
            if parts.len() < 3 { continue; }
            all.push(GitCommit {
                sha: parts[0].to_string(),
                date: parts[1].to_string(),
                subject: parts[2].to_string(),
                body: parts.get(3).map(|s| s.to_string()).unwrap_or_default(),
            });
        }
    }
    all.sort_by(|a, b| a.date.cmp(&b.date));
    all.dedup_by(|a, b| a.sha == b.sha);
    Ok(all)
}
```

- [ ] **Step 6.4: Run, expect pass**

- [ ] **Step 6.5: Commit**

```bash
git commit -am "feat(table_graph): git context extractor (3 slices)"
```

---

## Task 7: Call site extractor with fn back-scan

**Files:**
- Modify: `crates/epigraph-tools/examples/table_graph/dossier.rs`
- Modify: `crates/epigraph-tools/tests/table_graph_dossier_tests.rs`

- [ ] **Step 7.1: Failing test**

Append:

```rust
use dossier::collect_call_sites;

#[test]
fn finds_claim_repo_call_sites() {
    let sites = collect_call_sites("/home/jeremy/epigraph", "claims").unwrap();
    assert!(!sites.is_empty(), "claims should have many call sites");
    assert!(
        sites.iter().any(|s| s.crate_name == "epigraph-db" || s.crate_name == "epigraph-api"),
        "expected db or api crate among call sites"
    );
    for s in &sites {
        assert!(!s.function.is_empty(), "function name must be filled");
        assert!(!s.function.contains(':'), "function should be ident, not file:line");
    }
}
```

- [ ] **Step 7.2: Run, expect fail**

- [ ] **Step 7.3: Implement**

Append to `dossier.rs`:

```rust
fn back_scan_function(lines: &[&str], hit_idx: usize) -> String {
    let fn_re = Regex::new(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)").expect("regex");
    for i in (0..=hit_idx).rev() {
        if let Some(c) = fn_re.captures(lines[i]) {
            return c[1].to_string();
        }
    }
    "<top-level>".to_string()
}

fn classify(line: &str) -> Option<CallKind> {
    let l = line.to_uppercase();
    if l.contains("INSERT INTO") || l.contains("UPDATE ") || l.contains("DELETE FROM")
        || l.contains("UPSERT") || l.contains("COPY ") {
        Some(CallKind::WritesTo)
    } else if l.contains("SELECT") || l.contains("QUERY_AS") || l.contains("FROM ") {
        Some(CallKind::ReadsFrom)
    } else {
        None
    }
}

pub fn collect_call_sites(repo: &str, table: &str) -> Result<Vec<CallSite>> {
    let crates_dir = format!("{}/crates", repo);
    let word_re = Regex::new(&format!(r"\b{}\b", regex::escape(table)))?;
    let mut out = Vec::new();
    for entry in WalkDir::new(&crates_dir).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() { continue; }
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("rs") { continue; }
        if p.components().any(|c| c.as_os_str() == "target"
            || c.as_os_str() == ".sqlx"
            || c.as_os_str() == "migrations") { continue; }
        let rel = p.strip_prefix(&crates_dir).unwrap();
        let crate_name = rel.components().next()
            .and_then(|c| c.as_os_str().to_str())
            .unwrap_or("?").to_string();
        let text = match std::fs::read_to_string(p) { Ok(t) => t, Err(_) => continue };
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("///") || trimmed.starts_with("//!") { continue; }
            if !word_re.is_match(line) { continue; }
            let kind = match classify(line) { Some(k) => k, None => continue };
            let function = back_scan_function(&lines, i);
            let end = (i + 2).min(lines.len());
            let snippet = lines[i..end].join("\n").trim().to_string();
            out.push(CallSite { crate_name: crate_name.clone(), function, snippet, kind });
        }
    }
    Ok(out)
}
```

- [ ] **Step 7.4: Run, expect pass**

- [ ] **Step 7.5: Commit**

```bash
git commit -am "feat(table_graph): call-site extractor with fn back-scan"
```

---

## Task 8: FK target extractor + dossier builder

**Files:**
- Modify: `crates/epigraph-tools/examples/table_graph/dossier.rs`
- Modify: `crates/epigraph-tools/tests/table_graph_dossier_tests.rs`

- [ ] **Step 8.1: Failing test**

Append:

```rust
use dossier::extract_fk_targets;

#[test]
fn fk_targets_for_evidence_includes_claims() {
    let ddl = "CREATE TABLE evidence (id uuid, claim_id uuid REFERENCES claims(id));";
    let targets = extract_fk_targets(ddl);
    assert!(targets.contains(&"claims".to_string()));
}

#[test]
fn fk_targets_dedup() {
    let ddl = "FOO REFERENCES claims(id), BAR REFERENCES claims(id)";
    let targets = extract_fk_targets(ddl);
    assert_eq!(targets, vec!["claims".to_string()]);
}
```

- [ ] **Step 8.2: Run, expect fail**

- [ ] **Step 8.3: Implement**

Append to `dossier.rs`:

```rust
pub fn extract_fk_targets(ddl: &str) -> Vec<String> {
    let re = Regex::new(r"(?i)REFERENCES\s+(?:public\.)?(\w+)\s*\(").expect("regex");
    let mut out: Vec<String> = re.captures_iter(ddl)
        .map(|c| c[1].to_lowercase())
        .collect();
    out.sort();
    out.dedup();
    out
}

pub fn build_dossier(
    repo_root: &str, migration_dir: &str, table: &TableRef,
) -> Result<Dossier> {
    let ddl = collect_ddl(migration_dir, &table.name)?;
    let commits = collect_git_context(repo_root, &table.migration, &table.name)?;
    let call_sites = collect_call_sites(repo_root, &table.name)?;
    let fk_targets = extract_fk_targets(&ddl);
    Ok(Dossier { table: table.clone(), ddl, commits, call_sites, fk_targets })
}

pub fn content_hash<T: serde::Serialize>(v: &T) -> Result<String> {
    let bytes = serde_json::to_vec(v)?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex::encode(h.finalize()))
}
```

- [ ] **Step 8.4: Run, expect pass**

- [ ] **Step 8.5: Commit**

```bash
git commit -am "feat(table_graph): FK target extractor + dossier builder"
```

---

## Task 9: Claude CLI invoker → narrative Markdown

**Files:**
- Modify: `crates/epigraph-tools/examples/table_graph/llm.rs` (replace stub)
- Modify: `crates/epigraph-tools/tests/table_graph_dossier_tests.rs` (add llm test)

- [ ] **Step 9.1: Failing test**

Append to test file:

```rust
#[path = "../examples/table_graph/llm.rs"]
mod llm;

#[test]
fn build_prompt_includes_dossier_sections() {
    use crate::types::*;
    let d = Dossier {
        table: TableRef { repo: "epigraph".into(), name: "claims".into(),
                          migration: "001_initial_schema.sql".into() },
        ddl: "CREATE TABLE claims (id uuid);".into(),
        commits: vec![GitCommit { sha: "abc12345".into(), date: "2025-01-01T00:00:00Z".into(),
                                   subject: "init".into(), body: "".into() }],
        call_sites: vec![CallSite {
            crate_name: "epigraph-api".into(), function: "submit_claim_route".into(),
            snippet: "INSERT INTO claims (id".into(), kind: CallKind::WritesTo,
        }],
        fk_targets: vec!["agents".into()],
    };
    let p = llm::build_prompt(&d);
    assert!(p.contains("claims"));
    assert!(p.contains("CREATE TABLE claims"));
    assert!(p.contains("submit_claim_route"));
    assert!(p.contains("agents"));
    assert!(p.contains("init"));
}

#[test]
fn extract_md_from_response_strips_codefence() {
    let raw = "Sure, here you go:\n\n```markdown\n# Table `claims`\n\n## Purpose\n\ntext\n```";
    let md = llm::extract_md(raw).unwrap();
    assert!(md.starts_with("# Table"));
    assert!(!md.contains("```"));
}
```

- [ ] **Step 9.2: Run, expect fail**

- [ ] **Step 9.3: Implement**

Replace `llm.rs`:

```rust
//! Claude CLI driver. Builds a per-table prompt and invokes `claude` (OAuth)
//! to produce a structured Markdown narrative. No SDK fallback.

use crate::types::*;
use anyhow::{anyhow, Context, Result};
use std::process::{Command, Stdio};

const MD_INSTRUCTIONS: &str = r#"
Produce a Markdown document with EXACTLY this structure (no preamble, no postamble):

# Table `<name>` (`<repo>`)

## Purpose

<one paragraph: what this table stores, why it exists, who reads/writes it>

## Call sites

- Crate `<crate>` writes to via function `<fn>`: `<grep-able snippet>`
- Crate `<crate>` reads from via function `<fn>`: `<grep-able snippet>`
... (one bullet per discovered call site)

## Foreign key relationships

- References table `<target>`: `<DDL excerpt>`
... (one bullet per FK; omit section if none)

## DDL

```sql
<concatenated CREATE/ALTER>
```

## Git context

- <SHA-prefix> <date>: <subject>
... (one bullet per commit, most recent first)

Notes:
- Use the call sites and FK targets exactly as provided in the dossier; do not invent.
- Snippets must be grep-able strings that appear verbatim in the source code.
- The "Purpose" paragraph is your own synthesis from the dossier.
"#;

pub fn build_prompt(d: &Dossier) -> String {
    let mut p = String::new();
    p.push_str(&format!("Build a Tier-1 hierarchical narrative for database table `{}` in repo `{}`.\n\n",
        d.table.name, d.table.repo));
    p.push_str("# Dossier\n\n## DDL\n```sql\n");
    p.push_str(&d.ddl);
    p.push_str("\n```\n\n## Git context\n");
    for c in &d.commits {
        p.push_str(&format!("- {} {}: {}\n", &c.sha[..8.min(c.sha.len())], c.date, c.subject));
        if !c.body.is_empty() {
            p.push_str(&format!("  {}\n", c.body.lines().next().unwrap_or("")));
        }
    }
    p.push_str("\n## Call sites (deterministically extracted)\n");
    for s in &d.call_sites {
        p.push_str(&format!("- crate=`{}` fn=`{}` kind={:?}\n  snippet: `{}`\n",
            s.crate_name, s.function, s.kind, s.snippet));
    }
    p.push_str("\n## FK targets (deterministically extracted)\n");
    for t in &d.fk_targets {
        p.push_str(&format!("- {}\n", t));
    }
    p.push_str("\n");
    p.push_str(MD_INSTRUCTIONS);
    p
}

/// Strip an optional ```markdown ... ``` code fence and any leading prose.
/// Prefers a `# Table` header over a generic ``` fence, because real narrative
/// output contains an inner ```sql``` block that would otherwise be matched first.
pub fn extract_md(text: &str) -> Result<String> {
    if let Some(start) = text.find("```markdown") {
        let after = &text[start + "```markdown".len()..];
        let end = after.find("```").ok_or_else(|| anyhow!("unterminated code fence"))?;
        return Ok(after[..end].trim().to_string());
    }
    if let Some(start) = text.find("# Table") {
        return Ok(text[start..].trim().to_string());
    }
    if let Some(start) = text.find("```") {
        let after = &text[start + 3..];
        let end = after.find("```").ok_or_else(|| anyhow!("unterminated code fence"))?;
        return Ok(after[..end].trim().to_string());
    }
    Err(anyhow!("no '# Table' header or code fence"))
}

// File-based nested-CLI pattern. The `result` field of `claude -p
// --output-format json` is empty when the orchestrator is itself a Claude
// session (see `feedback_nested_cli.md`), so we instruct the subprocess to
// Write the narrative to a known path and poll for it.
pub fn invoke_claude(prompt: &str, result_path: &std::path::Path) -> Result<String> {
    use std::time::{Duration, Instant};
    if let Some(parent) = result_path.parent() {
        std::fs::create_dir_all(parent).context("create result_path parent")?;
    }
    if result_path.exists() { std::fs::remove_file(result_path).ok(); }

    let wrapped = format!(
        "{prompt}\n\n---\n\nWhen you have produced the Markdown document, use the Write tool to save it to:\n\n    {path}\n\nWrite ONLY the Markdown document to that file (no preamble, no postamble, no surrounding code fence). Do not print the document to the chat.\n",
        prompt = prompt, path = result_path.display(),
    );

    let status = Command::new("claude")
        .args(["-p", "--dangerously-skip-permissions", "--model", "claude-sonnet-4-6"])
        .arg(&wrapped)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .context("spawn claude CLI")?;
    if !status.success() {
        return Err(anyhow!("claude CLI exited non-zero (status {})", status));
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    while !result_path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    if !result_path.exists() {
        return Err(anyhow!("claude exited successfully but did not write {}", result_path.display()));
    }
    std::fs::read_to_string(result_path)
        .with_context(|| format!("read result file {}", result_path.display()))
}

/// Run claude once with a retry on parse failure.
pub fn extract(d: &Dossier) -> Result<String> {
    let result_dir = std::path::PathBuf::from(
        "docs/superpowers/artifacts/2026-04-30-table-graph/staging/llm-out");
    let result_path = result_dir.join(format!("{}.{}.md", d.table.repo, d.table.name));
    let prompt = build_prompt(d);
    let raw = invoke_claude(&prompt, &result_path)?;
    if let Ok(md) = extract_md(&raw) { return Ok(md); }
    let strict = format!("Respond with ONLY the Markdown document (no prose, no fences).\n\n{}", prompt);
    let raw = invoke_claude(&strict, &result_path)?;
    extract_md(&raw)
}
```

- [ ] **Step 9.4: Run, expect pass on the unit tests**

```bash
cargo test -p epigraph-tools --test table_graph_dossier_tests
```

(`invoke_claude` is exercised by the smoke run in Task 10.)

- [ ] **Step 9.5: Commit**

```bash
git commit -am "feat(table_graph): claude CLI invoker + Markdown extractor"
```

---

## Task 10: Wire `extract` subcommand — full per-table extraction loop

**Files:**
- Modify: `crates/epigraph-tools/examples/table_graph/dossier.rs` (replace `pub fn run` stub)

- [ ] **Step 10.1: Implement**

Replace the `pub fn run` at the bottom of `dossier.rs`:

```rust
pub fn run(only: Option<&str>) -> Result<()> {
    use crate::{discover, llm};
    use std::io::Write;

    let staging_dir = "docs/superpowers/artifacts/2026-04-30-table-graph/staging";
    let narratives_dir = "docs/superpowers/artifacts/2026-04-30-table-graph/narratives";
    std::fs::create_dir_all(staging_dir)?;
    std::fs::create_dir_all(narratives_dir)?;

    let tables = discover::scan_migrations(&[
        ("epigraph",   "/home/jeremy/epigraph/migrations",   &[]),
        ("episcience", "/home/jeremy/episcience/migrations", &["upstream"]),
    ])?;

    for t in &tables {
        if let Some(filter) = only { if t.name != filter { continue; } }
        let staging_path = format!("{}/{}.{}.json", staging_dir, t.repo, t.name);
        let md_path = format!("{}/{}.{}.md", narratives_dir, t.repo, t.name);
        let (repo_root, migration_dir) = match t.repo.as_str() {
            "epigraph"   => ("/home/jeremy/epigraph",   "/home/jeremy/epigraph/migrations"),
            "episcience" => ("/home/jeremy/episcience", "/home/jeremy/episcience/migrations"),
            _ => continue,
        };
        let dossier = build_dossier(repo_root, migration_dir, t)?;
        let dossier_hash = content_hash(&dossier)?;

        if let Ok(existing) = std::fs::read_to_string(&staging_path) {
            if let Ok(file) = serde_json::from_str::<StagingFile>(&existing) {
                if file.content_hash.starts_with(&dossier_hash[..16]) {
                    eprintln!("skip {} (unchanged)", t.name);
                    continue;
                }
            }
        }

        match llm::extract(&dossier) {
            Ok(narrative_md) => {
                let combined = serde_json::json!({"d": &dossier, "m": &narrative_md});
                let hash = content_hash(&combined)?;
                std::fs::write(&md_path, &narrative_md)?;
                let file = StagingFile { dossier, narrative_md, content_hash: hash };
                std::fs::write(&staging_path, serde_json::to_string_pretty(&file)?)?;
                eprintln!("wrote {} and {}", staging_path, md_path);
            }
            Err(e) => {
                eprintln!("FAIL {}: {}", t.name, e);
                let failed = format!("{}/failed.jsonl", staging_dir);
                let entry = serde_json::json!({"table": t.name, "error": e.to_string()});
                let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&failed)?;
                writeln!(f, "{}", entry)?;
            }
        }
    }
    Ok(())
}
```

- [ ] **Step 10.2: Smoke run on one table**

```bash
cargo run -p epigraph-tools --example table_graph -- extract --only frames
```

Expected: `staging/epigraph.frames.json` and `narratives/epigraph.frames.md` both exist.

- [ ] **Step 10.3: Inspect output**

```bash
head -30 docs/superpowers/artifacts/2026-04-30-table-graph/narratives/epigraph.frames.md
```

Expected: a `# Table` header, `## Purpose` section, `## Call sites` bullets.

- [ ] **Step 10.4: Commit**

```bash
git commit -am "feat(table_graph): wire extract subcommand"
```

---

## Task 11: Wire `ingest` subcommand — claude CLI orchestrates extract-claims + ingest_document

**Files:**
- Modify: `crates/epigraph-tools/examples/table_graph/ingest.rs` (replace stubs)

**Approach revision (Path A, decided 2026-05-01):**

`extract-claims` is a Claude skill at `.claude/skills/extract-claims/SKILL.md` and `ingest_document` is an MCP tool — both Claude-mediated, neither has a headless CLI subcommand. The orchestration happens inside a `claude -p` subprocess per table:

- For each narrative MD, invoke `claude -p --dangerously-skip-permissions` with a prompt instructing the session to (1) run extract-claims on the MD, (2) write the resulting `DocumentExtraction` JSON to a known path, (3) call `mcp__epigraph__ingest_document` with that path + the synthetic DOI. The orchestrator MUST keep the worktree as the current working directory because `mcp__epigraph__ingest_document` enforces a CWD-containment check on `file_path` (see `crates/epigraph-mcp/src/tools/ingestion.rs`).
- Claims will be authored by whatever signer the system MCP server uses. The MCP server hard-codes the auto-registered agent label as `mcp-agent` — there is NO row labeled `code-graph-extractor`. The pinned pubkey is documentation; downstream filters MUST discriminate via the synthetic DOI prefix `urn:epigraph-table:` on the source paper.
- The `extract-claims` skill emits claims with empty `labels` arrays regardless of MD-side hints, so labels-based filtering does not work. Don't rely on `code-shape`, `table-purpose`, `call-site`, or `fk-relationship` labels.
- Forget/regen workflow: use the EpiGraph paper-deletion API filtered on `doi LIKE 'urn:epigraph-table:%'` to remove the per-table papers (which removes their edges and orphan claims). Don't `psql DELETE` claims/edges directly — that's a project-wide rule (see `feedback_no_raw_sql.md`).

- [ ] **Step 11.2: Implement `run` and `verify`**

Replace `ingest.rs`:

```rust
//! Per-table ingestion: one `claude -p` subprocess per narrative MD orchestrates
//! the extract-claims skill + the mcp__epigraph__ingest_document tool.

use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::process::Command;

pub fn run(dry_run: bool) -> Result<()> {
    let narratives_dir = "docs/superpowers/artifacts/2026-04-30-table-graph/narratives";
    let staging_dir = "docs/superpowers/artifacts/2026-04-30-table-graph/staging";
    let failed_path = format!("{}/failed-ingest.jsonl", staging_dir);
    fs::create_dir_all(staging_dir)?;

    let mut count_ok = 0usize;
    let mut count_fail = 0usize;

    for entry in fs::read_dir(narratives_dir)
        .with_context(|| format!("read {}", narratives_dir))?
    {
        let p = entry?.path();
        if p.extension().and_then(|s| s.to_str()) != Some("md") { continue; }

        let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let parts: Vec<&str> = stem.splitn(2, '.').collect();
        if parts.len() != 2 { continue; }
        let (repo, table) = (parts[0], parts[1]);
        let doi = format!("urn:epigraph-table:{}:{}", repo, table);
        let md_abs = std::fs::canonicalize(&p)?;
        let extraction_json = p.with_extension("extraction.json");
        let extraction_abs = match std::fs::canonicalize(&extraction_json) {
            Ok(p) => p,
            Err(_) => extraction_json.clone(), // file may not exist yet
        };

        eprintln!("ingest {} ({})", stem, doi);

        if dry_run {
            eprintln!("  dry-run: would orchestrate claude -p extract+ingest");
            continue;
        }

        let prompt = format!(
"You have one task. Do not deviate.

1. Use the `extract-claims` skill on the markdown file at:
     {md}
   Produce a `DocumentExtraction` JSON.

2. Save the JSON to:
     {json}

3. Call the MCP tool `mcp__epigraph__ingest_document` with:
     file_path = {json}
   Use synthetic DOI `{doi}` for the source.

Report only the ingest_document tool result.",
            md = md_abs.display(), json = extraction_abs.display(), doi = doi);

        let status = Command::new("claude")
            .args([
                "-p",
                "--output-format",
                "json",
                "--dangerously-skip-permissions",
            ])
            .arg(&prompt)
            .status()?;
        if !status.success() {
            eprintln!("  claude orchestration failed");
            log_fail(&failed_path, table, "claude-orchestration")?;
            count_fail += 1;
            continue;
        }
        count_ok += 1;
    }

    eprintln!("ingestion complete: {} ok, {} failed (see {})", count_ok, count_fail, failed_path);
    Ok(())
}

fn log_fail(path: &str, table: &str, stage: &str) -> Result<()> {
    let mut f = fs::OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(f, r#"{{"table": "{}", "stage": "{}"}}"#, table, stage)?;
    Ok(())
}

pub fn verify() -> Result<()> {
    eprintln!("Verification — manual queries to run against EpiGraph:");
    eprintln!();
    eprintln!("1. Coverage — count per-table papers:");
    eprintln!("   psql ... -c \"SELECT count(*) FROM papers WHERE doi LIKE 'urn:epigraph-table:%';\"");
    eprintln!("   expected: ~85 papers (one per table)");
    eprintln!();
    eprintln!("2. Recall — semantic queries should surface the right table:");
    eprintln!("   recall \"what stores DST mass functions\"  → mass_functions purpose claim");
    eprintln!("   recall \"belief frame definition\"         → frames purpose claim");
    eprintln!("   recall \"harvester audit reports\"         → harvester_audit_reports");
    eprintln!();
    eprintln!("3. Sub-claim sanity — pick three purpose claims and check their");
    eprintln!("   decomposes_to children include call-site claims with greppable evidence.");
    Ok(())
}
```

- [ ] **Step 11.3: Smoke run with dry-run**

```bash
cargo run -p epigraph-tools --example table_graph -- ingest --dry-run
```

Expected: prints "dry-run: would extract+ingest" for each narrative MD.

- [ ] **Step 11.4: Single-table real ingest**

Make sure only the `frames` narrative MD exists in the narratives/ directory (Task 10's smoke run produced this). Then:

```bash
cd /home/jeremy/epigraph-wt-table-graph && cargo run -p epigraph-tools --example table_graph -- ingest 2>&1 | tail -30
```

Expected: a single `claude -p` subprocess runs, performs extract-claims internally, calls ingest_document, prints "1 ok, 0 failed".

**Working directory matters.** `mcp__epigraph__ingest_document` enforces a CWD-containment check on the `file_path` it's handed (see `crates/epigraph-mcp/src/tools/ingestion.rs`). The orchestrator inherits the parent's CWD — keep the worktree (`/home/jeremy/epigraph-wt-table-graph`) as the current directory before invoking `cargo run -- ingest`, and don't `cd` to a sibling repo inside the prompt. The result-file paths are absolute (canonicalized in `ingest.rs`), but the MCP tool still rejects paths outside the active CWD.

Authorship: claims will be authored by the system MCP server's signer (whatever the running `/usr/local/bin/epigraph-mcp` was started with), not by `code-graph-extractor` (the auto-registered agent label is hard-coded to `mcp-agent`). Discrimination is solely via the synthetic DOI prefix `urn:epigraph-table:` on the source paper, since `extract-claims` emits empty `labels` arrays.

- [ ] **Step 11.5: Verify a paper and at least one claim landed**

The MCP server hard-codes the auto-registered agent label as `mcp-agent` (see `crates/epigraph-mcp/src/server.rs::agent_id`) — there is no row labeled `code-graph-extractor`. Don't filter on agent label. The `extract-claims` skill also emits claims with empty `labels` arrays regardless of any MD-side hints, so labels-based filtering does not work either. Discriminate via the synthetic DOI prefix.

```bash
psql "postgres://epigraph:epigraph@localhost:5432/epigraph" \
  -c "SELECT id, doi FROM papers WHERE doi LIKE 'urn:epigraph-table:%' LIMIT 3;"
```

Expected: at least one row.

```bash
psql "postgres://epigraph:epigraph@localhost:5432/epigraph" \
  -c "SELECT count(DISTINCT e.target_id)
        FROM edges e JOIN papers p ON p.id = e.source_id
        WHERE p.doi LIKE 'urn:epigraph-table:%' AND e.relationship = 'asserts';"
```

Expected: ≥ 1 (claim count linked from per-table papers).

- [ ] **Step 11.6: Commit**

```bash
git commit -am "feat(table_graph): wire ingest subcommand (extract-claims + ingest_document)"
```

---

## Task 12: Verification subcommand (real queries)

**Files:**
- Modify: `crates/epigraph-tools/examples/table_graph/ingest.rs::verify`

Once a full extract + ingest run completes, the manual `verify` print can be replaced with actual SQL queries.

- [ ] **Step 12.1: Replace `verify` with real queries**

Replace the `verify` function in `ingest.rs`:

```rust
// Filter by synthetic DOI prefix on `papers`, NOT by claim labels.
// The extract-claims skill emits claims with empty `labels`, so labels
// filters return zero rows. Per-table papers are joined to claims via
// edges (source_id = paper.id, relationship = 'asserts').
pub fn verify() -> Result<()> {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://epigraph:epigraph@localhost:5432/epigraph".into());

    let papers = run_psql(&url,
        "SELECT count(*) FROM papers WHERE doi LIKE 'urn:epigraph-table:%'")?;
    eprintln!("Coverage: {} papers ingested with DOI prefix urn:epigraph-table: (expected ~85)",
        papers.trim());

    let total_claims = run_psql(&url, "
        SELECT count(DISTINCT e.target_id) FROM edges e
        JOIN papers p ON p.id = e.source_id
        WHERE p.doi LIKE 'urn:epigraph-table:%' AND e.relationship = 'asserts'
    ")?;
    eprintln!("Total claims linked from per-table papers: {}", total_claims.trim());

    let zero = run_psql(&url, "
        SELECT p.doi FROM papers p
        WHERE p.doi LIKE 'urn:epigraph-table:%'
          AND NOT EXISTS (
              SELECT 1 FROM edges e WHERE e.source_id = p.id AND e.relationship = 'asserts'
          )
    ")?;
    let zero_lines: Vec<&str> = zero.lines().filter(|l| !l.trim().is_empty()).collect();
    if !zero_lines.is_empty() {
        eprintln!("WARNING: {} per-table papers have no asserts edges:", zero_lines.len());
        for l in &zero_lines { eprintln!("  {}", l); }
    }

    eprintln!();
    eprintln!("Manual recall checks (run separately):");
    eprintln!("  recall \"what stores DST mass functions\"  → mass_functions");
    eprintln!("  recall \"belief frame definition\"         → frames");
    eprintln!("  recall \"harvester audit reports\"         → harvester_audit_reports");
    Ok(())
}

fn run_psql(url: &str, sql: &str) -> Result<String> {
    let out = std::process::Command::new("psql")
        .arg(url).arg("-tAc").arg(sql)
        .output()
        .with_context(|| "psql invocation failed")?;
    if !out.status.success() {
        return Err(anyhow::anyhow!("psql failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    Ok(String::from_utf8(out.stdout)?)
}
```

- [ ] **Step 12.2: Run after a full ingest**

```bash
cargo run -p epigraph-tools --example table_graph -- verify
```

- [ ] **Step 12.3: Commit**

```bash
git commit -am "feat(table_graph): verify subcommand with real queries"
```

---

## Task 13: Open the table-graph PR

- [ ] **Step 13.1: Push**

```bash
cd /home/jeremy/epigraph-wt-table-graph
git push -u origin feat/table-graph
```

- [ ] **Step 13.2: Open PR**

```bash
gh pr create --title "feat: table-graph extraction binary, per-table papers via DOI prefix" --body "$(cat <<'EOF'
## Summary
- New example binary `crates/epigraph-tools/examples/table_graph/` that discovers tables, builds dossiers, runs Claude CLI extraction, and ingests structured narratives via `extract-claims` + `ingest_document`
- Per-table papers are discriminated by the synthetic DOI prefix `urn:epigraph-table:` (NOT by an agent label — the MCP server hard-codes the auto-registered label as `mcp-agent`)
- Schema only — no row data; no schema/API changes
- Spec at `docs/superpowers/specs/2026-04-30-epigraph-table-graph-design.md`

## Test plan
- [x] Unit tests pass: `cargo test -p epigraph-tools`
- [x] Discover lists ~85 tables, 18 crates (epigraph-side; episcience cases marked `#[ignore]` because the upstream repo isn't checked out in CI)
- [x] Single-table extract produces a structured Markdown narrative (uses the file-based nested-CLI pattern: subprocess Writes the narrative to a result file, orchestrator polls)
- [x] Single-table ingest creates a per-table `paper` with `urn:epigraph-table:` DOI and at least one asserted claim
- [x] Verify reports paper count and per-table claim coverage via DOI-prefix queries
EOF
)"
```

---

## Self-Review Checklist (run before declaring this plan complete)

- [ ] **Spec coverage:** every section of `docs/superpowers/specs/2026-04-30-epigraph-table-graph-design.md` maps to one or more tasks above
- [ ] **No placeholders:** scan for `TBD`, `TODO`, `implement later`, `fill in details`
- [ ] **Type consistency:** `TableRef`, `CrateRef`, `Dossier`, `StagingFile` field names match across all task code blocks
- [ ] **Citation convention:** evidence carries `raw_content = "<grep-able snippet>"`, never `file:line`
- [ ] **Idempotency strategy:** staging `content_hash` for re-extract; DOI + `PIPELINE_VERSION` for re-ingest
- [ ] **No new entity/edge types:** uses only existing claim + evidence machinery
