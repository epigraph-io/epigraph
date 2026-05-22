# Cross-Source Matching Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the source-aware claim ↔ claim matcher specified in `docs/superpowers/specs/2026-05-21-cross-source-matching-design.md`: a multi-signal blocker, weighted scorer, mid-band LLM verifier (reusing Phase 7's `rerank_bridges::rerank_candidates_table`), durable `match_candidates` table, batch-sweep CLI + MCP tools + API route, and a `CORROBORATES`-aware DST aggregation step in the BP loop.

**Architecture:** New `matching` module under `crates/epigraph-engine`, sibling of `reconciliation`. Pipeline `blocker → source-filter → scorer → band → policy`, each unit independently testable. Three drivers (batch CLI, MCP tool, API route) all call the same pipeline. SciFact provides labeled pairs for calibration.

**Tech Stack:** Rust, Postgres + pgvector (existing), sqlx for DB, async tokio, existing `claude-cli` provider for LLM verifier via Phase 7's library entry-point. Calibration in `calibration.toml`.

**Branch / worktree:** `spec/cross-source-matching` checked out at `/home/jeremy/epigraph-wt-cross-source-matching`.

---

## Pre-flight: Phase 7 Dependency Check

**Status as of 2026-05-21:** `spec/cross-source-matching` is rebased on
`origin/feat/rerank-candidates-table-lockstep` (commit `a64010e`), which
provides:

- `epigraph_cli::rerank::core::rerank_candidates_table` — the public
  library entry-point we consume.
- Re-exports at `epigraph_cli::rerank::{rerank_candidates_table,
  rerank_global_join, RerankConfig, RerankSummary}`.

The Phase 7 *partial* HNSW index on level=3 atoms has not landed; the
embedding-ANN blocker uses the **existing full HNSW index** on
`claims.embedding` from migration 007 instead. Acceptable for development
and the calibration corpus; revisit the partial index when Phase 7's
sweep CLIs land for production-scale runs.

- [ ] **Step 1: Confirm the library entry-point is reachable**

```bash
grep -n "pub async fn rerank_candidates_table" \
    crates/epigraph-cli/src/rerank/core.rs
```

Expected: line 102 (or thereabouts) shows the public signature.

- [ ] **Step 2: Confirm the full HNSW index on `claims.embedding` exists**

```bash
grep -n "USING hnsw" migrations/007_create_indexes.sql
```

Expected: at least one match — `claims` USING hnsw (embedding vector_cosine_ops).

---

## File Structure

| File                                                                              | Responsibility                                                |
| --------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `migrations/110_match_candidates.sql`                                             | `match_candidates` table + indexes                            |
| `migrations/111_claims_last_match_scan.sql`                                       | `claims.last_match_scan_at` column                            |
| `crates/epigraph-engine/src/matching/mod.rs`                                      | Public surface of the `matching` module                       |
| `crates/epigraph-engine/src/matching/source_key.rs`                               | `SourceKey` type + `source_key(&Claim) -> SourceKey` + filter |
| `crates/epigraph-engine/src/matching/blocker/mod.rs`                              | `Blocker` trait + `union_block` helper                        |
| `crates/epigraph-engine/src/matching/blocker/embedding_ann.rs`                    | pgvector kNN top-K                                            |
| `crates/epigraph-engine/src/matching/blocker/theme_cluster.rs`                    | Same-theme co-membership                                      |
| `crates/epigraph-engine/src/matching/blocker/compound_nbhd.rs`                    | Compound-neighborhood co-membership                           |
| `crates/epigraph-engine/src/matching/blocker/shared_triple.rs`                    | Shared (subject, predicate)                                   |
| `crates/epigraph-engine/src/matching/blocker/content_hash_prefix.rs`              | Near-exact content hash                                       |
| `crates/epigraph-engine/src/matching/scorer.rs`                                   | `MatchFeatures` + weighted combiner                           |
| `crates/epigraph-engine/src/matching/calibration.rs`                              | Load weights + bands from `calibration.toml`                  |
| `crates/epigraph-engine/src/matching/verifier.rs`                                 | Wraps `rerank_bridges::rerank_candidates_table`               |
| `crates/epigraph-engine/src/matching/pipeline.rs`                                 | Orchestrator: blocker → filter → scorer → band → policy       |
| `crates/epigraph-engine/src/matching/policy.rs`                                   | Band → CORROBORATES edge / candidate-row / review queue       |
| `crates/epigraph-db/src/repos/match_candidate.rs`                                 | Read/write `match_candidates`                                 |
| `crates/epigraph-engine/src/cdst_bp.rs` (modify)                                  | CORROBORATES evidence-pool step                               |
| `crates/epigraph-cli/src/bin/cross_source_sweep.rs`                               | Batch-sweep CLI                                               |
| `crates/epigraph-mcp/src/tools/matching.rs`                                       | 3 MCP tools                                                   |
| `crates/epigraph-mcp/src/server.rs` (modify)                                      | Register MCP tools                                            |
| `crates/epigraph-api/src/routes/cross_source.rs`                                  | GET /claims/:id/cross_source_matches                          |
| `crates/epigraph-api/src/routes/mod.rs` (modify)                                  | Register route                                                |
| `tests/scifact/calibrate_matcher.rs` (new)                                        | SciFact calibration harness                                   |
| `tests/scifact/adversarial_pairs.rs` (new)                                        | Negation / scope-flip corpus                                  |
| `calibration.toml` (modify)                                                       | `[matcher.*]` weights + bands                                 |

---

## Task 1: Migration — `match_candidates` table

**Files:**
- Create: `migrations/110_match_candidates.sql`
- Test: `crates/epigraph-db/tests/match_candidate_migration.rs` (new)

- [ ] **Step 1: Write the failing test**

```rust
// crates/epigraph-db/tests/match_candidate_migration.rs
use sqlx::PgPool;

#[sqlx::test(migrations = "../../migrations")]
async fn match_candidates_table_exists(pool: PgPool) -> sqlx::Result<()> {
    let row: (bool,) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables
         WHERE table_name = 'match_candidates')",
    )
    .fetch_one(&pool)
    .await?;
    assert!(row.0, "match_candidates table missing");
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn match_candidates_enforces_canonical_order(pool: PgPool) -> sqlx::Result<()> {
    // Seed two agents + two claims so FKs are satisfied.
    let a = uuid::Uuid::new_v4();
    let b = uuid::Uuid::new_v4();
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let result = sqlx::query(
        "INSERT INTO match_candidates (claim_a, claim_b, score, features, status)
         VALUES ($1, $2, 0.9, '{}'::jsonb, 'pending')",
    )
    .bind(hi)
    .bind(lo)
    .execute(&pool)
    .await;
    assert!(result.is_err(), "non-canonical order should violate CHECK");
    Ok(())
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/jeremy/epigraph-wt-cross-source-matching
cargo test -p epigraph-db --test match_candidate_migration 2>&1 | tail -15
```

Expected: tests fail because table does not exist.

- [ ] **Step 3: Write the migration**

```sql
-- migrations/110_match_candidates.sql
-- match_candidates: durable store for cross-source claim matches.

CREATE TABLE match_candidates (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    claim_a            UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    claim_b            UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    score              REAL NOT NULL,
    features           JSONB NOT NULL,
    verifier_verdict   TEXT,
    verifier_rationale TEXT,
    status             TEXT NOT NULL,
    matcher_run_id     UUID,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at         TIMESTAMPTZ,
    decided_by         UUID,
    CONSTRAINT match_candidates_canonical_order CHECK (claim_a < claim_b),
    CONSTRAINT match_candidates_unique_pair UNIQUE (claim_a, claim_b),
    CONSTRAINT match_candidates_status_valid CHECK (
        status IN ('pending', 'promoted', 'rejected', 'stale')
    ),
    CONSTRAINT match_candidates_verdict_valid CHECK (
        verifier_verdict IS NULL OR verifier_verdict IN
        ('same', 'paraphrase', 'overlapping', 'distinct', 'contradicts')
    )
);

CREATE INDEX idx_match_candidates_status ON match_candidates(status);
CREATE INDEX idx_match_candidates_claim_a ON match_candidates(claim_a);
CREATE INDEX idx_match_candidates_claim_b ON match_candidates(claim_b);
CREATE INDEX idx_match_candidates_run ON match_candidates(matcher_run_id) WHERE matcher_run_id IS NOT NULL;
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test -p epigraph-db --test match_candidate_migration 2>&1 | tail -10
```

Expected: both tests pass.

- [ ] **Step 5: Commit**

```bash
git add migrations/110_match_candidates.sql \
        crates/epigraph-db/tests/match_candidate_migration.rs
git commit -m "feat(matching): add match_candidates table (mig 110)"
```

---

## Task 2: Migration — `claims.last_match_scan_at` column

**Files:**
- Create: `migrations/111_claims_last_match_scan.sql`
- Test: `crates/epigraph-db/tests/last_match_scan_column.rs` (new)

- [ ] **Step 1: Write the failing test**

```rust
// crates/epigraph-db/tests/last_match_scan_column.rs
use sqlx::PgPool;

#[sqlx::test(migrations = "../../migrations")]
async fn claims_has_last_match_scan_at(pool: PgPool) -> sqlx::Result<()> {
    let row: (bool,) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns
         WHERE table_name='claims' AND column_name='last_match_scan_at')",
    )
    .fetch_one(&pool)
    .await?;
    assert!(row.0, "claims.last_match_scan_at column missing");
    Ok(())
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p epigraph-db --test last_match_scan_column 2>&1 | tail -10
```

Expected: fail.

- [ ] **Step 3: Write the migration**

```sql
-- migrations/111_claims_last_match_scan.sql
ALTER TABLE claims ADD COLUMN last_match_scan_at TIMESTAMPTZ;
CREATE INDEX idx_claims_last_match_scan ON claims(last_match_scan_at)
    WHERE last_match_scan_at IS NOT NULL;
```

- [ ] **Step 4: Run test, expect pass**

```bash
cargo test -p epigraph-db --test last_match_scan_column 2>&1 | tail -5
```

- [ ] **Step 5: Commit**

```bash
git add migrations/111_claims_last_match_scan.sql \
        crates/epigraph-db/tests/last_match_scan_column.rs
git commit -m "feat(matching): add claims.last_match_scan_at (mig 111)"
```

---

## Task 3: `SourceKey` + source-filter

**Files:**
- Create: `crates/epigraph-engine/src/matching/mod.rs`
- Create: `crates/epigraph-engine/src/matching/source_key.rs`
- Modify: `crates/epigraph-engine/src/lib.rs` (add `pub mod matching;`)
- Test: `crates/epigraph-engine/src/matching/source_key.rs` (inline `#[cfg(test)]`)

- [ ] **Step 1: Write the failing tests**

```rust
// crates/epigraph-engine/src/matching/source_key.rs
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceKey {
    pub paper_doi:         Option<String>,
    pub agent_id:          Uuid,
    pub ingestion_run_id:  Option<Uuid>,
    pub derivation_root:   Option<Uuid>,
}

#[derive(Debug, Clone, Copy)]
pub struct SourceFilterConfig {
    pub include_agent_id: bool,
}

impl Default for SourceFilterConfig {
    fn default() -> Self { Self { include_agent_id: false } }
}

pub fn is_same_source(a: &SourceKey, b: &SourceKey, cfg: SourceFilterConfig) -> bool {
    fn both_eq<T: PartialEq>(x: &Option<T>, y: &Option<T>) -> bool {
        matches!((x, y), (Some(xv), Some(yv)) if xv == yv)
    }
    if both_eq(&a.paper_doi, &b.paper_doi) { return true; }
    if both_eq(&a.ingestion_run_id, &b.ingestion_run_id) { return true; }
    if both_eq(&a.derivation_root, &b.derivation_root) { return true; }
    if cfg.include_agent_id && a.agent_id == b.agent_id { return true; }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(p: Option<&str>, a: Uuid, ir: Option<Uuid>, dr: Option<Uuid>) -> SourceKey {
        SourceKey { paper_doi: p.map(str::to_string), agent_id: a,
                    ingestion_run_id: ir, derivation_root: dr }
    }

    #[test]
    fn same_paper_doi_is_same_source() {
        let a1 = Uuid::new_v4(); let a2 = Uuid::new_v4();
        let l = k(Some("10.1/x"), a1, None, None);
        let r = k(Some("10.1/x"), a2, None, None);
        assert!(is_same_source(&l, &r, SourceFilterConfig::default()));
    }

    #[test]
    fn different_paper_same_agent_is_cross_source_by_default() {
        let a = Uuid::new_v4();
        let l = k(Some("10.1/x"), a, None, None);
        let r = k(Some("10.1/y"), a, None, None);
        assert!(!is_same_source(&l, &r, SourceFilterConfig::default()));
    }

    #[test]
    fn different_paper_same_agent_is_same_source_with_strict_flag() {
        let a = Uuid::new_v4();
        let l = k(Some("10.1/x"), a, None, None);
        let r = k(Some("10.1/y"), a, None, None);
        assert!(is_same_source(&l, &r, SourceFilterConfig { include_agent_id: true }));
    }

    #[test]
    fn null_paper_doesnt_match_null_paper() {
        let a1 = Uuid::new_v4(); let a2 = Uuid::new_v4();
        let l = k(None, a1, None, None);
        let r = k(None, a2, None, None);
        assert!(!is_same_source(&l, &r, SourceFilterConfig::default()));
    }

    #[test]
    fn shared_derivation_root_is_same_source() {
        let root = Uuid::new_v4();
        let l = k(None, Uuid::new_v4(), None, Some(root));
        let r = k(None, Uuid::new_v4(), None, Some(root));
        assert!(is_same_source(&l, &r, SourceFilterConfig::default()));
    }
}
```

- [ ] **Step 2: Write `matching/mod.rs`**

```rust
// crates/epigraph-engine/src/matching/mod.rs
pub mod source_key;
```

- [ ] **Step 3: Register module in `lib.rs`**

Insert `pub mod matching;` into `crates/epigraph-engine/src/lib.rs` alphabetically after `pub mod lifecycle;`.

- [ ] **Step 4: Run tests**

```bash
cargo test -p epigraph-engine matching::source_key 2>&1 | tail -10
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/epigraph-engine/src/matching/ crates/epigraph-engine/src/lib.rs
git commit -m "feat(matching): source_key + source-filter (Task 3)"
```

---

## Task 4: SourceKey derivation from a `Claim` row

**Files:**
- Modify: `crates/epigraph-engine/src/matching/source_key.rs`
- Create: `crates/epigraph-db/src/repos/match_helpers.rs`
- Modify: `crates/epigraph-db/src/lib.rs` (or wherever repos are re-exported)
- Test: `crates/epigraph-engine/tests/source_key_derivation.rs` (integration)

The matcher needs to derive `SourceKey` from a claim's row + properties JSON + edges. `paper_doi` lives in `claims.properties->>'paper_doi'`. `ingestion_run_id` in `claims.properties->>'ingestion_run_id'` when present. `derivation_root` is found by chasing `derived_from`/`derives_from` edges to a root.

- [ ] **Step 1: Write the failing integration test**

```rust
// crates/epigraph-engine/tests/source_key_derivation.rs
use epigraph_engine::matching::source_key::{derive_source_key, SourceKey};
use sqlx::PgPool;

#[sqlx::test(migrations = "../../migrations")]
async fn derive_extracts_paper_doi_from_properties(pool: PgPool) -> sqlx::Result<()> {
    let agent_id = test_helpers::insert_agent(&pool).await?;
    let claim_id = test_helpers::insert_claim_with_properties(
        &pool, agent_id, serde_json::json!({"paper_doi": "10.1/abc"})).await?;
    let key = derive_source_key(&pool, claim_id).await.unwrap();
    assert_eq!(key.paper_doi.as_deref(), Some("10.1/abc"));
    assert_eq!(key.agent_id, agent_id);
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn derive_chases_derivation_root(pool: PgPool) -> sqlx::Result<()> {
    let agent_id = test_helpers::insert_agent(&pool).await?;
    let root = test_helpers::insert_claim(&pool, agent_id).await?;
    let mid = test_helpers::insert_claim(&pool, agent_id).await?;
    let leaf = test_helpers::insert_claim(&pool, agent_id).await?;
    test_helpers::insert_edge(&pool, mid, root, "derived_from").await?;
    test_helpers::insert_edge(&pool, leaf, mid, "derived_from").await?;
    let key = derive_source_key(&pool, leaf).await.unwrap();
    assert_eq!(key.derivation_root, Some(root));
    Ok(())
}
```

- [ ] **Step 2: Write `test_helpers` module (if not present)**

Place in `crates/epigraph-db/src/test_helpers.rs` behind `#[cfg(any(test, feature = "test-helpers"))]`. Provide `insert_agent`, `insert_claim`, `insert_claim_with_properties`, `insert_edge`. Pattern: copy the existing helpers in `claim_repo_helpers.rs`.

- [ ] **Step 3: Run test to verify it fails**

```bash
cargo test -p epigraph-engine --test source_key_derivation 2>&1 | tail -10
```

Expected: compile error (`derive_source_key` not defined).

- [ ] **Step 4: Implement `derive_source_key`**

Append to `crates/epigraph-engine/src/matching/source_key.rs`:

```rust
use sqlx::PgPool;

pub async fn derive_source_key(pool: &PgPool, claim_id: Uuid) -> Result<SourceKey, sqlx::Error> {
    let row: (Uuid, serde_json::Value) = sqlx::query_as(
        "SELECT agent_id, properties FROM claims WHERE id = $1",
    )
    .bind(claim_id)
    .fetch_one(pool)
    .await?;
    let (agent_id, props) = row;

    let paper_doi = props.get("paper_doi").and_then(|v| v.as_str()).map(str::to_string);
    let ingestion_run_id = props.get("ingestion_run_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());

    // Chase derived_from chain to root (acyclic).
    let mut current = claim_id;
    let mut depth = 0;
    let derivation_root = loop {
        if depth > 32 { break Some(current); } // safety cap
        let parent: Option<(Uuid,)> = sqlx::query_as(
            "SELECT target_id FROM edges
             WHERE source_id = $1 AND relationship = 'derived_from' LIMIT 1",
        )
        .bind(current)
        .fetch_optional(pool)
        .await?;
        match parent {
            Some((p,)) if p != current => { current = p; depth += 1; }
            _ => break if depth == 0 { None } else { Some(current) },
        }
    };

    Ok(SourceKey { paper_doi, agent_id, ingestion_run_id, derivation_root })
}
```

- [ ] **Step 5: Run tests**

```bash
cargo test -p epigraph-engine --test source_key_derivation 2>&1 | tail -10
```

Expected: both pass.

- [ ] **Step 6: Commit**

```bash
git add crates/epigraph-engine/src/matching/source_key.rs \
        crates/epigraph-engine/tests/source_key_derivation.rs \
        crates/epigraph-db/src/test_helpers.rs
git commit -m "feat(matching): derive SourceKey from claim row + edges"
```

---

## Task 5: Blocker trait + embedding-ANN strategy

**Files:**
- Create: `crates/epigraph-engine/src/matching/blocker/mod.rs`
- Create: `crates/epigraph-engine/src/matching/blocker/embedding_ann.rs`
- Modify: `crates/epigraph-engine/src/matching/mod.rs`
- Test: `crates/epigraph-engine/tests/blocker_embedding_ann.rs` (integration)

- [ ] **Step 1: Write the failing test**

```rust
// crates/epigraph-engine/tests/blocker_embedding_ann.rs
use epigraph_engine::matching::blocker::{Blocker, embedding_ann::EmbeddingAnnBlocker};
use sqlx::PgPool;

#[sqlx::test(migrations = "../../migrations")]
async fn returns_topk_neighbors_excluding_self(pool: PgPool) -> sqlx::Result<()> {
    let agent_id = test_helpers::insert_agent(&pool).await?;
    let seed = test_helpers::insert_claim_with_embedding(&pool, agent_id,
        &vec![1.0_f32; 1536]).await?;
    for _ in 0..5 {
        test_helpers::insert_claim_with_embedding(&pool, agent_id,
            &vec![0.9_f32; 1536]).await?;
    }
    let b = EmbeddingAnnBlocker::new(3);
    let pairs = b.candidates(&pool, &[seed]).await.unwrap();
    assert!(pairs.len() <= 3);
    assert!(pairs.iter().all(|(a, b)| a != b && a < b),
            "pairs must be canonical and non-self");
    Ok(())
}
```

- [ ] **Step 2: Write the trait + module index**

```rust
// crates/epigraph-engine/src/matching/blocker/mod.rs
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

pub mod embedding_ann;
// added in later tasks:
// pub mod theme_cluster;
// pub mod compound_nbhd;
// pub mod shared_triple;
// pub mod content_hash_prefix;

pub type CandidatePair = (Uuid, Uuid); // canonical: pair.0 < pair.1

#[async_trait]
pub trait Blocker: Send + Sync {
    /// Given a seed set of claim ids, return candidate pairs in canonical order.
    async fn candidates(
        &self,
        pool: &PgPool,
        seeds: &[Uuid],
    ) -> Result<Vec<CandidatePair>, sqlx::Error>;
}

pub fn canonical(a: Uuid, b: Uuid) -> Option<CandidatePair> {
    if a == b { None } else if a < b { Some((a, b)) } else { Some((b, a)) }
}
```

- [ ] **Step 3: Implement `EmbeddingAnnBlocker`**

```rust
// crates/epigraph-engine/src/matching/blocker/embedding_ann.rs
use super::{canonical, Blocker, CandidatePair};
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

pub struct EmbeddingAnnBlocker {
    pub top_k: usize,
}

impl EmbeddingAnnBlocker {
    pub fn new(top_k: usize) -> Self { Self { top_k } }
}

#[async_trait]
impl Blocker for EmbeddingAnnBlocker {
    async fn candidates(
        &self,
        pool: &PgPool,
        seeds: &[Uuid],
    ) -> Result<Vec<CandidatePair>, sqlx::Error> {
        if seeds.is_empty() { return Ok(Vec::new()); }
        let mut out: Vec<CandidatePair> = Vec::new();
        for &seed in seeds {
            let neighbors: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT c2.id
                 FROM claims c1
                 JOIN claims c2 ON c2.id <> c1.id
                 WHERE c1.id = $1
                   AND c1.embedding IS NOT NULL
                   AND c2.embedding IS NOT NULL
                 ORDER BY c1.embedding <=> c2.embedding ASC
                 LIMIT $2",
            )
            .bind(seed)
            .bind(self.top_k as i64)
            .fetch_all(pool)
            .await?;
            for (nbr,) in neighbors {
                if let Some(p) = canonical(seed, nbr) { out.push(p); }
            }
        }
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }
}
```

- [ ] **Step 4: Register `pub mod blocker;` in `matching/mod.rs`**

- [ ] **Step 5: Run test**

```bash
cargo test -p epigraph-engine --test blocker_embedding_ann 2>&1 | tail -10
```

Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add crates/epigraph-engine/src/matching/blocker/ \
        crates/epigraph-engine/src/matching/mod.rs \
        crates/epigraph-engine/tests/blocker_embedding_ann.rs
git commit -m "feat(matching): Blocker trait + embedding-ANN strategy"
```

---

## Task 6: Theme-cluster co-membership blocker

**Files:**
- Create: `crates/epigraph-engine/src/matching/blocker/theme_cluster.rs`
- Modify: `crates/epigraph-engine/src/matching/blocker/mod.rs` (uncomment `pub mod theme_cluster;`)
- Test: `crates/epigraph-engine/tests/blocker_theme_cluster.rs`

- [ ] **Step 1: Write the failing test**

```rust
// crates/epigraph-engine/tests/blocker_theme_cluster.rs
use epigraph_engine::matching::blocker::{theme_cluster::ThemeClusterBlocker, Blocker};
use sqlx::PgPool;

#[sqlx::test(migrations = "../../migrations")]
async fn returns_co_themed_claims(pool: PgPool) -> sqlx::Result<()> {
    let agent_id = test_helpers::insert_agent(&pool).await?;
    let theme_id = test_helpers::insert_theme(&pool, "biology").await?;
    let seed   = test_helpers::insert_claim(&pool, agent_id).await?;
    let other1 = test_helpers::insert_claim(&pool, agent_id).await?;
    let other2 = test_helpers::insert_claim(&pool, agent_id).await?;
    for c in [seed, other1, other2] {
        test_helpers::assign_theme(&pool, c, theme_id).await?;
    }
    let blocker = ThemeClusterBlocker::new(50);
    let pairs = blocker.candidates(&pool, &[seed]).await.unwrap();
    assert!(pairs.iter().any(|p| *p == (seed.min(other1), seed.max(other1))));
    assert!(pairs.iter().any(|p| *p == (seed.min(other2), seed.max(other2))));
    Ok(())
}
```

- [ ] **Step 2: Implement**

```rust
// crates/epigraph-engine/src/matching/blocker/theme_cluster.rs
use super::{canonical, Blocker, CandidatePair};
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

pub struct ThemeClusterBlocker { pub per_theme_cap: usize }

impl ThemeClusterBlocker {
    pub fn new(per_theme_cap: usize) -> Self { Self { per_theme_cap } }
}

#[async_trait]
impl Blocker for ThemeClusterBlocker {
    async fn candidates(
        &self,
        pool: &PgPool,
        seeds: &[Uuid],
    ) -> Result<Vec<CandidatePair>, sqlx::Error> {
        let mut out = Vec::new();
        for &seed in seeds {
            let nbrs: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT DISTINCT ct2.claim_id
                 FROM claim_themes ct1
                 JOIN claim_themes ct2 ON ct2.theme_id = ct1.theme_id
                                       AND ct2.claim_id <> ct1.claim_id
                 WHERE ct1.claim_id = $1
                 LIMIT $2",
            )
            .bind(seed)
            .bind(self.per_theme_cap as i64)
            .fetch_all(pool)
            .await?;
            for (n,) in nbrs { if let Some(p) = canonical(seed, n) { out.push(p); } }
        }
        out.sort_unstable(); out.dedup();
        Ok(out)
    }
}
```

(If the `claim_themes` table has a different schema than this query assumes, adapt; check `migrations/` for `claim_themes` or equivalent.)

- [ ] **Step 3: Run test, commit**

```bash
cargo test -p epigraph-engine --test blocker_theme_cluster 2>&1 | tail -10
git add crates/epigraph-engine/src/matching/blocker/theme_cluster.rs \
        crates/epigraph-engine/src/matching/blocker/mod.rs \
        crates/epigraph-engine/tests/blocker_theme_cluster.rs
git commit -m "feat(matching): theme-cluster co-membership blocker"
```

---

## Task 7: Compound-neighborhood co-membership blocker

**Files:**
- Create: `crates/epigraph-engine/src/matching/blocker/compound_nbhd.rs`
- Modify: `crates/epigraph-engine/src/matching/blocker/mod.rs`
- Test: `crates/epigraph-engine/tests/blocker_compound_nbhd.rs`

Same shape as Task 6. Query joins `graph_neighborhoods` (migration 026 or its renumbered successor — check `ls migrations/ | grep -i neighbor` for the actual file). Test uses `test_helpers::assign_to_neighborhood`.

- [ ] **Step 1: Write the failing test**

```rust
// crates/epigraph-engine/tests/blocker_compound_nbhd.rs
use epigraph_engine::matching::blocker::{compound_nbhd::CompoundNbhdBlocker, Blocker};
use sqlx::PgPool;

#[sqlx::test(migrations = "../../migrations")]
async fn returns_co_neighborhood_members(pool: PgPool) -> sqlx::Result<()> {
    let agent = test_helpers::insert_agent(&pool).await?;
    let nbhd = test_helpers::insert_neighborhood(&pool).await?;
    let seed  = test_helpers::insert_claim(&pool, agent).await?;
    let other = test_helpers::insert_claim(&pool, agent).await?;
    test_helpers::assign_to_neighborhood(&pool, seed, nbhd).await?;
    test_helpers::assign_to_neighborhood(&pool, other, nbhd).await?;
    let b = CompoundNbhdBlocker::new(50);
    let pairs = b.candidates(&pool, &[seed]).await.unwrap();
    assert!(pairs.iter().any(|p| *p == (seed.min(other), seed.max(other))));
    Ok(())
}
```

- [ ] **Step 2: Implement**

```rust
// crates/epigraph-engine/src/matching/blocker/compound_nbhd.rs
use super::{canonical, Blocker, CandidatePair};
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

pub struct CompoundNbhdBlocker { pub per_nbhd_cap: usize }

impl CompoundNbhdBlocker {
    pub fn new(per_nbhd_cap: usize) -> Self { Self { per_nbhd_cap } }
}

#[async_trait]
impl Blocker for CompoundNbhdBlocker {
    async fn candidates(
        &self,
        pool: &PgPool,
        seeds: &[Uuid],
    ) -> Result<Vec<CandidatePair>, sqlx::Error> {
        let mut out = Vec::new();
        for &seed in seeds {
            let nbrs: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT DISTINCT m2.claim_id
                 FROM graph_neighborhood_members m1
                 JOIN graph_neighborhood_members m2
                      ON m2.neighborhood_id = m1.neighborhood_id
                     AND m2.claim_id <> m1.claim_id
                 WHERE m1.claim_id = $1
                 LIMIT $2",
            )
            .bind(seed)
            .bind(self.per_nbhd_cap as i64)
            .fetch_all(pool)
            .await?;
            for (n,) in nbrs { if let Some(p) = canonical(seed, n) { out.push(p); } }
        }
        out.sort_unstable(); out.dedup();
        Ok(out)
    }
}
```

If the membership table is named differently, adapt the query (search `migrations/` for `graph_neighborhood`).

- [ ] **Step 3: Run, commit**

```bash
cargo test -p epigraph-engine --test blocker_compound_nbhd 2>&1 | tail -10
git add crates/epigraph-engine/src/matching/blocker/compound_nbhd.rs \
        crates/epigraph-engine/src/matching/blocker/mod.rs \
        crates/epigraph-engine/tests/blocker_compound_nbhd.rs
git commit -m "feat(matching): compound-neighborhood blocker"
```

---

## Task 8: Shared-triple blocker

**Files:**
- Create: `crates/epigraph-engine/src/matching/blocker/shared_triple.rs`
- Modify: `crates/epigraph-engine/src/matching/blocker/mod.rs`
- Test: `crates/epigraph-engine/tests/blocker_shared_triple.rs`

Joins `entity_triples` on `(subject_id, predicate)` equality across claims.

- [ ] **Step 1: Write the failing test**

```rust
// crates/epigraph-engine/tests/blocker_shared_triple.rs
use epigraph_engine::matching::blocker::{shared_triple::SharedTripleBlocker, Blocker};
use sqlx::PgPool;

#[sqlx::test(migrations = "../../migrations")]
async fn returns_claims_sharing_subject_predicate(pool: PgPool) -> sqlx::Result<()> {
    let agent = test_helpers::insert_agent(&pool).await?;
    let subj = test_helpers::insert_entity(&pool, "DNA origami").await?;
    let seed  = test_helpers::insert_claim(&pool, agent).await?;
    let other = test_helpers::insert_claim(&pool, agent).await?;
    test_helpers::insert_triple(&pool, seed,  subj, "exhibits", None).await?;
    test_helpers::insert_triple(&pool, other, subj, "exhibits", None).await?;
    let b = SharedTripleBlocker::new(50);
    let pairs = b.candidates(&pool, &[seed]).await.unwrap();
    assert!(pairs.iter().any(|p| *p == (seed.min(other), seed.max(other))));
    Ok(())
}
```

- [ ] **Step 2: Implement**

```rust
// crates/epigraph-engine/src/matching/blocker/shared_triple.rs
use super::{canonical, Blocker, CandidatePair};
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

pub struct SharedTripleBlocker { pub per_triple_cap: usize }

impl SharedTripleBlocker {
    pub fn new(per_triple_cap: usize) -> Self { Self { per_triple_cap } }
}

#[async_trait]
impl Blocker for SharedTripleBlocker {
    async fn candidates(
        &self,
        pool: &PgPool,
        seeds: &[Uuid],
    ) -> Result<Vec<CandidatePair>, sqlx::Error> {
        let mut out = Vec::new();
        for &seed in seeds {
            let nbrs: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT DISTINCT t2.claim_id
                 FROM entity_triples t1
                 JOIN entity_triples t2
                      ON t2.subject_id = t1.subject_id
                     AND t2.predicate  = t1.predicate
                     AND t2.claim_id  <> t1.claim_id
                 WHERE t1.claim_id = $1
                 LIMIT $2",
            )
            .bind(seed)
            .bind(self.per_triple_cap as i64)
            .fetch_all(pool)
            .await?;
            for (n,) in nbrs { if let Some(p) = canonical(seed, n) { out.push(p); } }
        }
        out.sort_unstable(); out.dedup();
        Ok(out)
    }
}
```

(Verify `entity_triples` column names with `\d entity_triples` or migration 091.)

- [ ] **Step 3: Run, commit**

```bash
cargo test -p epigraph-engine --test blocker_shared_triple 2>&1 | tail -10
git add crates/epigraph-engine/src/matching/blocker/shared_triple.rs \
        crates/epigraph-engine/src/matching/blocker/mod.rs \
        crates/epigraph-engine/tests/blocker_shared_triple.rs
git commit -m "feat(matching): shared (subject,predicate) blocker"
```

---

## Task 9: Content-hash-prefix blocker

**Files:**
- Create: `crates/epigraph-engine/src/matching/blocker/content_hash_prefix.rs`
- Modify: `crates/epigraph-engine/src/matching/blocker/mod.rs`
- Test: `crates/epigraph-engine/tests/blocker_content_hash_prefix.rs`

`content_hash` is BLAKE3 32 bytes. Block by exact equality (true near-duplicates only).

- [ ] **Step 1: Write the failing test**

```rust
// crates/epigraph-engine/tests/blocker_content_hash_prefix.rs
use epigraph_engine::matching::blocker::{content_hash_prefix::ContentHashBlocker, Blocker};
use sqlx::PgPool;

#[sqlx::test(migrations = "../../migrations")]
async fn returns_claims_with_identical_hash(pool: PgPool) -> sqlx::Result<()> {
    let a1 = test_helpers::insert_agent(&pool).await?;
    let a2 = test_helpers::insert_agent(&pool).await?;
    let hash = [7u8; 32];
    let seed  = test_helpers::insert_claim_with_hash(&pool, a1, &hash).await?;
    let other = test_helpers::insert_claim_with_hash(&pool, a2, &hash).await?;
    let b = ContentHashBlocker;
    let pairs = b.candidates(&pool, &[seed]).await.unwrap();
    assert!(pairs.iter().any(|p| *p == (seed.min(other), seed.max(other))));
    Ok(())
}
```

(Migration 107 makes `content_hash` unique per agent — two different agents can share a hash. That's exactly the cross-source paraphrase signal.)

- [ ] **Step 2: Implement**

```rust
// crates/epigraph-engine/src/matching/blocker/content_hash_prefix.rs
use super::{canonical, Blocker, CandidatePair};
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

pub struct ContentHashBlocker;

#[async_trait]
impl Blocker for ContentHashBlocker {
    async fn candidates(
        &self,
        pool: &PgPool,
        seeds: &[Uuid],
    ) -> Result<Vec<CandidatePair>, sqlx::Error> {
        let mut out = Vec::new();
        for &seed in seeds {
            let nbrs: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT c2.id
                 FROM claims c1
                 JOIN claims c2 ON c2.content_hash = c1.content_hash AND c2.id <> c1.id
                 WHERE c1.id = $1",
            )
            .bind(seed)
            .fetch_all(pool)
            .await?;
            for (n,) in nbrs { if let Some(p) = canonical(seed, n) { out.push(p); } }
        }
        out.sort_unstable(); out.dedup();
        Ok(out)
    }
}
```

- [ ] **Step 3: Run, commit**

```bash
cargo test -p epigraph-engine --test blocker_content_hash_prefix 2>&1 | tail -10
git add crates/epigraph-engine/src/matching/blocker/content_hash_prefix.rs \
        crates/epigraph-engine/src/matching/blocker/mod.rs \
        crates/epigraph-engine/tests/blocker_content_hash_prefix.rs
git commit -m "feat(matching): content-hash equality blocker"
```

---

## Task 10: `union_block` — combine strategies + source-filter

**Files:**
- Modify: `crates/epigraph-engine/src/matching/blocker/mod.rs`
- Test: `crates/epigraph-engine/tests/blocker_union.rs`

- [ ] **Step 1: Write the failing test**

```rust
// crates/epigraph-engine/tests/blocker_union.rs
use epigraph_engine::matching::blocker::{
    union_block, embedding_ann::EmbeddingAnnBlocker, content_hash_prefix::ContentHashBlocker,
    Blocker,
};
use epigraph_engine::matching::source_key::SourceFilterConfig;
use sqlx::PgPool;

#[sqlx::test(migrations = "../../migrations")]
async fn unions_dedups_and_source_filters(pool: PgPool) -> sqlx::Result<()> {
    // Two claims, same paper_doi → should be filtered out as same-source.
    let agent = test_helpers::insert_agent(&pool).await?;
    let hash = [9u8; 32];
    let seed = test_helpers::insert_claim_with_properties_and_hash(
        &pool, agent, serde_json::json!({"paper_doi": "10.1/x"}), &hash).await?;
    let _same_source = test_helpers::insert_claim_with_properties_and_hash(
        &pool, agent, serde_json::json!({"paper_doi": "10.1/x"}), &hash).await?;
    let blockers: Vec<Box<dyn Blocker>> = vec![
        Box::new(ContentHashBlocker),
        Box::new(EmbeddingAnnBlocker::new(10)),
    ];
    let pairs = union_block(&pool, &blockers, &[seed], SourceFilterConfig::default())
        .await.unwrap();
    assert!(pairs.is_empty(), "same-paper pairs should be filtered out");
    Ok(())
}
```

- [ ] **Step 2: Implement**

```rust
// Append to crates/epigraph-engine/src/matching/blocker/mod.rs
use crate::matching::source_key::{derive_source_key, is_same_source, SourceFilterConfig};

pub async fn union_block(
    pool: &PgPool,
    blockers: &[Box<dyn Blocker>],
    seeds: &[Uuid],
    cfg: SourceFilterConfig,
) -> Result<Vec<CandidatePair>, sqlx::Error> {
    let mut all = Vec::new();
    for b in blockers {
        all.extend(b.candidates(pool, seeds).await?);
    }
    all.sort_unstable();
    all.dedup();

    let mut out = Vec::with_capacity(all.len());
    let mut cache: std::collections::HashMap<Uuid, _> = Default::default();
    for (a, b) in all {
        let ka = match cache.get(&a) { Some(k) => k.clone(),
            None => { let k = derive_source_key(pool, a).await?; cache.insert(a, k.clone()); k } };
        let kb = match cache.get(&b) { Some(k) => k.clone(),
            None => { let k = derive_source_key(pool, b).await?; cache.insert(b, k.clone()); k } };
        if !is_same_source(&ka, &kb, cfg) { out.push((a, b)); }
    }
    Ok(out)
}
```

- [ ] **Step 3: Run test, commit**

```bash
cargo test -p epigraph-engine --test blocker_union 2>&1 | tail -10
git add crates/epigraph-engine/src/matching/blocker/mod.rs \
        crates/epigraph-engine/tests/blocker_union.rs
git commit -m "feat(matching): union_block with source-filter"
```

---

## Task 11: Scorer — features + weighted combiner

**Files:**
- Create: `crates/epigraph-engine/src/matching/scorer.rs`
- Modify: `crates/epigraph-engine/src/matching/mod.rs`
- Test: `crates/epigraph-engine/tests/scorer_features.rs`

- [ ] **Step 1: Write the failing test**

```rust
// crates/epigraph-engine/tests/scorer_features.rs
use epigraph_engine::matching::scorer::{score_pair, Weights};
use sqlx::PgPool;

#[sqlx::test(migrations = "../../migrations")]
async fn high_cosine_high_triple_overlap_yields_high_score(pool: PgPool) -> sqlx::Result<()> {
    let agent = test_helpers::insert_agent(&pool).await?;
    let subj = test_helpers::insert_entity(&pool, "X").await?;
    let v = vec![1.0_f32; 1536];
    let a = test_helpers::insert_claim_with_embedding(&pool, agent, &v).await?;
    let b = test_helpers::insert_claim_with_embedding(&pool, agent, &v).await?;
    test_helpers::insert_triple(&pool, a, subj, "P", None).await?;
    test_helpers::insert_triple(&pool, b, subj, "P", None).await?;
    let w = Weights::default();
    let f = score_pair(&pool, a, b, &w).await.unwrap();
    assert!(f.embed_cosine > 0.99);
    assert!(f.triple_overlap > 0.99);
    assert!(f.score > 0.55);
    Ok(())
}
```

- [ ] **Step 2: Implement**

```rust
// crates/epigraph-engine/src/matching/scorer.rs
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchFeatures {
    pub embed_cosine:       f32,
    pub triple_overlap:     f32,
    pub entity_jaccard:     f32,
    pub method_match:       bool,
    pub nbhd_overlap:       f32,
    pub citation_overlap:   f32,
    pub temporal_dist_days: i32,
    pub score:              f32,
}

#[derive(Debug, Clone)]
pub struct Weights {
    pub embed_cosine:     f32,
    pub triple_overlap:   f32,
    pub entity_jaccard:   f32,
    pub method_match:     f32,
    pub nbhd_overlap:     f32,
    pub citation_overlap: f32,
}

impl Default for Weights {
    fn default() -> Self {
        Self {
            embed_cosine: 0.40, triple_overlap: 0.20, entity_jaccard: 0.15,
            method_match: 0.10, nbhd_overlap: 0.10, citation_overlap: 0.05,
        }
    }
}

pub async fn score_pair(
    pool: &PgPool, a: Uuid, b: Uuid, w: &Weights,
) -> Result<MatchFeatures, sqlx::Error> {
    let embed_cosine: f32 = sqlx::query_scalar(
        "SELECT 1.0 - (c1.embedding <=> c2.embedding)::real
         FROM claims c1, claims c2 WHERE c1.id=$1 AND c2.id=$2",
    ).bind(a).bind(b).fetch_one(pool).await.unwrap_or(0.0);

    let triple_overlap: f32 = sqlx::query_scalar(
        "WITH ta AS (SELECT subject_id, predicate FROM entity_triples WHERE claim_id=$1),
              tb AS (SELECT subject_id, predicate FROM entity_triples WHERE claim_id=$2)
         SELECT COALESCE(
           (SELECT COUNT(*)::real FROM (SELECT * FROM ta INTERSECT SELECT * FROM tb) i)
           / NULLIF((SELECT COUNT(*)::real FROM (SELECT * FROM ta UNION SELECT * FROM tb) u), 0),
           0)::real",
    ).bind(a).bind(b).fetch_one(pool).await.unwrap_or(0.0);

    // entity_jaccard, method_match, nbhd_overlap, citation_overlap — analogous queries;
    // start with conservative defaults (0.0 / false) and expand in a follow-up commit
    // once the source tables are confirmed. See spec §3 scorer.
    let entity_jaccard   = 0.0_f32;
    let method_match     = false;
    let nbhd_overlap     = 0.0_f32;
    let citation_overlap = 0.0_f32;
    let temporal_dist_days = 0_i32;

    let raw = w.embed_cosine    * embed_cosine
            + w.triple_overlap  * triple_overlap
            + w.entity_jaccard  * entity_jaccard
            + w.method_match    * if method_match {1.0} else {0.0}
            + w.nbhd_overlap    * nbhd_overlap
            + w.citation_overlap* citation_overlap;
    let denom = w.embed_cosine + w.triple_overlap + w.entity_jaccard
              + w.method_match + w.nbhd_overlap + w.citation_overlap;
    let score = (raw / denom).clamp(0.0, 1.0);

    Ok(MatchFeatures { embed_cosine, triple_overlap, entity_jaccard, method_match,
        nbhd_overlap, citation_overlap, temporal_dist_days, score })
}
```

(The remaining four features are stubbed at 0.0/false in this task. Task 12 fills them in via dedicated tests — keeps each commit focused.)

- [ ] **Step 3: Register `pub mod scorer;` in `matching/mod.rs`, run test, commit**

```bash
cargo test -p epigraph-engine --test scorer_features 2>&1 | tail -10
git add crates/epigraph-engine/src/matching/scorer.rs \
        crates/epigraph-engine/src/matching/mod.rs \
        crates/epigraph-engine/tests/scorer_features.rs
git commit -m "feat(matching): scorer with embed_cosine + triple_overlap"
```

---

## Task 12: Scorer — fill in remaining features (entity, method, nbhd, citation, temporal)

**Files:**
- Modify: `crates/epigraph-engine/src/matching/scorer.rs`
- Test: `crates/epigraph-engine/tests/scorer_full_features.rs`

For each feature, write a failing test that sets up the relevant DB state and asserts the feature is computed nonzero/true. Then add the corresponding SQL to `score_pair`. Commit after each feature lands green.

Features and their data sources:

- `entity_jaccard` — Jaccard over `entity_triples.subject_id ∪ object_id` per claim.
- `method_match` — `claims.properties->>'method_id'` equal (or join through `methods` if present).
- `nbhd_overlap` — Jaccard over `graph_neighborhood_members.neighborhood_id` per claim.
- `citation_overlap` — Jaccard over papers cited via `cites` edges from each claim.
- `temporal_dist_days` — `|EXTRACT(DAY FROM (a.created_at - b.created_at))|`.

For each: TDD test → query addition → verify → commit. Keep each commit one-feature-shaped.

---

## Task 13: Calibration loader

**Files:**
- Create: `crates/epigraph-engine/src/matching/calibration.rs`
- Modify: `calibration.toml` — add `[matcher]` sections
- Modify: `crates/epigraph-engine/src/matching/mod.rs`
- Test: `crates/epigraph-engine/tests/calibration_load.rs`

- [ ] **Step 1: Write the failing test**

```rust
// crates/epigraph-engine/tests/calibration_load.rs
use epigraph_engine::matching::calibration::MatcherConfig;

#[test]
fn loads_weights_and_bands_from_default_calibration_toml() {
    let cfg = MatcherConfig::load_default().unwrap();
    assert!((cfg.weights.embed_cosine - 0.40).abs() < 1e-6);
    assert!((cfg.bands.high - 0.85).abs() < 1e-6);
    assert!((cfg.bands.mid - 0.60).abs() < 1e-6);
    assert_eq!(cfg.embedding_model_version, "v1");
}
```

- [ ] **Step 2: Add `[matcher.*]` to `calibration.toml`**

```toml
# calibration.toml (append)
[matcher.weights]
embed_cosine     = 0.40
triple_overlap   = 0.20
entity_jaccard   = 0.15
method_match     = 0.10
nbhd_overlap     = 0.10
citation_overlap = 0.05

[matcher.bands]
high = 0.85
mid  = 0.60

[matcher.embedding]
model_version = "v1"

[matcher.filter]
include_agent_id = false

[matcher.fan_out]
max_per_claim = 32
```

- [ ] **Step 3: Implement loader**

```rust
// crates/epigraph-engine/src/matching/calibration.rs
use serde::Deserialize;
use std::path::Path;
use crate::matching::scorer::Weights;
use crate::matching::source_key::SourceFilterConfig;

#[derive(Debug, Deserialize)]
pub struct MatcherConfig {
    pub weights: Weights,
    pub bands:   Bands,
    #[serde(default = "default_embed_model")]
    pub embedding_model_version: String,
    #[serde(default)]
    pub filter:  SourceFilterConfig,
    #[serde(default = "default_fan_out")]
    pub fan_out: FanOut,
}

#[derive(Debug, Deserialize, Clone, Copy)]
pub struct Bands { pub high: f32, pub mid: f32 }

#[derive(Debug, Deserialize, Clone, Copy)]
pub struct FanOut { pub max_per_claim: usize }

fn default_embed_model() -> String { "v1".to_string() }
fn default_fan_out() -> FanOut { FanOut { max_per_claim: 32 } }

#[derive(Debug, Deserialize)]
struct WrapperToml { matcher: MatcherConfig }

impl MatcherConfig {
    pub fn load_default() -> anyhow::Result<Self> {
        Self::load_from(Path::new("calibration.toml"))
    }
    pub fn load_from(p: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(p)?;
        let w: WrapperToml = toml::from_str(&raw)?;
        Ok(w.matcher)
    }
}
```

(Adjust `Weights` and `SourceFilterConfig` to derive `Deserialize` if not already.)

- [ ] **Step 4: Run test, commit**

```bash
cargo test -p epigraph-engine --test calibration_load 2>&1 | tail -10
git add calibration.toml crates/epigraph-engine/src/matching/calibration.rs \
        crates/epigraph-engine/src/matching/mod.rs \
        crates/epigraph-engine/src/matching/scorer.rs \
        crates/epigraph-engine/src/matching/source_key.rs \
        crates/epigraph-engine/tests/calibration_load.rs
git commit -m "feat(matching): calibration.toml loader"
```

---

## Task 14: Match-candidate repo

**Files:**
- Create: `crates/epigraph-db/src/repos/match_candidate.rs`
- Modify: `crates/epigraph-db/src/repos/mod.rs` (add `pub mod match_candidate;`)
- Test: `crates/epigraph-db/tests/match_candidate_repo.rs`

- [ ] **Step 1: Write failing tests for upsert + status transitions + stale-on-supersede**

```rust
// crates/epigraph-db/tests/match_candidate_repo.rs
use epigraph_db::repos::match_candidate::{MatchCandidateRow, MatchCandidateRepo};
use sqlx::PgPool;

#[sqlx::test(migrations = "../../migrations")]
async fn upsert_inserts_then_updates(pool: PgPool) -> sqlx::Result<()> {
    let agent = test_helpers::insert_agent(&pool).await?;
    let a = test_helpers::insert_claim(&pool, agent).await?;
    let b = test_helpers::insert_claim(&pool, agent).await?;
    let (lo, hi) = if a < b { (a,b) } else { (b,a) };
    let repo = MatchCandidateRepo::new(pool.clone());
    let id1 = repo.upsert(lo, hi, 0.7, serde_json::json!({}), "pending", None).await?;
    let id2 = repo.upsert(lo, hi, 0.9, serde_json::json!({"x":1}), "pending", None).await?;
    assert_eq!(id1, id2, "upsert must reuse the row");
    let row = repo.get(id1).await?;
    assert!((row.score - 0.9).abs() < 1e-6);
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn promote_writes_decided_fields(pool: PgPool) -> sqlx::Result<()> {
    let agent = test_helpers::insert_agent(&pool).await?;
    let a = test_helpers::insert_claim(&pool, agent).await?;
    let b = test_helpers::insert_claim(&pool, agent).await?;
    let (lo, hi) = if a < b { (a,b) } else { (b,a) };
    let repo = MatchCandidateRepo::new(pool.clone());
    let id = repo.upsert(lo, hi, 0.9, serde_json::json!({}), "pending", None).await?;
    repo.set_status(id, "promoted", Some(agent)).await?;
    let row = repo.get(id).await?;
    assert_eq!(row.status, "promoted");
    assert!(row.decided_at.is_some());
    Ok(())
}
```

- [ ] **Step 2: Implement**

```rust
// crates/epigraph-db/src/repos/match_candidate.rs
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, types::Json};
use uuid::Uuid;
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchCandidateRow {
    pub id: Uuid,
    pub claim_a: Uuid,
    pub claim_b: Uuid,
    pub score: f32,
    pub features: serde_json::Value,
    pub verifier_verdict: Option<String>,
    pub verifier_rationale: Option<String>,
    pub status: String,
    pub matcher_run_id: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub decided_at: Option<OffsetDateTime>,
    pub decided_by: Option<Uuid>,
}

pub struct MatchCandidateRepo { pool: PgPool }

impl MatchCandidateRepo {
    pub fn new(pool: PgPool) -> Self { Self { pool } }

    pub async fn upsert(
        &self, claim_a: Uuid, claim_b: Uuid, score: f32,
        features: serde_json::Value, status: &str, run_id: Option<Uuid>,
    ) -> sqlx::Result<Uuid> {
        debug_assert!(claim_a < claim_b, "callers must pass canonical order");
        let id: (Uuid,) = sqlx::query_as(
            "INSERT INTO match_candidates
                (claim_a, claim_b, score, features, status, matcher_run_id)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (claim_a, claim_b) DO UPDATE SET
                score    = EXCLUDED.score,
                features = EXCLUDED.features,
                status   = EXCLUDED.status,
                matcher_run_id = EXCLUDED.matcher_run_id
             RETURNING id",
        )
        .bind(claim_a).bind(claim_b).bind(score)
        .bind(Json(features)).bind(status).bind(run_id)
        .fetch_one(&self.pool).await?;
        Ok(id.0)
    }

    pub async fn get(&self, id: Uuid) -> sqlx::Result<MatchCandidateRow> {
        sqlx::query_as("SELECT * FROM match_candidates WHERE id=$1")
            .bind(id).fetch_one(&self.pool).await
    }

    pub async fn set_status(&self, id: Uuid, status: &str, by: Option<Uuid>) -> sqlx::Result<()> {
        sqlx::query(
            "UPDATE match_candidates
             SET status=$2, decided_at=now(), decided_by=$3
             WHERE id=$1",
        ).bind(id).bind(status).bind(by).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn list_pending(&self, limit: i64) -> sqlx::Result<Vec<MatchCandidateRow>> {
        sqlx::query_as("SELECT * FROM match_candidates WHERE status='pending'
                       ORDER BY score DESC LIMIT $1")
            .bind(limit).fetch_all(&self.pool).await
    }
}
```

- [ ] **Step 3: Run, commit**

```bash
cargo test -p epigraph-db --test match_candidate_repo 2>&1 | tail -10
git add crates/epigraph-db/src/repos/match_candidate.rs \
        crates/epigraph-db/src/repos/mod.rs \
        crates/epigraph-db/tests/match_candidate_repo.rs
git commit -m "feat(matching): match_candidate repo"
```

---

## Task 15: LLM verifier wrapper

**Files:**
- Create: `crates/epigraph-engine/src/matching/verifier.rs`
- Modify: `crates/epigraph-engine/src/matching/mod.rs`
- Test: `crates/epigraph-engine/tests/verifier_smoke.rs`

The verifier wraps Phase 7's `rerank_bridges::rerank_candidates_table`. It expects a candidate-pair table; we create one transiently, call the library function in dry-run mode, and harvest verdicts.

- [ ] **Step 1: Write the failing test** (uses a fake reranker injected via trait so the test doesn't need an LLM)

```rust
// crates/epigraph-engine/tests/verifier_smoke.rs
use epigraph_engine::matching::verifier::{Verdict, VerifierClient};
use async_trait::async_trait;

struct FakeRerank;
#[async_trait]
impl VerifierClient for FakeRerank {
    async fn verify(&self, _pairs: &[(uuid::Uuid, uuid::Uuid)])
        -> anyhow::Result<Vec<Verdict>>
    {
        Ok(vec![Verdict { relationship: "supports".into(),
                          strength: 0.9, rationale: "ok".into() }])
    }
}

#[tokio::test]
async fn verifier_maps_relationship_to_match_verdict() {
    use epigraph_engine::matching::verifier::{map_relationship, MatchVerdict};
    assert_eq!(map_relationship("supports", 0.9), MatchVerdict::Same);
    assert_eq!(map_relationship("elaborates", 0.7), MatchVerdict::Same);
    assert_eq!(map_relationship("analogous", 0.7), MatchVerdict::Paraphrase);
    assert_eq!(map_relationship("refines", 0.7), MatchVerdict::Overlapping);
    assert_eq!(map_relationship("contradicts", 0.7), MatchVerdict::Contradicts);
    assert_eq!(map_relationship("derives_from", 0.7), MatchVerdict::Distinct);
    assert_eq!(map_relationship("unknown_rel", 0.7), MatchVerdict::Distinct);
}
```

- [ ] **Step 2: Implement**

```rust
// crates/epigraph-engine/src/matching/verifier.rs
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub relationship: String,
    pub strength:     f32,
    pub rationale:    String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchVerdict { Same, Paraphrase, Overlapping, Contradicts, Distinct }

pub fn map_relationship(rel: &str, _strength: f32) -> MatchVerdict {
    match rel {
        "supports" | "elaborates"  => MatchVerdict::Same,
        "analogous"                => MatchVerdict::Paraphrase,
        "refines"                  => MatchVerdict::Overlapping,
        "contradicts"              => MatchVerdict::Contradicts,
        _                          => MatchVerdict::Distinct,
    }
}

#[async_trait]
pub trait VerifierClient: Send + Sync {
    async fn verify(&self, pairs: &[(Uuid, Uuid)]) -> anyhow::Result<Vec<Verdict>>;
}

/// Production client that delegates to Phase 7's library entry-point.
pub struct RerankBridgesClient {
    pool: sqlx::PgPool,
    // Any reranker config from Phase 7; pass-through.
}

impl RerankBridgesClient {
    pub fn new(pool: sqlx::PgPool) -> Self { Self { pool } }
}

#[async_trait]
impl VerifierClient for RerankBridgesClient {
    async fn verify(&self, pairs: &[(Uuid, Uuid)]) -> anyhow::Result<Vec<Verdict>> {
        // 1. Create a temp candidate-pair table.
        let table_name = format!("matcher_verify_{}", Uuid::new_v4().simple());
        sqlx::query(&format!(
            "CREATE TEMP TABLE {} (source_id uuid NOT NULL, target_id uuid NOT NULL)",
            table_name)).execute(&self.pool).await?;
        for (a, b) in pairs {
            sqlx::query(&format!(
                "INSERT INTO {} (source_id, target_id) VALUES ($1, $2)", table_name))
                .bind(a).bind(b).execute(&self.pool).await?;
        }
        // 2. Call Phase 7's rerank_candidates_table in dry-run mode.
        //    Public path: epigraph_cli::rerank::rerank_candidates_table
        //    (re-exported from epigraph_cli::rerank::core).
        //    Config type: epigraph_cli::rerank::RerankConfig
        //    Return type: epigraph_cli::rerank::RerankSummary
        let config = epigraph_cli::rerank::RerankConfig {
            dry_run: true,
            // Fill remaining fields by reading
            // crates/epigraph-cli/src/rerank/core.rs:24 and matching the
            // struct exactly — do not invent fields.
            ..Default::default()
        };
        let summary = epigraph_cli::rerank::rerank_candidates_table(
            &self.pool,
            &table_name,
            &config,
        ).await?;
        // 3. Map summary back to Verdict list aligned with `pairs`.
        //    NOTE: RerankSummary aggregates counts; per-pair verdicts may
        //    require reading rows from a results table populated by the
        //    reranker, or extending RerankSummary. Check the actual
        //    RerankSummary fields (crates/epigraph-cli/src/rerank/core.rs:51)
        //    before implementing — adapt this mapping accordingly.
        let _ = summary;
        Ok(Vec::new())
    }
}
```

(The exact path under `epigraph_cli::bridge::…` must match what Phase 7 landed. Adjust imports + `Cargo.toml` dependency when you confirm. The trait-based design keeps the engine crate decoupled from the CLI crate's internals.)

- [ ] **Step 3: Run unit test (mapping only), commit**

```bash
cargo test -p epigraph-engine --test verifier_smoke 2>&1 | tail -10
git add crates/epigraph-engine/src/matching/verifier.rs \
        crates/epigraph-engine/src/matching/mod.rs \
        crates/epigraph-engine/tests/verifier_smoke.rs
git commit -m "feat(matching): verifier wrapper + verdict mapping"
```

---

## Task 16: Pipeline orchestrator

**Files:**
- Create: `crates/epigraph-engine/src/matching/pipeline.rs`
- Create: `crates/epigraph-engine/src/matching/policy.rs`
- Modify: `crates/epigraph-engine/src/matching/mod.rs`
- Test: `crates/epigraph-engine/tests/pipeline_end_to_end.rs`

- [ ] **Step 1: Write the failing end-to-end test**

```rust
// crates/epigraph-engine/tests/pipeline_end_to_end.rs
use epigraph_engine::matching::pipeline::{run_pipeline, RunInputs};
use epigraph_engine::matching::calibration::MatcherConfig;
use sqlx::PgPool;

#[sqlx::test(migrations = "../../migrations")]
async fn high_band_pair_emits_promoted_candidate_and_corroborates_edge(
    pool: PgPool,
) -> sqlx::Result<()> {
    let agent_x = test_helpers::insert_agent(&pool).await?;
    let agent_y = test_helpers::insert_agent(&pool).await?;
    let v = vec![1.0_f32; 1536];
    let seed = test_helpers::insert_claim_with_properties_and_embedding(
        &pool, agent_x, serde_json::json!({"paper_doi": "10.1/A"}), &v).await?;
    let _peer = test_helpers::insert_claim_with_properties_and_embedding(
        &pool, agent_y, serde_json::json!({"paper_doi": "10.1/B"}), &v).await?;
    let mut cfg = MatcherConfig::load_default().unwrap();
    cfg.bands.high = 0.30; // ensure auto-promote in test
    cfg.bands.mid  = 0.20;

    let report = run_pipeline(&pool, RunInputs {
        seeds: vec![seed],
        cfg,
        verifier: Box::new(test_helpers::AlwaysSameVerifier),
        auto_promote: true,
    }).await.unwrap();

    assert!(report.promoted >= 1);
    let edges: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges WHERE relationship='CORROBORATES'")
        .fetch_one(&pool).await?;
    assert!(edges.0 >= 1);
    Ok(())
}
```

- [ ] **Step 2: Implement `pipeline.rs`**

```rust
// crates/epigraph-engine/src/matching/pipeline.rs
use sqlx::PgPool;
use uuid::Uuid;
use crate::matching::blocker::{union_block, Blocker,
    embedding_ann::EmbeddingAnnBlocker, theme_cluster::ThemeClusterBlocker,
    compound_nbhd::CompoundNbhdBlocker, shared_triple::SharedTripleBlocker,
    content_hash_prefix::ContentHashBlocker};
use crate::matching::calibration::MatcherConfig;
use crate::matching::scorer::score_pair;
use crate::matching::verifier::{VerifierClient, map_relationship, MatchVerdict};
use crate::matching::policy::{Policy, PolicyAction};
use epigraph_db::repos::match_candidate::MatchCandidateRepo;

pub struct RunInputs {
    pub seeds: Vec<Uuid>,
    pub cfg: MatcherConfig,
    pub verifier: Box<dyn VerifierClient>,
    pub auto_promote: bool,
}

pub struct RunReport {
    pub run_id: Uuid,
    pub scanned_pairs: usize,
    pub promoted: usize,
    pub mid_band: usize,
    pub rejected: usize,
}

pub async fn run_pipeline(pool: &PgPool, inputs: RunInputs) -> anyhow::Result<RunReport> {
    let run_id = Uuid::new_v4();
    let blockers: Vec<Box<dyn Blocker>> = vec![
        Box::new(EmbeddingAnnBlocker::new(50)),
        Box::new(ThemeClusterBlocker::new(50)),
        Box::new(CompoundNbhdBlocker::new(50)),
        Box::new(SharedTripleBlocker::new(50)),
        Box::new(ContentHashBlocker),
    ];
    let pairs = union_block(pool, &blockers, &inputs.seeds, inputs.cfg.filter).await?;

    let mut promoted = 0; let mut mid_band = 0; let mut rejected = 0;
    let repo = MatchCandidateRepo::new(pool.clone());
    let policy = Policy::new(pool.clone(), repo, run_id, inputs.auto_promote);

    let mut mid_pairs: Vec<(Uuid,Uuid)> = Vec::new();
    let mut mid_features = Vec::new();
    for (a,b) in &pairs {
        let f = score_pair(pool, *a, *b, &inputs.cfg.weights).await?;
        let s = f.score;
        if s >= inputs.cfg.bands.high {
            policy.act(PolicyAction::AutoPromote, *a, *b, &f, None).await?;
            promoted += 1;
        } else if s >= inputs.cfg.bands.mid {
            mid_pairs.push((*a,*b));
            mid_features.push(f);
        } else {
            rejected += 1;
        }
    }

    if !mid_pairs.is_empty() {
        let verdicts = inputs.verifier.verify(&mid_pairs).await?;
        for ((a,b), v, f) in mid_pairs.into_iter().zip(verdicts).zip(mid_features).map(|((p,v),f)| (p,v,f)) {
            let mv = map_relationship(&v.relationship, v.strength);
            mid_band += 1;
            match mv {
                MatchVerdict::Same | MatchVerdict::Paraphrase => {
                    policy.act(PolicyAction::AutoPromote, a, b, &f, Some(v)).await?;
                    promoted += 1;
                }
                MatchVerdict::Contradicts => {
                    policy.act(PolicyAction::WriteContradicts, a, b, &f, Some(v)).await?;
                    promoted += 1;
                }
                _ => {
                    policy.act(PolicyAction::Reject, a, b, &f, Some(v)).await?;
                    rejected += 1;
                }
            }
        }
    }

    Ok(RunReport { run_id, scanned_pairs: pairs.len(), promoted, mid_band, rejected })
}
```

- [ ] **Step 3: Implement `policy.rs`**

```rust
// crates/epigraph-engine/src/matching/policy.rs
use sqlx::PgPool;
use uuid::Uuid;
use epigraph_db::repos::match_candidate::MatchCandidateRepo;
use crate::matching::scorer::MatchFeatures;
use crate::matching::verifier::Verdict;

#[derive(Debug, Clone, Copy)]
pub enum PolicyAction { AutoPromote, WriteContradicts, Reject }

pub struct Policy {
    pool: PgPool,
    repo: MatchCandidateRepo,
    run_id: Uuid,
    auto_promote: bool,
}

impl Policy {
    pub fn new(pool: PgPool, repo: MatchCandidateRepo, run_id: Uuid, auto_promote: bool) -> Self {
        Self { pool, repo, run_id, auto_promote }
    }

    pub async fn act(
        &self, action: PolicyAction, a: Uuid, b: Uuid,
        f: &MatchFeatures, verdict: Option<Verdict>,
    ) -> anyhow::Result<()> {
        let features = serde_json::to_value(f)?;
        match action {
            PolicyAction::AutoPromote => {
                let id = self.repo.upsert(a, b, f.score, features, "promoted", Some(self.run_id)).await?;
                if self.auto_promote {
                    self.write_corroborates(a, b, f, id, verdict).await?;
                }
            }
            PolicyAction::WriteContradicts => {
                let id = self.repo.upsert(a, b, f.score, features, "promoted", Some(self.run_id)).await?;
                if self.auto_promote {
                    self.write_contradicts(a, b, f, id, verdict).await?;
                }
            }
            PolicyAction::Reject => {
                self.repo.upsert(a, b, f.score, features, "rejected", Some(self.run_id)).await?;
            }
        }
        Ok(())
    }

    async fn write_corroborates(&self, a: Uuid, b: Uuid, f: &MatchFeatures, cand: Uuid, v: Option<Verdict>) -> anyhow::Result<()> {
        let props = serde_json::json!({
            "matcher_run_id": self.run_id,
            "score": f.score,
            "features": f,
            "candidate_id": cand,
            "verifier_verdict": v.as_ref().map(|x| &x.relationship),
        });
        sqlx::query(
            "INSERT INTO edges (source_id, target_id, relationship, properties)
             VALUES ($1, $2, 'CORROBORATES', $3)
             ON CONFLICT DO NOTHING",
        ).bind(a).bind(b).bind(sqlx::types::Json(props)).execute(&self.pool).await?;
        Ok(())
    }

    async fn write_contradicts(&self, a: Uuid, b: Uuid, f: &MatchFeatures, cand: Uuid, v: Option<Verdict>) -> anyhow::Result<()> {
        let props = serde_json::json!({
            "matcher_run_id": self.run_id,
            "score": f.score,
            "features": f,
            "candidate_id": cand,
            "verifier_rationale": v.as_ref().map(|x| &x.rationale),
        });
        sqlx::query(
            "INSERT INTO edges (source_id, target_id, relationship, properties)
             VALUES ($1, $2, 'contradicts', $3)
             ON CONFLICT DO NOTHING",
        ).bind(a).bind(b).bind(sqlx::types::Json(props)).execute(&self.pool).await?;
        Ok(())
    }
}
```

- [ ] **Step 4: Add `test_helpers::AlwaysSameVerifier`**, register modules, run, commit

```bash
cargo test -p epigraph-engine --test pipeline_end_to_end 2>&1 | tail -10
git add crates/epigraph-engine/src/matching/pipeline.rs \
        crates/epigraph-engine/src/matching/policy.rs \
        crates/epigraph-engine/src/matching/mod.rs \
        crates/epigraph-db/src/test_helpers.rs \
        crates/epigraph-engine/tests/pipeline_end_to_end.rs
git commit -m "feat(matching): pipeline + policy"
```

---

## Task 17: CORROBORATES DST aggregation in CDST BP

**Files:**
- Modify: `crates/epigraph-engine/src/cdst_bp.rs`
- Test: `crates/epigraph-engine/tests/cdst_corroborates_aggregation.rs`

When the BP loop computes pignistic over `claim_a`, it must combine masses from `claim_b` for every `CORROBORATES` edge incident on `claim_a`, discounted by `1 - properties.score`, via Dempster's rule. Fan-out capped by `cfg.fan_out.max_per_claim`.

- [ ] **Step 1: Write the failing test**

```rust
// crates/epigraph-engine/tests/cdst_corroborates_aggregation.rs
use sqlx::PgPool;

#[sqlx::test(migrations = "../../migrations")]
async fn corroborated_claim_betp_rises_after_propagation(pool: PgPool) -> sqlx::Result<()> {
    // Two claims, each with high-evidence mass for the "true" hypothesis,
    // joined by a CORROBORATES edge with score=0.95. After BP, the
    // pignistic on the focal claim is higher than without the edge.
    // (Build a fixture; compute BetP twice — once with edge, once without —
    // and assert the with-edge BetP is strictly greater.)
    unimplemented!("see scaffolding in test_helpers")
}
```

- [ ] **Step 2: Implement the propagation step**

In `cdst_bp.rs`, add a function `aggregate_corroborates(pool, focal_claim, base_mass, cfg) -> CombinedMass` that:
1. Queries `CORROBORATES` edges incident on `focal_claim` (both directions), limited to `cfg.fan_out.max_per_claim`.
2. For each, fetches the peer claim's base mass.
3. Discounts the peer's mass by `1 - score`.
4. Combines with the focal mass via Dempster's rule (existing `bba::combine_dempster` or analogous in `bba.rs`).

Call this aggregation step at the appropriate point in the BP iteration (where node masses are updated). Reference `cdst_bp.rs` existing structure.

- [ ] **Step 3: Run, commit**

```bash
cargo test -p epigraph-engine --test cdst_corroborates_aggregation 2>&1 | tail -10
git add crates/epigraph-engine/src/cdst_bp.rs \
        crates/epigraph-engine/tests/cdst_corroborates_aggregation.rs
git commit -m "feat(bp): CORROBORATES evidence pooling in CDST BP"
```

---

## Task 18: Batch-sweep CLI binary

**Files:**
- Create: `crates/epigraph-cli/src/bin/cross_source_sweep.rs`
- Modify: `crates/epigraph-cli/Cargo.toml` (register binary)
- Test: `crates/epigraph-cli/tests/cross_source_sweep_smoke.rs`

- [ ] **Step 1: Write the failing smoke test**

```rust
// crates/epigraph-cli/tests/cross_source_sweep_smoke.rs
use assert_cmd::Command;

#[test]
fn binary_help_prints_expected_args() {
    let out = Command::cargo_bin("cross_source_sweep").unwrap()
        .arg("--help").output().unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("--limit"));
    assert!(s.contains("--dry-run"));
    assert!(s.contains("--apply"));
}
```

- [ ] **Step 2: Implement**

```rust
// crates/epigraph-cli/src/bin/cross_source_sweep.rs
use clap::Parser;
use sqlx::postgres::PgPoolOptions;
use epigraph_engine::matching::pipeline::{run_pipeline, RunInputs};
use epigraph_engine::matching::calibration::MatcherConfig;
use epigraph_engine::matching::verifier::RerankBridgesClient;

#[derive(Parser)]
#[command(name = "cross_source_sweep")]
struct Args {
    #[arg(long, default_value_t = 200)] limit: i64,
    #[arg(long)] dry_run: bool,
    #[arg(long)] apply: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.dry_run == args.apply {
        anyhow::bail!("exactly one of --dry-run or --apply must be set");
    }
    let pool = PgPoolOptions::new().connect(&std::env::var("DATABASE_URL")?).await?;
    let cfg = MatcherConfig::load_default()?;
    let seeds: Vec<uuid::Uuid> = sqlx::query_scalar(
        "SELECT id FROM claims
         WHERE last_match_scan_at IS NULL OR last_match_scan_at < now() - INTERVAL '7 days'
         ORDER BY created_at DESC LIMIT $1",
    ).bind(args.limit).fetch_all(&pool).await?;

    let verifier = Box::new(RerankBridgesClient::new(pool.clone()));
    let report = run_pipeline(&pool, RunInputs {
        seeds: seeds.clone(), cfg, verifier, auto_promote: args.apply,
    }).await?;

    sqlx::query("UPDATE claims SET last_match_scan_at = now() WHERE id = ANY($1)")
        .bind(&seeds).execute(&pool).await?;

    println!("{}", serde_json::json!({
        "run_id": report.run_id, "seeds": seeds.len(),
        "scanned_pairs": report.scanned_pairs, "promoted": report.promoted,
        "mid_band": report.mid_band, "rejected": report.rejected,
        "apply": args.apply,
    }));
    Ok(())
}
```

- [ ] **Step 3: Register, run, commit**

```bash
cargo test -p epigraph-cli --test cross_source_sweep_smoke 2>&1 | tail -10
git add crates/epigraph-cli/src/bin/cross_source_sweep.rs \
        crates/epigraph-cli/Cargo.toml \
        crates/epigraph-cli/tests/cross_source_sweep_smoke.rs
git commit -m "feat(matching): cross_source_sweep CLI"
```

---

## Task 19: MCP tools (find / list / decide)

**Files:**
- Create: `crates/epigraph-mcp/src/tools/matching.rs`
- Modify: `crates/epigraph-mcp/src/tools/mod.rs`
- Modify: `crates/epigraph-mcp/src/server.rs` (register handlers)
- Test: `crates/epigraph-mcp/tests/matching_tools_smoke.rs`

Three tools:

| Tool                              | Scope        | Behavior                                                  |
| --------------------------------- | ------------ | --------------------------------------------------------- |
| `find_cross_source_matches`       | any agent    | Scoped pipeline run; read-only unless `commit=true`       |
| `list_match_candidates`           | admin        | Returns pending candidates, sorted by score desc          |
| `decide_match_candidate`          | admin        | Promote → CORROBORATES, or reject                         |

- [ ] **Step 1: Write the failing smoke test** for `find_cross_source_matches`. Mirror existing MCP-tool integration tests under `epigraph-mcp/tests/`.

- [ ] **Step 2: Implement each tool** as a function in `matching.rs`, exporting a `ToolHandler` registered in `server.rs`. Admin tools use the `claims:admin` scope check pattern (search `epigraph-mcp/src/tools/` for `claims:admin` for the existing template).

- [ ] **Step 3: Run, commit per tool**

```bash
cargo test -p epigraph-mcp --test matching_tools_smoke 2>&1 | tail -10
git add crates/epigraph-mcp/src/tools/matching.rs \
        crates/epigraph-mcp/src/tools/mod.rs \
        crates/epigraph-mcp/src/server.rs \
        crates/epigraph-mcp/tests/matching_tools_smoke.rs
git commit -m "feat(matching): MCP tools (find, list, decide)"
```

---

## Task 20: API route — `GET /api/v1/claims/:id/cross_source_matches`

**Files:**
- Create: `crates/epigraph-api/src/routes/cross_source.rs`
- Modify: `crates/epigraph-api/src/routes/mod.rs` (register)
- Test: `crates/epigraph-api/tests/routes/cross_source_route_tests.rs`

- [ ] **Step 1: Write the failing route test**

```rust
// crates/epigraph-api/tests/routes/cross_source_route_tests.rs
// Patterned on existing route tests in the same directory.
// Asserts:
//   1. 200 OK with empty array when no candidates
//   2. Returns promoted CORROBORATES edges + pending match_candidates
//   3. 404 when claim does not exist
```

- [ ] **Step 2: Implement** the route returning `{ corroborates: [...], pending: [...] }`.

- [ ] **Step 3: Run, commit**

```bash
cargo test -p epigraph-api --test routes_tests cross_source_route 2>&1 | tail -10
git add crates/epigraph-api/src/routes/cross_source.rs \
        crates/epigraph-api/src/routes/mod.rs \
        crates/epigraph-api/tests/routes/cross_source_route_tests.rs
git commit -m "feat(matching): API route cross_source_matches"
```

---

## Task 21: SciFact calibration harness

**Files:**
- Create: `tests/scifact/calibrate_matcher.rs`
- Create: `scripts/scifact_ingest.sh` (one-shot SciFact ingest into a calibration DB)
- Modify: `calibration.toml` after a calibration pass

- [ ] **Step 1: Add scripts/scifact_ingest.sh** — downloads SciFact, ingests claims + evidence via existing ingest path into a fresh `epigraph_db_scifact` database.

- [ ] **Step 2: Write the harness**

```rust
// tests/scifact/calibrate_matcher.rs
// 1. Connect to epigraph_db_scifact.
// 2. Build positive pairs: SciFact claims sharing same supporting evidence on same fact.
// 3. Build hard negatives: same topic, different fact.
// 4. Build easy negatives: random.
// 5. For each weight tuple in a small grid + each (high, mid) threshold pair:
//    - Score all pairs via scorer.
//    - Compute precision/recall/F1 per band.
//    - Record to a JSON report.
// 6. Print top-3 (weights, bands) combinations by mid-band precision-after-verifier,
//    constrained to high-band precision >= 0.95.
```

- [ ] **Step 3: Run the harness, paste the winning tuple into `calibration.toml`**, commit.

```bash
cargo test --test calibrate_matcher --release -- --ignored --nocapture
# inspect report, pick top tuple, edit calibration.toml
git add tests/scifact/ scripts/scifact_ingest.sh calibration.toml
git commit -m "feat(matching): SciFact calibration harness + tuned weights"
```

---

## Task 22: Adversarial test corpus

**Files:**
- Create: `tests/scifact/adversarial_pairs.rs`

Hand-craft ~30 pairs covering:
- Negation flips (`"X causes Y"` vs `"X does not cause Y"`) — expect distinct
- Scope flips (`"in mice"` vs `"in humans"`) — expect overlapping
- Near-duplicates with one crucial number change — expect distinct
- Same-claim paraphrases — expect same

For each pair, assert the matcher's verdict matches the expected verdict (or, if mid-band, that the LLM verifier resolves it correctly). Fail the build if any adversarial pair flips.

- [ ] **Step 1: Write the corpus + harness**
- [ ] **Step 2: Run, fix any failures (typically requires verifier prompt tuning, not matcher changes)**
- [ ] **Step 3: Commit**

```bash
cargo test --test adversarial_pairs --release -- --ignored
git add tests/scifact/adversarial_pairs.rs
git commit -m "test(matching): adversarial pair corpus"
```

---

## Task 23: Cargo-workspace cleanup + docs

- [ ] **Step 1: `cargo fmt --all` and `cargo clippy --workspace -- -D warnings` clean**

```bash
cd /home/jeremy/epigraph-wt-cross-source-matching
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 2: Update `crates/epigraph-engine/src/lib.rs` doc-comment** to mention the `matching` module.

- [ ] **Step 3: Add an entry to the project README** linking to the spec and naming the CLI.

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "chore(matching): fmt + clippy clean; README pointer"
```

---

## Acceptance Checklist

- [ ] Migrations 110 + 111 apply cleanly on a fresh `epigraph_db_repo_test` database.
- [ ] All new tests (`source_key_*`, `blocker_*`, `scorer_*`, `pipeline_*`, `cdst_corroborates_*`, `matching_tools_*`, `cross_source_route_*`) pass.
- [ ] Phase 7 deliverables (`rerank_candidates_table` library entry-point + HNSW migration) confirmed present before merge.
- [ ] `cross_source_sweep --dry-run --limit 50` on the dev DB completes, emits a JSON report, writes `match_candidates` rows, writes zero edges.
- [ ] `cross_source_sweep --apply --limit 50` writes `CORROBORATES` edges only for high-band candidates and admin-approved mid-band.
- [ ] SciFact calibration produces high-band precision ≥ 0.95.
- [ ] Adversarial corpus: 0 unexpected flips.
- [ ] `cargo fmt --check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace` all green.
- [ ] MCP tools registered and callable via `mcp list_tools`.
- [ ] DST aggregation: a corroborated claim's BetP rises after BP, compared to an identical fixture without the `CORROBORATES` edge.

---

## Self-Review Notes

- All tasks list exact file paths.
- Each task is TDD: failing test → minimal impl → green → commit.
- Tasks 6–9 and 12 reuse the Task-5 pattern (Blocker trait + DB query + canonical-pair output); the plan shows full code for Task 5 and 6, structural for 7–9 — engineers reading out of order can lift from 5/6.
- Task 12 (remaining scorer features) is intentionally a single task that the engineer expands into per-feature commits inside it; this keeps the plan from ballooning while preserving fine-grained commits in the actual implementation.
- Task 17 (CDST aggregation) is the highest-risk task; the test fixture is the load-bearing verification. If the existing `bba::combine_dempster` signature differs, adapt the call site — do not change Dempster semantics.
- Phase 7 dependencies (verifier library entry-point, HNSW migration) are gated by the pre-flight section; the plan halts if absent.
