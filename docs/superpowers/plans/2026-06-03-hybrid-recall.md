# Hybrid (semantic + BM25) `recall` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the plain `recall` MCP tool a semantic + lexical (BM25-ish) hybrid: fuse a dense `claims.embedding` leg and a lexical `content_tsv` leg with Reciprocal Rank Fusion (RRF) in SQL.

**Architecture:** One new repo method (`ClaimRepository::search_hybrid_scoped`) runs both legs as CTEs and RRF-fuses in a single SQL round-trip; a sibling `search_lexical_scoped` powers the embedder-down fallback. `McpEmbedder` gains a thin hybrid wrapper; `recall()` calls it and degrades to scope-honoring lexical-only on embedder failure. A migration reconciles the untracked `content_tsv` column.

**Tech Stack:** Rust, sqlx (runtime `query_as`, no macros → no `.sqlx` churn), Postgres 16 + pgvector (HNSW) + native FTS (GIN), `#[sqlx::test]` integration tests.

**Spec:** `docs/superpowers/specs/2026-06-03-hybrid-recall-design.md`
**Worktree/branch:** `/home/jeremy/epigraph-wt-hybrid-recall` on `feat/hybrid-recall` (off `origin/main` @ `2a31f8d`).

**Standing conventions for every task:**
- Run all cargo commands with a worktree-dedicated target dir to avoid the shared-`~/.cargo-target` stale-rmeta foot-gun: prefix with `CARGO_TARGET_DIR=/home/jeremy/.cargo-target-hybrid`.
- DB tests: `DATABASE_URL=postgres://epigraph:epigraph@localhost:5432/epigraph` (the `epigraph` superuser; `#[sqlx::test]` creates/drops ephemeral DBs and needs that privilege).
- CI gate before every commit: `cargo fmt --check`, `cargo clippy --workspace --locked -- -D warnings`, then the task's tests. CI job order is build → clippy → fmt → test, all `--locked`.
- Commit messages follow the repo's Epistemic Commit Protocol (`<type>(<scope>): …` + Evidence/Reasoning/Verification). End with `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- Tests get a council-of-critics pass (reject tautological / mock-shaped / happy-path-only).

---

### Task 1: Reconcile the `content_tsv` schema drift (migration 050)

`content_tsv` + `idx_claims_content_tsv` exist on prod but are absent from `migrations/` and unreferenced by code. Fresh `#[sqlx::test]` DBs (built from `migrations/`) won't have the column, so every later test would fail. Add an idempotent migration.

**Files:**
- Create: `migrations/050_claims_content_tsv.sql`

- [ ] **Step 1: Write the migration**

```sql
-- 050_claims_content_tsv.sql
-- Reconcile the `content_tsv` generated column + its GIN index into version
-- control. Both already exist on prod (added manually, never migrated); this
-- records them so fresh DBs (sqlx::test, new deploys) are reproducible.
-- IF NOT EXISTS makes it a no-op where they already exist.
ALTER TABLE claims
  ADD COLUMN IF NOT EXISTS content_tsv tsvector
  GENERATED ALWAYS AS (to_tsvector('english', content)) STORED;

CREATE INDEX IF NOT EXISTS idx_claims_content_tsv
  ON claims USING gin (content_tsv);
```

- [ ] **Step 2: Verify the migration applies on a fresh DB**

The fastest proof is to run an existing epigraph-db integration test, which now runs migrations through `050`:

Run:
```bash
CARGO_TARGET_DIR=/home/jeremy/.cargo-target-hybrid \
DATABASE_URL=postgres://epigraph:epigraph@localhost:5432/epigraph \
cargo test -p epigraph-db --test claim_search_by_embedding -- --nocapture
```
Expected: PASS (3 tests). A migration error would surface as "migration 050 … failed".

- [ ] **Step 3: Commit**

```bash
git add migrations/050_claims_content_tsv.sql
git commit  # docs the drift reconciliation per Evidence/Reasoning/Verification
```

---

### Task 2: `HybridHit` + `ClaimRepository::search_hybrid_scoped` (RRF in SQL)

**Files:**
- Modify: `crates/epigraph-db/src/repos/claim.rs` (add struct near `ClaimEmbeddingHit` @ line 18; add method near `search_by_embedding_scoped` @ line 559)
- Modify: `crates/epigraph-db/src/repos/mod.rs:68` and `crates/epigraph-db/src/lib.rs:63` (re-export `HybridHit`)
- Test: `crates/epigraph-db/tests/claim_search_hybrid.rs` (new)

- [ ] **Step 1: Write the failing tests**

Create `crates/epigraph-db/tests/claim_search_hybrid.rs`:

```rust
//! Integration tests for `ClaimRepository::search_hybrid_scoped` (RRF fusion of
//! the dense `claims.embedding` leg and the lexical `content_tsv` leg).
//!
//! Schema notes (mirrors claim_search_by_embedding.rs): seed an `agents` row
//! first (FK + edge-validation trigger); `content_hash bytea NOT NULL` and
//! `(content_hash, agent_id)` UNIQUE → use distinct hashes. `content_tsv` is a
//! GENERATED column (migration 050), so inserting `content` auto-populates it.

use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// 1536-d unit-ish vector with the "hot" dimension at `idx` set to 0.99.
fn vec_hot(idx: usize) -> String {
    let mut v = vec!["0.0"; 1536];
    v[idx] = "0.99";
    format!("[{}]", v.join(","))
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(agent_id)
        .bind("aa".repeat(32))
        .execute(pool)
        .await
        .expect("seed agent");
    agent_id
}

fn distinct_hash(tag: u8) -> Vec<u8> {
    let mut h = vec![0u8; 32];
    h[0] = tag;
    h
}

#[allow(clippy::too_many_arguments)]
async fn insert_claim(
    pool: &PgPool,
    id: Uuid,
    agent: Uuid,
    tag: u8,
    content: &str,
    embedding_pgvec: &str,
    is_current: bool,
    labels: &[&str],
) {
    let labels_arr: Vec<String> = labels.iter().map(|s| s.to_string()).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, labels, embedding) \
         VALUES ($1, $2, $3, $4, 0.8, $5, $6, $7::vector)",
    )
    .bind(id)
    .bind(content)
    .bind(distinct_hash(tag))
    .bind(agent)
    .bind(is_current)
    .bind(&labels_arr)
    .bind(embedding_pgvec)
    .execute(pool)
    .await
    .expect("insert claim");
}

#[sqlx::test(migrations = "../../migrations")]
async fn hybrid_fuses_both_legs_ranking_the_overlap_first(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let query = vec_hot(0); // dense query points at dim 0

    // DENSE: closest vector, no lexical overlap with the query text.
    let dense = Uuid::new_v4();
    insert_claim(&pool, dense, agent, 1, "orthogonal filler prose about weather", &vec_hot(0), true, &[]).await;
    // BOTH: 2nd-closest vector AND contains the rare lexical term.
    let both = Uuid::new_v4();
    insert_claim(&pool, both, agent, 2, "discussion of quasinormal mechanosynthesis tooling", &vec_hot(1), true, &[]).await;
    // LEX: far vector, contains the rare lexical term.
    let lex = Uuid::new_v4();
    insert_claim(&pool, lex, agent, 3, "quasinormal mechanosynthesis appears here too", &vec_hot(900), true, &[]).await;

    let hits = ClaimRepository::search_hybrid_scoped(
        &pool, &query, "quasinormal mechanosynthesis", 50, 60, 10, None, None,
    )
    .await
    .expect("hybrid search");

    let order: Vec<Uuid> = hits.iter().map(|h| h.claim_id).collect();
    assert!(order.contains(&both) && order.contains(&dense) && order.contains(&lex));
    // `both` is in BOTH legs → its RRF sum beats any single-leg claim.
    assert_eq!(order[0], both, "overlap claim must rank first; got {order:?}");

    let both_hit = hits.iter().find(|h| h.claim_id == both).unwrap();
    assert!(both_hit.dense_similarity.is_some() && both_hit.in_lexical, "both legs");
    let dense_hit = hits.iter().find(|h| h.claim_id == dense).unwrap();
    assert!(dense_hit.dense_similarity.is_some() && !dense_hit.in_lexical, "dense only");
}

#[sqlx::test(migrations = "../../migrations")]
async fn hybrid_surfaces_lexical_only_hit_outside_dense_pool(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let query = vec_hot(0);

    let dense = Uuid::new_v4();
    insert_claim(&pool, dense, agent, 1, "no overlap filler", &vec_hot(0), true, &[]).await;
    let lex = Uuid::new_v4();
    insert_claim(&pool, lex, agent, 2, "rare token zubuzonium present", &vec_hot(900), true, &[]).await;

    // candidate_pool=1 → dense leg yields only `dense`; `lex` can only enter via
    // the lexical leg, so dense_similarity must be NULL there.
    let hits = ClaimRepository::search_hybrid_scoped(
        &pool, &query, "zubuzonium", 1, 60, 10, None, None,
    )
    .await
    .expect("hybrid search");

    let lex_hit = hits.iter().find(|h| h.claim_id == lex).expect("lexical-only hit present");
    assert!(lex_hit.dense_similarity.is_none(), "lexical-only ⇒ no dense similarity");
    assert!(lex_hit.in_lexical);
}

#[sqlx::test(migrations = "../../migrations")]
async fn hybrid_excludes_non_current_and_honors_tag_scope(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let query = vec_hot(0);

    // Non-current claim that would otherwise match both legs.
    let stale = Uuid::new_v4();
    insert_claim(&pool, stale, agent, 1, "zubuzonium stale", &vec_hot(0), false, &["keep"]).await;
    // Current, in-scope (label "keep").
    let keep = Uuid::new_v4();
    insert_claim(&pool, keep, agent, 2, "zubuzonium keep", &vec_hot(0), true, &["keep"]).await;
    // Current, out-of-scope (no "keep" label).
    let drop = Uuid::new_v4();
    insert_claim(&pool, drop, agent, 3, "zubuzonium drop", &vec_hot(0), true, &["other"]).await;

    let tags = vec!["keep".to_string()];
    let hits = ClaimRepository::search_hybrid_scoped(
        &pool, &query, "zubuzonium", 50, 60, 10, Some(&tags), None,
    )
    .await
    .expect("hybrid search");

    let ids: Vec<Uuid> = hits.iter().map(|h| h.claim_id).collect();
    assert!(ids.contains(&keep), "in-scope current claim present");
    assert!(!ids.contains(&stale), "non-current excluded");
    assert!(!ids.contains(&drop), "out-of-scope (tag) excluded on both legs");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
CARGO_TARGET_DIR=/home/jeremy/.cargo-target-hybrid \
DATABASE_URL=postgres://epigraph:epigraph@localhost:5432/epigraph \
cargo test -p epigraph-db --test claim_search_hybrid
```
Expected: FAIL to compile — `no function search_hybrid_scoped` / `no type HybridHit`.

- [ ] **Step 3: Add `HybridHit` struct + re-exports**

In `crates/epigraph-db/src/repos/claim.rs`, immediately after the `ClaimEmbeddingHit` struct (ends line 21):

```rust
/// One fused hit from [`ClaimRepository::search_hybrid_scoped`] /
/// [`ClaimRepository::search_lexical_scoped`].
///
/// `rrf_score` is the Reciprocal Rank Fusion score (higher = better; sums
/// `1/(k+rank)` across the legs the claim appeared in). `dense_similarity` is
/// `Some(1 - cosine_distance)` when the claim was in the dense (embedding) leg,
/// `None` for lexical-only hits. `in_lexical` is true when it appeared in the
/// lexical (`content_tsv`) leg.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct HybridHit {
    pub claim_id: Uuid,
    pub rrf_score: f64,
    pub dense_similarity: Option<f64>,
    pub in_lexical: bool,
}
```

In `crates/epigraph-db/src/repos/mod.rs:68`, add `HybridHit` to the `claim` re-export list:
```rust
    ClaimEmbeddingHit, ClaimPairDistance, ClaimRepository, EvolveStepResult, HybridHit, LineageHead,
```
In `crates/epigraph-db/src/lib.rs:63`, add `HybridHit` to the `pub use repos::{ … }` list (alongside `ClaimEmbeddingHit`):
```rust
    ChallengeRow, ClaimEmbeddingHit, ClaimEncryptionRepository, ClaimEncryptionRow, HybridHit,
```

- [ ] **Step 4: Add `search_hybrid_scoped`**

In `crates/epigraph-db/src/repos/claim.rs`, after `search_by_embedding_scoped` (line 594), inside `impl ClaimRepository`:

```rust
    /// Hybrid retrieval over current claims: RRF-fuse a dense
    /// (`claims.embedding`, HNSW) leg and a lexical (`content_tsv`, GIN) leg in
    /// one round-trip. Both legs share the `is_current` / `labels @> tags` /
    /// `agent_id` predicates, so the only difference is the relevance signal.
    /// `candidate_pool` caps each leg before fusion; `k_rrf` is the RRF constant.
    #[allow(clippy::too_many_arguments)]
    pub async fn search_hybrid_scoped(
        pool: &PgPool,
        query_embedding_pgvector: &str,
        query_text: &str,
        candidate_pool: i64,
        k_rrf: i64,
        limit: i64,
        tags: Option<&[String]>,
        agent_id: Option<Uuid>,
    ) -> Result<Vec<HybridHit>, DbError> {
        let tags_owned: Option<Vec<String>> = match tags {
            Some(t) if !t.is_empty() => Some(t.to_vec()),
            _ => None,
        };

        let rows = sqlx::query_as::<_, HybridHit>(
            r#"
            WITH dense AS (
                SELECT c.id,
                       row_number() OVER (ORDER BY c.embedding <=> $1::vector) AS rank,
                       1 - (c.embedding <=> $1::vector) AS cos
                FROM claims c
                WHERE c.embedding IS NOT NULL AND c.is_current
                  AND ($6::text[] IS NULL OR c.labels @> $6::text[])
                  AND ($7::uuid IS NULL OR c.agent_id = $7::uuid)
                ORDER BY c.embedding <=> $1::vector
                LIMIT $3
            ),
            lex AS (
                SELECT c.id,
                       row_number() OVER (ORDER BY ts_rank_cd(c.content_tsv, q) DESC) AS rank
                FROM claims c, websearch_to_tsquery('english', $2) q
                WHERE c.content_tsv @@ q AND c.is_current
                  AND ($6::text[] IS NULL OR c.labels @> $6::text[])
                  AND ($7::uuid IS NULL OR c.agent_id = $7::uuid)
                ORDER BY ts_rank_cd(c.content_tsv, q) DESC
                LIMIT $3
            )
            SELECT COALESCE(d.id, l.id) AS claim_id,
                   (COALESCE(1.0/($4 + d.rank), 0)
                    + COALESCE(1.0/($4 + l.rank), 0))::float8 AS rrf_score,
                   d.cos::float8 AS dense_similarity,
                   (l.rank IS NOT NULL) AS in_lexical
            FROM dense d
            FULL OUTER JOIN lex l ON d.id = l.id
            ORDER BY rrf_score DESC
            LIMIT $5
            "#,
        )
        .bind(query_embedding_pgvector) // $1
        .bind(query_text)               // $2
        .bind(candidate_pool)           // $3
        .bind(k_rrf)                    // $4
        .bind(limit)                    // $5
        .bind(tags_owned)               // $6
        .bind(agent_id)                 // $7
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run:
```bash
CARGO_TARGET_DIR=/home/jeremy/.cargo-target-hybrid \
DATABASE_URL=postgres://epigraph:epigraph@localhost:5432/epigraph \
cargo test -p epigraph-db --test claim_search_hybrid -- --nocapture
```
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add crates/epigraph-db/src/repos/claim.rs crates/epigraph-db/src/repos/mod.rs \
        crates/epigraph-db/src/lib.rs crates/epigraph-db/tests/claim_search_hybrid.rs
git commit  # feat(db): RRF hybrid search over claims.embedding + content_tsv
```

---

### Task 3: `ClaimRepository::search_lexical_scoped` (embedder-down fallback)

**Files:**
- Modify: `crates/epigraph-db/src/repos/claim.rs` (add after `search_hybrid_scoped`)
- Test: `crates/epigraph-db/tests/claim_search_hybrid.rs` (extend)

- [ ] **Step 1: Write the failing test** — append to `claim_search_hybrid.rs`:

```rust
#[sqlx::test(migrations = "../../migrations")]
async fn lexical_scoped_ranks_matches_and_honors_scope(pool: PgPool) {
    let agent = seed_agent(&pool).await;

    let hit = Uuid::new_v4();
    insert_claim(&pool, hit, agent, 1, "zubuzonium reactor design", &vec_hot(0), true, &["keep"]).await;
    let miss = Uuid::new_v4();
    insert_claim(&pool, miss, agent, 2, "unrelated weather prose", &vec_hot(0), true, &["keep"]).await;
    let stale = Uuid::new_v4();
    insert_claim(&pool, stale, agent, 3, "zubuzonium stale", &vec_hot(0), false, &["keep"]).await;
    let oos = Uuid::new_v4();
    insert_claim(&pool, oos, agent, 4, "zubuzonium other", &vec_hot(0), true, &["other"]).await;

    let tags = vec!["keep".to_string()];
    let hits = ClaimRepository::search_lexical_scoped(&pool, "zubuzonium", 60, 10, Some(&tags), None)
        .await
        .expect("lexical search");

    let ids: Vec<Uuid> = hits.iter().map(|h| h.claim_id).collect();
    assert!(ids.contains(&hit), "lexical match in scope present");
    assert!(!ids.contains(&miss), "non-matching content excluded");
    assert!(!ids.contains(&stale), "non-current excluded");
    assert!(!ids.contains(&oos), "out-of-scope tag excluded");

    let h = hits.iter().find(|h| h.claim_id == hit).unwrap();
    assert!(h.dense_similarity.is_none() && h.in_lexical, "lexical-only shape");
    assert!(h.rrf_score > 0.0);
}
```

- [ ] **Step 2: Run to verify it fails**

Run:
```bash
CARGO_TARGET_DIR=/home/jeremy/.cargo-target-hybrid \
DATABASE_URL=postgres://epigraph:epigraph@localhost:5432/epigraph \
cargo test -p epigraph-db --test claim_search_hybrid lexical_scoped
```
Expected: FAIL to compile — `no function search_lexical_scoped`.

- [ ] **Step 3: Implement** — in `crates/epigraph-db/src/repos/claim.rs`, after `search_hybrid_scoped`:

```rust
    /// Lexical-only retrieval over current claims (`content_tsv` / GIN), ranked
    /// by `ts_rank_cd`. Returns `HybridHit`s with `dense_similarity = None` and
    /// `in_lexical = true`; `rrf_score = 1/(k_rrf + rank)` keeps the score scale
    /// consistent with the hybrid path. Used as `recall`'s embedder-down
    /// fallback — unlike an ILIKE scan it honors the tag/agent scope in SQL.
    pub async fn search_lexical_scoped(
        pool: &PgPool,
        query_text: &str,
        k_rrf: i64,
        limit: i64,
        tags: Option<&[String]>,
        agent_id: Option<Uuid>,
    ) -> Result<Vec<HybridHit>, DbError> {
        let tags_owned: Option<Vec<String>> = match tags {
            Some(t) if !t.is_empty() => Some(t.to_vec()),
            _ => None,
        };

        let rows = sqlx::query_as::<_, HybridHit>(
            r#"
            SELECT c.id AS claim_id,
                   (1.0 / ($2 + row_number() OVER (
                       ORDER BY ts_rank_cd(c.content_tsv, q) DESC)))::float8 AS rrf_score,
                   NULL::float8 AS dense_similarity,
                   true AS in_lexical
            FROM claims c, websearch_to_tsquery('english', $1) q
            WHERE c.content_tsv @@ q AND c.is_current
              AND ($4::text[] IS NULL OR c.labels @> $4::text[])
              AND ($5::uuid IS NULL OR c.agent_id = $5::uuid)
            ORDER BY ts_rank_cd(c.content_tsv, q) DESC
            LIMIT $3
            "#,
        )
        .bind(query_text) // $1
        .bind(k_rrf)      // $2
        .bind(limit)      // $3
        .bind(tags_owned) // $4
        .bind(agent_id)   // $5
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }
```

- [ ] **Step 4: Run to verify it passes**

Run:
```bash
CARGO_TARGET_DIR=/home/jeremy/.cargo-target-hybrid \
DATABASE_URL=postgres://epigraph:epigraph@localhost:5432/epigraph \
cargo test -p epigraph-db --test claim_search_hybrid -- --nocapture
```
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/epigraph-db/src/repos/claim.rs crates/epigraph-db/tests/claim_search_hybrid.rs
git commit  # feat(db): scope-honoring lexical-only search for recall fallback
```

---

### Task 4: `McpEmbedder::search_hybrid_scoped` + RRF constants

**Files:**
- Modify: `crates/epigraph-mcp/src/embed.rs` (constants near top; method after `search_scoped` @ line 133)

- [ ] **Step 1: Add constants + method**

Near the top of `crates/epigraph-mcp/src/embed.rs` (after the `use` lines, before `pub struct McpEmbedder`):

```rust
/// Per-leg candidate pool size before RRF fusion in hybrid recall.
pub const HYBRID_CANDIDATE_POOL: i64 = 50;
/// Reciprocal Rank Fusion constant `k` (canonical default 60).
pub const HYBRID_RRF_K: i64 = 60;
```

Inside `impl McpEmbedder`, after `search_scoped` (closes at line 133):

```rust
    /// Hybrid retrieval: embed the query (1536d), then RRF-fuse the dense and
    /// lexical legs via [`ClaimRepository::search_hybrid_scoped`]. Returns the
    /// fused hits; the caller (`recall`) degrades to lexical-only on `Err`.
    pub async fn search_hybrid_scoped(
        &self,
        query: &str,
        limit: i64,
        tags: Option<&[String]>,
        agent_id: Option<uuid::Uuid>,
    ) -> Result<Vec<epigraph_db::HybridHit>, String> {
        let embedding = self.generate(query).await?;
        let pgvec = format_pgvector(&embedding);
        epigraph_db::ClaimRepository::search_hybrid_scoped(
            &self.pool,
            &pgvec,
            query,
            HYBRID_CANDIDATE_POOL,
            HYBRID_RRF_K,
            limit,
            tags,
            agent_id,
        )
        .await
        .map_err(|e| e.to_string())
    }
```

- [ ] **Step 2: Verify it compiles**

Run:
```bash
CARGO_TARGET_DIR=/home/jeremy/.cargo-target-hybrid cargo check -p epigraph-mcp
```
Expected: compiles (warnings about the unused method/consts are fine until Task 5 wires them).

- [ ] **Step 3: Commit**

```bash
git add crates/epigraph-mcp/src/embed.rs
git commit  # feat(mcp): McpEmbedder::search_hybrid_scoped + RRF tuning constants
```

---

### Task 5: Extend `RecallResult` + rewire `recall()` + seam test

**Files:**
- Modify: `crates/epigraph-mcp/src/types.rs:728` (`RecallResult`)
- Modify: `crates/epigraph-mcp/src/tools/memory.rs` (imports @ line 15; `recall()` @ line 135)
- Test: `crates/epigraph-mcp/tests/recall_hybrid.rs` (new)

- [ ] **Step 1: Write the failing seam test**

Create `crates/epigraph-mcp/tests/recall_hybrid.rs`:

```rust
//! `recall` embedder-down behavior: with a mock embedder (no API key) the
//! hybrid embed leg fails, so `recall` must serve scope-honoring lexical-only
//! results (the regression that previously returned [] for scoped queries).

use epigraph_mcp::tools::memory::recall;
use epigraph_mcp::types::RecallParams;
use sqlx::PgPool;
use uuid::Uuid;

fn build_test_server(pool: PgPool) -> epigraph_mcp::EpiGraphMcpFull {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::EpiGraphMcpFull;
    let signer = AgentSigner::from_bytes(&[0u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None); // mock → embed leg errors
    EpiGraphMcpFull::new(pool, signer, embedder, /*read_only=*/ false)
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(agent_id)
        .bind("aa".repeat(32))
        .execute(pool)
        .await
        .expect("seed agent");
    agent_id
}

fn parse_results(result: rmcp::model::CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content");
    serde_json::from_str(&text).expect("parse Vec<RecallResult> JSON")
}

#[sqlx::test(migrations = "../../migrations")]
async fn recall_falls_back_to_scope_honoring_lexical_when_embedder_down(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let h = |tag: u8| {
        let mut x = vec![0u8; 32];
        x[0] = tag;
        x
    };
    // In-scope lexical match.
    let keep = Uuid::new_v4();
    sqlx::query("INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, labels) \
                 VALUES ($1, 'zubuzonium synthesis route', $2, $3, 0.8, true, ARRAY['keep'])")
        .bind(keep).bind(h(1)).bind(agent).execute(&pool).await.expect("keep");
    // Out-of-scope lexical match (different label).
    let drop = Uuid::new_v4();
    sqlx::query("INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, labels) \
                 VALUES ($1, 'zubuzonium elsewhere', $2, $3, 0.8, true, ARRAY['other'])")
        .bind(drop).bind(h(2)).bind(agent).execute(&pool).await.expect("drop");

    let server = build_test_server(pool);
    let params = RecallParams {
        query: "zubuzonium".to_string(),
        min_truth: None,
        limit: None,
        tags: vec!["keep".to_string()],
        agent_id: None,
    };
    let out = recall(&server, params).await.expect("recall ok");
    let arr = parse_results(out);
    let arr = arr.as_array().expect("array");

    let ids: Vec<&str> = arr.iter().map(|r| r["claim_id"].as_str().unwrap()).collect();
    assert!(ids.contains(&keep.to_string().as_str()), "in-scope lexical hit returned");
    assert!(!ids.contains(&drop.to_string().as_str()), "out-of-scope hit excluded (the old bug)");

    let keep_row = arr.iter().find(|r| r["claim_id"] == keep.to_string()).unwrap();
    assert_eq!(keep_row["matched_via"], serde_json::json!(["lexical"]));
    assert_eq!(keep_row["similarity"], serde_json::json!(0.0)); // lexical-only
}
```

- [ ] **Step 2: Run to verify it fails**

Run:
```bash
CARGO_TARGET_DIR=/home/jeremy/.cargo-target-hybrid \
DATABASE_URL=postgres://epigraph:epigraph@localhost:5432/epigraph \
cargo test -p epigraph-mcp --test recall_hybrid
```
Expected: FAIL — `RecallResult` has no `matched_via` field / `recall` still calls `search_scoped`.

- [ ] **Step 3: Extend `RecallResult`**

In `crates/epigraph-mcp/src/types.rs`, replace the struct at line 728:

```rust
#[derive(Debug, Serialize)]
pub struct RecallResult {
    pub claim_id: String,
    pub content: String,
    pub truth_value: f64,
    /// Dense cosine similarity in `[0,1]`; `0.0` for a lexical-only hit.
    pub similarity: f64,
    /// Reciprocal Rank Fusion score (primary ordering).
    pub rrf_score: f64,
    /// Which legs matched: subset of `["dense","lexical"]`.
    pub matched_via: Vec<String>,
}
```

- [ ] **Step 4: Rewire `recall()`**

In `crates/epigraph-mcp/src/tools/memory.rs`, update the import on line 15 to add `HybridHit`:
```rust
use epigraph_db::{ClaimRepository, EvidenceRepository, HybridHit, ReasoningTraceRepository};
```
Add below the existing `use` block:
```rust
use crate::embed::HYBRID_RRF_K;
```
Replace the entire `recall` function (lines 135–179) with:

```rust
pub async fn recall(
    server: &EpiGraphMcpFull,
    params: RecallParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(10).clamp(1, 50);
    let min_truth = params.min_truth.unwrap_or(0.3);
    let agent_filter = parse_agent_filter(params.agent_id.as_deref()).map_err(invalid_params)?;
    let tags = params.tags;
    let tags_opt: Option<&[String]> = if tags.is_empty() { None } else { Some(&tags) };

    // Hybrid retrieval: dense (claims.embedding) + lexical (content_tsv), RRF-fused.
    // On embedder failure, degrade to lexical-only — which, unlike the old ILIKE
    // fallback, still honors tag/agent scope because it filters in SQL.
    let hits: Vec<HybridHit> = match server
        .embedder
        .search_hybrid_scoped(&params.query, limit, tags_opt, agent_filter)
        .await
    {
        Ok(hits) => hits,
        Err(e) => {
            tracing::warn!(
                error = %e,
                query = %params.query,
                "recall: hybrid embed leg failed; serving scope-honoring lexical-only"
            );
            ClaimRepository::search_lexical_scoped(
                &server.pool,
                &params.query,
                HYBRID_RRF_K,
                limit,
                tags_opt,
                agent_filter,
            )
            .await
            .map_err(internal_error)?
        }
    };

    let mut results = Vec::new();
    for hit in hits {
        if let Ok(Some(claim)) =
            ClaimRepository::get_by_id(&server.pool, ClaimId::from_uuid(hit.claim_id)).await
        {
            let tv = claim.truth_value.value();
            if tv >= min_truth {
                let mut matched_via = Vec::new();
                if hit.dense_similarity.is_some() {
                    matched_via.push("dense".to_string());
                }
                if hit.in_lexical {
                    matched_via.push("lexical".to_string());
                }
                results.push(RecallResult {
                    claim_id: hit.claim_id.to_string(),
                    content: claim.content,
                    truth_value: tv,
                    similarity: hit.dense_similarity.unwrap_or(0.0),
                    rrf_score: hit.rrf_score,
                    matched_via,
                });
            }
        }
    }

    success_json(&results)
}
```

NOTE: this removes the old `embedder.search_scoped` call and the `ClaimRepository::list` ILIKE fallback. If `EvidenceRepository` becomes unused in this file after the change, drop it from the import to satisfy `-D warnings`; if other functions still use it, leave it.

- [ ] **Step 5: Run the seam test + the embedder-up doc-path check**

Run:
```bash
CARGO_TARGET_DIR=/home/jeremy/.cargo-target-hybrid \
DATABASE_URL=postgres://epigraph:epigraph@localhost:5432/epigraph \
cargo test -p epigraph-mcp --test recall_hybrid -- --nocapture
```
Expected: PASS (1 test). (The embedder-up hybrid path is covered at the DB layer in Task 2; it needs a real OpenAI key and is not exercised here.)

- [ ] **Step 6: Commit**

```bash
git add crates/epigraph-mcp/src/types.rs crates/epigraph-mcp/src/tools/memory.rs \
        crates/epigraph-mcp/tests/recall_hybrid.rs
git commit  # feat(mcp): make recall a semantic+lexical hybrid with RRF + scoped lexical fallback
```

---

### Task 6: Full CI gate + sqlx offline check + workspace build

**Files:** none (verification only)

- [ ] **Step 1: sqlx offline check (no `.sqlx` churn expected — all runtime `query_as`)**

Run:
```bash
CARGO_TARGET_DIR=/home/jeremy/.cargo-target-hybrid \
SQLX_OFFLINE=true cargo check --workspace
```
Expected: compiles. (No `sqlx::query!`/`query_as!` macros were added, so `cargo sqlx prepare` is not required and `.sqlx/` should be unchanged. If `git status` shows `.sqlx/` changes, run `DATABASE_URL=postgres://epigraph:epigraph@localhost:5432/epigraph cargo sqlx prepare --workspace -- --tests` and add them.)

- [ ] **Step 2: Format + clippy (the CI gate)**

Run:
```bash
CARGO_TARGET_DIR=/home/jeremy/.cargo-target-hybrid cargo fmt --all -- --check
CARGO_TARGET_DIR=/home/jeremy/.cargo-target-hybrid cargo clippy --workspace --locked -- -D warnings
```
Expected: both clean. Fix any findings, then re-run.

- [ ] **Step 3: Full test sweep for the two touched crates**

Run:
```bash
CARGO_TARGET_DIR=/home/jeremy/.cargo-target-hybrid \
DATABASE_URL=postgres://epigraph:epigraph@localhost:5432/epigraph \
cargo test -p epigraph-db -p epigraph-mcp
```
Expected: PASS (incl. the new `claim_search_hybrid` + `recall_hybrid`, and existing recall tests unbroken).

- [ ] **Step 4: Final commit if anything changed (fmt/clippy fixes)**

```bash
git add -A && git commit  # chore(recall): satisfy fmt/clippy + sqlx offline for hybrid recall
```

---

## Deploy notes (out of plan scope, for the PR description)

- Migration `050` is idempotent; the boot-time migrator applies it. Per `feedback_spec_branch_migrations`, do **not** hand-apply `050` to prod before the binary that includes it is deployed (`_sqlx_migrations.max(version)` must not exceed the deploy tree).
- Rebuild/redeploy `epigraph-mcp` (→ `/usr/local/bin/epigraph-mcp`) per the standard recipe and restart `epigraph-mcp-http`, `epigraph-mcp-auth`, and `epiclaw`.

## Out of scope (future plans)
- Wiring `search_hybrid_scoped` into `recall_with_context`.
- True BM25 via ParadeDB `pg_search` (swap the `lex` CTE; §6 of the spec).
- Tuning knobs (`lexical_weight`, per-leg toggles, pool override).
```
