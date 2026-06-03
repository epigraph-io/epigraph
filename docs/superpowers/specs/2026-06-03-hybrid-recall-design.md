# Hybrid (semantic + BM25) `recall` — Design

**Date:** 2026-06-03
**Status:** Approved (design) — pending spec review
**Scope:** The plain `recall` MCP tool only. `recall_with_context`, true-BM25, and tuning knobs are explicitly out of scope (see §9).
**Branch:** `feat/hybrid-recall` (off `origin/main` @ `2a31f8d`)

## 1. Motivation

`recall`'s relevance is dense-only. On `origin/main` its semantic leg already
searches `claims.embedding` (level-agnostic) via
`ClaimRepository::search_by_embedding_scoped` — the dead-`evidence.embedding`
routing was fixed in `391e175`. What's missing is a **lexical leg**.

Dense embeddings and lexical (BM25-family) retrieval fail in disjoint ways:
dense captures paraphrase/semantics but fumbles exact-match / rare tokens /
identifiers / acronyms; lexical nails those but is blind to paraphrase. An
epistemic graph is unusually exact-match-heavy (claim/agent IDs, DOIs, framework
names like `Dempster-Shafer`, `BLAKE3`, gene/protein names), so the lexical leg
is high-value here. The state-of-practice answer is **hybrid retrieval with rank
fusion**; this spec adds that to `recall`.

## 2. Locked decisions

| Decision | Choice | Rationale |
|---|---|---|
| Target | The plain `recall` MCP tool (`tools/memory.rs`) | User scope; smallest surface. |
| Candidate scope | All current claims (level-agnostic) | Already what the dense leg does; covers memorized/workflow claims (no `level`). |
| Lexical engine | Native Postgres FTS over `content_tsv`, behind a swappable seam | `content_tsv` is a `GENERATED ALWAYS AS to_tsvector('english', content) STORED` column, GIN-indexed (`idx_claims_content_tsv`), **fully populated (432,054/432,054)** and proven (`ts_rank_cd` returns relevant hits live). |

### Schema / migration — reconcile `content_tsv` drift

`content_tsv` + `idx_claims_content_tsv` **exist on prod but are absent from
`migrations/`** (latest tracked migration is `049`) and unreferenced by any
code — undocumented manual drift. Because `#[sqlx::test]` builds fresh DBs *from
`migrations/`*, and fresh deploys must be reproducible, this work adds an
**idempotent** migration `050_claims_content_tsv.sql`:

```sql
ALTER TABLE claims ADD COLUMN IF NOT EXISTS content_tsv tsvector
  GENERATED ALWAYS AS (to_tsvector('english', content)) STORED;
CREATE INDEX IF NOT EXISTS idx_claims_content_tsv ON claims USING gin (content_tsv);
```

`IF NOT EXISTS` makes it a no-op on prod (column/index already there) while
creating both on fresh DBs. Deploy ordering caveat (per
`feedback_spec_branch_migrations`): do **not** apply `050` to prod before the
binary that includes it ships — the boot-time migrator handles it.
| Fusion | **Reciprocal Rank Fusion (RRF) in SQL** (Approach A) | Rank-based → no cross-scale normalization; single round-trip; both legs index-backed; keeps SQL in `repos/` per repo convention. |
| Response shape | Additive: keep `similarity` = dense cosine; add `rrf_score` + `matched_via` | Non-breaking for existing clients. |

**Native FTS is "BM25-ish," not true BM25.** `ts_rank_cd` is TF-based with
weaker IDF / length normalization than Okapi BM25. Accepted for v1; the fusion
seam (§6) makes a later swap to ParadeDB `pg_search` a one-method change.

## 3. Architecture

Three layers, each independently testable:

```
recall() ──► McpEmbedder::search_hybrid_scoped(query, …) ──► ClaimRepository::search_hybrid_scoped(pgvec, query_text, …)
 (tool)          (embed query → call repo)                        (two CTEs + RRF in one SQL round-trip)
```

### 3.1 `ClaimRepository::search_hybrid_scoped` (new, `repos/claim.rs`)

Signature (mirrors `search_by_embedding_scoped`, adds query text + RRF params):

```rust
pub async fn search_hybrid_scoped(
    pool: &PgPool,
    query_embedding_pgvector: &str,
    query_text: &str,
    candidate_pool: i64,   // per-leg LIMIT before fusion (const: 50)
    k_rrf: i64,            // RRF constant (const: 60)
    limit: i64,           // final fused LIMIT
    tags: Option<&[String]>,
    agent_id: Option<Uuid>,
) -> Result<Vec<HybridHit>, DbError>
```

Returns:

```rust
pub struct HybridHit {
    pub claim_id: Uuid,
    pub rrf_score: f64,
    pub dense_similarity: Option<f64>, // Some(cos) if in dense leg; None if lexical-only
    pub in_lexical: bool,              // true if the row appeared in the lexical leg
}
```

`dense_similarity.is_some()` signals dense-leg membership; `in_lexical` signals
lexical-leg membership. Both are needed to derive `matched_via` (§7).

SQL (runtime `query_as`, same precedent as `search_by_embedding_scoped`):

```sql
WITH dense AS (
  SELECT id,
         row_number() OVER (ORDER BY embedding <=> $1::vector) AS rank,
         1 - (embedding <=> $1::vector) AS cos
  FROM claims
  WHERE embedding IS NOT NULL AND is_current
    AND ($6::text[] IS NULL OR labels @> $6::text[])
    AND ($7::uuid  IS NULL OR agent_id = $7::uuid)
  ORDER BY embedding <=> $1::vector
  LIMIT $3                                     -- candidate_pool
),
lex AS (
  SELECT id,
         row_number() OVER (ORDER BY ts_rank_cd(content_tsv, q) DESC) AS rank
  FROM claims, websearch_to_tsquery('english', $2) q
  WHERE content_tsv @@ q AND is_current
    AND ($6::text[] IS NULL OR labels @> $6::text[])
    AND ($7::uuid  IS NULL OR agent_id = $7::uuid)
  ORDER BY ts_rank_cd(content_tsv, q) DESC
  LIMIT $3
)
SELECT COALESCE(d.id, l.id) AS claim_id,
       COALESCE(1.0/($4 + d.rank), 0) + COALESCE(1.0/($4 + l.rank), 0) AS rrf_score,
       d.cos AS dense_similarity,
       (l.rank IS NOT NULL) AS in_lexical
FROM dense d FULL OUTER JOIN lex l ON d.id = l.id
ORDER BY rrf_score DESC
LIMIT $5;
```

Params: `$1` pgvec, `$2` query_text, `$3` candidate_pool, `$4` k_rrf, `$5` limit,
`$6` tags, `$7` agent_id.

Index usage: dense `ORDER BY embedding <=> …` → HNSW `idx_claims_embedding_hnsw`;
`content_tsv @@ q` → GIN `idx_claims_content_tsv`. `ts_rank_cd` recomputes on the
(small) lexically-matched set — expected and cheap. Same `is_current` /
`labels @>` / `agent_id` predicates on both legs so the two candidate universes
are identical except for the relevance signal.

### 3.2 `McpEmbedder::search_hybrid_scoped` (new, `embed.rs`)

Mirrors `search_scoped`: embed `query` at 1536d (`generate`), format pgvector,
call the repo method, return `Vec<HybridHit>` (or `String` error). If the
embedder is unavailable (no API key), see §5 — `recall()` degrades to a
lexical-only call rather than failing.

### 3.3 `recall()` rewire (`tools/memory.rs`)

Replace the `embedder.search_scoped(...)` call with the hybrid path. Per-hit
hydration (`get_by_id` → `min_truth` filter → `RecallResult`) is unchanged
except for the new fields. `min_truth`, `limit`, `tags`, `agent_id` params are
untouched.

## 4. Data flow

1. `recall(query, limit, min_truth, tags, agent_id)`.
2. Embed `query` (1536d). On success → `search_hybrid_scoped` (both legs).
   On embedder failure → lexical-only path (§5).
3. SQL returns fused `HybridHit`s ordered by `rrf_score`, capped at `limit`.
4. Hydrate each `claim_id` (`get_by_id`), drop `truth_value < min_truth`.
5. Emit `RecallResult { claim_id, content, truth_value, similarity, rrf_score, matched_via }`.

## 5. Failure modes (improvements over today)

| Condition | Today | After |
|---|---|---|
| Lexical leg empty (e.g. all-stopword query) | n/a | `websearch_to_tsquery` → no `@@` match → dense-only fusion. Graceful. |
| Embedder down, **unscoped** | ILIKE over `content` via `ClaimRepository::list`, `similarity=0.0` | **Proper lexical-only** (`ts_rank_cd`) — strictly better ranking. |
| Embedder down, **scoped** (tags/agent) | Returns **empty** (ILIKE fallback can't scope) | **Lexical-only honoring scope** (CTE filters in SQL). Fixes the dead end. |

The crude ILIKE `list` fallback is **retired** — the lexical leg subsumes it and
can scope. Implementation: a dedicated `ClaimRepository::search_lexical_scoped`
(the `lex` CTE alone, RRF degenerating to a single `ts_rank_cd` order). A
"sentinel zero-vector into `search_hybrid_scoped`" is explicitly **rejected** —
pgvector `<=>` against a zero vector is NaN, so the dense ordering is undefined.

## 6. Swappable seam for true BM25

The lexical leg is isolated to the `lex` CTE (one `ts_rank_cd`/`@@` block).
Swapping to ParadeDB `pg_search` later = replace that CTE's ranking with
`@@@`/`paradedb.score(id)` and add the extension + a BM25 index; the fusion
shell, the `HybridHit` contract, the embedder method, and `recall()` are
untouched. No other call site sees the change.

## 7. Response shape

`RecallResult` gains two additive fields:
- `rrf_score: f64` — the fused score (primary ordering).
- `matched_via: Vec<String>` — subset of `["dense","lexical"]`, derived from the
  `HybridHit` flags: `dense_similarity.is_some()` ⇒ `"dense"`; `in_lexical` ⇒
  `"lexical"` (both surfaced by the §3.1 SQL projection).
- `similarity: f64` stays = `dense_similarity.unwrap_or(0.0)` (back-compat; `0.0`
  now unambiguously means "lexical-only hit," documented in the field doc).

## 8. Testing

Integration tests against `epigraph_db_repo_test` (NOT the live DB) — seed
`agents` + claims with distinct `content_hash`, set `embedding` + rely on the
generated `content_tsv`:

1. **Dense-only**: query semantically near claim A, lexically disjoint → A ranks
   via dense leg; `matched_via=["dense"]`.
2. **Lexical-only**: exact rare token present in claim B, embedding far → B
   surfaces; `matched_via=["lexical"]`, `similarity=0.0`.
3. **Both legs / RRF order**: a claim in both legs outranks claims in only one,
   per `1/(k+rank)` sums (assert exact ordering for a small fixture).
4. **Scope**: `tags` filter drops out-of-scope claims on **both** legs;
   `is_current=false` excluded.
5. **Embedder-down lexical-only** (unit at the `recall()`/embedder seam): scoped
   query still returns scoped lexical hits (the regression that today returns []).

Tests reviewed under the council-of-critics rule (reject tautological /
mock-shaped / happy-path-only). CI gate before commit:
`cargo fmt --check`, `cargo clippy --workspace --locked -- -D warnings`, build,
test. Runtime `query_as` ⇒ expect no `.sqlx` churn; verify with
`cargo sqlx prepare --workspace -- --tests` and commit `.sqlx/` only if it
changes.

## 9. Out of scope (later steps)

- Wiring hybrid retrieval into `recall_with_context` (its flat **and** diverse
  paths). The `search_hybrid_scoped` method is designed to be reusable there.
- True BM25 via `pg_search` (the §6 seam).
- Tuning knobs (`lexical_weight`, per-leg toggles, `candidate_pool` override).
  Constants for v1; promote to params only when a need appears (YAGNI).
- Migrating diversity (theme-MMR) onto a hybrid candidate pool.

## 10. Risks / open items

- **RRF constants.** `k=60`, `candidate_pool=50` are canonical defaults; not
  tuned for this corpus. Acceptable for v1; revisit with eval data.
- **HNSW + filter interaction.** Heavy `tags`/`agent` scoping can shrink HNSW
  recall (post-filtering). Pre-existing in `search_by_embedding_scoped`; not
  introduced here.
- **`english` regconfig** is hardcoded (matches the `content_tsv` generation
  expression). Multilingual content would need a config change at the column
  level first — out of scope.
```
