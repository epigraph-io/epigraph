# Cross-source matcher — renormalize-by-fired-features Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `scorer::score_pair` compute the combined score as a weighted average over only the features that produced a real signal, so genuine cross-source matches (where structural features are ~0 by construction) reach the LLM verifier band instead of being diluted below it.

**Architecture:** Each of the nine features becomes applicability-aware — its SQL surfaces `NULL` (rather than `COALESCE`-ing to `0.0`) when there is no data to compare, read into Rust as `Option`. A new `renormalized_score` helper averages weight·value over only the `Some` features, dividing by the sum of *their* weights. `embed_cosine` stays always-applicable (its `0.0`-on-NULL is deliberate suppression). Bands in `calibration.toml` move to a reachable provisional `mid` and an unreachable `high` so 100% of candidates route to the verifier.

**Tech Stack:** Rust, `sqlx` (dynamic `sqlx::query`, no compile-time macros here → no `.sqlx/` prepare needed), Postgres/pgvector, `#[sqlx::test]` integration tests against a fresh migrated DB.

**Spec:** `docs/superpowers/specs/2026-06-03-cross-source-bootstrap-matching-design.md`

**Backlog:** resolves `9b50c331`; provisional bands for `27bc9754` (final sweep → #239).

---

## File Structure

- **Modify:** `crates/epigraph-engine/src/matching/scorer.rs` — the only behavioral change. Add `renormalized_score`; make the five SQL queries surface `NULL`; bind features as `Option`; renormalize; preserve reported `MatchFeatures` values via `unwrap_or`.
- **Modify:** `crates/epigraph-engine/tests/scorer_features.rs` — add one embedding helper and five new tests. Existing tests are unaffected (they assert on reported feature values, which are preserved).
- **Modify:** `calibration.toml` — `[matcher.bands]` `mid 0.60→0.80`, `high 0.85→1.01`.

No other files. The blocker, verifier, policy, and `pipeline.rs` control flow are untouched.

---

## Pre-flight

- [ ] **Step 0: Confirm worktree + test DB**

You should already be in the worktree `/home/jeremy/epigraph-wt-matcher-renorm` on branch `feat/matcher-renormalize-fired-features`. Use a **small** throwaway DB for tests (never the live `epigraph` DB — it fans out 30+ min and pollutes prod):

```bash
cd /home/jeremy/epigraph-wt-matcher-renorm
git rev-parse --abbrev-ref HEAD   # expect: feat/matcher-renormalize-fired-features
createdb epigraph_matcher_renorm_test 2>/dev/null || true
export DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_matcher_renorm_test
```

`#[sqlx::test]` creates an isolated per-test database from `DATABASE_URL`'s server, so the named DB just needs to exist and be reachable.

---

## Task 1: Renormalize the combiner over fired features (the core change)

**Files:**
- Modify: `crates/epigraph-engine/src/matching/scorer.rs`
- Test: `crates/epigraph-engine/tests/scorer_features.rs`

- [ ] **Step 1: Write the headline failing test**

Add to the end of `crates/epigraph-engine/tests/scorer_features.rs`:

```rust
/// Cross-source bootstrap case: two claims with identical embeddings and NO
/// structural data, no mass function, unthemed. Only embed_cosine fires, so
/// the renormalized score must ≈ embed_cosine (≈1.0) — NOT the old diluted
/// 0.425 (= 0.35·1.0 + 0.10·0.5 + 0.05·0.5 over denom 1.0).
#[sqlx::test(migrations = "../../migrations")]
async fn renormalized_score_is_cosine_when_only_embedding_fires(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim_with_embedding(&pool, agent).await;
    let b = insert_claim_with_embedding(&pool, agent).await;

    let f = score_pair(&pool, a, b, &Weights::default())
        .await
        .expect("score_pair");

    assert!(
        f.embed_cosine > 0.99,
        "precondition: embed_cosine ≈ 1.0, got {}",
        f.embed_cosine
    );
    assert!(
        f.score > 0.99,
        "only embed_cosine fired → score must ≈ embed_cosine, got {}",
        f.score
    );
}
```

- [ ] **Step 2: Run it to confirm it fails**

```bash
cargo test -p epigraph-engine --test scorer_features renormalized_score_is_cosine_when_only_embedding_fires -- --nocapture
```

Expected: FAIL — `score must ≈ embed_cosine, got 0.425` (old combiner divides by all nine weights).

- [ ] **Step 3: Add the `renormalized_score` helper**

In `crates/epigraph-engine/src/matching/scorer.rs`, immediately above `pub async fn score_pair`, add:

```rust
/// Weighted average over only the features that produced a real signal.
///
/// Each entry is `(weight, Some(value))` when the feature fired, or
/// `(weight, None)` when it had no data to compare — `None` features are
/// excluded from BOTH the numerator and the denominator (renormalization).
/// This is the fix for cross-source score dilution (backlog 9b50c331): the
/// old combiner divided by the sum of all nine weights even though the
/// structural features are ~0 by construction for cross-source pairs.
///
/// `embed_cosine` is always passed as `Some` (its `0.0`-on-NULL is deliberate
/// suppression, not missing data), so `denom >= w.embed_cosine > 0` always
/// holds; the `denom == 0` branch is defensive only.
fn renormalized_score(weighted: &[(f32, Option<f32>)]) -> f32 {
    let mut num = 0.0_f32;
    let mut den = 0.0_f32;
    for (w, v) in weighted {
        if let Some(val) = v {
            num += w * val;
            den += w;
        }
    }
    if den == 0.0 {
        0.0
    } else {
        (num / den).clamp(0.0, 1.0)
    }
}
```

- [ ] **Step 4: Make Query 1 `method_match` applicability-aware**

In `score_pair`, replace the `method_match` projection in Query 1. Change:

```rust
            COALESCE(
                (SELECT properties->>'method_id' FROM a) IS NOT NULL
                AND (SELECT properties->>'method_id' FROM a)
                    = (SELECT properties->>'method_id' FROM b),
                false
            ) AS method_match,
```

to:

```rust
            CASE
                WHEN (SELECT properties->>'method_id' FROM a) IS NULL
                  OR (SELECT properties->>'method_id' FROM b) IS NULL
                    THEN NULL
                ELSE (SELECT properties->>'method_id' FROM a)
                     = (SELECT properties->>'method_id' FROM b)
            END AS method_match,
```

Then change the binding below the query from:

```rust
    let method_match: bool = row1.try_get("method_match")?;
```

to:

```rust
    let method_match_opt: Option<bool> = row1.try_get("method_match")?;
```

(`embed_cosine` and `temporal_dist_days` bindings are unchanged — `embed_cosine` keeps its `COALESCE(..., 0.0)`.)

- [ ] **Step 5: Make Query 2 Jaccards applicability-aware**

For each of the four Jaccard projections in Query 2 (`triple_overlap`, `entity_jaccard`, `nbhd_overlap`, `citation_overlap`), **remove the outer `COALESCE(..., 0.0)`** so an empty union (already produced by `NULLIF(union_count, 0)`) surfaces as `NULL`. For example, `triple_overlap` changes from:

```rust
            COALESCE(
                (SELECT COUNT(*)::real FROM (SELECT * FROM ta_sp INTERSECT SELECT * FROM tb_sp) i)
                / NULLIF(
                    (SELECT COUNT(*)::real FROM (SELECT * FROM ta_sp UNION SELECT * FROM tb_sp) u),
                    0
                ),
                0.0
            )::real AS triple_overlap,
```

to:

```rust
            (
                (SELECT COUNT(*)::real FROM (SELECT * FROM ta_sp INTERSECT SELECT * FROM tb_sp) i)
                / NULLIF(
                    (SELECT COUNT(*)::real FROM (SELECT * FROM ta_sp UNION SELECT * FROM tb_sp) u),
                    0
                )
            )::real AS triple_overlap,
```

Apply the identical transformation (delete `COALESCE(` and the trailing `, 0.0)`) to `entity_jaccard` (uses `ta_ent`/`tb_ent`), `nbhd_overlap` (uses `cca`/`ccb`), and `citation_overlap` (uses `cita`/`citb`). A non-empty union with empty intersection still yields `0.0` (an applicable negative); only an empty union yields `NULL`.

Then change the four bindings from `let x: f32 = row2.try_get("x")?;` to `Option<f32>`:

```rust
    let triple_overlap_opt: Option<f32> = row2.try_get("triple_overlap")?;
    let entity_jaccard_opt: Option<f32> = row2.try_get("entity_jaccard")?;
    let nbhd_overlap_opt: Option<f32> = row2.try_get("nbhd_overlap")?;
    let citation_overlap_opt: Option<f32> = row2.try_get("citation_overlap")?;
```

- [ ] **Step 6: Make Query 3 `graph_overlap` applicability-aware**

In Query 3, remove the `COALESCE(..., 0.0)` so an empty common-neighbor set surfaces as `NULL`. Change:

```rust
        SELECT
            COALESCE(
                TANH(SUM(1.0 / GREATEST(LN(d::float8), 0.5))),
                0.0
            )::real AS graph_overlap
        FROM deg
```

to:

```rust
        SELECT
            TANH(SUM(1.0 / GREATEST(LN(d::float8), 0.5)))::real AS graph_overlap
        FROM deg
```

Then change the binding from `let graph_overlap: f32 = ...` to:

```rust
    let graph_overlap_opt: Option<f32> = row3.try_get("graph_overlap")?;
```

(With ≥1 common neighbor the Adamic-Adar sum is ≥ `1/0.5 = 2.0` so `TANH(...) > 0`; `NULL` therefore unambiguously means "no shared neighbor".)

- [ ] **Step 7: Make Query 4 `belief_alignment` applicability-aware**

Replace the existing `belief_alignment` match (which produced `0.5` for the missing arm) with an `Option`:

```rust
    let betp_a: Option<f64> = row4.try_get("betp_a")?;
    let betp_b: Option<f64> = row4.try_get("betp_b")?;
    let belief_alignment_opt: Option<f32> = match (betp_a, betp_b) {
        (Some(pa), Some(pb)) => Some((1.0 - 2.0 * (pa - pb).abs()).clamp(0.0, 1.0) as f32),
        // No mass function on at least one side → not applicable (excluded
        // from the renormalized denominator, rather than a neutral 0.5 that
        // would dilute the score).
        _ => None,
    };
```

- [ ] **Step 8: Make Query 5 `theme_proximity` applicability-aware**

The SQL already returns `NULL` when either claim is unthemed. Keep the `Option` instead of collapsing it with `unwrap_or(0.5)`. Replace:

```rust
    let tp_opt: Option<f32> = row5.try_get("theme_proximity")?;
    let theme_proximity: f32 = tp_opt.unwrap_or(0.5).clamp(0.0, 1.0);
```

with:

```rust
    let tp_opt: Option<f32> = row5.try_get("theme_proximity")?;
    let theme_proximity_opt: Option<f32> = tp_opt.map(|v| v.clamp(0.0, 1.0));
```

- [ ] **Step 9: Replace the combined-score block + `MatchFeatures` construction**

Replace the entire tail of `score_pair` — the `let raw = ...`, `let denom = ...`, `let score = ...`, and the final `Ok(MatchFeatures { ... })` — with:

```rust
    // ------------------------------------------------------------------
    // Combined score: renormalized weighted average over fired features.
    // method_match contributes 1.0/0.0 when both claims have a method_id,
    // and is excluded (None) when either lacks one.
    // ------------------------------------------------------------------
    let method_match_val: Option<f32> =
        method_match_opt.map(|m| if m { 1.0_f32 } else { 0.0_f32 });

    let score = renormalized_score(&[
        (w.embed_cosine, Some(embed_cosine)),
        (w.triple_overlap, triple_overlap_opt),
        (w.entity_jaccard, entity_jaccard_opt),
        (w.method_match, method_match_val),
        (w.nbhd_overlap, nbhd_overlap_opt),
        (w.citation_overlap, citation_overlap_opt),
        (w.graph_overlap, graph_overlap_opt),
        (w.belief_alignment, belief_alignment_opt),
        (w.theme_proximity, theme_proximity_opt),
    ]);

    Ok(MatchFeatures {
        embed_cosine,
        // Reported feature values keep their pre-change sentinels so the
        // telemetry vector (match_candidates.features) is unchanged; only the
        // `score` math changed.
        triple_overlap: triple_overlap_opt.unwrap_or(0.0),
        entity_jaccard: entity_jaccard_opt.unwrap_or(0.0),
        method_match: method_match_opt.unwrap_or(false),
        nbhd_overlap: nbhd_overlap_opt.unwrap_or(0.0),
        citation_overlap: citation_overlap_opt.unwrap_or(0.0),
        graph_overlap: graph_overlap_opt.unwrap_or(0.0),
        belief_alignment: belief_alignment_opt.unwrap_or(0.5),
        theme_proximity: theme_proximity_opt.unwrap_or(0.5),
        temporal_dist_days,
        score,
    })
```

- [ ] **Step 10: Run the headline test — expect PASS**

```bash
cargo test -p epigraph-engine --test scorer_features renormalized_score_is_cosine_when_only_embedding_fires -- --nocapture
```

Expected: PASS (`f.score ≈ 1.0`).

- [ ] **Step 11: Run the full existing scorer suite — expect no regression**

```bash
cargo test -p epigraph-engine --test scorer_features
```

Expected: all existing tests PASS. They assert on reported feature values, which are preserved (e.g. `graph_overlap_zero_when_neighborhoods_disjoint` still sees `0.0` via `unwrap_or`).

- [ ] **Step 12: Commit**

```bash
git add crates/epigraph-engine/src/matching/scorer.rs crates/epigraph-engine/tests/scorer_features.rs
git commit -m "$(cat <<'EOF'
fix(matcher): renormalize pair score over fired features only

**Evidence:**
- Backlog 9b50c331: score = Σwᵢ·vᵢ / Σwᵢ divides by all nine weights, but
  cross-source structural features are ~0 by construction, capping a cos=1.0
  pair at ~0.425 < mid=0.60 — the verifier queue has 0 pending rows over 12,006
  historical candidates.

**Reasoning:**
- Renormalize over only features that produced a real signal: each feature's
  SQL surfaces NULL (no data) instead of COALESCE-ing to 0.0, read as Option;
  the combiner sums weight·value and divides by the weights of the fired
  features only. Jaccards key applicability on non-empty union (a zero-overlap
  with data stays a genuine negative); graph_overlap on value>0 (its 0.0 is the
  no-shared-neighbor sentinel); belief/theme on the data-present arm.
  embed_cosine stays always-applicable (0.0-on-NULL is deliberate suppression).
- Reported MatchFeatures values keep their old sentinels so telemetry is
  unchanged; only `score` changes.

**Verification:**
- New test: identical-embedding, no-structure pair scores ≈1.0 (was 0.425).
- Full scorer_features suite passes unchanged (reported values preserved).
EOF
)"
```

---

## Task 2: Lock in "zero-overlap-with-data is a negative" (Jaccard stays in denom)

**Files:**
- Test: `crates/epigraph-engine/tests/scorer_features.rs`

- [ ] **Step 1: Write the test**

```rust
/// A fired structural with empty intersection but non-empty UNION is a genuine
/// negative: it stays in the denominator and pulls the score below pure cosine.
/// (Contrast: a structural with no data at all is dropped — Task 1.)
#[sqlx::test(migrations = "../../migrations")]
async fn fired_zero_jaccard_pulls_score_below_cosine(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    // Both claims carry identical embeddings → embed_cosine ≈ 1.0.
    let a = insert_claim_with_embedding(&pool, agent).await;
    let b = insert_claim_with_embedding(&pool, agent).await;

    // Each claim has its OWN triple (disjoint subjects) → triple/entity unions
    // are non-empty, intersections empty → those features fire at 0.0.
    let subj_a = insert_entity(&pool).await;
    let subj_b = insert_entity(&pool).await;
    insert_triple(&pool, a, subj_a, "p").await;
    insert_triple(&pool, b, subj_b, "p").await;

    let f = score_pair(&pool, a, b, &Weights::default())
        .await
        .expect("score_pair");

    assert!(
        f.embed_cosine > 0.99,
        "precondition: cosine ≈ 1.0, got {}",
        f.embed_cosine
    );
    // With embed=1.0, triple_overlap=0, entity_jaccard=0 in the denominator:
    // score = 0.35·1.0 / (0.35 + 0.15 + 0.10) = 0.35/0.60 ≈ 0.583.
    assert!(
        f.score < 0.70 && f.score > 0.45,
        "fired zero-Jaccards must pull score to ~0.58, got {}",
        f.score
    );
}
```

- [ ] **Step 2: Run it — expect PASS**

```bash
cargo test -p epigraph-engine --test scorer_features fired_zero_jaccard_pulls_score_below_cosine -- --nocapture
```

Expected: PASS (`f.score ≈ 0.58`). This is a regression lock on the union-non-empty rule.

- [ ] **Step 3: Commit**

```bash
git add crates/epigraph-engine/tests/scorer_features.rs
git commit -m "$(cat <<'EOF'
test(matcher): lock zero-overlap-with-data as a scored negative

**Evidence:**
- Renormalization must distinguish "no data" (drop) from "data, zero overlap"
  (keep as negative). The union-non-empty applicability rule encodes this.

**Reasoning:**
- Two claims with disjoint triples have non-empty union, empty intersection →
  triple_overlap/entity_jaccard fire at 0.0 and stay in the denominator,
  pulling a cos≈1.0 pair to ~0.58. Guards the future intra-source path.

**Verification:**
- Test asserts score ∈ (0.45, 0.70) for the disjoint-triples + identical-
  embedding pair.
EOF
)"
```

---

## Task 3: Lock in "no shared neighbor drops graph_overlap" (not kept at 0)

**Files:**
- Test: `crates/epigraph-engine/tests/scorer_features.rs`

This is the advisor-flagged case: most candidate claims participate in the graph but share no neighbor, so `graph_overlap` must DROP (not sit at `0.0` in the denominator and dilute).

- [ ] **Step 1: Write the test**

```rust
/// graph_overlap with no shared neighbor is NOT applicable: it must be dropped
/// from the denominator, not held at 0.0 (which would dilute). Two claims with
/// identical embeddings and disjoint graph neighbors must still score ≈ cosine.
#[sqlx::test(migrations = "../../migrations")]
async fn no_shared_neighbor_drops_graph_overlap_from_denominator(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim_with_embedding(&pool, agent).await;
    let b = insert_claim_with_embedding(&pool, agent).await;
    // Each has a graph edge, but to DIFFERENT neighbors → no common neighbor.
    let only_a = insert_claim(&pool, agent).await;
    let only_b = insert_claim(&pool, agent).await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship)
         VALUES ($1, 'claim', $2, 'claim', 'supports'),
                ($3, 'claim', $4, 'claim', 'supports')",
    )
    .bind(a)
    .bind(only_a)
    .bind(b)
    .bind(only_b)
    .execute(&pool)
    .await
    .unwrap();

    let f = score_pair(&pool, a, b, &Weights::default())
        .await
        .expect("score_pair");

    assert_eq!(
        f.graph_overlap, 0.0,
        "reported graph_overlap stays 0.0 (telemetry), got {}",
        f.graph_overlap
    );
    // If graph_overlap were kept in the denom at 0.0:
    //   score = 0.35·1.0 / (0.35 + 0.10) ≈ 0.778. Dropping it → ≈ 1.0.
    assert!(
        f.score > 0.99,
        "graph_overlap must be dropped (not held at 0) → score ≈ cosine, got {}",
        f.score
    );
}
```

- [ ] **Step 2: Run it — expect PASS**

```bash
cargo test -p epigraph-engine --test scorer_features no_shared_neighbor_drops_graph_overlap_from_denominator -- --nocapture
```

Expected: PASS (`f.score ≈ 1.0`). On the old combiner this pair would have scored ≈ 0.43; the discriminating assertion (`> 0.99`) proves graph_overlap is dropped, not held at 0.

- [ ] **Step 3: Commit**

```bash
git add crates/epigraph-engine/tests/scorer_features.rs
git commit -m "$(cat <<'EOF'
test(matcher): lock no-shared-neighbor as graph_overlap drop, not zero-fill

**Evidence:**
- 89% of substantive candidate claims participate in the claim-claim graph but
  share no neighbor; holding graph_overlap at 0.0 in the denominator would
  re-dilute exactly the pairs the fix targets (advisor-flagged case).

**Reasoning:**
- value>0 applicability for graph_overlap (its 0.0 = no-shared-neighbor
  sentinel) drops it from the denominator, so a cos≈1.0 disjoint-neighbor pair
  scores ≈1.0, not ≈0.78.

**Verification:**
- Test asserts reported graph_overlap == 0.0 AND score > 0.99 for the
  disjoint-neighbor + identical-embedding pair.
EOF
)"
```

---

## Task 4: Lock in "opposite-stance belief pulls the score down" (fired negative)

**Files:**
- Test: `crates/epigraph-engine/tests/scorer_features.rs`

- [ ] **Step 1: Write the test**

```rust
/// belief_alignment fires only when both claims have a mass function. When it
/// fires with opposite stances it is a real negative and lowers the score
/// relative to an aligned pair with the same embeddings.
#[sqlx::test(migrations = "../../migrations")]
async fn opposite_stance_belief_lowers_score(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    // Identical embeddings on all three so cosine is constant (≈1.0) and the
    // only differentiator is belief_alignment.
    let a = insert_claim_with_embedding(&pool, agent).await;
    let b = insert_claim_with_embedding(&pool, agent).await;
    let c = insert_claim_with_embedding(&pool, agent).await;

    let frame_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses)
         VALUES ('binary', ARRAY['supported', 'unsupported'])
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("insert binary frame");

    // a, b strongly supported (BetP 0.9); c strongly unsupported (BetP 0.1).
    for &claim in &[a, b] {
        sqlx::query(
            "INSERT INTO mass_functions (claim_id, frame_id, masses)
             VALUES ($1, $2, '{\"0\": 0.8, \"0,1\": 0.2}')",
        )
        .bind(claim)
        .bind(frame_id)
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO mass_functions (claim_id, frame_id, masses)
         VALUES ($1, $2, '{\"1\": 0.8, \"0,1\": 0.2}')",
    )
    .bind(c)
    .bind(frame_id)
    .execute(&pool)
    .await
    .unwrap();

    let aligned = score_pair(&pool, a, b, &Weights::default())
        .await
        .expect("score a,b");
    let opposed = score_pair(&pool, a, c, &Weights::default())
        .await
        .expect("score a,c");

    // aligned: (0.35·1.0 + 0.10·~1.0)/(0.45) ≈ 1.0
    // opposed: (0.35·1.0 + 0.10·~0.0)/(0.45) ≈ 0.778
    assert!(
        opposed.score < aligned.score - 0.1,
        "opposite stance must lower score (aligned {} vs opposed {})",
        aligned.score,
        opposed.score
    );
    assert!(
        opposed.score < 0.85,
        "opposed-stance pair should drop well below cosine, got {}",
        opposed.score
    );
}
```

- [ ] **Step 2: Run it — expect PASS**

```bash
cargo test -p epigraph-engine --test scorer_features opposite_stance_belief_lowers_score -- --nocapture
```

Expected: PASS (`opposed ≈ 0.78 < aligned ≈ 1.0`).

- [ ] **Step 3: Commit**

```bash
git add crates/epigraph-engine/tests/scorer_features.rs
git commit -m "$(cat <<'EOF'
test(matcher): lock opposite-stance belief as a fired score negative

**Evidence:**
- belief_alignment is the precision feature that must keep penalizing
  same-topic-opposite-stance pairs even after renormalization.

**Reasoning:**
- With identical embeddings isolating belief, an opposed pair (BetP 0.9 vs 0.1)
  scores ≈0.78 vs an aligned pair ≈1.0, confirming the fired-negative path.

**Verification:**
- Test asserts opposed.score < aligned.score - 0.1 and opposed.score < 0.85.
EOF
)"
```

---

## Task 5: Lock in NULL-embedding suppression

**Files:**
- Test: `crates/epigraph-engine/tests/scorer_features.rs`

- [ ] **Step 1: Write the test**

```rust
/// A pair with no embeddings (embedding-invariant violation) must be suppressed:
/// embed_cosine is always applicable at 0.0, so with nothing else firing the
/// score is 0.0 — it can never reach a verifier band.
#[sqlx::test(migrations = "../../migrations")]
async fn null_embedding_pair_is_suppressed(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await; // no embedding
    let b = insert_claim(&pool, agent).await; // no embedding

    let f = score_pair(&pool, a, b, &Weights::default())
        .await
        .expect("score_pair");

    assert_eq!(
        f.embed_cosine, 0.0,
        "no embedding → embed_cosine 0.0, got {}",
        f.embed_cosine
    );
    assert!(
        f.score < 0.01,
        "null-embedding pair must be suppressed near 0, got {}",
        f.score
    );
}
```

- [ ] **Step 2: Run it — expect PASS**

```bash
cargo test -p epigraph-engine --test scorer_features null_embedding_pair_is_suppressed -- --nocapture
```

Expected: PASS (`f.score == 0.0`: `embed_cosine` 0.0 is the only applicable feature → `0.0/0.35`).

- [ ] **Step 3: Commit**

```bash
git add crates/epigraph-engine/tests/scorer_features.rs
git commit -m "$(cat <<'EOF'
test(matcher): lock NULL-embedding suppression under renormalization

**Evidence:**
- embed_cosine's 0.0-on-NULL is deliberate suppression for embedding-invariant
  violations; renormalization must not let another feature rescue such a pair.

**Reasoning:**
- embed_cosine is always applicable, so a no-embedding pair scores 0.0/w_embed
  = 0.0 and can never reach a verifier band.

**Verification:**
- Test asserts embed_cosine == 0.0 and score < 0.01 for a no-embedding pair.
EOF
)"
```

---

## Task 6: Reset the bands to the renormalized scale

**Files:**
- Modify: `calibration.toml`
- Test: `crates/epigraph-engine/tests/scorer_features.rs`

- [ ] **Step 1: Add the band-reachability test (with the binary-embedding helper)**

First add this helper near the other `insert_claim_*` helpers in `scorer_features.rs`:

```rust
/// Insert a claim whose 1536-dim embedding is 1.0 on `[start, start+len)` and
/// 0 elsewhere. Lets a test construct two claims with a chosen cosine: two
/// ranges overlapping in `k` of `len` positions give cosine ≈ k/len.
async fn insert_claim_with_binary_embedding(
    pool: &PgPool,
    agent: Uuid,
    start: usize,
    len: usize,
) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {}", id);
    let mut v = vec!["0"; 1536];
    for slot in v.iter_mut().skip(start).take(len) {
        *slot = "1";
    }
    let vec_literal = format!("[{}]", v.join(","));
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, embedding)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, $4::vector)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .bind(vec_literal)
    .execute(pool)
    .await
    .expect("insert claim with binary embedding");
    id
}
```

Then add the test:

```rust
/// Post-renormalization the cross-source score ≈ embed_cosine, so the provisional
/// mid=0.80 band (calibration.toml) cleanly separates genuine high-cosine
/// restatements (reach the verifier) from topical lower-cosine pairs (dropped).
#[sqlx::test(migrations = "../../migrations")]
async fn renormalized_score_separates_at_mid_band(pool: PgPool) {
    const MID: f32 = 0.80; // mirrors [matcher.bands].mid in calibration.toml
    let agent = insert_agent(&pool).await;
    let a = insert_claim_with_binary_embedding(&pool, agent, 0, 1000).await;
    // identical range → cosine ≈ 1.0
    let high = insert_claim_with_binary_embedding(&pool, agent, 0, 1000).await;
    // overlap 500 of 1000 → cosine ≈ 0.5
    let low = insert_claim_with_binary_embedding(&pool, agent, 500, 1000).await;

    let hi = score_pair(&pool, a, high, &Weights::default())
        .await
        .expect("score high");
    let lo = score_pair(&pool, a, low, &Weights::default())
        .await
        .expect("score low");

    assert!(
        hi.score >= MID,
        "high-cosine cross-source pair must reach mid={}, got {}",
        MID,
        hi.score
    );
    assert!(
        lo.score < MID,
        "topical low-cosine pair must stay below mid={}, got {}",
        MID,
        lo.score
    );
}
```

- [ ] **Step 2: Run it — expect PASS**

```bash
cargo test -p epigraph-engine --test scorer_features renormalized_score_separates_at_mid_band -- --nocapture
```

Expected: PASS (`hi.score ≈ 1.0 ≥ 0.80`; `lo.score ≈ 0.5 < 0.80`).

- [ ] **Step 3: Edit `calibration.toml` bands**

Change the `[matcher.bands]` block from:

```toml
[matcher.bands]
high = 0.85
mid  = 0.60
```

to:

```toml
[matcher.bands]
# Provisional bootstrap bands for the renormalized (≈cosine) cross-source score
# (backlog 27bc9754). mid is grounded in resolved item 4a715300 ("real
# corroboration clusters >0.85 cosine; 0.70–0.79 is topical noise"); high is set
# unreachable so EVERY candidate routes to the LLM verifier (the precision gate)
# rather than auto-promoting. Final calibrated values → #239 precision sweep.
high = 1.01
mid  = 0.80
```

- [ ] **Step 4: Verify the config still parses**

```bash
cargo test -p epigraph-engine
```

Expected: the whole `epigraph-engine` test suite PASSES, including any `MatcherConfig` loader test. (If a calibration-loader test asserts the old band values, update it to `mid = 0.80` / `high = 1.01`.)

- [ ] **Step 5: Commit**

```bash
git add calibration.toml crates/epigraph-engine/tests/scorer_features.rs
git commit -m "$(cat <<'EOF'
fix(matcher): reset bands to the renormalized score scale, route all to verifier

**Evidence:**
- Renormalization lifts cross-source score to ≈cosine, so the old mid=0.60/
  high=0.85 (calibrated for the diluted scale) now gate the wrong scale
  (backlog 27bc9754).

**Reasoning:**
- mid=0.80 is grounded in resolved item 4a715300 (real corroboration >0.85
  cosine; 0.70–0.79 topical noise); high=1.01 is unreachable so 100% of
  candidates go to the LLM verifier instead of blind auto-promotion. Provisional
  — final calibrated sweep deferred to #239.

**Verification:**
- Test: cos≈1.0 pair scores ≥0.80 (reaches verifier), cos≈0.5 pair scores <0.80
  (dropped). epigraph-engine suite green.
EOF
)"
```

---

## Task 7: Full CI gate + open PR

**Files:** none (verification + PR)

- [ ] **Step 1: Run the full pre-commit CI gate (fmt → clippy → test, all `--locked`)**

The epigraph CI test job runs build → clippy → fmt → test, all `--locked`. Local build/test alone misses fmt/clippy and costs a CI round-trip — run them here:

```bash
cargo fmt --check
cargo clippy --workspace --locked -- -D warnings
cargo test -p epigraph-engine --test scorer_features
```

Expected: `fmt --check` clean; clippy zero warnings; all scorer tests PASS. Fix any fmt/clippy findings and amend the relevant commit.

- [ ] **Step 2: Sanity-check `.sqlx`/offline build is unaffected**

These queries are dynamic `sqlx::query(...)`, not compile-time `sqlx::query!` macros, so no `.sqlx/` regeneration is needed. Confirm the offline check still passes:

```bash
SQLX_OFFLINE=true cargo check -p epigraph-engine
```

Expected: PASS with no "query metadata" errors. (If it fails citing a `query!` macro, that means a macro was introduced — regenerate with `cargo sqlx prepare --workspace -- --tests` and commit `.sqlx/`.)

- [ ] **Step 3: Push and open the PR**

```bash
git push -u origin feat/matcher-renormalize-fired-features
gh pr create --base main \
  --title "fix(matcher): renormalize pair score over fired features to unblock cross-source verifier queue" \
  --body "$(cat <<'EOF'
## Summary
Resolves backlog `9b50c331` (score dilution); provisional bands for `27bc9754`
(final sweep → #239).

The cross-source pair scorer divided by the sum of all nine feature weights even
though structural features are ~0 by construction for cross-source pairs, capping
a perfect-cosine pair at ~0.425 < mid=0.60. Across 12,006 historical candidates,
0 ever reached the LLM verifier (`pending`). This renormalizes the score over
only the features that produced a real signal, and resets the bands to the
resulting (≈cosine) scale so every candidate routes to the verifier.

## Changes
- `scorer.rs`: per-feature applicability (`Option`) + `renormalized_score`
  combiner. Jaccards key on non-empty union; `graph_overlap` on value>0;
  belief/theme on the data-present arm; `embed_cosine` always-applicable
  (0.0-on-NULL = deliberate suppression). Reported `MatchFeatures` values
  unchanged (telemetry stable).
- `calibration.toml`: `[matcher.bands]` mid 0.60→0.80, high 0.85→1.01.

## Validation
- SQL simulation over 170 substantive high-cosine cross-source pairs: avg score
  0.417 → 0.887; clears mid=0.80 0 → 164; queue 0 → 100% reaching the verifier.
- New scorer tests cover: cosine-only ≈ cosine; fired-zero Jaccard as negative;
  no-shared-neighbor drops graph_overlap; opposite-stance belief lowers score;
  NULL-embedding suppression; mid-band separation.

## Spec
`docs/superpowers/specs/2026-06-03-cross-source-bootstrap-matching-design.md`

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 4: Post-merge live verification (do NOT do in this plan — after merge + redeploy)**

After the PR merges and the engine is redeployed, run a real `cross_source_sweep` on the live DB and confirm `list_match_candidates(status="pending")` is non-empty, then retire the backlog items per the repo convention:

```
mcp__epigraph__resolve_backlog_item(
  original_id="9b50c331-a80f-4f3d-93c1-00b105cdfa18",
  resolution_content="Resolves 9b50c331: renormalized scorer over fired features (PR <n>); live sweep produced <k> pending candidates (was 0).")
```

and a partial note on `27bc9754` (provisional bands shipped; final precision sweep remains with #239).

---

## Self-Review

**Spec coverage:**
- Combiner renormalization → Task 1. ✓
- Per-feature applicability table (union-non-empty Jaccards; graph value>0; belief/theme data-present; embed always) → Tasks 1–4. ✓
- `embed_cosine` always-applicable + suppression → Task 1 (impl) + Task 5 (test). ✓
- Band reset mid=0.80/high=1.01 + verifier routing → Task 6. ✓
- Reported feature values unchanged (telemetry) → Task 1 Step 9 + existing-suite check Step 11. ✓
- Testing list (cosine-only; fired-structural-negative; opposite-stance belief; NULL guard; pipeline band separation) → Tasks 1–6. ✓
- Backlog retirement convention → Task 7 Step 4. ✓
- Latent intra-source tension → documented in spec; preserved by the union-non-empty rule (Task 2 locks it). ✓

**Placeholder scan:** No TBD/TODO; every code and SQL step shows full content. ✓

**Type consistency:** `renormalized_score(&[(f32, Option<f32>)]) -> f32` is defined once (Task 1 Step 3) and called once (Step 9) with nine `(weight, Option<f32>)` entries, including `method_match_val: Option<f32>` derived from `method_match_opt: Option<bool>`. Binding names (`*_opt`) are introduced in Steps 4–8 and consumed consistently in Step 9. Reported field types match `MatchFeatures` (`method_match: bool` via `unwrap_or(false)`; others `f32` via `unwrap_or`). ✓
